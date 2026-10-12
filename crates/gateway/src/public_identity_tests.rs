//! Actual gateway App/router and owned socket; no external service, key or proof.
use super::*;
use axum::{body::Body, http::Request};
use serde_json::Value;
use tower::ServiceExt;

async fn identity(router: Router) -> (StatusCode, axum::http::HeaderMap, Value) {
    let response = router
        .oneshot(Request::get("/identity").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = axum::body::to_bytes(response.into_body(), 16 * 1024)
        .await
        .unwrap();
    let value = if body.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&body).unwrap()
    };
    (status, headers, value)
}

#[tokio::test]
async fn public_identity_actual_router_exposes_only_resolved_public_state_without_mutation() {
    let app = tests::test_app();
    let before = app.gw.lock().await.v1_status_json();
    for production in [false, true] {
        let (status, headers, report) = identity(build_router(app.clone(), production)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers["cache-control"], "no-store");
        assert_eq!(report["schema"], service_identity::SCHEMA);
        assert_eq!(report["service"], "gateway");
        assert_eq!(report["evidence_kind"], "self_reported_unattested");
        assert_eq!(report["program"], Value::Null);
        assert_eq!(report["public_config"]["chain_id"], before["chainId"]);
        assert_eq!(report["public_config"]["vault"], before["vault"]);
        assert_eq!(report["public_config"]["l1"], Value::Null);
        assert_eq!(report["public_config"]["candidate_archive"], Value::Null);
        assert_eq!(
            report["capabilities"]["candidate_submission_supported"],
            false
        );
        assert_eq!(report["scope"]["running_services_attested"], false);
        assert_eq!(report["scope"]["release_gate"], "HOLD");
        assert_eq!(
            report["public_config_sha256"],
            service_identity::sha256(&service_identity::canonical(&report["public_config"]))
        );
        let keys: std::collections::BTreeSet<_> = report
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            [
                "schema",
                "service",
                "evidence_kind",
                "build",
                "program",
                "public_config",
                "public_config_sha256",
                "capabilities",
                "scope"
            ]
            .into_iter()
            .collect()
        );
        assert_eq!(app.gw.lock().await.v1_status_json(), before);
        assert!(app.reg_limit.lock().await.is_empty());
        assert!(!app.force_settle.load(std::sync::atomic::Ordering::SeqCst));
    }
    app.gw.lock().await.vault = [0x42; 20];
    let (_, _, changed) = identity(build_router(app.clone(), false)).await;
    assert_eq!(changed["public_config"]["vault"], hex0x(&[0x42; 20]));
    assert_ne!(changed["public_config"]["vault"], before["vault"]);
}

#[tokio::test]
async fn public_identity_post_retains_bounded_intake_and_cannot_change_state() {
    let app = tests::test_app();
    let before = app.gw.lock().await.v1_status_json();
    // The existing global service policy buffers a bounded body before method
    // dispatch. Identity adds no mutation handler and retains that policy.
    let unused_body = Body::from("ignored public diagnostic body");
    let response = build_router(app.clone(), true)
        .oneshot(Request::post("/identity").body(unused_body).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(app.gw.lock().await.v1_status_json(), before);
    let policy = Arc::new(service_policy::ServicePolicy::new(service_policy::Config {
        allowed_origins: vec![],
        max_connections: 1,
        http_max_in_flight: 8,
        http_max_body_bytes: 16,
        http_body_timeout: Duration::from_secs(1),
        max_message_bytes: 128,
        max_frame_bytes: 128,
        write_buffer_bytes: 128,
        max_write_buffer_bytes: 1024,
        send_timeout: Duration::from_secs(1),
        messages_per_second: 1,
    }));
    let oversized = build_router_with_policy(app.clone(), true, policy)
        .oneshot(
            Request::post("/identity")
                .body(Body::from(vec![b'x'; 17]))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(app.gw.lock().await.v1_status_json(), before);
}

#[tokio::test]
async fn public_identity_configured_prover_never_requests_a_proof_or_enables_candidate() {
    struct NoProof;
    impl prover_client::ProverClient for NoProof {
        fn prove(
            &self,
            _: &WindowWitness,
        ) -> Result<prover_client::RemoteProveResp, prover_client::ProverClientError> {
            panic!("a public identity read must never request a proof");
        }
    }
    let mut app = tests::test_app();
    Arc::get_mut(&mut app).unwrap().prover = Some(Arc::new(NoProof));
    let (status, _, report) = identity(build_router(app, false)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(report["public_config"]["prover_configured"], true);
    assert_eq!(report["public_config"]["clocked_prover_configured"], false);
    assert_eq!(
        report["capabilities"]["candidate_submission_supported"],
        false
    );
    assert_eq!(
        report["capabilities"]["candidate_submission_enabled"],
        false
    );
    assert_eq!(
        report["scope"]["proof_generated_by_identity_request"],
        false
    );
}

#[tokio::test]
async fn public_identity_missing_required_archive_is_unavailable_not_a_legacy_declaration() {
    let app = tests::test_app();
    let baseline = identity(build_router(app.clone(), false)).await;
    assert_eq!(baseline.0, StatusCode::OK);
    app.gw.lock().await.candidate_archive_required = true;
    let response = build_router(app.clone(), false)
        .oneshot(Request::get("/identity").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(axum::body::to_bytes(response.into_body(), 16 * 1024)
        .await
        .unwrap()
        .is_empty());
    assert!(app.gw.lock().await.candidate_archive_required);
}

#[tokio::test]
async fn public_identity_owned_socket_serves_same_metadata_and_stops_only_its_listener() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let app = tests::test_app();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            build_router(app, false).into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async {
            let _ = stop_rx.await;
        })
        .await
        .unwrap();
    });
    let operation = tokio::time::timeout(Duration::from_secs(5), async {
        let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
        stream
            .write_all(b"GET /identity HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        stream
            .take(16 * 1024)
            .read_to_end(&mut response)
            .await
            .unwrap();
        let response = String::from_utf8(response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200"));
        assert!(response
            .to_ascii_lowercase()
            .contains("cache-control: no-store"));
        let body = response.split_once("\r\n\r\n").unwrap().1;
        let metadata: Value = serde_json::from_str(body).unwrap();
        assert_eq!(metadata["service"], "gateway");
        assert_eq!(
            metadata["capabilities"]["candidate_submission_enabled"],
            false
        );
        assert_eq!(metadata["scope"]["release_gate"], "HOLD");
        assert_eq!(
            metadata["build"]["source_sha256"].as_str().unwrap().len(),
            64
        );
    })
    .await;
    let _ = stop_tx.send(());
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap();
    operation.unwrap();
}

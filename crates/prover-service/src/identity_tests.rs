//! Router-only identity acceptance. The program is an injected committed ELF
//! fixture, not a claim that a real prover service/backend was loaded or booted.
use crate::identity::{
    admit_program, program_descriptor, routes, witness_domains, witness_domains_in, PublicIdentity,
    PROGRAM_WITNESS_DOMAINS, WITNESS_DOMAIN,
};
use axum::{
    body::{to_bytes, Body},
    http::{Method, Request, StatusCode},
};
use serde_json::{json, Value};
use std::{net::SocketAddr, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tower::ServiceExt;

const FIXTURE_ELF: &[u8] =
    include_bytes!("../../../contracts/integration/fixtures/clock-pkg3-reviewed/guest.elf");
const FIXTURE_VKEY: &[u8] =
    include_bytes!("../../../contracts/integration/fixtures/clock-pkg3-reviewed/program-vkey.bin");

fn fixture_identity(dev_insecure: bool, body_bytes: usize) -> PublicIdentity {
    PublicIdentity::resolved(
        program_descriptor(FIXTURE_ELF, &format!("0x{}", hex::encode(FIXTURE_VKEY))),
        [0x37; 32],
        dev_insecure,
        3,
        body_bytes,
        Duration::from_secs(17),
    )
}

async fn get_value(identity: PublicIdentity) -> Value {
    let response = routes()
        .with_state(identity)
        .oneshot(Request::get("/identity").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(response.headers()["content-type"], "application/json");
    serde_json::from_slice(&to_bytes(response.into_body(), 32 * 1024).await.unwrap()).unwrap()
}

fn assert_closed_scope(value: &Value) {
    assert_eq!(value["schema"], "arcora-public-service-identity/v1");
    assert_eq!(value["service"], "prover");
    assert_eq!(value["evidence_kind"], "self_reported_unattested");
    assert_eq!(
        value["capabilities"]["candidate_submission_supported"],
        false
    );
    assert_eq!(value["capabilities"]["candidate_submission_enabled"], false);
    assert_eq!(value["scope"]["running_services_attested"], false);
    assert_eq!(value["scope"]["operator_policy_approved"], false);
    assert_eq!(value["scope"]["proof_generated_by_identity_request"], false);
    assert_eq!(value["scope"]["release_gate"], "HOLD");
    assert_eq!(
        value["program"]["supported_witness_domains"],
        json!(witness_domains(FIXTURE_ELF))
    );
}

#[test]
fn injected_reviewed_fixture_descriptor_binds_exact_bytes_and_clock_domain() {
    // Existing fixture bytes only. No setup, key derivation, SDK client or proof.
    assert_eq!(FIXTURE_ELF.len(), 535_904);
    assert_eq!(
        crate::service_identity::sha256(FIXTURE_ELF),
        "a6d516488c542673ef750c6c6d7cd0fb6b9c004d0cb6c82eb5b4bc57d630e7df"
    );
    let key = format!("0x{}", hex::encode(FIXTURE_VKEY));
    assert_eq!(
        key,
        "0x009cfc02120c4255b1a8c3eebbcc31f92a9ce0891c88641e78e0af23aae098ec"
    );
    let first = program_descriptor(FIXTURE_ELF, &key);
    assert_eq!(first["elf_bytes"], 535_904);
    assert_eq!(
        first["elf_sha256"],
        crate::service_identity::sha256(FIXTURE_ELF)
    );
    assert_eq!(first["sdk_version"], "6.1.0");
    assert_eq!(first["program_vkey"], key);
    assert_eq!(
        first["supported_witness_domains"],
        json!(witness_domains(FIXTURE_ELF))
    );
    // The reviewed guest is listed with the one framing `/prove` admits.
    assert_eq!(first["supported_witness_domains"], json!([WITNESS_DOMAIN]));
    assert_eq!(first.as_object().unwrap().len(), 5);
    let second = program_descriptor(b"different injected fixture bytes", "0x99");
    assert_ne!(first["elf_sha256"], second["elf_sha256"]);
    assert_ne!(first["elf_bytes"], second["elf_bytes"]);
    assert_ne!(first["program_vkey"], second["program_vkey"]);
}

/// The descriptor's domains come from the reviewed program table, keyed by the
/// exact ELF bytes: a program that is not listed, or is listed with another
/// framing, claims no domain, and only a program listed with `DPCLK4` claims it.
#[test]
fn supported_domains_are_those_of_the_embedded_program() {
    let unlisted = program_descriptor(b"different injected fixture bytes", "0x99");
    assert_eq!(unlisted["supported_witness_domains"], json!([]));
    // The clock-v2 guest accepts the unframed tuple and DPCLK2 only.
    let historical =
        include_bytes!("../../../contracts/integration/fixtures/clock-v2-verified/guest.elf");
    assert!(PROGRAM_WITNESS_DOMAINS.contains(&(
        "df59a19b310258b4d01d0d5e3cfa31bb7de9ca2f4ea7c2302cf76650c79967c5",
        "DPCLK2"
    )));
    assert_eq!(
        program_descriptor(historical, "0x99")["supported_witness_domains"],
        json!([])
    );
    // The reviewed guest accepts exactly the clock-bound framing.
    assert!(PROGRAM_WITNESS_DOMAINS.contains(&(
        "a6d516488c542673ef750c6c6d7cd0fb6b9c004d0cb6c82eb5b4bc57d630e7df",
        WITNESS_DOMAIN
    )));
    assert_eq!(
        program_descriptor(FIXTURE_ELF, "0x99")["supported_witness_domains"],
        json!([WITNESS_DOMAIN])
    );
    let elf = b"a reviewed program accepting the clock-bound framing";
    let digest = crate::service_identity::sha256(elf);
    assert_eq!(
        witness_domains_in(elf, &[(&digest, WITNESS_DOMAIN)]),
        [WITNESS_DOMAIN]
    );
    assert!(witness_domains_in(elf, &[(&digest, "DPCLK2")]).is_empty());
    assert!(witness_domains_in(b"other bytes", &[(&digest, WITNESS_DOMAIN)]).is_empty());
}

/// In production the service refuses to start unless its embedded program
/// accepts the one framing `/prove` admits.
#[test]
fn production_refuses_a_program_without_the_admitted_domain() {
    assert!(admit_program(&[WITNESS_DOMAIN], true).is_ok());
    let refused = admit_program(&[], true).unwrap_err();
    assert!(refused.contains("refusing to start"), "{refused}");
    assert!(admit_program(&["DPCLK2"], true).is_err());
    assert!(
        admit_program(&[], false).is_ok(),
        "outside production it only warns"
    );
}

#[tokio::test]
async fn actual_router_returns_resolved_public_fields_and_checksums() {
    let value = get_value(fixture_identity(true, 8192)).await;
    assert_closed_scope(&value);
    assert_eq!(
        value["public_config"],
        json!({
            "measurement": format!("0x{}", "37".repeat(32)),
            "dev_insecure": true,
            "admission": {"max_concurrent":3,"body_bytes":8192,"body_timeout_ms":17000}
        })
    );
    let canonical = format!(
        r#"{{"admission":{{"body_bytes":8192,"body_timeout_ms":17000,"max_concurrent":3}},"dev_insecure":true,"measurement":"0x{}"}}"#,
        "37".repeat(32)
    );
    assert_eq!(
        value["public_config_sha256"],
        crate::service_identity::sha256(canonical.as_bytes())
    );
    let mut keys = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "build",
            "capabilities",
            "evidence_kind",
            "program",
            "public_config",
            "public_config_sha256",
            "schema",
            "scope",
            "service"
        ]
    );
    assert_eq!(value["build"].as_object().unwrap().len(), 4);
    assert_eq!(value["build"]["schema"], "arcora-service-build-identity/v1");
    assert_eq!(
        value["build"]["algorithm"],
        "sha256-canonical-source-map-v1"
    );
    assert!(value["build"]["source_files"]
        .as_u64()
        .is_some_and(|n| n > 0));
    let checksum = value["build"]["source_sha256"].as_str().unwrap();
    assert_eq!(checksum.len(), 64);
    assert!(checksum
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
}

#[tokio::test]
async fn repeated_get_is_stable_and_resolved_changes_change_only_public_fingerprint() {
    let first = fixture_identity(false, 4096);
    let before = get_value(first.clone()).await;
    let repeated = get_value(first).await;
    assert_eq!(before, repeated);
    let changed = get_value(fixture_identity(true, 8192)).await;
    assert_ne!(
        before["public_config_sha256"],
        changed["public_config_sha256"]
    );
    assert_eq!(before["program"], changed["program"]);
    assert_eq!(before["build"], changed["build"]);
    assert_closed_scope(&before);
    assert_closed_scope(&changed);
}

#[tokio::test]
async fn identity_router_refuses_mutating_methods() {
    let router = routes().with_state(fixture_identity(false, 4096));
    for method in [Method::POST, Method::PUT, Method::PATCH, Method::DELETE] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri("/identity")
                    .header("authorization", "Bearer DO_NOT_RETURN_PRIVATE_SESSION")
                    .body(Body::from("DO_NOT_RETURN_SEALED_WITNESS"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        let body = to_bytes(response.into_body(), 32 * 1024).await.unwrap();
        assert!(!String::from_utf8_lossy(&body).contains("DO_NOT_RETURN"));
    }
}

async fn exchange(address: SocketAddr, method: &str, target: &str) -> Vec<u8> {
    let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
    stream.write_all(format!(
        "{method} {target} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nAuthorization: Bearer DO_NOT_RETURN_PRIVATE_SESSION\r\nContent-Length: 0\r\n\r\n"
    ).as_bytes()).await.unwrap();
    let mut bytes = Vec::new();
    stream
        .take(32 * 1024)
        .read_to_end(&mut bytes)
        .await
        .unwrap();
    bytes
}

#[tokio::test]
async fn actual_handler_owned_loopback_get_and_post_remain_public_and_unattested() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let router = routes().with_state(fixture_identity(true, 8192));
    let server = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async {
                let _ = stopped.await;
            })
            .await
            .unwrap();
    });
    let get = tokio::time::timeout(
        Duration::from_secs(5),
        exchange(
            address,
            "GET",
            "/identity?seal_root=DO_NOT_RETURN_ROOT&path=DO_NOT_RETURN_LOCAL_PATH",
        ),
    )
    .await
    .unwrap();
    let post = tokio::time::timeout(
        Duration::from_secs(5),
        exchange(address, "POST", "/identity"),
    )
    .await
    .unwrap();
    stop.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap();
    let text = std::str::from_utf8(&get).unwrap();
    assert!(text.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(text
        .to_ascii_lowercase()
        .contains("cache-control: no-store\r\n"));
    assert!(!text.contains("DO_NOT_RETURN"));
    let body = text.split_once("\r\n\r\n").unwrap().1;
    let value: Value = serde_json::from_str(body).unwrap();
    assert_closed_scope(&value);
    assert!(std::str::from_utf8(&post)
        .unwrap()
        .starts_with("HTTP/1.1 405 Method Not Allowed\r\n"));
}

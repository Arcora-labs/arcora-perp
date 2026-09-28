//! Accepted-request and socket lifecycle checks against the actual router.
use super::*;
use axum::{body::Body, http::Request};
use futures_util::StreamExt;
use tower::ServiceExt;

fn policy() -> Arc<service_policy::ServicePolicy> {
    let mut config = service_policy::Config::from_env(false).unwrap();
    config.http_max_in_flight = 1;
    config.http_max_body_bytes = 64;
    config.http_body_timeout = Duration::from_millis(100);
    Arc::new(service_policy::ServicePolicy::new(config))
}

fn register(body: Body) -> Request<Body> {
    Request::post("/v1/accounts")
        .extension(ConnectInfo(
            "127.0.0.1:12000".parse::<SocketAddr>().unwrap(),
        ))
        .body(body)
        .unwrap()
}

#[tokio::test]
async fn shutdown_drains_admitted_mutation_but_refuses_new_body_and_capacity() {
    let app = tests::test_app();
    let before = app.gw.lock().await.accounts.len();
    let policy = policy();
    let router = build_router_with_policy(app.clone(), false, policy.clone());
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let body = Body::from_stream(futures_util::stream::once(async move {
        started_tx.send(()).unwrap();
        release_rx.await.unwrap();
        Ok::<_, std::io::Error>("{}")
    }));
    let running = tokio::spawn(router.clone().oneshot(register(body)));
    started_rx.await.unwrap();
    for draining in [false, true] {
        if draining {
            policy.shutdown.begin();
        }
        let untouched = Body::from_stream(futures_util::stream::poll_fn(
            |_| -> std::task::Poll<Option<Result<Vec<u8>, std::io::Error>>> {
                panic!("refused request must not poll its body")
            },
        ));
        let reply = router.clone().oneshot(register(untouched)).await.unwrap();
        assert_eq!(reply.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(app.gw.lock().await.accounts.len(), before);
    }
    release_tx.send(()).unwrap();
    assert_eq!(running.await.unwrap().unwrap().status(), StatusCode::OK);
    assert_eq!(app.gw.lock().await.accounts.len(), before + 1);
}

#[tokio::test(start_paused = true)]
async fn shutdown_http_body_deadline_and_size_leave_no_mutation_and_return_capacity() {
    let app = tests::test_app();
    let before = app.gw.lock().await.accounts.len();
    let router = build_router_with_policy(app.clone(), false, policy());
    let pending = Body::from_stream(futures_util::stream::pending::<
        Result<Vec<u8>, std::io::Error>,
    >());
    assert_eq!(
        router
            .clone()
            .oneshot(register(pending))
            .await
            .unwrap()
            .status(),
        StatusCode::REQUEST_TIMEOUT
    );
    assert_eq!(
        router
            .clone()
            .oneshot(register(Body::from(vec![b' '; 65])))
            .await
            .unwrap()
            .status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    assert_eq!(app.gw.lock().await.accounts.len(), before);
    assert_eq!(
        router
            .oneshot(register(Body::from("{}")))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(app.gw.lock().await.accounts.len(), before + 1);
}

#[tokio::test]
async fn shutdown_closes_both_socket_streams_and_joins_upgraded_tasks() {
    let app = tests::test_app();
    let policy = policy();
    let router = build_router_with_policy(app.clone(), false, policy.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let stop = policy.shutdown.clone();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move { stop.cancelled().await })
        .await
        .unwrap();
    });
    let (mut public, _) = tokio_tungstenite::connect_async(format!("ws://{address}/ws"))
        .await
        .unwrap();
    let (mut private, _) = tokio_tungstenite::connect_async(format!("ws://{address}/v1/ws"))
        .await
        .unwrap();
    assert!(public.next().await.unwrap().unwrap().is_text());
    assert!(private.next().await.unwrap().unwrap().is_text());
    policy.shutdown.begin();
    tokio::time::timeout(Duration::from_secs(2), async {
        server.await.unwrap();
        policy.wait_for_sockets().await;
        assert!(matches!(
            public.next().await,
            None | Some(Err(_)) | Some(Ok(tokio_tungstenite::tungstenite::Message::Close(_)))
        ));
        assert!(matches!(
            private.next().await,
            None | Some(Err(_)) | Some(Ok(tokio_tungstenite::tungstenite::Message::Close(_)))
        ));
    })
    .await
    .unwrap();
    assert_eq!(app.tx.receiver_count(), 0);
    assert_eq!(app.events_tx.receiver_count(), 0);
}

#[tokio::test(start_paused = true)]
async fn shutdown_is_sticky_and_prevents_even_ready_next_tick() {
    let stop = service_shutdown::Shutdown::default();
    let mut interval = tokio::time::interval(Duration::from_secs(10));
    assert!(stop.next_tick(&mut interval).await);
    stop.begin();
    stop.begin();
    tokio::time::advance(Duration::from_secs(20)).await;
    assert!(!stop.next_tick(&mut interval).await);
    stop.cancelled().await;
}

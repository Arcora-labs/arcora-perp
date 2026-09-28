//! Actual gateway router/socket coverage for the installed service policy.
use super::*;
use axum::{body::Body, http::Request};
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{client::IntoClientRequest, Message as ClientMessage},
};
use tower::ServiceExt;

fn policy() -> Arc<service_policy::ServicePolicy> {
    Arc::new(service_policy::ServicePolicy::new(service_policy::Config {
        allowed_origins: vec!["http://localhost:5173".parse().unwrap()],
        max_connections: 1,
        http_max_in_flight: 64,
        http_max_body_bytes: 2 * 1024 * 1024,
        http_body_timeout: Duration::from_secs(5),
        max_message_bytes: 128,
        max_frame_bytes: 128,
        write_buffer_bytes: 1024,
        max_write_buffer_bytes: 1024 * 1024,
        send_timeout: Duration::from_secs(2),
        messages_per_second: 2,
    }))
}

#[tokio::test]
async fn actual_registration_rejects_bad_origin_before_body_and_mutation() {
    let app = tests::test_app();
    let router = build_router_with_policy(app.clone(), false, policy());
    let before = app.gw.lock().await.accounts.len();
    let forbidden_body = Body::from_stream(futures_util::stream::poll_fn(
        |_| -> std::task::Poll<Option<Result<Vec<u8>, std::io::Error>>> {
            panic!("unapproved origin must never poll the registration body")
        },
    ));
    let request = Request::post("/v1/accounts")
        .header("Origin", "https://untrusted.invalid")
        .extension(ConnectInfo(
            "127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
        ))
        .body(forbidden_body)
        .unwrap();
    assert_eq!(
        router.clone().oneshot(request).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(app.gw.lock().await.accounts.len(), before);
    assert!(app.reg_limit.lock().await.is_empty());
    let allowed = Request::post("/v1/accounts")
        .header("Origin", "http://localhost:5173")
        .extension(ConnectInfo(
            "127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
        ))
        .body(Body::from("{}"))
        .unwrap();
    let response = router.oneshot(allowed).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("access-control-allow-origin")
            .unwrap(),
        "http://localhost:5173"
    );
    assert_eq!(app.gw.lock().await.accounts.len(), before + 1);
}

#[tokio::test]
async fn actual_ws_routes_share_capacity_and_release_on_disconnect_and_message_limit() {
    let app = tests::test_app();
    let router = build_router_with_policy(app.clone(), false, policy());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let url = |path| format!("ws://{address}{path}");
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async {
            let _ = stop_rx.await;
        })
        .await
        .unwrap();
    });
    let mut denied = url("/v1/ws").into_client_request().unwrap();
    denied
        .headers_mut()
        .insert("Origin", "https://untrusted.invalid".parse().unwrap());
    assert!(
        matches!(connect_async(denied).await, Err(tokio_tungstenite::tungstenite::Error::Http(response)) if response.status() == StatusCode::FORBIDDEN)
    );
    let (mut legacy, _) = connect_async(url("/ws")).await.unwrap();
    assert!(legacy.next().await.unwrap().unwrap().is_text());
    assert!(
        matches!(connect_async(url("/v1/ws")).await, Err(tokio_tungstenite::tungstenite::Error::Http(response)) if response.status() == StatusCode::SERVICE_UNAVAILABLE)
    );
    legacy.close(None).await.unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(2), legacy.next())
        .await
        .unwrap();
    // A legacy idle close must wake its receive branch and release its slot.
    let (mut private, _) = connect_async(url("/v1/ws")).await.unwrap();
    assert!(private.next().await.unwrap().unwrap().is_text());
    for _ in 0..3 {
        private
            .send(ClientMessage::Text("invalid json".into()))
            .await
            .unwrap();
    }
    let closed = tokio::time::timeout(Duration::from_secs(2), private.next())
        .await
        .unwrap();
    assert!(matches!(
        closed,
        None | Some(Err(_)) | Some(Ok(ClientMessage::Close(_)))
    ));
    let (mut replacement, _) = connect_async(url("/ws")).await.unwrap();
    assert!(replacement.next().await.unwrap().unwrap().is_text());
    replacement.close(None).await.unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(2), replacement.next())
        .await
        .unwrap();
    stop_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(app.tx.receiver_count(), 0);
    assert_eq!(app.events_tx.receiver_count(), 0);
}

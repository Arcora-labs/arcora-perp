# Gateway service-policy integration design (applied)

The `service_policy.rs` module and `credential_session.rs` were prepared without
editing concurrently owned `main.rs`. Root applied the equivalent integration,
with configuration validated once at startup and passed through
`build_router_with_policy`; the current source is authoritative. The integrated
suite passes the actual-router tests listed in `service-policy.md`.
The snippets below record the integration design, not remaining instructions.

Add `mod service_policy;`, remove `use tower_http::cors::CorsLayer;`.

At the beginning of `build_router(app, prod)`:

```rust
let policy = Arc::new(service_policy::ServicePolicy::from_env(prod)
    .expect("invalid gateway service policy"));
```

Replace `.layer(CorsLayer::permissive())` at the end of `build_router` with:

```rust
.layer(policy.cors())
.layer(axum::middleware::from_fn_with_state(policy.clone(), service_policy::enforce_origin))
.layer(axum::Extension(policy))
```

Replace the private WebSocket handlers with:

```rust
async fn ws_v1_handler(
    State(app): State<Shared>,
    axum::Extension(policy): axum::Extension<Arc<service_policy::ServicePolicy>>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> axum::response::Response {
    let permit = match policy.admit(&headers) {
        Ok(permit) => permit,
        Err(status) => return status.into_response(),
    };
    policy.configure(ws).on_upgrade(move |socket| async move {
        let _permit = permit;
        ws_v1_loop(socket, app, policy).await;
    })
}

async fn ws_v1_loop(socket: WebSocket, app: Shared, policy: Arc<service_policy::ServicePolicy>) {
    credential_session::serve(socket, app, policy).await;
}
```

Replace the legacy public WebSocket handlers with:

```rust
async fn ws_handler(
    State(app): State<Shared>,
    axum::Extension(policy): axum::Extension<Arc<service_policy::ServicePolicy>>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> axum::response::Response {
    let permit = match policy.admit(&headers) {
        Ok(permit) => permit,
        Err(status) => return status.into_response(),
    };
    policy.configure(ws).on_upgrade(move |socket| async move {
        let _permit = permit;
        ws_loop(socket, app, policy).await;
    })
}

async fn ws_loop(mut socket: WebSocket, app: Shared, policy: Arc<service_policy::ServicePolicy>) {
    let mut rx = app.tx.subscribe();
    let mut budget = policy.message_budget();
    let initial = {
        serde_json::to_string(&WsMsg::State { state: app.gw.lock().await.snapshot() }).unwrap()
    };
    if !policy.send(&mut socket, Message::Text(initial)).await { return; }
    loop {
        tokio::select! {
            client = socket.recv() => {
                if !budget.take() { break; }
                match client {
                    None | Some(Err(_)) | Some(Ok(Message::Close(_))) => break,
                    _ => {},
                }
            }
            update = rx.recv() => {
                let Ok(message) = update else { break; };
                if !policy.send(&mut socket, Message::Text(message)).await { break; }
            }
        }
    }
}
```

//! Browser-origin and WebSocket resource policy, loaded once per router.
//! CORS is not authentication. Requests without Origin remain available to
//! native clients; the API's account/signature checks still authorize actions.
use super::service_shutdown::Shutdown;
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        ConnectInfo, Request, State,
    },
    http::{header, HeaderMap, HeaderValue, Method, StatusCode, Uri},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tower_http::cors::CorsLayer;

#[derive(Clone, Debug)]
pub(crate) struct Config {
    pub(crate) allowed_origins: Vec<HeaderValue>,
    pub(crate) max_connections: usize,
    pub(crate) http_max_in_flight: usize,
    pub(crate) http_max_in_flight_per_client: usize,
    pub(crate) http_max_body_bytes: usize,
    pub(crate) http_body_timeout: Duration,
    pub(crate) max_message_bytes: usize,
    pub(crate) max_frame_bytes: usize,
    pub(crate) write_buffer_bytes: usize,
    pub(crate) max_write_buffer_bytes: usize,
    pub(crate) send_timeout: Duration,
    pub(crate) messages_per_second: usize,
}

impl Config {
    pub(crate) fn from_env(prod: bool) -> Result<Self, String> {
        Self::from_lookup(prod, |name| match std::env::var(name) {
            Ok(value) => Ok(Some(value)),
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(_) => Err(format!("{name} must be valid UTF-8")),
        })
    }

    fn from_lookup(
        prod: bool,
        get: impl Fn(&str) -> Result<Option<String>, String>,
    ) -> Result<Self, String> {
        let allowed_origins = match get("GATEWAY_ALLOWED_ORIGINS")? {
            Some(value) => parse_origins(&value)?,
            None if prod => vec![],
            None => parse_origins("http://localhost:5173,http://127.0.0.1:5173,http://localhost:4173,http://127.0.0.1:4173")?,
        };
        let number = |name, default, max| match get(name)? {
            None => Ok(default),
            Some(value) => value
                .parse::<usize>()
                .ok()
                .filter(|n| (1..=max).contains(n))
                .ok_or_else(|| format!("{name} must be an integer in 1..={max}")),
        };
        let mut config = Self {
            allowed_origins,
            max_connections: number("GATEWAY_WS_MAX_CONNECTIONS", 256, 10_000)?,
            http_max_in_flight: number("GATEWAY_HTTP_MAX_IN_FLIGHT", 64, 4096)?,
            // placeholder; resolved against the global cap below
            http_max_in_flight_per_client: 0,
            http_max_body_bytes: number(
                "GATEWAY_HTTP_MAX_BODY_BYTES",
                2 * 1024 * 1024,
                8 * 1024 * 1024,
            )?,
            http_body_timeout: Duration::from_millis(number(
                "GATEWAY_HTTP_BODY_TIMEOUT_MS",
                5000,
                60000,
            )? as u64),
            max_message_bytes: number("GATEWAY_WS_MAX_MESSAGE_BYTES", 16 * 1024, 1024 * 1024)?,
            max_frame_bytes: number("GATEWAY_WS_MAX_FRAME_BYTES", 16 * 1024, 1024 * 1024)?,
            write_buffer_bytes: number("GATEWAY_WS_WRITE_BUFFER_BYTES", 16 * 1024, 1024 * 1024)?,
            max_write_buffer_bytes: number(
                "GATEWAY_WS_MAX_WRITE_BUFFER_BYTES",
                1024 * 1024,
                16 * 1024 * 1024,
            )?,
            send_timeout: Duration::from_millis(
                number("GATEWAY_WS_SEND_TIMEOUT_MS", 2_000, 30_000)? as u64,
            ),
            messages_per_second: number("GATEWAY_WS_MESSAGES_PER_SECOND", 32, 1_000)?,
        };
        if config.max_write_buffer_bytes <= config.write_buffer_bytes {
            return Err(
                "GATEWAY_WS_MAX_WRITE_BUFFER_BYTES must exceed GATEWAY_WS_WRITE_BUFFER_BYTES"
                    .into(),
            );
        }
        // Unset: 8, or the global cap when that is lower (a small global cap configured
        // before this setting existed keeps booting). Set explicitly: must fit inside it.
        config.http_max_in_flight_per_client = match get("GATEWAY_HTTP_MAX_IN_FLIGHT_PER_CLIENT")? {
            None => config.http_max_in_flight.min(8),
            Some(_) => number("GATEWAY_HTTP_MAX_IN_FLIGHT_PER_CLIENT", 8, 4096)?,
        };
        if config.http_max_in_flight_per_client > config.http_max_in_flight {
            return Err(
                "GATEWAY_HTTP_MAX_IN_FLIGHT_PER_CLIENT must not exceed GATEWAY_HTTP_MAX_IN_FLIGHT"
                    .into(),
            );
        }
        if config.max_frame_bytes > config.max_message_bytes {
            return Err(
                "GATEWAY_WS_MAX_FRAME_BYTES must not exceed GATEWAY_WS_MAX_MESSAGE_BYTES".into(),
            );
        }
        Ok(config)
    }
}

fn parse_origins(value: &str) -> Result<Vec<HeaderValue>, String> {
    if value.trim().is_empty() {
        return Ok(vec![]);
    }
    value.split(',').map(|origin| {
        let origin = origin.trim();
        let uri: Uri = origin.parse().map_err(|_| "GATEWAY_ALLOWED_ORIGINS contains an invalid origin")?;
        let authority = uri.authority().ok_or("GATEWAY_ALLOWED_ORIGINS requires scheme and host")?;
        // A browser Origin is a serialized scheme/host/port tuple, not a URL
        // with a path, credentials, wildcard, fragment, or opaque `null` origin.
        if !matches!(uri.scheme_str(), Some("http" | "https"))
            || authority.host().is_empty() || authority.as_str().contains('@')
            || origin.contains('*') || origin.contains('#')
            || origin != format!("{}://{}", uri.scheme_str().unwrap(), authority)
        {
            return Err("GATEWAY_ALLOWED_ORIGINS requires exact http(s) origins without paths or wildcards".into());
        }
        HeaderValue::from_str(origin).map_err(|_| "GATEWAY_ALLOWED_ORIGINS contains an invalid header value".into())
    }).collect()
}

pub(crate) struct ServicePolicy {
    pub(crate) config: Config,
    slots: Arc<Semaphore>,
    http_slots: Arc<Semaphore>,
    client_shares: Arc<ClientShares>,
    socket_finished: Arc<tokio::sync::Notify>,
    pub(crate) shutdown: Arc<Shutdown>,
}

pub(crate) struct ConnectionPermit {
    slot: Option<OwnedSemaphorePermit>,
    finished: Arc<tokio::sync::Notify>,
}
impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        drop(self.slot.take());
        self.finished.notify_one();
    }
}

impl ServicePolicy {
    pub(crate) fn new(config: Config) -> Self {
        Self {
            slots: Arc::new(Semaphore::new(config.max_connections)),
            http_slots: Arc::new(Semaphore::new(config.http_max_in_flight)),
            client_shares: Arc::new(ClientShares {
                limit: config.http_max_in_flight_per_client,
                in_flight: std::sync::Mutex::new(HashMap::new()),
            }),
            socket_finished: Arc::new(tokio::sync::Notify::new()),
            shutdown: Arc::new(Shutdown::default()),
            config,
        }
    }

    pub(crate) fn from_env(prod: bool) -> Result<Self, String> {
        Config::from_env(prod).map(Self::new)
    }

    pub(crate) fn cors(&self) -> CorsLayer {
        CorsLayer::new()
            .allow_origin(self.config.allowed_origins.clone())
            .allow_methods([Method::GET, Method::POST, Method::DELETE, Method::OPTIONS])
            .allow_headers([
                header::CONTENT_TYPE,
                header::AUTHORIZATION,
                header::HeaderName::from_static("x-api-key"),
                header::HeaderName::from_static("x-admin-key"),
            ])
    }

    pub(crate) fn origin_allowed(&self, headers: &HeaderMap) -> bool {
        let mut origins = headers.get_all(header::ORIGIN).iter();
        match (origins.next(), origins.next()) {
            (None, _) => true,
            (Some(origin), None) => self.config.allowed_origins.contains(origin),
            _ => false,
        }
    }

    pub(crate) fn admit(&self, headers: &HeaderMap) -> Result<ConnectionPermit, StatusCode> {
        if !self.origin_allowed(headers) {
            return Err(StatusCode::FORBIDDEN);
        }
        if self.shutdown.started() {
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
        let slot = self
            .slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        Ok(ConnectionPermit {
            slot: Some(slot),
            finished: self.socket_finished.clone(),
        })
    }

    pub(crate) async fn wait_for_sockets(&self) {
        loop {
            // Register before checking to avoid losing the final permit's wake-up.
            let finished = self.socket_finished.notified();
            if self.slots.available_permits() == self.config.max_connections {
                return;
            }
            finished.await;
        }
    }

    pub(crate) fn configure(&self, ws: WebSocketUpgrade) -> WebSocketUpgrade {
        ws.max_message_size(self.config.max_message_bytes)
            .max_frame_size(self.config.max_frame_bytes)
            .write_buffer_size(self.config.write_buffer_bytes)
            .max_write_buffer_size(self.config.max_write_buffer_bytes)
    }

    pub(crate) fn message_budget(&self) -> MessageBudget {
        MessageBudget {
            remaining: self.config.messages_per_second,
            limit: self.config.messages_per_second,
            window: tokio::time::Instant::now(),
        }
    }

    pub(crate) async fn send(&self, socket: &mut WebSocket, message: Message) -> bool {
        matches!(
            tokio::time::timeout(self.config.send_timeout, socket.send(message)).await,
            Ok(Ok(()))
        )
    }
}

/// Per-client share of the HTTP slots, so one source cannot hold all of them (e.g.
/// with slow request bodies). An entry exists only while that client has a request in
/// flight, so the map is bounded by the requests being admitted.
struct ClientShares {
    limit: usize,
    in_flight: std::sync::Mutex<HashMap<IpAddr, usize>>,
}

/// One admitted request's share; released on drop.
struct ClientSlot {
    shares: Arc<ClientShares>,
    client: IpAddr,
}
impl Drop for ClientSlot {
    fn drop(&mut self) {
        let mut in_flight = self
            .shares
            .in_flight
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if let Some(n) = in_flight.get_mut(&self.client) {
            *n -= 1;
            if *n == 0 {
                in_flight.remove(&self.client);
            }
        }
    }
}

impl ClientShares {
    fn acquire(self: &Arc<Self>, client: IpAddr) -> Option<ClientSlot> {
        let mut in_flight = self.in_flight.lock().unwrap_or_else(|e| e.into_inner());
        let n = in_flight.entry(client).or_insert(0);
        if *n >= self.limit {
            return None;
        }
        *n += 1;
        Some(ClientSlot {
            shares: self.clone(),
            client,
        })
    }
}

/// The per-client key for a client address (HTTP slot share and registration limit).
/// IPv6 is keyed by its /64 — one subscriber usually controls a whole /64, so
/// per-address keys would not bound it.
pub(crate) fn client_share_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6((u128::from(v6) & !((1u128 << 64) - 1)).into()),
        },
    }
}

/// Reject an unapproved browser origin before a handler can mutate state; CORS
/// response headers alone would only prevent the browser from reading its reply.
pub(crate) async fn enforce_origin(
    State(policy): State<Arc<ServicePolicy>>,
    request: Request,
    next: Next,
) -> Response {
    if !policy.origin_allowed(request.headers()) {
        return (StatusCode::FORBIDDEN, "origin not allowed").into_response();
    }
    if policy.shutdown.started() {
        return (StatusCode::SERVICE_UNAVAILABLE, "gateway is draining").into_response();
    }
    // The client is the proxy-reported address when the peer is the trusted loopback
    // proxy (same rule as the registration limiter). Without connection info (an
    // in-process test router) only the global cap applies.
    let client = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(peer)| client_share_key(super::client_ip(*peer, request.headers())));
    let _client_slot = match client {
        Some(client) => match policy.client_shares.acquire(client) {
            Some(slot) => Some(slot),
            None => {
                return (
                    StatusCode::TOO_MANY_REQUESTS,
                    "too many concurrent requests from this client",
                )
                    .into_response()
            }
        },
        None => None,
    };
    let Ok(_permit) = policy.http_slots.clone().try_acquire_owned() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "gateway request capacity reached",
        )
            .into_response();
    };
    // Only body intake is timed out. Do not drop an accepted mutation halfway
    // through durability/settlement and pretend it was never performed.
    let (parts, body) = request.into_parts();
    let body = match tokio::time::timeout(
        policy.config.http_body_timeout,
        axum::body::to_bytes(body, policy.config.http_max_body_bytes),
    )
    .await
    {
        Err(_) => return (StatusCode::REQUEST_TIMEOUT, "request body timed out").into_response(),
        Ok(Err(_)) => {
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                "request body exceeds limit or is invalid",
            )
                .into_response()
        }
        Ok(Ok(body)) => body,
    };
    next.run(Request::from_parts(parts, axum::body::Body::from(body)))
        .await
}

pub(crate) struct MessageBudget {
    remaining: usize,
    limit: usize,
    window: tokio::time::Instant,
}

impl MessageBudget {
    /// Count every received message, including invalid JSON and control messages,
    /// before parsing/authentication. State is bounded per admitted connection.
    pub(crate) fn take(&mut self) -> bool {
        let now = tokio::time::Instant::now();
        if now.duration_since(self.window) >= Duration::from_secs(1) {
            self.window = now;
            self.remaining = self.limit;
        }
        if self.remaining == 0 {
            return false;
        }
        self.remaining -= 1;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, extract::Extension, http::Request, middleware, routing::get, Router};
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::{
        connect_async,
        tungstenite::{client::IntoClientRequest, Message as ClientMessage},
    };
    use tower::ServiceExt;

    fn config(pairs: &[(&str, &str)], prod: bool) -> Result<Config, String> {
        Config::from_lookup(prod, |name| {
            Ok(pairs
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| value.to_string()))
        })
    }

    #[test]
    fn origin_policy_is_explicit_and_configuration_is_fail_closed() {
        let local = ServicePolicy::new(config(&[], false).unwrap());
        for origin in ["http://localhost:5173", "http://127.0.0.1:4173"] {
            let mut headers = HeaderMap::new();
            headers.insert(header::ORIGIN, origin.parse().unwrap());
            assert!(local.origin_allowed(&headers));
            headers.append(header::ORIGIN, origin.parse().unwrap());
            assert!(!local.origin_allowed(&headers));
        }
        let prod = ServicePolicy::new(config(&[], true).unwrap());
        let mut headers = HeaderMap::new();
        assert!(prod.origin_allowed(&headers));
        headers.insert(header::ORIGIN, "http://localhost:5173".parse().unwrap());
        assert!(!prod.origin_allowed(&headers));
        for invalid in [
            "*",
            "null",
            "https://example.com/",
            "https://example.com/path",
            "https://user@example.com",
            "https://*.example.com",
            "https://example.com#fragment",
            "https://example.com,",
        ] {
            assert!(parse_origins(invalid).is_err(), "{invalid}");
        }
        assert!(config(&[("GATEWAY_WS_MAX_CONNECTIONS", "0")], false).is_err());
        assert!(config(&[("GATEWAY_WS_SEND_TIMEOUT_MS", "bad")], false).is_err());
        assert!(config(&[("GATEWAY_WS_MAX_WRITE_BUFFER_BYTES", "16384")], false).is_err());
        assert!(config(
            &[
                ("GATEWAY_HTTP_MAX_IN_FLIGHT", "4"),
                ("GATEWAY_HTTP_MAX_IN_FLIGHT_PER_CLIENT", "5")
            ],
            false
        )
        .is_err());
        // unset per-client share: 8, capped by a lower global limit
        assert_eq!(config(&[], false).unwrap().http_max_in_flight_per_client, 8);
        assert_eq!(
            config(&[("GATEWAY_HTTP_MAX_IN_FLIGHT", "4")], false)
                .unwrap()
                .http_max_in_flight_per_client,
            4
        );
    }

    #[test]
    fn client_share_key_groups_ipv6_by_slash_64() {
        let v4: IpAddr = "198.51.100.7".parse().unwrap();
        assert_eq!(client_share_key(v4), v4);
        let mapped: IpAddr = "::ffff:198.51.100.7".parse().unwrap();
        assert_eq!(client_share_key(mapped), v4);
        let a: IpAddr = "2001:db8:1:2:aaaa::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:ffff:ffff:ffff:ffff".parse().unwrap();
        let other: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert_eq!(
            client_share_key(a),
            "2001:db8:1:2::".parse::<IpAddr>().unwrap()
        );
        assert_eq!(client_share_key(a), client_share_key(b));
        assert_ne!(client_share_key(a), client_share_key(other));
    }

    /// One source holding slow requests (e.g. slow bodies) used to be able to take
    /// every global HTTP slot; now it is capped at its share and others still get in.
    #[tokio::test]
    async fn one_client_cannot_hold_every_http_slot() {
        let policy = Arc::new(ServicePolicy::new(
            config(
                &[
                    ("GATEWAY_HTTP_MAX_IN_FLIGHT", "4"),
                    ("GATEWAY_HTTP_MAX_IN_FLIGHT_PER_CLIENT", "2"),
                ],
                false,
            )
            .unwrap(),
        ));
        let gate = Arc::new(Semaphore::new(0));
        let handler_gate = gate.clone();
        let app = Router::new()
            .route(
                "/",
                get(move || {
                    let gate = handler_gate.clone();
                    async move {
                        let _ = gate.acquire().await;
                        StatusCode::NO_CONTENT
                    }
                }),
            )
            .layer(middleware::from_fn_with_state(
                policy.clone(),
                enforce_origin,
            ));
        let from = |peer: &str, forwarded: Option<&str>| {
            let mut request = Request::get("/").extension(axum::extract::ConnectInfo(
                peer.parse::<SocketAddr>().unwrap(),
            ));
            if let Some(ip) = forwarded {
                request = request.header("x-forwarded-for", ip);
            }
            request.body(Body::empty()).unwrap()
        };
        let wait_for_free = |free: usize| {
            let policy = policy.clone();
            async move {
                tokio::time::timeout(Duration::from_secs(5), async {
                    while policy.http_slots.available_permits() != free {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .expect("requests reach the handler");
            }
        };
        let mut held = Vec::new();
        for _ in 0..2 {
            held.push(tokio::spawn(
                app.clone().oneshot(from("198.51.100.7:1000", None)),
            ));
        }
        wait_for_free(2).await;
        // The same client is refused at its share, without consuming a global slot.
        let refused = app
            .clone()
            .oneshot(from("198.51.100.7:1001", None))
            .await
            .unwrap();
        assert_eq!(refused.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(policy.http_slots.available_permits(), 2);
        // Behind the trusted loopback proxy the forwarded address is the client, so a
        // different real client still gets a slot...
        held.push(tokio::spawn(
            app.clone()
                .oneshot(from("127.0.0.1:1002", Some("203.0.113.9"))),
        ));
        wait_for_free(1).await;
        // ...while the hog cannot dodge its share through the proxy either.
        let refused = app
            .clone()
            .oneshot(from("127.0.0.1:1003", Some("198.51.100.7")))
            .await
            .unwrap();
        assert_eq!(refused.status(), StatusCode::TOO_MANY_REQUESTS);
        gate.add_permits(16);
        for request in held {
            assert_eq!(
                request.await.unwrap().unwrap().status(),
                StatusCode::NO_CONTENT
            );
        }
        assert_eq!(policy.http_slots.available_permits(), 4);
        assert!(policy.client_shares.in_flight.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn disallowed_origin_is_rejected_before_handler_and_cors_is_exact() {
        let policy = Arc::new(ServicePolicy::new(config(&[], false).unwrap()));
        let app = Router::new()
            .route("/", get(|| async { StatusCode::NO_CONTENT }))
            .layer(policy.cors())
            .layer(middleware::from_fn_with_state(policy, enforce_origin));
        for (origin, expected) in [
            ("https://untrusted.invalid", StatusCode::FORBIDDEN),
            ("http://localhost:5173", StatusCode::NO_CONTENT),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::get("/")
                        .header(header::ORIGIN, origin)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), expected);
            assert_eq!(
                response
                    .headers()
                    .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                    .and_then(|v| v.to_str().ok()),
                (expected == StatusCode::NO_CONTENT).then_some(origin)
            );
        }
        let preflight = app
            .oneshot(
                Request::builder()
                    .method(Method::OPTIONS)
                    .uri("/")
                    .header(header::ORIGIN, "http://127.0.0.1:4173")
                    .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
                    .header(
                        header::ACCESS_CONTROL_REQUEST_HEADERS,
                        "content-type,x-api-key",
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(preflight.status(), StatusCode::OK);
        assert_eq!(
            preflight
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap(),
            "http://127.0.0.1:4173"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn message_budget_is_per_connection_and_refills_after_one_second() {
        let policy =
            ServicePolicy::new(config(&[("GATEWAY_WS_MESSAGES_PER_SECOND", "2")], false).unwrap());
        let mut budget = policy.message_budget();
        assert!(budget.take());
        assert!(budget.take());
        assert!(!budget.take());
        let mut other = policy.message_budget();
        assert!(other.take());
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(budget.take());
    }

    async fn ws(
        Extension(policy): Extension<Arc<ServicePolicy>>,
        headers: HeaderMap,
        ws: WebSocketUpgrade,
    ) -> Response {
        let permit = match policy.admit(&headers) {
            Ok(permit) => permit,
            Err(code) => return code.into_response(),
        };
        policy
            .configure(ws)
            .on_upgrade(move |mut socket| async move {
                let _permit = permit;
                let mut budget = policy.message_budget();
                while let Some(Ok(message)) = socket.recv().await {
                    if !budget.take() {
                        break;
                    }
                    if matches!(message, Message::Close(_)) {
                        break;
                    }
                    if !policy.send(&mut socket, message).await {
                        break;
                    }
                }
            })
    }

    #[tokio::test]
    async fn loopback_upgrade_caps_connections_messages_and_releases_on_close() {
        let policy = Arc::new(ServicePolicy::new(
            config(
                &[
                    ("GATEWAY_WS_MAX_CONNECTIONS", "1"),
                    ("GATEWAY_WS_MAX_MESSAGE_BYTES", "64"),
                    ("GATEWAY_WS_MAX_FRAME_BYTES", "64"),
                ],
                false,
            )
            .unwrap(),
        ));
        let app = Router::new()
            .route("/ws", get(ws))
            .layer(Extension(policy.clone()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}/ws", listener.local_addr().unwrap());
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = stop_rx.await;
                })
                .await
                .unwrap();
        });
        let mut bad = url.clone().into_client_request().unwrap();
        bad.headers_mut()
            .insert(header::ORIGIN, "https://untrusted.invalid".parse().unwrap());
        assert!(
            matches!(connect_async(bad).await, Err(tokio_tungstenite::tungstenite::Error::Http(response)) if response.status() == StatusCode::FORBIDDEN)
        );
        let (mut client, _) = connect_async(&url).await.unwrap();
        assert!(
            matches!(connect_async(&url).await, Err(tokio_tungstenite::tungstenite::Error::Http(response)) if response.status() == StatusCode::SERVICE_UNAVAILABLE)
        );
        client
            .send(ClientMessage::Text("valid".into()))
            .await
            .unwrap();
        assert_eq!(
            client.next().await.unwrap().unwrap(),
            ClientMessage::Text("valid".into())
        );
        client
            .send(ClientMessage::Text("x".repeat(65)))
            .await
            .unwrap();
        // Oversize input closes the server task and returns the only slot.
        let closed = tokio::time::timeout(Duration::from_secs(2), client.next())
            .await
            .unwrap();
        assert!(matches!(
            closed,
            None | Some(Err(_)) | Some(Ok(ClientMessage::Close(_)))
        ));
        let (mut replacement, _) = connect_async(&url).await.unwrap();
        replacement.close(None).await.unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(2), replacement.next()).await;
        stop_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(policy.slots.available_permits(), 1);
    }
}

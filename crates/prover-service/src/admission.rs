//! Authenticate and reserve scarce proof capacity before polling request bodies.
//! An admitted request owns its slot until decoding/proving finishes. Moving the
//! permit into the blocking worker keeps that bound valid after HTTP cancellation.
use axum::{
    extract::{FromRef, FromRequest, FromRequestParts, Request},
    http::{header::AUTHORIZATION, request::Parts, HeaderMap, StatusCode},
    Json,
};
use dark_perp_attestation::ct_eq;
use std::{sync::Arc, time::Duration};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};

pub(crate) const MAX_BODY_BYTES: usize = 512 * 1024 * 1024;

#[derive(Clone)]
pub(crate) struct Limits {
    pub(crate) max_concurrent: usize,
    pub(crate) body_bytes: usize,
    pub(crate) body_timeout: Duration,
}

impl Limits {
    pub(crate) fn from_env() -> Result<Self, String> {
        Ok(Self {
            max_concurrent: positive_env("PROVER_MAX_CONCURRENT", 1, 8)?,
            body_bytes: positive_env("PROVER_MAX_BODY_BYTES", MAX_BODY_BYTES, MAX_BODY_BYTES)?,
            body_timeout: Duration::from_secs(
                positive_env("PROVER_BODY_TIMEOUT_SECS", 30, 300)? as u64
            ),
        })
    }
}

fn positive_env(name: &str, default: usize, maximum: usize) -> Result<usize, String> {
    match std::env::var(name) {
        Ok(value) => positive_value(name, &value, maximum),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(_) => Err(format!("{name} must be valid UTF-8")),
    }
}

fn positive_value(name: &str, value: &str, maximum: usize) -> Result<usize, String> {
    value
        .parse::<usize>()
        .ok()
        .filter(|v| (1..=maximum).contains(v))
        .ok_or_else(|| format!("{name} must be an integer in 1..={maximum}"))
}

#[derive(Clone)]
pub(crate) struct Gate {
    token: Option<String>,
    not_after: u64,
    slots: Arc<Semaphore>,
    capacity: usize,
    released: Arc<Notify>,
}

impl Gate {
    pub(crate) fn new(token: Option<String>, not_after: u64, max_concurrent: usize) -> Self {
        assert!((1..=8).contains(&max_concurrent));
        Self {
            token,
            not_after,
            slots: Arc::new(Semaphore::new(max_concurrent)),
            capacity: max_concurrent,
            released: Arc::new(Notify::new()),
        }
    }

    /// New admissions fail immediately; already-held worker permits remain live.
    pub(crate) fn close(&self) {
        self.slots.close();
    }

    /// Wait while Tokio is still running, including for workers whose HTTP
    /// waiter was cancelled. Merely dropping the runtime waits for blocking
    /// threads but tears down async services that those threads may still use.
    pub(crate) async fn drain(&self) {
        self.close();
        loop {
            // Subscribe before checking permits so the final release cannot
            // occur in a check-to-wait gap and leave shutdown asleep forever.
            let notified = self.released.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.slots.available_permits() == self.capacity {
                return;
            }
            notified.await;
        }
    }

    #[cfg(test)]
    pub(crate) fn test_status(&self) -> (bool, usize) {
        (self.slots.is_closed(), self.slots.available_permits())
    }

    fn admit(
        &self,
        headers: &HeaderMap,
        now_ms: u64,
    ) -> Result<ProofAdmission, (StatusCode, String)> {
        if !session_authorized(self.token.as_deref(), self.not_after, headers, now_ms) {
            return Err((
                StatusCode::UNAUTHORIZED,
                "attestation session required".into(),
            ));
        }
        self.slots
            .clone()
            .try_acquire_owned()
            .map(|permit| ProofAdmission {
                permit: Some(permit),
                released: self.released.clone(),
            })
            .map_err(|_| {
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "prover busy or shutting down".into(),
                )
            })
    }
}

pub(crate) fn session_authorized(
    stored: Option<&str>,
    not_after: u64,
    headers: &HeaderMap,
    now_ms: u64,
) -> bool {
    let Some(stored) = stored.filter(|t| !t.is_empty()) else {
        return false;
    };
    // Reject duplicate credentials rather than allowing intermediaries to choose
    // a different Authorization field from the one validated here.
    if headers.get_all(AUTHORIZATION).iter().count() != 1 {
        return false;
    }
    let Some(bearer) = headers
        .get(AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
    else {
        return false;
    };
    ct_eq(bearer.as_bytes(), stored.as_bytes()) && now_ms <= not_after
}

pub(crate) struct ProofAdmission {
    permit: Option<OwnedSemaphorePermit>,
    released: Arc<Notify>,
}

impl Drop for ProofAdmission {
    fn drop(&mut self) {
        // Return capacity before waking the drainer; waking first could leave
        // it observing a held slot with no later notification.
        drop(self.permit.take());
        self.released.notify_waiters();
    }
}

impl ProofAdmission {
    /// The permit belongs to the blocking work, including after an HTTP waiter
    /// is dropped. Runtime shutdown waits for that work rather than aborting it.
    pub(crate) async fn run_blocking<F, T>(self, work: F) -> Result<T, tokio::task::JoinError>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        tokio::task::spawn_blocking(move || {
            let _admission = self;
            work()
        })
        .await
    }
}

/// Bound body reception after admission. Synchronous JSON parsing still has the
/// configured byte cap; a cooperative timeout cannot preempt CPU-only parsing.
pub(crate) async fn read_json<T, S>(
    request: Request,
    state: &S,
    timeout: Duration,
) -> Result<Json<T>, (StatusCode, String)>
where
    T: serde::de::DeserializeOwned,
    S: Send + Sync,
{
    tokio::time::timeout(timeout, Json::<T>::from_request(request, state))
        .await
        .map_err(|_| (StatusCode::REQUEST_TIMEOUT, "proof body timed out".into()))?
        .map_err(|error| (error.status(), error.body_text()))
}

#[axum::async_trait]
impl<S> FromRequestParts<S> for ProofAdmission
where
    Gate: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = (StatusCode, String);

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(u64::MAX, |d| d.as_millis().try_into().unwrap_or(u64::MAX));
        Gate::from_ref(state).admit(&parts.headers, now_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        extract::{DefaultBodyLimit, State},
        http::Request,
        routing::post,
        Router,
    };
    use std::sync::atomic::{AtomicBool, Ordering};
    use tower::ServiceExt;

    fn headers(token: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, format!("Bearer {token}").parse().unwrap());
        headers
    }

    fn router(gate: Gate) -> Router {
        Router::new()
            .route(
                "/prove",
                post(
                    |State(gate): State<Gate>,
                     _permit: ProofAdmission,
                     request: axum::extract::Request| async move {
                        read_json::<serde_json::Value, _>(request, &gate, Duration::from_millis(20))
                            .await
                            .map(|_| StatusCode::NO_CONTENT)
                    },
                ),
            )
            .layer(DefaultBodyLimit::max(32))
            .with_state(gate)
    }

    fn request(auth: Option<&str>, body: Body) -> Request<Body> {
        let mut req = Request::post("/prove").header("content-type", "application/json");
        if let Some(auth) = auth {
            req = req.header(AUTHORIZATION, auth);
        }
        req.body(body).unwrap()
    }

    fn unpolled_body() -> Body {
        Body::from_stream(futures_util::stream::poll_fn(
            |_| -> std::task::Poll<Option<Result<Vec<u8>, std::io::Error>>> {
                panic!("rejected request body must never be polled")
            },
        ))
    }

    #[tokio::test]
    async fn authentication_precedes_body_polling_and_json_errors() {
        let app = router(Gate::new(Some("test".into()), u64::MAX, 1));
        for auth in [None, Some("Bearer wrong")] {
            let res = app
                .clone()
                .oneshot(request(auth, unpolled_body()))
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        }
        let expired = router(Gate::new(Some("test".into()), 0, 1));
        assert_eq!(
            expired
                .oneshot(request(Some("Bearer test"), unpolled_body()))
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        for token in [None, Some(String::new())] {
            assert_eq!(
                router(Gate::new(token, u64::MAX, 1))
                    .oneshot(request(Some("Bearer test"), unpolled_body()))
                    .await
                    .unwrap()
                    .status(),
                StatusCode::UNAUTHORIZED
            );
        }
        let invalid = app
            .clone()
            .oneshot(request(Some("Bearer test"), Body::from("{")))
            .await
            .unwrap();
        assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
        let oversized = app
            .clone()
            .oneshot(request(Some("Bearer test"), Body::from("x".repeat(33))))
            .await
            .unwrap();
        assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
        // Both rejection paths released the only slot.
        assert_eq!(
            app.oneshot(request(Some("Bearer test"), Body::from("{}")))
                .await
                .unwrap()
                .status(),
            StatusCode::NO_CONTENT
        );
    }

    #[tokio::test]
    async fn overload_is_rejected_before_body_polling_and_shutdown_stays_closed() {
        let gate = Gate::new(Some("test".into()), u64::MAX, 1);
        let slot = gate.admit(&headers("test"), 0).unwrap();
        assert_eq!(
            router(gate.clone())
                .oneshot(request(Some("Bearer test"), unpolled_body()))
                .await
                .unwrap()
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        drop(slot);
        assert!(gate.admit(&headers("test"), 0).is_ok());
        gate.close();
        assert_eq!(
            router(gate)
                .oneshot(request(Some("Bearer test"), unpolled_body()))
                .await
                .unwrap()
                .status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[tokio::test]
    async fn admitted_stalled_body_times_out_and_releases_its_slot() {
        let gate = Gate::new(Some("test".into()), u64::MAX, 1);
        let pending = Body::from_stream(futures_util::stream::pending::<
            Result<Vec<u8>, std::io::Error>,
        >());
        let response = router(gate.clone())
            .oneshot(request(Some("Bearer test"), pending))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
        assert!(gate.admit(&headers("test"), 0).is_ok());
    }

    #[tokio::test]
    async fn cancelling_waiter_does_not_release_a_running_blocking_worker_slot() {
        let gate = Gate::new(Some("test".into()), u64::MAX, 1);
        let permit = gate.admit(&headers("test"), 0).unwrap();
        let finished = Arc::new(AtomicBool::new(false));
        let finished_worker = finished.clone();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let (completed_tx, completed_rx) = tokio::sync::oneshot::channel();
        let waiter = tokio::spawn(async move {
            permit
                .run_blocking(move || {
                    started_tx.send(()).unwrap();
                    release_rx.recv_timeout(Duration::from_secs(2)).unwrap();
                    finished_worker.store(true, Ordering::SeqCst);
                    completed_tx.send(()).unwrap();
                })
                .await
                .unwrap();
        });
        started_rx.await.unwrap();
        waiter.abort(); // Cancel the actual async waiter, not the blocking task.
        assert!(waiter.await.unwrap_err().is_cancelled());
        assert!(gate.admit(&headers("test"), 0).is_err());
        release_tx.send(()).unwrap();
        completed_rx.await.unwrap();
        // Completion is sent inside the closure; the permit drops immediately
        // after it returns, so synchronize on its release rather than racing it.
        tokio::time::timeout(Duration::from_secs(2), async {
            while gate.test_status().1 == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(finished.load(Ordering::SeqCst));
        assert!(gate.admit(&headers("test"), 0).is_ok());
    }

    #[tokio::test]
    async fn worker_panic_remains_an_error_and_does_not_strand_shutdown() {
        let gate = Gate::new(Some("test".into()), u64::MAX, 1);
        let permit = gate.admit(&headers("test"), 0).unwrap();
        let outcome = permit
            .run_blocking(|| panic!("injected worker failure"))
            .await;
        assert!(
            outcome.unwrap_err().is_panic(),
            "worker failure cannot become a successful result"
        );
        tokio::time::timeout(Duration::from_secs(2), gate.drain())
            .await
            .unwrap();
        assert_eq!(gate.test_status(), (true, 1));
        assert!(gate.admit(&headers("test"), 0).is_err());
    }

    #[test]
    fn token_and_configuration_boundaries_fail_closed() {
        let mut auth = headers("test");
        assert!(session_authorized(Some("test"), 42, &auth, 42));
        assert!(!session_authorized(Some("test"), 42, &auth, 43));
        assert!(!session_authorized(Some("wrong"), 42, &auth, 42));
        assert!(!session_authorized(Some("tesu"), 42, &auth, 42));
        auth.append(AUTHORIZATION, "Bearer test".parse().unwrap());
        assert!(!session_authorized(Some("test"), 42, &auth, 42));
        for invalid in ["0", "9", "-1", "", "not-a-number"] {
            assert!(positive_value("PROVER_MAX_CONCURRENT", invalid, 8).is_err());
        }
        assert_eq!(positive_value("PROVER_MAX_CONCURRENT", "1", 8).unwrap(), 1);
    }
}

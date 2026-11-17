//! One open execution window at a time in clock mode. Admission is rejected,
//! not queued, while registration/proving/finality owns the exclusive permit.
//! A sealed-but-unresolved window leaves a sticky hold even if its task panics.
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::sync::{OwnedRwLockReadGuard, OwnedRwLockWriteGuard, RwLock};

pub(crate) struct ClockAdmission {
    enabled: bool,
    closed: AtomicBool,
    lock: Arc<RwLock<()>>,
}
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Status {
    enabled: bool,
    paused: bool,
}
impl ClockAdmission {
    pub(crate) fn status(&self) -> Status {
        Status {
            enabled: self.enabled,
            paused: self.enabled && self.closed.load(Ordering::Acquire),
        }
    }
    pub(crate) fn new(enabled: bool) -> Arc<Self> {
        Arc::new(Self {
            enabled,
            closed: AtomicBool::new(false),
            lock: Arc::new(RwLock::new(())),
        })
    }
    pub(crate) fn enter(&self) -> Result<Option<OwnedRwLockReadGuard<()>>, &'static str> {
        if !self.enabled {
            return Ok(None);
        }
        if self.closed.load(Ordering::Acquire) {
            return Err(BUSY);
        }
        let permit = self.lock.clone().try_read_owned().map_err(|_| BUSY)?;
        if self.closed.load(Ordering::Acquire) {
            return Err(BUSY);
        }
        Ok(Some(permit))
    }
    pub(crate) async fn pause(
        self: &Arc<Self>,
        stop: &crate::service_shutdown::Shutdown,
    ) -> Result<Option<Paused>, &'static str> {
        if !self.enabled {
            return Ok(None);
        }
        let was_closed = self.closed.swap(true, Ordering::AcqRel);
        let permit = tokio::select! {
            biased;
            _ = stop.cancelled() => return Err("shutdown while draining clock admission"),
            permit = self.lock.clone().write_owned() => permit,
        };
        Ok(Some(Paused {
            owner: self.clone(),
            _permit: permit,
            armed: was_closed,
        }))
    }
}

/// The refusal of every admission while a clock window owns the exclusive permit.
pub(crate) const BUSY: &str = "clock settlement in progress; retry after finality";

/// The answer to a request refused while admission is closed: 503 with
/// `Retry-After`, a polling hint (a settlement takes as long as it takes).
pub(crate) fn closed_response(error: &str) -> axum::response::Response {
    use axum::response::IntoResponse;
    (
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        [(axum::http::header::RETRY_AFTER, "2")],
        axum::Json(serde_json::json!({ "error": error })),
    )
        .into_response()
}

/// Prefix of the refusal of a timed operation while the open window is closing
/// (`WindowBound`). The HTTP layer answers it 503 with `Retry-After`.
pub(crate) const WINDOW_CLOSING: &str = "CLOCK_WINDOW_CLOSING";

/// When the open clock window stops admitting timed operations (audit G2-2).
///
/// The verifier refuses to register a window whose timed operations span more
/// than `maxWindowMs`. Only the settle loop's seal bounds the open window, and
/// several conditions skip a seal (a failed batch-count read, a stale challenge
/// read, a failed snapshot) while ticks go on adding timed funding operations, so
/// the window is bounded here instead: once its first timed operation is
/// `cutoff_ms` old, no further timed operation (a tick's fills, funding and
/// liquidations, an order, a withdrawal) is admitted until it is sealed. The
/// cutoff leaves one seal period of `maxWindowMs`, so the next seal finds the
/// window inside the bound and its last timed operation at most a seal period
/// before the registration that follows. Runtime policy, read from the verifier
/// at boot; demo and legacy modes have none.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct WindowBound {
    pub timing: crate::l1::ClockTiming,
    /// No timed operation is admitted once the window's first one is this old.
    pub cutoff_ms: u64,
    /// The settle loop's seal period.
    pub seal_period_ms: u64,
}
impl WindowBound {
    pub(crate) fn new(timing: crate::l1::ClockTiming, seal_period: std::time::Duration) -> Self {
        let period = u64::try_from(seal_period.as_millis()).unwrap_or(u64::MAX);
        Self {
            timing,
            cutoff_ms: timing.max_window_ms.saturating_sub(period),
            seal_period_ms: period,
        }
    }
    /// Whether a window whose first timed operation is at `first_ms` stops
    /// admitting timed operations at `now_ms`.
    pub(crate) fn closing(&self, first_ms: u64, now_ms: u64) -> bool {
        now_ms.saturating_sub(first_ms) >= self.cutoff_ms
    }
    /// Whether that window is within one seal period of `closing`. A window is
    /// sealed every seal period, so only one whose seals were skipped gets here.
    pub(crate) fn near_closing(&self, first_ms: u64, now_ms: u64) -> bool {
        now_ms.saturating_sub(first_ms) >= self.cutoff_ms.saturating_sub(self.seal_period_ms)
    }
}

pub(crate) struct Paused {
    owner: Arc<ClockAdmission>,
    _permit: OwnedRwLockWriteGuard<()>,
    armed: bool,
}
impl Paused {
    /// Call as soon as the window is sealed. Only a durable resolution may reopen.
    pub(crate) fn arm(&mut self) {
        self.armed = true;
    }
    pub(crate) fn resolved(&mut self) {
        self.armed = false;
    }
}
impl Drop for Paused {
    fn drop(&mut self) {
        if !self.armed {
            self.owner.closed.store(false, Ordering::Release);
        }
    }
}

/// Mutating routes the HTTP gate admits without holding the permit (audit G2-1).
/// Each reads L1, or waits for a lock held across L1 reads, before it changes
/// anything. The settle loop's pause closes admission and then waits for every
/// permit, so a permit held across that wait would make the seal wait for a slow
/// or rate-limited RPC while the open window's registration budget runs out.
/// They are still refused while admission is closed, and each takes the permit
/// itself after its L1 work, only for what it changes and makes durable, and
/// answers 503 with `Retry-After` if admission closed meanwhile.
fn admitted_without_permit(path: &str) -> bool {
    matches!(
        path,
        // The deposit scan (`deposit_ingestion::ingest_once`).
        "/v1/accounts/deposit/onchain"
            | "/v1/admin/insurance/bootstrap"
            // Waits for the deposit lock the scan holds across its reads.
            | "/v1/accounts/deposit/route"
            // Reads the settlement's deposit terms at the latest block.
            | "/v1/accounts/deposit/authorize"
            // Reads the L1 wind-down phase in close-only.
            | "/v1/accounts/withdraw"
            // Reads L1 close-only and, for the rebase, the finalized settled state.
            | "/v1/admin/wind-down"
            // Reads `slashCount()`; changes nothing a window holds.
            | "/v1/admin/bond/acknowledge-slash"
    )
}

pub(crate) async fn http_gate(
    axum::extract::State(app): axum::extract::State<crate::Shared>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let readonly = matches!(
        *request.method(),
        axum::http::Method::GET | axum::http::Method::HEAD | axum::http::Method::OPTIONS
    );
    // These endpoints only request recovery or cancel a dead L1 anchor; they
    // cannot mutate financial state, and they are needed while a window holds
    // admission closed.
    let recovery = matches!(
        request.uri().path(),
        "/v1/admin/settlement/resume" | "/v1/admin/settlement/cancel-anchor"
    );
    let late = admitted_without_permit(request.uri().path());
    let _permit = if readonly || recovery {
        None
    } else {
        match app.clock_admission.enter() {
            Ok(_) if late => None,
            Ok(p) => p,
            Err(error) => return closed_response(error),
        }
    };
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower::ServiceExt;
    #[tokio::test]
    async fn clock_admission_drains_active_work_and_does_not_queue_new_work() {
        let a = ClockAdmission::new(true);
        let active = a.enter().unwrap();
        let stop = crate::service_shutdown::Shutdown::default();
        let mut waiting = Box::pin(a.pause(&stop));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(10), waiting.as_mut())
                .await
                .is_err()
        );
        assert!(a.enter().is_err());
        drop(active);
        let mut paused = waiting.await.unwrap().unwrap();
        paused.arm();
        assert!(a.enter().is_err());
        paused.resolved();
        drop(paused);
        assert!(a.enter().is_ok());
    }
    #[tokio::test]
    async fn clock_admission_unresolved_or_panicked_worker_never_reopens() {
        let a = ClockAdmission::new(true);
        let stop = crate::service_shutdown::Shutdown::default();
        let mut p = a.pause(&stop).await.unwrap().unwrap();
        p.arm();
        drop(p);
        assert!(a.enter().is_err());
        let p = a.pause(&stop).await.unwrap().unwrap();
        drop(p);
        assert!(a.enter().is_err());
    }
    #[tokio::test]
    async fn clock_admission_shutdown_interrupts_drain_without_reopening() {
        let a = ClockAdmission::new(true);
        let active = a.enter().unwrap();
        let stop = crate::service_shutdown::Shutdown::default();
        stop.begin();
        assert!(a.pause(&stop).await.is_err());
        drop(active);
        assert!(a.enter().is_err());
    }
    #[tokio::test]
    async fn clock_admission_http_refuses_mutation_but_preserves_reads() {
        let mut app = crate::tests::test_app();
        Arc::get_mut(&mut app).unwrap().clock_admission = ClockAdmission::new(true);
        let stop = crate::service_shutdown::Shutdown::default();
        let mut p = app.clock_admission.pause(&stop).await.unwrap().unwrap();
        p.arm();
        let before = app.gw.lock().await.snapshot_plain();
        let router = crate::build_router(app.clone(), false);
        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/accounts")
            .header("content-type", "application/json")
            .body(axum::body::Body::from("{}"))
            .unwrap();
        let response = router.clone().oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            axum::http::StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(response.headers()["retry-after"], "2");
        assert_eq!(app.gw.lock().await.snapshot_plain(), before);
        let response = router
            .oneshot(
                axum::http::Request::builder()
                    .uri("/v1/system/status")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
    }
    #[tokio::test]
    async fn clock_admission_status_exposes_pause_sticky_hold_and_resolution() {
        let mut app = crate::tests::test_app();
        Arc::get_mut(&mut app).unwrap().clock_admission = ClockAdmission::new(true);
        let stop = crate::service_shutdown::Shutdown::default();
        let router = crate::build_router(app.clone(), false);
        async fn read(router: axum::Router, path: &str) -> serde_json::Value {
            let response = router
                .oneshot(
                    axum::http::Request::builder()
                        .uri(path)
                        .body(axum::body::Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), axum::http::StatusCode::OK);
            let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
                .await
                .unwrap();
            serde_json::from_slice::<serde_json::Value>(&body).unwrap()["clockAdmission"].clone()
        }
        assert_eq!(
            read(router.clone(), "/api/state").await,
            serde_json::json!({"enabled": true, "paused": false})
        );
        let mut pause = app.clock_admission.pause(&stop).await.unwrap().unwrap();
        pause.arm();
        assert_eq!(read(router.clone(), "/api/state").await["paused"], true);
        assert_eq!(
            read(router.clone(), "/v1/system/status").await["paused"],
            true
        );
        let mut receiver = app.tx.subscribe();
        app.broadcast(&*app.gw.lock().await).await;
        let frame: serde_json::Value =
            serde_json::from_str(&receiver.recv().await.unwrap()).unwrap();
        assert_eq!(frame["state"]["clockAdmission"]["paused"], true);
        drop(pause);
        assert_eq!(read(router.clone(), "/api/state").await["paused"], true);
        let mut pause = app.clock_admission.pause(&stop).await.unwrap().unwrap();
        pause.resolved();
        drop(pause);
        assert_eq!(read(router, "/api/state").await["paused"], false);
    }
    #[tokio::test]
    async fn clock_admission_blocks_direct_deposit_intake_without_snapshot_changes() {
        let mut app = crate::tests::test_app();
        Arc::get_mut(&mut app).unwrap().clock_admission = ClockAdmission::new(true);
        let stop = crate::service_shutdown::Shutdown::default();
        let mut pause = app.clock_admission.pause(&stop).await.unwrap().unwrap();
        pause.arm();
        let before = app.gw.lock().await.snapshot_plain();
        let error = crate::deposit_ingestion::ingest_once(&app)
            .await
            .unwrap_err();
        assert!(error.contains("clock settlement"));
        assert_eq!(app.gw.lock().await.snapshot_plain(), before);
    }

    #[tokio::test]
    async fn clock_admission_legacy_mode_is_unchanged() {
        let a = ClockAdmission::new(false);
        let stop = crate::service_shutdown::Shutdown::default();
        assert!(a.pause(&stop).await.unwrap().is_none());
        assert!(a.enter().unwrap().is_none());
    }
}

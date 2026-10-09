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
impl ClockAdmission {
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
        const BUSY: &str = "clock settlement in progress; retry after finality";
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

pub(crate) async fn http_gate(
    axum::extract::State(app): axum::extract::State<crate::Shared>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let readonly = matches!(
        *request.method(),
        axum::http::Method::GET | axum::http::Method::HEAD | axum::http::Method::OPTIONS
    );
    // This endpoint only requests recovery; it cannot mutate financial state.
    let recovery = request.uri().path() == "/v1/admin/settlement/resume";
    let _permit = if readonly || recovery {
        None
    } else {
        match app.clock_admission.enter() {
            Ok(p) => p,
            Err(error) => {
                return (
                    axum::http::StatusCode::SERVICE_UNAVAILABLE,
                    [(axum::http::header::RETRY_AFTER, "2")],
                    axum::Json(serde_json::json!({"error": error})),
                )
                    .into_response()
            }
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

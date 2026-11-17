// Audit 2026-11-16 G2-1 + G2-2: a slow or rate-limited L1 RPC must not push an
// open clock window past the verifier's `maxWindowMs`. The deposit scan must not
// hold the clock admission permit across its L1 reads. These tests make no chain
// calls.
mod audit_1116_g2 {
    use super::*;
    use crate::deposit_ingestion::tests::{ack_every_snapshot, chained_blocks, fresh, permit};
    use crate::deposit_ingestion::Purpose;
    use crate::deposit_rpc::{Cursor, DepositSource, Error as ReadError, Page};
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A deposit source whose every read waits until the test releases it, like a
    /// provider that answers each of the scan's L1 calls slowly.
    struct SlowReader {
        page: Page,
        reading: std::sync::Mutex<std::sync::mpsc::Sender<()>>,
        release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
        calls: AtomicUsize,
    }
    impl DepositSource for SlowReader {
        fn fetch(&self, cursor: Cursor) -> Result<Page, ReadError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let _ = self.reading.lock().unwrap().send(());
            self.release
                .lock()
                .unwrap()
                .recv()
                .map_err(|_| ReadError::Retry("reader released without an answer".into()))?;
            Ok(if cursor == self.page.start {
                self.page.clone()
            } else {
                Page {
                    start: cursor,
                    end: self.page.end.clone(),
                    events: vec![],
                }
            })
        }
    }

    /// An app in clock mode whose deposit reads wait for the returned sender, with
    /// one permitted deposit landed in the next block. The receiver reports each
    /// read as it starts.
    fn slow_app() -> (
        Shared,
        Arc<SlowReader>,
        std::sync::mpsc::Sender<()>,
        std::sync::mpsc::Receiver<()>,
        tokio::task::JoinHandle<()>,
    ) {
        let mut gw = fresh();
        let (_, commit) = permit(&mut gw, 5_000_000, Purpose::Collateral, 0);
        let start = gw.deposit_cursor();
        let (end, events) = chained_blocks(&gw, &[&[commit]])
            .remove(&start.count)
            .unwrap();
        let (reading_tx, reading_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let source = Arc::new(SlowReader {
            page: Page { start, end, events },
            reading: std::sync::Mutex::new(reading_tx),
            release: std::sync::Mutex::new(release_rx),
            calls: 0.into(),
        });
        let mut app = test_app();
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        {
            let a = Arc::get_mut(&mut app).unwrap();
            a.clock_admission = clock_admission::ClockAdmission::new(true);
            a.snapshot_req = Some(tx);
            a.deposit_source = Some(source.clone());
            a.gw = Mutex::new(gw);
            a.gw.get_mut().deposits.required = true;
        }
        (app, source, release_tx, reading_rx, ack_every_snapshot(rx))
    }

    async fn read_started(reading: std::sync::mpsc::Receiver<()>) -> std::sync::mpsc::Receiver<()> {
        tokio::task::spawn_blocking(move || {
            reading
                .recv_timeout(Duration::from_secs(30))
                .expect("the deposit scan never started its L1 read");
            reading
        })
        .await
        .unwrap()
    }

    /// G2-1: the settle loop's pause closes admission and then waits for every
    /// admission permit. A deposit scan in the middle of a slow L1 read must not
    /// hold one, or the pause waits for the RPC while the window's registration
    /// budget runs out. The page read while admission closed is not applied; the
    /// next scan after the window resolves credits it.
    #[tokio::test]
    async fn audit_1116_g2_1_a_slow_deposit_read_does_not_hold_off_the_clock_pause() {
        let (app, source, release, reading, writer) = slow_app();
        let scan = tokio::spawn({
            let app = app.clone();
            async move { deposit_ingestion::ingest_once(&app).await }
        });
        let reading = read_started(reading).await;
        let stop = service_shutdown::Shutdown::default();
        let paused =
            tokio::time::timeout(Duration::from_secs(10), app.clock_admission.pause(&stop)).await;
        // Answer the read either way, so the scan always finishes.
        release.send(()).unwrap();
        let mut paused = paused
            .expect("the clock pause waited for the deposit scan's L1 read")
            .unwrap()
            .unwrap();
        let refused = scan.await.unwrap().unwrap_err();
        assert!(refused.contains("clock settlement"), "{refused}");
        {
            let gw = app.gw.lock().await;
            assert_eq!(gw.seq.state.consumed_deposit_count, 0);
            assert!(gw.deposits.credits.is_empty());
            assert_eq!(gw.deposits.halt, None);
        }
        paused.resolved();
        drop(paused);
        release.send(()).unwrap();
        assert_eq!(deposit_ingestion::ingest_once(&app).await.unwrap(), 1);
        let _ = read_started(reading).await;
        assert_eq!(source.calls.load(Ordering::SeqCst), 2);
        assert_eq!(app.gw.lock().await.seq.state.consumed_deposit_count, 1);
        writer.abort();
    }

    /// G2-1: POST /v1/accounts/deposit/onchain runs the same scan. The HTTP
    /// admission gate must not hold its permit across that scan's L1 reads either.
    #[tokio::test]
    async fn audit_1116_g2_1_a_deposit_confirmation_does_not_hold_off_the_clock_pause() {
        use tower::ServiceExt as _;
        let (app, _source, release, reading, writer) = slow_app();
        let key = {
            let mut gw = app.gw.lock().await;
            gw.register_account(None).0
        };
        let router = build_router(app.clone(), false);
        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/accounts/deposit/onchain")
            .header("content-type", "application/json")
            .header("x-api-key", hex0x(&key))
            .body(axum::body::Body::from(
                serde_json::json!({"txHash": hex0x(&[9; 32]), "marketId": 0}).to_string(),
            ))
            .unwrap();
        let confirm = tokio::spawn(router.oneshot(request));
        let _reading = read_started(reading).await;
        let stop = service_shutdown::Shutdown::default();
        let paused =
            tokio::time::timeout(Duration::from_secs(10), app.clock_admission.pause(&stop)).await;
        release.send(()).unwrap();
        let mut paused = paused
            .expect("the clock pause waited for a deposit confirmation's L1 read")
            .unwrap()
            .unwrap();
        let response = confirm.await.unwrap().unwrap();
        assert_eq!(
            response.status(),
            axum::http::StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(app.gw.lock().await.seq.state.consumed_deposit_count, 0);
        paused.resolved();
        writer.abort();
    }
}

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

    const TIMING: crate::l1::ClockTiming = crate::l1::ClockTiming {
        max_window_ms: 30_000,
        clock_skew_ms: 30_000,
    };
    /// The production policy: maxWindowMs and clockSkewMs of 30 s, sealed every
    /// 7.5 s, so the open window stops admitting timed operations at 22.5 s.
    fn bound() -> clock_admission::WindowBound {
        clock_admission::WindowBound::new(TIMING, TIMING.seal_period().unwrap())
    }

    fn at(now_ms: u64) -> PriceUse<'static> {
        PriceUse {
            archive: None,
            now_ms,
        }
    }

    fn market_buy() -> OrderReq {
        OrderReq {
            market_id: 0,
            side: "Buy".into(),
            size: (SIZE_SCALE / 100).to_string(),
            limit_price: "0".into(),
            tif: "Ioc".into(),
            reduce_only: false,
            ..Default::default()
        }
    }

    /// A clock-bound gateway whose open window holds a fill at `t0`, so it is
    /// not an idle funding window.
    fn trading_window(t0: u64, bound: Option<clock_admission::WindowBound>) -> (Gw, [u8; 32]) {
        let mut gw = Gw::boot();
        gw.window_settle_mode = true;
        gw.seq.set_retain_tick_snapshots(false);
        gw.clock_window = bound;
        let (key, _) = gw.register_account(None);
        gw.account_deposit(&key, 0, 50_000 * QUOTE_SCALE).unwrap();
        gw.account_place_order_checked(&key, &market_buy(), at(t0))
            .unwrap();
        gw.tick_checked(at(t0)).unwrap();
        assert_eq!(gw.seq.window_first_timed_ms(), Some(t0));
        assert!(gw.seq.state.state_root() != gw.last_settled_root);
        (gw, key)
    }

    /// G2-2: only the 7.5 s seal kept the open window short. A skipped seal (a
    /// failed batch-count read, a stale challenge read, a failed snapshot) left
    /// admission open while every tick added timed funding operations, and after
    /// 30 s the window could never register and was voided with every trade in
    /// it. Now, once its first timed operation is maxWindowMs less a seal period
    /// old, the window admits no timed operation (no tick, order or withdrawal)
    /// until it is sealed, and the next window starts admitting at once.
    #[test]
    fn audit_1116_g2_2_a_window_near_max_window_ms_stops_admitting_timed_operations() {
        let bound = bound();
        assert_eq!(bound.cutoff_ms, 22_500);
        let t0 = now_ms() - 60_000;
        let (mut gw, key) = trading_window(t0, Some(bound));
        // Inside the cutoff a tick still adds its timed operations.
        gw.tick_checked(at(t0 + 22_499)).unwrap();
        let bounds = gw.seq.window_time_bounds().unwrap();
        assert_eq!((bounds.first_ms, bounds.last_ms), (t0, t0 + 22_499));
        let ops = gw.seq.window_op_count();
        // At the cutoff the tick adds nothing, and an order is refused.
        let tick = gw.tick;
        gw.tick_checked(at(t0 + 22_500)).unwrap();
        gw.tick_checked(at(t0 + 40_000)).unwrap();
        assert_eq!(gw.seq.window_op_count(), ops);
        assert_eq!(gw.tick, tick);
        let Err(refused) = gw.account_place_order_checked(&key, &market_buy(), at(t0 + 22_500))
        else {
            panic!("an order was admitted into the closing window");
        };
        assert!(
            refused.starts_with(clock_admission::WINDOW_CLOSING),
            "{refused}"
        );
        // The sealed window stays inside maxWindowMs.
        let sealed = gw.seq.seal_window();
        let bounds = perp_core::clock::TimeBounds::derive(&sealed.ops).unwrap();
        assert!(bounds.last_ms - bounds.first_ms <= TIMING.max_window_ms);
        TIMING
            .check_registrable(&Ok(bounds), bounds.last_ms)
            .unwrap();
        // The next window admits again, later in time than the sealed one.
        gw.accounts.get_mut(&key).unwrap().orders_this_sec = 0;
        gw.account_place_order_checked(&key, &market_buy(), at(t0 + 40_001))
            .unwrap();
        gw.tick_checked(at(t0 + 40_001)).unwrap();
        assert_eq!(gw.seq.window_first_timed_ms(), Some(t0 + 40_001));
    }

    /// G2-2: the refusal reaches a client as 503 with Retry-After, like the clock
    /// pause, for an order and for a withdrawal, and changes nothing.
    #[tokio::test]
    async fn audit_1116_g2_2_a_closing_window_answers_orders_with_retry_after() {
        use sha3::Digest as _;
        use tower::ServiceExt as _;
        let t0 = now_ms() - 30_000;
        let (mut gw, key) = trading_window(t0, Some(bound()));
        // A caller-signed account, so its withdrawal is authorized.
        let signing = k256::ecdsa::SigningKey::from_slice(&[0x51; 32]).unwrap();
        let point = signing.verifying_key().to_encoded_point(false);
        let mut signer = [0u8; 20];
        signer.copy_from_slice(&sha3::Keccak256::digest(&point.as_bytes()[1..])[12..]);
        let (signed, owner) = gw.register_account(Some(signer));
        let to = [7u8; 20];
        let amount = 5 * QUOTE_SCALE;
        let digest = withdraw_auth_digest(gw.chain_id, &gw.vault, &owner, 0, amount, &to, 1);
        let (signature, recid) = signing.sign_prehash_recoverable(&digest).unwrap();
        let mut sig = [0u8; 65];
        sig[..64].copy_from_slice(&signature.to_bytes());
        sig[64] = 27 + recid.to_byte();
        let mut app = test_app();
        Arc::get_mut(&mut app).unwrap().gw = Mutex::new(gw);
        let post = |uri: &str, key: &[u8; 32], body: serde_json::Value| {
            axum::http::Request::builder()
                .method("POST")
                .uri(uri)
                .header("x-api-key", hex0x(key))
                .header("content-type", "application/json")
                .body(axum::body::Body::from(body.to_string()))
                .unwrap()
        };
        let order = post(
            "/v1/orders",
            &key,
            serde_json::json!({
                "marketId": 0, "side": "Buy", "size": (SIZE_SCALE / 100).to_string(),
                "limitPrice": "0", "tif": "Ioc", "reduceOnly": false,
            }),
        );
        let withdrawal = post(
            "/v1/accounts/withdraw",
            &signed,
            serde_json::json!({
                "marketId": 0, "amount": amount.to_string(), "to": hex0x(&to),
                "nonce": 1, "signature": hex0x(&sig),
            }),
        );
        for request in [order, withdrawal] {
            let response = build_router(app.clone(), false)
                .oneshot(request)
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(response.headers()["retry-after"], "2");
        }
        let gw = app.gw.lock().await;
        assert_eq!(gw.accounts[&key].orders.len(), 1);
        assert!(gw.window_withdrawals.is_empty());
        assert_eq!(gw.accounts[&signed].last_withdraw_nonce, 0);
    }

    /// G2-2: a window holding only idle funding no-ops is dropped, as the settle
    /// loop drops it, instead of holding an idle exchange; demo and legacy modes
    /// have no bound at all.
    #[test]
    fn audit_1116_g2_2_idle_windows_and_demo_mode_are_not_held() {
        let t0 = now_ms() - 60_000;
        let mut idle = Gw::boot();
        idle.window_settle_mode = true;
        idle.seq.set_retain_tick_snapshots(false);
        idle.clock_window = Some(bound());
        idle.tick_checked(at(t0)).unwrap();
        // Funding no-ops only: timed, but the state is the settled one.
        assert_eq!(idle.seq.window_first_timed_ms(), Some(t0));
        assert_eq!(idle.seq.state.state_root(), idle.last_settled_root);
        let tick = idle.tick;
        idle.tick_checked(at(t0 + 30_000)).unwrap();
        assert_eq!(idle.tick, tick + 1, "an idle window must not hold the tick");
        assert_eq!(idle.seq.window_first_timed_ms(), Some(t0 + 30_000));
        let (mut demo, _) = trading_window(t0, None);
        let ops = demo.seq.window_op_count();
        demo.tick_checked(at(t0 + 60_000)).unwrap();
        assert!(demo.seq.window_op_count() > ops);
    }

    /// A sealed window whose timed operations are at `t0` and `t0 + span`.
    fn sealed_spanning(t0: u64, span: u64) -> sequencer::WindowWitness {
        let (mut gw, _) = trading_window(t0, None);
        gw.tick_checked(at(t0 + span)).unwrap();
        let w = gw.seq.seal_window();
        let b = perp_core::clock::TimeBounds::derive(&w.ops).unwrap();
        assert_eq!((b.first_ms, b.last_ms), (t0, t0 + span));
        w
    }

    /// G2-2: the gateway did not check maxWindowMs before registering: the
    /// verifier reverted the registration (InvalidTime), the revert was
    /// swallowed and the window waited twenty minutes to be voided. The post-seal
    /// preflight now refuses a window wider than maxWindowMs, or past its
    /// registration skew, as unregistrable: no rollback (it would seal the same
    /// times again), and nothing is sent.
    #[test]
    fn audit_1116_g2_2_preflight_refuses_a_window_wider_than_max_window_ms() {
        use crate::clock_client::{ClockProverClient, RegisterMode};
        use crate::prover_client::{
            MockProverClient, PreflightRefusal, ProverClient, RegisterPreconditions,
        };
        let client = ClockProverClient {
            inner: Arc::new(MockProverClient),
            l1: L1::test_clocked_reader("http://127.0.0.1:9".into(), [1; 20], 84532),
            register: RegisterMode::SendIfAbsent,
        };
        let pre = |w: &sequencer::WindowWitness| RegisterPreconditions {
            batch_count: w.batch_id,
            phase: 0,
            prover_body_bytes: None,
            timing: TIMING,
        };
        let now = now_ms();
        let exact = sealed_spanning(now - 31_000, 30_000);
        client.preflight(&exact, 0, Some(&pre(&exact))).unwrap();
        let wide = sealed_spanning(now - 31_000, 30_001);
        let refused = client.preflight(&wide, 0, Some(&pre(&wide)));
        assert!(
            matches!(&refused, Err(PreflightRefusal::Unregistrable(e)) if e.contains("maxWindowMs")),
            "{refused:?}"
        );
        let stale = sealed_spanning(now - 60_000, 1_000);
        let refused = client.preflight(&stale, 0, Some(&pre(&stale)));
        assert!(
            matches!(&refused, Err(PreflightRefusal::Unregistrable(e)) if e.contains("skew")),
            "{refused:?}"
        );
    }
}

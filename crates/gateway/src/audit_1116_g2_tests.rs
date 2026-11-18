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

    /// G2-1 (round 2): a deposit read that finishes after admission closed is
    /// dropped and read again. On a busy exchange with a slow RPC that can repeat
    /// with nothing credited while the oldest unconsumed deposit's
    /// livenessTimeoutBlocks runs, so repeated drops raise
    /// `deposit_reads_dropped`; a read applied under the permit clears it.
    #[tokio::test]
    async fn audit_1116_g2_1_repeatedly_dropped_deposit_reads_raise_an_alert() {
        let (app, _source, release, mut reading, writer) = slow_app();
        let stop = service_shutdown::Shutdown::default();
        let dropped = || async {
            app.gw
                .lock()
                .await
                .ops_alerts
                .active()
                .contains(&ops_alerts::AlertKind::DepositReadsDropped)
        };
        for round in 1..=deposit_ingestion::DROPPED_READS_ALERT {
            assert!(!dropped().await, "round {round}");
            let scan = tokio::spawn({
                let app = app.clone();
                async move { deposit_ingestion::ingest_once(&app).await }
            });
            reading = read_started(reading).await;
            let mut paused = app.clock_admission.pause(&stop).await.unwrap().unwrap();
            release.send(()).unwrap();
            let refused = scan.await.unwrap().unwrap_err();
            assert!(refused.starts_with(clock_admission::BUSY), "{refused}");
            assert_eq!(app.gw.lock().await.deposits.dropped_reads, round);
            paused.resolved();
        }
        assert!(dropped().await);
        // A refusal before any read is not a dropped read.
        let paused = app.clock_admission.pause(&stop).await.unwrap().unwrap();
        deposit_ingestion::ingest_once(&app).await.unwrap_err();
        drop(paused);
        assert_eq!(
            app.gw.lock().await.deposits.dropped_reads,
            deposit_ingestion::DROPPED_READS_ALERT
        );
        release.send(()).unwrap();
        assert_eq!(deposit_ingestion::ingest_once(&app).await.unwrap(), 1);
        assert!(!dropped().await);
        assert_eq!(app.gw.lock().await.deposits.dropped_reads, 0);
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
    /// pause, for an order, a withdrawal, an LP transfer and the demo withdrawal,
    /// and changes nothing.
    #[tokio::test]
    async fn audit_1116_g2_2_a_closing_window_answers_orders_with_retry_after() {
        use sha3::Digest as _;
        use tower::ServiceExt as _;
        let t0 = now_ms() - 30_000;
        let (mut gw, key) = trading_window(t0, Some(bound()));
        // A caller-signed account, so its withdrawal is authorized.
        let signing = k256::ecdsa::SigningKey::from_slice(&[0x51; 32]).unwrap();
        let point = signing.verifying_key().to_sec1_point(false);
        let mut signer = [0u8; 20];
        signer.copy_from_slice(&sha3::Keccak256::digest(&point.as_bytes()[1..])[12..]);
        let (signed, owner) = gw.register_account(Some(signer));
        let to = [7u8; 20];
        let amount = 5 * QUOTE_SCALE;
        let digest = withdraw_auth_digest(gw.chain_id, &gw.vault, &owner, 0, amount, &to, 1);
        let (signature, recid) = signing.sign_prehash_recoverable(&digest);
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
        // The LP and demo paths that apply timed operations answer alike.
        let lp = post("/v1/lp/deposit", &key, serde_json::json!({"amount": "1000000"}));
        let demo = post("/api/withdraw", &key, serde_json::json!({"amount": "1"}));
        for request in [order, withdrawal, lp, demo] {
            let uri = request.uri().to_string();
            let response = build_router(app.clone(), false)
                .oneshot(request)
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE, "{uri}");
            assert_eq!(response.headers()["retry-after"], "2", "{uri}");
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

    /// G2-2 (round 2): past the cutoff no timed operation is admitted, so the
    /// window's last one stays put and everything the settle loop does before the
    /// registration is spent from its clockSkewMs budget. Within one seal period
    /// of the cutoff the settle loop leaves the sends that wait for a receipt (the
    /// bond top-up, the stake-refund sweep) to a later tick. An idle window, and
    /// demo and legacy modes, defer nothing.
    #[test]
    fn audit_1116_g2_2_sends_wait_while_the_open_window_nears_its_cutoff() {
        let bound = bound();
        let t0 = now_ms() - 60_000;
        let (gw, _) = trading_window(t0, Some(bound));
        assert!(!gw.clock_window_near_cutoff(t0 + 14_999));
        assert!(gw.clock_window_near_cutoff(t0 + 15_000));
        assert!(gw.clock_window_near_cutoff(t0 + 40_000));
        let (demo, _) = trading_window(t0, None);
        assert!(!demo.clock_window_near_cutoff(t0 + 40_000));
        let mut idle = Gw::boot();
        idle.window_settle_mode = true;
        idle.seq.set_retain_tick_snapshots(false);
        idle.clock_window = Some(bound);
        idle.tick_checked(at(t0)).unwrap();
        assert_eq!(idle.seq.window_first_timed_ms(), Some(t0));
        assert!(!idle.clock_window_near_cutoff(t0 + 40_000));
    }

    /// G2-2 (round 2): `main()` bounds the open window only where windows are
    /// clock-bound: the verifier's timing was read and the settle loop's prover
    /// is clock-enabled. Demo and legacy modes have no bound.
    #[test]
    fn audit_1116_g2_2_main_bounds_the_window_only_in_clock_mode() {
        let period = TIMING.seal_period().unwrap();
        assert_eq!(
            clock_window_bound(Some(TIMING), true, period),
            Some(bound())
        );
        assert_eq!(bound().seal_period_ms, 7_500);
        assert_eq!(clock_window_bound(Some(TIMING), false, period), None);
        assert_eq!(clock_window_bound(None, true, period), None);
        assert_eq!(clock_window_bound(None, false, period), None);
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

    /// A JSON-RPC endpoint whose every answer waits until the test releases it,
    /// like a slow or rate-limited L1 provider. Once released, `answer` gives a
    /// request's result, or `None` for a JSON-RPC error; `started` reports each
    /// request as it arrives.
    struct SlowChain {
        url: String,
        started: tokio::sync::mpsc::UnboundedReceiver<()>,
        release: tokio::sync::watch::Sender<bool>,
        server: tokio::task::JoinHandle<()>,
    }
    impl SlowChain {
        async fn start(answer: fn(&serde_json::Value) -> Option<serde_json::Value>) -> Self {
            let (reported, started) = tokio::sync::mpsc::unbounded_channel();
            let (release, released) = tokio::sync::watch::channel(false);
            let rpc = Router::new().route(
                "/",
                post(move |Json(req): Json<serde_json::Value>| {
                    let reported = reported.clone();
                    let mut released = released.clone();
                    async move {
                        let _ = reported.send(());
                        let _ = released.wait_for(|released| *released).await;
                        let id = req["id"].clone();
                        Json(match answer(&req) {
                            Some(result) => serde_json::json!({"jsonrpc":"2.0","id":id,"result":result}),
                            None => serde_json::json!({"jsonrpc":"2.0","id":id,
                                "error":{"code":-32000,"message":"test RPC unavailable"}}),
                        })
                    }
                }),
            );
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let server = tokio::spawn(async move {
                axum::serve(listener, rpc).await.unwrap();
            });
            Self {
                url,
                started,
                release,
                server,
            }
        }
        /// A read-only bridge to this endpoint.
        fn l1(&self) -> L1 {
            let mut l1 = L1::test_reader(self.url.clone());
            l1.settlement = format!("0x{}", "11".repeat(20));
            l1
        }
        /// Until the first L1 call reaches the endpoint.
        async fn read_started(&mut self) {
            tokio::time::timeout(Duration::from_secs(30), self.started.recv())
                .await
                .expect("no L1 read reached the endpoint")
                .expect("the endpoint stopped");
        }
        /// Answer every call, held or later, at once.
        fn release(&self) {
            self.release.send_replace(true);
        }
    }
    impl Drop for SlowChain {
        fn drop(&mut self) {
            self.release();
            self.server.abort();
        }
    }

    /// The settlement's deposit terms at the latest block: accepting deposits.
    fn deposit_terms(req: &serde_json::Value) -> Option<serde_json::Value> {
        match req["method"].as_str()? {
            "eth_getBlockByNumber" => {
                Some(serde_json::json!({"number": "0x1c", "hash": hex32(&[0x42; 32])}))
            }
            "eth_call" => {
                let data = req["params"][0]["input"]
                    .as_str()
                    .or_else(|| req["params"][0]["data"].as_str())?;
                [
                    ("closeOnly()", 0u64),
                    ("acceptingDeposits()", 1),
                    ("depositCapacity()", 1_000_000_000_000),
                    ("consumedDepositCount()", 0),
                    ("lastProgressBlock()", 0x1c),
                    ("livenessTimeoutBlocks()", 43_200),
                ]
                .into_iter()
                .find(|(signature, _)| {
                    let selector = <sha3::Keccak256 as sha3::Digest>::digest(signature.as_bytes());
                    data.starts_with(&hex0x(&selector[..4]))
                })
                .map(|(_, value)| serde_json::json!(format!("0x{value:064x}")))
            }
            _ => None,
        }
    }

    /// No call is ever answered with a result.
    fn unavailable(_: &serde_json::Value) -> Option<serde_json::Value> {
        None
    }

    fn post_json(uri: &str, key: &[u8; 32], body: serde_json::Value) -> axum::http::Request<axum::body::Body> {
        axum::http::Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json")
            .header("x-api-key", hex0x(key))
            .body(axum::body::Body::from(body.to_string()))
            .unwrap()
    }

    /// G2-1 (round 2): POST /v1/accounts/deposit/route waits for the deposit
    /// lock, which the deposit scan holds across its L1 read, and it held the
    /// HTTP admission permit while it waited: the clock pause still waited for the
    /// scan's slow read. Any 32-byte key with a well-formed body reaches that lock
    /// before an account is checked, and so does an honest legacy-route call. The
    /// route now takes the permit after the lock, only to adopt the route and make
    /// it durable, and answers 503 with Retry-After once admission has closed.
    #[tokio::test]
    async fn audit_1116_g2_1_a_legacy_deposit_route_does_not_hold_off_the_clock_pause() {
        use tower::ServiceExt as _;
        let (app, _source, release, reading, writer) = slow_app();
        // A permit issued before routing was recorded with it.
        let (key, commit) = {
            let mut gw = app.gw.lock().await;
            let (key, commit) = permit(&mut gw, 7_000_000, Purpose::Collateral, 0);
            gw.deposits.routes.remove(&commit);
            (key, commit)
        };
        let route = || {
            post_json(
                "/v1/accounts/deposit/route",
                &key,
                serde_json::json!({
                    "ownerCommit": hex0x(&commit), "from": hex0x(&[0x42; 20]),
                    "amount": "7000000", "marketId": 0, "purpose": "collateral",
                }),
            )
        };
        let scan = tokio::spawn({
            let app = app.clone();
            async move { deposit_ingestion::ingest_once(&app).await }
        });
        let _reading = read_started(reading).await;
        let call = tokio::spawn(build_router(app.clone(), false).oneshot(route()));
        // This runtime runs one task at a time: while the test sleeps, the request
        // runs until it waits for the deposit lock the scan holds.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!call.is_finished());
        let stop = service_shutdown::Shutdown::default();
        let paused =
            tokio::time::timeout(Duration::from_secs(10), app.clock_admission.pause(&stop)).await;
        release.send(()).unwrap();
        let mut paused = paused
            .expect(
                "the clock pause waited for the deposit scan's L1 read via \
                 /v1/accounts/deposit/route",
            )
            .unwrap()
            .unwrap();
        paused.arm();
        let refused = scan.await.unwrap().unwrap_err();
        assert!(refused.contains("clock settlement"), "{refused}");
        let response = call.await.unwrap().unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers()["retry-after"], "2");
        assert!(!app.gw.lock().await.deposits.routes.contains_key(&commit));
        // Once the window resolves, the same request records the route.
        paused.resolved();
        drop(paused);
        let response = build_router(app.clone(), false)
            .oneshot(route())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(app.gw.lock().await.deposits.routes.contains_key(&commit));
        writer.abort();
    }

    /// G2-1 (round 2): POST /v1/accounts/deposit/authorize reads the
    /// settlement's deposit terms at the latest block (several L1 calls, each
    /// bounded only by the RPC timeout) before the account is checked, and it
    /// held the HTTP admission permit across that read: a slow RPC held off the
    /// clock pause on every permit request, honest or not. The read now runs
    /// without the permit; the permit is taken to store the permit and make it
    /// durable. A request whose read finished after admission closed answers 503
    /// with Retry-After and stores nothing.
    #[tokio::test]
    async fn audit_1116_g2_1_a_deposit_permit_request_does_not_hold_off_the_clock_pause() {
        use tower::ServiceExt as _;
        let mut chain = SlowChain::start(deposit_terms).await;
        let mut app = test_app();
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        {
            let a = Arc::get_mut(&mut app).unwrap();
            a.clock_admission = clock_admission::ClockAdmission::new(true);
            a.snapshot_req = Some(tx);
            a.l1 = Some(chain.l1());
        }
        let writer = ack_every_snapshot(rx);
        let key = {
            let mut gw = app.gw.lock().await;
            let (key, _) = gw.register_account(None);
            gw.accounts.get_mut(&key).unwrap().deposit_address = Some([0x42; 20]);
            key
        };
        let request = || {
            post_json(
                "/v1/accounts/deposit/authorize",
                &key,
                serde_json::json!({"from": hex0x(&[0x42; 20]), "amount": "100000000",
                    "marketId": 0, "purpose": "collateral"}),
            )
        };
        let call = tokio::spawn(build_router(app.clone(), false).oneshot(request()));
        chain.read_started().await;
        let stop = service_shutdown::Shutdown::default();
        let paused =
            tokio::time::timeout(Duration::from_secs(10), app.clock_admission.pause(&stop)).await;
        chain.release();
        let mut paused = paused
            .expect("the clock pause waited for a deposit permit request's L1 read")
            .unwrap()
            .unwrap();
        paused.arm();
        let response = tokio::time::timeout(Duration::from_secs(60), call)
            .await
            .expect("the permit request never finished")
            .unwrap()
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers()["retry-after"], "2");
        {
            let gw = app.gw.lock().await;
            assert!(gw.accounts[&key].deposit_authorizations.is_empty());
            assert!(gw.deposits.routes.is_empty());
        }
        // Once the window resolves, the same request is served.
        paused.resolved();
        drop(paused);
        let response = build_router(app.clone(), false)
            .oneshot(request())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            app.gw.lock().await.accounts[&key].deposit_authorizations.len(),
            1
        );
        writer.abort();
    }

    /// The paths `build_router` mounts with a mutating method, read from its
    /// source so that no route can be left out of the table below.
    fn mutating_routes() -> std::collections::BTreeSet<String> {
        let source = include_str!("main.rs");
        let body = &source[source.find("fn build_router_with_policy(").unwrap()..];
        let body: String = body[..body.find("\n}\n").unwrap()]
            .split_whitespace()
            .collect();
        body.split(".route(")
            .skip(1)
            .filter_map(|entry| {
                let path = entry.strip_prefix('"')?.split('"').next()?;
                ["post(", "delete(", "put(", "patch("]
                    .iter()
                    .any(|method| entry.contains(method))
                    .then(|| path.to_string())
            })
            .collect()
    }

    /// G2-1 (round 2): every mutating route, with a deposit scan in the middle
    /// of a slow L1 read and an L1 endpoint that answers nothing until released:
    /// none may hold the clock admission permit across an L1 call, or across a
    /// lock held across one, so the clock pause never waits for an RPC. Admin
    /// routes run with the admin key; the withdrawal runs in close-only too,
    /// where it reads the L1 wind-down phase.
    #[tokio::test]
    async fn audit_1116_g2_1_no_mutating_route_holds_the_admission_permit_across_l1() {
        use tower::ServiceExt as _;
        struct Restore(Option<std::ffi::OsString>);
        impl Drop for Restore {
            fn drop(&mut self) {
                match self.0.take() {
                    Some(value) => std::env::set_var("FIN_ADMIN_KEY", value),
                    None => std::env::remove_var("FIN_ADMIN_KEY"),
                }
            }
        }
        let _env = crate::wind_down::ADMIN_ENV_LOCK.lock().await;
        let _restore = Restore(std::env::var_os("FIN_ADMIN_KEY"));
        let admin = format!("0x{}", "bb".repeat(32));
        std::env::set_var("FIN_ADMIN_KEY", &admin);
        let sig = hex0x(&[0u8; 65]);
        let withdrawal = serde_json::json!({"marketId": 0, "amount": "1000000",
            "to": hex0x(&[7; 20]), "nonce": 1, "signature": sig});
        let cases: Vec<(&str, &str, String, serde_json::Value, bool)> = vec![
            ("POST", "/api/order", "/api/order".into(), serde_json::json!({}), false),
            ("POST", "/api/deposit", "/api/deposit".into(), serde_json::json!({"amount": "1"}), false),
            ("POST", "/api/withdraw", "/api/withdraw".into(), serde_json::json!({"amount": "1"}), false),
            ("POST", "/api/lp/deposit", "/api/lp/deposit".into(), serde_json::json!({"amount": "1"}), false),
            ("POST", "/api/lp/withdraw", "/api/lp/withdraw".into(), serde_json::json!({"shares": "1"}), false),
            ("POST", "/api/close", "/api/close".into(), serde_json::json!({"marketId": 0}), false),
            ("POST", "/api/cancel", "/api/cancel".into(), serde_json::json!({"orderId": "0x00"}), false),
            ("POST", "/api/mode", "/api/mode".into(), serde_json::json!({}), false),
            ("POST", "/api/simulate-adl", "/api/simulate-adl".into(), serde_json::json!({}), false),
            ("POST", "/api/select-market", "/api/select-market".into(), serde_json::json!({"marketId": 0}), false),
            ("POST", "/api/recover", "/api/recover".into(), serde_json::json!({}), false),
            ("POST", "/v1/lp/deposit", "/v1/lp/deposit".into(), serde_json::json!({"amount": "1000000"}), false),
            ("POST", "/v1/lp/withdraw", "/v1/lp/withdraw".into(),
                serde_json::json!({"shares": "1", "nonce": 1, "signature": sig}), false),
            ("POST", "/v1/accounts", "/v1/accounts".into(), serde_json::json!({}), false),
            ("POST", "/v1/accounts/recovery", "/v1/accounts/recovery".into(), serde_json::json!({}), false),
            ("POST", "/v1/accounts/deposit", "/v1/accounts/deposit".into(),
                serde_json::json!({"marketId": 0, "amount": "1000000"}), false),
            ("POST", "/v1/accounts/deposit/address", "/v1/accounts/deposit/address".into(),
                serde_json::json!({"address": hex0x(&[0x42; 20])}), false),
            ("POST", "/v1/accounts/deposit/authorize", "/v1/accounts/deposit/authorize".into(),
                serde_json::json!({"from": hex0x(&[0x42; 20]), "amount": "10000000",
                    "marketId": 0, "purpose": "collateral"}), false),
            ("POST", "/v1/accounts/deposit/route", "/v1/accounts/deposit/route".into(),
                serde_json::json!({"ownerCommit": hex0x(&[0x5c; 32]), "from": hex0x(&[0x42; 20]),
                    "amount": "10000000", "marketId": 0, "purpose": "collateral"}), false),
            ("POST", "/v1/accounts/deposit/onchain", "/v1/accounts/deposit/onchain".into(),
                serde_json::json!({"txHash": hex0x(&[9; 32]), "marketId": 0}), false),
            ("POST", "/v1/accounts/withdraw", "/v1/accounts/withdraw".into(), withdrawal.clone(), false),
            ("POST", "/v1/accounts/withdraw", "/v1/accounts/withdraw".into(), withdrawal, true),
            ("POST", "/v1/orders", "/v1/orders".into(),
                serde_json::json!({"marketId": 0, "side": "Buy", "size": (SIZE_SCALE / 100).to_string(),
                    "limitPrice": "0", "tif": "Ioc", "reduceOnly": false}), false),
            ("DELETE", "/v1/orders/:order_id", format!("/v1/orders/{}", hex0x(&[3; 32])),
                serde_json::Value::Null, false),
            ("POST", "/v1/admin/settlement/resume", "/v1/admin/settlement/resume".into(),
                serde_json::Value::Null, false),
            ("POST", "/v1/admin/settlement/cancel-anchor", "/v1/admin/settlement/cancel-anchor".into(),
                serde_json::json!({"batchId": 0, "phase": 0, "receipt": hex0x(&[1; 32])}), false),
            ("POST", "/v1/admin/wind-down", "/v1/admin/wind-down".into(), serde_json::Value::Null, false),
            ("POST", "/v1/admin/bond/acknowledge-slash", "/v1/admin/bond/acknowledge-slash".into(),
                serde_json::json!({"slashCount": 0}), false),
            ("POST", "/v1/admin/insurance/bootstrap", "/v1/admin/insurance/bootstrap".into(),
                serde_json::json!({"txHash": hex0x(&[9; 32]), "marketId": 0}), false),
        ];
        let covered: std::collections::BTreeSet<String> =
            cases.iter().map(|(_, path, ..)| path.to_string()).collect();
        assert_eq!(covered, mutating_routes(), "a mutating route is missing from the table");
        let mut held = Vec::new();
        for (method, _, uri, body, close_only) in cases {
            let mut chain = SlowChain::start(unavailable).await;
            let (mut app, _source, release, reading, writer) = slow_app();
            {
                let a = Arc::get_mut(&mut app).unwrap();
                a.l1 = Some(chain.l1());
                a.prover = Some(Arc::new(prover_client::MockProverClient));
            }
            let key = {
                let mut gw = app.gw.lock().await;
                let (key, _) = gw.register_account(None);
                gw.accounts.get_mut(&key).unwrap().deposit_address = Some([0x42; 20]);
                if close_only {
                    gw.seq.apply(&BatchOp::EnterCloseOnly).unwrap();
                }
                key
            };
            // A deposit scan in the middle of its L1 read, holding the deposit lock.
            let scan = tokio::spawn({
                let app = app.clone();
                async move { deposit_ingestion::ingest_once(&app).await }
            });
            let _reading = read_started(reading).await;
            let request = axum::http::Request::builder()
                .method(method)
                .uri(&uri)
                .header("content-type", "application/json")
                .header("x-api-key", hex0x(&key))
                .header("x-admin-key", &admin)
                .body(match body {
                    serde_json::Value::Null => axum::body::Body::empty(),
                    body => axum::body::Body::from(body.to_string()),
                })
                .unwrap();
            let call = tokio::spawn(build_router(app.clone(), false).oneshot(request));
            // Let the request run until it waits: on the L1 endpoint, on a lock, or
            // not at all. This runtime runs one task at a time.
            tokio::select! {
                _ = chain.read_started() => {}
                _ = tokio::time::sleep(Duration::from_millis(100)) => {}
            }
            let stop = service_shutdown::Shutdown::default();
            let paused =
                tokio::time::timeout(Duration::from_secs(10), app.clock_admission.pause(&stop))
                    .await;
            chain.release();
            release.send(()).unwrap();
            // Admission stays closed until the request and the scan are done.
            let paused = match paused {
                Ok(paused) => {
                    let mut paused = paused.unwrap().unwrap();
                    paused.arm();
                    Some(paused)
                }
                Err(_) => {
                    held.push(format!("{method} {uri} (close-only: {close_only})"));
                    None
                }
            };
            tokio::time::timeout(Duration::from_secs(60), call)
                .await
                .unwrap_or_else(|_| panic!("{method} {uri} never finished"))
                .unwrap()
                .unwrap();
            let _ = scan.await.unwrap();
            drop(paused);
            writer.abort();
        }
        assert!(
            held.is_empty(),
            "these routes held the clock admission permit across an L1 read or the deposit \
             lock, so the clock pause waited for an RPC: {held:#?}"
        );
    }
}

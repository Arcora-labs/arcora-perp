// Audit 2026-11-16 GF-1 + SM-4: per-order history must not accumulate in the
// sealed snapshot, order intake must fail closed when persistence fails, and the
// order route must limit each client address. These tests make no chain calls.
mod audit_1116_gf1 {
    use super::*;
    use crate::prover_client::{prove_and_prepare, MockProverClient};
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt as _;

    const SEED: [u8; 32] = [0x16; 32];

    struct TestDir(std::path::PathBuf);
    impl TestDir {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("arcora-gf1-{}", hex0x(&csprng_bytes32())));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    async fn json(response: axum::response::Response) -> serde_json::Value {
        serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 1 << 20)
                .await
                .unwrap(),
        )
        .unwrap()
    }

    /// A small market order: well above the $10 minimum, cheap in margin and fees.
    fn small_ioc(side: &str) -> OrderReq {
        OrderReq {
            market_id: 0,
            side: side.into(),
            size: (SIZE_SCALE / 100).to_string(),
            limit_price: "0".into(),
            tif: "Ioc".into(),
            reduce_only: false,
            ..Default::default()
        }
    }

    fn funded_account(gw: &mut Gw) -> [u8; 32] {
        let (key, _) = gw.register_account(None);
        gw.account_deposit(&key, 0, 50_000 * QUOTE_SCALE).unwrap();
        key
    }

    /// The production settle shape: seal the open window, prove it with the mock
    /// prover and commit it as settled on L1.
    fn settle_open_window(gw: &mut Gw) {
        let batch_count = gw.seq.state.next_batch_id;
        let Some((witness, ww)) = gw.begin_window_settle(batch_count).unwrap() else {
            return;
        };
        let ordered = witness.manifest.ordered.clone();
        let rejected: Vec<_> = witness.manifest.rejected.iter().map(|(h, _)| *h).collect();
        let batch_id = witness.batch_id;
        let prepared = prove_and_prepare(&MockProverClient, &witness, &ww).unwrap();
        let status = L1Status {
            settled_root: hex32(&prepared.outcome.new_root),
            batch_count: batch_id + 1,
            last_tx: "0xtx".into(),
            bond: "0".into(),
            withdrawals_root: hex32(&prepared.outcome.withdrawals_root),
        };
        gw.commit_window_settle(
            batch_id,
            ordered,
            rejected,
            prepared,
            status,
            trading_gate::GateObservation::OpensGate,
        );
    }

    /// Accept `n` alternating market orders for `key`, match them in ticks, settle
    /// the window on L1 and let one more tick observe SETTLED.
    fn trade_and_settle(gw: &mut Gw, key: &[u8; 32], n: usize) {
        for i in 0..n {
            // The per-account limit is a wall-clock window; this test is not about it.
            gw.accounts.get_mut(key).unwrap().orders_this_sec = 0;
            let side = if i % 2 == 0 { "Buy" } else { "Sell" };
            gw.account_place_order(key, &small_ioc(side)).unwrap();
            if i % 25 == 24 {
                gw.tick();
            }
        }
        gw.tick();
        settle_open_window(gw);
        gw.tick();
    }

    /// Bytes the snapshot spends on the accounts and their order history rows (the
    /// positional account map plus each row's execution record). Those rows are
    /// capped per account and in total (`account_order_history_cap`, tested
    /// below), so they are set aside when measuring the history beyond them.
    fn account_rows_bytes(gw: &Gw) -> u64 {
        let mut extension = Vec::new();
        execution::append_snapshot(gw, &mut extension);
        (postcard::to_allocvec(&gw.accounts).unwrap().len() + extension.len()) as u64
    }

    /// GF-1 + SM-4: every accepted order used to leave its order-log entry, its
    /// settled batch hashes and its finality and inclusion records in the snapshot
    /// for good, so order volume alone could push the payload to the 64 MiB
    /// ceiling. Apart from the capped account history, settling more orders must
    /// not grow the snapshot by more than a few bytes per order.
    #[tokio::test]
    async fn audit_1116_gf1_snapshot_stays_bounded_while_settled_orders_accumulate() {
        let app = test_app();
        let key = {
            let mut gw = app.gw.lock().await;
            gw.window_settle_mode = true;
            gw.seq.set_retain_tick_snapshots(false);
            funded_account(&mut gw)
        };
        let dir = TestDir::new();
        let path = dir.0.join("state");
        let serial = Arc::new(Mutex::new(()));
        trade_and_settle(&mut *app.gw.lock().await, &key, 50);
        assert!(write_snapshot(&app, &path, SEED, serial.clone()).await);
        let before = std::fs::metadata(&path).unwrap().len();
        let rows_before = account_rows_bytes(&*app.gw.lock().await);

        const MORE: u64 = 200;
        trade_and_settle(&mut *app.gw.lock().await, &key, MORE as usize);
        assert!(write_snapshot(&app, &path, SEED, serial).await);
        let after = std::fs::metadata(&path).unwrap().len();
        let rows_after = account_rows_bytes(&*app.gw.lock().await);
        let growth = after.saturating_sub(before);
        let history = growth.saturating_sub(rows_after.saturating_sub(rows_before));
        assert!(
            history < MORE * 16,
            "beyond the capped account rows the snapshot grew {history} bytes for {MORE} \
             settled orders ({before} -> {after})"
        );
    }

    /// The legacy settle simulation (no prover, no L1) never settles a window on
    /// L1, so nothing publishes or clears the manifest accumulators there, yet
    /// every matched or cancelled order's hash went into them, and so into the
    /// snapshot, for good. Only the last tick's hashes may stay.
    #[test]
    fn audit_1116_gf1_legacy_settle_mode_keeps_no_manifest_accumulators() {
        let mut gw = Gw::boot();
        assert!(!gw.window_settle_mode);
        let key = funded_account(&mut gw);
        for i in 0..30 {
            gw.accounts.get_mut(&key).unwrap().orders_this_sec = 0;
            let side = if i % 2 == 0 { "Buy" } else { "Sell" };
            gw.account_place_order(&key, &small_ioc(side)).unwrap();
            gw.tick();
        }
        // This tick's taker and its house counter.
        assert_eq!(gw.pending_ordered.len(), 2);
        let pending = OrderReq {
            limit_price: gw.px_of(0).to_string(),
            tif: "Gtc".into(),
            ..small_ioc("Sell")
        };
        gw.accounts.get_mut(&key).unwrap().orders_this_sec = 0;
        gw.account_place_order(&key, &pending).unwrap();
        // Rows are kept newest first.
        let id = gw.accounts[&key].orders[0].id.clone();
        gw.account_cancel(&key, &id).unwrap();
        for _ in 0..(SETTLE_TICKS + 1) {
            gw.tick();
        }
        assert!(
            gw.pending_ordered.is_empty() && gw.pending_rejected.is_empty(),
            "{} ordered and {} rejected hashes kept",
            gw.pending_ordered.len(),
            gw.pending_rejected.len()
        );
    }

    /// An order that never fills (an IOC that meets no liquidity, a rejected or
    /// cancelled order) never reaches SETTLED, and the per-account history cap
    /// evicted only SETTLED rows: unfilled orders grew one account's API history,
    /// and the snapshot, without bound. The newest finished rows are the ones kept.
    #[test]
    fn audit_1116_gf1_unfilled_orders_leave_the_capped_account_history() {
        let mut gw = Gw::boot();
        gw.window_settle_mode = true;
        gw.seq.set_retain_tick_snapshots(false);
        let key = funded_account(&mut gw);
        // A buy below the mark meets no counter order and no resting liquidity.
        let unfilled = OrderReq {
            limit_price: (gw.px_of(0) * 99 / 100).to_string(),
            ..small_ioc("Buy")
        };
        for i in 0..MAX_ACCOUNT_ORDER_HISTORY + 40 {
            gw.accounts.get_mut(&key).unwrap().orders_this_sec = 0;
            gw.account_place_order(&key, &unfilled).unwrap();
            if i % 50 == 49 {
                gw.tick();
            }
        }
        // Rows are kept newest first.
        let newest = gw.accounts[&key].orders[0].id.clone();
        let oldest = gw.accounts[&key].orders.last().unwrap().id.clone();
        gw.tick();
        settle_open_window(&mut gw);
        // One tick records the finality and lets the sequencer drop the finished
        // records; the next one caps the history.
        gw.tick();
        gw.tick();
        let rows = &gw.accounts[&key].orders;
        assert!(
            rows.iter()
                .all(|o| o.filled == 0 && o.last_finality == "ACCEPTED"),
            "none of them filled"
        );
        assert_eq!(rows.len(), MAX_ACCOUNT_ORDER_HISTORY);
        assert_eq!(rows[0].id, newest, "the newest finished row is kept");
        assert!(rows.iter().all(|o| o.id != oldest), "the oldest went");
    }

    /// With 500 finished rows per account, enough accounts could still fill the
    /// snapshot with order history (a row costs a few hundred bytes). The rows
    /// kept across all accounts stay within a budget: each account holding rows
    /// keeps an equal share, newest first, and a live row is never evicted.
    #[test]
    fn audit_1116_gf1_finished_order_history_has_a_global_budget() {
        const { assert!(ORDER_HISTORY_BUDGET >= MAX_ACCOUNTS) };
        for holders in [0, 1, 2, 99, 100, 101, 1_000, 10_000, 49_999, MAX_ACCOUNTS] {
            let cap = account_order_history_cap(holders, ORDER_HISTORY_BUDGET);
            assert!((1..=MAX_ACCOUNT_ORDER_HISTORY).contains(&cap));
            assert!(holders * cap <= ORDER_HISTORY_BUDGET, "{holders} x {cap}");
        }
        assert_eq!(
            account_order_history_cap(100, ORDER_HISTORY_BUDGET),
            MAX_ACCOUNT_ORDER_HISTORY
        );

        let mut gw = Gw::boot();
        gw.window_settle_mode = true;
        gw.seq.set_retain_tick_snapshots(false);
        let keys: Vec<[u8; 32]> = (0..4).map(|_| funded_account(&mut gw)).collect();
        let unfilled = OrderReq {
            limit_price: (gw.px_of(0) * 99 / 100).to_string(),
            ..small_ioc("Buy")
        };
        for key in &keys {
            for _ in 0..8 {
                gw.accounts.get_mut(key).unwrap().orders_this_sec = 0;
                gw.account_place_order(key, &unfilled).unwrap();
            }
        }
        // The demo user's list is one more holder.
        assert!(gw.orders.is_empty());
        for _ in 0..8 {
            gw.place_order(&unfilled).unwrap();
        }
        gw.tick();
        settle_open_window(&mut gw);
        gw.tick();
        let newest: Vec<String> = keys
            .iter()
            .map(|k| gw.accounts[k].orders[0].id.clone())
            .collect();
        // A live order of the first account: never evicted, not counted as finished.
        let pending = OrderReq {
            limit_price: gw.px_of(0).to_string(),
            tif: "Gtc".into(),
            ..small_ioc("Sell")
        };
        gw.accounts.get_mut(&keys[0]).unwrap().orders_this_sec = 0;
        gw.account_place_order(&keys[0], &pending).unwrap();

        let demo_newest = gw.orders[0].id.clone();

        // Five holders share a budget of 25: five rows each. Only finished rows
        // are evicted, oldest first; the live one counts but stays.
        gw.cap_account_order_history(25);
        for (i, key) in keys.iter().enumerate() {
            let rows = &gw.accounts[key].orders;
            assert_eq!(rows.len(), 5, "account {i}");
            assert!(rows.iter().any(|o| o.id == newest[i]));
        }
        assert!(!gw.accounts[&keys[0]].orders[0].sealed, "the live row stays");
        assert_eq!(gw.orders.len(), 5);
        assert_eq!(gw.orders[0].id, demo_newest);
    }

    fn order_request(key: &[u8; 32], client: Option<SocketAddr>) -> Request<Body> {
        let mut request = Request::builder()
            .method("POST")
            .uri("/v1/orders")
            .header("x-api-key", hex0x(key))
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({
                    "marketId": 0,
                    "side": "Buy",
                    "size": (SIZE_SCALE / 100).to_string(),
                    "limitPrice": "0",
                    "tif": "Ioc",
                    "reduceOnly": false,
                })
                .to_string(),
            ))
            .unwrap();
        if let Some(addr) = client {
            request.extensions_mut().insert(ConnectInfo(addr));
        }
        request
    }

    /// GF-1: after a failed snapshot write the gateway kept accepting orders and
    /// handing out signed receipts that a restart would forget. An order (and a
    /// registration) must be refused with 503 until a snapshot write succeeds again.
    #[tokio::test]
    async fn audit_1116_gf1_orders_are_refused_after_a_failed_snapshot_write_until_one_succeeds() {
        let app = test_app();
        let key = funded_account(&mut *app.gw.lock().await);
        let dir = TestDir::new();
        let parent = dir.0.join("not-yet-created");
        let path = parent.join("state");
        let serial = Arc::new(Mutex::new(()));
        assert!(
            !write_snapshot(&app, &path, SEED, serial.clone()).await,
            "a missing state directory fails the write"
        );

        let router = build_router(app.clone(), false);
        let refused = router
            .clone()
            .oneshot(order_request(&key, None))
            .await
            .unwrap();
        assert_eq!(refused.status(), StatusCode::SERVICE_UNAVAILABLE);
        let error = json(refused).await["error"].as_str().unwrap().to_string();
        assert!(error.starts_with("PERSISTENCE_UNAVAILABLE"), "{error}");
        {
            let gw = app.gw.lock().await;
            assert!(gw.accounts[&key].orders.is_empty(), "nothing was recorded");
            assert!(gw.order_log.is_empty(), "nothing was logged");
        }
        let mut register = Request::builder()
            .method("POST")
            .uri("/v1/accounts")
            .body(Body::empty())
            .unwrap();
        register.extensions_mut().insert(ConnectInfo(
            "198.51.100.9:40000".parse::<SocketAddr>().unwrap(),
        ));
        let refused = router.clone().oneshot(register).await.unwrap();
        assert_eq!(refused.status(), StatusCode::SERVICE_UNAVAILABLE);

        std::fs::create_dir(&parent).unwrap();
        assert!(write_snapshot(&app, &path, SEED, serial).await);
        let accepted = router.oneshot(order_request(&key, None)).await.unwrap();
        assert_eq!(accepted.status(), StatusCode::OK);
        assert_eq!(app.gw.lock().await.accounts[&key].orders.len(), 1);
    }

    /// GF-1: the per-account limit alone let one client spread orders over many
    /// free accounts. The order route also limits each client address (a token
    /// bucket keyed like the registration limiter), and one client's burst does
    /// not limit another. Time is paused, so only the burst is available.
    #[tokio::test(start_paused = true)]
    async fn audit_1116_gf1_order_route_limits_each_client_address() {
        let app = test_app();
        let keys: Vec<[u8; 32]> = {
            let mut gw = app.gw.lock().await;
            (0..6).map(|_| funded_account(&mut gw)).collect()
        };
        let router = build_router(app.clone(), false);
        let a: SocketAddr = "198.51.100.7:40000".parse().unwrap();
        let b: SocketAddr = "198.51.100.8:40000".parse().unwrap();
        let (mut accepted, mut limited) = (0, 0);
        // Ten orders per account stay within the per-account limit of 10/s.
        for i in 0..60 {
            let response = router
                .clone()
                .oneshot(order_request(&keys[i % keys.len()], Some(a)))
                .await
                .unwrap();
            match response.status() {
                StatusCode::OK => accepted += 1,
                StatusCode::TOO_MANY_REQUESTS => {
                    let error = json(response).await["error"].as_str().unwrap().to_string();
                    assert!(error.starts_with("RATE_LIMIT"), "{error}");
                    limited += 1;
                }
                other => panic!("unexpected status {other}"),
            }
        }
        assert!(
            limited > 0,
            "one address placed {accepted} orders unlimited"
        );
        assert!(accepted > 0);
        // Another client address has its own bucket. A fresh account keeps the
        // per-account limit out of the picture.
        let other = funded_account(&mut *app.gw.lock().await);
        let response = router
            .oneshot(order_request(&other, Some(b)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// Boot's restore: authenticate the snapshot, decode it, load the side logs.
    fn restore(path: &std::path::Path) -> Result<Gw, String> {
        let plain = snapshot::open(&std::fs::read(path).unwrap(), &SEED)?;
        let mut gw = Gw::boot_restored(&plain)?;
        gw.attach_history(path, &SEED, false)?;
        Ok(gw)
    }

    fn assert_same_history(restored: &Gw, live: &Gw) {
        assert_eq!(restored.order_log.len(), live.order_log.len());
        assert_eq!(restored.order_log.head(), live.order_log.head());
        assert_eq!(
            restored.order_log.recompute_head(),
            restored.order_log.head()
        );
        assert_eq!(&*restored.batch_orders, &*live.batch_orders);
    }

    /// The order log and the settled batches' hash lists leave the snapshot for
    /// its side logs, and a restart reads them back: the chain continues and an
    /// inclusion challenge for an order of the first settled batch can still be
    /// answered. A snapshot whose side logs are missing, or rolled back to an
    /// older copy, is refused rather than restored without them.
    #[tokio::test]
    async fn audit_1116_gf1_history_restores_from_its_side_logs() {
        let app = test_app();
        let key = {
            let mut gw = app.gw.lock().await;
            gw.window_settle_mode = true;
            gw.seq.set_retain_tick_snapshots(false);
            funded_account(&mut gw)
        };
        let dir = TestDir::new();
        let path = dir.0.join("state");
        let serial = Arc::new(Mutex::new(()));
        trade_and_settle(&mut *app.gw.lock().await, &key, 30);
        let (first_batch, early) = {
            let gw = app.gw.lock().await;
            let (batch, (ordered, _)) = gw.batch_orders.iter().next().unwrap();
            (*batch, ordered[0])
        };
        assert!(write_snapshot(&app, &path, SEED, serial.clone()).await);
        let old_batches = std::fs::read(side_log::Kind::Batches.path(&path)).unwrap();
        trade_and_settle(&mut *app.gw.lock().await, &key, 30);
        assert!(write_snapshot(&app, &path, SEED, serial).await);

        let live = app.gw.lock().await;
        assert!(
            live.order_log.tail().is_empty(),
            "every entry is in the side log"
        );
        let restored = restore(&path).unwrap();
        assert_same_history(&restored, &live);
        let (_, batch, proof) = restored.build_challenge_answer(&early).unwrap();
        assert_eq!(batch, first_batch);
        assert_eq!(
            Some((false, batch, proof)),
            live.build_challenge_answer(&early)
        );

        let batches = side_log::Kind::Batches.path(&path);
        let current = std::fs::read(&batches).unwrap();
        std::fs::write(&batches, &old_batches).unwrap();
        let error = restore(&path).err().unwrap();
        assert!(error.contains("does not hold"), "{error}");
        std::fs::write(&batches, &current).unwrap();
        std::fs::remove_file(side_log::Kind::OrderLog.path(&path)).unwrap();
        let error = restore(&path).err().unwrap();
        assert!(error.contains("does not hold"), "{error}");
    }

    /// An order log from another history beside the snapshot is refused and left
    /// as it is, even when it is longer than the snapshot's durable end: boot
    /// checks the records the snapshot relies on, never cuts into someone else's
    /// file as if it were a torn append.
    #[tokio::test]
    async fn audit_1116_gf1_an_order_log_of_another_history_is_refused_not_cut() {
        let serial = Arc::new(Mutex::new(()));
        let dir = TestDir::new();
        let ours = dir.0.join("state");
        let other = dir.0.join("other");
        for (path, rounds, orders) in [(&ours, 2, 10), (&other, 1, 40)] {
            let app = test_app();
            let key = {
                let mut gw = app.gw.lock().await;
                gw.window_settle_mode = true;
                gw.seq.set_retain_tick_snapshots(false);
                funded_account(&mut gw)
            };
            // Ours: two appends of 10 orders. The other: one append of 40, so its
            // file is longer and has no frame boundary where ours ends.
            for _ in 0..rounds {
                trade_and_settle(&mut *app.gw.lock().await, &key, orders);
                assert!(write_snapshot(&app, path, SEED, serial.clone()).await);
            }
        }
        let log = side_log::Kind::OrderLog.path(&ours);
        let foreign = std::fs::read(side_log::Kind::OrderLog.path(&other)).unwrap();
        assert!(foreign.len() as u64 > std::fs::metadata(&log).unwrap().len());
        std::fs::write(&log, &foreign).unwrap();

        let error = restore(&ours).err().expect("another history is refused");
        assert!(error.contains("does not match"), "{error}");
        assert_eq!(std::fs::read(&log).unwrap(), foreign, "nothing was cut");
    }

    /// A snapshot the base commit wrote (the frozen v10 fixture, its order log
    /// inside) still loads; boot then moves its history out, and the next
    /// snapshot restores to the same log from the side log.
    #[test]
    fn audit_1116_gf1_a_base_commit_snapshot_loads_and_moves_its_history_out() {
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("testdata/snapshots/v10/plain.bin");
        let legacy = std::fs::read(fixture).unwrap();
        let mut gw = Gw::boot_restored(&legacy).unwrap();
        assert!(gw.order_log.len() >= 2, "the fixture's orders are logged");
        assert_eq!(gw.order_log.tail().len() as u64, gw.order_log.len());
        let head = gw.order_log.head();

        let dir = TestDir::new();
        let path = dir.0.join("state");
        gw.attach_history(&path, &SEED, false).unwrap();
        append_history_locked(&mut gw, &path, &SEED).unwrap();
        assert!(gw.order_log.tail().is_empty());
        assert_eq!(gw.order_log.head(), head);
        let plain = gw.snapshot_plain();
        assert!(plain.len() < legacy.len(), "the entries left the payload");
        snapshot::write_atomic(&path, &snapshot::seal(&plain, &SEED)).unwrap();

        let restored = restore(&path).unwrap();
        assert_same_history(&restored, &gw);
        assert_eq!(restored.snapshot_plain(), plain, "byte-exact re-encoding");
        // Without its history extension the payload is refused: the head it keeps
        // no longer follows from the (now empty) entries it holds.
        let mut cut = plain.clone();
        cut.truncate(legacy_layout_len(&plain));
        assert!(
            Gw::boot_restored(&cut).is_err(),
            "the extension is not optional"
        );
    }

    /// The length of `plain` without its history extension.
    fn legacy_layout_len(plain: &[u8]) -> usize {
        plain
            .windows(8)
            .rposition(|w| w == b"DPHIST1\0")
            .expect("a snapshot relying on side logs carries the extension")
    }

    /// A snapshot that holds settled batches itself (written before this change,
    /// or by a gateway without side logs) migrates them at boot, and they stay
    /// answerable after the next restart.
    #[test]
    fn audit_1116_gf1_inline_settled_batches_migrate_to_the_side_log() {
        let mut gw = Gw::boot();
        gw.window_settle_mode = true;
        gw.seq.set_retain_tick_snapshots(false);
        let key = funded_account(&mut gw);
        trade_and_settle(&mut gw, &key, 20);
        trade_and_settle(&mut gw, &key, 20);
        assert!(gw.batch_orders.len() >= 2);
        let legacy = gw.snapshot_plain();
        assert!(
            legacy.windows(8).all(|w| w != b"DPHIST1\0"),
            "the earlier layout"
        );
        let dir = TestDir::new();
        let path = dir.0.join("state");
        snapshot::write_atomic(&path, &snapshot::seal(&legacy, &SEED)).unwrap();

        let mut booted = restore(&path).unwrap();
        assert_same_history(&booted, &gw);
        append_history_locked(&mut booted, &path, &SEED).unwrap();
        let plain = booted.snapshot_plain();
        assert!(plain.len() < legacy.len());
        snapshot::write_atomic(&path, &snapshot::seal(&plain, &SEED)).unwrap();
        let restored = restore(&path).unwrap();
        assert_same_history(&restored, &gw);
        let (batch, (ordered, _)) = gw.batch_orders.iter().next().unwrap();
        assert_eq!(
            restored.build_challenge_answer(&ordered[0]).unwrap().1,
            *batch
        );
    }

    /// A crash after the side logs were appended but before the snapshot that
    /// records it: the older snapshot restores, the records appended after it
    /// are kept (the log stays one chain), and a torn append is cut off.
    #[tokio::test]
    async fn audit_1116_gf1_a_crash_between_side_log_and_snapshot_keeps_one_history() {
        let app = test_app();
        let key = {
            let mut gw = app.gw.lock().await;
            gw.window_settle_mode = true;
            gw.seq.set_retain_tick_snapshots(false);
            funded_account(&mut gw)
        };
        let dir = TestDir::new();
        let path = dir.0.join("state");
        trade_and_settle(&mut *app.gw.lock().await, &key, 10);
        assert!(write_snapshot(&app, &path, SEED, Arc::new(Mutex::new(()))).await);
        let mut live = app.gw.lock().await;
        trade_and_settle(&mut live, &key, 10);
        append_history_locked(&mut live, &path, &SEED).unwrap();
        // The process dies here, mid-way through a later append.
        let log = side_log::Kind::OrderLog.path(&path);
        let durable = std::fs::metadata(&log).unwrap().len();
        let mut file = std::fs::OpenOptions::new().append(true).open(&log).unwrap();
        std::io::Write::write_all(&mut file, &[0x40, 0, 0, 0, 7, 7]).unwrap();
        drop(file);

        let mut restored = restore(&path).unwrap();
        assert_same_history(&restored, &live);
        assert_eq!(
            std::fs::metadata(&log).unwrap().len(),
            durable,
            "torn tail cut"
        );
        // It continues the same chain.
        restored.accounts.get_mut(&key).unwrap().orders_this_sec = 0;
        restored
            .account_place_order(&key, &small_ioc("Buy"))
            .unwrap();
        append_history_locked(&mut restored, &path, &SEED).unwrap();
        let plain = restored.snapshot_plain();
        snapshot::write_atomic(&path, &snapshot::seal(&plain, &SEED)).unwrap();
        let again = restore(&path).unwrap();
        assert_same_history(&again, &restored);
        assert_eq!(again.order_log.len(), live.order_log.len() + 1);
    }

    /// A fresh genesis never adopts side logs some earlier state left behind, and
    /// a state that never loaded them never cuts into them.
    #[tokio::test]
    async fn audit_1116_gf1_leftover_side_logs_are_never_adopted_or_cut() {
        let dir = TestDir::new();
        let path = dir.0.join("state");
        let mut gw = Gw::boot();
        gw.attach_history(&path, &SEED, true).unwrap();
        let log = side_log::Kind::OrderLog.path(&path);
        std::fs::write(&log, b"left behind").unwrap();
        let mut fresh = Gw::boot();
        let error = fresh.attach_history(&path, &SEED, true).unwrap_err();
        assert!(error.contains("move it aside"), "{error}");

        let app = test_app();
        let key = funded_account(&mut *app.gw.lock().await);
        app.gw
            .lock()
            .await
            .account_place_order(&key, &small_ioc("Buy"))
            .unwrap();
        assert!(!write_snapshot(&app, &path, SEED, Arc::new(Mutex::new(()))).await);
        assert_eq!(std::fs::read(&log).unwrap(), b"left behind");
        assert_eq!(
            app.gw.lock().await.order_log.tail().len(),
            1,
            "kept in the snapshot"
        );
        let plain = snapshot::open(&std::fs::read(&path).unwrap(), &SEED).unwrap();
        assert_eq!(Gw::boot_restored(&plain).unwrap().order_log.len(), 1);
    }

    /// The size alarm fires at three quarters of the cap, before writes fail.
    #[test]
    fn audit_1116_gf1_snapshot_size_alarm_fires_before_the_cap() {
        let alerts = ops_alerts::OpsAlerts::default();
        note_snapshot_size(&alerts, snapshot::SIZE_ALERT_BYTES - 1);
        assert!(alerts.active().is_empty());
        note_snapshot_size(&alerts, snapshot::SIZE_ALERT_BYTES);
        assert_eq!(
            alerts.active(),
            vec![ops_alerts::AlertKind::SnapshotSizeHigh]
        );
        const { assert!(snapshot::SIZE_ALERT_BYTES < snapshot::MAX_PLAIN_BYTES) };
        note_snapshot_size(&alerts, 1024);
        assert!(alerts.active().is_empty());
    }
}

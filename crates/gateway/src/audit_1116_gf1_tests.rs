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
    /// positional account map plus each row's execution record). That history is
    /// capped per account by design (`MAX_ACCOUNT_ORDER_HISTORY`), so it is set
    /// aside when measuring the per-order history this finding is about.
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
        let register = Request::builder()
            .method("POST")
            .uri("/v1/accounts")
            .body(Body::empty())
            .unwrap();
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
}

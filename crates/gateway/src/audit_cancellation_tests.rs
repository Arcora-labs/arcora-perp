// A04 cancellation regressions. These tests make no live chain calls.
mod audit_cancellation {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt as _;

    fn stage(gw: &mut Gw) -> ([u8; 32], Order) {
        let (key, _) = gw.register_account(None);
        gw.account_deposit(&key, 0, 20_000 * QUOTE_SCALE).unwrap();
        let req = OrderReq {
            market_id: 0,
            side: "Sell".into(),
            size: (SIZE_SCALE / 10).to_string(),
            limit_price: gw.px_of(0).to_string(),
            tif: "Gtc".into(),
            reduce_only: false,
            ..Default::default()
        };
        gw.account_place_order(&key, &req).unwrap();
        (key, gw.accounts[&key].orders[0].order)
    }
    fn rest(gw: &mut Gw) -> ([u8; 32], Order) {
        let (key, order) = stage(gw);
        gw.tick();
        assert!(gw.accounts[&key].orders[0].sealed);
        assert_eq!(gw.seq.cancellable_size(&order.owner, &order, true), Some(order.size));
        (key, order)
    }
    fn request(key: &[u8; 32]) -> Request<Body> {
        Request::builder()
            .method("DELETE")
            .uri("/v1/orders/o1")
            .header("x-api-key", hex0x(key))
            .body(Body::empty())
            .unwrap()
    }
    async fn body(response: axum::response::Response) -> serde_json::Value {
        serde_json::from_slice(&axum::body::to_bytes(response.into_body(), 1 << 20).await.unwrap()).unwrap()
    }
    struct TestDir(std::path::PathBuf);
    impl TestDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("dark-perp-cancel-{}", hex0x(&csprng_bytes32())));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn sealed_resting_order_cancels_and_appears_in_the_window_manifest() {
        let mut gw = Gw::boot();
        let (key, order) = rest(&mut gw);
        let root = gw.seq.state.state_root();
        assert_eq!(gw.account_cancel(&key, "o1").unwrap(), order.size);
        assert_eq!(gw.seq.state.state_root(), root);
        assert!(gw.accounts[&key].orders.is_empty());
        assert_eq!(gw.seq.book(0).unwrap().resting_size(Side::Sell), 0);
        let witness = gw.seq.seal_window();
        assert!(witness.manifest.rejected.contains(&(order.order_hash::<Keccak256>(), perp_core::order::RejectReason::Cancelled)));
        let derived = perp_core::commitment::derive_roots(&mut witness.pre_state.clone(), &witness.ops, &witness.manifest).unwrap();
        assert_eq!(derived.new_state_root, gw.seq.state.state_root());
    }

    #[test]
    fn pending_cancel_is_committed_instead_of_silently_dropping_a_receipted_order() {
        let mut gw = Gw::boot();
        let (key, order) = stage(&mut gw);
        assert_eq!(gw.account_cancel(&key, "o1").unwrap(), order.size);
        gw.tick();
        let hash = order.order_hash::<Keccak256>();
        assert!(!gw.seq.inclusion_violations(0).contains(&hash));
        assert!(gw.seq.seal_window().manifest.rejected.contains(&(hash, perp_core::order::RejectReason::Cancelled)));
    }

    #[test]
    fn identical_order_ids_remain_account_scoped_after_sealing() {
        let mut gw = Gw::boot();
        let (a, order_a) = stage(&mut gw);
        let (b, order_b) = stage(&mut gw);
        gw.tick();
        assert_eq!(gw.accounts[&a].orders[0].id, "o1");
        assert_eq!(gw.accounts[&b].orders[0].id, "o1");
        gw.account_cancel(&a, "o1").unwrap();
        assert_eq!(gw.seq.cancellable_size(&order_a.owner, &order_a, true), None);
        assert_eq!(gw.seq.cancellable_size(&order_b.owner, &order_b, true), Some(order_b.size));
        assert_eq!(gw.account_cancel(&a, "o1").unwrap_err(), "Order not found.");
        assert_eq!(gw.accounts[&b].orders.len(), 1);
    }

    #[test]
    fn partial_cancel_reads_the_matcher_not_the_legacy_fabricated_fill_field() {
        let mut gw = Gw::boot();
        let (maker_key, maker) = rest(&mut gw);
        let (taker_key, _) = gw.register_account(None);
        gw.account_deposit(&taker_key, 0, 20_000 * QUOTE_SCALE).unwrap();
        gw.account_place_order(&taker_key, &OrderReq {
            market_id: 0,
            side: "Buy".into(),
            size: (maker.size / 4).to_string(),
            limit_price: maker.limit_price.to_string(),
            tif: "Gtc".into(),
            reduce_only: false,
            ..Default::default()
        }).unwrap();
        gw.tick();
        assert_eq!(gw.seq.state.position(&maker.owner, 0).unwrap().size, -maker.size / 4);
        // This field remains an A05 defect; cancellation must not depend on it.
        gw.accounts.get_mut(&maker_key).unwrap().orders[0].filled = maker.size;
        assert_eq!(gw.v1_orders_json(&maker_key).unwrap()["orders"][0]["cancellable"], true);
        let root = gw.seq.state.state_root();
        assert_eq!(gw.account_cancel(&maker_key, "o1").unwrap(), maker.size * 3 / 4);
        assert_eq!(gw.seq.state.state_root(), root);
        assert_eq!(gw.seq.state.position(&maker.owner, 0).unwrap().size, -maker.size / 4);
    }

    #[test]
    fn cancelled_snapshot_restores_without_resurrecting_depth_or_ingress() {
        let mut gw = Gw::boot();
        let (key, order) = rest(&mut gw);
        gw.account_cancel(&key, "o1").unwrap();
        let mut restored = Gw::boot_restored(&gw.snapshot_plain()).unwrap();
        assert!(restored.accounts[&key].orders.is_empty());
        assert_eq!(restored.seq.book(0).unwrap().resting_size(Side::Sell), 0);
        restored.tick();
        assert_eq!(restored.seq.book(0).unwrap().resting_size(Side::Sell), 0);
        assert!(restored.seq.seal_window().manifest.rejected.contains(&(order.order_hash::<Keccak256>(), perp_core::order::RejectReason::Cancelled)));
    }

    #[test]
    fn cancellation_only_window_is_not_skipped_and_original_inclusion_is_preferred() {
        let mut gw = Gw::boot();
        let (key, order) = rest(&mut gw);
        let first = gw.seq.seal_window();
        gw.last_settled_root = gw.seq.state.state_root();
        let hash = order.order_hash::<Keccak256>();
        gw.batch_orders.insert(first.batch_id, (vec![hash], vec![]));
        assert!(!gw.seq.window_has_pending_manifest());
        gw.account_cancel(&key, "o1").unwrap();
        let id = gw.seq.current_window_id();
        let (witness, _) = gw.begin_window_settle(id).unwrap().expect("manifest-only cancellation must settle");
        assert!(witness.manifest.rejected.contains(&(hash, perp_core::order::RejectReason::Cancelled)));
        gw.batch_orders.insert(witness.batch_id, (vec![], vec![hash]));
        let (is_rejection, answer_batch, _) = gw.build_challenge_answer(&hash).unwrap();
        assert!(!is_rejection, "prefer the original inclusion to a later rejection");
        assert_eq!(answer_batch, first.batch_id);
    }

    #[tokio::test]
    async fn production_without_persistence_refuses_before_cancelling() {
        let app = test_app();
        let (key, order) = {
            let mut gw = app.gw.lock().await;
            let pair = rest(&mut gw);
            gw.prod = true;
            pair
        };
        let response = build_router(app.clone(), true).oneshot(request(&key)).await.unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let gw = app.gw.lock().await;
        assert_eq!(gw.accounts[&key].orders.len(), 1);
        assert_eq!(gw.seq.cancellable_size(&order.owner, &order, true), Some(order.size));
    }

    #[tokio::test]
    async fn production_success_waits_for_durable_cancellation() {
        let mut app = test_app();
        let (tx, mut rx) = tokio::sync::mpsc::channel::<SnapshotAck>(1);
        Arc::get_mut(&mut app).unwrap().snapshot_req = Some(tx);
        let (key, order) = {
            let mut gw = app.gw.lock().await;
            let pair = rest(&mut gw);
            gw.prod = true;
            pair
        };
        let task = tokio::spawn(build_router(app.clone(), true).oneshot(request(&key)));
        let ack = tokio::time::timeout(Duration::from_secs(5), rx.recv()).await.unwrap().unwrap();
        assert!(!task.is_finished(), "no successful response before durable acknowledgement");
        let dir = TestDir::new();
        let path = dir.0.join("state");
        let seed = [42; 32];
        assert!(write_snapshot(&app, &path, seed, Arc::new(Mutex::new(()))).await);
        let plain = snapshot::open(&std::fs::read(path).unwrap(), &seed).unwrap();
        let restored = Gw::boot_restored(&plain).unwrap();
        assert!(restored.accounts[&key].orders.is_empty());
        assert_eq!(restored.seq.book(0).unwrap().resting_size(Side::Sell), 0);
        ack.send(true).unwrap();
        let response = task.await.unwrap().unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let data = body(response).await;
        assert_eq!(data["cancelled"], true);
        assert_eq!(data["cancelledSize"], order.size.to_string());
    }

    #[tokio::test]
    async fn failed_write_is_not_reported_as_success_and_does_not_restore_the_quote() {
        let mut app = test_app();
        let (tx, mut rx) = tokio::sync::mpsc::channel::<SnapshotAck>(1);
        Arc::get_mut(&mut app).unwrap().snapshot_req = Some(tx);
        let (key, _) = rest(&mut *app.gw.lock().await);
        let task = tokio::spawn(build_router(app.clone(), true).oneshot(request(&key)));
        let ack = tokio::time::timeout(Duration::from_secs(5), rx.recv()).await.unwrap().unwrap();
        ack.send(false).unwrap();
        let response = task.await.unwrap().unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let data = body(response).await;
        assert_eq!(data["durability"], "unknown");
        assert!(data.get("cancelled").is_none());
        assert_eq!(app.gw.lock().await.seq.book(0).unwrap().resting_size(Side::Sell), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn full_snapshot_queue_times_out_without_success() {
        let mut app = test_app();
        let (tx, _rx) = tokio::sync::mpsc::channel::<SnapshotAck>(1);
        let (occupied, _reply) = tokio::sync::oneshot::channel();
        tx.send(occupied).await.unwrap();
        Arc::get_mut(&mut app).unwrap().snapshot_req = Some(tx);
        let (key, _) = rest(&mut *app.gw.lock().await);
        let response = build_router(app.clone(), true).oneshot(request(&key)).await.unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body(response).await["durability"], "unknown");
    }

    #[test]
    fn settled_partial_maker_survives_history_pruning_and_remains_cancellable() {
        let mut gw = Gw::boot();
        let (maker_key, maker) = rest(&mut gw);
        let (taker_key, _) = gw.register_account(None);
        gw.account_deposit(&taker_key, 0, 20_000 * QUOTE_SCALE).unwrap();
        gw.account_place_order(&taker_key, &OrderReq {
            market_id: 0,
            side: "Buy".into(),
            size: (maker.size / 4).to_string(),
            limit_price: maker.limit_price.to_string(),
            tif: "Gtc".into(),
            reduce_only: false,
            ..Default::default()
        }).unwrap();
        gw.tick();
        let hash = maker.order_hash::<Keccak256>();
        assert_eq!(gw.seq.state.position(&maker.owner, 0).unwrap().size, -maker.size / 4);
        // Settle the real partial fill, then let the gateway observe that finality.
        // No live chain is involved in this native state-machine regression.
        gw.seq.mark_settled(gw.seq.current_batch_id() - 1);
        gw.tick();
        assert_eq!(gw.seq.finality_of(&hash), Some(Finality::Settled));
        assert_eq!(gw.accounts[&maker_key].orders[0].last_finality, "SETTLED");
        assert_eq!(gw.seq.cancellable_size(&maker.owner, &maker, true), Some(maker.size * 3 / 4));

        // Pad only display history with terminal fixtures, not 500 fabricated
        // accounting fills. The genuine live maker is deliberately first: the
        // legacy finality-only eviction would remove its sole API row first.
        let template = serde_json::to_vec(&gw.accounts[&maker_key].orders[0]).unwrap();
        let account = gw.accounts.get_mut(&maker_key).unwrap();
        for n in 0..MAX_ACCOUNT_ORDER_HISTORY {
            let mut historical: GwOrder = serde_json::from_slice(&template).unwrap();
            historical.id = format!("history-{n}");
            historical.order.nonce = 10_000 + n as u64;
            historical.order_hash = historical.order.order_hash::<Keccak256>();
            assert_ne!(historical.order_hash, hash);
            account.orders.push(historical);
        }
        assert_eq!(account.orders.len(), MAX_ACCOUNT_ORDER_HISTORY + 1);
        gw.tick();
        let account = &gw.accounts[&maker_key];
        assert_eq!(account.orders.len(), MAX_ACCOUNT_ORDER_HISTORY);
        assert!(account.orders.iter().any(|o| o.order_hash == hash), "live maker API row was pruned");
        let view = gw.v1_orders_json(&maker_key).unwrap();
        let maker_view = view["orders"].as_array().unwrap().iter()
            .find(|o| o["orderId"] == "o1").expect("maker visible");
        assert_eq!(maker_view["cancellable"], true);
        assert_eq!(gw.account_cancel(&maker_key, "o1").unwrap(), maker.size * 3 / 4);
        assert_eq!(gw.seq.book(0).unwrap().remaining_for(&maker.owner, &hash), None);
    }
}

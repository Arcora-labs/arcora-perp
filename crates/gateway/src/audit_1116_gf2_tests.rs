// Audit 2026-11-16 GF-2: an order receipt and its L1 challenge authority must not
// leave the gateway before a durable snapshot holds the order. These tests make
// no chain calls.
mod audit_1116_gf2 {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt as _;

    const SEED: [u8; 32] = [0x26; 32];
    const BENEFICIARY: [u8; 20] = [0x42; 20];

    struct TestDir(std::path::PathBuf);
    impl TestDir {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("arcora-gf2-{}", hex0x(&csprng_bytes32())));
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

    /// An app whose durability barrier requests arrive on the returned receiver,
    /// with one funded account bound to `BENEFICIARY` under a configured
    /// settlement, so every receipt it is given carries an `l1Challenge`.
    async fn staged() -> (
        Shared,
        tokio::sync::mpsc::Receiver<SnapshotAck>,
        [u8; 32],
    ) {
        let mut app = test_app();
        let (tx, rx) = tokio::sync::mpsc::channel::<SnapshotAck>(8);
        Arc::get_mut(&mut app).unwrap().snapshot_req = Some(tx);
        let key = {
            let mut gw = app.gw.lock().await;
            gw.l1_settlement = Some([0x22; 20]);
            let (key, _) = gw.register_account(None);
            gw.accounts.get_mut(&key).unwrap().deposit_address = Some(BENEFICIARY);
            gw.account_deposit(&key, 0, 20_000 * QUOTE_SCALE).unwrap();
            key
        };
        (app, rx, key)
    }

    fn place(key: &[u8; 32]) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/v1/orders")
            .header("x-api-key", hex0x(key))
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({
                    "marketId": 0, "side": "Buy", "size": "100000", "limitPrice": "1",
                    "tif": "Gtc", "reduceOnly": false,
                })
                .to_string(),
            ))
            .unwrap()
    }

    /// GF-2: with the snapshot write failing, the order response used to carry the
    /// enclave-signed receipt and its `l1Challenge` all the same. A crash then lost
    /// the order while its holder kept the authority to challenge it on L1 (and
    /// slash the bond, since no batch can ever answer it). Now the handler waits for
    /// the durable write and, when it fails, releases neither.
    #[tokio::test]
    async fn audit_1116_gf2_a_failed_snapshot_releases_no_receipt_or_l1_challenge() {
        let (app, mut rx, key) = staged().await;
        let task = tokio::spawn(build_router(app.clone(), false).oneshot(place(&key)));
        let ack = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("the order handler did not reach the durability barrier")
            .expect("the order handler must request a durable snapshot");
        ack.send(false).unwrap();
        let response = task.await.unwrap().unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = json(response).await;
        assert_eq!(body["durability"], "unknown");
        for field in ["signature", "enclaveSigner", "l1Challenge", "seqNo"] {
            assert!(body.get(field).is_none(), "{field} released: {body}");
        }
        // The order stays accepted in memory: a tick may already have matched it,
        // and the next durable snapshot holds it.
        let gw = app.gw.lock().await;
        assert_eq!(gw.accounts[&key].orders.len(), 1);
        assert_eq!(
            body["orderHash"],
            hex0x(&gw.accounts[&key].orders[0].order_hash)
        );
    }

    /// GF-2: the successful response leaves only after the write it waited for is
    /// durable, and that write holds the order.
    #[tokio::test]
    async fn audit_1116_gf2_the_receipt_follows_a_durable_write_that_holds_the_order() {
        let (app, mut rx, key) = staged().await;
        let task = tokio::spawn(build_router(app.clone(), false).oneshot(place(&key)));
        let ack = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("the order handler did not reach the durability barrier")
            .expect("the order handler must request a durable snapshot");
        assert!(!task.is_finished(), "no receipt before the durable write");
        let dir = TestDir::new();
        let path = dir.0.join("state");
        assert!(write_snapshot(&app, &path, SEED, Arc::new(Mutex::new(()))).await);
        let plain = snapshot::open(&std::fs::read(&path).unwrap(), &SEED).unwrap();
        let restored = Gw::boot_restored(&plain).unwrap();
        assert_eq!(restored.accounts[&key].orders.len(), 1);
        ack.send(true).unwrap();
        let response = task.await.unwrap().unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let receipt = json(response).await;
        assert_eq!(
            receipt["orderHash"],
            hex0x(&restored.accounts[&key].orders[0].order_hash)
        );
        assert_eq!(receipt["l1Challenge"]["beneficiary"], hex0x(&BENEFICIARY));
    }

    /// GF-2: production without persistence cannot make any receipt durable, so it
    /// refuses the order before accepting anything, as cancellation does.
    #[tokio::test]
    async fn audit_1116_gf2_production_without_persistence_refuses_orders_before_accepting() {
        let app = test_app();
        let key = {
            let mut gw = app.gw.lock().await;
            let (key, _) = gw.register_account(None);
            gw.account_deposit(&key, 0, 20_000 * QUOTE_SCALE).unwrap();
            gw.prod = true;
            key
        };
        let nonce = app.gw.lock().await.accounts[&key].nonce;
        let response = build_router(app.clone(), true)
            .oneshot(place(&key))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = json(response).await;
        assert!(
            body["error"]
                .as_str()
                .unwrap()
                .starts_with(PERSISTENCE_UNAVAILABLE),
            "{body}"
        );
        let gw = app.gw.lock().await;
        assert!(gw.accounts[&key].orders.is_empty());
        assert_eq!(gw.accounts[&key].nonce, nonce);
    }
}

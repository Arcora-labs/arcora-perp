// Regression tests for the first 2026-09-17 remediation slice. No live RPC or funds.
mod audit_remediation {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt as _;

    struct TestDir(std::path::PathBuf);
    impl TestDir {
        fn new() -> Self {
            let p = std::env::temp_dir().join(format!(
                "dark-perp-remediation-{}",
                hex0x(&csprng_bytes32())
            ));
            std::fs::create_dir(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    async fn payer(app: &Shared) -> [u8; 32] {
        let mut gw = app.gw.lock().await;
        let (key, _) = gw.register_account(None);
        gw.accounts.get_mut(&key).unwrap().deposit_address = Some([0x42; 20]);
        key
    }
    fn permit_request(key: &[u8; 32]) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/v1/accounts/deposit/authorize")
            .header("content-type", "application/json")
            .header("x-api-key", hex0x(key))
            .body(Body::from(
                serde_json::json!({"from": hex0x(&[0x42; 20]), "amount": "5000000", "marketId": 0, "purpose": "collateral"}).to_string(),
            ))
            .unwrap()
    }
    async fn json_body(response: axum::response::Response) -> serde_json::Value {
        serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 1 << 20)
                .await
                .unwrap(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn authorization_waits_for_disk_before_signature_and_restores_creditably() {
        let mut app = test_app();
        let (tx, mut rx) = tokio::sync::mpsc::channel::<SnapshotAck>(1);
        Arc::get_mut(&mut app).unwrap().snapshot_req = Some(tx);
        let key = payer(&app).await;
        let router = build_router(app.clone(), true);
        let request = tokio::spawn(router.oneshot(permit_request(&key)));
        let ack = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("authorization handler did not reach the durability barrier")
            .expect("authorization must request a durability barrier");
        assert!(
            !request.is_finished(),
            "no HTTP response before durability acknowledgement"
        );
        let dir = TestDir::new();
        let path = dir.0.join("state");
        let seed = [42u8; 32];
        assert!(write_snapshot(&app, &path, seed, Arc::new(Mutex::new(()))).await);
        let plain = snapshot::open(&std::fs::read(&path).unwrap(), &seed).unwrap();
        let mut restored = Gw::boot_restored(&plain).unwrap();
        assert_eq!(restored.accounts[&key].deposit_authorizations.len(), 1);
        ack.send(true).unwrap();
        let response = request.await.unwrap().unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        let commit = parse_hex32(body["ownerCommit"].as_str().unwrap()).unwrap();
        let sig = parse_hex65(body["sig"].as_str().unwrap()).unwrap();
        assert_eq!(
            recover_eth_address(
                &app.gateway_signer.digest(&[0x42; 20], &commit, 5_000_000),
                &sig
            ),
            Some(app.gateway_signer.address())
        );
        assert!(restored.accounts[&key]
            .deposit_authorizations
            .contains_key(&commit));
        let id = restored.seq.state.consumed_deposit_count;
        assert_eq!(
            restored
                .account_confirm_deposit(
                    &key,
                    [0x42; 20],
                    commit,
                    5_000_000,
                    id,
                    "test-restored",
                    0
                )
                .unwrap(),
            5_000_000
        );
        assert!(restored.seq.state.conservation_holds());
    }

    #[tokio::test]
    async fn authorization_without_persistence_releases_no_signature() {
        let app = test_app();
        let key = payer(&app).await;
        let response = build_router(app.clone(), true)
            .oneshot(permit_request(&key))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(json_body(response).await.get("sig").is_none());
        assert!(app.gw.lock().await.accounts[&key]
            .deposit_authorizations
            .is_empty());
    }

    #[tokio::test]
    async fn failed_disk_ack_releases_no_signature_and_drops_the_unsigned_permit() {
        let mut app = test_app();
        let (tx, mut rx) = tokio::sync::mpsc::channel::<SnapshotAck>(1);
        Arc::get_mut(&mut app).unwrap().snapshot_req = Some(tx);
        let key = payer(&app).await;
        let request = tokio::spawn(build_router(app.clone(), true).oneshot(permit_request(&key)));
        tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("authorization handler did not reach the durability barrier")
            .unwrap()
            .send(false)
            .unwrap();
        let response = request.await.unwrap().unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(json_body(response).await.get("sig").is_none());
        assert!(app.gw.lock().await.accounts[&key]
            .deposit_authorizations
            .is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn a_full_queue_is_inside_the_snapshot_deadline() {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<SnapshotAck>(1);
        let (first, _first_reply) = tokio::sync::oneshot::channel();
        tx.send(first).await.unwrap();
        let started = tokio::time::Instant::now();
        let result = tokio::time::timeout(
            Duration::from_secs(SNAPSHOT_ACK_TIMEOUT_SECS + 1),
            snapshot_now(&Some(tx)),
        )
        .await
        .expect("the internal deadline must expire before this external watchdog");
        assert!(result.unwrap_err().contains("timed out"));
        assert!(started.elapsed() <= Duration::from_secs(SNAPSHOT_ACK_TIMEOUT_SECS));
        drop(rx.try_recv().unwrap());
        assert!(
            rx.try_recv().is_err(),
            "timed-out enqueue must not leave a phantom request"
        );
    }

    #[tokio::test]
    async fn snapshot_serialization_precedes_state_capture() {
        let dir = TestDir::new();
        let path = dir.0.join("state");
        let app = test_app();
        let serial = Arc::new(Mutex::new(()));
        let lock = serial.clone().lock_owned().await;
        let app2 = app.clone();
        let path2 = path.clone();
        let serial2 = serial.clone();
        let writer =
            tokio::spawn(async move { write_snapshot(&app2, &path2, [42; 32], serial2).await });
        tokio::task::yield_now().await;
        assert!(!writer.is_finished());
        let key = payer(&app).await;
        drop(lock);
        assert!(writer.await.unwrap());
        let plain = snapshot::open(&std::fs::read(path).unwrap(), &[42; 32]).unwrap();
        let restored = Gw::boot_restored(&plain).unwrap();
        assert!(
            restored.accounts.contains_key(&key),
            "a queued writer must not publish a pre-lock capture"
        );
    }

    #[test]
    #[cfg(unix)]
    fn atomic_writer_never_follows_a_preexisting_tmp_symlink() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let dir = TestDir::new();
        let state = dir.0.join("state");
        let unrelated = dir.0.join("unrelated");
        std::fs::write(&unrelated, b"do not overwrite").unwrap();
        symlink(&unrelated, dir.0.join("state.tmp")).unwrap();
        snapshot::write_atomic(&state, b"private state").unwrap();
        assert_eq!(std::fs::read(&unrelated).unwrap(), b"do not overwrite");
        assert_eq!(std::fs::read(&state).unwrap(), b"private state");
        assert_eq!(
            std::fs::metadata(&state).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn failed_atomic_rename_retains_the_existing_target_and_cleans_only_its_tmp() {
        let dir = TestDir::new();
        let target = dir.0.join("state");
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("existing"), b"retained").unwrap();
        assert!(snapshot::write_atomic(&target, b"cannot replace a directory").is_err());
        assert_eq!(std::fs::read(target.join("existing")).unwrap(), b"retained");
        assert_eq!(
            std::fs::read_dir(&dir.0).unwrap().count(),
            1,
            "owned temporary file cleaned up"
        );
    }

    #[test]
    fn oversized_deposit_is_rejected_before_creating_an_authorization() {
        let mut gw = Gw::boot();
        let key = gw.account_register_for_test();
        let before = gw.snapshot_plain();
        assert!(gw
            .account_authorize_deposit(&key, [0x42; 20], i128::MAX as u128 + 1)
            .is_err());
        assert_eq!(gw.snapshot_plain(), before);
    }

    fn sign(sk: &k256::ecdsa::SigningKey, digest: &Digest) -> [u8; 65] {
        let (sig, recid) = sk.sign_prehash_recoverable(digest).unwrap();
        let mut bytes = [0u8; 65];
        bytes[..64].copy_from_slice(&sig.to_bytes());
        bytes[64] = 27 + recid.to_byte();
        bytes
    }

    #[test]
    fn pending_deposit_permits_prevent_a_rebind_from_stranding_the_queue() {
        let mut gw = Gw::boot();
        let (key, owner) = gw.register_account(None);
        let old = GatewaySigner::from_parts([3; 32], 84532, [1; 20])
            .unwrap()
            .address();
        let new = GatewaySigner::from_parts([4; 32], 84532, [1; 20])
            .unwrap()
            .address();
        let old_sk = k256::ecdsa::SigningKey::from_bytes((&[3; 32]).into()).unwrap();
        let new_sk = k256::ecdsa::SigningKey::from_bytes((&[4; 32]).into()).unwrap();
        gw.accounts.get_mut(&key).unwrap().deposit_address = Some(old);
        let commit = gw.account_authorize_deposit(&key, old, 1000).unwrap();
        let new_sig = sign(&new_sk, &deposit_bind_digest(&owner, &new));
        let current_sig = sign(
            &old_sk,
            &rebind_auth_digest(gw.chain_id, &gw.vault, &owner, 0, &old, &new),
        );
        let err = gw
            .account_set_deposit_address(&key, new, &new_sig, Some(&current_sig))
            .unwrap_err();
        assert!(err.contains("outstanding"));
        assert_eq!(gw.accounts[&key].deposit_address, Some(old));
        let id = gw.seq.state.consumed_deposit_count;
        gw.account_confirm_deposit(&key, old, commit, 1000, id, "pending-before-rebind", 0)
            .unwrap();
        gw.account_set_deposit_address(&key, new, &new_sig, Some(&current_sig))
            .unwrap();
        assert_eq!(gw.accounts[&key].deposit_address, Some(new));
    }

    #[test]
    fn served_receipt_reproduces_original_signature_and_survives_restore() {
        let mut gw = Gw::boot();
        let order = mk_order(
            gw.user.owner,
            0,
            Side::Buy,
            SIZE_SCALE / 10,
            usd(60_000.0),
            90,
            TimeInForce::Gtc,
            false,
        );
        let signed = gw.seq.accept_order(&order, 1234);
        let original = WReceipt {
            order_hash: hex0x(&signed.receipt.order_hash),
            seq_no: signed.receipt.seq_no,
            recv_time_ms: signed.receipt.recv_time_ms,
            batch_id_hint: signed.receipt.batch_id_hint,
            window_id: signed.receipt.window_id,
        };
        let wire = gw.receipt_json(&original);
        let mut expected = [0u8; 65];
        expected[..32].copy_from_slice(&signed.r);
        expected[32..64].copy_from_slice(&signed.s);
        expected[64] = signed.v;
        assert_eq!(wire["signature"], hex0x(&expected));
        assert_eq!(wire["enclaveSigner"], hex0x(&signed.enclave_address));
        assert_eq!(
            recover_eth_address(&signed.receipt.signing_digest::<Keccak256>(), &expected),
            Some(signed.enclave_address)
        );
        let mut tampered = signed.receipt;
        tampered.recv_time_ms += 1;
        assert_ne!(
            recover_eth_address(&tampered.signing_digest::<Keccak256>(), &expected),
            Some(signed.enclave_address)
        );
        gw.seq.seal_batch(&[], 9999); // never refresh original receipt metadata at read time
        let restored = Gw::boot_restored(&gw.snapshot_plain()).unwrap();
        assert_eq!(restored.receipt_json(&original), wire);
    }

    #[tokio::test]
    async fn order_post_and_list_both_deliver_the_same_acceptance_signature() {
        let app = test_app();
        let key = payer(&app).await;
        app.gw
            .lock()
            .await
            .account_deposit(&key, 0, 20_000 * QUOTE_SCALE)
            .unwrap();
        let req = Request::builder().method("POST").uri("/v1/orders")
            .header("x-api-key", hex0x(&key)).header("content-type", "application/json")
            .body(Body::from(serde_json::json!({"marketId":0,"side":"Buy","size":"1","limitPrice":"1","tif":"Gtc","reduceOnly":false}).to_string())).unwrap();
        let response = build_router(app.clone(), false).oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let receipt = json_body(response).await;
        assert_eq!(receipt["signature"].as_str().unwrap().len(), 132);
        app.gw.lock().await.tick();
        let req = Request::builder()
            .uri("/v1/orders")
            .header("x-api-key", hex0x(&key))
            .body(Body::empty())
            .unwrap();
        let body = json_body(build_router(app, false).oneshot(req).await.unwrap()).await;
        assert_eq!(body["orders"][0]["receipt"], receipt);
    }

    #[test]
    fn every_production_book_surface_explicitly_withholds_depth() {
        let mut gw = Gw::boot_with(GenesisMode::Production);
        gw.prod = true;
        let rest = gw.v1_orderbook_json(0).unwrap();
        let public = gw.v1_public_json();
        let state = serde_json::to_value(gw.snapshot()).unwrap();
        for book in [&rest, &public["markets"][0]["book"], &state["book"]] {
            assert_eq!(book["unavailable"], true);
            assert!(book["bids"].as_array().unwrap().is_empty());
            assert!(book["asks"].as_array().unwrap().is_empty());
        }
        gw.prod = false;
        assert!(
            !gw.v1_orderbook_json(0).unwrap()["bids"]
                .as_array()
                .unwrap()
                .is_empty(),
            "demo remains visibly simulated"
        );
    }

    #[test]
    fn public_oracle_time_is_observation_time_not_request_time() {
        let mut gw = Gw::boot();
        let t = oracle_of(usd(60_000.0), 12345, 0, &gw.oracle_signer);
        gw.apply_real_oracle(0, t);
        assert_eq!(gw.v1_oracle_json(0).unwrap()["publishTimeMs"], 12345);
        assert_eq!(gw.snapshot().oracle.publish_time_ms, 12345);
        let first = *gw.seq.oracle(0).unwrap();
        gw.apply_real_oracle(0, oracle_of(usd(62_000.0), 12344, 0, &gw.oracle_signer));
        gw.apply_real_oracle(0, oracle_of(usd(63_000.0), 12345, 0, &gw.oracle_signer));
        assert_eq!(
            gw.seq.oracle(0).unwrap().publish_time_ms,
            first.publish_time_ms
        );
        assert_eq!(gw.seq.oracle(0).unwrap().price, first.price);
        assert_eq!(
            gw.v1_oracle_json(0).unwrap()["price"],
            first.price.to_string()
        );
        let restored = Gw::boot_restored(&gw.snapshot_plain()).unwrap();
        assert_eq!(
            restored.v1_oracle_json(0).unwrap()["publishTimeMs"],
            0,
            "unpersisted source freshness is unknown after restore"
        );
    }

    #[test]
    fn receipt_cache_is_bounded_metadata_bound_and_not_persisted() {
        let gw = Gw::boot();
        let stored = WReceipt {
            order_hash: hex0x(&[1; 32]),
            seq_no: 1,
            recv_time_ms: 2000,
            batch_id_hint: 3,
            window_id: 4,
        };
        let before = gw.snapshot_plain();
        let wire = gw.receipt_json(&stored);
        assert_eq!(gw.receipt_json(&stored), wire);
        assert_eq!(gw.receipt_cache.lock().unwrap().len(), 1);
        assert_eq!(
            gw.snapshot_plain(),
            before,
            "read caching cannot change the snapshot schema or state"
        );
        let mut other = stored.clone();
        other.window_id += 1;
        let moved_window = gw.receipt_json(&other);
        assert_eq!(moved_window["windowId"], 5);
        assert_eq!(
            moved_window["signature"], wire["signature"],
            "window hint stays unsigned"
        );
        other.recv_time_ms += 1;
        assert_ne!(gw.receipt_json(&other)["signature"], wire["signature"]);
        {
            let mut cache = gw.receipt_cache.lock().unwrap();
            cache.clear();
            for i in 0..MAX_RECEIPT_CACHE as u64 {
                cache.insert(([0; 32], i, [0; 20]), serde_json::Value::Null);
            }
        }
        assert_eq!(gw.receipt_json(&stored), wire);
        assert_eq!(
            gw.receipt_cache.lock().unwrap().len(),
            1,
            "bounded cache must evict before insertion"
        );
        let restored = Gw::boot_restored(&gw.snapshot_plain()).unwrap();
        assert!(restored.receipt_cache.lock().unwrap().is_empty());
        assert_eq!(restored.receipt_json(&stored), wire);
    }
}


#[tokio::test]
async fn s1f_send_lease_fences_rotation_without_holding_gw() {
    let (mut app, key, owner, sk) = prepared();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<SnapshotAck>(8);
    Arc::get_mut(&mut app).unwrap().snapshot_req = Some(tx);
    let session = crate::credential_session::Session::authenticate(&app.gw.lock().await, key).unwrap();
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let send = tokio::spawn({
        let app = app.clone();
        async move {
            crate::credential_session::send_fenced(&app, &session, async {
                entered_tx.send(()).unwrap();
                release_rx.await.unwrap();
                Ok::<(), ()>(())
            }).await
        }
    });
    entered_rx.await.unwrap();
    // The test future is paused at the actual production send boundary.
    let before = app.gw.lock().await.snapshot_plain();
    let sig = signature(&app, &sk, &owner, 0).await;
    assert!(app.gw.lock().await.recover_account(owner, 0, &sig).is_err(),
        "synchronous callers must not bypass an in-flight send lease");
    assert_eq!(app.gw.lock().await.snapshot_plain(), before);
    let router = build_router(app.clone(), false);
    let recovery = tokio::spawn(router.oneshot(post_recovery(&hex0x(&owner), 0, &sig)));
    assert!(tokio::time::timeout(Duration::from_millis(100), rx.recv()).await.is_err());
    assert_eq!(view_nonce(&app, &hex0x(&owner)).await, 0);
    // Another account's registration and lookup remain possible during the send.
    let (other, _) = app.gw.lock().await.register_account(None);
    assert_eq!(build_router(app.clone(), false).oneshot(get_me(&other)).await.unwrap().status(), StatusCode::OK);
    release_tx.send(()).unwrap();
    assert!(send.await.unwrap());
    rx.recv().await.unwrap().send(true).unwrap();
    assert_eq!(recovery.await.unwrap().unwrap().status(), StatusCode::OK);
}

#[tokio::test(start_paused = true)]
async fn s1f_stalled_send_releases_lease_on_deadline() {
    let (mut app, key, owner, sk) = prepared();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<SnapshotAck>(8);
    Arc::get_mut(&mut app).unwrap().snapshot_req = Some(tx);
    let session = crate::credential_session::Session::authenticate(&app.gw.lock().await, key).unwrap();
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let send = tokio::spawn({
        let app = app.clone();
        async move {
            crate::credential_session::send_fenced(&app, &session, async {
                entered_tx.send(()).unwrap();
                std::future::pending::<Result<(), ()>>().await
            }).await
        }
    });
    entered_rx.await.unwrap();
    let sig = signature(&app, &sk, &owner, 0).await;
    let recovery = tokio::spawn(build_router(app.clone(), false).oneshot(post_recovery(&hex0x(&owner), 0, &sig)));
    tokio::time::advance(crate::credential_session::SEND_TIMEOUT).await;
    assert!(!send.await.unwrap(), "stalled transport must be abandoned");
    rx.recv().await.unwrap().send(true).unwrap();
    assert_eq!(recovery.await.unwrap().unwrap().status(), StatusCode::OK);
}

#[tokio::test]
async fn s1f_queued_private_event_cannot_cross_rotation() {
    let (mut app, key, owner, sk) = prepared();
    let (tx, _) = controllable_writer();
    Arc::get_mut(&mut app).unwrap().snapshot_req = Some(tx);
    let base = spawn_ws_server(app.clone()).await;
    let (mut ws, reply) = connect_auth(&base, &key).await;
    assert_eq!(reply["type"], "authOk");
    let control = app.gw.lock().await.recovery_control(&owner).unwrap();
    let gate = control.fence.clone().write_owned().await;
    let sig = signature(&app, &sk, &owner, 0).await;
    let recovery = build_router(app.clone(), false).oneshot(post_recovery(&hex0x(&owner), 0, &sig));
    tokio::pin!(recovery);
    // Poll while the write fence is held: recovery queues ahead of event delivery.
    assert!(matches!(futures_util::poll!(&mut recovery), std::task::Poll::Pending));
    publish_private(&app, &hex0x(&owner), 901);
    tokio::task::yield_now().await;
    drop(gate);
    assert_eq!(recovery.await.unwrap().status(), StatusCode::OK);
    let next = tokio::time::timeout(Duration::from_secs(3), ws.next()).await.unwrap();
    if let Some(Ok(Message::Text(text))) = next {
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["message"], "api key rotated");
        assert_ne!(value["type"], "execution");
    } else {
        assert!(matches!(next, None | Some(Err(_)) | Some(Ok(Message::Close(_)))));
    }
}

#[tokio::test(start_paused = true)]
async fn s1f_full_and_closed_snapshot_queues_do_not_disclose_credentials() {
    let (mut app, _, owner, sk) = prepared();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<SnapshotAck>(1);
    let (occupy, _unused) = tokio::sync::oneshot::channel();
    tx.send(occupy).await.unwrap();
    Arc::get_mut(&mut app).unwrap().snapshot_req = Some(tx);
    let sig = signature(&app, &sk, &owner, 0).await;
    let router = build_router(app.clone(), false);
    let response = router.clone().oneshot(post_recovery(&hex0x(&owner), 0, &sig)).await.unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
    let value = body_json(response).await;
    assert_eq!(value["durability"], "unknown");
    assert!(value.get("apiKey").is_none());
    assert!(value["error"].as_str().unwrap().contains("timed out"));
    drop(rx.recv().await);
    let retry = tokio::spawn(router.clone().oneshot(post_recovery(&hex0x(&owner), 0, &sig)));
    rx.recv().await.unwrap().send(true).unwrap();
    let response = retry.await.unwrap().unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(view_nonce(&app, &hex0x(&owner)).await, 1);
    let before = body_json(response).await["apiKey"].clone();
    drop(rx);
    let response = router.oneshot(post_recovery(&hex0x(&owner), 0, &sig)).await.unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let value = body_json(response).await;
    assert!(value.get("apiKey").is_none());
    assert!(value["error"].as_str().unwrap().contains("writer is gone"));
    let current = app.gw.lock().await.accounts.keys().next().copied().unwrap();
    assert_eq!(hex0x(&current), before);
}

#[tokio::test]
async fn s1f_actual_snapshot_restore_after_cancelled_response_allows_fresh_recovery() {
    let (mut app, original, owner, sk) = prepared();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<SnapshotAck>(8);
    Arc::get_mut(&mut app).unwrap().snapshot_req = Some(tx);
    let sig = signature(&app, &sk, &owner, 0).await;
    let request = tokio::spawn(build_router(app.clone(), false).oneshot(post_recovery(&hex0x(&owner), 0, &sig)));
    let ack = rx.recv().await.unwrap(); // Exact cancellation point after mutation.
    let directory = std::env::temp_dir().join(format!("dark-perp-s1f-{}", hex0x(&csprng_bytes32())));
    std::fs::create_dir(&directory).unwrap();
    let path = directory.join("snapshot");
    let seed = [0x71; 32];
    assert!(write_snapshot(&app, &path, seed, Arc::new(Mutex::new(()))).await);
    let sealed = std::fs::read(&path).unwrap();
    let lost_key = app.gw.lock().await.accounts.keys().next().copied().unwrap();
    request.abort();
    assert!(request.await.unwrap_err().is_cancelled());
    assert!(ack.send(true).is_err(), "cancelled response must not accept ACK");
    let plain = snapshot::open(&sealed, &seed).unwrap();
    let restored = Gw::boot_restored(&plain).unwrap();
    assert_eq!(restored.accounts[&lost_key].recovery_nonce, 1);
    assert!(restored.accounts[&lost_key].recovery_last.is_none());
    assert_eq!(restored.snapshot_plain(), plain, "runtime fences must not change persisted bytes");
    let mut restarted = crate::tests::test_app();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<SnapshotAck>(8);
    let state = Arc::get_mut(&mut restarted).unwrap();
    state.gw = Mutex::new(restored);
    state.snapshot_req = Some(tx);
    // Do not guess nonce+1 after a restart. Read the restored public challenge.
    let nonce = view_nonce(&restarted, &hex0x(&owner)).await;
    let old_retry = build_router(restarted.clone(), false).oneshot(post_recovery(&hex0x(&owner), 0, &sig)).await.unwrap();
    assert_eq!(old_retry.status(), StatusCode::BAD_REQUEST);
    let sig = signature(&restarted, &sk, &owner, nonce).await;
    let recovery = tokio::spawn(build_router(restarted.clone(), false).oneshot(post_recovery(&hex0x(&owner), nonce, &sig)));
    let ack = rx.recv().await.unwrap();
    assert!(write_snapshot(&restarted, &path, seed, Arc::new(Mutex::new(()))).await);
    ack.send(true).unwrap();
    let response = recovery.await.unwrap().unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let value = body_json(response).await;
    let key = parse_hex32(value["apiKey"].as_str().unwrap()).unwrap();
    assert_ne!(key, original);
    assert_ne!(key, lost_key);
    let reloaded = Gw::boot_restored(&snapshot::open(&std::fs::read(&path).unwrap(), &seed).unwrap()).unwrap();
    assert!(reloaded.accounts.contains_key(&key));
    assert_eq!(reloaded.accounts[&key].recovery_nonce, 2);
    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn s1f_post_ack_authorizer_change_is_conflict_without_secret() {
    let (mut app, key, owner, sk) = prepared();
    app.gw.lock().await.accounts.get_mut(&key).unwrap().signer = None;
    let (tx, mut rx) = tokio::sync::mpsc::channel::<SnapshotAck>(8);
    Arc::get_mut(&mut app).unwrap().snapshot_req = Some(tx);
    let sig = signature(&app, &sk, &owner, 0).await;
    let task = tokio::spawn(build_router(app.clone(), false).oneshot(post_recovery(&hex0x(&owner), 0, &sig)));
    let ack = rx.recv().await.unwrap();
    // Controlled fixture mutation at the rebind boundary, not an end-to-end
    // rebind authorization test. Tests the final response guard independently.
    app.gw.lock().await.accounts.values_mut().next().unwrap().deposit_address = Some([0x99; 20]);
    ack.send(true).unwrap();
    let response = task.await.unwrap().unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert!(body_json(response).await.get("apiKey").is_none());
}

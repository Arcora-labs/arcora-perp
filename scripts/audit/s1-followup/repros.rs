
// Independent S1 follow-up: run these unchanged against the PR #14 baseline
// and the fixed tree. A timeout is a test failure, not evidence of revocation.
#[tokio::test]
async fn s1f_concurrent_rotation_is_serialized_through_ack() {
    let (mut app, _, owner, sk) = prepared();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<SnapshotAck>(8);
    Arc::get_mut(&mut app).unwrap().snapshot_req = Some(tx);
    let router = build_router(app.clone(), false);
    let sig0 = signature(&app, &sk, &owner, 0).await;
    let sig1 = signature(&app, &sk, &owner, 1).await;
    let req0 = post_recovery(&hex0x(&owner), 0, &sig0);
    let req1 = post_recovery(&hex0x(&owner), 1, &sig1);
    let first = tokio::spawn(router.clone().oneshot(req0));
    let ack0 = tokio::time::timeout(Duration::from_secs(5), rx.recv()).await.unwrap().unwrap();
    let second = tokio::spawn(router.clone().oneshot(req1));
    let overlapped = tokio::time::timeout(Duration::from_millis(100), rx.recv()).await;
    assert!(overlapped.is_err(), "second rotation mutated before first recovery's durable ACK/response");
    assert_eq!(view_nonce(&app, &hex0x(&owner)).await, 1);
    ack0.send(true).unwrap();
    let response0 = first.await.unwrap().unwrap();
    assert_eq!(response0.status(), StatusCode::OK);
    assert_eq!(body_json(response0).await["recoveryNonce"], 1);
    let ack1 = tokio::time::timeout(Duration::from_secs(5), rx.recv()).await.unwrap().unwrap();
    ack1.send(true).unwrap();
    let response1 = second.await.unwrap().unwrap();
    assert_eq!(response1.status(), StatusCode::OK);
    let value = body_json(response1).await;
    assert_eq!(value["recoveryNonce"], 2);
    let key = parse_hex32(value["apiKey"].as_str().unwrap()).unwrap();
    assert_eq!(router.oneshot(get_me(&key)).await.unwrap().status(), StatusCode::OK);
}

#[tokio::test]
async fn s1f_idle_authenticated_socket_closes_without_traffic() {
    let (mut app, key, owner, sk) = prepared();
    let (tx, _) = controllable_writer();
    Arc::get_mut(&mut app).unwrap().snapshot_req = Some(tx);
    let base = spawn_ws_server(app.clone()).await;
    let (mut ws, reply) = connect_auth(&base, &key).await;
    assert_eq!(reply["type"], "authOk");
    let sig = signature(&app, &sk, &owner, 0).await;
    let result = build_router(app.clone(), false)
        .oneshot(post_recovery(&hex0x(&owner), 0, &sig)).await.unwrap();
    assert_eq!(result.status(), StatusCode::OK);
    // No public tick, private event, Ping, command, or client frame is sent.
    let next = tokio::time::timeout(Duration::from_secs(3), ws.next()).await
        .expect("idle authenticated socket was not revoked");
    if let Some(Ok(Message::Text(text))) = next {
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["message"], "api key rotated");
        let close = tokio::time::timeout(Duration::from_secs(3), ws.next()).await
            .expect("revocation error was sent but the socket remained open");
        assert!(matches!(close, None | Some(Err(_)) | Some(Ok(Message::Close(_)))));
    } else {
        assert!(matches!(next, None | Some(Err(_)) | Some(Ok(Message::Close(_)))));
    }
}

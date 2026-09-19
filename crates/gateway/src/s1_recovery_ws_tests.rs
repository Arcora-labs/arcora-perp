//! S1: recovery HTTP durability wedge (idempotent retry) + WS session revocation
//! after API-key rotation. Real route + real socket tests.
use super::*;
use crate::account_recovery::digest;
use k256::ecdsa::SigningKey;
use sha3::Keccak256 as RawKeccak;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc as StdArc, Mutex as StdMutex};
use tower::ServiceExt as _;

fn prepared() -> (Shared, [u8; 32], PubKey, SigningKey) {
    let sk = SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
    let public = sk.verifying_key().to_encoded_point(false);
    let hash = <RawKeccak as sha3::Digest>::digest(&public.as_bytes()[1..]);
    let payer: [u8; 20] = hash[12..].try_into().unwrap();
    let mut gw = Gw::boot_with(GenesisMode::Production);
    let (key, owner) = gw.register_account(Some(payer));
    gw.accounts.get_mut(&key).unwrap().deposit_address = Some(payer);
    let mut app = crate::tests::test_app();
    Arc::get_mut(&mut app).unwrap().gw = Mutex::new(gw);
    (app, key, owner, sk)
}

async fn signature(app: &Shared, sk: &SigningKey, owner: &PubKey, nonce: u64) -> [u8; 65] {
    let (chain_id, vault) = {
        let gw = app.gw.lock().await;
        (gw.chain_id, gw.vault)
    };
    let d = digest(chain_id, &vault, owner, nonce);
    let (sig, recovery) = sk.sign_prehash_recoverable(&d).unwrap();
    let mut wire = [0u8; 65];
    wire[..64].copy_from_slice(&sig.to_bytes());
    wire[64] = recovery.to_byte() + 27;
    wire
}

fn post_recovery(
    owner_hex: &str,
    nonce: u64,
    sig: &[u8; 65],
) -> axum::http::Request<axum::body::Body> {
    axum::http::Request::builder()
        .method("POST")
        .uri("/v1/accounts/recovery")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            serde_json::json!({"owner": owner_hex, "nonce": nonce, "signature": hex0x(sig)})
                .to_string(),
        ))
        .unwrap()
}

fn get_me(key: &[u8; 32]) -> axum::http::Request<axum::body::Body> {
    axum::http::Request::builder()
        .uri("/v1/accounts/me")
        .header("x-api-key", hex0x(key))
        .body(axum::body::Body::empty())
        .unwrap()
}

async fn body_json(r: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(r.into_body(), 1 << 20).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// Snapshot-writer stub whose verdict is switchable at runtime. Mode 0 = ack
/// true, 1 = ack false, 2 = park (receive but never reply), 3 = drop the ack. Parked acks are
/// drained — with the CURRENT mode — when the mode changes, so a test can
/// simulate a wedged writer and then "fix" it mid-scenario.
struct WriterCtl {
    mode: AtomicU8,
    parked: StdMutex<Vec<SnapshotAck>>,
}
fn controllable_writer() -> (tokio::sync::mpsc::Sender<SnapshotAck>, StdArc<WriterCtl>) {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<SnapshotAck>(8);
    let ctl = StdArc::new(WriterCtl {
        mode: AtomicU8::new(0),
        parked: StdMutex::new(Vec::new()),
    });
    let c = ctl.clone();
    tokio::spawn(async move {
        while let Some(ack) = rx.recv().await {
            match c.mode.load(Ordering::SeqCst) {
                2 => c.parked.lock().unwrap().push(ack),
                3 => drop(ack),
                m => {
                    let _ = ack.send(m == 0);
                }
            }
        }
    });
    (tx, ctl)
}
fn set_writer_mode(ctl: &WriterCtl, mode: u8) {
    ctl.mode.store(mode, Ordering::SeqCst);
    let parked: Vec<_> = ctl.parked.lock().unwrap().drain(..).collect();
    for ack in parked {
        let _ = ack.send(mode == 0);
    }
}

async fn view_nonce(app: &Shared, owner_hex: &str) -> u64 {
    let r = build_router(app.clone(), false)
        .oneshot(
            axum::http::Request::builder()
                .uri(format!("/v1/accounts/recovery/{owner_hex}"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    body_json(r).await["recoveryNonce"].as_u64().unwrap()
}

// ── Bug B: recovery HTTP durability wedge ────────────────────────────────────

#[tokio::test]
async fn recovery_without_writer_is_503_and_state_unchanged() {
    let (app, key, owner, sk) = prepared();
    let router = build_router(app.clone(), false);
    let owner_hex = hex0x(&owner);
    let r = router
        .clone()
        .oneshot(post_recovery(
            &owner_hex,
            0,
            &signature(&app, &sk, &owner, 0).await,
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body_json(r).await["durability"], "unknown");
    assert_eq!(view_nonce(&app, &owner_hex).await, 0, "not rotated");
    let r = router.oneshot(get_me(&key)).await.unwrap();
    assert_eq!(r.status(), StatusCode::OK, "old key still works");
}

#[tokio::test]
async fn recovery_false_ack_then_retry_returns_same_key() {
    let (tx, ctl) = controllable_writer();
    let (mut app, old_key, owner, sk) = prepared();
    Arc::get_mut(&mut app).unwrap().snapshot_req = Some(tx);
    let router = build_router(app.clone(), false);
    let owner_hex = hex0x(&owner);
    let sig = signature(&app, &sk, &owner, 0).await;
    let req = || post_recovery(&owner_hex, 0, &sig);

    set_writer_mode(&ctl, 1);
    let r = router.clone().oneshot(req()).await.unwrap();
    assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body_json(r).await["durability"], "unknown");

    set_writer_mode(&ctl, 0);
    let r = router.clone().oneshot(req()).await.unwrap();
    assert_eq!(r.status(), StatusCode::OK, "retry confirmed");
    let v = body_json(r).await;
    assert_eq!(v["durability"], "confirmed");
    let new_key_hex = v["apiKey"].as_str().unwrap().to_string();
    let new_key = parse_hex32(&new_key_hex).unwrap();

    // Safe-retry idempotence: the same authorization returns the byte-identical key.
    let r = router.clone().oneshot(req()).await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(body_json(r).await["apiKey"], new_key_hex);

    assert_eq!(
        view_nonce(&app, &owner_hex).await,
        1,
        "advanced exactly once"
    );
    let r = router.clone().oneshot(get_me(&new_key)).await.unwrap();
    assert_eq!(r.status(), StatusCode::OK, "new key works");
    let r = router.clone().oneshot(get_me(&old_key)).await.unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "old key rejected");
}

#[tokio::test]
async fn recovery_dropped_ack_then_retry_returns_same_key() {
    let (tx, ctl) = controllable_writer();
    let (mut app, _old_key, owner, sk) = prepared();
    Arc::get_mut(&mut app).unwrap().snapshot_req = Some(tx);
    let router = build_router(app.clone(), false);
    let owner_hex = hex0x(&owner);
    let sig = signature(&app, &sk, &owner, 0).await;
    let req = || post_recovery(&owner_hex, 0, &sig);

    // Writer takes the request then drops the ack (closed queue / dropped reply).
    set_writer_mode(&ctl, 3);
    let r = router.clone().oneshot(req()).await.unwrap();
    assert_eq!(
        r.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "dropped the request"
    );

    // "Fix" the writer and retry: the rotation already committed, so this is
    // the idempotent retry and must return the SAME key.
    set_writer_mode(&ctl, 0);
    let r = router.clone().oneshot(req()).await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let v = body_json(r).await;
    assert_eq!(v["durability"], "confirmed");
    let new_key = parse_hex32(v["apiKey"].as_str().unwrap()).unwrap();
    let r = router.clone().oneshot(get_me(&new_key)).await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(view_nonce(&app, &owner_hex).await, 1);
}

#[tokio::test(start_paused = true)]
async fn recovery_wedged_writer_times_out_then_retry_returns_same_key() {
    let (tx, ctl) = controllable_writer();
    let (mut app, _old_key, owner, sk) = prepared();
    Arc::get_mut(&mut app).unwrap().snapshot_req = Some(tx);
    let router = build_router(app.clone(), false);
    let owner_hex = hex0x(&owner);
    let sig = signature(&app, &sk, &owner, 0).await;
    let req = || post_recovery(&owner_hex, 0, &sig);

    set_writer_mode(&ctl, 2);
    let r = router.clone().oneshot(req()).await.unwrap();
    assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE, "timed out");
    assert!(body_json(r).await["error"]
        .as_str()
        .unwrap()
        .contains("timed out"));

    set_writer_mode(&ctl, 0);
    let r = router.clone().oneshot(req()).await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let v = body_json(r).await;
    let new_key_hex = v["apiKey"].as_str().unwrap().to_string();
    assert_eq!(v["durability"], "confirmed");
    assert_eq!(view_nonce(&app, &owner_hex).await, 1, "no double increment");
    let r = router
        .clone()
        .oneshot(get_me(&parse_hex32(&new_key_hex).unwrap()))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
}

#[tokio::test]
async fn recovery_dropped_request_then_retry_returns_same_key() {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<SnapshotAck>(8);
    tokio::spawn(async move {
        while let Some(ack) = rx.recv().await {
            let _ = ack.send(true);
        }
    });
    let (mut app, _old_key, owner, sk) = prepared();
    Arc::get_mut(&mut app).unwrap().snapshot_req = Some(tx);
    let router = build_router(app.clone(), false);
    let owner_hex = hex0x(&owner);
    let sig = signature(&app, &sk, &owner, 0).await;

    // Client gives up mid-flight: whatever the server did, the retry contract
    // must hold — same key, no double rotation.
    let owner_hex_for_task = owner_hex.clone();
    let task = tokio::spawn({
        let router = router.clone();
        async move {
            router
                .oneshot(post_recovery(&owner_hex_for_task, 0, &sig))
                .await
        }
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    task.abort();
    let _ = task.await;

    let r = router
        .clone()
        .oneshot(post_recovery(&owner_hex, 0, &sig))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let v = body_json(r).await;
    let new_key = parse_hex32(v["apiKey"].as_str().unwrap()).unwrap();
    let r = router.clone().oneshot(get_me(&new_key)).await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(view_nonce(&app, &owner_hex).await, 1);
}

#[tokio::test]
async fn recovery_racing_sequential_nonces_and_stale_retry_is_rejected() {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<SnapshotAck>(16);
    tokio::spawn(async move {
        while let Some(ack) = rx.recv().await {
            let _ = ack.send(true);
        }
    });
    let (mut app, _old_key, owner, sk) = prepared();
    Arc::get_mut(&mut app).unwrap().snapshot_req = Some(tx);
    let router = build_router(app.clone(), false);
    let owner_hex = hex0x(&owner);
    let sig0 = signature(&app, &sk, &owner, 0).await;
    let sig1 = signature(&app, &sk, &owner, 1).await;

    // Two correctly-sequenced rotations racing: both are authorized, so both
    // may land — the invariants are no panic, no lost account, exact nonce.
    let (r0, r1) = tokio::join!(
        router.clone().oneshot(post_recovery(&owner_hex, 0, &sig0)),
        router.clone().oneshot(post_recovery(&owner_hex, 1, &sig1)),
    );
    let statuses = [r0.unwrap().status(), r1.unwrap().status()];
    assert!(statuses.contains(&StatusCode::OK));
    assert_eq!(
        view_nonce(&app, &owner_hex).await,
        2,
        "exactly two rotations"
    );
    // The account still exists and is recoverable.
    assert_eq!(view_nonce(&app, &owner_hex).await, 2);

    // A retry of the SUPERSEDED first rotation must NOT hand out a key: the
    // recorded last rotation used nonce 1, so nonce 0 falls to the mismatch.
    let r = router
        .clone()
        .oneshot(post_recovery(&owner_hex, 0, &sig0))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    assert!(body_json(r).await["error"]
        .as_str()
        .unwrap()
        .contains("nonce mismatch"));
    // ...and the current generation's retry still works.
    let r = router
        .clone()
        .oneshot(post_recovery(&owner_hex, 1, &sig1))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
}

#[tokio::test]
async fn recovery_rejections_and_nonce_overflow() {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<SnapshotAck>(8);
    tokio::spawn(async move {
        while let Some(ack) = rx.recv().await {
            let _ = ack.send(true);
        }
    });
    let (mut app, _old_key, owner, sk) = prepared();
    Arc::get_mut(&mut app).unwrap().snapshot_req = Some(tx);
    let router = build_router(app.clone(), false);
    let owner_hex = hex0x(&owner);
    let sig = signature(&app, &sk, &owner, 0).await;
    let req = || post_recovery(&owner_hex, 0, &sig);

    // Unknown owner.
    let r = router
        .clone()
        .oneshot(post_recovery(&hex0x(&[0xee; 32]), 0, &sig))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);

    // Wrong domain digest: signature made over a different chain id.
    let wrong_sk = SigningKey::from_bytes((&[9u8; 32]).into()).unwrap();
    let (chain_id, vault) = {
        let gw = app.gw.lock().await;
        (gw.chain_id, gw.vault)
    };
    let d = digest(chain_id ^ 1, &vault, &owner, 0);
    let (s, rec) = wrong_sk.sign_prehash_recoverable(&d).unwrap();
    let mut wire = [0u8; 65];
    wire[..64].copy_from_slice(&s.to_bytes());
    wire[64] = rec.to_byte() + 27;
    let r = router
        .clone()
        .oneshot(post_recovery(&owner_hex, 0, &wire))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);

    // Non-authorizer signer (valid signature, wrong key).
    let foreign = signature(&app, &wrong_sk, &owner, 0).await;
    let r = router
        .clone()
        .oneshot(post_recovery(&owner_hex, 0, &foreign))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);

    // Genuine replay of the last rotation IS the idempotent retry (returns the
    // same key) — verified here so the rejection cases below are unambiguous.
    let r = router.clone().oneshot(req()).await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let key_hex = body_json(r).await["apiKey"].as_str().unwrap().to_string();
    let r = router.clone().oneshot(req()).await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(body_json(r).await["apiKey"], key_hex);

    // Recovery nonce overflow: rotation refused, state untouched.
    {
        let mut gw = app.gw.lock().await;
        for a in gw.accounts.values_mut() {
            a.recovery_nonce = u64::MAX;
        }
    }
    let sig_max = signature(&app, &sk, &owner, u64::MAX).await;
    let r = router
        .clone()
        .oneshot(post_recovery(&owner_hex, u64::MAX, &sig_max))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    assert_eq!(view_nonce(&app, &owner_hex).await, u64::MAX, "unchanged");
}

// ── Bug A: WS sessions revoked after API-key rotation ────────────────────────

use futures_util::{SinkExt as _, StreamExt as _};
use tokio_tungstenite::tungstenite::Message;

async fn spawn_ws_server(app: Shared) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, build_router(app, false))
            .await
            .unwrap();
    });
    format!("ws://{addr}")
}

async fn connect_auth(
    base: &str,
    key: &[u8; 32],
) -> (
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    serde_json::Value,
) {
    let (mut ws, _) = tokio_tungstenite::connect_async(format!("{base}/v1/ws"))
        .await
        .unwrap();
    // First frame is the public snapshot.
    let _initial: serde_json::Value = match tokio::time::timeout(Duration::from_secs(5), ws.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
    {
        Message::Text(t) => serde_json::from_str(&t).unwrap(),
        other => panic!("expected text frame, got {other:?}"),
    };
    ws.send(Message::Text(
        serde_json::json!({"type":"auth","apiKey":hex0x(key)}).to_string(),
    ))
    .await
    .unwrap();
    loop {
        let v: serde_json::Value = match tokio::time::timeout(Duration::from_secs(5), ws.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
        {
            Message::Text(t) => serde_json::from_str(&t).unwrap(),
            other => panic!("expected text frame, got {other:?}"),
        };
        if v.get("type").is_some() {
            return (ws, v);
        }
    }
}

fn publish_private(app: &Shared, owner_hex: &str, tag: u64) {
    let _ = app.events_tx.send(
        serde_json::json!({"owner": owner_hex, "type": "execution", "orderId": tag, "status": "CANCELLED"})
            .to_string(),
    );
}

#[tokio::test]
async fn ws_session_revoked_after_key_rotation() {
    let (mut app, old_key, owner, sk) = prepared();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<SnapshotAck>(8);
    tokio::spawn(async move {
        while let Some(ack) = rx.recv().await {
            let _ = ack.send(true);
        }
    });
    Arc::get_mut(&mut app).unwrap().snapshot_req = Some(tx);
    let owner_hex = hex0x(&owner);
    let base = spawn_ws_server(app.clone()).await;

    // 1. Authenticate with the old key; receive a private event.
    let (mut ws, auth_reply) = connect_auth(&base, &old_key).await;
    assert_eq!(auth_reply["type"], "authOk");
    assert_eq!(auth_reply["owner"], owner_hex);
    publish_private(&app, &owner_hex, 1);
    let ev: serde_json::Value = match tokio::time::timeout(Duration::from_secs(5), ws.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
    {
        Message::Text(t) => serde_json::from_str(&t).unwrap(),
        other => panic!("expected text frame, got {other:?}"),
    };
    assert_eq!(
        ev["type"], "execution",
        "authed session receives its events"
    );

    // 2. Rotate the key over the real recovery route.
    let r = build_router(app.clone(), false)
        .oneshot(post_recovery(
            &owner_hex,
            0,
            &signature(&app, &sk, &owner, 0).await,
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let new_key = parse_hex32(body_json(r).await["apiKey"].as_str().unwrap()).unwrap();

    // 3. A private event published AFTER the rotation must not be delivered:
    // the session is revoked (error frame and/or close).
    publish_private(&app, &owner_hex, 2);
    let mut saw_rotation_error = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let msg = tokio::time::timeout(remaining, ws.next()).await;
        match msg {
            Ok(Some(Ok(Message::Text(t)))) => {
                let v: serde_json::Value = serde_json::from_str(&t).unwrap();
                assert_ne!(
                    v["type"], "execution",
                    "revoked session must not receive private events"
                );
                if v["message"] == "api key rotated" {
                    saw_rotation_error = true;
                }
            }
            Ok(Some(Ok(Message::Close(_)))) | Err(_) => break,
            Ok(Some(Ok(_))) => continue,
            Ok(None) => break,
            Ok(Some(Err(_))) => break,
        }
        if saw_rotation_error {
            break;
        }
    }

    // 4. Reconnect with the NEW key: auth ok, private events flow again.
    let (mut ws2, auth_reply) = connect_auth(&base, &new_key).await;
    assert_eq!(auth_reply["type"], "authOk");
    publish_private(&app, &owner_hex, 3);
    let ev: serde_json::Value = match tokio::time::timeout(Duration::from_secs(5), ws2.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
    {
        Message::Text(t) => serde_json::from_str(&t).unwrap(),
        other => panic!("expected text frame, got {other:?}"),
    };
    assert_eq!(ev["type"], "execution");
    assert_eq!(ev["orderId"], 3);

    // 5. Reconnect with the OLD key: rejected.
    let (_ws3, reply) = connect_auth(&base, &old_key).await;
    assert_eq!(reply["type"], "error");
}

#[tokio::test]
async fn ws_unrelated_sessions_unaffected_by_rotation() {
    let (mut app, key_a, owner_a, sk_a) = prepared();
    // Second account with its own authorizer.
    let sk_b = SigningKey::from_bytes((&[11u8; 32]).into()).unwrap();
    let public_b = sk_b.verifying_key().to_encoded_point(false);
    let hash_b = <RawKeccak as sha3::Digest>::digest(&public_b.as_bytes()[1..]);
    let payer_b: [u8; 20] = hash_b[12..].try_into().unwrap();
    let (key_b, owner_b) = {
        let mut gw = app.gw.lock().await;
        let (k, o) = gw.register_account(Some(payer_b));
        gw.accounts.get_mut(&k).unwrap().deposit_address = Some(payer_b);
        (k, o)
    };
    let (tx, mut rx) = tokio::sync::mpsc::channel::<SnapshotAck>(8);
    tokio::spawn(async move {
        while let Some(ack) = rx.recv().await {
            let _ = ack.send(true);
        }
    });
    Arc::get_mut(&mut app).unwrap().snapshot_req = Some(tx);
    let hex_a = hex0x(&owner_a);
    let hex_b = hex0x(&owner_b);
    let base = spawn_ws_server(app.clone()).await;

    let (mut ws_a, reply) = connect_auth(&base, &key_a).await;
    assert_eq!(reply["type"], "authOk");
    let (mut ws_b, reply) = connect_auth(&base, &key_b).await;
    assert_eq!(reply["type"], "authOk");

    // Rotate A only.
    let r = build_router(app.clone(), false)
        .oneshot(post_recovery(
            &hex_a,
            0,
            &signature(&app, &sk_a, &owner_a, 0).await,
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);

    // B's session still receives B's private events.
    publish_private(&app, &hex_b, 10);
    let ev: serde_json::Value = match tokio::time::timeout(Duration::from_secs(5), ws_b.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
    {
        Message::Text(t) => serde_json::from_str(&t).unwrap(),
        other => panic!("expected text frame, got {other:?}"),
    };
    assert_eq!(ev["type"], "execution");
    assert_eq!(ev["owner"], hex_b);

    // A's session is revoked on the next private event for A.
    publish_private(&app, &hex_a, 11);
    let mut revoked = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !revoked {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(remaining, ws_a.next()).await {
            Ok(Some(Ok(Message::Text(t)))) => {
                let v: serde_json::Value = serde_json::from_str(&t).unwrap();
                assert_ne!(v["type"], "execution");
                if v["message"] == "api key rotated" {
                    revoked = true;
                }
            }
            _ => revoked = true, // close / timeout: session gone
        }
    }
    assert!(revoked);
}

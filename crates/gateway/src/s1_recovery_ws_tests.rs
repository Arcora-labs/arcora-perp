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
    let ack0 = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .unwrap()
        .unwrap();
    let second = tokio::spawn(router.clone().oneshot(req1));
    let overlapped = tokio::time::timeout(Duration::from_millis(100), rx.recv()).await;
    assert!(
        overlapped.is_err(),
        "second rotation mutated before first recovery's durable ACK/response"
    );
    assert_eq!(view_nonce(&app, &hex0x(&owner)).await, 1);
    ack0.send(true).unwrap();
    let response0 = first.await.unwrap().unwrap();
    assert_eq!(response0.status(), StatusCode::OK);
    assert_eq!(body_json(response0).await["recoveryNonce"], 1);
    let ack1 = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .unwrap()
        .unwrap();
    ack1.send(true).unwrap();
    let response1 = second.await.unwrap().unwrap();
    assert_eq!(response1.status(), StatusCode::OK);
    let value = body_json(response1).await;
    assert_eq!(value["recoveryNonce"], 2);
    let key = parse_hex32(value["apiKey"].as_str().unwrap()).unwrap();
    assert_eq!(
        router.oneshot(get_me(&key)).await.unwrap().status(),
        StatusCode::OK
    );
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
        .oneshot(post_recovery(&hex0x(&owner), 0, &sig))
        .await
        .unwrap();
    assert_eq!(result.status(), StatusCode::OK);
    // No public tick, private event, Ping, command, or client frame is sent.
    let next = tokio::time::timeout(Duration::from_secs(3), ws.next())
        .await
        .expect("idle authenticated socket was not revoked");
    if let Some(Ok(Message::Text(text))) = next {
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["message"], "api key rotated");
        let close = tokio::time::timeout(Duration::from_secs(3), ws.next())
            .await
            .expect("revocation error was sent but the socket remained open");
        assert!(matches!(
            close,
            None | Some(Err(_)) | Some(Ok(Message::Close(_)))
        ));
    } else {
        assert!(matches!(
            next,
            None | Some(Err(_)) | Some(Ok(Message::Close(_)))
        ));
    }
}

#[tokio::test]
async fn s1f_send_lease_fences_rotation_without_holding_gw() {
    let (mut app, key, owner, sk) = prepared();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<SnapshotAck>(8);
    Arc::get_mut(&mut app).unwrap().snapshot_req = Some(tx);
    let session =
        crate::credential_session::Session::authenticate(&*app.gw.lock().await, key).unwrap();
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let send = tokio::spawn({
        let app = app.clone();
        async move {
            crate::credential_session::send_fenced(&app, &session, async {
                entered_tx.send(()).unwrap();
                release_rx.await.unwrap();
                Ok::<(), ()>(())
            })
            .await
        }
    });
    entered_rx.await.unwrap();
    // The test future is paused at the actual production send boundary.
    let before = app.gw.lock().await.snapshot_plain();
    let sig = signature(&app, &sk, &owner, 0).await;
    assert!(
        app.gw.lock().await.recover_account(owner, 0, &sig).is_err(),
        "synchronous callers must not bypass an in-flight send lease"
    );
    assert_eq!(app.gw.lock().await.snapshot_plain(), before);
    let router = build_router(app.clone(), false);
    let recovery = tokio::spawn(router.oneshot(post_recovery(&hex0x(&owner), 0, &sig)));
    assert!(tokio::time::timeout(Duration::from_millis(100), rx.recv())
        .await
        .is_err());
    assert_eq!(view_nonce(&app, &hex0x(&owner)).await, 0);
    // Another account's registration and lookup remain possible during the send.
    let (other, _) = app.gw.lock().await.register_account(None);
    assert_eq!(
        build_router(app.clone(), false)
            .oneshot(get_me(&other))
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
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
    let session =
        crate::credential_session::Session::authenticate(&*app.gw.lock().await, key).unwrap();
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let send = tokio::spawn({
        let app = app.clone();
        async move {
            crate::credential_session::send_fenced(&app, &session, async {
                entered_tx.send(()).unwrap();
                std::future::pending::<Result<(), ()>>().await
            })
            .await
        }
    });
    entered_rx.await.unwrap();
    let sig = signature(&app, &sk, &owner, 0).await;
    let recovery = tokio::spawn(build_router(app.clone(), false).oneshot(post_recovery(
        &hex0x(&owner),
        0,
        &sig,
    )));
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
    assert!(matches!(
        futures_util::poll!(&mut recovery),
        std::task::Poll::Pending
    ));
    publish_private(&app, &hex0x(&owner), 901);
    tokio::task::yield_now().await;
    drop(gate);
    assert_eq!(recovery.await.unwrap().status(), StatusCode::OK);
    let next = tokio::time::timeout(Duration::from_secs(3), ws.next())
        .await
        .unwrap();
    if let Some(Ok(Message::Text(text))) = next {
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["message"], "api key rotated");
        assert_ne!(value["type"], "execution");
    } else {
        assert!(matches!(
            next,
            None | Some(Err(_)) | Some(Ok(Message::Close(_)))
        ));
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
    let response = router
        .clone()
        .oneshot(post_recovery(&hex0x(&owner), 0, &sig))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
    let value = body_json(response).await;
    assert_eq!(value["durability"], "unknown");
    assert!(value.get("apiKey").is_none());
    assert!(value["error"].as_str().unwrap().contains("timed out"));
    drop(rx.recv().await);
    let retry = tokio::spawn(
        router
            .clone()
            .oneshot(post_recovery(&hex0x(&owner), 0, &sig)),
    );
    rx.recv().await.unwrap().send(true).unwrap();
    let response = retry.await.unwrap().unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(view_nonce(&app, &hex0x(&owner)).await, 1);
    let before = body_json(response).await["apiKey"].clone();
    drop(rx);
    let response = router
        .oneshot(post_recovery(&hex0x(&owner), 0, &sig))
        .await
        .unwrap();
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
    let request = tokio::spawn(build_router(app.clone(), false).oneshot(post_recovery(
        &hex0x(&owner),
        0,
        &sig,
    )));
    let ack = rx.recv().await.unwrap(); // Exact cancellation point after mutation.
    let directory =
        std::env::temp_dir().join(format!("dark-perp-s1f-{}", hex0x(&csprng_bytes32())));
    std::fs::create_dir(&directory).unwrap();
    let path = directory.join("snapshot");
    let seed = [0x71; 32];
    assert!(write_snapshot(&app, &path, seed, Arc::new(Mutex::new(()))).await);
    let sealed = std::fs::read(&path).unwrap();
    let lost_key = app.gw.lock().await.accounts.keys().next().copied().unwrap();
    request.abort();
    assert!(request.await.unwrap_err().is_cancelled());
    assert!(
        ack.send(true).is_err(),
        "cancelled response must not accept ACK"
    );
    let plain = snapshot::open(&sealed, &seed).unwrap();
    let restored = Gw::boot_restored(&plain).unwrap();
    assert_eq!(restored.accounts[&lost_key].recovery_nonce, 1);
    assert!(restored.accounts[&lost_key].recovery_last.is_none());
    assert_eq!(
        restored.snapshot_plain(),
        plain,
        "runtime fences must not change persisted bytes"
    );
    let mut restarted = crate::tests::test_app();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<SnapshotAck>(8);
    let state = Arc::get_mut(&mut restarted).unwrap();
    state.gw = Mutex::new(restored);
    state.snapshot_req = Some(tx);
    // Do not guess nonce+1 after a restart. Read the restored public challenge.
    let nonce = view_nonce(&restarted, &hex0x(&owner)).await;
    let old_retry = build_router(restarted.clone(), false)
        .oneshot(post_recovery(&hex0x(&owner), 0, &sig))
        .await
        .unwrap();
    assert_eq!(old_retry.status(), StatusCode::BAD_REQUEST);
    let sig = signature(&restarted, &sk, &owner, nonce).await;
    let recovery = tokio::spawn(
        build_router(restarted.clone(), false).oneshot(post_recovery(&hex0x(&owner), nonce, &sig)),
    );
    let ack = rx.recv().await.unwrap();
    assert!(write_snapshot(&restarted, &path, seed, Arc::new(Mutex::new(()))).await);
    ack.send(true).unwrap();
    let response = recovery.await.unwrap().unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let value = body_json(response).await;
    let key = parse_hex32(value["apiKey"].as_str().unwrap()).unwrap();
    assert_ne!(key, original);
    assert_ne!(key, lost_key);
    let reloaded =
        Gw::boot_restored(&snapshot::open(&std::fs::read(&path).unwrap(), &seed).unwrap()).unwrap();
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
    let task = tokio::spawn(build_router(app.clone(), false).oneshot(post_recovery(
        &hex0x(&owner),
        0,
        &sig,
    )));
    let ack = rx.recv().await.unwrap();
    // Controlled fixture mutation at the rebind boundary, not an end-to-end
    // rebind authorization test. Tests the final response guard independently.
    app.gw
        .lock()
        .await
        .accounts
        .values_mut()
        .next()
        .unwrap()
        .deposit_address = Some([0x99; 20]);
    ack.send(true).unwrap();
    let response = task.await.unwrap().unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert!(body_json(response).await.get("apiKey").is_none());
}

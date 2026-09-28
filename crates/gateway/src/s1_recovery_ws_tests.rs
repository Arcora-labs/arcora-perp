//! S1: fresh-challenge recovery, durable publication and WS session revocation
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

/// The round-3 recovery contract: after ANY unknown outcome (timeout, lost
/// response, dropped request) the client reads the CURRENT nonce from the
/// recovery view, signs a FRESH authorization, and posts that. Reusing a stale
/// authorization is always rejected. Returns the confirmed new key.
async fn fresh_challenge(
    app: &Shared,
    router: &axum::Router,
    owner: &PubKey,
    sk: &SigningKey,
    owner_hex: &str,
) -> [u8; 32] {
    let nonce = view_nonce(app, owner_hex).await;
    let sig = signature(app, sk, owner, nonce).await;
    let r = router
        .clone()
        .oneshot(post_recovery(owner_hex, nonce, &sig))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK, "fresh challenge confirmed");
    let v = body_json(r).await;
    assert_eq!(v["durability"], "confirmed");
    parse_hex32(v["apiKey"].as_str().unwrap()).unwrap()
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
async fn recovery_false_ack_then_fresh_challenge_succeeds() {
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
    // The rotation WAS applied in memory: the nonce advanced past the failed
    // attempt's authorization, so reusing it is a stale authorization.
    assert_eq!(view_nonce(&app, &owner_hex).await, 1);

    // Stale reuse of the original authorization: rejected, no secret leaked.
    let r = router.clone().oneshot(req()).await.unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    assert!(body_json(r).await["error"]
        .as_str()
        .unwrap()
        .contains("nonce mismatch"));

    // Fresh challenge at the current nonce: confirmed, exactly one more step.
    set_writer_mode(&ctl, 0);
    let new_key = fresh_challenge(&app, &router, &owner, &sk, &owner_hex).await;
    assert_eq!(
        view_nonce(&app, &owner_hex).await,
        2,
        "no double increment from the failed attempt"
    );
    let r = router.clone().oneshot(get_me(&new_key)).await.unwrap();
    assert_eq!(r.status(), StatusCode::OK, "new key works");
    let r = router.clone().oneshot(get_me(&old_key)).await.unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "old key rejected");
}

#[tokio::test]
async fn recovery_dropped_ack_then_fresh_challenge_succeeds() {
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
    assert_eq!(view_nonce(&app, &owner_hex).await, 1);

    // Stale reuse rejected; fresh challenge at the current nonce succeeds.
    let r = router.clone().oneshot(req()).await.unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    set_writer_mode(&ctl, 0);
    let new_key = fresh_challenge(&app, &router, &owner, &sk, &owner_hex).await;
    let r = router.clone().oneshot(get_me(&new_key)).await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(view_nonce(&app, &owner_hex).await, 2);
}

#[tokio::test(start_paused = true)]
async fn recovery_wedged_writer_times_out_then_fresh_challenge_succeeds() {
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
    assert_eq!(
        view_nonce(&app, &owner_hex).await,
        1,
        "one applied rotation"
    );

    set_writer_mode(&ctl, 0);
    let new_key = fresh_challenge(&app, &router, &owner, &sk, &owner_hex).await;
    assert_eq!(view_nonce(&app, &owner_hex).await, 2, "no double increment");
    let r = router.clone().oneshot(get_me(&new_key)).await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
}

#[tokio::test]
async fn recovery_dropped_request_then_fresh_challenge_succeeds() {
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

    // Client gives up mid-flight: whatever the server did, the fresh-challenge
    // contract must hold — read the view, sign the current nonce, succeed.
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

    let nonce_before = view_nonce(&app, &owner_hex).await;
    // Stale reuse of the original authorization is rejected either way.
    if nonce_before == 1 {
        let r = router
            .clone()
            .oneshot(post_recovery(&owner_hex, 0, &sig))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    }
    let new_key = fresh_challenge(&app, &router, &owner, &sk, &owner_hex).await;
    let r = router.clone().oneshot(get_me(&new_key)).await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(
        view_nonce(&app, &owner_hex).await,
        nonce_before + 1,
        "exactly one rotation beyond the aborted attempt's applied state"
    );
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

    // Re-presenting EITHER used authorization is rejected — there is no
    // idempotent-retry acceptance; a client must sign the current nonce.
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
    let r = router
        .clone()
        .oneshot(post_recovery(&owner_hex, 1, &sig1))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    assert!(body_json(r).await["error"]
        .as_str()
        .unwrap()
        .contains("nonce mismatch"));
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

    // Replay of the just-applied authorization is rejected (stale challenge —
    // the client must GET the view and sign the current nonce instead).
    let r = router.clone().oneshot(req()).await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let r = router.clone().oneshot(req()).await.unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    assert!(
        body_json(r).await["apiKey"].is_null(),
        "no secret on replay"
    );

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
            Ok(Some(Ok(Message::Close(_)))) => break,
            Err(_) => panic!("revoked socket did not close before the deadline"),
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
            Err(_) => panic!("revoked socket did not close before the deadline"),
            Ok(None) | Ok(Some(Err(_))) | Ok(Some(Ok(Message::Close(_)))) => revoked = true,
            Ok(Some(Ok(_))) => {}
        }
    }
    assert!(revoked);
}

// ── S1 follow-up: superseded race, WS command surface, revocation boundary ────

/// Round-3 makes rotations fully serialized: `post_v1_recovery` holds the
/// `ws_delivery` WRITE guard from the queue pre-flight through the post-ACK
/// recheck, so a second rotation cannot interleave between a parked rotation's
/// mutation and its recheck — the round-2 "superseded 409" interleaving is
/// structurally impossible (the recheck remains as defense in depth). This test
/// pins the serialization: B must wait for A's parked ACK; A is correctly
/// confirmed with its key at its own linearization point; B then supersedes it.
#[tokio::test]
async fn recovery_rotations_serialize_against_inflight_ack() {
    // Writer that parks the FIRST request's ack until signaled, and acks true
    // every subsequent request.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<SnapshotAck>(8);
    let parked: StdArc<StdMutex<Option<SnapshotAck>>> = StdArc::new(StdMutex::new(None));
    let parked_flag = parked.clone();
    let notify = StdArc::new(tokio::sync::Notify::new());
    let notify_flag = notify.clone();
    tokio::spawn(async move {
        let mut first = true;
        while let Some(ack) = rx.recv().await {
            if first {
                first = false;
                *parked_flag.lock().unwrap() = Some(ack);
                notify_flag.notify_one();
            } else {
                let _ = ack.send(true);
            }
        }
    });
    let (mut app, key_a, owner, sk) = prepared();
    Arc::get_mut(&mut app).unwrap().snapshot_req = Some(tx);
    let router = build_router(app.clone(), false);
    let owner_hex = hex0x(&owner);
    let sig0 = signature(&app, &sk, &owner, 0).await;
    let sig1 = signature(&app, &sk, &owner, 1).await;

    // Request A: rotates nonce 0, then parks waiting for its ACK — holding the
    // revocation guard the whole time.
    let task_a = tokio::spawn({
        let router = router.clone();
        let owner_hex = owner_hex.clone();
        async move {
            router
                .oneshot(post_recovery(&owner_hex, 0, &sig0))
                .await
                .unwrap()
        }
    });
    notify.notified().await;
    assert!(!task_a.is_finished(), "A is parked on its snapshot ACK");

    // Request B (nonce 1) arrives while A is parked: it must NOT interleave.
    let task_b = tokio::spawn({
        let router = router.clone();
        let owner_hex = owner_hex.clone();
        async move {
            router
                .oneshot(post_recovery(&owner_hex, 1, &sig1))
                .await
                .unwrap()
        }
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        !task_b.is_finished(),
        "B must wait for A's guard, not interleave with the parked rotation"
    );
    // A's rotation committed before it parked; its key is the active one.
    assert_eq!(view_nonce(&app, &owner_hex).await, 1);
    let r = router.clone().oneshot(get_me(&key_a)).await.unwrap();
    assert_eq!(
        r.status(),
        StatusCode::UNAUTHORIZED,
        "A's new key replaced the original"
    );

    // Release A's ACK: A completes confirmed with ITS key (still active at its
    // recheck — correct at A's linearization point).
    parked.lock().unwrap().take().unwrap().send(true).unwrap();
    let r_a = task_a.await.unwrap();
    assert_eq!(
        r_a.status(),
        StatusCode::OK,
        "A confirmed at its linearization point"
    );
    let key_a_new = parse_hex32(body_json(r_a).await["apiKey"].as_str().unwrap()).unwrap();
    assert_ne!(key_a_new, key_a);

    // B now runs to completion and supersedes A's key.
    let r_b = tokio::time::timeout(Duration::from_secs(5), task_b)
        .await
        .expect("B unblocked once A released the guard")
        .unwrap();
    assert_eq!(r_b.status(), StatusCode::OK, "B confirmed");
    let key_b = parse_hex32(body_json(r_b).await["apiKey"].as_str().unwrap()).unwrap();
    assert_ne!(key_b, key_a_new);

    // Final state: B's key active, both earlier keys dead.
    {
        let gw = app.gw.lock().await;
        assert!(!gw.accounts.contains_key(&key_a), "original key gone");
        assert!(
            !gw.accounts.contains_key(&key_a_new),
            "A's key superseded by B"
        );
        assert!(gw.accounts.contains_key(&key_b), "winner keeps the account");
        assert_eq!(gw.accounts[&key_b].recovery_nonce, 2);
    }
    assert_eq!(view_nonce(&app, &owner_hex).await, 2);
    let r = router.clone().oneshot(get_me(&key_b)).await.unwrap();
    assert_eq!(r.status(), StatusCode::OK, "B's key works");
    let r = router.clone().oneshot(get_me(&key_a_new)).await.unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "A's key rejected");
}

/// WS implements ONLY `auth` frames. Hypothetical command frames — including
/// garbage and binary — must be ignored without touching account state and
/// without killing the connection.
#[tokio::test]
async fn ws_non_auth_command_frames_do_not_mutate_state() {
    let (app, key, owner, _sk) = prepared();
    let owner_hex = hex0x(&owner);
    let base = spawn_ws_server(app.clone()).await;
    let (mut ws, reply) = connect_auth(&base, &key).await;
    assert_eq!(reply["type"], "authOk");

    let frames = [
        Message::Text(
            serde_json::json!({"type":"placeOrder","marketId":0,"size":"100","side":"BUY"})
                .to_string(),
        ),
        Message::Text(
            serde_json::json!({"type":"cancel","orderId":"0x01"}).to_string(),
        ),
        Message::Text(
            serde_json::json!({"type":"withdraw","amount":"1000","to":"0x000000000000000000000000000000000000dead"})
                .to_string(),
        ),
        Message::Text(serde_json::json!({"type":"subscribe","channel":"fills"}).to_string()),
        Message::Text("{not valid json".to_string()),
        Message::Binary(vec![0xde, 0xad, 0xbe, 0xef]),
    ];
    for f in frames {
        ws.send(f).await.unwrap();
    }

    // The gateway lock is observable: nothing about the account may have moved.
    {
        let gw = app.gw.lock().await;
        let a = &gw.accounts[&key];
        assert!(a.orders.is_empty(), "no order landed");
        assert_eq!(a.nonce, 1, "account nonce untouched");
        assert_eq!(a.orders_this_sec, 0);
        assert!(a.deposit_authorizations.is_empty());
        assert!(gw.deposits.credits.is_empty(), "no credit landed");
        assert!(gw.deposits.routes.is_empty(), "no route landed");
    }

    // The connection is still healthy: the VALID session keeps receiving its
    // own private events (commands are ignored, not fatal).
    publish_private(&app, &owner_hex, 77);
    let ev: serde_json::Value = match tokio::time::timeout(Duration::from_secs(5), ws.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
    {
        Message::Text(t) => serde_json::from_str(&t).unwrap(),
        other => panic!("expected text frame, got {other:?}"),
    };
    assert_eq!(ev["type"], "execution");
    assert_eq!(ev["orderId"], 77);
}

/// Revocation boundary under backpressure: the rotation HTTP request must not
/// block on a slow WS consumer (the Gw lock is never held across a socket
/// send), and once revocation fires no owner event is delivered afterwards.
#[tokio::test]
async fn ws_revocation_race_slow_consumer_and_no_lock_across_send() {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<SnapshotAck>(8);
    tokio::spawn(async move {
        while let Some(ack) = rx.recv().await {
            let _ = ack.send(true);
        }
    });
    let (mut app, old_key, owner, sk) = prepared();
    Arc::get_mut(&mut app).unwrap().snapshot_req = Some(tx);
    let owner_hex = hex0x(&owner);
    let base = spawn_ws_server(app.clone()).await;
    let (mut ws, reply) = connect_auth(&base, &old_key).await;
    assert_eq!(reply["type"], "authOk");

    // Flood the session's queue without reading it, then rotate mid-stream.
    for tag in 0..50 {
        publish_private(&app, &owner_hex, tag);
    }
    // (a) The rotation must complete promptly even though the socket is not
    // being read — i.e. no gateway lock is held across a socket send.
    let rotate = tokio::time::timeout(Duration::from_secs(5), async {
        build_router(app.clone(), false)
            .oneshot(post_recovery(
                &owner_hex,
                0,
                &signature(&app, &sk, &owner, 0).await,
            ))
            .await
            .unwrap()
    });
    let r = rotate
        .await
        .expect("rotation wedged behind the slow WS consumer");
    assert_eq!(r.status(), StatusCode::OK);
    let new_key = parse_hex32(body_json(r).await["apiKey"].as_str().unwrap()).unwrap();

    // (b) An error frame is advisory; only actual transport termination proves
    // revocation. A quiet reader or an arbitrary protocol error is not success.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut saw_revocation = false;
    loop {
        match tokio::time::timeout_at(deadline, ws.next())
            .await
            .expect("slow consumer did not reach transport closure")
        {
            None | Some(Ok(Message::Close(_))) => break,
            Some(Err(error)) if is_transport_closed(&error) => break,
            Some(Ok(Message::Text(text))) => {
                let value: serde_json::Value = serde_json::from_str(&text).unwrap();
                assert!(!saw_revocation, "payload was flushed after revocation");
                saw_revocation = value["message"] == "api key rotated";
            }
            other => panic!("unexpected revocation result: {other:?}"),
        }
    }

    // (c) A fresh session under the new key receives owner events again.
    let (mut ws2, reply) = connect_auth(&base, &new_key).await;
    assert_eq!(reply["type"], "authOk");
    publish_private(&app, &owner_hex, 1000);
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
    assert_eq!(ev["orderId"], 1000);
}

/// Restart boundary: a process restart (snapshot round-trip) keeps only the
/// durable rotation state. The old nonce-0 authorization is then just a stale
/// authorization — it must be REJECTED, never answered with the key (no secret
/// leak post-restart).
#[tokio::test]
async fn recovery_restart_drops_pending_retry_and_rejects_old_authorization() {
    let (app, _old_key, owner, sk) = prepared();
    let owner_hex = hex0x(&owner);
    let sig0 = signature(&app, &sk, &owner, 0).await;

    // Apply the rotation the way the handler does, then snapshot+restore to
    // simulate a restart with the ACKed state (trailer carries recovery_nonce).
    let mut restored = {
        let mut gw = app.gw.lock().await;
        let key1 = gw.recover_account(owner, 0, &sig0).unwrap();
        let snapshot = gw.snapshot_plain();
        let restored = Gw::boot_restored(&snapshot).unwrap();
        // Everything about the rotation survived the restart...
        assert!(restored.accounts.contains_key(&key1));
        assert_eq!(restored.accounts[&key1].recovery_nonce, 1);
        restored
    };

    // ...and the old nonce-0 authorization is stale, not a retry: rejected, and
    // the key never comes back. A client that lost its response to a restart
    // must GET the view and sign nonce 1.
    let key1 = *restored.accounts.keys().next().unwrap();
    let err = restored.recover_account(owner, 0, &sig0).unwrap_err();
    assert!(
        err.contains("nonce mismatch"),
        "stale authorization after restart must be rejected, got: {err}"
    );
    assert!(restored.accounts.contains_key(&key1), "account intact");

    // The recovery view reports the fresh nonce so the client can build a new
    // authorization.
    let mut app2 = crate::tests::test_app();
    Arc::get_mut(&mut app2).unwrap().gw = Mutex::new(restored);
    let r = build_router(app2, false)
        .oneshot(
            axum::http::Request::builder()
                .uri(format!("/v1/accounts/recovery/{owner_hex}"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let v = body_json(r).await;
    assert_eq!(v["recoveryNonce"], 1);
    assert_eq!(v["owner"], owner_hex);
}

// ── S1 round-3: queue pre-flight, real write/restore ─────────────────────────

/// A CLOSED snapshot queue is discovered BEFORE the irreversible in-memory
/// rotation: 503 durability-unknown with state provably untouched.
#[tokio::test]
async fn recovery_closed_queue_is_preflight_503_and_state_unchanged() {
    let (tx, rx) = tokio::sync::mpsc::channel::<SnapshotAck>(8);
    drop(rx); // writer is gone
    let (mut app, key, owner, sk) = prepared();
    Arc::get_mut(&mut app).unwrap().snapshot_req = Some(tx);
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
    let v = body_json(r).await;
    assert_eq!(v["durability"], "unknown");
    assert!(v["error"].as_str().unwrap().contains("writer is gone"));
    assert!(v["apiKey"].is_null(), "no key on a refused rotation");
    // State provably unchanged: the old key still works, nonce unmoved.
    assert_eq!(view_nonce(&app, &owner_hex).await, 0);
    let r = router.oneshot(get_me(&key)).await.unwrap();
    assert_eq!(r.status(), StatusCode::OK, "old key still works");
}

/// A FULL snapshot queue is likewise refused pre-mutation.
#[tokio::test]
async fn recovery_full_queue_is_preflight_503_and_state_unchanged() {
    let (tx, _rx) = tokio::sync::mpsc::channel::<SnapshotAck>(1);
    // Fill the only queue slot; the receiver never drains it.
    let (filler, _filler_rx) = tokio::sync::oneshot::channel::<bool>();
    tx.try_send(filler).unwrap();
    let (mut app, key, owner, sk) = prepared();
    Arc::get_mut(&mut app).unwrap().snapshot_req = Some(tx);
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
    let v = body_json(r).await;
    assert_eq!(v["durability"], "unknown");
    assert!(v["error"].as_str().unwrap().contains("queue is full"));
    assert!(v["apiKey"].is_null(), "no key on a refused rotation");
    assert_eq!(view_nonce(&app, &owner_hex).await, 0);
    let r = router.oneshot(get_me(&key)).await.unwrap();
    assert_eq!(r.status(), StatusCode::OK, "old key still works");
}

/// The confirmed ACK must cover the exact generation durably: the writer stub
/// performs the REAL serialization (`write_snapshot`, same as the production
/// writer task), and the test restores the Gw from the persisted bytes via the
/// production open path — the new key must be the active credential there,
/// and replaying the original authorization against the restored state must
/// be rejected.
#[tokio::test]
async fn recovery_confirmed_via_real_snapshot_write_and_restore() {
    let seed = [7u8; 32];
    let dir = std::env::temp_dir().join(format!(
        "dark-perp-s1-write-restore-{}-{}",
        std::process::id(),
        hex0x(&csprng_bytes32())
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("snapshot.bin");
    let serial: Arc<Mutex<()>> = Arc::new(Mutex::new(()));

    let (mut app, old_key, owner, sk) = prepared();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<SnapshotAck>(8);
    Arc::get_mut(&mut app).unwrap().snapshot_req = Some(tx);
    let app_for_writer = app.clone();
    let serial_for_writer = serial.clone();
    let path_for_writer = path.clone();
    tokio::spawn(async move {
        while let Some(ack) = rx.recv().await {
            // The production writer's exact call: seal under the serial guard
            // and atomically rename into place, then report the verdict.
            let ok = write_snapshot(
                &app_for_writer,
                &path_for_writer,
                seed,
                serial_for_writer.clone(),
            )
            .await;
            let _ = ack.send(ok);
        }
    });
    let router = build_router(app.clone(), false);
    let owner_hex = hex0x(&owner);
    let sig0 = signature(&app, &sk, &owner, 0).await;

    let r = router
        .clone()
        .oneshot(post_recovery(&owner_hex, 0, &sig0))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let v = body_json(r).await;
    assert_eq!(v["durability"], "confirmed");
    assert_eq!(v["recoveryNonce"], 1);
    let new_key = parse_hex32(v["apiKey"].as_str().unwrap()).unwrap();

    // The ACKed bytes exist on disk and restore cleanly.
    let sealed = std::fs::read(&path).expect("snapshot file written");
    let plain = snapshot::open(&sealed, &seed).expect("snapshot opens with the seed");
    let restored = Gw::boot_restored(&plain).expect("snapshot restores");

    // The exact generation the ACK covered is the durable state: new key
    // active, old key absent, recovery nonce 1.
    assert!(restored.accounts.contains_key(&new_key), "new key durable");
    assert!(
        !restored.accounts.contains_key(&old_key),
        "old key absent from the durable state"
    );
    assert_eq!(restored.accounts[&new_key].recovery_nonce, 1);

    // Replaying the original authorization against the RESTORED state is a
    // stale challenge: rejected, no secret leak.
    let mut restored = restored;
    let err = restored.recover_account(owner, 0, &sig0).unwrap_err();
    assert!(
        err.contains("nonce mismatch"),
        "replay against restored state rejected, got: {err}"
    );
    assert!(
        restored.accounts.contains_key(&new_key),
        "rejection mutates nothing"
    );

    // And the restored gateway is fully operational for a fresh challenge.
    let sig1 = signature(&app, &sk, &owner, 1).await;
    let key2 = restored.recover_account(owner, 1, &sig1).unwrap();
    assert_ne!(key2, new_key);
    assert_eq!(restored.accounts[&key2].recovery_nonce, 2);

    std::fs::remove_dir_all(&dir).ok();
}

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
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        match tokio::time::timeout_at(deadline, ws.next())
            .await
            .expect("queued-event socket did not close after rotation")
        {
            None | Some(Ok(Message::Close(_))) => break,
            Some(Err(error)) if is_transport_closed(&error) => break,
            Some(Ok(Message::Text(text))) => {
                let value: serde_json::Value = serde_json::from_str(&text).unwrap();
                assert_eq!(value["type"], "error");
                assert_eq!(value["message"], "api key rotated");
            }
            other => panic!("unexpected queued-event revocation: {other:?}"),
        }
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
    assert!(value["error"].as_str().unwrap().contains("queue is full"));
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

// Direct review regressions. These tests also compile on PR19; an assertion
// failure there is a reproduction, not a compiler failure counted as evidence.
#[tokio::test]
async fn direct_no_snapshot_request_before_mutation_and_real_restore() {
    let (mut app, old_key, owner, sk) = prepared();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<SnapshotAck>(8);
    Arc::get_mut(&mut app).unwrap().snapshot_req = Some(tx);
    let sig = signature(&app, &sk, &owner, 0).await;
    let router = build_router(app.clone(), false);
    let held = app.gw.lock().await;
    let mut request = Box::pin(
        router
            .clone()
            .oneshot(post_recovery(&hex0x(&owner), 0, &sig)),
    );
    assert!(futures_util::poll!(request.as_mut()).is_pending());
    assert!(
        matches!(
            rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ),
        "writer was notified while the mutation was still blocked by Gw"
    );
    assert!(held.accounts.contains_key(&old_key));
    drop(held);
    let task = tokio::spawn(request);
    let ack = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .unwrap()
        .unwrap();
    let new_key = *app.gw.lock().await.accounts.keys().next().unwrap();
    assert_ne!(old_key, new_key);
    let directory =
        std::env::temp_dir().join(format!("arcora-direct-{}", hex0x(&csprng_bytes32())));
    std::fs::create_dir(&directory).unwrap();
    let path = directory.join("state");
    assert!(write_snapshot(&app, &path, [0x61; 32], Arc::new(Mutex::new(()))).await);
    ack.send(true).unwrap();
    let response = task.await.unwrap().unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let reply = body_json(response).await;
    assert_eq!(reply["apiKey"], hex0x(&new_key));
    assert_eq!(reply["durability"], "confirmed");
    let plain = snapshot::open(&std::fs::read(&path).unwrap(), &[0x61; 32]).unwrap();
    let restored = Gw::boot_restored(&plain).unwrap();
    assert!(!restored.accounts.contains_key(&old_key));
    assert_eq!(restored.accounts[&new_key].recovery_nonce, 1);
    let mut restarted = crate::tests::test_app();
    Arc::get_mut(&mut restarted).unwrap().gw = Mutex::new(restored);
    let router = build_router(restarted, false);
    assert_eq!(
        router
            .clone()
            .oneshot(get_me(&old_key))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        router.oneshot(get_me(&new_key)).await.unwrap().status(),
        StatusCode::OK
    );
    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn direct_other_account_delivers_while_recovery_waits_for_disk() {
    let (mut app, key_a, owner_a, sk) = prepared();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<SnapshotAck>(8);
    Arc::get_mut(&mut app).unwrap().snapshot_req = Some(tx);
    let (key_b, owner_b) = {
        let mut gw = app.gw.lock().await;
        let signer = gw.accounts[&key_a].signer;
        gw.register_account(signer)
    };
    let base = spawn_ws_server(app.clone()).await;
    let (mut ws_b, reply) = connect_auth(&base, &key_b).await;
    assert_eq!(reply["type"], "authOk");
    let sig = signature(&app, &sk, &owner_a, 0).await;
    let task = tokio::spawn(build_router(app.clone(), false).oneshot(post_recovery(
        &hex0x(&owner_a),
        0,
        &sig,
    )));
    let ack = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(!task.is_finished());
    publish_private(&app, &hex0x(&owner_b), 771);
    let frame = tokio::time::timeout(Duration::from_secs(1), ws_b.next())
        .await
        .expect("account A's disk wait blocked account B's private delivery")
        .unwrap()
        .unwrap();
    let Message::Text(text) = frame else {
        panic!("expected private event");
    };
    let event: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(event["owner"], hex0x(&owner_b));
    assert_eq!(event["orderId"], 771);
    ack.send(true).unwrap();
    assert_eq!(task.await.unwrap().unwrap().status(), StatusCode::OK);
}

#[tokio::test]
async fn direct_idle_revocation_requires_transport_closure_not_silence() {
    let (mut app, old, owner, sk) = prepared();
    let (tx, _) = controllable_writer();
    Arc::get_mut(&mut app).unwrap().snapshot_req = Some(tx);
    let base = spawn_ws_server(app.clone()).await;
    let (mut ws, auth) = connect_auth(&base, &old).await;
    assert_eq!(auth["type"], "authOk");
    let sig = signature(&app, &sk, &owner, 0).await;
    let response = build_router(app.clone(), false)
        .oneshot(post_recovery(&hex0x(&owner), 0, &sig))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        let message = tokio::time::timeout_at(deadline, ws.next())
            .await
            .expect("idle socket stayed open; timeout is a failure, not revocation");
        match message {
            None | Some(Ok(Message::Close(_))) => break,
            Some(Err(tokio_tungstenite::tungstenite::Error::Protocol(
                tokio_tungstenite::tungstenite::error::ProtocolError::ResetWithoutClosingHandshake,
            ))) => break,
            Some(Ok(Message::Text(text))) => {
                let value: serde_json::Value = serde_json::from_str(&text).unwrap();
                assert_eq!(value["type"], "error");
                assert_eq!(value["message"], "api key rotated");
                // An error frame alone is insufficient; require EOF or Close.
            }
            other => panic!("unexpected revocation outcome: {other:?}"),
        }
    }
    let (_, old_auth) = connect_auth(&base, &old).await;
    assert_eq!(old_auth["type"], "error");
}

fn local_sign_digest(sk: &SigningKey, digest: &[u8; 32]) -> [u8; 65] {
    let (sig, recovery) = sk.sign_prehash_recoverable(digest).unwrap();
    let mut wire = [0u8; 65];
    wire[..64].copy_from_slice(&sig.to_bytes());
    wire[64] = recovery.to_byte() + 27;
    wire
}

#[tokio::test]
async fn local_same_nonce_race_has_one_winner_and_no_secret_for_loser() {
    let (mut app, original, owner, sk) = prepared();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<SnapshotAck>(2);
    Arc::get_mut(&mut app).unwrap().snapshot_req = Some(tx);
    let sig = signature(&app, &sk, &owner, 0).await;
    let router = build_router(app.clone(), false);
    let first = tokio::spawn(
        router
            .clone()
            .oneshot(post_recovery(&hex0x(&owner), 0, &sig)),
    );
    let ack = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .unwrap()
        .unwrap();
    let second = tokio::spawn(
        router
            .clone()
            .oneshot(post_recovery(&hex0x(&owner), 0, &sig)),
    );
    assert!(tokio::time::timeout(Duration::from_millis(100), rx.recv())
        .await
        .is_err());
    assert_eq!(
        router
            .clone()
            .oneshot(get_me(&original))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    ack.send(true).unwrap();
    let winner = first.await.unwrap().unwrap();
    assert_eq!(winner.status(), StatusCode::OK);
    let new_key = parse_hex32(body_json(winner).await["apiKey"].as_str().unwrap()).unwrap();
    let loser = tokio::time::timeout(Duration::from_secs(2), second)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(loser.status(), StatusCode::BAD_REQUEST);
    assert!(body_json(loser).await.get("apiKey").is_none());
    assert!(
        rx.try_recv().is_err(),
        "rejected replay published a disk write"
    );
    let gw = app.gw.lock().await;
    assert_eq!(gw.accounts[&new_key].recovery_nonce, 1);
    assert_eq!(gw.accounts.len(), 1);
    let restored = Gw::boot_restored(&gw.snapshot_plain()).unwrap();
    assert!(restored.accounts.contains_key(&new_key));
    assert!(!restored.accounts.contains_key(&original));
}

#[tokio::test]
async fn local_real_rebind_before_recovery_rechecks_current_authorizer() {
    for caller_signed in [false, true] {
        let (mut app, key, owner, old_sk) = prepared();
        if !caller_signed {
            app.gw.lock().await.accounts.get_mut(&key).unwrap().signer = None;
        }
        let (tx, mut rx) = tokio::sync::mpsc::channel::<SnapshotAck>(2);
        Arc::get_mut(&mut app).unwrap().snapshot_req = Some(tx);
        let new_sk = SigningKey::from_bytes((&[9u8; 32]).into()).unwrap();
        let public = new_sk.verifying_key().to_encoded_point(false);
        let hash = <RawKeccak as sha3::Digest>::digest(&public.as_bytes()[1..]);
        let new_address: [u8; 20] = hash[12..].try_into().unwrap();
        let sig = signature(&app, &old_sk, &owner, 0).await;
        let proof = local_sign_digest(&new_sk, &deposit_bind_digest(&owner, &new_address));
        let (chain, vault, old_address) = {
            let gw = app.gw.lock().await;
            (
                gw.chain_id,
                gw.vault,
                gw.accounts[&key].deposit_address.unwrap(),
            )
        };
        let authorization = local_sign_digest(
            &old_sk,
            &rebind_auth_digest(chain, &vault, &owner, 0, &old_address, &new_address),
        );
        let request = axum::http::Request::builder().method("POST").uri("/v1/accounts/deposit/address")
            .header("content-type", "application/json").header("x-api-key", hex0x(&key))
            .body(axum::body::Body::from(serde_json::json!({"address":hex0x(&new_address),"signature":hex0x(&proof),"currentSignature":hex0x(&authorization)}).to_string())).unwrap();
        let router = build_router(app.clone(), false);
        let held = app.gw.lock().await;
        let mut rebind = Box::pin(router.clone().oneshot(request));
        assert!(futures_util::poll!(rebind.as_mut()).is_pending());
        let mut recovery = Box::pin(
            router
                .clone()
                .oneshot(post_recovery(&hex0x(&owner), 0, &sig)),
        );
        assert!(futures_util::poll!(recovery.as_mut()).is_pending());
        drop(held); // FIFO Gw waiters place the fully authorized rebind first.
        assert_eq!(rebind.await.unwrap().status(), StatusCode::OK);
        let recovery = tokio::spawn(recovery);
        if caller_signed {
            tokio::time::timeout(Duration::from_secs(2), rx.recv())
                .await
                .unwrap()
                .unwrap()
                .send(true)
                .unwrap();
            assert_eq!(recovery.await.unwrap().unwrap().status(), StatusCode::OK);
        } else {
            let response = tokio::time::timeout(Duration::from_secs(2), recovery)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert!(body_json(response).await.get("apiKey").is_none());
            assert!(rx.try_recv().is_err());
            assert_eq!(view_nonce(&app, &hex0x(&owner)).await, 0);
            let fresh = signature(&app, &new_sk, &owner, 0).await;
            let next = tokio::spawn(router.oneshot(post_recovery(&hex0x(&owner), 0, &fresh)));
            tokio::time::timeout(Duration::from_secs(2), rx.recv())
                .await
                .unwrap()
                .unwrap()
                .send(true)
                .unwrap();
            assert_eq!(next.await.unwrap().unwrap().status(), StatusCode::OK);
        }
        let gw = app.gw.lock().await;
        let a = gw.accounts.values().next().unwrap();
        assert_eq!(a.deposit_address, Some(new_address));
        assert_eq!(a.rebind_counter, 1);
        assert_eq!(a.recovery_nonce, 1);
        assert!(!gw.accounts.contains_key(&key));
        assert_eq!(
            Gw::boot_restored(&gw.snapshot_plain())
                .unwrap()
                .snapshot_plain(),
            gw.snapshot_plain()
        );
    }
}

/// Owns the listener task so the test can verify shutdown instead of depending
/// on Tokio's test-runtime teardown to abort leaked sockets.
struct LocalWsServer {
    base: String,
    shutdown: tokio::sync::oneshot::Sender<()>,
    task: tokio::task::JoinHandle<()>,
}
impl LocalWsServer {
    async fn start(app: Shared, max_write_buffer_bytes: usize) -> Self {
        let mut config = service_policy::Config::from_env(false).unwrap();
        // This fixture deliberately tests transport backpressure after a large
        // bounded write has been admitted. The production 1 MiB buffer cap is
        // separately tested; only this in-process server allows the 8 MiB frame.
        config.max_write_buffer_bytes = max_write_buffer_bytes;
        config.send_timeout = crate::credential_session::SEND_TIMEOUT;
        let policy = Arc::new(service_policy::ServicePolicy::new(config));
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        // Accepted sockets inherit this small send buffer. A single bounded
        // payload below fills it without an unbounded producer/flood loop.
        socket.set_send_buffer_size(8 * 1024).unwrap();
        socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let listener = socket.listen(8).unwrap();
        let addr = listener.local_addr().unwrap();
        let (shutdown, stop) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            axum::serve(listener, build_router_with_policy(app, false, policy))
                .with_graceful_shutdown(async {
                    let _ = stop.await;
                })
                .await
                .unwrap();
        });
        Self {
            base: format!("ws://{addr}"),
            shutdown,
            task,
        }
    }
    async fn stop(self) {
        self.shutdown.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(3), self.task)
            .await
            .expect("loopback listener did not shut down")
            .unwrap();
    }
}

fn is_transport_closed(error: &tokio_tungstenite::tungstenite::Error) -> bool {
    use tokio_tungstenite::tungstenite::{error::ProtocolError, Error};
    matches!(
        error,
        Error::ConnectionClosed
            | Error::AlreadyClosed
            | Error::Protocol(ProtocolError::ResetWithoutClosingHandshake)
    ) || matches!(error, Error::Io(e) if matches!(e.kind(), std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe))
}

#[tokio::test]
async fn local_tcp_backpressure_has_bounded_send_and_other_account_progress() {
    let (mut app, old_key, owner, sk) = prepared();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<SnapshotAck>(2);
    Arc::get_mut(&mut app).unwrap().snapshot_req = Some(tx);
    let (key_b, owner_b) = app.gw.lock().await.register_account(None);
    let baseline_receivers = app.events_tx.receiver_count();
    let server = LocalWsServer::start(app.clone(), 16 * 1024 * 1024).await;
    let (mut slow, auth) = connect_auth(&server.base, &old_key).await;
    assert_eq!(auth["type"], "authOk");
    let (mut healthy, auth) = connect_auth(&server.base, &key_b).await;
    assert_eq!(auth["type"], "authOk");
    let (mut same_owner, auth) = connect_auth(&server.base, &old_key).await;
    assert_eq!(auth["type"], "authOk");
    let control = app.gw.lock().await.recovery_control(&owner).unwrap();
    const PAYLOAD_BYTES: usize = 8 * 1024 * 1024;
    let payload = serde_json::json!({"owner":hex0x(&owner),"type":"execution","orderId":9001,"padding":"x".repeat(PAYLOAD_BYTES)}).to_string();
    let started = tokio::time::Instant::now();
    app.events_tx.send(payload).unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if control.fence.try_write().is_err() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("did not observe the real socket send holding its account lease");
    let other_started = tokio::time::Instant::now();
    publish_private(&app, &hex0x(&owner_b), 9002);
    let event = tokio::time::timeout(Duration::from_secs(1), healthy.next())
        .await
        .expect("slow account blocked the other socket")
        .unwrap()
        .unwrap();
    let Message::Text(text) = event else {
        panic!("expected other account private event");
    };
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&text).unwrap()["orderId"],
        9002
    );
    let other_ms = other_started.elapsed().as_millis();
    assert!(
        control.fence.try_write().is_err(),
        "payload did not sustain backpressure through other-account delivery"
    );
    let sig = signature(&app, &sk, &owner, 0).await;
    let recovery = tokio::spawn(build_router(app.clone(), false).oneshot(post_recovery(
        &hex0x(&owner),
        0,
        &sig,
    )));
    let ack = tokio::time::timeout(
        crate::credential_session::SEND_TIMEOUT + Duration::from_secs(1),
        rx.recv(),
    )
    .await
    .expect("socket send never released its lease")
    .unwrap();
    let release_ms = started.elapsed().as_millis();
    assert!(
        release_ms >= 1500,
        "send completed too early to prove timeout/backpressure: {release_ms}ms"
    );
    ack.send(true).unwrap();
    assert_eq!(recovery.await.unwrap().unwrap().status(), StatusCode::OK);
    // Resume reads only after rotation; buffered pre-rotation bytes are allowed.
    // An incomplete giant frame normally ends with TCP EOF/reset, never silence.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        match tokio::time::timeout_at(deadline, slow.next())
            .await
            .expect("stalled socket never reached actual closure")
        {
            None | Some(Ok(Message::Close(_))) => break,
            Some(Err(error)) if is_transport_closed(&error) => break,
            Some(Ok(Message::Text(text))) => {
                let value: serde_json::Value = serde_json::from_str(&text).unwrap();
                assert!(value["orderId"] == 9001 || value["message"] == "api key rotated");
            }
            other => panic!("unexpected socket termination: {other:?}"),
        }
    }
    drop(slow);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        match tokio::time::timeout_at(deadline, same_owner.next())
            .await
            .expect("second same-owner socket was not revoked")
        {
            None | Some(Ok(Message::Close(_))) => break,
            Some(Err(error)) if is_transport_closed(&error) => break,
            Some(Ok(Message::Text(text))) => {
                let value: serde_json::Value = serde_json::from_str(&text).unwrap();
                assert!(value["orderId"] == 9001 || value["message"] == "api key rotated");
            }
            other => panic!("unexpected same-owner socket termination: {other:?}"),
        }
    }
    drop(same_owner);
    healthy.close(None).await.unwrap();
    drop(healthy);
    tokio::time::timeout(Duration::from_secs(3), async {
        while app.events_tx.receiver_count() != baseline_receivers {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("websocket task/subscription leaked after clients closed");
    server.stop().await;
    println!("LOCAL_TCP_OBSERVATION {{\"payloadBytes\":{PAYLOAD_BYTES},\"connections\":3,\"sendBufferRequested\":8192,\"otherAccountMs\":{other_ms},\"leaseReleaseMs\":{release_ms},\"receiversAfter\":{baseline_receivers}}}");
}

#[tokio::test]
async fn local_http_body_and_registration_limits_are_bounded() {
    use axum::extract::ConnectInfo;
    let (app, _, _, _) = prepared();
    let router = build_router(app.clone(), true);
    let peer: SocketAddr = "192.0.2.42:3210".parse().unwrap();
    let initial = app.gw.lock().await.accounts.len();
    for i in 0..=V1_REGISTER_RATE {
        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/accounts")
            .extension(ConnectInfo(peer))
            .body(axum::body::Body::empty())
            .unwrap();
        let response = router.clone().oneshot(request).await.unwrap();
        let expected = if i < V1_REGISTER_RATE {
            StatusCode::OK
        } else {
            StatusCode::TOO_MANY_REQUESTS
        };
        assert_eq!(response.status(), expected);
        if i == V1_REGISTER_RATE {
            assert!(body_json(response).await.get("apiKey").is_none());
        }
    }
    assert_eq!(
        app.gw.lock().await.accounts.len(),
        initial + V1_REGISTER_RATE as usize
    );
    let before = app.gw.lock().await.snapshot_plain();
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/accounts")
        .extension(ConnectInfo(peer))
        .body(axum::body::Body::from(vec![b'x'; 2 * 1024 * 1024 + 1]))
        .unwrap();
    assert_eq!(
        router.clone().oneshot(request).await.unwrap().status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    assert_eq!(app.gw.lock().await.snapshot_plain(), before);
    for path in [
        "/api/deposit",
        "/api/order",
        "/api/recover",
        "/v1/lp/deposit",
    ] {
        let request = axum::http::Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .body(axum::body::Body::from("{}"))
            .unwrap();
        assert_eq!(
            router.clone().oneshot(request).await.unwrap().status(),
            StatusCode::NOT_FOUND,
            "production mounted {path}"
        );
    }
    for key in [
        None,
        Some("not-hex"),
        Some("0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"),
    ] {
        let mut request = axum::http::Request::builder().uri("/v1/accounts/me");
        if let Some(key) = key {
            request = request.header("x-api-key", key);
        }
        assert_eq!(
            router
                .clone()
                .oneshot(request.body(axum::body::Body::empty()).unwrap())
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(app.gw.lock().await.snapshot_plain(), before);
}

#[tokio::test]
async fn local_tcp_auth_ok_queued_behind_rotation_never_discloses_stale_success() {
    let (mut app, old, owner, sk) = prepared();
    let (tx, mut rx) = tokio::sync::mpsc::channel::<SnapshotAck>(2);
    Arc::get_mut(&mut app).unwrap().snapshot_req = Some(tx);
    let receivers_before = app.events_tx.receiver_count();
    let server = LocalWsServer::start(app.clone(), 16 * 1024 * 1024).await;
    let control = app.gw.lock().await.recovery_control(&owner).unwrap();
    let gate = control.fence.clone().write_owned().await;
    let sig = signature(&app, &sk, &owner, 0).await;
    let mut recovery =
        Box::pin(build_router(app.clone(), false).oneshot(post_recovery(&hex0x(&owner), 0, &sig)));
    assert!(futures_util::poll!(recovery.as_mut()).is_pending());
    // Rotation is queued first. Let a real socket authenticate the old key and
    // subscribe to revocation while its authOk is waiting for the read fence.
    let (mut ws, _) = tokio_tungstenite::connect_async(format!("{}/v1/ws", server.base))
        .await
        .unwrap();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(2), ws.next())
            .await
            .unwrap(),
        Some(Ok(Message::Text(_)))
    ));
    ws.send(Message::Text(
        serde_json::json!({"type":"auth","apiKey":hex0x(&old)}).to_string(),
    ))
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while control.changed.receiver_count() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("auth did not reach the credential boundary");
    drop(gate);
    let recovery = tokio::spawn(recovery);
    let ack = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .unwrap()
        .unwrap();
    ack.send(true).unwrap();
    assert_eq!(recovery.await.unwrap().unwrap().status(), StatusCode::OK);
    let message = tokio::time::timeout(Duration::from_secs(3), ws.next())
        .await
        .expect("stale authOk path did not close its transport");
    match message {
        None | Some(Ok(Message::Close(_))) => {}
        Some(Err(error)) if is_transport_closed(&error) => {}
        other => panic!("stale authentication emitted data after rotation: {other:?}"),
    }
    drop(ws);
    tokio::time::timeout(Duration::from_secs(2), async {
        while app.events_tx.receiver_count() != receivers_before {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("auth-race socket task leaked");
    server.stop().await;
}

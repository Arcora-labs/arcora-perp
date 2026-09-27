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

    // (b) Drain the old session: at some point the revocation (error frame
    // and/or close) must arrive. Afterwards, read a few more bounded frames:
    // NONE of them may be an owner event.
    let mut revoked = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !revoked {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(remaining, ws.next()).await {
            Ok(Some(Ok(Message::Text(t)))) => {
                let v: serde_json::Value = serde_json::from_str(&t).unwrap();
                if v["message"] == "api key rotated" {
                    revoked = true;
                }
            }
            Ok(Some(Ok(Message::Close(_)))) | Ok(None) | Ok(Some(Err(_))) | Err(_) => {
                revoked = true
            }
            Ok(Some(Ok(_))) => continue,
        }
    }
    assert!(revoked, "revocation must fire while events are in flight");
    let mut events_after_revocation = 0u32;
    for _ in 0..5 {
        match tokio::time::timeout(Duration::from_millis(500), ws.next()).await {
            Ok(Some(Ok(Message::Text(t)))) => {
                let v: serde_json::Value = serde_json::from_str(&t).unwrap();
                if v["owner"] == owner_hex && v["type"] == "execution" {
                    events_after_revocation += 1;
                }
            }
            _ => break, // close / EOF / quiet: nothing more can arrive
        }
    }
    assert_eq!(
        events_after_revocation, 0,
        "no owner event may be delivered after the rotation revoked the session"
    );

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

//! Characterization of known-bad behavior at the pinned audit baseline.
//! These tests PASS when a finding is reproduced; they are NOT remediation tests.
//! Compiled only in the disposable source tree created by run.py.
use super::*;

fn bound_account(gw: &mut Gw, payer: u8) -> [u8; 32] {
    let (key, _) = gw.register_account(None);
    gw.accounts.get_mut(&key).unwrap().deposit_address = Some([payer; 20]);
    key
}

fn order(side: &str, size: i128, price: i128) -> OrderReq {
    OrderReq {
        market_id: 0,
        side: side.into(),
        size: size.to_string(),
        limit_price: price.to_string(),
        tif: "Gtc".into(),
        reduce_only: false,
        ..Default::default()
    }
}

fn maker_fixture() -> (Gw, [u8; 32], String, i128, i128) {
    let mut gw = Gw::boot();
    // Do not depend on the demo's timer-based SETTLED simulation.
    gw.window_settle_mode = true;
    let (key, _) = gw.register_account(None);
    gw.account_deposit(&key, 0, 20_000 * QUOTE_SCALE).unwrap();
    let size = SIZE_SCALE / 10;
    let price = gw.px_of(0);
    gw.account_place_order(&key, &order("Sell", size, price)).unwrap();
    let id = gw.accounts[&key].orders[0].id.clone();
    let _ = gw.tick();
    assert_eq!(gw.seq.book(0).unwrap().resting_size(Side::Sell), size);
    assert_eq!(gw.seq.state.position(&gw.accounts[&key].wallet.owner, 0).unwrap().size, 0);
    (gw, key, id, size, price)
}

#[test]
fn authorization_is_lost_by_restoring_the_previous_snapshot() {
    let mut gw = Gw::boot();
    let key = bound_account(&mut gw, 0x42);
    let before_authorize = gw.snapshot_plain();
    let amount = 1_000u128;
    let commit = gw.account_authorize_deposit(&key, [0x42; 20], amount).unwrap();
    assert!(gw.accounts[&key].deposit_authorizations.contains_key(&commit));
    let mut restored = Gw::boot_restored(&before_authorize).unwrap();
    // This models process loss between authorization and the next periodic save.
    // It does not claim an actual L1 transaction or host power-cut was performed.
    let id = restored.seq.state.consumed_deposit_count;
    let err = restored.account_confirm_deposit(
        &key, [0x42; 20], commit, amount, id, "audit-crash-tx", 0,
    ).unwrap_err();
    assert!(err.contains("no gateway authorization"), "{err}");
    assert_eq!(restored.seq.state.consumed_deposit_count, id);
    println!("AUDIT_CASE A02: prior snapshot loses an issued authorization's blind");
}

#[test]
fn next_payer_cannot_advance_the_queue_without_the_first_payer() {
    let mut gw = Gw::boot();
    let a = bound_account(&mut gw, 0x41);
    let b = bound_account(&mut gw, 0x42);
    let amount = 1_000u128;
    let ca = gw.account_authorize_deposit(&a, [0x41; 20], amount).unwrap();
    let cb = gw.account_authorize_deposit(&b, [0x42; 20], amount).unwrap();
    let next = gw.seq.state.consumed_deposit_count;
    let err = gw.account_confirm_deposit(
        &b, [0x42; 20], cb, amount, next + 1, "audit-payer-b", 0,
    ).unwrap_err();
    assert!(err.contains("not next-in-line"), "{err}");
    assert_eq!(gw.seq.state.consumed_deposit_count, next);
    // Control: exactly the same B request works once the missing prefix is supplied.
    gw.account_confirm_deposit(&a, [0x41; 20], ca, amount, next, "audit-payer-a", 0).unwrap();
    gw.account_confirm_deposit(&b, [0x42; 20], cb, amount, next + 1, "audit-payer-b", 0).unwrap();
    assert_eq!(gw.seq.state.consumed_deposit_count, next + 2);
    println!("AUDIT_CASE A01: a missing earlier confirmation blocks a valid later deposit");
}

#[test]
fn resting_unfilled_maker_cannot_be_cancelled_after_seal() {
    let (mut gw, key, id, size, _) = maker_fixture();
    assert!(gw.accounts[&key].orders[0].sealed);
    let err = gw.account_cancel(&key, &id).unwrap_err();
    assert!(err.contains("Only an ACCEPTED order"), "{err}");
    assert_eq!(gw.seq.book(0).unwrap().resting_size(Side::Sell), size);
    println!("AUDIT_CASE A04: an unfilled sealed maker remains live after cancel refusal");
}

#[test]
fn partial_maker_fill_is_reported_as_the_full_order_size() {
    let (mut gw, maker, _, size, price) = maker_fixture();
    let (taker, _) = gw.register_account(None);
    gw.account_deposit(&taker, 0, 20_000 * QUOTE_SCALE).unwrap();
    let executed = size / 4;
    gw.account_place_order(&taker, &order("Buy", executed, price)).unwrap();
    let _ = gw.tick();
    let owner = gw.accounts[&maker].wallet.owner;
    assert_eq!(gw.seq.state.position(&owner, 0).unwrap().size, -executed);
    assert_eq!(gw.seq.book(0).unwrap().resting_size(Side::Sell), size - executed);
    let orders = gw.v1_orders_json(&maker).unwrap();
    assert_eq!(orders["orders"][0]["filledSize"].as_str().unwrap(), size.to_string());
    assert_ne!(size, executed);
    println!("AUDIT_CASE A05: actual fill={executed}, API filledSize={size}");
}

#[test]
fn returned_order_receipt_has_no_signature_bytes() {
    let mut gw = Gw::boot();
    let (key, _) = gw.register_account(None);
    gw.account_deposit(&key, 0, 20_000 * QUOTE_SCALE).unwrap();
    let receipt = gw.account_place_order(&key, &order("Sell", SIZE_SCALE / 10, gw.px_of(0))).unwrap();
    let json = serde_json::to_value(&receipt).unwrap();
    let fields = json.as_object().unwrap();
    assert_eq!(fields.len(), 5);
    for name in ["orderHash", "seqNo", "recvTimeMs", "batchIdHint", "windowId"] {
        assert!(fields.contains_key(name), "missing expected field {name}");
    }
    let listed = gw.v1_orders_json(&key).unwrap();
    assert_eq!(listed["orders"][0]["receipt"], json);
    println!("AUDIT_CASE A03: both receipt surfaces omit the enclave signature");
}

#[test]
fn empty_production_book_is_served_as_nonempty_depth() {
    let gw = Gw::boot_with(GenesisMode::Production);
    let real = gw.seq.book(0).map(|b| b.resting_size(Side::Buy) + b.resting_size(Side::Sell)).unwrap_or(0);
    assert_eq!(real, 0);
    let json = gw.v1_orderbook_json(0).unwrap();
    assert!(!json["bids"].as_array().unwrap().is_empty());
    assert!(!json["asks"].as_array().unwrap().is_empty());
    println!("AUDIT_CASE A08: zero real resting depth is displayed as populated bids/asks");
}

#[test]
fn oracle_endpoint_restamps_an_old_market_observation() {
    let mut gw = Gw::boot_with(GenesisMode::Production);
    let stale = now_ms().saturating_sub(60_000);
    gw.mkts[0].live = true;
    gw.mkts[0].px_ms = stale;
    let before = now_ms();
    let json = gw.v1_oracle_json(0).unwrap();
    assert!(json["publishTimeMs"].as_u64().unwrap() >= before);
    assert!(json["publishTimeMs"].as_u64().unwrap() > stale);
    println!("AUDIT_CASE A08: public publishTimeMs is serving time, not source freshness");
}

#[tokio::test(start_paused = true)]
async fn full_snapshot_request_queue_outlives_the_advertised_timeout() {
    let (tx, _rx) = tokio::sync::mpsc::channel::<SnapshotAck>(1);
    let (ack, _ack_rx) = tokio::sync::oneshot::channel();
    tx.send(ack).await.unwrap();
    let req = Some(tx);
    let result = tokio::time::timeout(
        Duration::from_secs(SNAPSHOT_ACK_TIMEOUT_SECS + 1),
        snapshot_now(&req),
    ).await;
    assert!(result.is_err(), "the existing timeout only wraps the reply, not enqueueing");
    println!("AUDIT_CASE A09: backpressure blocks before the internal snapshot timeout starts");
}

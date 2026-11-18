//! Audit 2026-11-16 GA-1 + SM-1: the sequencer's open-order caps and its
//! collateral reserve for pending orders hold at intake. A refused order gets an
//! HTTP error and no receipt, and is never recorded.
use super::*;
use axum::body::Body;
use axum::http::Request;
use tower::ServiceExt as _;

use sequencer::MAX_OPEN_ORDERS_PER_MARKET as PER_MARKET;

/// A plaintext GTC buy for market 0.
fn bid(size: i128, limit: i128) -> OrderReq {
    OrderReq {
        market_id: 0,
        side: "Buy".into(),
        size: size.to_string(),
        limit_price: limit.to_string(),
        tif: "Gtc".into(),
        reduce_only: false,
        nonce: None,
        signature: None,
        ..Default::default()
    }
}

/// The refusal text of an intake call that must refuse.
fn refusal<T>(result: Result<T, String>) -> String {
    match result {
        Ok(_) => panic!("the order was admitted"),
        Err(error) => error,
    }
}

/// Clear the per-account one-second order window, so a test can post more than
/// the rate limit allows in a second.
fn unthrottle(gw: &mut Gw, key: &[u8; 32]) {
    let account = gw.accounts.get_mut(key).unwrap();
    account.last_order_ms = 0;
    account.orders_this_sec = 0;
}

/// Register an account, credit it `usd` in market 0 and post `count` bids of
/// `size` 1% under the mark, sealing half of them before posting the rest, so its
/// open orders are partly resting and partly waiting for the next batch.
fn account_with_bids(gw: &mut Gw, usd: i128, count: usize, size: i128) -> [u8; 32] {
    let (key, _) = gw.register_account(None);
    gw.account_deposit(&key, 0, usd * QUOTE_SCALE).unwrap();
    let limit = gw.px_of(0) * 99 / 100;
    for n in 0..count {
        if n == count / 2 {
            gw.tick();
        }
        unthrottle(gw, &key);
        gw.account_place_order(&key, &bid(size, limit))
            .unwrap_or_else(|e| panic!("bid {n}: {e}"));
    }
    key
}

#[test]
fn audit_1116_ga1_intake_refuses_an_order_past_the_open_order_cap() {
    let mut gw = Gw::boot();
    let size = SIZE_SCALE / 100;
    let key = account_with_bids(&mut gw, 1_000_000, PER_MARKET, size);
    unthrottle(&mut gw, &key);
    let limit = gw.px_of(0) * 99 / 100;
    let refused = refusal(gw.account_place_order(&key, &bid(size, limit)));
    assert!(refused.starts_with("OPEN_ORDER_LIMIT"), "{refused}");
    assert_eq!(
        gw.accounts[&key].orders.len(),
        PER_MARKET,
        "a refused order is never recorded"
    );
    gw.tick();
    let owner = gw.accounts[&key].wallet.owner;
    assert_eq!(
        gw.seq.book(0).unwrap().resting_hashes_for(&owner).len(),
        PER_MARKET
    );
}

/// With $200 of collateral the account margins as many $100 bids as fit in $200
/// of initial margin at the oracle price, counting the ones waiting for the next
/// batch; the next one is refused at intake. Each bid passes the per-order check
/// on its own. (The amounts are ten times the order minimum, so the entry holds
/// the 100 USDC entry minimum of audit G1-1.)
#[test]
fn audit_1116_sm1_intake_refuses_an_order_its_pending_orders_leave_no_margin_for() {
    let mut gw = Gw::boot();
    let mark = gw.validated_oracle_price(0, now_ms()).unwrap();
    let divisor = SIZE_SCALE * (PRICE_SCALE / QUOTE_SCALE);
    let raw = sequencer::MIN_ORDER_NOTIONAL * divisor;
    let size = LOT * (raw / mark + i128::from(raw % mark != 0));
    let collateral = 200 * QUOTE_SCALE;
    let fit = (1..)
        .take_while(|k| required_margin(size * k, mark) <= collateral)
        .count();
    assert!((10..20).contains(&fit), "fixture: {fit}");
    let key = account_with_bids(&mut gw, 200, fit, size);
    unthrottle(&mut gw, &key);
    let limit = gw.px_of(0) * 99 / 100;
    let refused = refusal(gw.account_place_order(&key, &bid(size, limit)));
    assert!(refused.starts_with("PENDING_MARGIN"), "{refused}");
    assert_eq!(gw.accounts[&key].orders.len(), fit);
}

/// Over HTTP the cap is `409 Conflict` with `{ error }`, and no receipt.
#[tokio::test]
async fn audit_1116_ga1_a_capped_account_gets_409() {
    let app = crate::tests::test_app();
    let key = {
        let mut gw = app.gw.lock().await;
        let key = account_with_bids(&mut gw, 1_000_000, PER_MARKET, SIZE_SCALE / 100);
        unthrottle(&mut gw, &key);
        key
    };
    let limit = app.gw.lock().await.px_of(0) * 99 / 100;
    let body = serde_json::json!({"marketId": 0, "side": "Buy",
        "size": (SIZE_SCALE / 100).to_string(), "limitPrice": limit.to_string(),
        "tif": "Gtc", "reduceOnly": false})
    .to_string();
    let request = Request::builder()
        .method("POST")
        .uri("/v1/orders")
        .header("content-type", "application/json")
        .header("x-api-key", hex0x(&key))
        .body(Body::from(body))
        .unwrap();
    let response = build_router(app.clone(), false)
        .oneshot(request)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 16)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let error = json["error"].as_str().unwrap();
    assert!(error.starts_with("OPEN_ORDER_LIMIT"), "{error}");
    assert!(json.get("orderHash").is_none() && json.get("signature").is_none());
    assert_eq!(app.gw.lock().await.accounts[&key].orders.len(), PER_MARKET);
}

/// The multiple of the order minimum the reserve fixtures post, so the collateral
/// behind their bids holds the 100 USDC entry minimum (audit G1-1), below which no
/// order may add exposure.
const LOT: i128 = 10;

/// The smallest order size that reaches the $10 order minimum at `mark`.
fn minimum_size(mark: i128) -> i128 {
    let divisor = SIZE_SCALE * (PRICE_SCALE / QUOTE_SCALE);
    let raw = sequencer::MIN_ORDER_NOTIONAL * divisor;
    raw / mark + i128::from(raw % mark != 0)
}

/// Pin market 0's oracle at `px`: the demo random walk leaves a market with a
/// live feed alone, so the reserve's arithmetic in a test does not drift.
fn pin_price(gw: &mut Gw, px: i128) {
    let m = gw.mkts.iter_mut().find(|m| m.id == 0).unwrap();
    m.live = true;
    m.px = px;
    let oracle = oracle_of(px, now_ms(), 0, &gw.oracle_signer);
    gw.seq.set_oracle(0, oracle);
}

/// A gateway-custody account bound to the address of `sk`, with `collateral` in
/// market 0, and `max` bids of [`LOT`] times the order minimum, or as many as its
/// reserve admits, resting on the book. Returns the account's key and its bids.
fn bound_account_with_bids(
    gw: &mut Gw,
    sk: &k256::ecdsa::SigningKey,
    collateral: i128,
    max: usize,
) -> ([u8; 32], Vec<WReceipt>) {
    let (key, _) = gw.register_account(None);
    gw.accounts.get_mut(&key).unwrap().deposit_address = Some(eth_address(sk));
    gw.account_deposit(&key, 0, collateral).unwrap();
    let mark = gw.px_of(0);
    let limit = mark * 99 / 100;
    let mut bids = Vec::new();
    while bids.len() < max {
        unthrottle(gw, &key);
        match gw.account_place_order(&key, &bid(LOT * minimum_size(mark), limit)) {
            Ok(receipt) => bids.push(receipt),
            Err(e) => {
                assert!(e.starts_with("PENDING_MARGIN"), "{e}");
                break;
            }
        }
    }
    gw.tick();
    let owner = gw.accounts[&key].wallet.owner;
    assert_eq!(
        gw.seq.book(0).unwrap().resting_hashes_for(&owner).len(),
        bids.len()
    );
    (key, bids)
}

/// A signed withdrawal of `amount` from `key`'s market-0 collateral to its bound
/// address.
fn withdraw(
    gw: &mut Gw,
    key: &[u8; 32],
    sk: &k256::ecdsa::SigningKey,
    amount: i128,
) -> Result<Withdrawal, String> {
    let (owner, to, auth) = {
        let a = &gw.accounts[key];
        (
            a.wallet.owner,
            a.deposit_address.unwrap(),
            a.last_withdraw_nonce + 1,
        )
    };
    let digest = withdraw_auth_digest(gw.chain_id, &gw.vault, &owner, 0, amount, &to, auth);
    let (sig, recid) = sk.sign_prehash_recoverable(&digest).unwrap();
    let mut wire = [0u8; 65];
    wire[..64].copy_from_slice(&sig.to_bytes());
    wire[64] = 27 + recid.to_byte();
    gw.account_withdraw(key, 0, amount, to, auth, &wire)
}

fn collateral_of(gw: &Gw, key: &[u8; 32]) -> i128 {
    let owner = gw.accounts[key].wallet.owner;
    gw.seq.state.position(&owner, 0).map_or(0, |p| p.collateral)
}

/// Audit 2026-11-16 SM-1, round 2 of the review: the reserve holds the collateral
/// behind pending orders until they fill, are cancelled, expire or are rejected,
/// not only when they are admitted. The review's case: with $100 an account rests
/// the bids its reserve admits, then withdraws the $100 to move it on to the next
/// account. The signed withdrawal is now refused, and nothing changes.
#[test]
fn audit_1116_sm1_a_withdrawal_cannot_take_the_margin_of_pending_orders() {
    let mut gw = Gw::boot();
    let px = gw.validated_oracle_price(0, now_ms()).unwrap();
    pin_price(&mut gw, px);
    let sk = k256::ecdsa::SigningKey::from_slice(&[0x5B; 32]).unwrap();
    let collateral = 100 * QUOTE_SCALE;
    let (key, bids) = bound_account_with_bids(&mut gw, &sk, collateral, usize::MAX);
    assert!(bids.len() >= 9, "fixture: {}", bids.len());
    let refused = withdraw(&mut gw, &key, &sk, collateral).unwrap_err();
    assert!(refused.starts_with("PENDING_MARGIN"), "{refused}");
    assert_eq!(collateral_of(&gw, &key), collateral, "nothing left");
    assert_eq!(gw.accounts[&key].last_withdraw_nonce, 0);
    let owner = gw.accounts[&key].wallet.owner;
    assert_eq!(
        gw.seq.book(0).unwrap().resting_hashes_for(&owner).len(),
        bids.len()
    );
}

/// What the pending orders do not need can leave; what they need cannot, until
/// they are cancelled. $240 behind twenty $100 bids: about $40 is free. (Twenty
/// bids hold more than the 100 USDC entry minimum, so the reserve, not the entry
/// minimum, is what keeps the rest in.)
#[test]
fn audit_1116_sm1_a_withdrawal_takes_only_what_pending_orders_do_not_need() {
    let mut gw = Gw::boot();
    let px = gw.validated_oracle_price(0, now_ms()).unwrap();
    pin_price(&mut gw, px);
    let sk = k256::ecdsa::SigningKey::from_slice(&[0x5D; 32]).unwrap();
    let collateral = 240 * QUOTE_SCALE;
    let (key, bids) = bound_account_with_bids(&mut gw, &sk, collateral, 20);
    assert_eq!(bids.len(), 20);
    let held = required_margin(LOT * minimum_size(px) * 20, px);
    let spare = collateral - held;
    assert!(spare > 10 * QUOTE_SCALE, "fixture: {spare}");

    let refused = withdraw(&mut gw, &key, &sk, spare + QUOTE_SCALE / 100).unwrap_err();
    assert!(refused.starts_with("PENDING_MARGIN"), "{refused}");
    withdraw(&mut gw, &key, &sk, spare).expect("the spare collateral is free");
    assert_eq!(collateral_of(&gw, &key), held);
    let refused = withdraw(&mut gw, &key, &sk, 10 * QUOTE_SCALE).unwrap_err();
    assert!(refused.starts_with("PENDING_MARGIN"), "{refused}");

    // cancelled, the bids hold nothing
    let ids: Vec<String> = gw.accounts[&key]
        .orders
        .iter()
        .map(|o| o.id.clone())
        .collect();
    for id in ids {
        gw.account_cancel(&key, &id).unwrap();
    }
    withdraw(&mut gw, &key, &sk, held).expect("nothing pending");
    assert_eq!(collateral_of(&gw, &key), 0);
}

/// The demo pool transfers (an LP deposit) move collateral out of the account's
/// market-0 entry just as a withdrawal does: they cannot take what its pending
/// orders hold either.
#[test]
fn audit_1116_sm1_an_lp_deposit_cannot_take_the_margin_of_pending_orders() {
    let mut gw = Gw::boot();
    let px = gw.validated_oracle_price(0, now_ms()).unwrap();
    pin_price(&mut gw, px);
    let sk = k256::ecdsa::SigningKey::from_slice(&[0x5C; 32]).unwrap();
    let collateral = 100 * QUOTE_SCALE;
    let (key, _) = bound_account_with_bids(&mut gw, &sk, collateral, usize::MAX);
    let wallet = gw.accounts[&key].wallet;
    let refused = gw.lp_deposit(key, &wallet, collateral).unwrap_err();
    assert!(refused.starts_with("PENDING_MARGIN"), "{refused}");
    assert_eq!(collateral_of(&gw, &key), collateral);
}

/// The demo order path checks the open-order limits before it spends the demo
/// user's nonce: an order the reserve refuses leaves the nonce as it was.
#[test]
fn audit_1116_sm1_a_refused_demo_order_spends_no_nonce() {
    let mut gw = Gw::boot();
    let px = gw.validated_oracle_price(0, now_ms()).unwrap();
    pin_price(&mut gw, px);
    // IOC bids, each needing about a third of the free balance as margin: the
    // third or fourth is refused for the ones waiting for the batch
    let free = gw.market_free(0);
    let divisor = SIZE_SCALE * (PRICE_SCALE / QUOTE_SCALE);
    let size = free * 10 / 3 * divisor / px;
    let order = OrderReq {
        tif: "Ioc".into(),
        ..bid(size, px * 99 / 100)
    };
    for n in 0.. {
        let nonce = gw.user_nonce;
        match gw.place_order(&order) {
            Ok(_) => assert_eq!(gw.user_nonce, nonce + 1),
            Err(e) => {
                assert!(e.starts_with("PENDING_MARGIN"), "{e}");
                assert!(n >= 2, "fixture: refused after {n}");
                assert_eq!(gw.user_nonce, nonce, "a refused order spends no nonce");
                break;
            }
        }
    }
}

/// Round 2 of the review: the house counter the injector gives a taker must not
/// outlive a taker the seal refuses. A taker admitted at intake right at its reserve
/// limit, whose limit the oracle then moves past before the seal, passes the
/// per-order check on its own but is refused at the seal; before, its house counter
/// rested with nothing to answer, and the house is exempt from the caps.
#[test]
fn audit_1116_sm1_a_taker_the_seal_refuses_gets_no_house_counter() {
    let mut gw = Gw::boot();
    let px = gw.validated_oracle_price(0, now_ms()).unwrap();
    pin_price(&mut gw, px);
    let size = LOT * minimum_size(px);
    let count = 10i128;
    let (key, _) = gw.register_account(None);
    gw.account_deposit(&key, 0, required_margin(size * count, px))
        .unwrap();
    let limit = px * 99 / 100;
    for _ in 1..count {
        unthrottle(&mut gw, &key);
        gw.account_place_order(&key, &bid(size, limit)).unwrap();
    }
    gw.tick();
    // the last order the reserve admits: a market IOC buy
    unthrottle(&mut gw, &key);
    let taker = OrderReq {
        tif: "Ioc".into(),
        ..bid(size, 0)
    };
    gw.account_place_order(&key, &taker).unwrap();
    // the oracle rises 1% before the seal
    pin_price(&mut gw, px * 101 / 100);
    let house = gw.mm.owner;
    let house_resting = |gw: &Gw| gw.seq.book(0).unwrap().resting_hashes_for(&house).len();
    let before = house_resting(&gw);
    gw.tick();
    let owner = gw.accounts[&key].wallet.owner;
    assert_eq!(
        gw.seq.state.position(&owner, 0).map_or(0, |p| p.size),
        0,
        "the seal refused the taker"
    );
    assert_eq!(house_resting(&gw), before, "no house counter rests");
}

/// The same for a reduce-only taker that follows another order of its owner in the
/// same market and batch, which the seal refuses as `ReduceOnlyViolation`.
#[test]
fn audit_1116_sm1_a_reduce_only_taker_the_seal_refuses_gets_no_house_counter() {
    let mut gw = Gw::boot();
    let px = gw.validated_oracle_price(0, now_ms()).unwrap();
    pin_price(&mut gw, px);
    let size = SIZE_SCALE / 100;
    let (key, _) = gw.register_account(None);
    gw.account_deposit(&key, 0, 10_000 * QUOTE_SCALE).unwrap();
    // open a long against the house
    let open = OrderReq {
        tif: "Ioc".into(),
        ..bid(size, 0)
    };
    gw.account_place_order(&key, &open).unwrap();
    gw.tick();
    let owner = gw.accounts[&key].wallet.owner;
    assert_eq!(gw.seq.state.position(&owner, 0).unwrap().size, size);
    // a reduce-only market sell, then a bid: the seal takes the newer order first
    unthrottle(&mut gw, &key);
    let close = OrderReq {
        side: "Sell".into(),
        tif: "Ioc".into(),
        reduce_only: true,
        ..bid(size, 0)
    };
    gw.account_place_order(&key, &close).unwrap();
    gw.account_place_order(&key, &bid(size, px * 99 / 100))
        .unwrap();
    let house = gw.mm.owner;
    let house_resting = |gw: &Gw| gw.seq.book(0).unwrap().resting_hashes_for(&house).len();
    let before = house_resting(&gw);
    gw.tick();
    assert_eq!(
        gw.seq.state.position(&owner, 0).unwrap().size,
        size,
        "the seal refused the reduce-only taker"
    );
    assert_eq!(house_resting(&gw), before, "no house counter rests");
}

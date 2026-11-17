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

/// With $20 of collateral the account margins as many $10-minimum bids as fit in
/// $20 of initial margin at the oracle price, counting the ones waiting for the
/// next batch; the next one is refused at intake. Each bid passes the per-order
/// check on its own.
#[test]
fn audit_1116_sm1_intake_refuses_an_order_its_pending_orders_leave_no_margin_for() {
    let mut gw = Gw::boot();
    let mark = gw.validated_oracle_price(0, now_ms()).unwrap();
    let divisor = SIZE_SCALE * (PRICE_SCALE / QUOTE_SCALE);
    let raw = sequencer::MIN_ORDER_NOTIONAL * divisor;
    let size = raw / mark + i128::from(raw % mark != 0);
    let collateral = 20 * QUOTE_SCALE;
    let fit = (1..)
        .take_while(|k| required_margin(size * k, mark) <= collateral)
        .count();
    assert!((10..20).contains(&fit), "fixture: {fit}");
    let key = account_with_bids(&mut gw, 20, fit, size);
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
/// market 0, and as many bids at the order minimum as its reserve admits, resting
/// on the book. Returns the account's key and its bids.
fn bound_account_with_bids(
    gw: &mut Gw,
    sk: &k256::ecdsa::SigningKey,
    collateral: i128,
) -> ([u8; 32], Vec<WReceipt>) {
    let (key, _) = gw.register_account(None);
    gw.accounts.get_mut(&key).unwrap().deposit_address = Some(eth_address(sk));
    gw.account_deposit(&key, 0, collateral).unwrap();
    let mark = gw.px_of(0);
    let limit = mark * 99 / 100;
    let mut bids = Vec::new();
    loop {
        unthrottle(gw, &key);
        match gw.account_place_order(&key, &bid(minimum_size(mark), limit)) {
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
/// not only when they are admitted. With $10 an account rests the ten-odd bids its
/// reserve admits; a signed withdrawal of the $10, or of any part the bids need, is
/// refused while they rest, so the capital cannot move on to back another
/// account's orders. What the bids do not need can leave, and once they are
/// cancelled, all of it.
#[test]
fn audit_1116_sm1_a_withdrawal_cannot_take_the_margin_of_pending_orders() {
    let mut gw = Gw::boot();
    let px = gw.validated_oracle_price(0, now_ms()).unwrap();
    pin_price(&mut gw, px);
    let sk = k256::ecdsa::SigningKey::from_slice(&[0x5B; 32]).unwrap();
    let collateral = 10 * QUOTE_SCALE + QUOTE_SCALE / 2;
    let (key, bids) = bound_account_with_bids(&mut gw, &sk, collateral);
    assert!(bids.len() >= 9, "fixture: {}", bids.len());
    let held = required_margin(minimum_size(px) * bids.len() as i128, px);
    assert!(held <= collateral && held > collateral - QUOTE_SCALE);

    let refused = withdraw(&mut gw, &key, &sk, collateral).unwrap_err();
    assert!(refused.starts_with("PENDING_MARGIN"), "{refused}");
    let refused = withdraw(&mut gw, &key, &sk, collateral - held + 1).unwrap_err();
    assert!(refused.starts_with("PENDING_MARGIN"), "{refused}");
    assert_eq!(collateral_of(&gw, &key), collateral, "nothing left");
    assert_eq!(gw.accounts[&key].last_withdraw_nonce, 0);

    // what the bids do not need is free (here: at most a dollar, so the
    // withdrawal takes all of it, the minimum's exception)
    let spare = collateral - held;
    if spare > 0 {
        withdraw(&mut gw, &key, &sk, spare).expect("the spare collateral is free");
    }

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
    let collateral = 10 * QUOTE_SCALE;
    let (key, _) = bound_account_with_bids(&mut gw, &sk, collateral);
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
    let size = minimum_size(px);
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

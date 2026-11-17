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

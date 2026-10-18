//! Order intake applies the engine's initial margin and the sequencer's minimum
//! order size, so an order the gateway accepts is measured the same way at the seal.
use super::*;
use perp_core::position::MIN_INITIAL_MARGIN;

fn order(side: &str, size: i128, reduce_only: bool) -> OrderReq {
    OrderReq {
        market_id: 0,
        side: side.into(),
        size: size.to_string(),
        limit_price: "0".into(),
        tif: "Ioc".into(),
        reduce_only,
        nonce: None,
        signature: None,
        ..Default::default()
    }
}

/// The smallest size whose notional at `mark` reaches the minimum order size.
fn minimum_size(mark: i128) -> i128 {
    let divisor = SIZE_SCALE * (PRICE_SCALE / QUOTE_SCALE);
    let raw = sequencer::MIN_ORDER_NOTIONAL * divisor;
    raw / mark + i128::from(raw % mark != 0)
}

/// The refusal text of an intake call that must refuse.
fn refusal<T>(result: Result<T, String>) -> String {
    match result {
        Ok(_) => panic!("the order was admitted"),
        Err(error) => error,
    }
}

#[test]
fn required_margin_is_the_engine_initial_margin() {
    let mark = 59_575 * PRICE_SCALE + 14 * PRICE_SCALE / 100;
    for cfg in MARKETS {
        let market = genesis::genesis_market(cfg, [0x11; 20]);
        assert_eq!(
            market.initial_margin_ratio,
            IMR_BP * perp_core::fixed::RATE_SCALE / 10_000
        );
        for size in [
            1,
            7,
            SIZE_SCALE / 1_000 + 3,
            SIZE_SCALE / 10,
            25 * SIZE_SCALE,
        ] {
            for price in [1, PRICE_SCALE - 1, mark, 3 * mark + 1] {
                let mut position = Position::empty([0; 32], cfg.id);
                position.size = size;
                assert_eq!(
                    Some(required_margin(size, price)),
                    position.initial_required(&market, price),
                    "size {size} price {price}"
                );
            }
        }
    }
    // The floor and the rounding: a dust position still needs $1, and a notional a
    // fraction of a quote unit over a whole number rounds up, never down.
    assert_eq!(required_margin(1, PRICE_SCALE), MIN_INITIAL_MARGIN);
    assert_eq!(
        required_margin(SIZE_SCALE / 10, 100_000 * PRICE_SCALE),
        1_000 * QUOTE_SCALE
    );
    assert_eq!(
        required_margin(SIZE_SCALE / 10, 100_000 * PRICE_SCALE + 1),
        1_000 * QUOTE_SCALE + 1
    );
    assert_eq!(required_margin(0, PRICE_SCALE), 0);
}

#[test]
fn account_intake_refuses_an_opener_below_the_minimum_before_any_mutation() {
    let mut gw = Gw::boot();
    let (key, owner) = gw.register_account(None);
    gw.account_deposit(&key, 0, 1_000 * QUOTE_SCALE).unwrap();
    let mark = gw.px_of(0);
    let floor = minimum_size(mark);
    for side in ["Buy", "Sell"] {
        let refused = refusal(gw.account_place_order(&key, &order(side, floor - 1, false)));
        assert_eq!(refused, below_order_minimum_error(), "{side}");
        let refused = refusal(gw.account_place_order(&key, &order(side, 1, false)));
        assert_eq!(refused, below_order_minimum_error(), "{side}");
    }
    assert!(gw.orders.is_empty(), "a refused order is never recorded");
    assert_eq!(
        gw.accounts[&key].orders_this_sec, 0,
        "nor counted against the rate limit"
    );
    assert_eq!(gw.seq.state.position(&owner, 0).map_or(0, |p| p.size), 0);
    // Exactly the minimum, measured at the oracle price rather than the limit.
    gw.account_place_order(&key, &order("Buy", floor, false))
        .expect("minimum admitted");
    let mut far_limit = order("Sell", floor, false);
    far_limit.limit_price = (mark / 2).to_string();
    far_limit.tif = "Gtc".into();
    gw.accounts.get_mut(&key).unwrap().last_order_ms = 0;
    gw.account_place_order(&key, &far_limit)
        .expect("the limit price does not change the measured notional");
}

#[test]
fn reductions_and_reduce_only_orders_are_exempt() {
    let mut gw = Gw::boot();
    let (key, owner) = gw.register_account(None);
    gw.account_deposit(&key, 0, 20_000 * QUOTE_SCALE).unwrap();
    gw.account_place_order(&key, &order("Buy", SIZE_SCALE / 10, false))
        .unwrap();
    gw.tick();
    let held = gw
        .seq
        .state
        .position(&owner, 0)
        .expect("long after the seal")
        .size;
    assert!(held > 0);
    gw.account_place_order(&key, &order("Sell", 1, true))
        .expect("a reduce-only order of any size");
    gw.accounts.get_mut(&key).unwrap().last_order_ms = 0;
    gw.account_place_order(&key, &order("Sell", 1, false))
        .expect("a plain reduction of any size");
    gw.accounts.get_mut(&key).unwrap().last_order_ms = 0;
    assert_eq!(
        refusal(gw.account_place_order(&key, &order("Buy", 1, false))),
        below_order_minimum_error(),
        "growing the position is measured"
    );
    // A flip is measured on the whole order, which here is far above the minimum.
    gw.account_place_order(&key, &order("Sell", held + 1, false))
        .expect("a flip whose whole order reaches the minimum");
}

#[test]
fn demo_intake_applies_the_same_minimum() {
    let mut gw = Gw::boot();
    let refused = refusal(gw.place_order(&order("Buy", 1, false)));
    assert_eq!(refused, below_order_minimum_error());
    assert!(gw.orders.is_empty());
    let floor = minimum_size(gw.px_of(0));
    gw.place_order(&order("Buy", floor, false))
        .expect("minimum admitted");
}

#[test]
fn no_size_refusal_without_a_price() {
    let position = Position::empty([7; 32], 0);
    assert!(!below_order_minimum(&position, Side::Buy, 1, false, 0));
    assert!(below_order_minimum(
        &position,
        Side::Buy,
        1,
        false,
        PRICE_SCALE
    ));
    assert!(!below_order_minimum(
        &position,
        Side::Buy,
        1,
        true,
        PRICE_SCALE
    ));
}

//! Order intake applies the engine's initial margin and the sequencer's minimum
//! order size, so an order the gateway accepts is measured the same way at the seal.
//!
//! The agreement tests put the same order to the intake and to the sequencer's
//! pre-trade gate (`Sequencer::pre_trade_check`, which `seal_batch` applies to
//! every order it seals) at the same position and validated oracle price, or seal
//! the admitted order and read the outcome.
use super::*;
use perp_core::order::RejectReason;
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
    assert!(!below_order_minimum(&position, Side::Buy, 1, false, None));
    assert!(!below_order_minimum(
        &position,
        Side::Buy,
        1,
        false,
        Some(0)
    ));
    assert!(below_order_minimum(
        &position,
        Side::Buy,
        1,
        false,
        Some(PRICE_SCALE)
    ));
    assert!(!below_order_minimum(
        &position,
        Side::Buy,
        1,
        true,
        Some(PRICE_SCALE)
    ));
}

/// A small deterministic generator (SplitMix64) for the sweeps below, so a failing
/// case reproduces exactly.
struct SplitMix(u64);

impl SplitMix {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }
}

fn side_name(side: Side) -> &'static str {
    match side {
        Side::Buy => "Buy",
        Side::Sell => "Sell",
    }
}

/// The order the sequencer seals for an intake request: the same owner, market,
/// side, size and reduce-only flag (the minimum and the margin rule read nothing
/// else).
fn sealed_form(owner: PubKey, side: Side, size: i128, reduce_only: bool) -> Order {
    mk_order(owner, 0, side, size, 0, 1, TimeInForce::Ioc, reduce_only)
}

/// Whether the intake refused `req` for its size. A refused order is not recorded,
/// so the call leaves nothing behind but an admitted order waiting for the seal.
fn intake_refuses_for_size(gw: &mut Gw, key: &[u8; 32], req: &OrderReq) -> bool {
    gw.accounts.get_mut(key).unwrap().last_order_ms = 0;
    matches!(gw.account_place_order(key, req), Err(e) if e == below_order_minimum_error())
}

/// Stop the simulated price walk on market 0 and sign a fresh oracle at its current
/// price, so a test can place limit orders exactly at the price the seal validates.
fn pin_market_zero(gw: &mut Gw) -> i128 {
    let px = gw.px_of(0);
    gw.mkts.iter_mut().find(|m| m.id == 0).unwrap().live = true;
    let fresh = oracle_of(px, now_ms(), 0, &gw.oracle_signer);
    gw.seq.set_oracle(0, fresh);
    px
}

/// The open position size of `owner` in market 0.
fn held(gw: &Gw, owner: &PubKey) -> i128 {
    gw.seq.state.position(owner, 0).map_or(0, |p| p.size)
}

#[test]
fn intake_and_seal_agree_on_both_sides_of_the_threshold() {
    let mut gw = Gw::boot();
    let (key, owner) = gw.register_account(None);
    gw.account_deposit(&key, 0, 1_000 * QUOTE_SCALE).unwrap();
    let now = now_ms();
    let mark = gw
        .validated_oracle_price(0, now)
        .expect("boot signs a fresh oracle");
    let floor = minimum_size(mark);
    for side in [Side::Buy, Side::Sell] {
        // One size unit below the minimum: refused at intake, and the seal refuses
        // the same order for its size.
        assert!(intake_refuses_for_size(
            &mut gw,
            &key,
            &order(side_name(side), floor - 1, false)
        ));
        assert_eq!(
            gw.seq
                .pre_trade_check(&sealed_form(owner, side, floor - 1, false), now),
            Err(RejectReason::BelowMinimumSize)
        );
        // Exactly the minimum: the sequencer admits it (the intake's admission of it
        // is sealed below).
        assert_eq!(
            gw.seq
                .pre_trade_check(&sealed_form(owner, side, floor, false), now),
            Ok(())
        );
    }
    assert!(gw.orders.is_empty() && gw.accounts[&key].orders.is_empty());
    // Sealing the refused size directly records exactly that reason.
    let dust = sealed_form(owner, Side::Buy, floor - 1, false);
    let sealed = gw.seq.seal_batch(&[dust], now);
    assert_eq!(
        sealed.manifest.rejected,
        vec![(
            dust.order_hash::<Keccak256>(),
            RejectReason::BelowMinimumSize
        )]
    );
    // The admitted minimum is sealed and fills against the house counter.
    gw.account_place_order(&key, &order("Buy", floor, false))
        .expect("minimum admitted");
    let admitted = gw.accounts[&key].orders[0].order_hash;
    gw.tick();
    assert!(!gw.pending_rejected.contains(&admitted));
    assert_eq!(held(&gw, &owner), floor);
}

#[test]
fn intake_refusals_for_size_match_the_sequencer_for_every_position() {
    let mut gw = Gw::boot();
    let (key, owner) = gw.register_account(None);
    gw.account_deposit(&key, 0, 5_000 * QUOTE_SCALE).unwrap();
    let floor = minimum_size(gw.px_of(0));
    let mut checked = 0;
    let mut refused = 0;
    // Flat, long above the minimum, long below it, and short after a flip.
    for step in [
        None,
        Some(("Buy", 3 * floor)),
        Some(("Sell", 3 * floor - 2)),
        Some(("Sell", 2 + 3 * floor)),
    ] {
        if let Some((side, size)) = step {
            gw.accounts.get_mut(&key).unwrap().last_order_ms = 0;
            gw.account_place_order(&key, &order(side, size, false))
                .expect("position step admitted");
            gw.tick();
        }
        let position = held(&gw, &owner);
        let now = now_ms();
        let floor = minimum_size(gw.validated_oracle_price(0, now).unwrap());
        let a = position.abs();
        let sizes = [
            1,
            floor - 1,
            floor,
            floor + 1,
            a.max(1),
            a + 1,
            a + floor - 1,
            a + floor,
            2 * a + 1,
        ];
        for size in sizes {
            for side in [Side::Buy, Side::Sell] {
                for reduce_only in [false, true] {
                    let intake = intake_refuses_for_size(
                        &mut gw,
                        &key,
                        &order(side_name(side), size, reduce_only),
                    );
                    let sequencer = gw
                        .seq
                        .pre_trade_check(&sealed_form(owner, side, size, reduce_only), now)
                        == Err(RejectReason::BelowMinimumSize);
                    assert_eq!(
                        intake, sequencer,
                        "position {position}, {side:?} {size}, reduce-only {reduce_only}"
                    );
                    checked += 1;
                    refused += usize::from(intake);
                }
            }
        }
        // The admitted probes of this step are never sealed.
        gw.accounts.get_mut(&key).unwrap().orders.clear();
    }
    assert!(refused > 0 && refused < checked, "{refused} of {checked}");
}

#[test]
fn a_reduce_only_order_below_the_minimum_is_admitted_and_fills() {
    let mut gw = Gw::boot();
    let (key, owner) = gw.register_account(None);
    gw.account_deposit(&key, 0, 1_000 * QUOTE_SCALE).unwrap();
    let floor = minimum_size(gw.px_of(0));
    gw.account_place_order(&key, &order("Buy", floor, false))
        .unwrap();
    gw.tick();
    assert_eq!(held(&gw, &owner), floor);
    for (size, reduce_only) in [(1, true), (2, false)] {
        assert_eq!(
            gw.seq
                .pre_trade_check(&sealed_form(owner, Side::Sell, size, reduce_only), now_ms()),
            Ok(())
        );
        gw.accounts.get_mut(&key).unwrap().last_order_ms = 0;
        gw.account_place_order(&key, &order("Sell", size, reduce_only))
            .expect("a reduction of any size is admitted");
        let hash = gw.accounts[&key].orders[0].order_hash;
        gw.tick();
        assert!(!gw.pending_rejected.contains(&hash));
    }
    assert_eq!(held(&gw, &owner), floor - 3, "both reductions filled");
}

#[test]
fn a_resting_remainder_below_the_minimum_keeps_matching() {
    let mut gw = Gw::boot();
    let px = pin_market_zero(&mut gw);
    let floor = minimum_size(px);
    let mut accounts = Vec::new();
    for _ in 0..3 {
        let (key, owner) = gw.register_account(None);
        gw.account_deposit(&key, 0, 1_000 * QUOTE_SCALE).unwrap();
        accounts.push((key, owner));
    }
    let [(maker, maker_owner), (first, first_owner), (second, second_owner)] =
        [accounts[0], accounts[1], accounts[2]];
    let resting = |side: &str, size: i128| {
        let mut req = order(side, size, false);
        req.tif = "Gtc".into();
        req.limit_price = px.to_string();
        req
    };
    // A resting sell above the minimum; a taker leaves less than the minimum of it.
    let total = floor + floor / 2;
    let left = floor / 2;
    gw.account_place_order(&maker, &resting("Sell", total))
        .unwrap();
    let maker_hash = gw.accounts[&maker].orders[0].order_hash;
    gw.tick();
    assert_eq!(held(&gw, &maker_owner), 0, "the sell rests");
    gw.account_place_order(&first, &resting("Buy", total - left))
        .unwrap();
    gw.tick();
    assert_eq!(held(&gw, &maker_owner), -(total - left));
    assert_eq!(held(&gw, &first_owner), total - left);
    assert!(
        left < floor
            && sequencer::below_minimum_order_notional(
                &Position::empty(maker_owner, 0),
                &sealed_form(maker_owner, Side::Sell, left, false),
                px
            ),
        "the remainder is below the minimum as a new order"
    );
    // The next taker matches the remainder, which nothing re-checks.
    gw.account_place_order(&second, &resting("Buy", floor))
        .unwrap();
    gw.tick();
    assert_eq!(held(&gw, &maker_owner), -total, "the remainder filled");
    assert_eq!(held(&gw, &second_owner), left);
    assert!(!gw.pending_rejected.contains(&maker_hash));
}

#[test]
fn the_minimum_is_measured_at_the_validated_oracle_price() {
    let mut gw = Gw::boot();
    let (key, owner) = gw.register_account(None);
    gw.account_deposit(&key, 0, 1_000 * QUOTE_SCALE).unwrap();
    let now = now_ms();
    let oracle = gw.validated_oracle_price(0, now).unwrap();
    let floor = minimum_size(oracle);
    // The displayed mark is not the price the seal validates: the intake follows the
    // oracle, as the seal does.
    gw.mkts.iter_mut().find(|m| m.id == 0).unwrap().px = 10 * oracle;
    assert!(intake_refuses_for_size(
        &mut gw,
        &key,
        &order("Buy", floor - 1, false)
    ));
    assert_eq!(
        gw.seq
            .pre_trade_check(&sealed_form(owner, Side::Buy, floor - 1, false), now),
        Err(RejectReason::BelowMinimumSize)
    );
    // Without a validated price the seal refuses every order as `OracleUnavailable`
    // whatever its size, so the intake does not refuse it for its size.
    let stale = oracle_of(oracle, 1, 0, &gw.oracle_signer);
    gw.seq.set_oracle(0, stale);
    assert_eq!(gw.validated_oracle_price(0, now_ms()), None);
    assert!(!intake_refuses_for_size(
        &mut gw,
        &key,
        &order("Buy", 1, false)
    ));
    assert_eq!(
        gw.seq
            .pre_trade_check(&sealed_form(owner, Side::Buy, 1, false), now_ms()),
        Err(RejectReason::OracleUnavailable)
    );
}

#[tokio::test]
async fn both_order_routes_answer_400_below_the_minimum() {
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt as _;

    let app = tests::test_app();
    let key = app.gw.lock().await.register_account(None).0;
    let body = serde_json::json!({"marketId": 0, "side": "Buy", "size": "1",
        "limitPrice": "0", "tif": "Ioc", "reduceOnly": false})
    .to_string();
    for (path, api_key) in [("/api/order", None), ("/v1/orders", Some(hex0x(&key)))] {
        let mut request = Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json");
        if let Some(api_key) = &api_key {
            request = request.header("x-api-key", api_key);
        }
        let response = build_router(app.clone(), false)
            .oneshot(request.body(Body::from(body.clone())).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{path}");
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 16)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["error"], below_order_minimum_error(), "{path}");
    }
    let gw = app.gw.lock().await;
    assert!(gw.orders.is_empty() && gw.accounts[&key].orders.is_empty());
}

#[test]
fn required_margin_agrees_with_the_engine_over_random_inputs() {
    let mut rng = SplitMix(0x6d61_7267_696e_0001);
    let markets: Vec<Market> = MARKETS
        .iter()
        .map(|cfg| genesis::genesis_market(cfg, [0x11; 20]))
        .collect();
    let mut floored = 0;
    let mut overflowed = 0;
    for _ in 0..20_000 {
        // Log-uniform magnitudes, from a single unit to far past the notional's range.
        let wide = u128::from(rng.next()) << 64 | u128::from(rng.next());
        let size = 1 + (wide % (1u128 << (1 + rng.below(100)))) as i128;
        let price = 1 + (rng.next() % (1u64 << (1 + rng.below(62)))) as i128;
        let market = &markets[rng.below(markets.len() as u64) as usize];
        for signed in [size, -size] {
            let mut position = Position::empty([0; 32], market.id);
            position.size = signed;
            let engine = position.initial_required(market, price);
            assert_eq!(
                required_margin(size, price),
                engine.unwrap_or(i128::MAX),
                "size {signed} price {price}"
            );
            floored += usize::from(engine == Some(MIN_INITIAL_MARGIN));
            overflowed += usize::from(engine.is_none());
        }
    }
    assert!(floored > 0 && overflowed > 0, "{floored} {overflowed}");
}

#[test]
fn intake_margin_admission_agrees_with_the_engine_for_openings() {
    let mut gw = Gw::boot();
    let mut rng = SplitMix(0x6f70_656e_696e_6702);
    let now = now_ms();
    let mark = gw.validated_oracle_price(0, now).unwrap();
    let floor = minimum_size(mark);
    let mut admitted_count = 0;
    let mut refused_count = 0;
    for _ in 0..400 {
        let (key, owner) = gw.register_account(None);
        let deposit = (10 + rng.below(5_000) as i128) * QUOTE_SCALE + rng.below(1_000_000) as i128;
        gw.account_deposit(&key, 0, deposit).unwrap();
        let collateral = gw.seq.state.position(&owner, 0).unwrap().collateral;
        // A size whose initial margin lies within about 0.1% of the collateral.
        let unit = SIZE_SCALE * (PRICE_SCALE / QUOTE_SCALE);
        let balanced = collateral * 10_000 / IMR_BP * unit / mark;
        let jitter = rng.below(2_001) as i128 - 1_000;
        let size = (balanced + balanced * jitter / 1_000_000 + rng.below(3) as i128 - 1).max(floor);
        let side = if rng.below(2) == 0 {
            Side::Buy
        } else {
            Side::Sell
        };
        let intake = gw.account_place_order(&key, &order(side_name(side), size, false));
        let engine = gw
            .seq
            .pre_trade_check(&sealed_form(owner, side, size, false), now);
        match intake {
            Ok(_) => {
                assert_eq!(engine, Ok(()), "collateral {collateral} size {size}");
                admitted_count += 1;
            }
            Err(error) => {
                assert_eq!(
                    error, "Insufficient free margin to open this position (§3).",
                    "collateral {collateral} size {size}"
                );
                assert_eq!(engine, Err(RejectReason::InsufficientMargin));
                refused_count += 1;
            }
        }
    }
    assert!(
        admitted_count > 50 && refused_count > 50,
        "{admitted_count} admitted, {refused_count} refused"
    );
}

#[test]
fn intake_margin_admission_is_never_looser_than_the_engine_for_increases() {
    let mut gw = Gw::boot();
    let mut rng = SplitMix(0x6772_6f77_7468_0003);
    let now = now_ms();
    let mark = gw.validated_oracle_price(0, now).unwrap();
    let index = gw.seq.state.funding[&0].index_at(mark, now);
    let floor = minimum_size(mark);
    let unit = SIZE_SCALE * (PRICE_SCALE / QUOTE_SCALE);
    let mut admitted_count = 0;
    let mut refused_count = 0;
    for _ in 0..400 {
        let (key, owner) = gw.register_account(None);
        // An open position entered at the oracle price with no funding owed: its
        // equity is its collateral.
        let collateral = (20 + rng.below(5_000) as i128) * QUOTE_SCALE;
        let open_size =
            (rng.below(1 + (collateral * 10_000 / IMR_BP * unit / mark) as u64) as i128).max(floor);
        let long = rng.below(2) == 0;
        gw.seq.state.positions.insert(
            (owner, 0),
            Position {
                owner,
                market_id: 0,
                size: if long { open_size } else { -open_size },
                entry_price: mark,
                collateral,
                funding_entry: index,
            },
        );
        let size = floor + rng.below((collateral * 10_000 / IMR_BP * unit / mark) as u64) as i128;
        let side = if long { Side::Buy } else { Side::Sell };
        let intake = gw.account_place_order(&key, &order(side_name(side), size, false));
        let engine = gw
            .seq
            .pre_trade_check(&sealed_form(owner, side, size, false), now);
        if intake.is_ok() {
            assert_eq!(
                engine,
                Ok(()),
                "open {open_size} size {size} collateral {collateral}"
            );
            admitted_count += 1;
        } else {
            refused_count += 1;
        }
    }
    assert!(
        admitted_count > 50 && refused_count > 50,
        "{admitted_count} admitted, {refused_count} refused"
    );
}

/// The house counter has the size of the taker it answers, and the taker is held
/// to the minimum itself. With the house long, a reduce-only close below the
/// minimum gets a counter that grows the house's long by that small amount; the
/// counter is admitted, and the close fills.
#[test]
fn a_small_reduce_only_close_fills_against_a_house_counter_that_grows_its_side() {
    let mut gw = Gw::boot();
    let px = pin_market_zero(&mut gw);
    let floor = minimum_size(px);
    let (seller, _) = gw.register_account(None);
    let (closer, closer_owner) = gw.register_account(None);
    for key in [seller, closer] {
        gw.account_deposit(&key, 0, 1_000 * QUOTE_SCALE).unwrap();
    }
    // The house goes long against a seller, then sells the closer its position.
    gw.account_place_order(&seller, &order("Sell", 4 * floor, false))
        .unwrap();
    gw.tick();
    let house = gw.mm.owner;
    assert_eq!(held(&gw, &house), 4 * floor);
    gw.account_place_order(&closer, &order("Buy", floor, false))
        .unwrap();
    gw.tick();
    assert_eq!(held(&gw, &closer_owner), floor);
    assert_eq!(held(&gw, &house), 3 * floor, "still long");
    // Half the position, reduce-only: its counter is a buy that grows the house's
    // long by less than the minimum.
    let half = floor / 2;
    gw.accounts.get_mut(&closer).unwrap().last_order_ms = 0;
    gw.account_place_order(&closer, &order("Sell", half, true))
        .unwrap();
    let hash = gw.accounts[&closer].orders[1].order_hash;
    gw.tick();
    assert!(!gw.pending_rejected.contains(&hash));
    assert_eq!(held(&gw, &closer_owner), floor - half, "the close filled");
    assert_eq!(held(&gw, &house), 3 * floor + half);
}

/// A taker the seal refuses gets no house counter: the counter would otherwise be
/// admitted on its own and rest in the book with no taker to answer.
#[test]
fn a_taker_refused_at_the_seal_leaves_no_house_quote_resting() {
    let mut gw = Gw::boot();
    let px = pin_market_zero(&mut gw);
    let floor = minimum_size(px);
    let (key, owner) = gw.register_account(None);
    gw.account_deposit(&key, 0, 1_000 * QUOTE_SCALE).unwrap();
    gw.account_place_order(&key, &order("Buy", floor, false))
        .expect("exactly the minimum at the intake's price");
    let hash = gw.accounts[&key].orders[0].order_hash;
    // By the seal the validated price has moved down, so the same size is under
    // the minimum there.
    let lower = px - px / 100;
    gw.mkts.iter_mut().find(|m| m.id == 0).unwrap().px = lower;
    let moved = oracle_of(lower, now_ms(), 0, &gw.oracle_signer);
    gw.seq.set_oracle(0, moved);
    assert_eq!(
        gw.seq
            .pre_trade_check(&sealed_form(owner, Side::Buy, floor, false), now_ms()),
        Err(RejectReason::BelowMinimumSize)
    );
    gw.tick();
    assert!(gw.pending_rejected.contains(&hash), "the taker is refused");
    assert_eq!(held(&gw, &owner), 0);
    let house = gw.mm.owner;
    assert!(
        gw.seq
            .book(0)
            .unwrap()
            .resting_hashes_for(&house)
            .is_empty(),
        "no house quote rests"
    );
    assert_eq!(held(&gw, &house), 0);
}

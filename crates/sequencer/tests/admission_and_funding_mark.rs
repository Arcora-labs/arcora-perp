//! Sequencer admission and funding-mark rules:
//!
//!  * the pre-trade check reads the funding index the engine's fill will read
//!    (`FundingState::index_at`), so it agrees with the engine after a pause;
//!  * the minimum order notional applies only to orders that add exposure, judged
//!    against the position the order will meet when it executes;
//!  * close-only admission refuses orders that add exposure;
//!  * the funding mark is the impact-notional book mid, averaged over the open
//!    window, with the oracle index as the fallback; only depth the engine could
//!    fill and that takers face counts, and one sample cannot saturate the rate;
//!  * idle markets keep windows idle, a traded market refreshes its price once per
//!    epoch, ADL leaves winners healthy, and pruned positions leave the scans.

use std::collections::BTreeMap;

use k256::ecdsa::SigningKey;
use perp_core::engine::BatchOp;
use perp_core::fixed::{PRICE_SCALE, QUOTE_SCALE, RATE_SCALE, SIZE_SCALE};
use perp_core::funding::{FundingState, MAX_FUNDING_RATE_PER_INTERVAL, PRICE_REFRESH_MS};
use perp_core::hash::{word_u64, Keccak256};
use perp_core::market::Market;
use perp_core::note::{owner_from_spend_key, PubKey};
use perp_core::oracle::{oracle_digest, OracleSig, OracleTranscript};
use perp_core::order::{Order, RejectReason, Side, TimeInForce};
use perp_core::position::Position;
use perp_core::{EngineError, FillLeg, Note, RiskError};
use sequencer::{
    below_minimum_order_notional, EnclaveIdentity, Sequencer, FUNDING_IMPACT_MAX_ORDERS,
    FUNDING_IMPACT_NOTIONAL, FUNDING_MARK_MIN_SPAN_MS, MIN_ORDER_NOTIONAL,
};

fn enclave() -> EnclaveIdentity {
    EnclaveIdentity::from_seed([7u8; 32], 1, [0xABu8; 32])
}

fn owner_id(owner: u64) -> PubKey {
    owner_from_spend_key::<Keccak256>(&[owner as u8; 32])
}

fn oracle_key() -> SigningKey {
    SigningKey::from_bytes((&[7u8; 32]).into()).expect("valid dev scalar")
}

fn oracle_addr() -> [u8; 20] {
    let probe = oracle_digest(0, 0, 0, 0, 0);
    OracleSig::sign(&oracle_key(), &probe)
        .recover(&probe)
        .expect("fresh signature recovers")
}

fn test_market(id: u64) -> Market {
    let mut m = Market::conservative(id);
    m.oracle_pubkey = oracle_addr();
    m
}

/// A market-0 transcript at `price` (price-scaled), published at `now`.
fn oracle_px(price: i128, now: u64) -> OracleTranscript {
    let confidence = 10 * PRICE_SCALE;
    let d = oracle_digest(0, price, now, confidence, price);
    OracleTranscript {
        price,
        publish_time_ms: now,
        confidence,
        backup_twap: price,
        signature: OracleSig::sign(&oracle_key(), &d),
    }
}

fn oracle(price_usd: i128, now: u64) -> OracleTranscript {
    oracle_px(price_usd * PRICE_SCALE, now)
}

/// A GTC market-0 order at `price_usd` (whole dollars) for `size` (size-scaled).
fn order(owner: u64, side: Side, size: i128, price_usd: i128, nonce: u64) -> Order {
    Order {
        owner: owner_id(owner),
        market_id: 0,
        side,
        size,
        limit_price: price_usd * PRICE_SCALE,
        tif: TimeInForce::Gtc,
        reduce_only: false,
        nonce,
        expiry_ms: 0,
        ciphertext_commit: word_u64(nonce.wrapping_mul(13) ^ owner),
    }
}

fn fund(seq: &mut Sequencer, owner: u64, amount_usd: i128, blind: u8) {
    let o = owner_id(owner);
    let amount = amount_usd * QUOTE_SCALE;
    let cm = Note::new(o, 0, amount, [blind; 32]).commitment::<Keccak256>();
    let deposit_id = seq.state.consumed_deposit_count;
    seq.apply(&BatchOp::Deposit {
        owner: o,
        asset_id: 0,
        amount,
        blinding: [blind; 32],
        from: [0u8; 20],
        deposit_id,
        deposit_blind: [0u8; 32],
    })
    .unwrap();
    seq.apply(&BatchOp::FundPosition {
        owner: o,
        market_id: 0,
        note_commitment: cm,
        spend_key: [owner as u8; 32],
    })
    .unwrap();
}

/// Market 0 at $100k, owners 1 and 2 funded with $20k each.
fn setup(now: u64) -> Sequencer {
    let mut s = Sequencer::new(enclave(), 20);
    s.add_market(test_market(0));
    s.set_oracle(0, oracle(100_000, now));
    fund(&mut s, 1, 20_000, 0x11);
    fund(&mut s, 2, 20_000, 0x22);
    s
}

/// The mark of the single market-0 `AccrueFunding` op in `ops`.
fn accrue_mark(ops: &[BatchOp]) -> i128 {
    let marks: Vec<i128> = ops
        .iter()
        .filter_map(|op| match op {
            BatchOp::AccrueFunding {
                market_id: 0, mark, ..
            } => Some(*mark),
            _ => None,
        })
        .collect();
    assert_eq!(marks.len(), 1, "exactly one market-0 funding op: {ops:?}");
    marks[0]
}

/// The market-0 mark band at `index`, as the engine bounds it (5% by default).
fn band(index: i128) -> i128 {
    test_market(0).max_mark_deviation_ratio * index / RATE_SCALE
}

/// The smallest premium at which the rate reaches its clamp at `index`, within
/// the mark band: the most a sample or the window average may carry.
fn cap(index: i128) -> i128 {
    let saturating = (MAX_FUNDING_RATE_PER_INTERVAL * index + RATE_SCALE - 1) / RATE_SCALE;
    saturating.min(band(index))
}

/// A model of the sequencer's funding mark: samples `(time, premium)`, each taken
/// from the book a tick's takers face (before the tick matches) and pricing the
/// span since the previous sample. The mark at a tick is the index plus the
/// time-weighted average of the closed spans, divided by at least
/// `FUNDING_MARK_MIN_SPAN_MS`, with every premium capped at `cap`.
#[derive(Default)]
struct MarkModel {
    samples: Vec<(u64, i128)>,
}

impl MarkModel {
    fn mark(&self, index: i128) -> i128 {
        let mut weighted = 0i128;
        let mut elapsed = 0u64;
        for pair in self.samples.windows(2) {
            let ((t0, _), (t1, p1)) = (pair[0], pair[1]);
            weighted += p1 * i128::from(t1 - t0);
            elapsed += t1 - t0;
        }
        let avg = weighted / i128::from(elapsed.max(FUNDING_MARK_MIN_SPAN_MS));
        index + avg.clamp(-cap(index), cap(index))
    }

    /// Record the sample the sequencer takes at `now`, before the tick's orders
    /// reach the book. Call it after the tick's oracle is set and before sealing.
    fn sample(&mut self, seq: &Sequencer, now: u64, index: i128) {
        let premium = seq
            .impact_mid(0, now)
            .map_or(0, |mid| (mid - index).clamp(-cap(index), cap(index)));
        self.samples.push((now, premium));
    }
}

/// One tick at `t` with a fresh $100k oracle: the model samples first, as the
/// sequencer does, then the batch is sealed and its funding mark returned.
fn modeled_tick(s: &mut Sequencer, model: &mut MarkModel, t: u64, orders: &[Order]) -> i128 {
    let index = 100_000 * PRICE_SCALE;
    s.set_oracle(0, oracle(100_000, t));
    model.sample(s, t, index);
    let sealed = s.seal_batch(orders, t);
    let mark = accrue_mark(&sealed.ops);
    assert_eq!(mark, model.mark(index), "the sequencer's mark at {t}");
    mark
}

// ---------------------------------------------------------------------------
// Pre-trade check: index_at agreement
// ---------------------------------------------------------------------------

/// After a 30-minute pause at the maximum rate, a long owes $25/BTC of funding that
/// the stored index does not show yet; the fill commits it before checking margin.
/// The pre-trade check must read the same index, or it admits an order the fill
/// then refuses (the probe would ban it after matching).
#[test]
fn pre_trade_check_reads_the_index_the_fill_will_after_a_pause() {
    let t0 = 1_000u64;
    let mut s = setup(t0);
    // owner 2 opens 1 BTC long at the mark against owner 1
    s.seal_batch(
        &[
            order(1, Side::Sell, SIZE_SCALE, 100_000, 1),
            order(2, Side::Buy, SIZE_SCALE, 100_000, 2),
        ],
        t0,
    );
    assert_eq!(s.state.position(&owner_id(2), 0).unwrap().size, SIZE_SCALE);
    // a funding tick observes a 1% premium: longs pay the maximum rate from t0
    s.apply(&BatchOp::AccrueFunding {
        market_id: 0,
        mark: 101_000 * PRICE_SCALE,
        oracle: oracle(100_000, t0),
        now_ms: t0,
    })
    .unwrap();
    assert_eq!(s.state.funding[&0].rate, MAX_FUNDING_RATE_PER_INTERVAL);

    // reopen after a 30-minute pause
    let t1 = t0 + 1_800_000;
    let transcript = oracle(100_000, t1);
    s.set_oracle(0, transcript);
    let mark = 100_000 * PRICE_SCALE;
    let stored = s.state.funding[&0].cumulative_index;
    let settled = s.state.funding[&0].index_at(mark, t1);
    assert_eq!(settled - stored, 25 * QUOTE_SCALE, "$25/BTC for the pause");

    let market = test_market(0);
    let long = *s.state.position(&owner_id(2), 0).unwrap();
    // equity $20,000 at the stored index, $19,975 with the pause's funding: growing
    // the long by 0.999 BTC needs $19,990 of initial margin
    let grow = order(2, Side::Buy, SIZE_SCALE * 999 / 1_000, 100_000, 3);
    assert!(
        long.fits_initial_after(&market, grow.signed_size(), mark, stored),
        "fixture: the stored index would admit the order"
    );
    assert_eq!(
        s.pre_trade_check(&grow, t1),
        Err(RejectReason::InsufficientMargin)
    );
    let fill = |o: &Order| BatchOp::Fill {
        taker: o.owner,
        maker: owner_id(1),
        market_id: 0,
        taker_side: o.side,
        size: o.size,
        price: mark,
        oracle: transcript,
        now_ms: t1,
    };
    assert_eq!(
        s.state.clone().apply_op(&fill(&grow)).unwrap_err(),
        EngineError::Risk {
            source: RiskError::InsufficientMargin,
            leg: Some(FillLeg::Taker),
        },
        "the engine refuses it too"
    );
    // 0.997 BTC needs $19,970: both admit it
    let fits = order(2, Side::Buy, SIZE_SCALE * 997 / 1_000, 100_000, 4);
    assert_eq!(s.pre_trade_check(&fits, t1), Ok(()));
    assert!(s.state.clone().apply_op(&fill(&fits)).is_ok());

    // through a real tick: owner 1 rests the liquidity, the refused order never
    // reaches the book, and the resting depth survives untouched
    let maker = order(1, Side::Sell, SIZE_SCALE, 100_000, 5);
    let grow_hash = grow.order_hash::<Keccak256>();
    let sealed = s.seal_batch(&[maker, grow], t1);
    assert!(sealed
        .manifest
        .rejected
        .contains(&(grow_hash, RejectReason::InsufficientMargin)));
    assert!(sealed.settlement_rejected.is_empty());
    assert!(sealed.settled_order_hashes.is_empty());
    assert_eq!(s.book(0).unwrap().resting_size(Side::Sell), SIZE_SCALE);
    assert_eq!(s.state.position(&owner_id(2), 0).unwrap().size, SIZE_SCALE);
    assert!(s.state.conservation_holds());
}

// ---------------------------------------------------------------------------
// Minimum order notional
// ---------------------------------------------------------------------------

/// 0.0001 BTC at $100k is exactly $10.
const TEN_DOLLARS: i128 = SIZE_SCALE / 10_000;

#[test]
fn the_minimum_order_notional_applies_to_orders_that_add_exposure() {
    let t = 1_000u64;
    let mut s = setup(t);
    assert_eq!(MIN_ORDER_NOTIONAL, 10 * QUOTE_SCALE);

    // opening from flat: one unit below $10 is refused, $10 exactly is admitted
    let under = order(2, Side::Buy, TEN_DOLLARS - 1, 100_000, 1);
    let exact = order(2, Side::Buy, TEN_DOLLARS, 100_000, 2);
    assert_eq!(
        s.pre_trade_check(&under, t),
        Err(RejectReason::BelowMinimumSize)
    );
    assert_eq!(s.pre_trade_check(&exact, t), Ok(()));
    let mut short = under;
    short.side = Side::Sell;
    assert_eq!(
        s.pre_trade_check(&short, t),
        Err(RejectReason::BelowMinimumSize),
        "a short is measured the same way"
    );

    // the refusal is committed in the manifest; the order never reaches the book
    let under_hash = under.order_hash::<Keccak256>();
    let sealed = s.seal_batch(&[under], t);
    assert_eq!(
        sealed.manifest.rejected,
        vec![(under_hash, RejectReason::BelowMinimumSize)]
    );
    assert!(sealed.manifest.ordered.is_empty() && sealed.receipts.is_empty());
    assert!(s.book(0).unwrap().best_bid().is_none());

    // owner 2 opens 0.1 BTC long
    s.seal_batch(
        &[
            order(1, Side::Sell, SIZE_SCALE / 10, 100_000, 3),
            order(2, Side::Buy, SIZE_SCALE / 10, 100_000, 4),
        ],
        t,
    );
    assert_eq!(
        s.state.position(&owner_id(2), 0).unwrap().size,
        SIZE_SCALE / 10
    );
    // a small reduction is exempt, reduce-only or not
    let trim = order(2, Side::Sell, TEN_DOLLARS / 2, 100_000, 5);
    assert_eq!(s.pre_trade_check(&trim, t), Ok(()));
    let mut trim_ro = order(2, Side::Sell, TEN_DOLLARS / 2, 100_000, 6);
    trim_ro.reduce_only = true;
    assert_eq!(s.pre_trade_check(&trim_ro, t), Ok(()));
    // growing by less than $10 is refused
    let top_up = order(2, Side::Buy, TEN_DOLLARS / 2, 100_000, 7);
    assert_eq!(
        s.pre_trade_check(&top_up, t),
        Err(RejectReason::BelowMinimumSize)
    );
}

/// A flip opens fresh opposite exposure, so it is subject to the minimum; the
/// whole order's notional is measured.
#[test]
fn a_flip_is_measured_on_the_whole_order() {
    let mark = 100_000 * PRICE_SCALE;
    let mut long = Position::empty(owner_id(1), 0);
    long.size = TEN_DOLLARS / 2;
    long.entry_price = mark;
    let flip = |size| order(1, Side::Sell, size, 100_000, 1);
    assert!(below_minimum_order_notional(
        &long,
        &flip(TEN_DOLLARS - 1),
        mark
    ));
    assert!(!below_minimum_order_notional(
        &long,
        &flip(TEN_DOLLARS),
        mark
    ));
    // an exact close of a small position is a reduction: exempt
    assert!(!below_minimum_order_notional(
        &long,
        &flip(TEN_DOLLARS / 2),
        mark
    ));
    // a malformed size is left to the matcher
    assert!(!below_minimum_order_notional(&long, &flip(0), mark));
    assert!(!below_minimum_order_notional(&long, &flip(-5), mark));
}

/// A resting remainder that a partial fill left below $10 keeps matching.
#[test]
fn a_resting_remainder_below_the_minimum_keeps_matching() {
    let t = 1_000u64;
    let mut s = setup(t);
    fund(&mut s, 3, 20_000, 0x33);
    let maker = order(1, Side::Sell, TEN_DOLLARS * 3 / 2, 100_000, 1); // $15
    let maker_hash = maker.order_hash::<Keccak256>();
    s.seal_batch(&[maker, order(2, Side::Buy, TEN_DOLLARS, 100_000, 2)], t);
    assert_eq!(
        s.remaining_order_size(&maker_hash),
        Some(TEN_DOLLARS / 2),
        "a $5 remainder rests"
    );
    let sealed = s.seal_batch(&[order(3, Side::Buy, TEN_DOLLARS, 100_000, 3)], t);
    assert!(sealed.settled_order_hashes.contains(&maker_hash));
    assert_eq!(s.remaining_order_size(&maker_hash), None, "fully filled");
    assert_eq!(
        s.state.position(&owner_id(1), 0).unwrap().size,
        -(TEN_DOLLARS * 3 / 2)
    );
    assert_eq!(
        s.state.position(&owner_id(3), 0).unwrap().size,
        TEN_DOLLARS / 2
    );
    assert!(s.state.conservation_holds());
}

/// An IOC copy of `o`.
fn ioc(o: Order) -> Order {
    Order {
        tif: TimeInForce::Ioc,
        ..o
    }
}

/// Owner 2 holds a $100 long (0.001 BTC). In one batch it closes it and adds a $5
/// sell, which measured against the long alone would be an exempt reduction. After
/// the close it would open a $5 short, so it is refused before matching; the close
/// itself trades.
#[test]
fn a_same_batch_reduction_cannot_open_below_the_minimum() {
    let t = 10_000u64;
    let mut s = setup(t);
    let lot = SIZE_SCALE / 1_000;
    s.seal_batch(
        &[
            order(1, Side::Sell, lot, 100_000, 1),
            order(2, Side::Buy, lot, 100_000, 2),
        ],
        t,
    );
    assert_eq!(s.state.position(&owner_id(2), 0).unwrap().size, lot);
    let maker = order(1, Side::Buy, lot + TEN_DOLLARS / 2, 100_000, 3);
    let close = order(2, Side::Sell, lot, 100_000, 4);
    let tiny = order(2, Side::Sell, TEN_DOLLARS / 2, 100_000, 5);
    assert_eq!(
        s.pre_trade_check(&tiny, t),
        Ok(()),
        "alone it is a reduction"
    );
    let sealed = s.seal_batch(&[maker, close, tiny], t + 700);
    assert_eq!(
        sealed.manifest.rejected,
        vec![(
            tiny.order_hash::<Keccak256>(),
            RejectReason::BelowMinimumSize
        )]
    );
    assert!(sealed
        .settled_order_hashes
        .contains(&close.order_hash::<Keccak256>()));
    assert_eq!(s.state.position(&owner_id(2), 0).unwrap().size, 0);
    // the other order of the pair keeps its exemption: a $5 trim after a $50 trim
    // of a larger long still only reduces
    s.seal_batch(
        &[
            order(1, Side::Sell, lot, 100_000, 6),
            order(2, Side::Buy, lot, 100_000, 7),
        ],
        t + 1_400,
    );
    let half = order(2, Side::Sell, lot / 2, 100_000, 8);
    let trim = order(2, Side::Sell, TEN_DOLLARS / 2, 100_000, 9);
    let sealed = s.seal_batch(&[half, trim], t + 2_100);
    assert!(
        sealed.manifest.rejected.is_empty(),
        "{:?}",
        sealed.manifest.rejected
    );
    assert!(s.state.conservation_holds());
}

/// Owner 2 rests a $5 sell as an exempt reduction of its $100 long, then closes
/// the long with another order. When a buyer later reaches the resting $5 sell, the
/// fill would open a $5 short, so settlement refuses it: the sell is banned with
/// `BelowMinimumSize` and the buyer's order is left to rest.
#[test]
fn a_resting_exempt_order_cannot_open_when_it_fills() {
    let t = 10_000u64;
    let mut s = setup(t);
    fund(&mut s, 3, 20_000, 0x33);
    let lot = SIZE_SCALE / 1_000;
    s.seal_batch(
        &[
            order(1, Side::Sell, lot, 100_000, 1),
            order(2, Side::Buy, lot, 100_000, 2),
        ],
        t,
    );
    let tiny = order(2, Side::Sell, TEN_DOLLARS / 2, 100_100, 3);
    let tiny_hash = tiny.order_hash::<Keccak256>();
    let sealed = s.seal_batch(&[tiny], t + 700);
    assert!(sealed.manifest.ordered.contains(&tiny_hash));
    assert_eq!(s.remaining_order_size(&tiny_hash), Some(TEN_DOLLARS / 2));
    // the long is closed by an IOC against owner 1's bid
    s.seal_batch(
        &[
            order(1, Side::Buy, lot, 100_000, 4),
            ioc(order(2, Side::Sell, lot, 100_000, 5)),
        ],
        t + 1_400,
    );
    assert_eq!(s.state.position(&owner_id(2), 0).unwrap().size, 0);
    assert_eq!(s.remaining_order_size(&tiny_hash), Some(TEN_DOLLARS / 2));
    // owner 3 buys $10 up to $100,100 and reaches the $5 sell
    let buy = order(3, Side::Buy, TEN_DOLLARS, 100_100, 6);
    let sealed = s.seal_batch(&[buy], t + 2_100);
    assert_eq!(
        sealed.manifest.rejected,
        vec![(tiny_hash, RejectReason::BelowMinimumSize)]
    );
    assert!(sealed.applied_fills.is_empty());
    assert_eq!(
        s.remaining_order_size(&tiny_hash),
        None,
        "banned from the book"
    );
    assert_eq!(
        s.remaining_order_size(&buy.order_hash::<Keccak256>()),
        Some(TEN_DOLLARS)
    );
    assert_eq!(s.state.position(&owner_id(2), 0).unwrap().size, 0);
    assert!(s.state.conservation_holds());
}

/// While it still reduces, a resting exempt order fills normally, and a cancelled
/// one leaves nothing behind.
#[test]
fn a_resting_exempt_order_fills_while_it_reduces() {
    let t = 10_000u64;
    let mut s = setup(t);
    fund(&mut s, 3, 20_000, 0x33);
    let lot = SIZE_SCALE / 1_000;
    s.seal_batch(
        &[
            order(1, Side::Sell, lot, 100_000, 1),
            order(2, Side::Buy, lot, 100_000, 2),
        ],
        t,
    );
    let tiny = order(2, Side::Sell, TEN_DOLLARS / 2, 100_100, 3);
    s.seal_batch(&[tiny], t + 700);
    let sealed = s.seal_batch(&[order(3, Side::Buy, TEN_DOLLARS, 100_100, 4)], t + 1_400);
    assert!(sealed.manifest.rejected.is_empty());
    assert!(sealed
        .settled_order_hashes
        .contains(&tiny.order_hash::<Keccak256>()));
    assert_eq!(
        s.state.position(&owner_id(2), 0).unwrap().size,
        lot - TEN_DOLLARS / 2
    );
    let again = order(2, Side::Sell, TEN_DOLLARS / 2, 100_200, 5);
    s.seal_batch(&[again], t + 2_100);
    assert!(s.cancel_order(&owner_id(2), &again, true).is_some());
    assert!(s.state.conservation_holds());
}

/// The gateway's house market maker answers each taker with a counter order of the
/// taker's size. A $5 reduce-only close is exempt from the minimum, but its counter
/// adds to the house's position, so without the house exemption the counter is
/// refused and the close finds no liquidity. With it, the close trades.
#[test]
fn an_exempt_owner_can_counter_a_small_close() {
    for exempt in [false, true] {
        let t = 10_000u64;
        let mut s = setup(t); // 1 = house, 2 = user
        fund(&mut s, 3, 20_000, 0x33); // 3 = another user
        if exempt {
            s.set_minimum_exempt_owner(Some(owner_id(1)));
        }
        // user 3 shorts 0.01 BTC against the house: the house is long 0.01
        s.seal_batch(
            &[
                order(1, Side::Buy, SIZE_SCALE / 100, 100_000, 1),
                ioc(order(3, Side::Sell, SIZE_SCALE / 100, 100_000, 2)),
            ],
            t,
        );
        // user 2 buys $20, then sells $15 of it reduce-only, keeping a $5 long
        s.seal_batch(
            &[
                order(1, Side::Sell, TEN_DOLLARS * 2, 100_000, 3),
                ioc(order(2, Side::Buy, TEN_DOLLARS * 2, 100_000, 4)),
            ],
            t + 700,
        );
        s.seal_batch(
            &[
                order(1, Side::Buy, TEN_DOLLARS * 3 / 2, 100_000, 5),
                ioc(Order {
                    reduce_only: true,
                    ..order(2, Side::Sell, TEN_DOLLARS * 3 / 2, 100_000, 6)
                }),
            ],
            t + 1_400,
        );
        assert_eq!(
            s.state.position(&owner_id(2), 0).unwrap().size,
            TEN_DOLLARS / 2
        );
        // the $5 close and its house counter
        let counter = order(1, Side::Buy, TEN_DOLLARS / 2, 100_000, 7);
        let close = ioc(Order {
            reduce_only: true,
            ..order(2, Side::Sell, TEN_DOLLARS / 2, 100_000, 8)
        });
        let sealed = s.seal_batch(&[counter, close], t + 2_100);
        let counter_refused = sealed.manifest.rejected.contains(&(
            counter.order_hash::<Keccak256>(),
            RejectReason::BelowMinimumSize,
        ));
        assert_eq!(counter_refused, !exempt);
        let left = s.state.position(&owner_id(2), 0).unwrap().size;
        assert_eq!(
            left,
            if exempt { 0 } else { TEN_DOLLARS / 2 },
            "exempt={exempt}"
        );
        assert!(s.state.conservation_holds());
    }
}

/// While the engine is close-only, an order that adds exposure is refused before
/// matching with `MarketCloseOnly`, also when only the owner's earlier order of the
/// same batch makes it add exposure.
#[test]
fn close_only_admission_refuses_orders_that_add_exposure() {
    let t = 10_000u64;
    let mut s = setup(t);
    let lot = SIZE_SCALE / 100;
    s.seal_batch(
        &[
            order(1, Side::Sell, lot, 100_000, 1),
            order(2, Side::Buy, lot, 100_000, 2),
        ],
        t,
    );
    s.apply(&BatchOp::EnterCloseOnly).unwrap();
    let open = order(2, Side::Buy, lot, 100_000, 3);
    assert_eq!(
        s.pre_trade_check(&open, t),
        Err(RejectReason::MarketCloseOnly)
    );
    let close = order(2, Side::Sell, lot, 100_000, 4);
    let reopen = order(2, Side::Sell, lot, 99_000, 5);
    let maker = order(1, Side::Buy, lot, 100_000, 6);
    let sealed = s.seal_batch(&[close, reopen, maker], t + 700);
    assert_eq!(
        sealed.manifest.rejected,
        vec![(
            reopen.order_hash::<Keccak256>(),
            RejectReason::MarketCloseOnly
        )]
    );
    assert_eq!(s.state.position(&owner_id(2), 0).unwrap().size, 0);
    assert!(s.state.conservation_holds());
}

// ---------------------------------------------------------------------------
// Wind-down recipient
// ---------------------------------------------------------------------------

#[test]
#[should_panic(expected = "set_wind_down_recipient must run before the first window is sealed")]
fn the_recipient_cannot_be_set_after_a_window_is_sealed() {
    let mut s = Sequencer::new(enclave(), 20);
    s.add_market(test_market(0));
    s.set_wind_down_recipient([0x5A; 20]);
    s.seal_genesis_baseline();
    let _ = s.seal_window();
    s.set_wind_down_recipient([0x5A; 20]);
}

#[test]
#[should_panic(expected = "the wind-down recipient is fixed once set")]
fn the_recipient_cannot_be_replaced() {
    let mut s = Sequencer::new(enclave(), 20);
    s.add_market(test_market(0));
    s.set_wind_down_recipient([0x5A; 20]);
    s.set_wind_down_recipient([0x5B; 20]);
}

#[test]
#[should_panic(expected = "set_wind_down_recipient must run before any window ops")]
fn the_recipient_cannot_be_set_over_a_pending_manifest() {
    let mut s = Sequencer::new(enclave(), 20);
    s.add_market(test_market(0));
    // a rejection in the open window's manifest, with no op
    s.reject_in_window(&[word_u64(1)], RejectReason::Cancelled);
    assert!(s.window_has_pending_manifest() && !s.window_has_staged_ops());
    s.set_wind_down_recipient([0x5A; 20]);
}

#[test]
fn the_same_recipient_may_be_set_again_before_genesis() {
    let mut s = Sequencer::new(enclave(), 20);
    s.add_market(test_market(0));
    s.set_wind_down_recipient([0x5A; 20]);
    let root = s.state.state_root();
    s.set_wind_down_recipient([0x5A; 20]);
    assert_eq!(s.state.state_root(), root);
    assert_eq!(s.window_baseline().state_root(), root);
}

// ---------------------------------------------------------------------------
// Funding mark
// ---------------------------------------------------------------------------

/// Owners 1 and 2 quote $10k each side, $100 either side of a $100k index, so the
/// impact mid sits on the index. Owner 3 (the attacker) is funded with $1k.
fn quoted_book(t: u64) -> Sequencer {
    let mut s = setup(t);
    fund(&mut s, 3, 1_000, 0x33);
    let sealed = s.seal_batch(
        &[
            order(1, Side::Buy, SIZE_SCALE / 10, 99_900, 1),
            order(2, Side::Sell, SIZE_SCALE / 10, 100_100, 2),
        ],
        t,
    );
    assert!(sealed.manifest.rejected.is_empty());
    assert_eq!(s.impact_mid(0, t), Some(100_000 * PRICE_SCALE));
    s
}

/// A $10 bid $1 under the ask, placed at the last tick before the window is sealed,
/// moves the top-of-book mid enough to clamp the rate. The funding mark is not
/// moved by it: the tick's sample is taken before its orders reach the book, the
/// bid is far below the impact size, and the next window starts its average
/// afresh, so the rate in force over the pause after the seal carries no premium.
#[test]
fn a_ten_dollar_quote_at_the_last_tick_cannot_set_the_pause_rate() {
    let index = 100_000 * PRICE_SCALE;
    let t1 = 10_000u64;
    let mut s = quoted_book(t1);
    // the quotes arrived in t1's batch: t1's sample saw an empty book
    let mut model = MarkModel {
        samples: vec![(t1, 0)],
    };
    let mut t = t1;
    for _ in 0..8 {
        t += 700;
        let mark = modeled_tick(&mut s, &mut model, t, &[]);
        assert_eq!(mark, index, "the honest window has no premium");
    }

    // the last tick before the seal: the attacker's $10 bid, $1 under the ask
    t += 700;
    let attack = order(3, Side::Buy, TEN_DOLLARS, 100_099, 9);
    s.set_oracle(0, oracle(100_000, t));
    model.sample(&s, t, index);
    let sealed = s.seal_batch(&[attack], t);
    assert!(sealed
        .manifest
        .ordered
        .contains(&attack.order_hash::<Keccak256>()));
    let book = s.book(0).unwrap();
    let top_mid = book.best_bid().unwrap() / 2 + book.best_ask().unwrap() / 2;
    assert_eq!(
        FundingState::funding_rate(top_mid, index),
        MAX_FUNDING_RATE_PER_INTERVAL,
        "fixture: the top-of-book mid would clamp the rate"
    );
    assert_eq!(accrue_mark(&sealed.ops), index);
    assert_eq!(accrue_mark(&sealed.ops), model.mark(index));
    assert_eq!(
        s.state.funding[&0].rate, 0,
        "the pause is priced at no premium"
    );
    let impact_premium = s.impact_mid(0, t).unwrap() - index;
    assert!(
        impact_premium > 0 && impact_premium < PRICE_SCALE,
        "the $10 bid moves the impact mid by under $1: {impact_premium}"
    );

    // seal and pause for 30 minutes
    let _ = s.seal_window();
    let mut model = MarkModel::default();
    let reopen = t + 1_800_000;
    let mark = modeled_tick(&mut s, &mut model, reopen, &[]);
    assert_eq!(
        mark, index,
        "the new window carries no sample over the pause"
    );
    // the bid is still resting: from now on it counts, at its impact weight only,
    // and over at least the minimum span
    let next = reopen + 700;
    let mark = modeled_tick(&mut s, &mut model, next, &[]);
    assert_eq!(
        mark,
        index + impact_premium * 700 / i128::from(FUNDING_MARK_MIN_SPAN_MS)
    );
    let rate = s.state.funding[&0].rate;
    assert_eq!(rate, FundingState::funding_rate(mark, index));
    assert!(
        rate * 50 < MAX_FUNDING_RATE_PER_INTERVAL,
        "the rate stays far below the clamp: {rate}"
    );
}

/// Quotes that together hold less than the impact notional on a side give no
/// impact price, however far they sit from the index.
#[test]
fn quotes_below_the_impact_size_do_not_move_the_mark() {
    let index = 100_000 * PRICE_SCALE;
    let t1 = 10_000u64;
    let mut s = setup(t1);
    // $999 of bids and $999 of asks, both well above the index (a 0.5% premium)
    let size = FUNDING_IMPACT_NOTIONAL * SIZE_SCALE * 999 / 1_000 / (100_500 * QUOTE_SCALE);
    s.seal_batch(
        &[
            order(1, Side::Buy, size, 100_500, 1),
            order(2, Side::Sell, size, 100_520, 2),
        ],
        t1,
    );
    assert!(s.book(0).unwrap().best_bid().is_some() && s.book(0).unwrap().best_ask().is_some());
    let mut t = t1;
    for _ in 0..5 {
        assert_eq!(s.impact_mid(0, t), None);
        t += 700;
        s.set_oracle(0, oracle(100_000, t));
        let sealed = s.seal_batch(&[], t);
        assert_eq!(accrue_mark(&sealed.ops), index);
        assert_eq!(s.state.funding[&0].rate, 0);
    }
}

#[test]
fn an_empty_side_falls_back_to_the_index() {
    let index = 100_000 * PRICE_SCALE;
    let t1 = 10_000u64;
    let mut s = setup(t1);
    // deep asks only, 1% above the index
    s.seal_batch(&[order(2, Side::Sell, SIZE_SCALE, 101_000, 1)], t1);
    assert!(s.book(0).unwrap().best_bid().is_none());
    let mut t = t1;
    for _ in 0..5 {
        assert_eq!(s.impact_mid(0, t), None);
        t += 700;
        s.set_oracle(0, oracle(100_000, t));
        let sealed = s.seal_batch(&[], t);
        assert_eq!(accrue_mark(&sealed.ops), index);
        assert_eq!(s.state.funding[&0].rate, 0);
    }
}

/// The window average weighs each premium sample by the span it prices (the time
/// since the previous tick), counts missing time up to the minimum span at the
/// index, and averages the premium rather than the mid: a move of the index during
/// the window does not read as a premium. A quote withdrawn before a tick prices
/// nothing at that tick.
#[test]
fn the_mark_is_the_time_weighted_premium_of_the_open_window() {
    let t1 = 10_000u64;
    let mut s = setup(t1);
    // impact mid $100,020 against a $100,000 index: a $20 premium
    let bid = order(1, Side::Buy, SIZE_SCALE / 10, 100_000, 1);
    let sealed = s.seal_batch(
        &[bid, order(2, Side::Sell, SIZE_SCALE / 10, 100_040, 2)],
        t1,
    );
    assert_eq!(
        accrue_mark(&sealed.ops),
        100_000 * PRICE_SCALE,
        "the quotes arrived in t1's batch"
    );
    assert_eq!(s.impact_mid(0, t1), Some(100_020 * PRICE_SCALE));

    // 700 ms later the index has risen by $10: the premium is now $10, and the
    // 700 ms it priced count over the 7 s minimum span
    let t2 = t1 + 700;
    let index2 = 100_010 * PRICE_SCALE;
    s.set_oracle(0, oracle_px(index2, t2));
    let sealed = s.seal_batch(&[], t2);
    let premium = 10 * PRICE_SCALE;
    let mark = accrue_mark(&sealed.ops);
    assert_eq!(mark, index2 + premium * 700 / 7_000);
    assert_eq!(
        s.state.funding[&0].rate,
        FundingState::funding_rate(mark, index2)
    );

    // 7,000 ms more at the same premium: 7,700 ms of $10 is a $10 average
    let t3 = t2 + 7_000;
    s.set_oracle(0, oracle_px(index2, t3));
    let sealed = s.seal_batch(&[], t3);
    assert_eq!(accrue_mark(&sealed.ops), index2 + premium);

    // the bid is cancelled between ticks: the next 2,300 ms are priced at the
    // index, since no impact bid faced the takers at t4
    assert!(s.cancel_order(&owner_id(1), &bid, true).is_some());
    let t4 = t3 + 2_300;
    s.set_oracle(0, oracle_px(index2, t4));
    let sealed = s.seal_batch(&[], t4);
    let mark = accrue_mark(&sealed.ops);
    assert_eq!(mark, index2 + premium * 7_700 / 10_000);
    assert_eq!(
        s.state.funding[&0].rate,
        FundingState::funding_rate(mark, index2)
    );
}

/// Owner 3, funded with $1k, rests a bid at +4.9% and an ask at +5.0%, about
/// $1,050 a side. Both lie inside the 5% mark band but outside the 2% fill band, so
/// no taker could ever trade against them: they give no impact price, and the
/// rate stays at zero. A seller that crosses the bid finds the fill refused and the
/// bid banned.
#[test]
fn depth_outside_the_fill_band_does_not_move_the_mark() {
    let t1 = 10_000u64;
    let mut s = setup(t1);
    fund(&mut s, 3, 1_000, 0x33);
    s.seal_genesis_baseline();
    let mut model = MarkModel::default();
    let mut t = t1;
    modeled_tick(&mut s, &mut model, t, &[]);
    t += 700;
    let bid = order(3, Side::Buy, SIZE_SCALE / 100, 104_900, 1);
    let ask = order(3, Side::Sell, SIZE_SCALE / 100, 105_000, 2);
    s.set_oracle(0, oracle(100_000, t));
    let sealed = s.seal_batch(&[bid, ask], t);
    assert!(sealed.manifest.rejected.is_empty());
    assert_eq!(s.impact_mid(0, t), None);
    for _ in 0..8 {
        t += 700;
        s.set_oracle(0, oracle(100_000, t));
        let sealed = s.seal_batch(&[], t);
        assert_eq!(accrue_mark(&sealed.ops), 100_000 * PRICE_SCALE);
        assert_eq!(s.state.funding[&0].rate, 0);
    }
    // the bid was never fillable
    t += 700;
    s.set_oracle(0, oracle(100_000, t));
    let sell = Order {
        tif: TimeInForce::Ioc,
        ..order(2, Side::Sell, SIZE_SCALE / 100, 100_000, 3)
    };
    let sealed = s.seal_batch(&[sell], t);
    assert!(sealed.manifest.rejected.contains(&(
        bid.order_hash::<Keccak256>(),
        RejectReason::FillPriceOutOfBand
    )));
    assert!(s
        .state
        .position(&owner_id(3), 0)
        .is_none_or(|p| p.size == 0));
}

/// Depth whose maker could not settle the fill is not depth: owner 3 quotes about
/// $1,010 a side inside the fill band, then unbinds all but $50 of its collateral,
/// so neither quote could fill without breaking its initial margin.
#[test]
fn depth_its_maker_could_not_margin_does_not_move_the_mark() {
    let t1 = 10_000u64;
    let mut s = setup(t1);
    fund(&mut s, 3, 1_000, 0x33);
    let bid = order(3, Side::Buy, SIZE_SCALE / 100, 101_000, 1);
    let ask = order(3, Side::Sell, SIZE_SCALE / 100, 101_050, 2);
    s.seal_batch(&[bid, ask], t1);
    assert_eq!(
        s.impact_mid(0, t1),
        Some(101_025 * PRICE_SCALE),
        "fixture: margined, the quotes are depth"
    );
    let collateral = s.state.position(&owner_id(3), 0).unwrap().collateral;
    s.apply(&BatchOp::Unbind {
        owner: owner_id(3),
        market_id: 0,
        amount: collateral - 50 * QUOTE_SCALE,
        blinding: [0x7A; 32],
        oracle: oracle(100_000, t1),
        now_ms: t1,
    })
    .unwrap();
    assert_eq!(s.impact_mid(0, t1), None);
    let mut t = t1;
    for _ in 0..8 {
        t += 700;
        s.set_oracle(0, oracle(100_000, t));
        let sealed = s.seal_batch(&[], t);
        assert_eq!(accrue_mark(&sealed.ops), 100_000 * PRICE_SCALE);
        assert_eq!(s.state.funding[&0].rate, 0);
    }
}

/// Quotes inside the fill band at +1.925%, placed at one tick and cancelled (or
/// expiring) before the next, were never on the book when any taker could trade
/// against them, so they price no span: the stored rate stays at zero through the
/// window, and the quoter holds no position.
#[test]
fn a_quote_withdrawn_before_the_next_tick_never_counts() {
    for expire in [false, true] {
        let t1 = 10_000u64;
        let mut s = setup(t1);
        fund(&mut s, 3, 1_000, 0x33);
        s.seal_genesis_baseline();
        let mut model = MarkModel::default();
        let mut t = t1;
        modeled_tick(&mut s, &mut model, t, &[]);
        t += 700;
        let expiry_ms = if expire { t + 1 } else { 0 };
        let bid = Order {
            expiry_ms,
            ..order(3, Side::Buy, SIZE_SCALE / 100, 101_900, 1)
        };
        let ask = Order {
            expiry_ms,
            ..order(3, Side::Sell, SIZE_SCALE / 100, 101_950, 2)
        };
        modeled_tick(&mut s, &mut model, t, &[bid, ask]);
        assert!(
            s.impact_mid(0, t).is_some(),
            "fixture: the quotes are depth at t"
        );
        if !expire {
            assert!(s.cancel_order(&owner_id(3), &bid, true).is_some());
            assert!(s.cancel_order(&owner_id(3), &ask, true).is_some());
        }
        for _ in 0..8 {
            t += 700;
            let mark = modeled_tick(&mut s, &mut model, t, &[]);
            assert_eq!(mark, 100_000 * PRICE_SCALE);
            assert_eq!(s.state.funding[&0].rate, 0, "expire={expire}");
        }
        assert!(s
            .state
            .position(&owner_id(3), 0)
            .is_none_or(|p| p.size == 0));
    }
}

/// A book where owner 3 holds a $10 long and rests `stacked` asks of $9 at
/// $100,050, one per batch, each admitted below the minimum because it reduces
/// that position. Owner 1 bids $10k at $99,950 and owner 2 asks $10k at $100,100.
/// Every book runs the same ticks, so twins differ only in the stacked asks.
fn exempt_ask_book(stacked: usize, ticks: usize) -> (Sequencer, u64, Vec<Order>) {
    let mut t = 10_000u64;
    let mut s = setup(t);
    fund(&mut s, 3, 1_000, 0x33);
    s.seal_batch(
        &[
            order(1, Side::Sell, TEN_DOLLARS, 100_000, 1),
            ioc(order(3, Side::Buy, TEN_DOLLARS, 100_000, 2)),
            order(1, Side::Buy, SIZE_SCALE / 10, 99_950, 3),
            order(2, Side::Sell, SIZE_SCALE / 10, 100_100, 4),
        ],
        t,
    );
    assert_eq!(s.state.position(&owner_id(3), 0).unwrap().size, TEN_DOLLARS);
    let mut asks = Vec::new();
    for i in 0..ticks {
        t += 700;
        s.set_oracle(0, oracle(100_000, t));
        let batch: Vec<Order> = if i < stacked {
            vec![order(
                3,
                Side::Sell,
                TEN_DOLLARS * 9 / 10,
                100_050,
                100 + i as u64,
            )]
        } else {
            Vec::new()
        };
        let sealed = s.seal_batch(&batch, t);
        assert!(sealed.manifest.rejected.is_empty(), "tick {i}");
        asks.extend(batch);
    }
    (s, t, asks)
}

/// Orders admitted below the minimum because they reduce can be stacked, one per
/// batch, far beyond the position they reduce; settlement fills them only while
/// they still reduce. They give no depth beyond that position either: with 120
/// stacked $9 asks against a $10 long, the impact ask is the one a single such ask
/// gives, and a $1,000 buy at their price fills $9 of them.
#[test]
fn stacked_exempt_orders_give_no_depth_beyond_the_committed_position() {
    let ticks = 120;
    let (mut stacked, t, asks) = exempt_ask_book(ticks, ticks);
    let (single, t_single, _) = exempt_ask_book(1, ticks);
    assert_eq!(t, t_single);
    assert!(
        i128::try_from(asks.len()).unwrap() * 9 * QUOTE_SCALE > FUNDING_IMPACT_NOTIONAL,
        "fixture: the stacked asks hold more than the impact notional"
    );
    for ask in &asks {
        assert!(stacked
            .remaining_order_size(&ask.order_hash::<Keccak256>())
            .is_some());
    }
    let mid = stacked.impact_mid(0, t).unwrap();
    assert_eq!(Some(mid), single.impact_mid(0, t));
    assert!(
        mid > 100_020 * PRICE_SCALE,
        "the impact ask is mostly owner 2's $100,100 depth: {mid}"
    );
    // the depth the mark counted is the depth settlement fills
    fund(&mut stacked, 4, 20_000, 0x44);
    let t2 = t + 700;
    stacked.set_oracle(0, oracle(100_000, t2));
    let buy = ioc(order(4, Side::Buy, TEN_DOLLARS * 100, 100_050, 9_999));
    let sealed = stacked.seal_batch(&[buy], t2);
    assert_eq!(
        stacked.state.position(&owner_id(4), 0).unwrap().size,
        TEN_DOLLARS * 9 / 10
    );
    assert!(sealed
        .manifest
        .rejected
        .iter()
        .any(|(_, reason)| *reason == RejectReason::BelowMinimumSize));
}

/// A book with `orders` $10 bids from owner 3 (funded with $15) at $100,010, ahead
/// of owner 1's $10k of bids at $99,990; owner 2 asks $10k at $100,030. Each of
/// owner 3's bids fits initial margin on its own, but together only about $150 of
/// them could fill.
fn bloated_bid_book(orders: usize) -> (Sequencer, u64) {
    let t = 10_000u64;
    let mut s = setup(t);
    fund(&mut s, 3, 15, 0x33);
    let mut batch: Vec<Order> = (0..orders)
        .map(|n| order(3, Side::Buy, TEN_DOLLARS, 100_010, 10 + n as u64))
        .collect();
    batch.push(order(1, Side::Buy, SIZE_SCALE / 10, 99_990, 1));
    batch.push(order(2, Side::Sell, SIZE_SCALE / 10, 100_030, 2));
    let sealed = s.seal_batch(&batch, t);
    assert!(sealed.manifest.rejected.is_empty());
    (s, t)
}

/// The impact sweep visits at most `FUNDING_IMPACT_MAX_ORDERS` orders of a side.
/// Below that, the orders a maker could not fill are passed over and the honest
/// depth behind them prices the side; a side that would need more has no impact
/// price, and the mark is the index, as for a side without the depth.
#[test]
fn a_side_that_needs_more_orders_than_the_sweep_visits_falls_back_to_the_index() {
    let (s, t) = bloated_bid_book(FUNDING_IMPACT_MAX_ORDERS - 2);
    let mid = s.impact_mid(0, t).expect("the honest bids are reached");
    // the same mid as a book where owner 3 rests only a few more bids than fill
    let (few, _) = bloated_bid_book(20);
    assert_eq!(few.impact_mid(0, t), Some(mid));
    assert!(mid > 100_000 * PRICE_SCALE && mid < 100_030 * PRICE_SCALE);
    let (mut s, t) = bloated_bid_book(FUNDING_IMPACT_MAX_ORDERS + 1);
    assert_eq!(s.impact_mid(0, t), None);
    let t2 = t + 700;
    s.set_oracle(0, oracle(100_000, t2));
    let sealed = s.seal_batch(&[], t2);
    assert_eq!(accrue_mark(&sealed.ops), 100_000 * PRICE_SCALE);
}

/// A quote resting through one tick's matching counts for the span it priced,
/// and no more: its premium is capped at the one that saturates the rate, and the window
/// average divides by at least the minimum span. So one sample at +1.925% in a
/// ten-tick window moves the stored rate at the window's last tick to at most
/// `MAX · 700 / FUNDING_MARK_MIN_SPAN_MS`.
#[test]
fn one_sample_cannot_saturate_the_pause_rate() {
    let index = 100_000 * PRICE_SCALE;
    let t1 = 10_000u64;
    let mut s = setup(t1);
    fund(&mut s, 3, 1_000, 0x33);
    s.seal_genesis_baseline();
    let bid = order(3, Side::Buy, SIZE_SCALE / 100, 101_900, 1);
    let ask = order(3, Side::Sell, SIZE_SCALE / 100, 101_950, 2);
    let mut model = MarkModel::default();
    let mut t = t1;
    // the quotes arrive in the window's first tick and rest through the second
    modeled_tick(&mut s, &mut model, t, &[bid, ask]);
    t += 700;
    let mark = modeled_tick(&mut s, &mut model, t, &[]);
    assert_eq!(
        model.samples[1].1,
        cap(index),
        "the +1.925% sample is capped"
    );
    assert_eq!(
        mark,
        index + cap(index) * 700 / i128::from(FUNDING_MARK_MIN_SPAN_MS)
    );
    assert!(s.cancel_order(&owner_id(3), &bid, true).is_some());
    assert!(s.cancel_order(&owner_id(3), &ask, true).is_some());
    for _ in 0..8 {
        t += 700;
        modeled_tick(&mut s, &mut model, t, &[]);
    }
    let rate = s.state.funding[&0].rate;
    let bound = MAX_FUNDING_RATE_PER_INTERVAL * 700 / i128::from(FUNDING_MARK_MIN_SPAN_MS);
    assert!(rate > 0 && rate <= bound, "rate {rate} above {bound}");
    let _ = s.seal_window();
    assert_eq!(
        s.state.funding[&0].rate, rate,
        "the rate that prices the pause"
    );
}

/// A book far above the index no longer drops the funding tick: depth the engine
/// could fill only counts inside the fill band, and every premium is capped below
/// the mark band, so the op is always admissible. A deep in-band book at the edge
/// of the fill band held through a whole window saturates the rate, as an honest
/// premium should.
#[test]
fn a_premium_held_through_the_window_reaches_the_clamp() {
    let index = 100_000 * PRICE_SCALE;
    let t1 = 10_000u64;
    let mut s = setup(t1);
    // a two-sided book 1.9% above the index
    s.seal_batch(
        &[
            order(1, Side::Buy, SIZE_SCALE / 10, 101_900, 1),
            order(2, Side::Sell, SIZE_SCALE / 10, 101_950, 2),
        ],
        t1,
    );
    let mut model = MarkModel {
        samples: vec![(t1, 0)],
    };
    let mut t = t1;
    let mut mark = index;
    for _ in 0..10 {
        t += 700;
        mark = modeled_tick(&mut s, &mut model, t, &[]);
        assert!(mark <= index + cap(index));
    }
    assert_eq!(mark, index + cap(index), "ten ticks fill the minimum span");
    assert_eq!(s.state.funding[&0].rate, MAX_FUNDING_RATE_PER_INTERVAL);
}

// ---------------------------------------------------------------------------
// Idle windows and price epochs
// ---------------------------------------------------------------------------

/// Ticks of a market at a zero rate change no state: the window stays idle and
/// its funding no-ops are discarded.
#[test]
fn zero_rate_ticks_keep_the_window_idle() {
    let mut s = setup(1_000);
    s.seal_genesis_baseline();
    let root = s.state.state_root();
    for k in 0..20u64 {
        let t = 1_000 + k * 700;
        s.set_oracle(0, oracle(100_000, t));
        let sealed = s.seal_batch(&[], t);
        assert_eq!(accrue_mark(&sealed.ops), 100_000 * PRICE_SCALE);
    }
    assert_eq!(s.state.state_root(), root);
    assert!(s.window_op_count() > 0);
    assert!(s.discard_idle_funding_window());
    assert_eq!(s.window_op_count(), 0);
    assert!(s.seal_empty_window().is_some(), "the keepalive may seal it");
}

/// Once a market has recorded a price, its zero-rate ticks refresh that price at
/// the first tick of every price epoch, and only then: exactly one non-idle window
/// per epoch.
#[test]
fn a_traded_market_gives_one_non_idle_window_per_price_epoch() {
    let t0 = 1_000u64;
    let mut s = setup(t0);
    s.seal_genesis_baseline();
    s.seal_batch(
        &[
            order(1, Side::Sell, SIZE_SCALE / 10, 100_000, 1),
            order(2, Side::Buy, SIZE_SCALE / 10, 100_000, 2),
        ],
        t0,
    );
    assert_eq!(s.state.funding[&0].last_price_ms, t0);
    let _ = s.seal_window();

    let mut non_idle: BTreeMap<u64, u32> = BTreeMap::new();
    for k in 1..=48u64 {
        let t = t0 + k * 1_800_000; // every 30 minutes for a day
        s.set_oracle(0, oracle(100_000, t));
        s.seal_batch(&[], t);
        if !s.discard_idle_funding_window() {
            assert!(s.window_has_staged_ops());
            assert_eq!(
                s.state.funding[&0].last_price_ms, t,
                "the refresh records the price"
            );
            *non_idle.entry(t / PRICE_REFRESH_MS).or_default() += 1;
            let _ = s.seal_window();
        }
    }
    assert_eq!(
        non_idle,
        BTreeMap::from([(1, 1), (2, 1), (3, 1), (4, 1)]),
        "one refresh per epoch after the trade's, none in the trade's own epoch"
    );
}

// ---------------------------------------------------------------------------
// Liquidation scans
// ---------------------------------------------------------------------------

/// Auto-deleverage takes at most what leaves each winner at or above maintenance
/// margin, so a winner healthy after the cascade at one seal is not liquidated at
/// the next under the same oracle and index.
#[test]
fn an_adl_winner_healthy_at_one_seal_is_not_liquidated_at_the_next() {
    let mut s = setup(1_000);
    s.seal_batch(
        &[
            order(1, Side::Sell, SIZE_SCALE, 100_000, 1),
            order(2, Side::Buy, SIZE_SCALE, 100_000, 2),
        ],
        1_000,
    );
    // a gap to $75k: the long's $25k loss exceeds its $20k collateral, and with no
    // insurance or treasury the shortfall is clawed from the short
    let crash = oracle(75_000, 5_000);
    s.set_oracle(0, crash);
    let n = s.seal_batch(&[], 5_000);
    assert_eq!(n.liquidation_tags.len(), 1);
    assert!(!n.adl_receipts.is_empty(), "the winner was clawed");
    let index = s.state.funding[&0].cumulative_index;
    let winner = *s.state.position(&owner_id(1), 0).unwrap();
    let market = test_market(0);
    let price = 75_000 * PRICE_SCALE;
    assert!(winner.is_open());
    assert!(
        winner.equity(price, index).unwrap()
            >= winner.maintenance_required(&market, price).unwrap()
    );

    // the next seal, same transcript, same index
    let n1 = s.seal_batch(&[], 5_700);
    assert_eq!(s.state.funding[&0].cumulative_index, index);
    assert!(n1.liquidation_tags.is_empty());
    assert!(!n1
        .ops
        .iter()
        .any(|op| matches!(op, BatchOp::Liquidate { .. })));
    assert_eq!(*s.state.position(&owner_id(1), 0).unwrap(), winner);
    assert!(s.state.conservation_holds());
}

/// A position closed and fully unbound leaves the state, so the sequencer's scans
/// no longer see it: the maintenance pass skips it and the pre-trade check treats
/// the owner as flat.
#[test]
fn pruned_positions_leave_the_scans() {
    let t = 1_000u64;
    let mut s = setup(t);
    s.seal_batch(
        &[
            order(1, Side::Sell, SIZE_SCALE / 10, 100_000, 1),
            order(2, Side::Buy, SIZE_SCALE / 10, 100_000, 2),
        ],
        t,
    );
    s.seal_batch(
        &[
            order(1, Side::Buy, SIZE_SCALE / 10, 100_000, 3),
            order(2, Side::Sell, SIZE_SCALE / 10, 100_000, 4),
        ],
        t,
    );
    let flat = *s.state.position(&owner_id(2), 0).unwrap();
    assert_eq!(flat.size, 0);
    s.apply(&BatchOp::Unbind {
        owner: owner_id(2),
        market_id: 0,
        amount: flat.collateral,
        blinding: [0x77; 32],
        oracle: oracle(100_000, t),
        now_ms: t,
    })
    .unwrap();
    assert!(s.state.position(&owner_id(2), 0).is_none(), "pruned");
    assert!(!s.state.positions.values().any(|p| p.is_empty()));

    let mut ro = order(2, Side::Sell, SIZE_SCALE / 10, 100_000, 5);
    ro.reduce_only = true;
    assert_eq!(
        s.pre_trade_check(&ro, t),
        Err(RejectReason::ReduceOnlyViolation),
        "the pruned owner is flat"
    );

    s.set_oracle(0, oracle(84_000, 5_000));
    let sealed = s.seal_batch(&[], 5_000);
    assert!(sealed.liquidation_tags.is_empty());
    assert!(s.state.position(&owner_id(2), 0).is_none());
    assert!(s.state.conservation_holds());
}

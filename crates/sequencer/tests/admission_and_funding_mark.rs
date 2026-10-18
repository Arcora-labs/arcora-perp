//! Sequencer admission and funding-mark rules:
//!
//!  * the pre-trade check reads the funding index the engine's fill will read
//!    (`FundingState::index_at`), so it agrees with the engine after a pause;
//!  * the minimum order notional applies only to orders that add exposure;
//!  * the funding mark is the impact-notional book mid, averaged over the open
//!    window, with the oracle index as the fallback;
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
    below_minimum_order_notional, EnclaveIdentity, Sequencer, FUNDING_IMPACT_NOTIONAL,
    MIN_ORDER_NOTIONAL,
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

/// A model of the sequencer's funding mark: samples `(time, premium)`, each in
/// force until the next; the mark at a tick is the index plus the time-weighted
/// average of the samples whose span has closed.
#[derive(Default)]
struct MarkModel {
    samples: Vec<(u64, i128)>,
}

impl MarkModel {
    fn mark_at(&self, now: u64, index: i128) -> i128 {
        let mut weighted = 0i128;
        let mut elapsed = 0i128;
        for (i, (t, p)) in self.samples.iter().enumerate() {
            let end = self.samples.get(i + 1).map_or(now, |(t1, _)| *t1);
            weighted += p * i128::from(end - t);
            elapsed += i128::from(end - t);
        }
        let avg = if elapsed == 0 { 0 } else { weighted / elapsed };
        index + avg.clamp(-band(index), band(index))
    }

    /// Record the sample the sequencer takes after a tick at `now`.
    fn sample(&mut self, seq: &Sequencer, now: u64, index: i128) {
        let premium = seq
            .impact_mid(0, now)
            .map_or(0, |mid| (mid - index).clamp(-band(index), band(index)));
        self.samples.push((now, premium));
    }
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
/// moved by it: a tick's own quote never weighs in that tick's mark, the bid is far
/// below the impact size, and the next window starts its average afresh, so the
/// rate in force over the pause after the seal carries no premium.
#[test]
fn a_ten_dollar_quote_at_the_last_tick_cannot_set_the_pause_rate() {
    let index = 100_000 * PRICE_SCALE;
    let t1 = 10_000u64;
    let mut s = quoted_book(t1);
    let mut model = MarkModel::default();
    model.sample(&s, t1, index);
    let mut t = t1;
    for _ in 0..8 {
        t += 700;
        s.set_oracle(0, oracle(100_000, t));
        let sealed = s.seal_batch(&[], t);
        assert_eq!(accrue_mark(&sealed.ops), model.mark_at(t, index));
        assert_eq!(
            accrue_mark(&sealed.ops),
            index,
            "the honest window has no premium"
        );
        model.sample(&s, t, index);
    }

    // the last tick before the seal: the attacker's $10 bid, $1 under the ask
    t += 700;
    s.set_oracle(0, oracle(100_000, t));
    let attack = order(3, Side::Buy, TEN_DOLLARS, 100_099, 9);
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
    assert_eq!(
        s.state.funding[&0].rate, 0,
        "the pause is priced at no premium"
    );
    model.sample(&s, t, index);
    let impact_premium = model.samples.last().unwrap().1;
    assert!(
        impact_premium > 0 && impact_premium < PRICE_SCALE,
        "the $10 bid moves the impact mid by under $1: {impact_premium}"
    );

    // seal and pause for 30 minutes
    let _ = s.seal_window();
    let reopen = t + 1_800_000;
    s.set_oracle(0, oracle(100_000, reopen));
    let sealed = s.seal_batch(&[], reopen);
    assert_eq!(
        accrue_mark(&sealed.ops),
        index,
        "the new window carries no sample over the pause"
    );
    // the bid is still resting: from now on it counts, at its impact weight only
    let next = reopen + 700;
    s.set_oracle(0, oracle(100_000, next));
    let sealed = s.seal_batch(&[], next);
    let mark = accrue_mark(&sealed.ops);
    assert_eq!(mark, index + impact_premium);
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

/// The window average weighs each premium sample by the time it was in force, and
/// it averages the premium rather than the mid: a move of the index during the
/// window does not read as a premium.
#[test]
fn the_mark_is_the_time_weighted_premium_of_the_open_window() {
    let t1 = 10_000u64;
    let mut s = setup(t1);
    // impact mid $100,050 against a $100,000 index: a $50 premium
    s.seal_batch(
        &[
            order(1, Side::Buy, SIZE_SCALE / 10, 100_000, 1),
            order(2, Side::Sell, SIZE_SCALE / 10, 100_100, 2),
        ],
        t1,
    );
    assert_eq!(s.impact_mid(0, t1), Some(100_050 * PRICE_SCALE));

    // 700 ms later the index has risen to the mid; the $50 sample was in force
    let t2 = t1 + 700;
    let index2 = 100_050 * PRICE_SCALE;
    s.set_oracle(0, oracle_px(index2, t2));
    let sealed = s.seal_batch(&[], t2);
    assert_eq!(accrue_mark(&sealed.ops), index2 + 50 * PRICE_SCALE);
    assert_eq!(s.state.funding[&0].rate, 499, "≈ 0.05%, at the new index");

    // 2,100 ms at no premium: (50 · 700 + 0 · 2,100) / 2,800 = $12.50
    let t3 = t2 + 2_100;
    s.set_oracle(0, oracle_px(index2, t3));
    let sealed = s.seal_batch(&[], t3);
    let mark = accrue_mark(&sealed.ops);
    assert_eq!(mark, index2 + 1_250 * PRICE_SCALE / 100);
    assert_eq!(
        s.state.funding[&0].rate,
        FundingState::funding_rate(mark, index2)
    );
    assert_eq!(s.state.funding[&0].rate, 124);
}

/// A book far outside the mark band no longer drops the funding tick: each sample
/// is clamped to the band, so the op is always admissible and the rate clamps.
#[test]
fn an_out_of_band_book_clamps_the_mark_to_the_band() {
    let index = 100_000 * PRICE_SCALE;
    let t1 = 10_000u64;
    let mut s = setup(t1);
    // a two-sided book 10% above the index
    s.seal_batch(
        &[
            order(1, Side::Buy, SIZE_SCALE / 10, 110_000, 1),
            order(2, Side::Sell, SIZE_SCALE / 10, 110_100, 2),
        ],
        t1,
    );
    let t2 = t1 + 700;
    s.set_oracle(0, oracle(100_000, t2));
    let sealed = s.seal_batch(&[], t2);
    assert_eq!(accrue_mark(&sealed.ops), index + band(index));
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

//! Funding spans are charged to the positions that existed during them.
//!
//! * Each market stores the rate observed by its last `AccrueFunding`; a span is
//!   committed at that stored rate, so it is never priced at a rate observed
//!   after it.
//! * `Fill`, `Liquidate` and `Unbind` commit the open span up to their own time
//!   before they read the index. A position opened at time `t` owes nothing for
//!   the time before `t`; a position closed at `t` pays all of it. Within one
//!   timestamp the order of ops does not change the post-state.
//! * Each span is charged for at most one funding interval.
//! * A zero rate observed on a market whose stored rate is zero changes nothing,
//!   so idle ticks leave the state root unchanged.
//! * A refused op leaves the funding state unchanged.

use k256::ecdsa::SigningKey;
use perp_core::engine::BatchOp;
use perp_core::fixed::{PRICE_SCALE, QUOTE_SCALE, SIZE_SCALE};
use perp_core::funding::{FUNDING_DIVISOR, FUNDING_INTERVAL_MS, MAX_FUNDING_RATE_PER_INTERVAL};
use perp_core::hash::Keccak256;
use perp_core::note::{owner_from_spend_key, PubKey};
use perp_core::oracle::{oracle_digest, OracleSig, OracleTranscript};
use perp_core::order::Side;
use perp_core::position::Position;
use perp_core::{DefaultState, EngineError, Market, Note};

const T0: u64 = 1_700_000_000_000;
const PRICE: i128 = 100_000;
const INDEX: i128 = PRICE * PRICE_SCALE;
/// The index notional of one BTC, micro-USD.
const INDEX_QUOTE: i128 = PRICE * QUOTE_SCALE;
const MAX: i128 = MAX_FUNDING_RATE_PER_INTERVAL;
const MINUTE: u64 = 60_000;

fn usd(x: i128) -> i128 {
    x * QUOTE_SCALE
}

fn owner_of(sk: u8) -> PubKey {
    owner_from_spend_key::<Keccak256>(&[sk; 32])
}

fn oracle_key() -> SigningKey {
    SigningKey::from_bytes((&[7u8; 32]).into()).unwrap()
}

fn oracle_addr() -> [u8; 20] {
    let d = oracle_digest(0, 1, 1, 0, 1);
    OracleSig::sign(&oracle_key(), &d).recover(&d).unwrap()
}

/// A signed market-0 transcript at $100k, published at `now`.
fn oracle(now: u64) -> OracleTranscript {
    oracle_at(INDEX, now)
}

/// A signed market-0 transcript at `price` (price-scaled), published at `now`.
fn oracle_at(price: i128, now: u64) -> OracleTranscript {
    let confidence = price / 10_000; // 0.01%
    let d = oracle_digest(0, price, now, confidence, price);
    OracleTranscript {
        price,
        publish_time_ms: now,
        confidence,
        backup_twap: price,
        signature: OracleSig::sign(&oracle_key(), &d),
    }
}

fn state() -> DefaultState {
    let mut m = Market::conservative(0);
    m.oracle_pubkey = oracle_addr();
    let mut s = DefaultState::new(20);
    s.add_market(m);
    s
}

/// Deposit `amount` for owner `sk` and move it into its market-0 position.
fn fund(s: &mut DefaultState, sk: u8, amount: i128) {
    let owner = owner_of(sk);
    let blind = [sk; 32];
    let cm = Note::new(owner, 0, amount, blind).commitment::<Keccak256>();
    let id = s.consumed_deposit_count;
    s.apply_batch(&[
        BatchOp::Deposit {
            owner,
            asset_id: 0,
            amount,
            blinding: blind,
            from: [sk; 20],
            deposit_id: id,
            deposit_blind: [0xDB; 32],
        },
        BatchOp::FundPosition {
            owner,
            market_id: 0,
            note_commitment: cm,
            spend_key: [sk; 32],
        },
    ])
    .unwrap();
}

/// `taker` takes `side` for 1 BTC at $100k against `maker`.
fn fill(taker: u8, maker: u8, side: Side, now: u64) -> BatchOp {
    BatchOp::Fill {
        taker: owner_of(taker),
        maker: owner_of(maker),
        market_id: 0,
        taker_side: side,
        size: SIZE_SCALE,
        price: INDEX,
        oracle: oracle(now),
        now_ms: now,
    }
}

/// A funding tick at `mark`.
fn tick(mark: i128, now: u64) -> BatchOp {
    BatchOp::AccrueFunding {
        market_id: 0,
        mark,
        oracle: oracle(now),
        now_ms: now,
    }
}

/// A +1% mark: the observed rate is the clamp.
const PREMIUM: i128 = INDEX * 101 / 100;

/// Apply `op` as a one-op batch (conservation is checked after it).
fn apply(s: &mut DefaultState, op: BatchOp) {
    s.apply_batch(&[op]).expect("op applies");
}

fn pos(s: &DefaultState, sk: u8) -> Position {
    *s.position(&owner_of(sk), 0).expect("position")
}

fn index(s: &DefaultState) -> i128 {
    s.funding[&0].cumulative_index
}

/// Index units one BTC owes for `dt` ms at `rate`, carrying `remainder`.
fn span(rate: i128, dt: u64, remainder: i128) -> i128 {
    (remainder + INDEX_QUOTE * rate * dt as i128) / FUNDING_DIVISOR
}

/// A market whose stored rate is the clamp from `T0`, with V (owner 1) long
/// 1 BTC against P (owner 2) from `T0`, and A (3) and B (4) funded but flat.
fn long_held_at_max_rate() -> DefaultState {
    let mut s = state();
    for sk in 1..=4 {
        fund(&mut s, sk, usd(50_000));
    }
    apply(&mut s, tick(PREMIUM, T0));
    assert_eq!(index(&s), 0, "a fresh market's first tick charges nothing");
    assert_eq!(s.funding[&0].rate, MAX);
    apply(&mut s, fill(1, 2, Side::Buy, T0));
    s
}

/// A short opened one tick before a premium is first observed, after an hour
/// whose stored rate was zero, owes and collects nothing for that hour. Funding
/// at the premium's rate starts with the span after the tick that observed it,
/// and that span is credited to the short exactly.
#[test]
fn a_position_opened_before_a_premium_is_observed_collects_nothing_for_the_past() {
    let mut s = state();
    for sk in 1..=4 {
        fund(&mut s, sk, usd(50_000));
    }
    // a small premium for an hour before T0
    let small = INDEX + INDEX / 100_000; // 0.001% ⇒ rate 10
    apply(&mut s, tick(small, T0 - FUNDING_INTERVAL_MS));
    apply(&mut s, tick(small, T0));
    let small_rate = s.funding[&0].rate;
    assert_eq!(small_rate, 10);
    assert_eq!(index(&s), span(10, FUNDING_INTERVAL_MS, 0));
    // V long against P at T0
    apply(&mut s, fill(1, 2, Side::Buy, T0));
    let v_entry = pos(&s, 1).funding_entry;
    assert_eq!(v_entry, index(&s));

    // ~59 minutes of ticks with mark == index: the first commits 700ms at the
    // small rate and stores a zero rate; every later one changes nothing
    let mut t = T0 + 700;
    apply(&mut s, tick(INDEX, t));
    assert_eq!(s.funding[&0].rate, 0);
    let idle_root = s.state_root();
    let idle_funding = s.funding[&0];
    for _ in 0..5_049 {
        t += 700;
        s.apply_op(&tick(INDEX, t)).unwrap();
    }
    assert_eq!(s.state_root(), idle_root, "idle ticks are root-neutral");
    assert_eq!(s.funding[&0], idle_funding);
    assert!(t - T0 > 58 * MINUTE);

    // A opens a 1 BTC short (as maker), then the next tick observes +1%
    t += 700;
    apply(&mut s, fill(4, 3, Side::Buy, t));
    let a = pos(&s, 3);
    assert_eq!(a.funding_entry, index(&s));
    t += 700;
    apply(&mut s, tick(PREMIUM, t));
    assert_eq!(s.funding[&0].rate, MAX);
    assert_eq!(
        a.funding_owed(index(&s)),
        Some(0),
        "the span before the premium was observed is charged at the zero rate"
    );
    // V paid for the hour exactly what the rate in force charged: 700ms at the
    // small rate
    let v_owed = pos(&s, 1).funding_owed(index(&s)).unwrap();
    assert_eq!(v_owed, span(small_rate, 700, 0));
    assert!(v_owed < usd(1) / 1_000);

    // the next 700ms span is charged at the premium's rate, and A collects it
    let before = s.funding[&0];
    t += 700;
    apply(&mut s, tick(PREMIUM, t));
    let delta = index(&s) - before.cumulative_index;
    assert_eq!(delta, span(MAX, 700, before.remainder));
    assert_eq!(a.funding_owed(index(&s)), Some(-delta));
    assert!(delta < usd(1) / 100, "700ms at the clamp is below one cent");
    assert!(s.conservation_holds());
}

/// After a pause the sequencer settles fills before the window's funding tick.
/// The position that closes at reopen pays the whole pause at the stored rate;
/// the position that opens at reopen owes nothing for it.
#[test]
fn a_pause_is_charged_to_the_positions_open_during_it() {
    let mut s = long_held_at_max_rate();
    let t1 = T0 + 30 * MINUTE;
    let v_before = pos(&s, 1).collateral;
    let p_before = pos(&s, 2).collateral;
    // V closes against P, A opens long against B, then the funding tick
    s.apply_batch(&[
        fill(2, 1, Side::Buy, t1),
        fill(3, 4, Side::Buy, t1),
        tick(INDEX, t1),
    ])
    .unwrap();
    let pause = span(MAX, 30 * MINUTE, 0);
    assert_eq!(pause, usd(25), "30 minutes at the clamp on $100k");
    assert_eq!(pos(&s, 1).size, 0);
    assert_eq!(
        pos(&s, 1).collateral,
        v_before - pause,
        "the closing long pays"
    );
    assert_eq!(pos(&s, 2).size, 0);
    assert_eq!(
        pos(&s, 2).collateral,
        p_before + pause,
        "the closing short collects"
    );
    let a = pos(&s, 3);
    assert_eq!(a.funding_entry, index(&s));
    assert_eq!(
        a.funding_owed(index(&s)),
        Some(0),
        "the opener owes nothing"
    );
    assert_eq!(pos(&s, 4).funding_owed(index(&s)), Some(0));
    assert!(s.conservation_holds());
}

/// A gap is charged for at most one funding interval, however long it is.
#[test]
fn a_pause_is_charged_for_at_most_one_interval() {
    for pause_ms in [
        FUNDING_INTERVAL_MS,
        3 * FUNDING_INTERVAL_MS,
        30 * FUNDING_INTERVAL_MS,
    ] {
        let mut s = long_held_at_max_rate();
        let v_before = pos(&s, 1).collateral;
        apply(&mut s, fill(2, 1, Side::Buy, T0 + pause_ms));
        assert_eq!(
            pos(&s, 1).collateral,
            v_before - usd(50),
            "one interval at the clamp on $100k, pause {pause_ms} ms"
        );
        assert_eq!(s.funding[&0].last_update_ms, T0 + pause_ms);
    }
}

/// Fills, unbinds and the funding tick at one timestamp give the same post-state
/// in every order.
#[test]
fn op_order_within_one_timestamp_does_not_change_the_post_state() {
    let t1 = T0 + 40 * MINUTE;
    let ops = [
        fill(3, 4, Side::Buy, t1),
        BatchOp::Unbind {
            owner: owner_of(1),
            market_id: 0,
            amount: usd(1_000),
            blinding: [0x5E; 32],
            oracle: oracle(t1),
            now_ms: t1,
        },
        tick(INDEX - INDEX / 200, t1),
    ];
    let orders = [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ];
    let mut roots = Vec::new();
    for order in orders {
        let mut s = long_held_at_max_rate();
        let batch: Vec<BatchOp> = order.iter().map(|&i| ops[i].clone()).collect();
        s.apply_batch(&batch).unwrap();
        assert_eq!(s.funding[&0].rate, -MAX);
        roots.push(s.state_root());
    }
    assert!(roots.windows(2).all(|w| w[0] == w[1]), "{roots:?}");
}

/// Liquidation reads the index settled up to its own time: a position that the
/// stored rate has pushed below maintenance margin during a pause is
/// liquidatable at reopen, before any funding tick runs.
#[test]
fn liquidation_reads_the_index_settled_to_its_own_time() {
    let base = || {
        let mut s = state();
        let (v, p) = (owner_of(1), owner_of(2));
        apply(&mut s, tick(PREMIUM, T0));
        let idx = index(&s);
        // V long 1 BTC from $100k with maintenance margin + $30; P the other side
        for (owner, size, collateral) in
            [(v, SIZE_SCALE, usd(5_030)), (p, -SIZE_SCALE, usd(50_000))]
        {
            s.positions.insert(
                (owner, 0),
                Position {
                    owner,
                    market_id: 0,
                    size,
                    entry_price: INDEX,
                    collateral,
                    funding_entry: idx,
                },
            );
        }
        s.external_in = s.internal_value().unwrap();
        assert!(s.conservation_holds());
        let m = s.markets[&0];
        assert_eq!(
            s.position(&v, 0).unwrap().maintenance_required(&m, INDEX),
            Some(usd(5_000))
        );
        s
    };
    let liquidate = |now: u64| BatchOp::Liquidate {
        owner: owner_of(1),
        market_id: 0,
        oracle: oracle(now),
        now_ms: now,
    };

    // 30 minutes owe $25: still above maintenance, refused, nothing changes
    let mut s = base();
    let before = s.state_root();
    assert_eq!(
        s.apply_batch(&[liquidate(T0 + 30 * MINUTE)]),
        Err(EngineError::NotLiquidatable)
    );
    assert_eq!(s.state_root(), before);
    assert_eq!(s.funding[&0].last_update_ms, T0);

    // an hour owes $50: below maintenance, liquidated with no tick in between
    let mut s = base();
    s.apply_batch(&[liquidate(T0 + 60 * MINUTE)]).unwrap();
    assert!(s.position(&owner_of(1), 0).is_none_or(|p| p.size == 0));
    assert_eq!(index(&s), span(MAX, FUNDING_INTERVAL_MS, 0));
    assert_eq!(s.funding[&0].last_update_ms, T0 + 60 * MINUTE);
    assert!(s.conservation_holds());
}

/// The Unbind margin check reads the index settled up to its own time, so the
/// funding a pause charged counts against the collateral that may leave. A long
/// funded with its initial margin plus $100 owes $25 for 30 minutes at the clamp:
/// it may then unbind $75, which leaves its equity exactly at initial margin,
/// but not $90.
#[test]
fn an_unbind_after_a_pause_keeps_initial_margin_net_of_the_pause_funding() {
    let mut s = state();
    fund(&mut s, 1, usd(10_100));
    fund(&mut s, 2, usd(50_000));
    apply(&mut s, tick(PREMIUM, T0));
    assert_eq!(s.funding[&0].rate, MAX);
    apply(&mut s, fill(1, 2, Side::Buy, T0));
    let m = s.markets[&0];
    assert_eq!(pos(&s, 1).initial_required(&m, INDEX), Some(usd(10_000)));

    let t1 = T0 + 30 * MINUTE;
    let pause = span(MAX, 30 * MINUTE, 0);
    assert_eq!(pause, usd(25));
    assert_eq!(s.funding[&0].index_at(INDEX, t1), pause);
    let unbind = |amount: i128| BatchOp::Unbind {
        owner: owner_of(1),
        market_id: 0,
        amount,
        blinding: [0x7A; 32],
        oracle: oracle(t1),
        now_ms: t1,
    };

    // $90 would leave $10,100 − $90 − $25 = $9,985 of equity: refused, and
    // nothing changes, the funding state included
    let funding = s.funding[&0];
    let root = s.state_root();
    assert_eq!(
        s.apply_batch(&[unbind(usd(90))]),
        Err(EngineError::Risk {
            source: perp_core::RiskError::InsufficientMargin,
            leg: None,
        })
    );
    assert_eq!(s.funding[&0], funding);
    assert_eq!(s.state_root(), root);

    // $75 leaves exactly the initial margin
    apply(&mut s, unbind(usd(75)));
    assert_eq!(index(&s), pause);
    assert_eq!(s.funding[&0].last_update_ms, t1);
    let long = pos(&s, 1);
    assert_eq!(long.collateral, usd(10_025));
    assert_eq!(long.equity(INDEX, index(&s)), Some(usd(10_000)));
    assert_eq!(long.check_initial_margin(&m, INDEX, index(&s)), Ok(()));
    assert!(s.conservation_holds());
}

/// Auto-deleverage sizes each winner's haircut at the index settled up to the
/// liquidation's own time. After a pause at a positive stored rate a long winner
/// owes the pause's funding, which shrinks its headroom above maintenance; the
/// haircut is exactly the clawable amount at the settled index, so the winner
/// ends at maintenance margin, not below it. A later refused liquidation leaves
/// the funding state unchanged.
#[test]
fn auto_deleverage_after_a_pause_sizes_each_haircut_at_the_settled_index() {
    let px = 112_000 * PRICE_SCALE;
    for pause_min in [30u64, 60] {
        let mut s = state();
        apply(&mut s, tick(PREMIUM, T0));
        assert_eq!(s.funding[&0].rate, MAX);
        let (l, w) = (owner_of(1), owner_of(2));
        // L short 1 BTC from $100k with $11k; W long 1 BTC from $109k with $3k;
        // both opened at the current index
        for (owner, size, entry, collateral) in [
            (l, -SIZE_SCALE, 100_000, usd(11_000)),
            (w, SIZE_SCALE, 109_000, usd(3_000)),
        ] {
            s.positions.insert(
                (owner, 0),
                Position {
                    owner,
                    market_id: 0,
                    size,
                    entry_price: entry * PRICE_SCALE,
                    collateral,
                    funding_entry: 0,
                },
            );
        }
        s.external_in = s.internal_value().unwrap();
        assert!(s.conservation_holds());
        let m = s.markets[&0];

        let now = T0 + pause_min * MINUTE;
        let stored = s.funding[&0].cumulative_index;
        let settled = s.funding[&0].index_at(px, now);
        // $112k for the pause at the clamp: $28 per BTC for 30 minutes, $56 for 60
        assert_eq!(settled - stored, usd(28) * pause_min as i128 / 30);
        let winner = *s.position(&w, 0).unwrap();
        assert!(!winner.is_liquidatable(&m, px, settled));
        assert!(s.position(&l, 0).unwrap().is_liquidatable(&m, px, settled));
        let clawable = winner.adl_clawable(&m, px, settled).unwrap();
        assert_eq!(
            clawable,
            usd(400) - (settled - stored),
            "the headroom above maintenance binds"
        );
        assert!(
            winner.adl_clawable(&m, px, stored).unwrap() > clawable,
            "the index before the pause would leave a larger clawable amount"
        );

        let haircuts = s.liquidate(&l, 0, &oracle_at(px, now), now).unwrap();
        assert_eq!(index(&s), settled);
        assert_eq!(s.funding[&0].last_update_ms, now);
        assert_eq!(haircuts.len(), 1, "pause {pause_min} min");
        assert_eq!(haircuts[0].owner, w);
        assert_eq!(haircuts[0].clawed, clawable, "pause {pause_min} min");
        let after = *s.position(&w, 0).unwrap();
        assert_eq!(after.collateral, winner.collateral - clawable);
        assert_eq!(
            after.equity(px, settled),
            after.maintenance_required(&m, px),
            "the winner ends at maintenance margin"
        );
        assert!(!after.is_liquidatable(&m, px, settled));
        assert!(s.conservation_holds());

        // after a rise to $113k the winner is not liquidatable: the refusal
        // leaves the funding state unchanged although the span moved on
        let funding = s.funding[&0];
        let root = s.state_root();
        let later = now + 10_000;
        let up = 113_000 * PRICE_SCALE;
        assert_ne!(funding.index_at(up, later), funding.cumulative_index);
        assert_eq!(
            s.apply_batch(&[BatchOp::Liquidate {
                owner: w,
                market_id: 0,
                oracle: oracle_at(up, later),
                now_ms: later,
            }]),
            Err(EngineError::NotLiquidatable)
        );
        assert_eq!(s.funding[&0], funding);
        assert_eq!(s.state_root(), root);
    }
}

/// A refused fill or unbind leaves the market's funding state unchanged, even
/// though it settled the open span on its staged copy.
#[test]
fn a_refused_op_leaves_the_funding_state_unchanged() {
    let mut s = long_held_at_max_rate();
    let funding = s.funding[&0];
    let root = s.state_root();
    let t1 = T0 + 20 * MINUTE;
    // owner 9 has no collateral: opening fails initial margin
    let refused_fill = BatchOp::Fill {
        taker: owner_of(9),
        maker: owner_of(4),
        market_id: 0,
        taker_side: Side::Buy,
        size: SIZE_SCALE,
        price: INDEX,
        oracle: oracle(t1),
        now_ms: t1,
    };
    assert!(matches!(
        s.apply_batch(&[refused_fill]),
        Err(EngineError::Risk { .. })
    ));
    // V cannot unbind more than its collateral
    let refused_unbind = BatchOp::Unbind {
        owner: owner_of(1),
        market_id: 0,
        amount: usd(60_000),
        blinding: [0x6E; 32],
        oracle: oracle(t1),
        now_ms: t1,
    };
    assert!(matches!(
        s.apply_batch(&[refused_unbind]),
        Err(EngineError::Risk { .. })
    ));
    assert_eq!(s.funding[&0], funding);
    assert_eq!(s.state_root(), root);
}

/// A zero rate observed on a fresh market changes nothing; the first non-zero
/// observation only stores the rate and starts the span.
#[test]
fn a_fresh_market_charges_nothing_until_a_rate_is_stored() {
    let mut s = state();
    let genesis = s.state_root();
    for k in 0..10 {
        s.apply_op(&tick(INDEX, T0 + k * 700)).unwrap();
    }
    assert_eq!(s.state_root(), genesis);
    apply(&mut s, tick(PREMIUM, T0 + 7_000));
    let f = s.funding[&0];
    assert_eq!((f.cumulative_index, f.remainder), (0, 0));
    assert_eq!((f.rate, f.last_update_ms), (MAX, T0 + 7_000));
}

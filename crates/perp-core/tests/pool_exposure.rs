//! The clearing pool never carries open exposure, funding is paid only out of what
//! the paying side owes, the protocol never pays out more than came in, and a
//! position keeps its initial margin in collateral (audit 2026-11-16, PC-1 and PC-2).
//!
//! * `Liquidate` closes the liquidated position and, at the same price, the opposite
//!   side by the same size, pro rata by size. Per market the sizes of all positions
//!   keep summing to zero, so the clearing pool (`vault_pool`) is never the
//!   counterparty to open interest. A pool exposure left by an older state only
//!   shrinks.
//! * The gain a counterparty realizes in that close stays within reach of the
//!   bad-debt waterfall (insurance, treasury, auto-deleverage), and a counterparty
//!   that the close leaves flat and underwater joins the same waterfall.
//! * `AccrueFunding` stores a zero rate while the receiving side holds more open
//!   interest than the paying side.
//! * A withdrawal that would take `external_out` above `external_in` is refused.
//! * `Unbind` from an open position keeps the initial margin in collateral, not in
//!   unrealized gain, so a profitable position cannot empty its collateral.

use k256::ecdsa::SigningKey;
use perp_core::engine::BatchOp;
use perp_core::fixed::{PRICE_SCALE, QUOTE_SCALE, SIZE_SCALE};
use perp_core::funding::MAX_FUNDING_RATE_PER_INTERVAL;
use perp_core::hash::Keccak256;
use perp_core::note::{owner_from_spend_key, PubKey};
use perp_core::oracle::{oracle_digest, OracleSig, OracleTranscript};
use perp_core::position::Position;
use perp_core::state::Mode;
use perp_core::{DefaultState, EngineError, Market, Note, RiskError};

const TREE_DEPTH: u8 = 20;
const T0: u64 = 1_700_000_000_000;
const HOUR: u64 = 3_600_000;

fn usd(x: i128) -> i128 {
    x * QUOTE_SCALE
}

fn btc(tenths: i128) -> i128 {
    tenths * SIZE_SCALE / 10
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

/// A signed market-0 transcript at `price_usd`, published at `now`.
fn oracle(price_usd: i128, now: u64) -> OracleTranscript {
    let price = price_usd * PRICE_SCALE;
    let confidence = price / 1_000; // 0.1%
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
    let mut s = DefaultState::new(TREE_DEPTH);
    s.add_market(m);
    s
}

/// Place a market-0 position directly: `size` is size-scaled, `entry_usd` in whole
/// dollars, `collateral` quote-scaled, opened at funding index 0.
fn put(s: &mut DefaultState, owner: PubKey, size: i128, entry_usd: i128, collateral: i128) {
    s.positions.insert(
        (owner, 0),
        Position {
            owner,
            market_id: 0,
            size,
            entry_price: entry_usd * PRICE_SCALE,
            collateral,
            funding_entry: 0,
        },
    );
}

/// Make the conservation identity hold for a directly assembled state.
fn balance(s: &mut DefaultState) {
    s.external_out = 0;
    s.external_in = s.internal_value().unwrap();
    assert!(s.conservation_holds());
}

/// The sum of every market-0 position's size: the negation of the clearing
/// pool's implicit position.
fn net_size(s: &DefaultState) -> i128 {
    s.positions
        .iter()
        .filter(|((_, m), _)| *m == 0)
        .map(|(_, p)| p.size)
        .sum()
}

fn size_of(s: &DefaultState, owner: &PubKey) -> i128 {
    s.position(owner, 0).map_or(0, |p| p.size)
}

fn collateral_of(s: &DefaultState, owner: &PubKey) -> i128 {
    s.position(owner, 0).map_or(0, |p| p.collateral)
}

fn liquidate(s: &mut DefaultState, owner: &PubKey, price_usd: i128) -> Vec<(PubKey, i128)> {
    s.liquidate(owner, 0, &oracle(price_usd, T0), T0)
        .expect("liquidation")
        .into_iter()
        .map(|h| (h.owner, h.clawed))
        .collect()
}

// --- PC-1: the liquidation closes the opposite side ------------------------------

/// L and M long 1 BTC each, W1 short 1.2 and W2 short 0.8, all from $100k with
/// $10k. At $94k L is liquidatable: equity $4k against $4.7k of maintenance.
fn balanced_book() -> (DefaultState, [PubKey; 4]) {
    let mut s = state();
    let (l, m, w1, w2) = (owner_of(1), owner_of(2), owner_of(3), owner_of(4));
    put(&mut s, l, btc(10), 100_000, usd(10_000));
    put(&mut s, m, btc(10), 100_000, usd(10_000));
    put(&mut s, w1, -btc(12), 100_000, usd(10_000));
    put(&mut s, w2, -btc(8), 100_000, usd(10_000));
    balance(&mut s);
    assert_eq!(net_size(&s), 0);
    (s, [l, m, w1, w2])
}

#[test]
fn audit_1116_pc1_liquidation_closes_the_opposite_side_pro_rata_at_its_price() {
    let (mut s, [l, m, w1, w2]) = balanced_book();
    let m_before = *s.position(&m, 0).unwrap();
    let value = s.internal_value().unwrap();

    let haircuts = liquidate(&mut s, &l, 94_000);

    assert!(haircuts.is_empty(), "the close left no bad debt");
    // L closes at $94k: −$6k realized, then the 1% penalty of $940.
    assert_eq!(collateral_of(&s, &l), usd(10_000 - 6_000 - 940));
    assert_eq!(size_of(&s, &l), 0);
    // The shorts give up 1 BTC between them, 0.6 and 0.4, at the same price,
    // and realize their $6,000 per BTC gain.
    assert_eq!(size_of(&s, &w1), -btc(6));
    assert_eq!(size_of(&s, &w2), -btc(4));
    assert_eq!(collateral_of(&s, &w1), usd(10_000 + 3_600));
    assert_eq!(collateral_of(&s, &w2), usd(10_000 + 2_400));
    assert_eq!(
        s.position(&m, 0),
        Some(&m_before),
        "the other long is untouched"
    );
    // The pool carries no exposure, and the realized results cancelled in it.
    assert_eq!(net_size(&s), 0, "the clearing pool holds no position");
    assert_eq!(s.vault_pool, 0);
    assert_eq!(s.insurance_fund, usd(940));
    assert_eq!(s.mode, Mode::Normal);
    assert_eq!(s.internal_value(), Some(value));
    assert!(s.conservation_holds());
}

/// A gap past L's bankruptcy price: W, the only short, is closed with L, and the
/// gain it realizes in that close still covers L's shortfall through ADL.
#[test]
fn audit_1116_pc1_a_counterparty_closed_by_the_liquidation_still_covers_the_shortfall() {
    let mut s = state();
    let (l, w) = (owner_of(1), owner_of(2));
    put(&mut s, l, btc(10), 100_000, usd(10_000));
    put(&mut s, w, -btc(10), 100_000, usd(10_000));
    balance(&mut s);

    let haircuts = liquidate(&mut s, &l, 85_000);

    // L ends $5k underwater; with no insurance or treasury, W's $15k gain covers it.
    assert_eq!(haircuts, vec![(w, usd(5_000))]);
    assert!(s.position(&l, 0).is_none(), "the debt is covered in full");
    assert_eq!(size_of(&s, &w), 0, "W is closed with L");
    assert_eq!(collateral_of(&s, &w), usd(10_000 + 15_000 - 5_000));
    assert_eq!(net_size(&s), 0);
    assert_eq!(s.vault_pool, 0);
    assert_eq!(s.mode, Mode::Normal);
    assert!(s.conservation_holds());
}

/// A counterparty that the close leaves flat and underwater adds its debt to the
/// shortfall the waterfall covers; what is left stays parked and trips close-only.
#[test]
fn audit_1116_pc1_an_underwater_counterparty_joins_the_waterfall() {
    for (insurance, l_parked, w_parked, mode) in [
        (10_000, 0, 0, Mode::Normal),
        (6_000, 0, 1_000, Mode::CloseOnly),
        (4_000, 1_000, 2_000, Mode::CloseOnly),
    ] {
        let mut s = state();
        let (l, w) = (owner_of(1), owner_of(2));
        // At $85k: L (long from $100k) is $5k under water, W (short from $80k) $2k.
        put(&mut s, l, btc(10), 100_000, usd(10_000));
        put(&mut s, w, -btc(10), 80_000, usd(3_000));
        s.insurance_fund = usd(insurance);
        balance(&mut s);

        let haircuts = liquidate(&mut s, &l, 85_000);

        assert!(haircuts.is_empty(), "nobody has a gain to give");
        assert_eq!(size_of(&s, &w), 0, "W is closed with L");
        assert_eq!(
            collateral_of(&s, &l),
            -usd(l_parked),
            "insurance {insurance}"
        );
        assert_eq!(
            collateral_of(&s, &w),
            -usd(w_parked),
            "insurance {insurance}"
        );
        assert_eq!(
            s.insurance_fund,
            usd((insurance - 7_000).max(0)),
            "insurance {insurance}"
        );
        assert_eq!(s.mode, mode, "insurance {insurance}");
        assert_eq!(net_size(&s), 0);
        assert!(s.conservation_holds());
    }
}

/// Round-1 review: a counterparty that was itself liquidatable left the close
/// without the liquidation penalty, so a trader could exit an underwater position
/// penalty-free whenever an opposite liquidation hit first, and the insurance fund
/// lost that income. It pays the penalty on the size the close takes, out of its
/// positive collateral, as a liquidation of that size would have charged it.
#[test]
fn audit_1116_pc1_a_liquidatable_counterparty_pays_the_penalty_on_what_the_close_takes() {
    // At $94k both are under maintenance ($4.7k for 1 BTC): L (long from $100k)
    // has $4k of equity and W (short from $90k) $2k.
    let mut s = state();
    let (l, w, k) = (owner_of(1), owner_of(2), owner_of(3));
    put(&mut s, l, btc(10), 100_000, usd(10_000));
    put(&mut s, w, -btc(10), 90_000, usd(6_000));
    balance(&mut s);
    let value = s.internal_value().unwrap();

    let haircuts = liquidate(&mut s, &l, 94_000);

    assert!(haircuts.is_empty());
    // L: −$6k realized, then 1% of $94k.
    assert_eq!(collateral_of(&s, &l), usd(10_000 - 6_000 - 940));
    // W is closed with L: −$4k realized, then the same 1% of the $94k it closed.
    assert_eq!(size_of(&s, &w), 0);
    assert_eq!(collateral_of(&s, &w), usd(6_000 - 4_000 - 940));
    assert_eq!(s.insurance_fund, usd(940 + 940));
    assert_eq!(s.internal_value(), Some(value));
    assert!(s.conservation_holds());

    // A partial close charges the closed part; the rest is liquidated on its own
    // and pays for itself, so the total is what one liquidation would charge.
    let mut s = state();
    put(&mut s, l, btc(5), 100_000, usd(5_000));
    put(&mut s, k, btc(5), 90_000, usd(10_000));
    put(&mut s, w, -btc(10), 90_000, usd(6_000));
    balance(&mut s);
    liquidate(&mut s, &l, 94_000);
    assert_eq!(size_of(&s, &w), -btc(5));
    assert_eq!(collateral_of(&s, &w), usd(6_000 - 2_000 - 470));
    assert_eq!(s.insurance_fund, usd(470 + 470));
    liquidate(&mut s, &w, 94_000);
    assert_eq!(s.insurance_fund, usd(470 + 470 + 470));
    assert_eq!(net_size(&s), 0);
    assert!(s.conservation_holds());

    // A healthy counterparty pays nothing for being closed.
    let (mut s, [l, _, w1, w2]) = balanced_book();
    liquidate(&mut s, &l, 94_000);
    assert_eq!(collateral_of(&s, &w1), usd(10_000 + 3_600));
    assert_eq!(collateral_of(&s, &w2), usd(10_000 + 2_400));
    assert_eq!(s.insurance_fund, usd(940));
}

/// A state written before this rule may already hold a pool exposure. A
/// liquidation never grows it: the pool takes only the part of the close that
/// reduces its own position, and the opposite side takes the rest.
#[test]
fn audit_1116_pc1_a_legacy_pool_exposure_only_shrinks() {
    // Pool implicitly short 0.6 BTC (net +0.6): L's long closes 0.6 against the
    // pool and 0.4 against W.
    let mut s = state();
    let (l, w, k) = (owner_of(1), owner_of(2), owner_of(3));
    put(&mut s, l, btc(10), 100_000, usd(10_000));
    put(&mut s, w, -btc(4), 100_000, usd(10_000));
    balance(&mut s);
    liquidate(&mut s, &l, 94_000);
    assert_eq!(size_of(&s, &w), 0);
    assert_eq!(net_size(&s), 0, "the pool's own short is closed out");
    assert!(s.conservation_holds());

    // Pool implicitly long 1 BTC (net −1): L's long cannot reduce it, so the whole
    // close goes to the shorts, pro rata, and the exposure stays at 1 BTC.
    let mut s = state();
    put(&mut s, l, btc(5), 100_000, usd(5_000));
    put(&mut s, w, -btc(10), 100_000, usd(10_000));
    put(&mut s, k, -btc(5), 100_000, usd(10_000));
    balance(&mut s);
    liquidate(&mut s, &l, 94_000);
    let (w_take, k_take) = (size_of(&s, &w) + btc(10), size_of(&s, &k) + btc(5));
    assert_eq!(w_take + k_take, btc(5), "the shorts close L's whole size");
    assert!((w_take - 2 * k_take).abs() <= 2, "pro rata by size");
    assert_eq!(net_size(&s), -btc(10), "the exposure did not grow");
    assert!(s.conservation_holds());
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Uniform in `lo..=hi`.
    fn range(&mut self, lo: i128, hi: i128) -> i128 {
        lo + (self.next() % (hi - lo + 1) as u64) as i128
    }
}

/// Random balanced books: every liquidation keeps the market's sizes summing to
/// zero, closes exactly the liquidated size on the other side without flipping
/// anyone, touches no same-side position's size, and conserves value.
#[test]
fn audit_1116_pc1_no_liquidation_leaves_the_pool_with_a_position() {
    let mut rng = Rng(0x0116_0000_0000_0001);
    let mut liquidated = 0;
    for case in 0..800 {
        let mut s = state();
        let n = rng.range(2, 7) as u8;
        let mut sizes: Vec<i128> = (0..n)
            .map(|_| {
                let size = rng.range(1, 30) * SIZE_SCALE / 10;
                if rng.next().is_multiple_of(2) {
                    size
                } else {
                    -size
                }
            })
            .collect();
        // the last position balances the book
        let rest: i128 = sizes[..sizes.len() - 1].iter().sum();
        if rest == 0 {
            continue;
        }
        *sizes.last_mut().unwrap() = -rest;
        for (i, size) in sizes.iter().enumerate() {
            put(
                &mut s,
                owner_of(i as u8 + 1),
                *size,
                rng.range(90_000, 110_000),
                usd(rng.range(500, 20_000)),
            );
        }
        s.insurance_fund = usd(rng.range(0, 3_000));
        balance(&mut s);
        let price = rng.range(80_000, 120_000);
        let before = s.clone();
        for i in 0..n {
            let owner = owner_of(i + 1);
            let Some(p) = s.position(&owner, 0).copied() else {
                continue;
            };
            let pre = s.clone();
            if s.liquidate(&owner, 0, &oracle(price, T0), T0).is_err() {
                assert_eq!(s.state_root(), pre.state_root(), "case {case}");
                continue;
            }
            liquidated += 1;
            assert_eq!(net_size(&s), 0, "case {case}");
            assert!(s.conservation_holds(), "case {case}");
            let mut closed = 0;
            for (o, q) in pre.positions.iter().filter(|((o, _), _)| *o != owner) {
                let after = size_of(&s, &o.0);
                if q.size.signum() == p.size.signum() || q.size == 0 {
                    assert_eq!(after, q.size, "same side untouched ({case})");
                } else {
                    assert!(after.signum() != -q.size.signum(), "no flip ({case})");
                    assert!(after.abs() <= q.size.abs(), "only reduced ({case})");
                    closed += q.size.abs() - after.abs();
                }
            }
            assert_eq!(closed, p.size.abs(), "case {case}");
        }
        assert_eq!(
            s.internal_value(),
            before.internal_value(),
            "no value created ({case})"
        );
    }
    assert!(liquidated > 300, "liquidated {liquidated}");
}

// --- PC-1: funding is paid only out of what the paying side owes -----------------

/// Two funding ticks an hour apart at `mark_usd` against a $100k index.
fn two_ticks(s: &mut DefaultState, mark_usd: i128) {
    for t in [T0, T0 + HOUR] {
        s.apply_op(&BatchOp::AccrueFunding {
            market_id: 0,
            mark: mark_usd * PRICE_SCALE,
            oracle: oracle(100_000, t),
            now_ms: t,
        })
        .expect("tick");
    }
}

#[test]
fn audit_1116_pc1_funding_with_one_empty_side_pays_nothing() {
    // Only a short is open (its long was liquidated against the pool before this
    // rule): at a premium the longs would pay, but there are none.
    let mut s = state();
    let w = owner_of(2);
    put(&mut s, w, -btc(10), 100_000, usd(10_000));
    balance(&mut s);
    two_ticks(&mut s, 101_000);
    let f = s.funding[&0];
    assert_eq!(f.rate, 0, "no long pays, so no short is paid");
    assert_eq!(f.cumulative_index, 0);
    assert_eq!(
        s.position(&w, 0).unwrap().funding_owed(f.cumulative_index),
        Some(0)
    );

    // The mirror: only a long, at a discount the shorts would pay.
    let mut s = state();
    let l = owner_of(1);
    put(&mut s, l, btc(10), 100_000, usd(10_000));
    balance(&mut s);
    two_ticks(&mut s, 99_000);
    assert_eq!(s.funding[&0].rate, 0);
    assert_eq!(s.funding[&0].cumulative_index, 0);
}

#[test]
fn audit_1116_pc1_funding_receivers_never_outweigh_the_payers() {
    // Longs 1 BTC, shorts 2 BTC: at a premium the shorts would receive twice what
    // the longs pay, so nothing is charged.
    let mut s = state();
    put(&mut s, owner_of(1), btc(10), 100_000, usd(10_000));
    put(&mut s, owner_of(2), -btc(20), 100_000, usd(20_000));
    balance(&mut s);
    two_ticks(&mut s, 101_000);
    assert_eq!(s.funding[&0].rate, 0);
    assert_eq!(s.funding[&0].cumulative_index, 0);

    // At a discount the shorts pay and the longs receive half of it: charged.
    let mut s = state();
    put(&mut s, owner_of(1), btc(10), 100_000, usd(10_000));
    put(&mut s, owner_of(2), -btc(20), 100_000, usd(20_000));
    balance(&mut s);
    two_ticks(&mut s, 99_000);
    assert_eq!(s.funding[&0].rate, -MAX_FUNDING_RATE_PER_INTERVAL);
    assert!(s.funding[&0].cumulative_index < 0);

    // A balanced book is charged as before, whichever side pays.
    for mark in [101_000, 99_000] {
        let mut s = state();
        put(&mut s, owner_of(1), btc(10), 100_000, usd(10_000));
        put(&mut s, owner_of(2), -btc(10), 100_000, usd(10_000));
        balance(&mut s);
        two_ticks(&mut s, mark);
        assert_ne!(s.funding[&0].cumulative_index, 0, "mark {mark}");
    }
}

/// Round-1 review: the net size a funding tick needs reads every position, so a
/// batch measures each market once and keeps it. A liquidation in the same batch
/// changes it, and the ticks after it must see the new value: replaying the ops
/// one at a time and as one batch gives the same state.
#[test]
fn audit_1116_pc1_a_batch_keeps_the_net_size_a_liquidation_leaves() {
    // A legacy pool short of 0.6 BTC (net +0.6). At $94k, L (long 1 BTC) is
    // liquidatable; the pool takes 0.6 of the close and W and N the other 0.4.
    let mut s = state();
    let (l, m, w, n) = (owner_of(1), owner_of(2), owner_of(3), owner_of(4));
    put(&mut s, l, btc(10), 100_000, usd(10_000));
    put(&mut s, m, btc(5), 100_000, usd(10_000));
    put(&mut s, w, -btc(4), 100_000, usd(10_000));
    put(&mut s, n, -btc(5), 100_000, usd(10_000));
    balance(&mut s);
    assert_eq!(net_size(&s), btc(6));
    // At a discount the shorts would pay the longs, who outweigh them: nothing is
    // charged until the liquidation leaves the book balanced, then it is.
    let tick = |t: u64| BatchOp::AccrueFunding {
        market_id: 0,
        mark: 93_000 * PRICE_SCALE,
        oracle: oracle(94_000, t),
        now_ms: t,
    };
    let ops = [
        tick(T0),
        tick(T0 + HOUR),
        BatchOp::Liquidate {
            owner: l,
            market_id: 0,
            oracle: oracle(94_000, T0 + HOUR),
            now_ms: T0 + HOUR,
        },
        tick(T0 + HOUR),
        tick(T0 + 2 * HOUR),
    ];

    let mut one_by_one = s.clone();
    let mut rates = Vec::new();
    for op in &ops {
        one_by_one.apply_op(op).expect("op");
        rates.push(one_by_one.funding[&0].rate);
    }
    assert_eq!(net_size(&one_by_one), 0);
    assert_eq!(rates[..2], [0, 0], "longs outweigh the paying shorts");
    assert!(rates[3] < 0, "the balanced book is charged: {rates:?}");

    let mut batch = s.clone();
    batch.apply_batch(&ops).expect("batch");
    one_by_one.next_batch_id += 1;
    assert_eq!(batch.funding[&0], one_by_one.funding[&0]);
    assert_eq!(batch.state_root(), one_by_one.state_root());
}

// --- PC-1: no more out than came in ----------------------------------------------

/// `owner_of(5)` holds unspent notes of `amounts`; the clearing pool is $60 short,
/// so the value inside is $60 less than the notes.
fn notes_over_a_short_pool(amounts: &[i128]) -> (DefaultState, Vec<[u8; 32]>) {
    let mut s = state();
    let owner = owner_of(5);
    let mut cms = Vec::new();
    for (i, amount) in amounts.iter().enumerate() {
        let note = Note::new(owner, 0, usd(*amount), [0x50 + i as u8; 32]);
        let cm = note.commitment::<Keccak256>();
        s.tree.append(cm).unwrap();
        s.notes.insert(cm, note);
        cms.push(cm);
    }
    s.vault_pool = -usd(60);
    balance(&mut s);
    (s, cms)
}

fn withdraw(cm: [u8; 32], to: Option<[u8; 20]>, nonce: u64) -> BatchOp {
    BatchOp::Withdraw {
        note_commitment: cm,
        spend_key: [5; 32],
        to,
        nonce,
    }
}

#[test]
fn audit_1116_pc1_a_withdrawal_beyond_external_in_is_refused() {
    // $100 of notes, $40 inside: the $100 note cannot leave.
    let (mut s, cms) = notes_over_a_short_pool(&[100]);
    assert_eq!(s.external_in, usd(40));
    for (to, nonce) in [(Some([0xAB; 20]), 1), (None, 0)] {
        let root = s.state_root();
        assert_eq!(
            s.apply_batch(&[withdraw(cms[0], to, nonce)]),
            Err(EngineError::WithdrawalExceedsDeposits)
        );
        assert_eq!(s.state_root(), root, "nothing changed");
        assert!(s.notes.contains_key(&cms[0]));
    }

    // $40 and $60 notes: the first exactly uses up what came in, the second is
    // refused.
    let (mut s, cms) = notes_over_a_short_pool(&[40, 60]);
    s.apply_batch(&[withdraw(cms[0], Some([0xAB; 20]), 1)])
        .expect("external_out reaches external_in");
    assert_eq!(s.external_out, s.external_in);
    let root = s.state_root();
    assert_eq!(
        s.apply_batch(&[withdraw(cms[1], Some([0xAB; 20]), 2)]),
        Err(EngineError::WithdrawalExceedsDeposits)
    );
    assert_eq!(s.state_root(), root);
}

// --- PC-2: initial margin stays in collateral --------------------------------------

const MARGIN: EngineError = EngineError::Risk {
    source: RiskError::InsufficientMargin,
    leg: None,
};

fn unbind(owner: PubKey, amount: i128, price_usd: i128) -> BatchOp {
    BatchOp::Unbind {
        owner,
        market_id: 0,
        amount,
        blinding: [0x77; 32],
        oracle: oracle(price_usd, T0),
        now_ms: T0,
    }
}

#[test]
fn audit_1116_pc2_a_profitable_position_cannot_unbind_its_collateral_to_zero() {
    // L long 1 BTC from $100k with $10k; at $125k it is $25k up, so its equity
    // ($35k) would clear the $12.5k initial margin with no collateral at all.
    let mut s = state();
    let (l, w) = (owner_of(1), owner_of(2));
    put(&mut s, l, btc(10), 100_000, usd(10_000));
    put(&mut s, w, -btc(10), 100_000, usd(40_000));
    balance(&mut s);
    let m = s.markets[&0];
    let px = 125_000 * PRICE_SCALE;
    let root = s.state_root();

    assert_eq!(s.apply_op(&unbind(l, usd(10_000), 125_000)), Err(MARGIN));
    assert_eq!(s.state_root(), root, "nothing changed");
    assert_eq!(collateral_of(&s, &l), usd(10_000));
    assert!(s.position(&l, 0).unwrap().adl_clawable(&m, px, 0).unwrap() > 0);

    // With $20k it may unbind down to the $12.5k initial margin, not one micro-USD
    // further: the rule the gateway applies to a withdrawal.
    s.positions.get_mut(&(l, 0)).unwrap().collateral = usd(20_000);
    balance(&mut s);
    let root = s.state_root();
    assert_eq!(s.apply_op(&unbind(l, usd(7_500) + 1, 125_000)), Err(MARGIN));
    assert_eq!(s.state_root(), root);
    s.apply_op(&unbind(l, usd(7_500), 125_000))
        .expect("down to the initial margin");
    assert_eq!(collateral_of(&s, &l), usd(12_500));
    assert!(s.position(&l, 0).unwrap().adl_clawable(&m, px, 0).unwrap() > 0);
    assert!(s.conservation_holds());
}

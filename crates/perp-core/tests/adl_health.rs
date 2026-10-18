//! The live bad-debt waterfall and the auto-deleverage (ADL) bound.
//!
//! * A liquidation whose close leaves the position underwater is covered, in
//!   order, by the insurance fund, the treasury, and ADL of the winners in its
//!   market. Whatever is still uncovered stays parked on the closed position and
//!   the system trips to close-only.
//! * ADL takes from each winner at most `max(0, min(P − F, C⁺, E − MM))`
//!   ([`Position::adl_clawable`]): its price gain net of signed funding, never
//!   more than its non-negative collateral, and never more than its headroom
//!   above maintenance margin. So a winner keeps `C ≥ 0` and `E ≥ MM`, no
//!   position becomes liquidatable through ADL, and the haircuts sum to at most
//!   the residual.
//! * Any overflow while planning ADL leaves no haircut at all (fail closed).
//! * One allocator ([`allocate_pro_rata`]) splits a shortfall exactly, for ADL
//!   and for `SettleAll` alike.

use k256::ecdsa::SigningKey;
use perp_core::engine::{allocate_pro_rata, BatchOp};
use perp_core::fixed::{PRICE_SCALE, QUOTE_SCALE, SIZE_SCALE};
use perp_core::hash::Keccak256;
use perp_core::note::{owner_from_spend_key, PubKey};
use perp_core::oracle::{oracle_digest, OracleSig, OracleTranscript};
use perp_core::position::Position;
use perp_core::state::Mode;
use perp_core::{DefaultState, EngineError, Market};
use std::collections::BTreeMap;

const TREE_DEPTH: u8 = 20;
const T0: u64 = 1_700_000_000_000;

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

fn market(s: &DefaultState) -> Market {
    s.markets[&0]
}

/// Place a market-0 position directly: `size` is size-scaled, `entry_usd` in
/// whole dollars, `collateral` and `funding_entry` quote-scaled.
fn put(
    s: &mut DefaultState,
    owner: PubKey,
    size: i128,
    entry_usd: i128,
    collateral: i128,
    funding_entry: i128,
) {
    s.positions.insert(
        (owner, 0),
        Position {
            owner,
            market_id: 0,
            size,
            entry_price: entry_usd * PRICE_SCALE,
            collateral,
            funding_entry,
        },
    );
}

fn set_index(s: &mut DefaultState, index: i128) {
    s.funding.get_mut(&0).unwrap().cumulative_index = index;
}

/// Make the conservation identity hold for a directly assembled state.
fn balance(s: &mut DefaultState) {
    s.external_out = 0;
    s.external_in = s.internal_value().unwrap();
    assert!(s.conservation_holds());
}

fn liquidate(s: &mut DefaultState, owner: &PubKey, price_usd: i128) -> Vec<(PubKey, i128)> {
    s.liquidate(owner, 0, &oracle(price_usd, T0), T0)
        .expect("liquidation")
        .into_iter()
        .map(|h| (h.owner, h.clawed))
        .collect()
}

/// Funding index at which shorts opened at index 0 owe $20,500 per BTC.
const SHORTS_PAY: i128 = -20_500 * QUOTE_SCALE;

/// L long 1 BTC from $100k with $10k, opened at the current index. W short 1 BTC
/// from $100k with $10k, opened at index 0, so it owes $20,500 of funding. X is
/// flat with $30,500, the funding it already collected out of the pool.
fn winner_owing_funding() -> (DefaultState, PubKey, PubKey) {
    let mut s = state();
    let (l, w, x) = (owner_of(1), owner_of(2), owner_of(3));
    set_index(&mut s, SHORTS_PAY);
    put(&mut s, w, -SIZE_SCALE, 100_000, usd(10_000), 0);
    put(&mut s, l, SIZE_SCALE, 100_000, usd(10_000), SHORTS_PAY);
    put(&mut s, x, 0, 0, usd(30_500), SHORTS_PAY);
    s.vault_pool = -usd(20_500);
    balance(&mut s);
    (s, l, w)
}

#[test]
fn a_winner_whose_funding_debt_exceeds_its_price_gain_gives_nothing() {
    let (mut s, l, w) = winner_owing_funding();
    let m = market(&s);
    let px = 85_000 * PRICE_SCALE;
    let w_before = *s.position(&w, 0).unwrap();
    assert_eq!(w_before.equity(px, SHORTS_PAY), Some(usd(4_500)));
    assert_eq!(w_before.maintenance_required(&m, px), Some(usd(4_250)));
    // P = +15,000 but F = +20,500: nothing is gained net of funding.
    assert_eq!(w_before.adl_clawable(&m, px, SHORTS_PAY), Some(0));

    let haircuts = liquidate(&mut s, &l, 85_000);

    assert!(haircuts.is_empty(), "no winner has a net gain to give");
    assert_eq!(s.position(&w, 0), Some(&w_before), "W is untouched");
    assert!(!w_before.is_liquidatable(&m, px, SHORTS_PAY));
    assert_eq!(
        s.position(&l, 0).unwrap().collateral,
        -usd(5_000),
        "the uncovered shortfall stays parked on the closed position"
    );
    assert_eq!(
        s.mode,
        Mode::CloseOnly,
        "an uncovered shortfall trips close-only"
    );
    assert!(s.conservation_holds());

    // W is still healthy at the same price, so it cannot be liquidated next.
    let root = s.state_root();
    assert_eq!(
        s.liquidate(&w, 0, &oracle(85_000, T0), T0),
        Err(EngineError::NotLiquidatable)
    );
    assert_eq!(s.state_root(), root);
}

#[test]
fn the_treasury_covers_the_shortfall_after_insurance_and_before_adl() {
    let (mut s, l, w) = winner_owing_funding();
    s.insurance_fund = usd(2_000);
    s.treasury = usd(8_000);
    balance(&mut s);
    let w_before = *s.position(&w, 0).unwrap();

    let haircuts = liquidate(&mut s, &l, 85_000);

    assert!(haircuts.is_empty());
    assert_eq!(s.insurance_fund, 0, "insurance is drawn first, in full");
    assert_eq!(
        s.treasury,
        usd(5_000),
        "the treasury pays exactly the remaining $3,000"
    );
    assert!(
        s.position(&l, 0).is_none(),
        "covered in full, so the closed entry is removed"
    );
    assert_eq!(s.position(&w, 0), Some(&w_before));
    assert_eq!(
        s.mode,
        Mode::Normal,
        "a covered shortfall keeps the system open"
    );
    assert!(s.conservation_holds());
}

#[test]
fn reserves_are_used_up_in_order_before_close_only() {
    let (mut s, l, w) = winner_owing_funding();
    s.insurance_fund = usd(1_000);
    s.treasury = usd(1_000);
    balance(&mut s);
    let w_before = *s.position(&w, 0).unwrap();

    let haircuts = liquidate(&mut s, &l, 85_000);

    assert!(haircuts.is_empty());
    assert_eq!(s.insurance_fund, 0);
    assert_eq!(s.treasury, 0);
    assert_eq!(s.position(&l, 0).unwrap().collateral, -usd(3_000));
    assert_eq!(s.position(&w, 0), Some(&w_before));
    assert_eq!(s.mode, Mode::CloseOnly);
    assert!(s.conservation_holds());
}

/// After a liquidation the live waterfall could not cover, the wind-down closes
/// the surviving winner at the liquidation's recorded price. W settles its
/// $20,500 of funding and its $15,000 gain at $85k, which leaves the clearing
/// pool at exactly zero; the debt parked on L is then shared by one haircut of
/// W and X. The pool ends at zero, and with a recipient set every reserve
/// does too.
#[test]
fn settlement_after_an_uncovered_shortfall_leaves_every_reserve_at_zero() {
    for (insurance, treasury, parked) in [(0, 0, 5_000), (1_000, 1_000, 3_000)] {
        let (mut s, l, w) = winner_owing_funding();
        s.insurance_fund = usd(insurance);
        s.treasury = usd(treasury);
        balance(&mut s);
        s.set_wind_down_recipient([0x5E; 20]);
        liquidate(&mut s, &l, 85_000);
        assert_eq!(s.mode, Mode::CloseOnly);
        assert_eq!(s.position(&l, 0).unwrap().collateral, -usd(parked));
        assert_eq!(s.funding[&0].last_price, 85_000 * PRICE_SCALE);
        let value = s.internal_value().unwrap();

        let out = s.apply_batch(&[BatchOp::SettleAll]).unwrap();

        assert!(
            out.withdrawals.is_empty(),
            "the reserves went to the shortfall"
        );
        assert_eq!((s.vault_pool, s.insurance_fund, s.treasury), (0, 0, 0));
        assert!(s.position(&l, 0).is_none(), "the parked debt is covered");
        let w_after = *s.position(&w, 0).unwrap();
        assert_eq!(w_after.size, 0);
        // $10k − $20,500 + $15,000 = $4,500 before W's share of the haircut
        assert!(w_after.collateral > 0 && w_after.collateral < usd(4_500));
        assert_eq!(s.positions_collateral(), Some(usd(30_500 + 4_500 - parked)));
        assert_eq!(s.internal_value(), Some(value));
        assert!(s.conservation_holds());
    }
}

/// L long 1 BTC from $100k with $10k. W short 1 BTC from $86k with $4k and no
/// funding: at $85k, P = +$1,000, E = $5,000 and MM = $4,250.
fn thin_winner() -> (DefaultState, PubKey, PubKey) {
    let mut s = state();
    let (l, w) = (owner_of(1), owner_of(2));
    put(&mut s, l, SIZE_SCALE, 100_000, usd(10_000), 0);
    put(&mut s, w, -SIZE_SCALE, 86_000, usd(4_000), 0);
    balance(&mut s);
    (s, l, w)
}

#[test]
fn adl_stops_at_the_maintenance_margin() {
    let (mut s, l, w) = thin_winner();
    let m = market(&s);
    let px = 85_000 * PRICE_SCALE;
    assert_eq!(
        s.position(&w, 0).unwrap().adl_clawable(&m, px, 0),
        Some(usd(750)),
        "min(P 1,000, C 4,000, E − MM 750)"
    );

    let haircuts = liquidate(&mut s, &l, 85_000);

    assert_eq!(haircuts, vec![(w, usd(750))]);
    let w_after = *s.position(&w, 0).unwrap();
    assert_eq!(w_after.collateral, usd(3_250));
    assert_eq!(
        w_after.equity(px, 0),
        w_after.maintenance_required(&m, px),
        "W ends exactly at its maintenance margin"
    );
    assert!(!w_after.is_liquidatable(&m, px, 0));
    assert_eq!(s.position(&l, 0).unwrap().collateral, -usd(4_250));
    assert_eq!(s.mode, Mode::CloseOnly);
    assert!(s.conservation_holds());
    assert_eq!(
        s.liquidate(&w, 0, &oracle(85_000, T0), T0),
        Err(EngineError::NotLiquidatable)
    );
}

#[test]
fn a_funded_treasury_spares_the_winners() {
    let (mut s, l, w) = thin_winner();
    s.treasury = usd(20_000);
    balance(&mut s);
    let w_before = *s.position(&w, 0).unwrap();

    let haircuts = liquidate(&mut s, &l, 85_000);

    assert!(haircuts.is_empty(), "W is not clawed");
    assert_eq!(s.position(&w, 0), Some(&w_before));
    assert_eq!(s.treasury, usd(15_000));
    assert!(s.position(&l, 0).is_none());
    assert_eq!(s.mode, Mode::Normal);
    assert!(s.conservation_holds());
}

#[test]
fn adl_draws_on_the_winners_with_a_net_gain_and_headroom() {
    // As in the funding case, plus Y: short 1 BTC from $100k with $10k, opened at
    // the current index (no funding owed), so its clawable amount is $10,000.
    let (mut s, l, w) = winner_owing_funding();
    let y = owner_of(4);
    put(&mut s, y, -SIZE_SCALE, 100_000, usd(10_000), SHORTS_PAY);
    balance(&mut s);
    let m = market(&s);
    let px = 85_000 * PRICE_SCALE;
    let w_before = *s.position(&w, 0).unwrap();

    let haircuts = liquidate(&mut s, &l, 85_000);

    assert_eq!(haircuts, vec![(y, usd(5_000))], "Y covers the whole $5,000");
    assert_eq!(s.position(&w, 0), Some(&w_before), "W is untouched");
    let y_after = *s.position(&y, 0).unwrap();
    assert_eq!(y_after.collateral, usd(5_000));
    assert_eq!(y_after.equity(px, SHORTS_PAY), Some(usd(20_000)));
    assert!(!y_after.is_liquidatable(&m, px, SHORTS_PAY));
    assert!(s.position(&l, 0).is_none());
    assert_eq!(s.mode, Mode::Normal);
    assert!(s.conservation_holds());
}

#[test]
fn funding_receivable_counts_towards_the_clawable_gain() {
    // W short 1 BTC from $86k with $10k, opened at index 0; the index is now
    // +$3,000, so W is owed $3,000. At $85k: P = +1,000, F = −3,000, P − F = 4,000.
    let mut s = state();
    let (l, w) = (owner_of(1), owner_of(2));
    let index = usd(3_000);
    set_index(&mut s, index);
    put(&mut s, l, SIZE_SCALE, 100_000, usd(10_000), index);
    put(&mut s, w, -SIZE_SCALE, 86_000, usd(10_000), 0);
    balance(&mut s);
    let m = market(&s);
    let px = 85_000 * PRICE_SCALE;

    let haircuts = liquidate(&mut s, &l, 85_000);

    assert_eq!(haircuts, vec![(w, usd(4_000))]);
    let w_after = *s.position(&w, 0).unwrap();
    assert_eq!(w_after.collateral, usd(6_000));
    assert_eq!(w_after.equity(px, index), Some(usd(10_000)));
    assert!(!w_after.is_liquidatable(&m, px, index));
    assert_eq!(s.position(&l, 0).unwrap().collateral, -usd(1_000));
    assert_eq!(s.mode, Mode::CloseOnly);
    assert!(s.conservation_holds());
}

#[test]
fn an_overflowing_winner_leaves_no_haircut_and_trips_close_only() {
    // Y is an ordinary winner worth $10,000 of ADL. Z is open in the same market,
    // but its funding owed overflows, so no ADL plan exists for this market.
    let mut s = state();
    let (l, y, z) = (owner_of(1), owner_of(2), owner_of(3));
    put(&mut s, l, SIZE_SCALE, 100_000, usd(10_000), 0);
    put(&mut s, y, -SIZE_SCALE, 100_000, usd(10_000), 0);
    put(
        &mut s,
        z,
        -SIZE_SCALE / 10,
        100_000,
        usd(1_000),
        i128::MIN / 2,
    );
    balance(&mut s);
    let m = market(&s);
    let px = 85_000 * PRICE_SCALE;
    assert_eq!(s.position(&z, 0).unwrap().adl_clawable(&m, px, 0), None);
    let y_before = *s.position(&y, 0).unwrap();
    let z_before = *s.position(&z, 0).unwrap();

    let out = s
        .apply_batch(&[BatchOp::Liquidate {
            owner: l,
            market_id: 0,
            oracle: oracle(85_000, T0),
            now_ms: T0,
        }])
        .expect("the liquidation itself still applies");

    assert!(out.withdrawals.is_empty());
    assert_eq!(s.position(&y, 0), Some(&y_before), "no haircut is applied");
    assert_eq!(s.position(&z, 0), Some(&z_before));
    assert_eq!(s.position(&l, 0).unwrap().collateral, -usd(5_000));
    assert_eq!(s.mode, Mode::CloseOnly);
    assert!(s.conservation_holds());
}

#[test]
fn allocate_pro_rata_is_exact_and_bounded() {
    assert_eq!(allocate_pro_rata(0, &[]), Some(vec![]));
    assert_eq!(allocate_pro_rata(0, &[0, 0]), Some(vec![0, 0]));
    assert_eq!(allocate_pro_rata(1, &[]), None, "need above the total");
    assert_eq!(allocate_pro_rata(4, &[1, 2]), None, "need above the total");
    assert_eq!(allocate_pro_rata(-1, &[1, 2]), None, "negative need");
    assert_eq!(allocate_pro_rata(1, &[-1, 2]), None, "negative weight");
    assert_eq!(
        allocate_pro_rata(1, &[i128::MAX, 1]),
        None,
        "total overflows"
    );
    assert_eq!(
        allocate_pro_rata(1 << 64, &[1 << 64, 1]),
        None,
        "share product overflows"
    );
    // floor shares 3·1/3 = 1 each, nothing left over
    assert_eq!(allocate_pro_rata(3, &[1, 1, 1]), Some(vec![1, 1, 1]));
    // floor shares 0, 0, 1; the remainder goes out in slice order
    assert_eq!(allocate_pro_rata(2, &[1, 1, 2]), Some(vec![1, 0, 1]));
    // the whole total
    assert_eq!(allocate_pro_rata(9, &[2, 3, 4]), Some(vec![2, 3, 4]));

    let mut rng = Rng(0x5EED_A110_CA7E_0001);
    for _ in 0..20_000 {
        let n = rng.below(10) as usize;
        let scale = [10, 1_000, 1_000_000_000_000][rng.below(3) as usize];
        let weights: Vec<i128> = (0..n).map(|_| rng.below(scale) as i128).collect();
        let total: i128 = weights.iter().sum();
        let need = if total == 0 {
            0
        } else {
            rng.below(total as u64 + 1) as i128
        };
        let takes = allocate_pro_rata(need, &weights).expect("in range");
        assert_eq!(takes.len(), n);
        assert_eq!(takes.iter().sum::<i128>(), need, "the split is exact");
        for (take, w) in takes.iter().zip(&weights) {
            assert!(0 <= *take && take <= w, "each share is within its weight");
            if total > 0 {
                assert!(*take >= need * w / total, "never below the floor share");
            }
        }
        assert_eq!(allocate_pro_rata(total + 1, &weights), None);
    }
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

    fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            0
        } else {
            self.next() % n
        }
    }

    /// Uniform in `lo..=hi`.
    fn range(&mut self, lo: i128, hi: i128) -> i128 {
        lo + self.below((hi - lo + 1) as u64) as i128
    }
}

/// Liquidate one random loser among random winners, losers, flat entries and
/// reserves, and check the waterfall and the ADL bound against values computed
/// from the pre-state alone.
#[test]
fn liquidation_preserves_the_health_of_every_other_position() {
    let mut rng = Rng(0xAD1_0000_0000_0001);
    let mut oracles: BTreeMap<i128, OracleTranscript> = BTreeMap::new();
    let (mut liquidated, mut clawed_any, mut tripped, mut from_treasury) = (0, 0, 0, 0);
    let (mut some_spared, mut zero_clawable) = (0, 0);

    for case in 0..1_500 {
        let mut s = state();
        let m = market(&s);
        let index = usd(rng.range(-6_000, 6_000));
        set_index(&mut s, index);
        let loser_long = rng.below(2) == 0;
        let dir = if loser_long { 1 } else { -1 };
        let l = owner_of(1);
        put(
            &mut s,
            l,
            dir * rng.range(1, 20) * SIZE_SCALE / 10,
            100_000,
            usd(rng.range(500, 15_000)),
            index + usd(rng.range(-2_000, 2_000)),
        );
        for i in 0..rng.range(1, 6) {
            let o = owner_of(2 + i as u8);
            if rng.below(8) == 0 {
                put(&mut s, o, 0, 0, usd(rng.range(1, 5_000)), index);
                continue;
            }
            // mostly the other side of the loser, sometimes the same side
            let side = if rng.below(4) == 0 { dir } else { -dir };
            put(
                &mut s,
                o,
                side * rng.range(1, 20) * SIZE_SCALE / 10,
                rng.range(80_000, 120_000),
                usd(rng.range(-1_000, 20_000)),
                index + usd(rng.range(-8_000, 8_000)),
            );
        }
        s.insurance_fund = if rng.below(3) == 0 {
            0
        } else {
            usd(rng.range(0, 6_000))
        };
        s.treasury = if rng.below(3) == 0 {
            0
        } else {
            usd(rng.range(0, 6_000))
        };
        balance(&mut s);

        let price_usd = if loser_long {
            60_000 + 1_000 * rng.range(0, 40)
        } else {
            100_000 + 1_000 * rng.range(0, 40)
        };
        let px = price_usd * PRICE_SCALE;
        let orc = *oracles
            .entry(price_usd)
            .or_insert_with(|| oracle(price_usd, T0));

        let loser = *s.position(&l, 0).unwrap();
        let others: Vec<(PubKey, Position, bool, i128, i128, i128)> = s
            .positions
            .iter()
            .filter(|((o, _), _)| *o != l)
            .map(|((o, _), p)| {
                (
                    *o,
                    *p,
                    p.is_liquidatable(&m, px, index),
                    p.equity(px, index).unwrap(),
                    p.maintenance_required(&m, px).unwrap(),
                    p.adl_clawable(&m, px, index).unwrap(),
                )
            })
            .collect();
        let (insurance0, treasury0) = (s.insurance_fund, s.treasury);

        let result = s.liquidate(&l, 0, &orc, T0);
        if !loser.is_liquidatable(&m, px, index) {
            assert_eq!(result, Err(EngineError::NotLiquidatable), "case {case}");
            continue;
        }
        liquidated += 1;
        let haircuts = result.unwrap_or_else(|e| panic!("case {case}: {e:?}"));
        assert!(s.conservation_holds(), "case {case}");

        // The close realizes P − F, so the shortfall is the negative part of equity.
        let bad = (-loser.equity(px, index).unwrap()).max(0);
        let c1 = bad.min(insurance0.max(0));
        let c2 = (bad - c1).min(treasury0.max(0));
        let residual = bad - c1 - c2;
        if bad > 0 {
            assert_eq!(s.insurance_fund, insurance0 - c1, "case {case}");
            assert_eq!(s.treasury, treasury0 - c2, "case {case}");
            if c2 > 0 {
                from_treasury += 1;
                assert_eq!(c1, insurance0, "insurance is exhausted first ({case})");
            }
        } else {
            assert_eq!(s.treasury, treasury0, "case {case}");
            assert!(haircuts.is_empty(), "case {case}");
        }

        let total_clawable: i128 = others.iter().map(|o| o.5).sum();
        let clawed: i128 = haircuts.iter().map(|h| h.clawed).sum();
        assert_eq!(clawed, residual.min(total_clawable), "case {case}");
        assert!(clawed <= residual);
        let parked = residual - clawed;
        if clawed > 0 {
            clawed_any += 1;
        }
        if clawed > 0 && haircuts.len() < others.iter().filter(|o| o.1.is_open()).count() {
            some_spared += 1;
        }
        match s.position(&l, 0) {
            None => assert_eq!(parked, 0, "case {case}"),
            Some(p) => {
                assert_eq!(p.size, 0, "case {case}");
                if bad > 0 {
                    assert_eq!(p.collateral, -parked, "case {case}");
                }
            }
        }
        assert_eq!(s.mode == Mode::CloseOnly, parked > 0, "case {case}");
        if parked > 0 {
            tripped += 1;
        }

        let mut seen = Vec::new();
        for h in &haircuts {
            assert!(h.clawed > 0 && h.owner != l, "case {case}");
            assert!(!seen.contains(&h.owner), "one haircut per winner ({case})");
            seen.push(h.owner);
        }
        for (o, before, liq_before, eq_before, mm, clawable) in &others {
            let take = haircuts
                .iter()
                .find(|h| h.owner == *o)
                .map_or(0, |h| h.clawed);
            assert!(take <= *clawable, "case {case}");
            if take == 0 && *clawable == 0 && before.is_open() {
                zero_clawable += 1;
            }
            let after = *s.position(o, 0).unwrap();
            assert_eq!(
                after,
                Position {
                    collateral: before.collateral - take,
                    ..*before
                },
                "only collateral moves, by the haircut ({case})"
            );
            assert_eq!(
                after.is_liquidatable(&m, px, index),
                *liq_before,
                "ADL never changes who is liquidatable ({case})"
            );
            if before.collateral >= 0 {
                assert!(after.collateral >= 0, "no new bad debt ({case})");
            }
            if eq_before >= mm {
                assert!(
                    after.equity(px, index).unwrap() >= *mm,
                    "a healthy winner stays at or above maintenance ({case})"
                );
            }
        }
    }

    // The sample must exercise every branch, not pass vacuously.
    assert!(liquidated > 1_000, "liquidated {liquidated}");
    assert!(clawed_any > 400, "clawed {clawed_any}");
    assert!(tripped > 250, "tripped close-only {tripped}");
    assert!(from_treasury > 300, "treasury draws {from_treasury}");
    assert!(
        some_spared > 200,
        "open winners left untouched {some_spared}"
    );
    assert!(
        zero_clawable > 500,
        "open positions with nothing clawable {zero_clawable}"
    );
}

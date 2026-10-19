//! Funding rate and the cumulative funding index (Proof-v1: funding correctness).
//!
//! Perps track spot via funding: when the perp trades above the oracle (index)
//! price, longs pay shorts, and vice-versa. We accumulate a per-market
//! cumulative index in micro-USD per 1.0 base unit; a position settles funding as
//! `size · (index_now − index_entry) / SIZE_SCALE` (see
//! [`crate::position::Position::funding_owed`]). The rate is clamped — bounded,
//! deterministic, re-proven — so a manipulated mark can't drain collateral
//! through runaway funding (§12).
//!
//! ## Accrual rule
//!
//! Each market stores the clamped rate observed by its last `AccrueFunding`
//! ([`FundingState::rate`]) and the time from which the not-yet-committed span
//! runs ([`FundingState::last_update_ms`]). Funding for a span is always committed
//! at the STORED rate, so a span is priced at the rate observed at its start and
//! never at a rate observed after it; a newly observed rate applies from the tick
//! that observes it.
//!
//! Every op that reads the index for a position (`Fill`, `Liquidate`, `Unbind`)
//! first commits the open span up to its own time ([`FundingState::settle_to`]).
//! So each span is charged to exactly the positions that existed during it,
//! whatever order the ops of one batch arrive in: a position opened at time `t`
//! owes nothing for the time before `t`, and a position closed at `t` pays for
//! all of it.
//!
//! Each span between two settlements is charged for at most one funding interval
//! ([`FUNDING_INTERVAL_MS`]); the rest of a longer gap is not charged. The
//! division is exact: the part of a span's funding too small to move the index is
//! carried in [`FundingState::remainder`], so many short spans add up to exactly
//! what one long span at the same rate would.

use crate::fixed::{PRICE_SCALE, QUOTE_SCALE, RATE_SCALE};

/// Per-market funding accumulator.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FundingState {
    /// Cumulative funding index: micro-USD per 1.0 base unit.
    pub cumulative_index: i128,
    /// Start of the span not yet committed to the index, ms.
    pub last_update_ms: u64,
    /// The clamped funding rate in force since `last_update_ms`
    /// ([`RATE_SCALE`]-scaled, per [`FUNDING_INTERVAL_MS`]): the rate the last
    /// `AccrueFunding` observed. 0 on a fresh market. Always within
    /// `±MAX_FUNDING_RATE_PER_INTERVAL`.
    pub rate: i128,
    /// The funding committed but too small to move the index, as a numerator over
    /// [`FUNDING_DIVISOR`] (micro-USD per base): `cumulative_index ·
    /// FUNDING_DIVISOR + remainder` is the exact funding committed so far.
    /// `|remainder| < FUNDING_DIVISOR` always holds.
    pub remainder: i128,
    /// The newest validated oracle index price recorded for this market
    /// ([`PRICE_SCALE`]-scaled); 0 while none is recorded. Never negative.
    /// `Fill`, `Liquidate` and `Unbind` record their validated price, and
    /// `AccrueFunding` records its index when the tick changed the funding state,
    /// when a refresh is due ([`FundingState::price_refresh_due`]), or while the
    /// system is close-only. `SettleAll` closes the market's open positions at
    /// this price.
    pub last_price: i128,
    /// The publish time of `last_price`, ms; 0 while none is recorded.
    pub last_price_ms: u64,
}

/// Clamp bound on the per-interval funding rate (RATE_SCALE-scaled). 0.05% here.
pub const MAX_FUNDING_RATE_PER_INTERVAL: i128 = RATE_SCALE / 2000;

/// Wall-clock length of one funding interval, in ms (1 hour). The `MAX_FUNDING_
/// RATE_PER_INTERVAL` cap and the `funding_rate` premium are quoted PER this
/// interval; [`FundingState::settle_to`] scales each span by its real elapsed time
/// so cumulative funding tracks wall-clock, not the number of calls (the sequencer
/// accrues on every ~700ms seal tick). It is also the most any one span is charged
/// for.
pub const FUNDING_INTERVAL_MS: u64 = 3_600_000;

/// Divisor of the exact funding carry: one rate unit held for one interval. A span
/// of `dt` ms at rate `r` and index notional `q` (micro-USD per base) contributes
/// the numerator `q · r · dt`; each whole `FUNDING_DIVISOR` of the running
/// numerator moves the index by 1 and the rest stays in
/// [`FundingState::remainder`].
pub const FUNDING_DIVISOR: i128 = RATE_SCALE * FUNDING_INTERVAL_MS as i128;

/// Length of one price-refresh epoch, in ms (6 hours). Epochs are aligned to
/// multiples of this length from the Unix epoch, so `t / PRICE_REFRESH_MS` names
/// the epoch that contains time `t` (see [`FundingState::price_refresh_due`]).
pub const PRICE_REFRESH_MS: u64 = 21_600_000;

impl FundingState {
    /// Compute the clamped funding rate from the premium of `mark` over the
    /// oracle `index_price`. RATE_SCALE-scaled, sign = direction longs pay.
    pub fn funding_rate(mark: i128, index_price: i128) -> i128 {
        if index_price <= 0 {
            return 0;
        }
        // premium fraction = (mark - index)/index, RATE_SCALE-scaled. `index_price > 0`
        // here, so the subtraction can only UNDERFLOW — an extreme-negative mark (e.g. an
        // attacker's resting price near i128::MIN, audit DP-008). Clamp sign-preservingly
        // to -MAX rather than panicking (debug) or wrapping to a bogus +MAX (release).
        let premium = match mark.checked_sub(index_price) {
            Some(p) => p,
            None => return -MAX_FUNDING_RATE_PER_INTERVAL,
        };
        let raw = match premium.checked_mul(RATE_SCALE) {
            Some(v) => v / index_price,
            // overflow ⇒ clamp, but preserve the SIGN of the premium (a deep
            // discount must clamp to −MAX, a deep premium to +MAX).
            None if premium < 0 => return -MAX_FUNDING_RATE_PER_INTERVAL,
            None => return MAX_FUNDING_RATE_PER_INTERVAL,
        };
        raw.clamp(
            -MAX_FUNDING_RATE_PER_INTERVAL,
            MAX_FUNDING_RATE_PER_INTERVAL,
        )
    }

    /// Commit the funding of the span `[last_update_ms, now_ms]` at the STORED
    /// rate, then start the next span at `now_ms`. The span is charged for at most
    /// [`FUNDING_INTERVAL_MS`]. `index_price` is the validated oracle index the
    /// caller's op carries; it prices the span's notional.
    ///
    /// Infallible: every step is bounded-saturating, and the carry keeps
    /// `|remainder| < FUNDING_DIVISOR`. When `now_ms` is not after
    /// `last_update_ms` nothing changes; otherwise the clock always advances, also
    /// at a zero rate.
    pub fn settle_to(&mut self, index_price: i128, now_ms: u64) {
        if now_ms <= self.last_update_ms {
            return;
        }
        if self.rate != 0 {
            // audit DP-008: the payment notional is the VALIDATED oracle index, NOT
            // the raw book mark, so a manipulated mark can move the rate (within the
            // clamp) but never scale the payment.
            // index micro-USD = index · QUOTE_SCALE / PRICE_SCALE
            let index_quote = index_price.saturating_mul(QUOTE_SCALE) / PRICE_SCALE;
            let dt = (now_ms - self.last_update_ms).min(FUNDING_INTERVAL_MS) as i128;
            let numerator = self
                .remainder
                .saturating_add(index_quote.saturating_mul(self.rate).saturating_mul(dt));
            self.cumulative_index = self
                .cumulative_index
                .saturating_add(numerator / FUNDING_DIVISOR);
            // Both truncate toward zero, so the remainder keeps the numerator's sign
            // and stays strictly inside ±FUNDING_DIVISOR.
            self.remainder = numerator % FUNDING_DIVISOR;
        }
        self.last_update_ms = now_ms;
    }

    /// The cumulative index as [`FundingState::settle_to`] would leave it at
    /// `now_ms`, without changing `self`. An off-chain check that must agree with
    /// the engine (a pre-trade margin check, say) reads the index through this.
    pub fn index_at(&self, index_price: i128, now_ms: u64) -> i128 {
        let mut f = *self;
        f.settle_to(index_price, now_ms);
        f.cumulative_index
    }

    /// One funding tick (`AccrueFunding`): commit the open span at the stored
    /// rate, then adopt the rate observed now from `mark` against the validated
    /// `index_price`. The adopted rate prices the span that starts now.
    ///
    /// A tick that observes a zero rate while the stored rate is zero changes
    /// nothing, the clock included, so an idle market's ticks leave the state root
    /// unchanged. Returns whether the state changed.
    pub fn accrue(&mut self, mark: i128, index_price: i128, now_ms: u64) -> bool {
        let new_rate = Self::funding_rate(mark, index_price);
        if self.rate == 0 && new_rate == 0 {
            return false;
        }
        let before = *self;
        self.settle_to(index_price, now_ms);
        self.rate = new_rate;
        *self != before
    }

    /// Record `price`, published at `publish_ms`, as the market's newest price.
    /// Only a positive price strictly newer than the recorded one replaces it, so
    /// an op that carries an older (still fresh) transcript never moves the
    /// recorded price back in time.
    pub fn record_price(&mut self, price: i128, publish_ms: u64) {
        if price > 0 && publish_ms > self.last_price_ms {
            self.last_price = price;
            self.last_price_ms = publish_ms;
        }
    }

    /// Whether a price published at `publish_ms` falls in a later price-refresh
    /// epoch ([`PRICE_REFRESH_MS`]) than the recorded one. Always false while no
    /// price is recorded.
    pub fn price_refresh_due(&self, publish_ms: u64) -> bool {
        self.last_price_ms != 0
            && publish_ms / PRICE_REFRESH_MS > self.last_price_ms / PRICE_REFRESH_MS
    }

    /// Whether every field is in the range the engine maintains: the rate within
    /// the clamp, the carry strictly inside `±FUNDING_DIVISOR`, a non-negative
    /// recorded price, and no recorded publish time without a recorded price. Every
    /// state built by `State::add_market` and the engine's ops satisfies it.
    pub fn is_well_formed(&self) -> bool {
        (-MAX_FUNDING_RATE_PER_INTERVAL..=MAX_FUNDING_RATE_PER_INTERVAL).contains(&self.rate)
            && (-(FUNDING_DIVISOR - 1)..=FUNDING_DIVISOR - 1).contains(&self.remainder)
            && self.last_price >= 0
            && (self.last_price != 0 || self.last_price_ms == 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BTC: i128 = 100_000 * PRICE_SCALE;

    /// The exact numerator a span of `dt` ms adds at `rate` and `index`.
    fn numerator(index: i128, rate: i128, dt: u64) -> i128 {
        (index * QUOTE_SCALE / PRICE_SCALE) * rate * dt as i128
    }

    /// A market whose stored rate is `rate`, in force since `t`.
    fn in_force(rate: i128, t: u64) -> FundingState {
        FundingState {
            rate,
            last_update_ms: t,
            ..FundingState::default()
        }
    }

    #[test]
    fn premium_makes_longs_pay() {
        // mark 1% above index → positive rate, clamped to 0.05%
        let r = FundingState::funding_rate(101_000 * PRICE_SCALE, 100_000 * PRICE_SCALE);
        assert_eq!(r, MAX_FUNDING_RATE_PER_INTERVAL);
    }

    #[test]
    fn discount_makes_shorts_pay() {
        let r = FundingState::funding_rate(99_000 * PRICE_SCALE, 100_000 * PRICE_SCALE);
        assert_eq!(r, -MAX_FUNDING_RATE_PER_INTERVAL);
    }

    #[test]
    fn small_premium_not_clamped() {
        // 0.01% premium < 0.05% clamp
        let r = FundingState::funding_rate(100_010 * PRICE_SCALE, 100_000 * PRICE_SCALE);
        assert!(r > 0 && r < MAX_FUNDING_RATE_PER_INTERVAL);
    }

    // audit DP-008 (adversarial follow-up): an attacker-rested price near i128::MIN
    // reaches funding_rate as an extreme-negative mark; the premium subtraction must not
    // panic (debug) or wrap to a bogus +MAX (release) — a deep discount clamps to -MAX.
    #[test]
    fn extreme_negative_mark_clamps_to_minus_max() {
        let idx = 100_000 * PRICE_SCALE;
        assert_eq!(
            FundingState::funding_rate(i128::MIN, idx),
            -MAX_FUNDING_RATE_PER_INTERVAL
        );
        assert_eq!(
            FundingState::funding_rate(i128::MIN + 1, idx),
            -MAX_FUNDING_RATE_PER_INTERVAL
        );
    }

    #[test]
    fn overflow_clamp_preserves_sign() {
        // a deep discount whose premium*RATE_SCALE overflows must clamp to −MAX,
        // not +MAX (the sign-blind bug).
        let r = FundingState::funding_rate(1, i128::MAX);
        assert_eq!(r, -MAX_FUNDING_RATE_PER_INTERVAL, "deep discount → -MAX");
        let r2 = FundingState::funding_rate(i128::MAX, 1);
        assert_eq!(r2, MAX_FUNDING_RATE_PER_INTERVAL, "deep premium → +MAX");
    }

    /// The first tick on a fresh market only adopts the rate; the next tick
    /// charges the span between them at that rate.
    #[test]
    fn accrue_moves_index_up_on_premium() {
        let mark = 101_000 * PRICE_SCALE;
        let mut f = FundingState::default();
        assert!(f.accrue(mark, BTC, 1_000), "seeding tick adopts the rate");
        assert_eq!(
            f.cumulative_index, 0,
            "a fresh market's first tick charges 0"
        );
        assert_eq!(f.rate, MAX_FUNDING_RATE_PER_INTERVAL);
        assert_eq!(f.last_update_ms, 1_000);

        assert!(f.accrue(mark, BTC, 61_000));
        let n = numerator(BTC, MAX_FUNDING_RATE_PER_INTERVAL, 60_000);
        assert!(f.cumulative_index > 0);
        assert_eq!(f.cumulative_index, n / FUNDING_DIVISOR);
        assert_eq!(f.remainder, n % FUNDING_DIVISOR);
        assert_eq!(f.last_update_ms, 61_000);
    }

    // audit DP-008: a manipulated book-mid mark must not scale the funding payment.
    // Both a 1%-premium mark and a 100x mark hit the +MAX clamped rate; the span's
    // funding is anchored to the validated index notional, so an extreme mark cannot
    // produce a larger payment than a mark at the clamp boundary.
    #[test]
    fn manipulated_mark_cannot_inflate_the_funding_notional() {
        let mut sane = FundingState::default();
        let mut manip = FundingState::default();
        sane.accrue(101_000 * PRICE_SCALE, BTC, 1_000); // 1% premium → rate MAX
        manip.accrue(100 * BTC, BTC, 1_000); // 100x book mark → rate MAX
        assert_eq!(sane, manip, "both seed the clamped rate");
        sane.accrue(101_000 * PRICE_SCALE, BTC, 61_000);
        manip.accrue(100 * BTC, BTC, 61_000);
        assert!(sane.cumulative_index > 0);
        assert_eq!(
            manip, sane,
            "funding is bounded by the index notional, not the manipulable mark",
        );
    }

    // AUDIT (HIGH — funding over-accrual): the cumulative index must track ELAPSED
    // WALL-CLOCK TIME, not the number of ticks. With the exact carry, one interval
    // sampled once and the same interval sampled 1000 times commit exactly the same
    // funding: no per-tick truncation remains.
    #[test]
    fn funding_tracks_elapsed_time_not_call_count() {
        let mark = 101_000 * PRICE_SCALE; // steady 1% premium → clamped MAX rate
        let start = 1_000_000u64;
        let window = FUNDING_INTERVAL_MS;

        let mut once = FundingState::default();
        once.accrue(mark, BTC, start); // seed the rate
        once.accrue(mark, BTC, start + window);

        let mut many = FundingState::default();
        many.accrue(mark, BTC, start);
        for k in 1..=1000u64 {
            many.accrue(mark, BTC, start + k * (window / 1000));
        }

        assert!(once.cumulative_index > 0);
        assert_eq!(
            many, once,
            "1000 ticks and 1 tick over one interval agree exactly"
        );
        let n = numerator(BTC, MAX_FUNDING_RATE_PER_INTERVAL, window);
        assert_eq!(once.cumulative_index, n / FUNDING_DIVISOR);
        assert_eq!(once.remainder, n % FUNDING_DIVISOR);
    }

    // AUDIT (review regression): a LOW-priced market's per-tick funding is
    // sub-micro-USD. The carry must still accrue it in full over an interval —
    // otherwise LIT ($1.10) never accrues any funding at all.
    #[test]
    fn low_priced_market_still_accrues_funding_via_the_carry() {
        let index = 110_000_000i128; // $1.10 * PRICE_SCALE (LIT)
        let mark = 111_000_000i128; // ~0.9% premium → clamped MAX rate
        let mut f = in_force(MAX_FUNDING_RATE_PER_INTERVAL, 1_000);
        // ~700ms ticks across one interval; each tick alone is below one index unit
        let ticks = FUNDING_INTERVAL_MS / 700;
        for k in 1..=ticks {
            f.accrue(mark, index, 1_000 + k * 700);
            if k == 1 {
                assert_eq!(f.cumulative_index, 0, "one tick is below one index unit");
                assert!(f.remainder > 0, "but it is carried, not dropped");
            }
        }
        // exactly what one span of the same length commits: 549 of the interval's 550
        let n = numerator(index, MAX_FUNDING_RATE_PER_INTERVAL, ticks * 700);
        assert_eq!(f.cumulative_index, n / FUNDING_DIVISOR);
        assert_eq!(f.cumulative_index, 549);
        assert_eq!(f.remainder, n % FUNDING_DIVISOR);
    }

    /// A tick that observes a zero rate on a market whose stored rate is zero
    /// changes nothing, the clock included.
    #[test]
    fn a_zero_rate_tick_on_a_zero_rate_market_changes_nothing() {
        let mut f = FundingState {
            cumulative_index: -42,
            last_update_ms: 5_000,
            rate: 0,
            remainder: 17,
            last_price: BTC,
            last_price_ms: 4_000,
        };
        let before = f;
        assert!(!f.accrue(BTC, BTC, 9_000));
        assert_eq!(f, before);
        // a non-zero stored rate is committed and then replaced by zero
        let mut g = in_force(MAX_FUNDING_RATE_PER_INTERVAL, 5_000);
        assert!(g.accrue(BTC, BTC, 9_000));
        assert_eq!(g.rate, 0);
        assert_eq!(g.last_update_ms, 9_000);
        assert!(g.cumulative_index > 0);
    }

    /// A premium is charged only from the tick that observes it. However long the
    /// span at a zero stored rate, the tick that first sees the premium commits
    /// nothing for it; the next span is charged at the premium's rate for its own
    /// length only.
    #[test]
    fn a_premium_is_charged_only_from_the_tick_that_observes_it() {
        let t0 = 1_700_000_000_000u64;
        let mut f = FundingState::default();
        // a market that saw a small premium, and then a zero rate at t0
        f.accrue(BTC + BTC / 100_000, BTC, t0 - 700);
        f.accrue(BTC, BTC, t0);
        assert_eq!(f.rate, 0);
        let settled = f;
        // ~59.9 minutes of zero-rate ticks
        let ticks = 5_130u64;
        for k in 1..=ticks {
            assert!(!f.accrue(BTC, BTC, t0 + k * 700));
        }
        assert_eq!(f, settled);
        // the tick that first observes a +1% premium
        let seen = t0 + (ticks + 1) * 700;
        assert!(f.accrue(BTC * 101 / 100, BTC, seen));
        assert_eq!(
            f.cumulative_index, settled.cumulative_index,
            "the span before the premium was observed is charged at the zero rate"
        );
        assert_eq!(f.remainder, settled.remainder);
        assert_eq!(f.rate, MAX_FUNDING_RATE_PER_INTERVAL);
        // the next 700ms span is charged at the premium's rate, for 700ms only
        f.accrue(BTC * 101 / 100, BTC, seen + 700);
        let n = settled.remainder + numerator(BTC, MAX_FUNDING_RATE_PER_INTERVAL, 700);
        assert_eq!(
            f.cumulative_index,
            settled.cumulative_index + n / FUNDING_DIVISOR
        );
        assert_eq!(f.remainder, n % FUNDING_DIVISOR);
    }

    /// Each span is charged for at most one interval; the rest of a longer gap is
    /// not charged. The clock still moves to the end of the gap.
    #[test]
    fn each_span_is_charged_for_at_most_one_interval() {
        for rate in [
            MAX_FUNDING_RATE_PER_INTERVAL,
            -MAX_FUNDING_RATE_PER_INTERVAL,
        ] {
            let mut capped = in_force(rate, 10_000);
            capped.settle_to(BTC, 10_000 + 3 * FUNDING_INTERVAL_MS);
            let mut one = in_force(rate, 10_000);
            one.settle_to(BTC, 10_000 + FUNDING_INTERVAL_MS);
            assert_eq!(capped.cumulative_index, one.cumulative_index);
            assert_eq!(capped.remainder, one.remainder);
            assert_eq!(capped.last_update_ms, 10_000 + 3 * FUNDING_INTERVAL_MS);
            // one interval at the clamp: index · MAX_RATE exactly, no remainder
            assert_eq!(one.cumulative_index, rate.signum() * 50_000_000);
            assert_eq!(one.remainder, 0);
        }
    }

    /// A non-advancing time changes nothing; a zero stored rate only moves the
    /// clock.
    #[test]
    fn settle_to_moves_only_forward() {
        let mut f = FundingState {
            cumulative_index: 9,
            last_update_ms: 50_000,
            rate: MAX_FUNDING_RATE_PER_INTERVAL,
            remainder: -3,
            last_price: 0,
            last_price_ms: 0,
        };
        let before = f;
        f.settle_to(BTC, 50_000);
        f.settle_to(BTC, 1);
        assert_eq!(f, before);
        let mut z = FundingState { rate: 0, ..before };
        let z_before = z;
        z.settle_to(BTC, 80_000);
        assert_eq!(
            z,
            FundingState {
                last_update_ms: 80_000,
                ..z_before
            }
        );
    }

    /// `index_at` is `settle_to` without the mutation.
    #[test]
    fn index_at_matches_settle_to() {
        let f = FundingState {
            cumulative_index: 1_234,
            last_update_ms: 7_000,
            rate: -317,
            remainder: -(FUNDING_DIVISOR - 5),
            last_price: 0,
            last_price_ms: 0,
        };
        for now in [0u64, 7_000, 7_001, 99_999, 7_000 + 5 * FUNDING_INTERVAL_MS] {
            let mut g = f;
            g.settle_to(BTC, now);
            assert_eq!(f.index_at(BTC, now), g.cumulative_index, "now = {now}");
        }
    }

    /// The carry is exact over any sequence of spans: index · DIVISOR + remainder
    /// equals the sum of every span's numerator, and the remainder stays strictly
    /// inside ±DIVISOR.
    #[test]
    fn the_carry_is_exact_and_bounded() {
        let mut seed = 0x2545_F491_4F6C_DD1Du64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..50 {
            let mut f = FundingState::default();
            let mut t = 1_000u64;
            let mut total = 0i128;
            for _ in 0..400 {
                let index = 1 + (next() % 200_000) as i128 * PRICE_SCALE / 1_000;
                let mark = index + (next() % 2_001) as i128 * index / 100_000 - index / 100;
                t += next() % 5_000;
                let dt = (t - f.last_update_ms).min(FUNDING_INTERVAL_MS);
                if f.rate != 0 && t > f.last_update_ms {
                    total += numerator(index, f.rate, dt);
                }
                f.accrue(mark, index, t);
                assert!(f.is_well_formed(), "{f:?}");
                assert_eq!(f.cumulative_index * FUNDING_DIVISOR + f.remainder, total);
            }
        }
    }

    #[test]
    fn record_price_keeps_the_newest_positive_price() {
        let mut f = FundingState::default();
        f.record_price(0, 10);
        f.record_price(-5, 10);
        assert_eq!((f.last_price, f.last_price_ms), (0, 0));
        f.record_price(BTC, 10);
        assert_eq!((f.last_price, f.last_price_ms), (BTC, 10));
        f.record_price(2 * BTC, 10); // not newer
        f.record_price(3 * BTC, 9); // older
        assert_eq!((f.last_price, f.last_price_ms), (BTC, 10));
        f.record_price(4 * BTC, 11);
        assert_eq!((f.last_price, f.last_price_ms), (4 * BTC, 11));
        assert!(f.is_well_formed());
    }

    #[test]
    fn price_refresh_is_due_once_per_epoch() {
        let mut f = FundingState::default();
        assert!(!f.price_refresh_due(5 * PRICE_REFRESH_MS));
        f.record_price(BTC, 2 * PRICE_REFRESH_MS + 1);
        assert!(!f.price_refresh_due(2 * PRICE_REFRESH_MS + 2));
        assert!(!f.price_refresh_due(3 * PRICE_REFRESH_MS - 1));
        assert!(f.price_refresh_due(3 * PRICE_REFRESH_MS));
        assert!(!f.price_refresh_due(PRICE_REFRESH_MS));
    }

    #[test]
    fn well_formed_bounds_every_field() {
        assert!(FundingState::default().is_well_formed());
        let edge = FundingState {
            cumulative_index: i128::MIN,
            last_update_ms: u64::MAX,
            rate: -MAX_FUNDING_RATE_PER_INTERVAL,
            remainder: FUNDING_DIVISOR - 1,
            last_price: i128::MAX,
            last_price_ms: u64::MAX,
        };
        assert!(edge.is_well_formed());
        assert!(FundingState {
            rate: MAX_FUNDING_RATE_PER_INTERVAL,
            remainder: -(FUNDING_DIVISOR - 1),
            ..edge
        }
        .is_well_formed());
        let bad = [
            FundingState {
                rate: MAX_FUNDING_RATE_PER_INTERVAL + 1,
                ..edge
            },
            FundingState {
                rate: i128::MIN,
                ..edge
            },
            FundingState {
                remainder: FUNDING_DIVISOR,
                ..edge
            },
            FundingState {
                remainder: -FUNDING_DIVISOR,
                ..edge
            },
            FundingState {
                remainder: i128::MIN,
                ..edge
            },
            FundingState {
                last_price: -1,
                ..edge
            },
            FundingState {
                last_price: 0,
                last_price_ms: 1,
                ..edge
            },
        ];
        for f in bad {
            assert!(!f.is_well_formed(), "{f:?}");
        }
    }
}

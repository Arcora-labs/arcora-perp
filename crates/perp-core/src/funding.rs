//! Funding rate and the cumulative funding index (Proof-v1: funding correctness).
//!
//! Perps track spot via funding: when the perp trades above the oracle (index)
//! price, longs pay shorts, and vice-versa. We accumulate a per-market
//! cumulative index in micro-USD per 1.0 base unit; a position settles funding as
//! `size · (index_now − index_entry) / SIZE_SCALE` (see
//! [`crate::position::Position::funding_owed`]). The rate is clamped — bounded,
//! deterministic, re-proven — so a manipulated mark can't drain collateral
//! through runaway funding (§12).

use crate::fixed::{PRICE_SCALE, QUOTE_SCALE, RATE_SCALE};

/// Per-market funding accumulator.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FundingState {
    /// Cumulative funding index: micro-USD per 1.0 base unit.
    pub cumulative_index: i128,
    /// Last update timestamp, ms.
    pub last_update_ms: u64,
}

/// Clamp bound on the per-interval funding rate (RATE_SCALE-scaled). 0.05% here.
pub const MAX_FUNDING_RATE_PER_INTERVAL: i128 = RATE_SCALE / 2000;

/// Wall-clock length of one funding interval, in ms (1 hour). The `MAX_FUNDING_
/// RATE_PER_INTERVAL` cap and the `funding_rate` premium are quoted PER this
/// interval; [`FundingState::accrue`] scales each accrual by the real elapsed
/// time so cumulative funding tracks wall-clock, not the number of `accrue` calls
/// (the sequencer accrues on every ~700ms seal tick).
pub const FUNDING_INTERVAL_MS: u64 = 3_600_000;

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

    /// Advance the cumulative index by the funding owed for the wall-clock time
    /// elapsed since the last accrual, at the given mark / index price. Returns the
    /// index delta applied (micro-USD per base).
    pub fn accrue(&mut self, mark: i128, index_price: i128, now_ms: u64) -> i128 {
        let rate = Self::funding_rate(mark, index_price);
        // audit DP-008: the payment notional is the VALIDATED oracle index, NOT the raw
        // book mark. `funding_rate` already captures the (clamped) mark-vs-index premium,
        // so a manipulated book mid can flip or max the rate but can NOT scale the
        // payment — the notional is anchored to the sane index, which bounds the
        // per-interval delta to `index_quote · MAX_FUNDING_RATE_PER_INTERVAL`.
        // index micro-USD = index · QUOTE_SCALE / PRICE_SCALE
        let index_quote = index_price.saturating_mul(QUOTE_SCALE) / PRICE_SCALE;
        let full_delta = index_quote.saturating_mul(rate) / RATE_SCALE;
        // audit (HIGH — funding over-accrual): scale the per-interval delta by the real
        // elapsed time so accruing on every ~700ms seal tick sums to one interval's
        // funding per interval, not one per call (~5000×/hr). Cap the elapsed span at a
        // single interval so the first accrual on a fresh market (last_update_ms == 0 vs
        // a real unix-ms clock) and any post-downtime catch-up apply AT MOST one interval
        // — bounded, never a spike. A non-monotonic clock yields 0 elapsed ⇒ 0 delta.
        let elapsed = now_ms
            .saturating_sub(self.last_update_ms)
            .min(FUNDING_INTERVAL_MS);
        let delta = full_delta.saturating_mul(elapsed as i128) / FUNDING_INTERVAL_MS as i128;
        // Carry the remainder: only COMMIT (and advance the clock) once the elapsed span
        // produces a non-zero delta. Without this, a low-priced market's sub-micro-USD
        // per-tick funding (e.g. LIT at $1.10: full_delta≈550, so 550·700/3_600_000
        // truncates to 0 every ~700ms tick) would advance last_update_ms while accruing
        // nothing and NEVER accumulate. Leaving last_update_ms unadvanced lets `elapsed`
        // keep growing until the division rounds up to ≥1 (works for both signs, since
        // integer division truncates toward zero).
        if delta != 0 {
            self.cumulative_index = self.cumulative_index.saturating_add(delta);
            self.last_update_ms = now_ms;
        }
        delta
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn accrue_moves_index_up_on_premium() {
        let mut f = FundingState::default();
        let d = f.accrue(101_000 * PRICE_SCALE, 100_000 * PRICE_SCALE, 1000);
        assert!(d > 0);
        assert_eq!(f.cumulative_index, d);
        assert_eq!(f.last_update_ms, 1000);
    }

    // audit DP-008: a manipulated book-mid mark must not scale the funding payment.
    // Both a 1%-premium mark and a 100x mark hit the +MAX clamped rate; the per-interval
    // delta is anchored to the validated index notional, so an extreme mark cannot
    // produce a materially larger payment than a mark at the clamp boundary.
    #[test]
    fn manipulated_mark_cannot_inflate_the_funding_notional() {
        let index = 100_000 * PRICE_SCALE;
        let mut sane = FundingState::default();
        let d_sane = sane.accrue(101_000 * PRICE_SCALE, index, 1000); // 1% premium → rate MAX
        let mut manip = FundingState::default();
        let d_manip = manip.accrue(100 * index, index, 1000); // 100x book mark → rate MAX
        assert!(d_sane > 0);
        assert_eq!(
            d_manip, d_sane,
            "funding delta is bounded by the index notional, not the manipulable mark",
        );
    }

    // AUDIT (HIGH — funding over-accrual): the cumulative index must track ELAPSED
    // WALL-CLOCK TIME, not the number of `accrue` calls. The sequencer accrues on
    // every ~700ms seal tick; a steady premium over one funding interval must accrue
    // the same total whether sampled once or thousands of times, otherwise the
    // per-call cadence (~5000×/hr) over-charges funding and liquidates healthy
    // positions purely by call frequency.
    #[test]
    fn funding_tracks_elapsed_time_not_call_count() {
        let index = 100_000 * PRICE_SCALE;
        let mark = 101_000 * PRICE_SCALE; // steady 1% premium → clamped MAX rate
        let start = 1_000_000u64;
        let window = FUNDING_INTERVAL_MS;

        // sampled ONCE across the whole interval
        let mut once = FundingState {
            cumulative_index: 0,
            last_update_ms: start,
        };
        once.accrue(mark, index, start + window);

        // sampled 1000 times across the SAME interval (the ~700ms tick cadence)
        let mut many = FundingState {
            cumulative_index: 0,
            last_update_ms: start,
        };
        for k in 1..=1000u64 {
            many.accrue(mark, index, start + k * (window / 1000));
        }

        // The two totals must agree (within integer-truncation drift over 1000 steps),
        // NOT differ by ~1000× as the per-call bug would.
        let tol = once.cumulative_index / 1000 + 10;
        assert!(
            (many.cumulative_index - once.cumulative_index).abs() <= tol,
            "funding over one interval: 1000 steps = {}, 1 step = {} (tol {tol})",
            many.cumulative_index,
            once.cumulative_index,
        );
    }

    // AUDIT (review regression): a LOW-priced market's per-tick funding is sub-micro-USD
    // and integer-truncates to 0 every ~700ms tick. The carry (not advancing
    // last_update_ms until the delta rounds up) must still accrue it over an interval —
    // otherwise LIT ($1.10) never accrues any funding at all.
    #[test]
    fn low_priced_market_still_accrues_funding_via_the_carry() {
        let index = 110_000_000i128; // $1.10 * PRICE_SCALE (LIT)
        let mark = 111_000_000i128; // ~0.9% premium → clamped MAX rate
                                    // one interval's worth at MAX rate = index_quote·MAX_RATE = 1_100_000·500/1e6 = 550
        let mut f = FundingState {
            cumulative_index: 0,
            last_update_ms: 1_000,
        };
        // accrue on ~700ms ticks across one full interval; each raw tick delta floors to 0
        let ticks = FUNDING_INTERVAL_MS / 700;
        for k in 1..=ticks {
            f.accrue(mark, index, 1_000 + k * 700);
        }
        assert!(
            f.cumulative_index > 0,
            "low-priced market must accrue funding over an interval, got {} (pre-fix: 0)",
            f.cumulative_index,
        );
        // bounded near one interval's delta (≈550), never a runaway
        assert!(
            f.cumulative_index <= 550,
            "must not over-accrue, got {}",
            f.cumulative_index,
        );
    }
}

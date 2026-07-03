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

    /// Advance the cumulative index by one funding interval at the given mark /
    /// index price. Returns the index delta applied (micro-USD per base).
    pub fn accrue(&mut self, mark: i128, index_price: i128, now_ms: u64) -> i128 {
        let rate = Self::funding_rate(mark, index_price);
        // audit DP-008: the payment notional is the VALIDATED oracle index, NOT the raw
        // book mark. `funding_rate` already captures the (clamped) mark-vs-index premium,
        // so a manipulated book mid can flip or max the rate but can NOT scale the
        // payment — the notional is anchored to the sane index, which bounds the
        // per-interval delta to `index_quote · MAX_FUNDING_RATE_PER_INTERVAL`.
        // index micro-USD = index · QUOTE_SCALE / PRICE_SCALE
        let index_quote = index_price.saturating_mul(QUOTE_SCALE) / PRICE_SCALE;
        let delta = index_quote.saturating_mul(rate) / RATE_SCALE;
        self.cumulative_index = self.cumulative_index.saturating_add(delta);
        self.last_update_ms = now_ms;
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
}

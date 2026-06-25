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
        // premium fraction = (mark - index)/index, RATE_SCALE-scaled
        let raw = match (mark - index_price).checked_mul(RATE_SCALE) {
            Some(v) => v / index_price,
            None => return MAX_FUNDING_RATE_PER_INTERVAL, // overflow ⇒ clamp
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
        // payment per 1.0 base = mark(in micro-USD) · rate
        // mark micro-USD = mark · QUOTE_SCALE / PRICE_SCALE
        let mark_quote = mark.saturating_mul(QUOTE_SCALE) / PRICE_SCALE;
        let delta = mark_quote.saturating_mul(rate) / RATE_SCALE;
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

    #[test]
    fn accrue_moves_index_up_on_premium() {
        let mut f = FundingState::default();
        let d = f.accrue(101_000 * PRICE_SCALE, 100_000 * PRICE_SCALE, 1000);
        assert!(d > 0);
        assert_eq!(f.cumulative_index, d);
        assert_eq!(f.last_update_ms, 1000);
    }
}

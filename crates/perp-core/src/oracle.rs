//! Oracle transcript and sanity bounds (§8).
//!
//! The engine never trusts a raw price. Every price arrives as a *transcript* —
//! signed value, publish time, confidence interval, and a backup TWAP — and is
//! admitted only if it clears the market's deterministic sanity gates (§12). The
//! same checks become Proof-v1 constraints, so the prover re-verifies that every
//! liquidation and settlement used an in-bounds price (§4, §8).
//!
//! Calibration (§8): Pyth-primary + TWAP backup with a sanity bound, and a
//! close-only circuit breaker on anomaly — *not* a perfect low-latency failover,
//! which would tax the very latency we optimize for.

use crate::fixed::{abs, RATE_SCALE};
use crate::hash::{word_i128, word_u64, Digest, Domain, Hasher};
use crate::market::Market;

/// A price observation as delivered to the enclave and committed in the manifest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct OracleTranscript {
    /// Primary (Pyth) price, [`crate::fixed::PRICE_SCALE`]-scaled.
    pub price: i128,
    /// Publish timestamp, milliseconds.
    pub publish_time_ms: u64,
    /// Confidence interval (± around price), price-scaled.
    pub confidence: i128,
    /// Backup TWAP used for the deviation sanity bound.
    pub backup_twap: i128,
}

/// Why a price was rejected — these map 1:1 to close-only / pause triggers (§8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OracleError {
    Stale,
    LowConfidence,
    DeviatesFromBackup,
    NonPositivePrice,
}

impl OracleTranscript {
    /// Validate against a market's bounds at the current time.
    ///
    /// `now_ms` is the batch's reference clock (committed in the manifest); the
    /// circuit re-checks `publish_time ∈ [now - max_staleness, now]`.
    pub fn validate(&self, market: &Market, now_ms: u64) -> Result<i128, OracleError> {
        if self.price <= 0 {
            return Err(OracleError::NonPositivePrice);
        }
        // freshness: not stale, not from the future
        if self.publish_time_ms > now_ms
            || now_ms - self.publish_time_ms > market.max_oracle_staleness_ms
        {
            return Err(OracleError::Stale);
        }
        // confidence: conf/price <= max_confidence_ratio
        // rearranged to avoid division: conf * SCALE <= max_ratio * price.
        // The price/confidence are attacker-influenced and this runs in the zkVM
        // guest, so use checked math and treat ANY overflow as out-of-bounds (reject)
        // — an extreme price must never wrap the gate and slip through, nor panic the
        // circuit (consistent with the "never wrap" rule in the risk math).
        match (
            abs(self.confidence).checked_mul(RATE_SCALE),
            market.max_oracle_confidence_ratio.checked_mul(self.price),
        ) {
            (Some(lhs), Some(rhs)) if lhs <= rhs => {}
            _ => return Err(OracleError::LowConfidence),
        }
        // deviation vs backup: |price - twap|/price <= max_deviation_ratio. A
        // non-positive backup TWAP is malformed — a real feed always carries a positive
        // mid/price — so it must be REJECTED, never used to SKIP the deviation gate. The
        // old `if backup_twap > 0` let a transcript with backup_twap = 0 clear validation
        // on price alone, silently disabling the last sanity gate (audit Tier-3).
        if self.backup_twap <= 0 {
            return Err(OracleError::DeviatesFromBackup);
        }
        let dev = abs(self.price - self.backup_twap);
        match (
            dev.checked_mul(RATE_SCALE),
            market.max_oracle_deviation_ratio.checked_mul(self.price),
        ) {
            (Some(lhs), Some(rhs)) if lhs <= rhs => {}
            _ => return Err(OracleError::DeviatesFromBackup),
        }
        Ok(self.price)
    }

    /// Transcript hash, committed in the batch manifest (§2, §8).
    pub fn hash<H: Hasher>(&self) -> Digest {
        H::hash_words(
            Domain::OracleTranscript,
            &[
                word_i128(self.price),
                word_u64(self.publish_time_ms),
                word_i128(self.confidence),
                word_i128(self.backup_twap),
            ],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixed::PRICE_SCALE;

    fn good() -> OracleTranscript {
        OracleTranscript {
            price: 100_000 * PRICE_SCALE,
            publish_time_ms: 1_000_000,
            confidence: 100 * PRICE_SCALE, // $100 conf on $100k = 0.1% < 1%
            backup_twap: 100_100 * PRICE_SCALE,
        }
    }

    #[test]
    fn accepts_fresh_tight_price() {
        let m = Market::conservative(0);
        assert_eq!(good().validate(&m, 1_005_000), Ok(100_000 * PRICE_SCALE));
    }

    // AUDIT (Tier-3): a malformed transcript with backup_twap = 0 (and confidence = 0)
    // must NOT clear validation on price alone — the deviation gate must reject a
    // non-positive TWAP rather than silently skip it.
    #[test]
    fn zero_backup_twap_is_rejected_not_skipped() {
        let m = Market::conservative(0);
        let mut t = good();
        t.backup_twap = 0;
        t.confidence = 0;
        assert_eq!(
            t.validate(&m, 1_005_000),
            Err(OracleError::DeviatesFromBackup),
            "a zero backup TWAP must be rejected, not skip the deviation gate"
        );
    }

    #[test]
    fn rejects_stale() {
        let m = Market::conservative(0);
        // 20s later, max staleness 10s
        assert_eq!(good().validate(&m, 1_020_001), Err(OracleError::Stale));
    }

    #[test]
    fn rejects_future_price() {
        let m = Market::conservative(0);
        assert_eq!(good().validate(&m, 999_999), Err(OracleError::Stale));
    }

    #[test]
    fn rejects_wide_confidence() {
        let m = Market::conservative(0);
        let mut t = good();
        t.confidence = 2_000 * PRICE_SCALE; // 2% > 1%
        assert_eq!(t.validate(&m, 1_005_000), Err(OracleError::LowConfidence));
    }

    #[test]
    fn extreme_price_is_rejected_not_wrapped() {
        // An extreme price must never overflow the gate arithmetic (which would
        // wrap and could let a manipulated price slip through, or panic the guest).
        // It is rejected cleanly via checked math.
        let m = Market::conservative(0);
        let mut t = good();
        t.price = i128::MAX;
        t.backup_twap = i128::MAX; // keep deviation 0 so we exercise the conf gate
        assert!(
            t.validate(&m, 1_005_000).is_err(),
            "i128::MAX price rejected, not wrapped"
        );
        // and a huge price vs a normal backup trips the deviation gate without overflow
        let mut t2 = good();
        t2.price = i128::MAX;
        t2.backup_twap = 100_000 * PRICE_SCALE;
        assert!(
            t2.validate(&m, 1_005_000).is_err(),
            "no overflow panic/wrap"
        );
    }

    #[test]
    fn rejects_backup_deviation() {
        let m = Market::conservative(0);
        let mut t = good();
        t.backup_twap = 105_000 * PRICE_SCALE; // 5% off > 2%
        assert_eq!(
            t.validate(&m, 1_005_000),
            Err(OracleError::DeviatesFromBackup)
        );
    }
}

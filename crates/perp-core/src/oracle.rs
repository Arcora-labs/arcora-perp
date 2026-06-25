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
        // rearranged to avoid division: conf * SCALE <= max_ratio * price
        if abs(self.confidence) * RATE_SCALE > market.max_oracle_confidence_ratio * self.price {
            return Err(OracleError::LowConfidence);
        }
        // deviation vs backup: |price - twap|/price <= max_deviation_ratio
        if self.backup_twap > 0 {
            let dev = abs(self.price - self.backup_twap);
            if dev * RATE_SCALE > market.max_oracle_deviation_ratio * self.price {
                return Err(OracleError::DeviatesFromBackup);
            }
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

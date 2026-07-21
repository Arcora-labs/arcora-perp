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
use crate::hash::{word_i128, word_u64, Digest, Domain, Hasher, Keccak256};
use crate::market::Market;
use k256::ecdsa::VerifyingKey;

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

/// Ethereum-style address of a secp256k1 verifying key (matches L1 `ecrecover`):
/// the low 20 bytes of `keccak256(uncompressed_pubkey[1..])`.
///
/// Mirrors `committee::eth_address` but uses the crate's own no_std `tiny_keccak`
/// (not `sha3`) so it compiles unchanged inside the zkVM guest. Kept private —
/// callers recover an address via [`OracleSig::recover`].
fn eth_address(vk: &VerifyingKey) -> [u8; 20] {
    use tiny_keccak::{Hasher as _, Keccak};
    let point = vk.to_encoded_point(false);
    let mut k = Keccak::v256();
    k.update(&point.as_bytes()[1..]);
    let mut hash = [0u8; 32];
    k.finalize(&mut hash);
    let mut a = [0u8; 20];
    a.copy_from_slice(&hash[12..]);
    a
}

/// A per-market publisher's recoverable secp256k1 signature over an
/// [`oracle_digest`] (ZK-001).
///
/// Same shape/semantics as `committee::EnclaveSig`: `v = 27 + recovery_id`, and
/// [`recover`](OracleSig::recover) returns the signer's [`eth_address`]. The
/// recover path is verify-only (`recover_from_prehash`, no RNG) so it runs
/// unchanged inside the no_std zkVM guest, where the price attestation is
/// re-verified in circuit.
#[derive(Clone, Copy, Debug)]
pub struct OracleSig {
    pub r: [u8; 32],
    pub s: [u8; 32],
    pub v: u8,
}

impl OracleSig {
    /// Sign a prehashed digest (host / test convenience — deterministic RFC-6979,
    /// no RNG). The guest never signs; it only [`recover`](OracleSig::recover)s.
    pub fn sign(key: &k256::ecdsa::SigningKey, digest: &Digest) -> Self {
        let (sig, recid) = key.sign_prehash_recoverable(digest).expect("sign");
        let b = sig.to_bytes();
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&b[..32]);
        s.copy_from_slice(&b[32..]);
        Self {
            r,
            s,
            v: 27 + recid.to_byte(),
        }
    }

    /// Recover the signer's eth address, or `None` if the signature is malformed
    /// or (via k256's enforced low-`s`) a malleated high-`s` twin. This is the
    /// only path the guest needs.
    pub fn recover(&self, digest: &Digest) -> Option<[u8; 20]> {
        use k256::ecdsa::{RecoveryId, Signature};
        let mut rs = [0u8; 64];
        rs[..32].copy_from_slice(&self.r);
        rs[32..].copy_from_slice(&self.s);
        let sig = Signature::from_slice(&rs).ok()?;
        let recid = self.v.checked_sub(27).and_then(RecoveryId::from_byte)?;
        let vk = VerifyingKey::recover_from_prehash(digest, &sig, recid).ok()?;
        Some(eth_address(&vk))
    }
}

/// The per-market oracle-attestation digest a publisher signs, and which the
/// guest re-verifies in circuit (§8, ZK-001).
///
/// Domain-separated under [`Domain::OracleAttest`] and bound to `market_id`, so a
/// signature over one market's price can never be replayed as another market's.
/// The tuple mirrors [`OracleTranscript`] (price / publish_time / confidence /
/// backup_twap) with `market_id` prepended.
pub fn oracle_digest(
    market_id: u64,
    price: i128,
    publish_time_ms: u64,
    confidence: i128,
    backup_twap: i128,
) -> Digest {
    Keccak256::hash_words(
        Domain::OracleAttest,
        &[
            word_u64(market_id),
            word_i128(price),
            word_u64(publish_time_ms),
            word_i128(confidence),
            word_i128(backup_twap),
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixed::PRICE_SCALE;
    use k256::ecdsa::SigningKey;

    // ZK-001: the oracle price fed into proving must be bound to a per-market
    // publisher signature that the guest re-verifies. This pins the primitive:
    // sign → recover round-trips to the signer's eth address, the digest is
    // bound to `market_id` (a sig over market 1 does NOT recover the signer over
    // market 2), and the digest bytes are frozen as a KAT for host cross-checks.
    #[test]
    fn oracle_sig_round_trips_and_binds_digest() {
        let key = SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
        let addr = eth_address(key.verifying_key());

        let d = oracle_digest(1, 100_000, 1_700_000_000_000, 500, 100_000);
        let sig = OracleSig::sign(&key, &d);
        assert_eq!(sig.recover(&d), Some(addr), "recovers to the signer");

        // market_id binding: the same signature over a different market's digest
        // must not recover the signer.
        let d2 = oracle_digest(2, 100_000, 1_700_000_000_000, 500, 100_000);
        assert_ne!(d, d2, "market_id changes the digest");
        assert_ne!(
            sig.recover(&d2),
            Some(addr),
            "a market-1 sig must not verify over market-2's digest"
        );

        // Pinned KAT — a host re-impl / future cross-check reuses this exact
        // digest for oracle_digest(1, 100_000, 1_700_000_000_000, 500, 100_000).
        // 0x37f39f942463637b7823ce4f7712e17a116bd56275473abcd531f4ea0af9bb0d
        let kat: Digest = [
            0x37, 0xf3, 0x9f, 0x94, 0x24, 0x63, 0x63, 0x7b, 0x78, 0x23, 0xce, 0x4f, 0x77, 0x12,
            0xe1, 0x7a, 0x11, 0x6b, 0xd5, 0x62, 0x75, 0x47, 0x3a, 0xbc, 0xd5, 0x31, 0xf4, 0xea,
            0x0a, 0xf9, 0xbb, 0x0d,
        ];
        assert_eq!(d, kat, "oracle_digest KAT is frozen");
    }

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

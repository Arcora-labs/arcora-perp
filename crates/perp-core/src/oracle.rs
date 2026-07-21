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
    /// ZK-001: the market publisher's recoverable secp256k1 signature over
    /// [`oracle_digest`]`(market.id, price, publish_time_ms, confidence, backup_twap)`.
    /// [`validate`](Self::validate) admits a price ONLY if this recovers to the
    /// market's `oracle_pubkey` — the fail-closed gate the guest re-runs in circuit,
    /// which is what binds the (otherwise unsigned) prover witness to the trusted
    /// publisher and makes every downstream sanity bound (incl. `backup_twap`) an
    /// *attested* value rather than prover-chosen.
    pub signature: OracleSig,
}

/// Why a price was rejected — these map 1:1 to close-only / pause triggers (§8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OracleError {
    Stale,
    LowConfidence,
    DeviatesFromBackup,
    NonPositivePrice,
    /// ZK-001: the transcript's publisher signature is missing or malformed — it did
    /// not recover to any address. Fail-closed: no price is returned.
    BadOracleSig,
    /// ZK-001: the signature recovered to an address other than the market's
    /// `oracle_pubkey` — the wrong signer, or a `{market_id, price, publish_time,
    /// confidence, backup_twap}` tuple the publisher never attested (e.g. a price
    /// signed for another market, or any tampered field). Fail-closed: no price is
    /// returned.
    WrongOraclePublisher,
}

impl OracleTranscript {
    /// Validate against a market's bounds at the current time.
    ///
    /// `now_ms` is the batch's reference clock (committed in the manifest); the
    /// circuit re-checks `publish_time ∈ [now - max_staleness, now]`.
    pub fn validate(&self, market: &Market, now_ms: u64) -> Result<i128, OracleError> {
        // ZK-001 — fail-closed publisher-signature gate, FIRST so it can never be
        // masked or bypassed by the price/freshness/confidence/deviation gates below.
        // The oracle price is an unsigned prover witness; a malicious prover could
        // supply any value. The publisher signs `oracle_digest(market.id, price,
        // publish_time_ms, confidence, backup_twap)`, and the guest re-runs this exact
        // check in circuit — so a price is admitted ONLY if the signature recovers to
        // the market's trusted `oracle_pubkey`. No signature (or a malformed one) ⇒
        // `BadOracleSig`; a signature by any other key, or over any other market_id /
        // tampered field, recovers to a DIFFERENT address ⇒ `WrongOraclePublisher`.
        // Either way NO price is returned. The zero `oracle_pubkey` is fail-closed: a
        // real ECDSA signature can never recover to the zero address, so an unset key
        // refuses every price.
        let d = oracle_digest(
            market.id,
            self.price,
            self.publish_time_ms,
            self.confidence,
            self.backup_twap,
        );
        let signer = self
            .signature
            .recover(&d)
            .ok_or(OracleError::BadOracleSig)?;
        if signer != market.oracle_pubkey {
            return Err(OracleError::WrongOraclePublisher);
        }
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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

    /// Recover the signer's eth address, or `None` if malformed. (A malleated
    /// high-`s` twin is NOT rejected here — k256's `from_slice` accepts high-`s`;
    /// the twin simply recovers to a DIFFERENT address and is caught by the
    /// downstream `signer == oracle_pubkey` check.) This is the only path the guest
    /// needs.
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

    // A fixed publisher key + a market whose `oracle_pubkey` is that key's address,
    // so the existing gate tests run THROUGH the real fail-closed signature gate
    // (ZK-001), not around it. `signed` binds the signature to the FINAL field values:
    // because the gate is FIRST, mutating a field after signing would be caught as a
    // signature failure before ever reaching the price/freshness/deviation gates, so
    // each variant is signed over exactly the tuple it means to exercise.
    const TEST_MKT: u64 = 0;

    fn oracle_key() -> SigningKey {
        SigningKey::from_bytes((&[7u8; 32]).into()).unwrap()
    }

    fn signed_market() -> Market {
        let mut m = Market::conservative(TEST_MKT);
        m.oracle_pubkey = eth_address(oracle_key().verifying_key());
        m
    }

    fn signed(
        price: i128,
        publish_time_ms: u64,
        confidence: i128,
        backup_twap: i128,
    ) -> OracleTranscript {
        let d = oracle_digest(TEST_MKT, price, publish_time_ms, confidence, backup_twap);
        OracleTranscript {
            price,
            publish_time_ms,
            confidence,
            backup_twap,
            signature: OracleSig::sign(&oracle_key(), &d),
        }
    }

    fn good() -> OracleTranscript {
        signed(
            100_000 * PRICE_SCALE,
            1_000_000,
            100 * PRICE_SCALE, // $100 conf on $100k = 0.1% < 1%
            100_100 * PRICE_SCALE,
        )
    }

    #[test]
    fn accepts_fresh_tight_price() {
        let m = signed_market();
        assert_eq!(good().validate(&m, 1_005_000), Ok(100_000 * PRICE_SCALE));
    }

    // AUDIT (Tier-3): a malformed transcript with backup_twap = 0 (and confidence = 0)
    // must NOT clear validation on price alone — the deviation gate must reject a
    // non-positive TWAP rather than silently skip it. Signed over the zero-twap tuple
    // so the sig gate passes and we genuinely reach the deviation gate.
    #[test]
    fn zero_backup_twap_is_rejected_not_skipped() {
        let m = signed_market();
        let t = signed(100_000 * PRICE_SCALE, 1_000_000, 0, 0);
        assert_eq!(
            t.validate(&m, 1_005_000),
            Err(OracleError::DeviatesFromBackup),
            "a zero backup TWAP must be rejected, not skip the deviation gate"
        );
    }

    #[test]
    fn rejects_stale() {
        let m = signed_market();
        // 20s later, max staleness 10s
        assert_eq!(good().validate(&m, 1_020_001), Err(OracleError::Stale));
    }

    #[test]
    fn rejects_future_price() {
        let m = signed_market();
        assert_eq!(good().validate(&m, 999_999), Err(OracleError::Stale));
    }

    #[test]
    fn rejects_wide_confidence() {
        let m = signed_market();
        let t = signed(
            100_000 * PRICE_SCALE,
            1_000_000,
            2_000 * PRICE_SCALE, // 2% > 1%
            100_100 * PRICE_SCALE,
        );
        assert_eq!(t.validate(&m, 1_005_000), Err(OracleError::LowConfidence));
    }

    #[test]
    fn extreme_price_is_rejected_not_wrapped() {
        // An extreme price must never overflow the gate arithmetic (which would
        // wrap and could let a manipulated price slip through, or panic the guest).
        // It is rejected cleanly via checked math (after the sig gate admits it).
        let m = signed_market();
        let t = signed(i128::MAX, 1_000_000, 100 * PRICE_SCALE, i128::MAX);
        assert!(
            t.validate(&m, 1_005_000).is_err(),
            "i128::MAX price rejected, not wrapped"
        );
        // and a huge price vs a normal backup still rejects without overflow
        let t2 = signed(
            i128::MAX,
            1_000_000,
            100 * PRICE_SCALE,
            100_000 * PRICE_SCALE,
        );
        assert!(
            t2.validate(&m, 1_005_000).is_err(),
            "no overflow panic/wrap"
        );
    }

    #[test]
    fn rejects_backup_deviation() {
        let m = signed_market();
        let t = signed(
            100_000 * PRICE_SCALE,
            1_000_000,
            100 * PRICE_SCALE,
            105_000 * PRICE_SCALE, // 5% off > 2%
        );
        assert_eq!(
            t.validate(&m, 1_005_000),
            Err(OracleError::DeviatesFromBackup)
        );
    }

    // ZK-001 CORE: `validate()` is a fail-closed publisher-signature gate that runs
    // FIRST — a price is admitted ONLY if the transcript's signature recovers to
    // `market.oracle_pubkey`. Every non-happy path returns WITHOUT a price, and no
    // price/freshness/etc. error can mask (or be reached past) a signature failure.
    #[test]
    fn validate_requires_correct_publisher_signature() {
        let key = SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
        let addr = eth_address(key.verifying_key());
        let mut mkt = Market::conservative(1);
        mkt.oracle_pubkey = addr;
        let now = 1_700_000_000_000u64;
        let (price, conf, twap) = (100_000i128, 100i128, 100_000i128);
        let d = oracle_digest(mkt.id, price, now, conf, twap);
        let good = OracleTranscript {
            price,
            publish_time_ms: now,
            confidence: conf,
            backup_twap: twap,
            signature: OracleSig::sign(&key, &d),
        };
        // signed by the market's key ⇒ price admitted (the later gates still run).
        assert_eq!(good.validate(&mkt, now).unwrap(), price);

        // no/garbage signature ⇒ BadOracleSig, NO price.
        let garbage = OracleTranscript {
            signature: OracleSig {
                r: [0; 32],
                s: [0; 32],
                v: 27,
            },
            ..good
        };
        assert!(matches!(
            garbage.validate(&mkt, now),
            Err(OracleError::BadOracleSig)
        ));

        // valid signature by a DIFFERENT key ⇒ WrongOraclePublisher, NO price.
        let other = SigningKey::from_bytes((&[9u8; 32]).into()).unwrap();
        let wrong = OracleTranscript {
            signature: OracleSig::sign(&other, &d),
            ..good
        };
        assert!(matches!(
            wrong.validate(&mkt, now),
            Err(OracleError::WrongOraclePublisher)
        ));

        // a signature over a DIFFERENT market_id (market 2 replayed to market 1) ⇒
        // the digest binds market.id, so recover yields the signer over the WRONG
        // digest ⇒ ≠ pubkey ⇒ refused.
        let d2 = oracle_digest(2, price, now, conf, twap);
        let replayed = OracleTranscript {
            signature: OracleSig::sign(&key, &d2),
            ..good
        };
        assert!(matches!(
            replayed.validate(&mkt, now),
            Err(OracleError::WrongOraclePublisher)
        ));

        // zero oracle_pubkey ⇒ refused (a real signature never recovers to 0x0..0).
        let mut zmkt = mkt;
        zmkt.oracle_pubkey = [0u8; 20];
        assert!(good.validate(&zmkt, now).is_err());

        // Every signed field is bound: tampering ANY of {price, publish_time_ms,
        // confidence, backup_twap} breaks the signature ⇒ refused. Notably `backup_twap`
        // is attested — this is what makes the deviation-vs-backup gate meaningful.
        let tampered = OracleTranscript {
            backup_twap: twap + 1,
            ..good
        };
        assert!(tampered.validate(&mkt, now).is_err());
        let tp = OracleTranscript {
            price: price + 1,
            ..good
        };
        assert!(tp.validate(&mkt, now).is_err());
        let tc = OracleTranscript {
            confidence: conf + 1,
            ..good
        };
        assert!(tc.validate(&mkt, now).is_err());
        // publish_time is validated at now+1 so freshness WOULD pass — the refusal can
        // only come from the (first) signature gate, proving it cannot be masked.
        let tt = OracleTranscript {
            publish_time_ms: now + 1,
            ..good
        };
        assert!(tt.validate(&mkt, now + 1).is_err());
    }
}

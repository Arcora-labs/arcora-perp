//! Orders, receipts, batch manifests, and finality status (§2, §3, §4).
//!
//! This module encodes the *sequencing accountability* primitives. ZK proves the
//! state transition is valid for the orders it was given; it cannot prove which
//! orders were included or in what sequence (§0). That gap is closed by signed
//! receipts + a published manifest + inclusion timeouts + slashing (§2). Phase 0
//! defines the data and the hashing; the enclave signature and the L1 slashing
//! claim land in Phase 1 / Phase 3.

use crate::hash::{word_u64, Digest, Domain, Hasher};
use crate::market::MarketId;
use crate::note::PubKey;
use alloc::vec::Vec;

/// Buy (long) or sell (short).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Side {
    Buy,
    Sell,
}

/// Time-in-force / execution flags. Full semantics are a Proof-v2 obligation
/// (matching determinism, §4); the wire format exists from Phase 0 so manifests
/// are forward-compatible.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum TimeInForce {
    /// Rests on the book until filled or expired.
    Gtc,
    /// Immediate-or-cancel: fill what crosses now, cancel the rest.
    Ioc,
    /// Fill-or-kill: all-or-nothing immediately.
    Fok,
    /// Post-only: reject if it would take liquidity.
    PostOnly,
}

/// A signed trading intent. In production the body is encrypted to the enclave
/// pubkey; Phase 0 carries plaintext fields plus the *commitment* the receipt
/// binds to, so the accountability math is exact.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Order {
    pub owner: PubKey,
    pub market_id: MarketId,
    pub side: Side,
    /// Order size (always positive), size-scaled.
    pub size: i128,
    /// Limit price, price-scaled. `0` means market order.
    pub limit_price: i128,
    pub tif: TimeInForce,
    /// `reduce_only`: may only shrink an existing position.
    pub reduce_only: bool,
    /// Replay protection; unique per owner.
    pub nonce: u64,
    /// Expiry timestamp, ms. `0` = no expiry.
    pub expiry_ms: u64,
    /// Hash of the ciphertext body (the value the user actually transmits).
    pub ciphertext_commit: Digest,
}

impl Order {
    /// `order_hash = H(ciphertext_commit, owner, nonce, expiry, market_id)` (§2).
    ///
    /// This is what the receipt signs and what the manifest lists. It binds the
    /// user's encrypted order to a market, nonce, and expiry without revealing
    /// direction or size to an observer of the manifest.
    pub fn order_hash<H: Hasher>(&self) -> Digest {
        H::hash_words(
            Domain::OrderHash,
            &[
                self.ciphertext_commit,
                self.owner,
                word_u64(self.nonce),
                word_u64(self.expiry_ms),
                word_u64(self.market_id),
            ],
        )
    }

    /// Signed size for the matcher: `+size` for buys, `−size` for sells.
    pub fn signed_size(&self) -> i128 {
        match self.side {
            Side::Buy => self.size,
            Side::Sell => -self.size,
        }
    }
}

/// The enclave's signed acknowledgement that an order was received (§2, §3).
///
/// `ACCEPTED` proof: the user keeps this and, if the order never appears in any
/// manifest within the inclusion timeout, submits it to L1 to trigger
/// slashing / forced-exit (§2, §6). The signature itself is produced by the TEE
/// in Phase 1; Phase 0 fixes the *committed contents*.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Receipt {
    pub order_hash: Digest,
    pub seq_no: u64,
    pub recv_time_ms: u64,
    pub batch_id_hint: u64,
    /// UNSIGNED plaintext reconciliation hint (Slice 3b-4): the open window
    /// (Counter B, `state.next_batch_id`) when the order was sequenced. The order
    /// may settle in this window OR a later one — this is a lower-bound hint for
    /// off-chain reconciliation, NOT an enclave-signed guarantee. It is deliberately
    /// excluded from `signing_digest`.
    pub window_id: u64,
}

impl Receipt {
    /// The digest the enclave signs.
    pub fn signing_digest<H: Hasher>(&self) -> Digest {
        H::hash_words(
            Domain::OrderHash,
            &[
                self.order_hash,
                word_u64(self.seq_no),
                word_u64(self.recv_time_ms),
                word_u64(self.batch_id_hint),
            ],
        )
    }
}

/// Reason an order was not included / not filled, surfaced in the manifest (§2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum RejectReason {
    Expired = 1,
    SelfTradePrevented = 2,
    PostOnlyWouldTake = 3,
    ReduceOnlyViolation = 4,
    InsufficientMargin = 5,
    MarketCloseOnly = 6,
    OracleUnavailable = 7,
    /// Fill-or-kill could not be filled in full against available liquidity.
    FillOrKillUnfillable = 8,
    /// Order expired before / at the matching instant.
    Cancelled = 9,
    /// The order/op was malformed or could not be applied for a reason with no more
    /// specific code (unknown market, non-positive amount, self-trade at settlement,
    /// arithmetic overflow, …). An honest catch-all — never the misleading
    /// `ReduceOnlyViolation` the manifest used to report for these (audit Tier-3).
    InvalidOrder = 10,
    /// SEC-022: the fill price lay outside the market's `max_fill_deviation_ratio` band
    /// around the attested oracle mark. Appending (rather than reusing `InvalidOrder`)
    /// changes no existing encoding — the discriminants are explicit and stable — and the
    /// manifest is what users and auditors read, so the reason must be specific.
    FillPriceOutOfBand = 11,
    /// SEC-022: the fill would have left a leg closed with negative collateral, or still
    /// open below maintenance margin. Rejected rather than settled into parked debt.
    FillWouldBankrupt = 12,
}

/// Per-batch public commitment to exactly what was sequenced (§2).
///
/// Anyone can recompute [`BatchManifest::hash`] and check their receipt's
/// `order_hash` is in `ordered` (included) or `rejected` (with a reason). The
/// hash is anchored on L1 with the proof, making inclusion auditable.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BatchManifest {
    pub previous_state_root: Digest,
    pub batch_id: u64,
    pub ordered: Vec<Digest>,
    pub rejected: Vec<(Digest, RejectReason)>,
    pub oracle_updates: Vec<Digest>,
    pub matching_rule_version: u32,
    pub enclave_measurement: Digest,
    pub sequencer_pubkey_epoch: u64,
}

impl BatchManifest {
    /// Canonical manifest hash, bound into the proof's public inputs (§2, §10b).
    pub fn hash<H: Hasher>(&self) -> Digest {
        let mut words: Vec<Digest> = Vec::new();
        words.push(self.previous_state_root);
        words.push(word_u64(self.batch_id));
        words.push(word_u64(self.ordered.len() as u64));
        words.extend_from_slice(&self.ordered);
        words.push(word_u64(self.rejected.len() as u64));
        for (h, r) in &self.rejected {
            words.push(*h);
            words.push(word_u64(*r as u64));
        }
        words.push(word_u64(self.oracle_updates.len() as u64));
        words.extend_from_slice(&self.oracle_updates);
        words.push(word_u64(self.matching_rule_version as u64));
        words.push(self.enclave_measurement);
        words.push(word_u64(self.sequencer_pubkey_epoch));
        H::hash_words(Domain::BatchManifest, &words)
    }

    /// Was a given order hash included in this batch?
    pub fn includes(&self, order_hash: &Digest) -> bool {
        self.ordered.contains(order_hash)
    }
}

/// The three-layer finality status surfaced to the client (§3).
///
/// **Binding finality is `Settled`.** `Matched` is a good-faith preconfirmation,
/// not financial certainty — the UI and contracts state this explicitly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Finality {
    /// Enclave received the order and issued a receipt + seq_no.
    Accepted,
    /// Fill preconfirmation signed (soft).
    Matched,
    /// ZK proof verified on L1 (hard, withdrawable).
    Settled,
}

impl Finality {
    /// Only `Settled` state is withdrawable (§3, §6).
    pub fn is_withdrawable(&self) -> bool {
        matches!(self, Finality::Settled)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::{word_u64, Keccak256};

    fn order(nonce: u64) -> Order {
        Order {
            owner: word_u64(1),
            market_id: 0,
            side: Side::Buy,
            size: 100_000_000,
            limit_price: 0,
            tif: TimeInForce::Ioc,
            reduce_only: false,
            nonce,
            expiry_ms: 0,
            ciphertext_commit: [7u8; 32],
        }
    }

    #[test]
    fn order_hash_depends_on_nonce() {
        assert_ne!(
            order(1).order_hash::<Keccak256>(),
            order(2).order_hash::<Keccak256>()
        );
    }

    #[test]
    fn manifest_inclusion_and_hash_stable() {
        let oh = order(1).order_hash::<Keccak256>();
        let m = BatchManifest {
            previous_state_root: [0u8; 32],
            batch_id: 1,
            ordered: alloc::vec![oh],
            rejected: alloc::vec![],
            oracle_updates: alloc::vec![],
            matching_rule_version: 1,
            enclave_measurement: [9u8; 32],
            sequencer_pubkey_epoch: 0,
        };
        assert!(m.includes(&oh));
        assert_eq!(m.hash::<Keccak256>(), m.clone().hash::<Keccak256>());
    }

    #[test]
    fn only_settled_is_withdrawable() {
        assert!(!Finality::Accepted.is_withdrawable());
        assert!(!Finality::Matched.is_withdrawable());
        assert!(Finality::Settled.is_withdrawable());
    }

    #[test]
    fn signing_digest_ignores_window_id() {
        let base = Receipt {
            order_hash: [1u8; 32],
            seq_no: 7,
            recv_time_ms: 100,
            batch_id_hint: 3,
            window_id: 1,
        };
        let other = Receipt {
            window_id: 2,
            ..base
        };
        // window_id is UNSIGNED — it must NOT affect the enclave signing digest.
        assert_eq!(
            base.signing_digest::<Keccak256>(),
            other.signing_digest::<Keccak256>()
        );
    }
}

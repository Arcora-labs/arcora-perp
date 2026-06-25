//! Shielded notes: collateral held privately as commitments (§1, §7).
//!
//! A note is a UTXO-style record of collateral owned by a key. Only its
//! *commitment* ever enters the public Merkle tree; the plaintext lives encrypted
//! in the note archive (§7) under the owner's view-key. Spending reveals a
//! *nullifier* deterministically derived from the note + spend key, so the same
//! note can be nullified at most once (double-spend prevention, Proof-v1).

use crate::hash::{word_i128, word_u64, Digest, Domain, Hasher};

/// A public key identifier (opaque 32 bytes; in Phase 0 a hash of the spend key).
pub type PubKey = Digest;

/// Plaintext note. Lives client-side and in the encrypted archive — never on-chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Note {
    /// Owner public key.
    pub owner: PubKey,
    /// Collateral asset id (0 = the canonical USD-stable collateral in Phase 0).
    pub asset_id: u64,
    /// Amount in quote scale (micro-USD). Non-negative.
    pub amount: i128,
    /// Per-note blinding factor; makes commitments hiding.
    pub blinding: Digest,
}

impl Note {
    pub fn new(owner: PubKey, asset_id: u64, amount: i128, blinding: Digest) -> Self {
        debug_assert!(amount >= 0, "note amounts are non-negative");
        Self {
            owner,
            asset_id,
            amount,
            blinding,
        }
    }

    /// Commitment `cm = H(owner, asset_id, amount, blinding)`.
    ///
    /// This is the value appended to the commitment tree. Binding (can't change
    /// the note without changing `cm`) and hiding (blinding masks the amount).
    pub fn commitment<H: Hasher>(&self) -> Digest {
        H::hash_words(
            Domain::NoteCommitment,
            &[
                self.owner,
                word_u64(self.asset_id),
                word_i128(self.amount),
                self.blinding,
            ],
        )
    }

    /// Nullifier `nf = H(cm, spend_key)`.
    ///
    /// Deterministic in the note and the spender's secret, so an honest spender
    /// produces one fixed nullifier and cannot double-spend; an observer without
    /// `spend_key` cannot link `nf` to `cm`.
    pub fn nullifier<H: Hasher>(&self, spend_key: &Digest) -> Digest {
        let cm = self.commitment::<H>();
        H::hash_words(Domain::Nullifier, &[cm, *spend_key])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::{word_u64, Keccak256};

    fn note(amount: i128, blind: u8) -> Note {
        Note::new(word_u64(7), 0, amount, [blind; 32])
    }

    #[test]
    fn commitment_is_binding() {
        let a = note(1_000_000, 1);
        let b = note(2_000_000, 1);
        assert_ne!(a.commitment::<Keccak256>(), b.commitment::<Keccak256>());
    }

    #[test]
    fn commitment_is_hiding_on_blinding() {
        let a = note(1_000_000, 1);
        let b = note(1_000_000, 2);
        assert_ne!(
            a.commitment::<Keccak256>(),
            b.commitment::<Keccak256>(),
            "different blinding ⇒ different commitment"
        );
    }

    #[test]
    fn nullifier_is_deterministic() {
        let n = note(1_000_000, 9);
        let sk = [42u8; 32];
        assert_eq!(n.nullifier::<Keccak256>(&sk), n.nullifier::<Keccak256>(&sk));
    }
}

//! Pluggable hashing.
//!
//! Phase 0 prioritizes *accounting soundness*, not the final proving circuit, so
//! we default to Keccak-256 — ubiquitous, audited, and identical to what the L1
//! settlement contracts (§13, Faz 2) will use natively. The [`Hasher`] trait
//! keeps every commitment, nullifier, and Merkle node hash-agnostic, so a
//! ZK-friendly algebraic hash (Poseidon/Poseidon2 over the proving field) can be
//! swapped in for the circuit phase **without touching the state-machine logic**.
//!
//! This is a deliberate decision, not a shortcut: the note tree's *shape* and the
//! state transition are what Phase 0 must get right; the concrete hash is a
//! parameter the prover phase pins down (see `docs/DECISIONS.md`).

use tiny_keccak::{Hasher as _, Keccak};

/// A 32-byte digest. Field elements / commitments / roots are all `Digest`.
pub type Digest = [u8; 32];

/// Domain-separated, fixed-arity hashing over 32-byte words.
///
/// Implementors MUST be deterministic and collision-resistant. Domain tags keep
/// note commitments, nullifiers, and Merkle nodes in disjoint hash sub-spaces so
/// a value valid in one role can never be reinterpreted in another.
pub trait Hasher {
    /// Hash an ordered list of 32-byte words under a domain tag.
    fn hash_words(domain: Domain, words: &[Digest]) -> Digest;

    /// Convenience: two-input compression for Merkle internal nodes.
    fn compress(domain: Domain, left: &Digest, right: &Digest) -> Digest {
        Self::hash_words(domain, &[*left, *right])
    }
}

/// Domain-separation tags. Every hash call commits to exactly one of these.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum Domain {
    /// Note commitment: `H(owner_pk, asset_id, amount, blinding)`.
    NoteCommitment = 1,
    /// Nullifier: `H(commitment, spend_key)`.
    Nullifier = 2,
    /// Merkle internal node.
    MerkleNode = 3,
    /// Empty/padding leaf for a sparse subtree level.
    MerkleEmpty = 4,
    /// Order hash for receipts (§2).
    OrderHash = 5,
    /// Batch manifest hash (§2).
    BatchManifest = 6,
    /// Global state root binding (§3).
    StateRoot = 7,
    /// Oracle transcript hash (§8).
    OracleTranscript = 8,
    /// Merkle leaf domain. Level-0 entries are hashed under this tag so an inner
    /// node (`MerkleNode`) can never be presented as a leaf — RFC-6962-style
    /// second-preimage separation. Appended last so existing domain tags (and thus
    /// every committed hash) are unchanged.
    MerkleLeaf = 9,
    /// Encrypted-note-archive keystream (§7). A dedicated tag so the view-key
    /// keystream can never share a preimage structure with nullifiers or any other
    /// hash purpose (one-domain-one-purpose). Not a cross-layer-committed value.
    NoteKeystream = 10,
    /// Privacy-bridge mix-shuffle PRNG (§13). Dedicated tag for the Fisher–Yates
    /// stream so it is separated from state-root hashing. Not cross-layer-committed.
    MixShuffle = 11,
    /// Confidential-prover witness-sealing keystream (§10b). Dedicated tag so the
    /// measurement-bound seal stream is separated from oracle-transcript hashing.
    /// Not a cross-layer-committed value.
    WitnessSeal = 12,
    /// Wallet key-derivation from a seed (§7 recovery root): owner / view-key /
    /// spend-key. A dedicated tag so the most secret derivation in the system can
    /// never share a preimage structure with state-root binding (`StateRoot`) or
    /// any other hash purpose — one-domain-one-purpose. Not cross-layer-committed.
    KeyDerivation = 13,
    /// Privacy-bridge mix-entry commitment (§13). A dedicated tag so a bridge
    /// bucket's hiding commitment can never collide with a spendable note
    /// commitment (`NoteCommitment`) — the two are different purposes and must not
    /// share a preimage namespace. Not a cross-layer-committed value.
    BridgeCommitment = 14,
    /// Committee Shamir secret-sharing coefficient stream (§5, Phase 5). A
    /// dedicated tag so the polynomial coefficients that hide the shared secret are
    /// never drawn from the same preimage structure as note nullifiers
    /// (`Nullifier`) or any other purpose. Not a cross-layer-committed value.
    ShamirShare = 15,
    /// Confidential-prover witness commitment (§10b). A dedicated tag so the
    /// hiding commitment to a private witness can never share a preimage structure
    /// with a batch-manifest hash (`BatchManifest`) — different purposes. Internal
    /// to the proving stand-in; not a cross-layer-committed value.
    WitnessCommitment = 16,
    /// Confidential-prover witness-seal MAC (§10b). Authenticates the sealed
    /// witness ciphertext (encrypt-then-MAC), so tampering or a wrong seal key is
    /// detected on open. A dedicated tag, separate from the seal keystream
    /// (`WitnessSeal`) — one-domain-one-purpose. Not a cross-layer-committed value.
    WitnessSealMac = 17,
    /// Attested-enclave measurement fold (§10b). The 48-byte TDX MRTD folded into
    /// the 32-byte `Digest` measurement domain so it can key measurement-bound
    /// seal release (`SealKeyProvider`) and identify the enclave
    /// (`EnclaveIdentity`). A dedicated tag so an enclave-identity digest can never
    /// share a preimage structure with the witness seal stream/MAC or any other
    /// hash purpose — one-domain-one-purpose. Not a cross-layer-committed value.
    Measurement = 18,
}

/// The default Phase 0 hasher: Keccak-256 with a 1-byte domain prefix.
#[derive(Clone, Copy, Debug, Default)]
pub struct Keccak256;

impl Hasher for Keccak256 {
    fn hash_words(domain: Domain, words: &[Digest]) -> Digest {
        let mut k = Keccak::v256();
        k.update(&[domain as u8]);
        for w in words {
            k.update(w);
        }
        let mut out = [0u8; 32];
        k.finalize(&mut out);
        out
    }
}

/// Encode a little-endian `i128` into a 32-byte word (sign-extended).
///
/// Used to fold scalar fields (amounts, ids, prices) into the word-oriented
/// hash. Little-endian + sign-extension is canonical and matches how the future
/// circuit will range-check these values.
pub fn word_i128(v: i128) -> Digest {
    let mut out = if v < 0 { [0xffu8; 32] } else { [0u8; 32] };
    out[..16].copy_from_slice(&v.to_le_bytes());
    out
}

/// Encode a little-endian `u64` into a 32-byte word.
pub fn word_u64(v: u64) -> Digest {
    let mut out = [0u8; 32];
    out[..8].copy_from_slice(&v.to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domains_separate() {
        let w = [word_u64(42)];
        assert_ne!(
            Keccak256::hash_words(Domain::NoteCommitment, &w),
            Keccak256::hash_words(Domain::Nullifier, &w),
            "domain separation must change the digest"
        );
    }

    #[test]
    fn all_domains_pairwise_distinct() {
        // Domain separation is only real if EVERY tag yields a different digest for
        // the same input — the keystream/shuffle/seal hardening (note-archive, bridge,
        // prover) all rely on this. A duplicated discriminant or a hasher that ignored
        // the domain would collapse two purposes; this catches it. Keep in sync with
        // the enum.
        use Domain::*;
        let all = [
            NoteCommitment,
            Nullifier,
            MerkleNode,
            MerkleEmpty,
            OrderHash,
            BatchManifest,
            StateRoot,
            OracleTranscript,
            MerkleLeaf,
            NoteKeystream,
            MixShuffle,
            WitnessSeal,
            KeyDerivation,
            BridgeCommitment,
            ShamirShare,
            WitnessCommitment,
            WitnessSealMac,
            Measurement,
        ];
        let w = [word_u64(42)];
        for i in 0..all.len() {
            // the tag is also distinct as a u8 discriminant (no two share a value)
            assert_eq!(
                all[i] as u8,
                i as u8 + 1,
                "domain discriminants must be 1..=N dense"
            );
            for j in (i + 1)..all.len() {
                assert_ne!(
                    Keccak256::hash_words(all[i], &w),
                    Keccak256::hash_words(all[j], &w),
                    "domains {:?} and {:?} collide",
                    all[i],
                    all[j]
                );
            }
        }
    }

    #[test]
    fn deterministic() {
        let w = [word_i128(-5), word_u64(7)];
        assert_eq!(
            Keccak256::hash_words(Domain::OrderHash, &w),
            Keccak256::hash_words(Domain::OrderHash, &w)
        );
    }

    #[test]
    fn sign_extension_distinguishes() {
        assert_ne!(word_i128(-1), word_i128(i128::MAX));
        assert_eq!(word_i128(1)[16], 0);
        assert_eq!(word_i128(-1)[16], 0xff);
    }
}

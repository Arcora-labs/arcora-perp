//! # note-archive — encrypted note recovery (§7)
//!
//! 4844 blobs are transient (~weeks), so a user's notes cannot live only there.
//! This crate models the **mandatory** Encrypted Note Archive / Indexer: a public
//! archive of note *ciphertexts* keyed by `(batch_id, commitment)` that the owner
//! scans with a **view-key** derived from their seed. After device loss the flow
//! is: `seed → view-key → scan archive → recover notes/positions`. Without it the
//! product is "phone breaks ⇒ position lost".
//!
//! ## Keys from one seed
//!
//! A [`Wallet`] derives three values from a 32-byte seed:
//! - `owner`     — the public note owner id (appears in commitments),
//! - `view_key`  — decrypts note ciphertexts (scan capability, no spend power),
//! - `spend_key` — produces nullifiers to spend notes.
//!
//! The view/spend split is the §7 + §15 "dark" property: a view-key holder can
//! *find* and *read* the owner's notes but cannot *move* them.
//!
//! ## Encryption (documented stand-in)
//!
//! A note ciphertext is `serialize(note) XOR keystream(view_key, commitment)`.
//! Trial-decryption confirms ownership: decrypt, recompute the commitment, and
//! accept iff it equals the archived commitment. Only the matching view-key
//! yields a consistent note. This is a clearly-labelled stand-in for a real
//! note-encryption scheme (e.g. ECIES / Zcash-style note encryption); it models
//! the *scanning capability boundary*, not production confidentiality.

#![no_std]
#![cfg_attr(not(feature = "std"), forbid(unsafe_code))]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

use alloc::vec::Vec;
use perp_core::hash::{word_u64, Digest, Domain, Hasher, Keccak256};
use perp_core::note::{Note, PubKey};

/// Key-derivation labels (distinct constants → independent derived keys).
const LABEL_OWNER: u64 = 1;
const LABEL_VIEW: u64 = 2;
const LABEL_SPEND: u64 = 3;

/// A wallet derived deterministically from a single seed (§7 recovery root).
#[derive(Clone, Copy, Debug)]
pub struct Wallet {
    pub owner: PubKey,
    pub view_key: Digest,
    pub spend_key: Digest,
}

impl Wallet {
    /// Derive `(owner, view_key, spend_key)` from a 32-byte seed.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let spend_key = derive(&seed, LABEL_SPEND);
        let view_key = derive(&seed, LABEL_VIEW);
        let owner = derive(&seed, LABEL_OWNER);
        Self {
            owner,
            view_key,
            spend_key,
        }
    }

    /// Build a note owned by this wallet (helper for deposits/unbinds).
    pub fn note(&self, asset_id: u64, amount: i128, blinding: Digest) -> Note {
        Note::new(self.owner, asset_id, amount, blinding)
    }
}

fn derive(seed: &[u8; 32], label: u64) -> Digest {
    Keccak256::hash_words(Domain::StateRoot, &[*seed, word_u64(label)])
}

/// 88-byte canonical note serialization: owner(32) ‖ asset_id(8 LE) ‖
/// amount(16 LE, i128) ‖ blinding(32).
fn serialize_note(n: &Note) -> [u8; 88] {
    let mut out = [0u8; 88];
    out[0..32].copy_from_slice(&n.owner);
    out[32..40].copy_from_slice(&n.asset_id.to_le_bytes());
    out[40..56].copy_from_slice(&n.amount.to_le_bytes());
    out[56..88].copy_from_slice(&n.blinding);
    out
}

fn deserialize_note(bytes: &[u8; 88]) -> Note {
    let mut owner = [0u8; 32];
    owner.copy_from_slice(&bytes[0..32]);
    let mut a = [0u8; 8];
    a.copy_from_slice(&bytes[32..40]);
    let asset_id = u64::from_le_bytes(a);
    let mut m = [0u8; 16];
    m.copy_from_slice(&bytes[40..56]);
    let amount = i128::from_le_bytes(m);
    let mut blinding = [0u8; 32];
    blinding.copy_from_slice(&bytes[56..88]);
    // Construct directly (not Note::new): trial-decrypting someone else's note
    // yields garbage that may be a "negative amount"; we must not assert on it —
    // the commitment-consistency check downstream rejects such garbage.
    Note {
        owner,
        asset_id,
        amount,
        blinding,
    }
}

/// Keystream derived from the view-key and the (public) commitment nonce.
fn keystream(view_key: &Digest, commitment: &Digest, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut counter = 0u64;
    while out.len() < len {
        let block = Keccak256::hash_words(
            Domain::Nullifier,
            &[*view_key, *commitment, word_u64(counter)],
        );
        out.extend_from_slice(&block);
        counter += 1;
    }
    out.truncate(len);
    out
}

/// Encrypt a note to its owner's view-key, bound to its commitment.
pub fn encrypt_note(note: &Note, view_key: &Digest) -> Vec<u8> {
    let commitment = note.commitment::<Keccak256>();
    let plain = serialize_note(note);
    let ks = keystream(view_key, &commitment, plain.len());
    plain.iter().zip(ks).map(|(p, k)| p ^ k).collect()
}

/// One archived record: the public commitment (the archive key) and the
/// ciphertext. `batch_id` lets a scanner reconstruct ordering / retention (§7).
#[derive(Clone, Debug)]
pub struct ArchivedNote {
    pub batch_id: u64,
    pub commitment: Digest,
    pub ciphertext: Vec<u8>,
}

/// The public encrypted-note archive / indexer (§7).
#[derive(Clone, Debug, Default)]
pub struct NoteArchive {
    records: Vec<ArchivedNote>,
}

impl NoteArchive {
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Record a freshly minted note (called by the sequencer on deposit/unbind).
    /// The owner's view-key is used only to produce the ciphertext; the archive
    /// itself never learns the plaintext.
    pub fn record(&mut self, batch_id: u64, note: &Note, owner_view_key: &Digest) {
        let commitment = note.commitment::<Keccak256>();
        let ciphertext = encrypt_note(note, owner_view_key);
        self.records.push(ArchivedNote {
            batch_id,
            commitment,
            ciphertext,
        });
    }

    /// Scan the whole archive with a view-key, returning every note that
    /// trial-decrypts consistently (its recomputed commitment matches). This is
    /// the device-loss recovery path: `seed → view_key → scan → notes`.
    pub fn scan(&self, view_key: &Digest) -> Vec<RecoveredNote> {
        let mut found = Vec::new();
        for rec in &self.records {
            if rec.ciphertext.len() != 88 {
                continue;
            }
            let ks = keystream(view_key, &rec.commitment, 88);
            let mut plain = [0u8; 88];
            for i in 0..88 {
                plain[i] = rec.ciphertext[i] ^ ks[i];
            }
            let note = deserialize_note(&plain);
            // ownership/consistency check: recomputed commitment must match.
            if note.commitment::<Keccak256>() == rec.commitment {
                found.push(RecoveredNote {
                    batch_id: rec.batch_id,
                    note,
                });
            }
        }
        found
    }

    /// Total recoverable collateral for a view-key, MINUS notes already spent.
    /// `spent` is the set of nullifiers known spent (from L1 / the state); a note
    /// whose nullifier is spent is excluded. This reconstructs the *current*
    /// shielded balance after recovery.
    pub fn recover_balance(&self, wallet: &Wallet, is_spent: impl Fn(&Digest) -> bool) -> i128 {
        self.scan(&wallet.view_key)
            .iter()
            .filter(|r| !is_spent(&r.note.nullifier::<Keccak256>(&wallet.spend_key)))
            .map(|r| r.note.amount)
            .sum()
    }
}

/// A note recovered by scanning.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveredNote {
    pub batch_id: u64,
    pub note: Note,
}

#[cfg(test)]
mod tests {
    use super::*;
    use perp_core::fixed::QUOTE_SCALE;

    fn seeded(n: u8) -> [u8; 32] {
        [n; 32]
    }

    #[test]
    fn serialize_roundtrips() {
        let w = Wallet::from_seed(seeded(1));
        let note = w.note(0, 12_345 * QUOTE_SCALE, [7u8; 32]);
        let bytes = serialize_note(&note);
        assert_eq!(deserialize_note(&bytes), note);
    }

    #[test]
    fn owner_view_spend_are_distinct() {
        let w = Wallet::from_seed(seeded(1));
        assert_ne!(w.owner, w.view_key);
        assert_ne!(w.view_key, w.spend_key);
        assert_ne!(w.owner, w.spend_key);
        // deterministic from seed (recovery!)
        assert_eq!(w.owner, Wallet::from_seed(seeded(1)).owner);
    }

    #[test]
    fn recover_my_notes_from_seed() {
        let alice = Wallet::from_seed(seeded(1));
        let bob = Wallet::from_seed(seeded(2));
        let mut archive = NoteArchive::new();

        // a few deposits across batches for both wallets
        archive.record(
            0,
            &alice.note(0, 10_000 * QUOTE_SCALE, [1; 32]),
            &alice.view_key,
        );
        archive.record(1, &bob.note(0, 5_000 * QUOTE_SCALE, [2; 32]), &bob.view_key);
        archive.record(
            2,
            &alice.note(0, 7_000 * QUOTE_SCALE, [3; 32]),
            &alice.view_key,
        );

        // Alice, on a new device, derives her view-key from seed and scans.
        let recovered = archive.scan(&Wallet::from_seed(seeded(1)).view_key);
        assert_eq!(recovered.len(), 2, "Alice recovers exactly her two notes");
        let total: i128 = recovered.iter().map(|r| r.note.amount).sum();
        assert_eq!(total, 17_000 * QUOTE_SCALE);
    }

    #[test]
    fn cannot_read_others_notes() {
        let alice = Wallet::from_seed(seeded(1));
        let bob = Wallet::from_seed(seeded(2));
        let mut archive = NoteArchive::new();
        archive.record(0, &bob.note(0, 5_000 * QUOTE_SCALE, [2; 32]), &bob.view_key);
        // Alice's view-key must not decrypt Bob's note
        assert!(archive.scan(&alice.view_key).is_empty());
    }

    #[test]
    fn recover_balance_excludes_spent() {
        let alice = Wallet::from_seed(seeded(1));
        let mut archive = NoteArchive::new();
        let n1 = alice.note(0, 10_000 * QUOTE_SCALE, [1; 32]);
        let n2 = alice.note(0, 4_000 * QUOTE_SCALE, [2; 32]);
        archive.record(0, &n1, &alice.view_key);
        archive.record(1, &n2, &alice.view_key);

        // n1 has been spent (its nullifier is on L1)
        let spent_nf = n1.nullifier::<Keccak256>(&alice.spend_key);
        let balance = archive.recover_balance(&alice, |nf| *nf == spent_nf);
        assert_eq!(balance, 4_000 * QUOTE_SCALE, "only the unspent note counts");
    }
}

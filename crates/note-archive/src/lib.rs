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
//! - `view_key`  — the scan secret; the X25519 note-decryption keypair
//!   ([`Wallet::view_x25519_secret`] / [`Wallet::view_x25519_public`]) is
//!   derived from it (scan capability, no spend power),
//! - `spend_key` — produces nullifiers to spend notes.
//!
//! The view/spend split is the §7 + §15 "dark" property: a view-key holder can
//! *find* and *read* the owner's notes but cannot *move* them.
//!
//! ## Encryption (sealed-box)
//!
//! A note ciphertext is a `sealed-box` — X25519 ECDH + HKDF-SHA256 +
//! XChaCha20-Poly1305 — sealed to the owner's X25519 *viewing* public key,
//! with `aad = domain_aad(Domain::NoteEncryptAad, commitment)` so the
//! ciphertext is cryptographically bound to its archive entry. Scanning
//! trial-`unseal`s each record with the viewing secret: a successful open is
//! AEAD-authenticated, and the recomputed note commitment must additionally
//! equal the archived commitment. The archive host stores only commitments and
//! sealed ciphertexts — never plaintext, and never any decryption capability.

#![no_std]
#![cfg_attr(not(feature = "std"), forbid(unsafe_code))]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

use alloc::vec::Vec;
use perp_core::hash::{word_u64, Digest, Domain, Hasher, Keccak256};
use perp_core::note::{owner_from_spend_key, Note, PubKey};
use rand_core::{CryptoRng, RngCore};

/// Key-derivation labels (distinct constants → independent derived keys). The owner
/// is NOT derived directly from the seed — it is derived from the spend key so that
/// holding the spend key is exactly the authority to spend the wallet's notes (DP-003).
const LABEL_VIEW: u64 = 2;
const LABEL_SPEND: u64 = 3;

/// A wallet derived deterministically from a single seed (§7 recovery root).
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
        // audit DP-003: owner == H(spend_key), so possessing the spend key IS the
        // authority to spend this wallet's notes; the engine re-derives and checks it.
        let owner = owner_from_spend_key::<Keccak256>(&spend_key);
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

    /// X25519 viewing *secret* — the note-decryption capability (Task 8 note
    /// encryption). Derived from `view_key` (itself the seed-derived scan secret)
    /// under a dedicated `X25519ViewKey` domain, so the view/spend split is kept
    /// intact and no new seed material is stored on the wallet.
    pub fn view_x25519_secret(&self) -> [u8; 32] {
        let info = [Domain::X25519ViewKey as u8];
        sealed_box::x25519_keypair_from_ikm(&self.view_key, &info).0
    }

    /// X25519 viewing *public* key — the address others encrypt notes to. Pairs
    /// with [`Wallet::view_x25519_secret`] and is deterministic from the seed.
    pub fn view_x25519_public(&self) -> [u8; 32] {
        let info = [Domain::X25519ViewKey as u8];
        sealed_box::x25519_keypair_from_ikm(&self.view_key, &info).1
    }
}

fn derive(seed: &[u8; 32], label: u64) -> Digest {
    // §7 recovery root: derive owner / view / spend keys under a DEDICATED domain,
    // never the state-root tag — one-domain-one-purpose (see Domain::KeyDerivation).
    Keccak256::hash_words(Domain::KeyDerivation, &[*seed, word_u64(label)])
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

/// Seal a note to its owner's X25519 viewing public key (sealed-box: X25519 +
/// HKDF-SHA256 + XChaCha20-Poly1305). The AAD binds the note's commitment
/// under `Domain::NoteEncryptAad`, so a ciphertext only opens against the
/// archive entry it was minted for. The rng is threaded (not hardcoded) so the
/// no_std lib path never depends on getrandom; std callers pass `OsRng`.
pub fn seal_note(note: &Note, owner_view_pub: &[u8; 32], rng: impl RngCore + CryptoRng) -> Vec<u8> {
    let commitment = note.commitment::<Keccak256>();
    let aad = sealed_box::domain_aad(Domain::NoteEncryptAad as u8, &commitment);
    sealed_box::seal(owner_view_pub, &serialize_note(note), &aad, rng).to_bytes()
}

/// One archived record: the public commitment (the archive key) and the
/// ciphertext. `batch_id` lets a scanner reconstruct ordering / retention (§7).
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ArchivedNote {
    pub batch_id: u64,
    pub commitment: Digest,
    pub ciphertext: Vec<u8>,
}

/// The public encrypted-note archive / indexer (§7).
#[derive(Clone, Debug, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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

    /// Record a freshly minted note (called by the sequencer on deposit/unbind),
    /// sealed to the owner's X25519 viewing PUBLIC key — the recorder holds no
    /// decryption capability, and the archive never learns the plaintext.
    pub fn record(
        &mut self,
        batch_id: u64,
        note: &Note,
        owner_view_pub: &[u8; 32],
        rng: impl RngCore + CryptoRng,
    ) {
        let commitment = note.commitment::<Keccak256>();
        let ciphertext = seal_note(note, owner_view_pub, rng);
        self.records.push(ArchivedNote {
            batch_id,
            commitment,
            ciphertext,
        });
    }

    /// Scan the whole archive with the X25519 viewing secret, returning every
    /// note that trial-unseals (AEAD-authenticated, AAD-bound to the archived
    /// commitment) AND whose recomputed commitment matches. This is the
    /// device-loss recovery path: `seed → view secret → scan → notes`.
    pub fn scan(&self, view_secret: &[u8; 32]) -> Vec<RecoveredNote> {
        let mut found = Vec::new();
        for rec in &self.records {
            let Some(sb) = sealed_box::SealedBox::from_bytes(&rec.ciphertext) else {
                continue;
            };
            let aad = sealed_box::domain_aad(Domain::NoteEncryptAad as u8, &rec.commitment);
            let Some(plain) = sealed_box::unseal(view_secret, &sb, &aad) else {
                continue;
            };
            let Ok(bytes) = <[u8; 88]>::try_from(plain.as_slice()) else {
                continue;
            };
            let note = deserialize_note(&bytes);
            // defense in depth: the recomputed commitment must match the archive
            // key even after an authenticated open.
            if note.commitment::<Keccak256>() == rec.commitment {
                found.push(RecoveredNote {
                    batch_id: rec.batch_id,
                    note,
                });
            }
        }
        found
    }

    /// Read-only view of the archived records — exactly what the (untrusted)
    /// archive host stores: `(batch_id, commitment, sealed ciphertext)`.
    pub fn notes(&self) -> &[ArchivedNote] {
        &self.records
    }

    /// Total recoverable collateral for a view-key, MINUS notes already spent.
    /// `spent` is the set of nullifiers known spent (from L1 / the state); a note
    /// whose nullifier is spent is excluded. This reconstructs the *current*
    /// shielded balance after recovery.
    pub fn recover_balance(&self, wallet: &Wallet, is_spent: impl Fn(&Digest) -> bool) -> i128 {
        self.scan(&wallet.view_x25519_secret())
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
    use rand_core::OsRng;

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
    fn key_derivation_is_domain_separated_from_state_root() {
        // The §7 recovery root must derive under Domain::KeyDerivation, NOT the
        // state-root tag (one-domain-one-purpose). If derive() ever reverted to
        // Domain::StateRoot, the spend-key here would equal the StateRoot-domain
        // hash of the same preimage — this pins the separation.
        let seed = seeded(9);
        let w = Wallet::from_seed(seed);
        let under_state_root =
            Keccak256::hash_words(Domain::StateRoot, &[seed, word_u64(LABEL_SPEND)]);
        assert_ne!(
            w.spend_key, under_state_root,
            "spend-key must not be derivable under the state-root domain"
        );
        let under_kdf =
            Keccak256::hash_words(Domain::KeyDerivation, &[seed, word_u64(LABEL_SPEND)]);
        assert_eq!(
            w.spend_key, under_kdf,
            "spend-key uses the KeyDerivation domain"
        );
    }

    #[test]
    fn viewing_keypair_is_deterministic_and_scoped() {
        let w = Wallet::from_seed([7u8; 32]);
        assert_eq!(
            w.view_x25519_public(),
            Wallet::from_seed([7u8; 32]).view_x25519_public()
        );
        assert_ne!(
            w.view_x25519_public(),
            Wallet::from_seed([8u8; 32]).view_x25519_public()
        );
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
    fn sealed_note_scans_for_owner_only() {
        let w = Wallet::from_seed([1u8; 32]);
        let other = Wallet::from_seed([2u8; 32]);
        let note = w.note(0, 5_000_000, [9u8; 32]);
        let mut arch = NoteArchive::new();
        arch.record(1, &note, &w.view_x25519_public(), OsRng);
        assert_eq!(arch.scan(&w.view_x25519_secret()).len(), 1);
        assert_eq!(arch.scan(&other.view_x25519_secret()).len(), 0);
    }

    #[test]
    fn archive_host_without_key_reads_nothing() {
        let w = Wallet::from_seed([3u8; 32]);
        let mut arch = NoteArchive::new();
        arch.record(1, &w.note(0, 42, [1u8; 32]), &w.view_x25519_public(), OsRng);
        // ciphertext bytes never equal the plaintext note serialization
        let raw = &arch.notes()[0].ciphertext;
        assert!(!raw.windows(8).any(|win| win == &42i128.to_le_bytes()[..8]));
    }

    /// The genuinely-NEW property of the sealed-box archive vs the old XOR
    /// keystream: the AAD binds each ciphertext to ITS archive commitment, so a
    /// host that swaps a (perfectly valid) ciphertext under a different
    /// commitment key produces an entry that fails the AEAD open outright —
    /// scan never even sees a plaintext to commitment-check. (Under the XOR
    /// scheme the swap still DECRYPTED and only the downstream recompute check
    /// caught it; here `unseal` itself must return `None`.)
    #[test]
    fn swapped_commitment_ciphertext_is_rejected_by_aad_binding() {
        let w = Wallet::from_seed(seeded(4));
        let note = w.note(0, 1_234 * QUOTE_SCALE, [5u8; 32]);
        let real_commitment = note.commitment::<Keccak256>();
        let ciphertext = seal_note(&note, &w.view_x25519_public(), OsRng);

        // a DIFFERENT (also plausible) commitment the host files the ct under
        let other_commitment = w
            .note(0, 999 * QUOTE_SCALE, [6u8; 32])
            .commitment::<Keccak256>();
        assert_ne!(real_commitment, other_commitment);

        // Direct AEAD-level assertion: the same wire opens under its own
        // commitment AAD and REFUSES the swapped one.
        let sb = sealed_box::SealedBox::from_bytes(&ciphertext).expect("wire parses");
        let own_aad = sealed_box::domain_aad(Domain::NoteEncryptAad as u8, &real_commitment);
        assert!(sealed_box::unseal(&w.view_x25519_secret(), &sb, &own_aad).is_some());
        let swapped_aad = sealed_box::domain_aad(Domain::NoteEncryptAad as u8, &other_commitment);
        assert_eq!(
            sealed_box::unseal(&w.view_x25519_secret(), &sb, &swapped_aad),
            None,
            "AAD binding must reject the ciphertext under a swapped commitment"
        );

        // And end-to-end: an archive carrying the swapped entry yields NOTHING
        // on scan — the owner cannot be fooled into recovering a mis-keyed note.
        let mut archive = NoteArchive::new();
        archive.records.push(ArchivedNote {
            batch_id: 0,
            commitment: other_commitment,
            ciphertext,
        });
        assert!(
            archive.scan(&w.view_x25519_secret()).is_empty(),
            "scan must not return a swapped-commitment entry"
        );
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
            &alice.view_x25519_public(),
            OsRng,
        );
        archive.record(
            1,
            &bob.note(0, 5_000 * QUOTE_SCALE, [2; 32]),
            &bob.view_x25519_public(),
            OsRng,
        );
        archive.record(
            2,
            &alice.note(0, 7_000 * QUOTE_SCALE, [3; 32]),
            &alice.view_x25519_public(),
            OsRng,
        );

        // Alice, on a new device, derives her viewing secret from seed and scans.
        let recovered = archive.scan(&Wallet::from_seed(seeded(1)).view_x25519_secret());
        assert_eq!(recovered.len(), 2, "Alice recovers exactly her two notes");
        let total: i128 = recovered.iter().map(|r| r.note.amount).sum();
        assert_eq!(total, 17_000 * QUOTE_SCALE);
    }

    #[test]
    fn cannot_read_others_notes() {
        let alice = Wallet::from_seed(seeded(1));
        let bob = Wallet::from_seed(seeded(2));
        let mut archive = NoteArchive::new();
        archive.record(
            0,
            &bob.note(0, 5_000 * QUOTE_SCALE, [2; 32]),
            &bob.view_x25519_public(),
            OsRng,
        );
        // Alice's viewing secret must not unseal Bob's note
        assert!(archive.scan(&alice.view_x25519_secret()).is_empty());
    }

    #[test]
    fn recover_balance_excludes_spent() {
        let alice = Wallet::from_seed(seeded(1));
        let mut archive = NoteArchive::new();
        let n1 = alice.note(0, 10_000 * QUOTE_SCALE, [1; 32]);
        let n2 = alice.note(0, 4_000 * QUOTE_SCALE, [2; 32]);
        archive.record(0, &n1, &alice.view_x25519_public(), OsRng);
        archive.record(1, &n2, &alice.view_x25519_public(), OsRng);

        // n1 has been spent (its nullifier is on L1)
        let spent_nf = n1.nullifier::<Keccak256>(&alice.spend_key);
        let balance = archive.recover_balance(&alice, |nf| *nf == spent_nf);
        assert_eq!(balance, 4_000 * QUOTE_SCALE, "only the unspent note counts");
    }
}

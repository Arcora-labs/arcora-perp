//! Hash-chained, **encrypted**, append-only order log (Task 12).
//!
//! Every order the gateway ACCEPTS is appended here: its canonical 51-byte
//! terms are sealed (X25519 sealed-box) to the enclave's **log public key**, and
//! the resulting ciphertext is folded into a running hash chain, so the log is
//!
//! * **confidential** — the plaintext terms are never stored; the gateway holds
//!   only the log PUBLIC key and can never read an entry back, and
//! * **tamper-evident** — `entry_hash = keccak256(Domain::OrderLogChain ‖
//!   prev_head ‖ commitment ‖ entry_ct)` with the chain starting at the zero
//!   digest, so mutating, reordering, or dropping any entry diverges
//!   [`OrderLog::recompute_head`] from the stored head.
//!
//! The log keypair derives from `ENCLAVE_SEED` under the dedicated
//! `Domain::X25519LogKey` label (`sealed_box::x25519_keypair_from_ikm(seed,
//! [X25519LogKey])`). The gateway derives — and keeps — only the public half;
//! the SECRET half is derivable from the seed and is intended to be released
//! only to an attested prover (spec §9: the log is the prover's order-flow
//! witness). Nothing in this module (or the gateway) materializes that secret.

use perp_core::hash::{Digest, Domain};
use rand::{CryptoRng, RngCore};

/// One sealed, chained log entry.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct LogEntry {
    /// The order's terms commitment (`Order::ciphertext_commit`) — a public,
    /// deterministic keccak over the same canonical terms sealed in `entry_ct`,
    /// so a party who CAN open the entry can verify it against the commitment.
    pub commitment: Digest,
    /// `sealed_box::seal(log_pub, canonical_terms, aad, rng).to_bytes()` with
    /// `aad = domain_aad(Domain::LogEncryptAad, seq.to_le_bytes())` — the entry
    /// index is AAD-bound, so a ciphertext cannot be replayed at another slot.
    pub entry_ct: Vec<u8>,
    /// `keccak256(Domain::OrderLogChain ‖ prev_head ‖ commitment ‖ entry_ct)` —
    /// the chain link.
    pub entry_hash: Digest,
}

/// The append-only encrypted order log. Persisted (entries + head) in the
/// sealed state snapshot; the recipient pubkey is `#[serde(skip)]`ped and
/// re-derived from `ENCLAVE_SEED` on boot/restore — no key material, public or
/// secret, is ever read from disk.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct OrderLog {
    /// X25519 log PUBLIC key entries are sealed to. Never persisted: `Gw::boot`
    /// / `boot_restored` re-derive it (same posture as the order-epoch key).
    #[serde(skip)]
    log_pub: [u8; 32],
    entries: Vec<LogEntry>,
    /// Running chain head: the `entry_hash` of the newest entry (zero digest
    /// while the log is empty).
    head: Digest,
}

impl OrderLog {
    /// Fresh, empty log sealing to `log_pub`; the head is the zero digest.
    pub fn new(log_pub: [u8; 32]) -> Self {
        Self {
            log_pub,
            entries: Vec::new(),
            head: [0u8; 32],
        }
    }

    /// Re-arm the (serde-skipped) recipient public key after a snapshot
    /// restore. Called by `Gw::boot_restored` with the key re-derived from
    /// `ENCLAVE_SEED` — the snapshot itself never carries key material.
    pub fn set_recipient(&mut self, log_pub: [u8; 32]) {
        self.log_pub = log_pub;
    }

    /// The recipient (log) public key entries are sealed to. Read by the
    /// persistence tests to prove restore re-derives the SAME key boot used.
    #[allow(dead_code)] // exercised by the snapshot round-trip test
    pub fn recipient(&self) -> [u8; 32] {
        self.log_pub
    }

    /// Number of entries appended so far.
    #[allow(dead_code)] // exercised by the ingest + persistence tests
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[allow(dead_code)] // customary companion of `len` (clippy: len_without_is_empty)
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Seal `canonical` (the accepted order's canonical terms bytes) to the log
    /// pubkey and chain it: `entry_hash = keccak256(Domain::OrderLogChain ‖ head
    /// ‖ commitment ‖ entry_ct)` becomes the new head, which is returned. The new entry's
    /// index is bound into the AEAD AAD (`Domain::LogEncryptAad ‖ seq_le`), so
    /// an entry ciphertext is only valid at the position it was minted for.
    ///
    /// The rng is threaded (the gateway passes `OsRng`) — same pattern as
    /// `note-archive`, keeping the sealing path free of a hardcoded entropy
    /// source.
    pub fn append(
        &mut self,
        commitment: &Digest,
        canonical: &[u8],
        rng: impl RngCore + CryptoRng,
    ) -> Digest {
        let seq = self.entries.len() as u64;
        let aad = sealed_box::domain_aad(Domain::LogEncryptAad as u8, &seq.to_le_bytes());
        let entry_ct = sealed_box::seal(&self.log_pub, canonical, &aad, rng).to_bytes();
        let entry_hash = chain(&self.head, commitment, &entry_ct);
        self.entries.push(LogEntry {
            commitment: *commitment,
            entry_ct,
            entry_hash,
        });
        self.head = entry_hash;
        entry_hash
    }

    /// The current chain head (zero digest while the log is empty).
    ///
    /// NOTE (controller decision, Task 12): this head is **not** folded into
    /// the batch manifest / on-chain `publicCommitment` here — that anchoring
    /// is deferred to the ZK-verifier workstream (the log is designed as the
    /// prover's order-flow witness, spec §9), because the manifest hash is a
    /// cross-layer consensus commitment with pinned vectors.
    // Read by the tests today; the zk workstream consumes it for anchoring.
    #[allow(dead_code)]
    pub fn head(&self) -> Digest {
        self.head
    }

    /// Re-fold every stored entry from the zero digest. Equal to [`Self::head`]
    /// iff no entry has been mutated, reordered, or dropped — the
    /// tamper-evidence check a verifier (or test) runs over the log.
    #[allow(dead_code)] // exercised by the tamper-evidence tests; a verifier's entry point
    pub fn recompute_head(&self) -> Digest {
        let mut h = [0u8; 32];
        for e in &self.entries {
            h = chain(&h, &e.commitment, &e.entry_ct);
        }
        h
    }
}

/// One chain link: `keccak256(Domain::OrderLogChain ‖ prev ‖ commitment ‖
/// entry_ct)`. Raw keccak over the byte concatenation (the gateway's `sha3` —
/// same primitive style as `mk_order`'s terms commitment and
/// `epoch_signing_digest`) with a leading 1-byte domain tag, so a chain link
/// lives in its own hash sub-space and can never be reinterpreted as an order
/// hash / manifest hash / any other raw-keccak value. `prev` and `commitment`
/// are fixed 32-byte fields, so the variable-length ciphertext tail is
/// unambiguous. [`OrderLog::recompute_head`] folds through this same function,
/// so append and verify can never diverge on the tag.
fn chain(prev: &Digest, commitment: &Digest, entry_ct: &[u8]) -> Digest {
    use sha3::Digest as _;
    let mut k = sha3::Keccak256::new();
    k.update([Domain::OrderLogChain as u8]);
    k.update(prev);
    k.update(commitment);
    k.update(entry_ct);
    k.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    /// The log keypair exactly as the gateway derives it from the enclave seed.
    fn log_keypair(seed: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
        sealed_box::x25519_keypair_from_ikm(seed, &[Domain::X25519LogKey as u8])
    }

    #[test]
    fn append_chains_and_is_tamper_evident() {
        let (_, pk) = log_keypair(&[9u8; 32]);
        let mut log = OrderLog::new(pk);
        assert_eq!(log.head(), [0u8; 32], "head starts at the zero digest");
        assert_eq!(log.recompute_head(), [0u8; 32]);

        let h1 = log.append(&[1u8; 32], b"order-a", OsRng);
        let h2 = log.append(&[2u8; 32], b"order-b", OsRng);
        assert_ne!(h1, h2, "each append advances the chain");
        assert_eq!(log.head(), h2);
        assert_eq!(
            log.recompute_head(),
            h2,
            "re-folding every entry from zero reproduces the head"
        );

        // Tamper-evidence: flip ONE ciphertext byte in the FIRST entry — the
        // recomputed chain diverges from the stored head.
        let last = log.entries[0].entry_ct.len() - 1;
        log.entries[0].entry_ct[last] ^= 0x01;
        assert_ne!(
            log.recompute_head(),
            log.head(),
            "a flipped entry byte must break the chain"
        );
        log.entries[0].entry_ct[last] ^= 0x01; // restore …
        assert_eq!(log.recompute_head(), log.head());
        // … and a tampered COMMITMENT is equally evident.
        log.entries[1].commitment[0] ^= 0x01;
        assert_ne!(log.recompute_head(), log.head());
    }

    /// The chain link must be `keccak256(Domain::OrderLogChain ‖ prev ‖
    /// commitment ‖ entry_ct)` — a silent revert to the untagged pre-merge
    /// formula would move every persisted head into the shared raw-keccak
    /// preimage space. Pins the tag byte into the link.
    #[test]
    fn chain_link_is_domain_tagged() {
        use sha3::Digest as _;
        let (_, pk) = log_keypair(&[9u8; 32]);
        let mut log = OrderLog::new(pk);
        let commitment = [1u8; 32];
        let head = log.append(&commitment, b"order-a", OsRng);
        let ct = &log.entries[0].entry_ct;

        let mut tagged = sha3::Keccak256::new();
        tagged.update([Domain::OrderLogChain as u8]);
        tagged.update([0u8; 32]); // zero-digest chain start
        tagged.update(commitment);
        tagged.update(ct);
        assert_eq!(
            head,
            <[u8; 32]>::from(tagged.finalize()),
            "chain link is the DOMAIN-TAGGED keccak"
        );

        let mut untagged = sha3::Keccak256::new();
        untagged.update([0u8; 32]);
        untagged.update(commitment);
        untagged.update(ct);
        assert_ne!(
            head,
            <[u8; 32]>::from(untagged.finalize()),
            "the untagged (pre-merge) formula must no longer match"
        );
    }

    #[test]
    fn entries_are_sealed_not_plaintext_and_open_only_with_log_secret() {
        let (sk, pk) = log_keypair(&[9u8; 32]);
        let mut log = OrderLog::new(pk);
        let canonical: &[u8] = b"canonical-order-terms-that-must-never-be-stored-in-the-clear";
        log.append(&[7u8; 32], canonical, OsRng);

        // ENCRYPTED: no window of the stored entry equals the plaintext.
        let ct = &log.entries[0].entry_ct;
        assert!(
            !ct.windows(canonical.len()).any(|w| w == canonical),
            "the canonical terms must not appear in the stored entry"
        );

        // The seed-derived log SECRET (future: attested prover) opens entry 0
        // under the seq-bound AAD …
        let sb = sealed_box::SealedBox::from_bytes(ct).expect("wire parses");
        let aad = sealed_box::domain_aad(Domain::LogEncryptAad as u8, &0u64.to_le_bytes());
        assert_eq!(
            sealed_box::unseal(&sk, &sb, &aad).as_deref(),
            Some(canonical),
            "log secret recovers the canonical terms"
        );
        // … and the WRONG entry index (AAD) does not — position is bound.
        let wrong = sealed_box::domain_aad(Domain::LogEncryptAad as u8, &1u64.to_le_bytes());
        assert_eq!(sealed_box::unseal(&sk, &sb, &wrong), None);
    }
}

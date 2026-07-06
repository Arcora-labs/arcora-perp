//! Order-ingress **epoch keypair** for the enclave (Task 9).
//!
//! A client that wants to submit an *encrypted* order needs an ephemeral X25519
//! recipient public key that (a) only the live enclave holds the secret for, and
//! (b) it can trust is the real enclave's — not a MITM's. This module owns the
//! X25519 keypair (sealed to the enclave), rotates it, and keeps the immediately
//! previous epoch's secret alive for a grace window so an order encrypted to the
//! epoch that was current when the client fetched it still decrypts right after a
//! rotation.
//!
//! Trust comes from the publication endpoint (`GET /v1/enclave/epoch` in
//! `main.rs`), which signs the epoch public key with the enclave's **secp256k1**
//! identity (the same key that signs receipts) and echoes the attested
//! `measurement`. The signed digest layout lives in [`epoch_signing_digest`] and
//! is a cross-component contract with the client (Task 11).
//!
//! The X25519 keypair derives from `ENCLAVE_SEED` (seed-based, NOT
//! measurement-based) so a reboot / re-pin of the same enclave yields the same
//! keys — the same guarantee the sealed state snapshot relies on.

use perp_core::hash::Domain;

/// One order-ingress epoch: the X25519 recipient keypair the enclave decrypts
/// incoming orders with, plus when it stops being the *published* current key.
pub struct EpochKey {
    pub epoch_id: u64,
    /// X25519 secret scalar — never leaves the enclave; used to decrypt orders
    /// sealed to `public`. Read via [`EnclaveEpochs::secret_for`] by order-decrypt
    /// (Task 10); not yet read by this task's publication handler.
    #[allow(dead_code)]
    pub secret: [u8; 32],
    /// X25519 public key — published (signed) so clients can seal orders to it.
    pub public: [u8; 32],
    /// Advisory expiry (ms): clients should refetch before this. Bound into the
    /// signed digest so a stale published key can be told apart from a fresh one.
    pub not_after_ms: u64,
}

/// The enclave's rolling epoch keys: the current one plus the immediately
/// previous one retained for a grace window (so orders encrypted to the key a
/// client just fetched still decrypt across a rotation).
pub struct EnclaveEpochs {
    // `seed`/`prev` are exercised now by rotation + grace-window retrieval (unit
    // tests) and by order-decrypt (Task 10); the publication handler only reads
    // `cur`, so the non-test build sees them as unused until Task 10 lands.
    #[allow(dead_code)]
    seed: [u8; 32],
    cur: EpochKey,
    #[allow(dead_code)]
    prev: Option<EpochKey>,
}

/// Deterministically derive the epoch keypair from the enclave seed.
///
/// `info = [Domain::X25519OrderEpoch as u8] ‖ epoch_id.to_le_bytes()` — domain-
/// separated from every other seed-derived key and scoped per epoch, so two
/// epochs (or two enclaves with different seeds) never share an X25519 key.
fn derive_epoch(seed: &[u8; 32], epoch_id: u64, now_ms: u64, ttl_ms: u64) -> EpochKey {
    let mut info = [0u8; 1 + 8];
    info[0] = Domain::X25519OrderEpoch as u8;
    info[1..].copy_from_slice(&epoch_id.to_le_bytes());
    let (secret, public) = sealed_box::x25519_keypair_from_ikm(seed, &info);
    EpochKey {
        epoch_id,
        secret,
        public,
        not_after_ms: now_ms.saturating_add(ttl_ms),
    }
}

impl EnclaveEpochs {
    /// Derive the epoch set starting at `epoch_id` (current key), no retained
    /// previous key yet. `now_ms + ttl_ms` becomes the current key's advisory
    /// expiry.
    pub fn derive(seed: [u8; 32], epoch_id: u64, now_ms: u64, ttl_ms: u64) -> Self {
        Self {
            seed,
            cur: derive_epoch(&seed, epoch_id, now_ms, ttl_ms),
            prev: None,
        }
    }

    /// The current (published) epoch key.
    pub fn current(&self) -> &EpochKey {
        &self.cur
    }

    /// The X25519 secret for `epoch_id`, if it is either the current epoch OR the
    /// retained previous epoch (grace window). Used by order-decrypt (Task 10) to
    /// open an order sealed to whichever epoch was current when the client fetched
    /// it. Returns `None` once the epoch has aged past the retained previous.
    // Consumed by order-decrypt (Task 10); only the unit tests call it in this task.
    #[allow(dead_code)]
    pub fn secret_for(&self, epoch_id: u64) -> Option<&[u8; 32]> {
        if self.cur.epoch_id == epoch_id {
            Some(&self.cur.secret)
        } else {
            self.prev
                .as_ref()
                .filter(|p| p.epoch_id == epoch_id)
                .map(|p| &p.secret)
        }
    }

    /// Rotate to the next epoch: derive `epoch_id + 1` as the new current key and
    /// retain the just-superseded key as the grace-window `prev` (its secret stays
    /// available via [`secret_for`] until the *next* rotation drops it).
    // A rotation scheduler wires this in a later task; unit-tested here.
    #[allow(dead_code)]
    pub fn rotate(&mut self, now_ms: u64, ttl_ms: u64) {
        let next_id = self.cur.epoch_id + 1;
        let next = derive_epoch(&self.seed, next_id, now_ms, ttl_ms);
        self.prev = Some(core::mem::replace(&mut self.cur, next));
    }
}

impl Default for EnclaveEpochs {
    /// Placeholder used only to satisfy `#[serde(skip)]` on the `Gw` snapshot
    /// field; `Gw::boot` / `boot_restored` always overwrite it with a set derived
    /// from the real `ENCLAVE_SEED`, so a snapshot never carries (nor restores) an
    /// epoch secret.
    fn default() -> Self {
        EnclaveEpochs::derive([0u8; 32], 1, 0, 0)
    }
}

/// Canonical signed-digest preimage for a published order-ingress epoch key.
///
/// **Cross-component contract (Task 11 client MUST match this byte-for-byte):**
/// the enclave's secp256k1 identity signs `keccak256(preimage)` where `preimage`
/// is the 49 bytes:
///
/// ```text
///   [0]      Domain::X25519OrderEpoch as u8   (= 25)         1 byte
///   [1..9]   epoch_id      as u64 little-endian              8 bytes
///   [9..41]  x25519_pub    (raw 32-byte X25519 public key)  32 bytes
///   [41..49] not_after_ms  as u64 little-endian              8 bytes
/// ```
///
/// The returned 32-byte value is the prehash fed to `sign_prehash_recoverable`
/// (recoverable `r‖s‖v`, `v` in Ethereum 27/28 convention). The client recomputes
/// this exact preimage, keccak256s it, and `ecrecover`s the published `sig` to the
/// pinned enclave signer — while separately checking `measurement` equals the
/// pinned attestation measurement.
pub fn epoch_signing_digest(epoch_id: u64, x25519_pub: &[u8; 32], not_after_ms: u64) -> [u8; 32] {
    use sha3::Digest as _;
    let mut h = sha3::Keccak256::new();
    h.update([Domain::X25519OrderEpoch as u8]);
    h.update(epoch_id.to_le_bytes());
    h.update(x25519_pub);
    h.update(not_after_ms.to_le_bytes());
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn epoch_key_is_seed_scoped_and_stable() {
        let e = EnclaveEpochs::derive([5u8; 32], 1, 0, 3_600_000);
        assert_eq!(
            e.current().public,
            EnclaveEpochs::derive([5u8; 32], 1, 0, 3_600_000)
                .current()
                .public
        );
        assert_ne!(
            e.current().public,
            EnclaveEpochs::derive([6u8; 32], 1, 0, 3_600_000)
                .current()
                .public
        );
    }
    #[test]
    fn old_epoch_secret_retained_for_grace() {
        let mut e = EnclaveEpochs::derive([5u8; 32], 1, 0, 3_600_000);
        let old = e.current().epoch_id;
        e.rotate(3_600_001, 3_600_000);
        assert!(e.secret_for(old).is_some());
        assert_ne!(e.current().epoch_id, old);
    }

    /// Locks the cross-component contract the client (Task 11) verifies: the
    /// published `sig` over [`epoch_signing_digest`], produced by the enclave's
    /// secp256k1 identity, `ecrecover`s back to that enclave's address. Guards the
    /// exact digest byte layout AND the reused signer against silent drift.
    #[test]
    fn published_epoch_sig_recovers_to_enclave_identity() {
        use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
        use sequencer::EnclaveIdentity;

        let seed = [7u8; 32];
        let measurement = [0xABu8; 32];
        let id = EnclaveIdentity::from_seed(seed, 1, measurement);
        let epochs = EnclaveEpochs::derive(seed, 1, 0, ORDER_EPOCH_TTL_MS_TEST);
        let ek = epochs.current();

        let digest = epoch_signing_digest(ek.epoch_id, &ek.public, ek.not_after_ms);
        let (r, s, v) = id.sign_prehash(&digest);

        let mut rs = [0u8; 64];
        rs[..32].copy_from_slice(&r);
        rs[32..].copy_from_slice(&s);
        let sig = Signature::from_slice(&rs).unwrap();
        let recid = RecoveryId::from_byte(v - 27).unwrap();
        let vk = VerifyingKey::recover_from_prehash(&digest, &sig, recid).unwrap();
        assert_eq!(eth_address(&vk), id.eth_address());
    }

    // Ethereum address of a secp256k1 pubkey: keccak256 of the 64-byte uncompressed
    // point (drop the 0x04 tag), last 20 bytes — matches `sequencer::eth_address`.
    fn eth_address(vk: &k256::ecdsa::VerifyingKey) -> [u8; 20] {
        use sha3::Digest as _;
        let enc = vk.to_encoded_point(false);
        let hash = sha3::Keccak256::digest(&enc.as_bytes()[1..]);
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&hash[12..]);
        addr
    }

    // Local TTL for the recovery test (module const `ORDER_EPOCH_TTL_MS` lives in main.rs).
    const ORDER_EPOCH_TTL_MS_TEST: u64 = 24 * 60 * 60 * 1000;
}

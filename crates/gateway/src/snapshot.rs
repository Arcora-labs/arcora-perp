//! Sealed gateway state snapshots — persistence across restarts.
//!
//! The engine state (accounts, positions, books, pending withdrawals) lives in
//! process memory; without this module a restart wipes every account while the
//! vault still holds their USDC on L1. `DARKPERP_STATE=<path>` enables sealed
//! snapshots: the serialized state is **encrypt-then-MAC'd** under a key derived
//! from the enclave seed (the gateway's boot secret) and written atomically
//! (tmp + rename), then restored on the next boot.
//!
//! ## Why the seal key is the enclave seed, not the measurement
//!
//! The witness seal (`prover::SealedWitness`) gates key release on the attested
//! measurement. A snapshot must instead SURVIVE a legitimate measurement change:
//! on Azure the measurement folds the measured-boot PCRs, so a routine
//! kernel/bootloader update + reboot changes it — a measurement-bound snapshot
//! would brick the state exactly when persistence matters most. The secrecy
//! anchor is `ENCLAVE_SEED` (whoever holds it owns the enclave identity anyway);
//! real TEE key-release lands with ATTESTATION.md #5d and can wrap this same
//! boundary.
//!
//! ## No two-time pad
//!
//! The keystream is derived from `(seed, nonce)` under the dedicated
//! `Domain::SnapshotSeal` tag; the nonce (unix-ms ‖ CSPRNG bytes, stored in the
//! clear) is fresh per write, so no two snapshots share a pad — the same rule
//! the witness seal enforces (see the prover's two-time-pad regression).

use perp_core::hash::{word_u64, Digest, Domain, Hasher, Keccak256};
use std::io::Write;
use std::path::Path;

/// File magic + format version. Bump the trailing digit on layout changes so an
/// old binary refuses a new snapshot (and vice versa) instead of misreading it.
const MAGIC: &[u8; 8] = b"DPSNAP1\0";

/// Keystream block derived from the SECRET seed and the per-snapshot nonce.
fn keystream(seed: &[u8; 32], nonce: &Digest, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut counter: u64 = 0;
    while out.len() < len {
        let block =
            Keccak256::hash_words(Domain::SnapshotSeal, &[*seed, *nonce, word_u64(counter)]);
        out.extend_from_slice(&block);
        counter += 1;
    }
    out.truncate(len);
    out
}

/// Encrypt-then-MAC tag binding `(seed, nonce, len, ciphertext)`.
fn mac(seed: &[u8; 32], nonce: &Digest, ciphertext: &[u8]) -> Digest {
    let mut words = vec![*seed, *nonce, word_u64(ciphertext.len() as u64)];
    for chunk in ciphertext.chunks(32) {
        let mut w = [0u8; 32];
        w[..chunk.len()].copy_from_slice(chunk);
        words.push(w);
    }
    Keccak256::hash_words(Domain::SnapshotSealMac, &words)
}

/// Constant-time 32-byte tag comparison (no early exit on the first mismatch).
fn ct_eq(a: &Digest, b: &Digest) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Seal `plain` under `seed`. Layout: `MAGIC ‖ nonce(32) ‖ tag(32) ‖ ciphertext`.
pub fn seal(plain: &[u8], seed: &[u8; 32]) -> Vec<u8> {
    // Fresh per-seal nonce: unix-ms ‖ 24 CSPRNG bytes (public; uniqueness is what
    // prevents keystream reuse across snapshot writes).
    let mut nonce = [0u8; 32];
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    nonce[..8].copy_from_slice(&ms.to_le_bytes());
    getrandom::getrandom(&mut nonce[8..]).expect("OS CSPRNG");

    let ks = keystream(seed, &nonce, plain.len());
    let ciphertext: Vec<u8> = plain.iter().zip(ks).map(|(p, k)| p ^ k).collect();
    let tag = mac(seed, &nonce, &ciphertext);

    let mut out = Vec::with_capacity(8 + 32 + 32 + ciphertext.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&tag);
    out.extend_from_slice(&ciphertext);
    out
}

/// Open a sealed snapshot. Authenticates BEFORE decrypting; a wrong seed, a
/// truncated file, or any flipped ciphertext byte is rejected.
pub fn open(sealed: &[u8], seed: &[u8; 32]) -> Result<Vec<u8>, String> {
    if sealed.len() < 8 + 32 + 32 {
        return Err("snapshot too short".into());
    }
    if &sealed[..8] != MAGIC {
        return Err("snapshot magic/version mismatch".into());
    }
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&sealed[8..40]);
    let mut tag = [0u8; 32];
    tag.copy_from_slice(&sealed[40..72]);
    let ciphertext = &sealed[72..];
    let expected = mac(seed, &nonce, ciphertext);
    if !ct_eq(&expected, &tag) {
        return Err("snapshot authentication failed (wrong seed or tampered file)".into());
    }
    let ks = keystream(seed, &nonce, ciphertext.len());
    Ok(ciphertext.iter().zip(ks).map(|(c, k)| c ^ k).collect())
}

/// Write `bytes` to `path` atomically: a 0600 sibling tmp file is fully written
/// and fsynced, then renamed over the target — a crash mid-write never leaves a
/// torn snapshot, only the previous intact one.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_round_trip() {
        let seed = [9u8; 32];
        let plain = b"the engine state".to_vec();
        let sealed = seal(&plain, &seed);
        assert_eq!(open(&sealed, &seed).unwrap(), plain);
    }

    #[test]
    fn wrong_seed_rejected() {
        let sealed = seal(b"state", &[9u8; 32]);
        assert!(open(&sealed, &[10u8; 32]).is_err());
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let mut sealed = seal(b"state bytes", &[9u8; 32]);
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert!(open(&sealed, &[9u8; 32]).is_err());
    }

    #[test]
    fn truncated_or_wrong_magic_rejected() {
        let seed = [9u8; 32];
        assert!(open(&[], &seed).is_err());
        let mut sealed = seal(b"state", &seed);
        sealed[0] ^= 0xFF;
        assert!(open(&sealed, &seed).is_err());
    }

    #[test]
    fn distinct_nonces_no_keystream_reuse() {
        // Two seals of the same plaintext must not share a pad (two-time-pad
        // guard): identical plaintexts, different ciphertexts.
        let seed = [9u8; 32];
        let a = seal(b"same plaintext", &seed);
        let b = seal(b"same plaintext", &seed);
        assert_ne!(a[8..40], b[8..40], "nonces must differ");
        assert_ne!(a[72..], b[72..], "ciphertexts must differ");
    }

    #[test]
    fn seal_hides_plaintext() {
        let plain = b"secret account spend keys".to_vec();
        let sealed = seal(&plain, &[9u8; 32]);
        // no window of the sealed file equals the plaintext
        assert!(!sealed.windows(plain.len()).any(|w| w == plain.as_slice()));
    }
}

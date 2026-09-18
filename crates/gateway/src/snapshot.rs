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
/// v2: SEC-022 added `Market.max_fill_deviation_ratio`, which sits inside the
/// sealed payload (`Gw.seq.state.markets`); postcard is positional, so a v1
/// snapshot read by a v2 binary would shift by one `i128` per market — and
/// `is_coherent()` is never re-run on a deserialized `Market`, so a mis-decoded
/// band ratio would silently disable the fill band (fail-OPEN). The magic is
/// the guard for when the planned snapshot wipe is forgotten.
/// v3: SEC-024 — `BatchOp`'s MEANING changed: ordinal 8 (`SeedInsurance`, the
/// unbound insurance mint) now always rejects, and ordinal 9 (`FundInsurance`)
/// exists. The snapshot carries `BatchOp`s — `Sequencer` derives serde and its
/// `window_ops: Vec<BatchOp>` is `#[serde(default)]`, not skipped — and `DPSNAP2`
/// spans other in-bundle pre-SEC-024 builds (SEC-022/025-B/025-C), so without a
/// bump this binary would ACCEPT their snapshots; a restored `window_ops` still
/// holding a legacy `SeedInsurance` then wedges the NEXT window (`seal_window` →
/// `derive_roots` → `Err(DeprecatedOp)` → prove fails → rollback re-prepends the
/// same ops) instead of failing loudly at boot. The journal's v4 bump
/// (`rollback_journal.rs::MAGIC`) refuses this exact hazard through the journal
/// door; this refuses it through the snapshot door.
/// v4: SEC-025-A added `Gw.bootstrap`, the operator insurance bootstrap record. `Gw` is
/// encoded positionally by postcard (`snapshot_plain` writes `(self, mkt_px)`), so a v3
/// snapshot read by a v4 binary shifts every field after it. `#[serde(default)]` does not
/// rescue that — postcard is not self-describing. SEC-025-D adds another `Gw` field and
/// takes DPSNAP5; do not reuse v4 for it.
/// v5: SEC-025-D added `Gw.trading_gate`, the launch gate, inserted mid-struct (after
/// `bootstrap`). Same positional-postcard hazard as v4: every field after it shifts on
/// a cross-version read. 025-A already took v4 for `Gw.bootstrap`, and two pieces
/// claiming one magic means whichever lands second changes the positional schema
/// without changing its guard — the exact misread the magic exists to refuse.
// v6: explicit A01 extension; the legacy Gw/Account positional encoding is frozen.
// v7: A05 execution metadata wraps the unchanged A01 v6 payload.
// The v7 MAC binds its version; authenticated v5/v6 remain readable losslessly.
// Formats older than v5 remain refused; no automatic wipe or downgrade.
const MAGIC: &[u8; 8] = b"DPSNAP8\0";
const A05_MAGIC: &[u8; 8] = b"DPSNAP7\0";
const A01_MAGIC: &[u8; 8] = b"DPSNAP6\0";
const LEGACY_MAGIC: &[u8; 8] = b"DPSNAP5\0";

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

/// The v7 domain binds the version as well as the entire authenticated v6 payload.
fn mac_version(seed: &[u8; 32], nonce: &Digest, ciphertext: &[u8], version:u64) -> Digest {
    let tag = mac(seed, nonce, ciphertext);
    Keccak256::hash_words(Domain::SnapshotSealMac, &[word_u64(version), tag])
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
    let tag = mac_version(seed, &nonce, &ciphertext, 8);

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
    if &sealed[..8] != MAGIC && &sealed[..8] != A05_MAGIC && &sealed[..8] != A01_MAGIC && &sealed[..8] != LEGACY_MAGIC {
        return Err("snapshot magic/version mismatch".into());
    }
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&sealed[8..40]);
    let mut tag = [0u8; 32];
    tag.copy_from_slice(&sealed[40..72]);
    let ciphertext = &sealed[72..];
    let expected = if &sealed[..8] == MAGIC {
        mac_version(seed, &nonce, ciphertext, 8)
    } else if &sealed[..8] == A05_MAGIC {
        mac_version(seed, &nonce, ciphertext, 7)
    } else {
        mac(seed, &nonce, ciphertext)
    };
    if !ct_eq(&expected, &tag) {
        return Err("snapshot authentication failed (wrong seed or tampered file)".into());
    }
    let ks = keystream(seed, &nonce, ciphertext.len());
    Ok(ciphertext.iter().zip(ks).map(|(c, k)| c ^ k).collect())
}

/// The sibling tmp path for an atomic write: the FULL file name + ".tmp".
/// APPENDED (like `journal_path` builds its sidecar name) — never
/// `with_extension`, which REPLACES the last extension and collides siblings
/// sharing a stem: for an extensionless state path, the snapshot `state` and
/// the rollback journal `state.rollback` would BOTH map to `state.tmp`, letting
/// the two writers race one shared tmp and rename each other's bytes over the
/// wrong target (Task 3 fix).
fn tmp_path(path: &Path) -> std::path::PathBuf {
    let mut os = path.as_os_str().to_os_string();
    os.push(".tmp");
    std::path::PathBuf::from(os)
}

/// Write a private, exclusive sibling temporary file, fsync it, rename it over
/// the destination, then fsync the parent directory. A successful return means
/// BOTH data and the rename were acknowledged by the filesystem. Runtime callers
/// must still serialize state capture plus publication to prevent stale overwrites.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let directory = std::fs::File::open(parent)?;
    let mut random = [0u8; 16];
    getrandom::getrandom(&mut random).map_err(|e| std::io::Error::other(e.to_string()))?;
    let mut name = tmp_path(path).into_os_string();
    name.push(".");
    name.push(
        random
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
    );
    let tmp = std::path::PathBuf::from(name);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp)?;
    let result = (|| {
        f.write_all(bytes)?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)?;
        directory.sync_all()
    })();
    // Remove only the exclusively created temporary file, never another writer's
    // target or an existing legacy .tmp path. A failed directory sync is still Err.
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
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

    /// SEC-025-D: pin the MAGIC VALUE, not just that some magic is checked. The sibling
    /// test XORs a byte, which passes under any value — so reverting DPSNAP5 to DPSNAP4
    /// left the whole suite green. 025-A already ships DPSNAP4 on `main`, so a revert here
    /// would make a v4 snapshot from that build decode positionally into a v5 `Gw` and
    /// shift every field after `trading_gate`.
    #[test]
    fn a_stale_snapshot_magic_is_refused() {
        let seed = [42u8; 32];
        // The magic lives in the SEALED ENVELOPE (`MAGIC ‖ nonce ‖ tag ‖ ciphertext`),
        // not in the payload — unlike the rollback journal, which carries its own magic
        // inside a snapshot-sealed body. So overwrite the envelope's first eight bytes
        // with the previous value; the body stays a perfectly valid v5 snapshot, which is
        // exactly the hazard: a v4 build's file is well-formed, just differently shaped.
        let mut sealed = seal(b"a valid payload", &seed);
        sealed[..8].copy_from_slice(b"DPSNAP4\0");
        assert!(
            open(&sealed, &seed).is_err(),
            "a snapshot under the previous magic must be refused, not decoded"
        );
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

    /// Task 3 regression: the atomic-write tmp name must be APPENDED to the full
    /// file name, never `with_extension`-replaced — for an extensionless state
    /// path, `state` and its sidecar journal `state.rollback` would otherwise
    /// BOTH map to `state.tmp` (with_extension replaces `.rollback`), letting the
    /// snapshot writer and the journal writer race one shared tmp file and rename
    /// each other's bytes over the wrong target.
    #[test]
    fn write_atomic_tmp_names_distinct_per_target() {
        // the naming rule itself, on both shapes the gateway uses
        assert_eq!(tmp_path(Path::new("/x/state")), Path::new("/x/state.tmp"));
        assert_eq!(
            tmp_path(Path::new("/x/state.rollback")),
            Path::new("/x/state.rollback.tmp")
        );
        assert_ne!(
            tmp_path(Path::new("/x/state")),
            tmp_path(Path::new("/x/state.rollback")),
            "an extensionless snapshot and its journal must never share a tmp"
        );
        assert_eq!(
            tmp_path(Path::new("/x/state.snap")),
            Path::new("/x/state.snap.tmp")
        );
        assert_ne!(
            tmp_path(Path::new("/x/state.snap")),
            tmp_path(Path::new("/x/state.snap.rollback"))
        );

        // and the writes land on the right finals, with no stray tmp left behind
        let mut rnd = [0u8; 8];
        getrandom::getrandom(&mut rnd).expect("OS CSPRNG");
        let sfx: String = rnd.iter().map(|b| format!("{b:02x}")).collect();
        let dir = std::env::temp_dir().join(format!("darkperp-atomic-{sfx}"));
        std::fs::create_dir_all(&dir).unwrap();
        let a = dir.join("state");
        let b = dir.join("state.rollback");
        write_atomic(&a, b"AAA").unwrap();
        write_atomic(&b, b"BBB").unwrap();
        assert_eq!(std::fs::read(&a).unwrap(), b"AAA");
        assert_eq!(std::fs::read(&b).unwrap(), b"BBB");
        assert!(!tmp_path(&a).exists() && !tmp_path(&b).exists());
        std::fs::remove_dir_all(&dir).ok();
    }
}

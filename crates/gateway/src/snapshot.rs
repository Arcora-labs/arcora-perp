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
use sha2::{Digest as _, Sha256};
use std::io::{Read, Write};
use std::path::Path;

/// File magic + format version. Bump the version (and `VERSION`) on layout changes
/// so an old binary refuses a new snapshot (and vice versa) instead of misreading it.
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
/// v6-v9: the A01 deposit, A05 execution, A07 recovery and wind-down layers.
/// v10: the engine state the payload carries changed (the note tree and
/// nullifier log wire, the funding state, the last withdrawal nonce and the
/// wind-down recipient) and the sequencer's own serialized state. Every earlier
/// file is refused, envelope and payload alike: there is no reader for v5-v9 and
/// no automatic wipe, downgrade or migration. A v10 stack starts from a fresh
/// genesis.
const MAGIC: &[u8; 8] = b"DPSNAP10";

/// The version bound into the MAC of every snapshot this binary seals or opens,
/// so a header rewritten to another version fails authentication.
const VERSION: u64 = 10;

/// The authenticated payload's own header, at the start of the plaintext: the
/// wind-down flag, the `(Gw, market dynamics, deposit state)` postcard body, the
/// execution extension and the recovery extension follow it, in that order. A
/// rollback journal sealed with the same envelope starts with its own magic, so
/// one is never read as the other.
pub const PAYLOAD_MAGIC: &[u8] = b"\xffDP-GATEWAY-STATE-v10\0";

/// Operational resource limit, shared by disk intake, parser and atomic writer.
/// This is not a wire-format change: oversized files are preserved and refused
/// for offline reconciliation, never truncated, reset or acknowledged durable.
pub const MAX_PLAIN_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_SEALED_BYTES: usize = MAX_PLAIN_BYTES + 72;

/// Explicit recovery intent, separate from an initial deployment's fresh genesis.
/// A supplied checkpoint always requires a snapshot, even when the flag is "0".
/// The hash must come from a trusted recovery record; matching it is not proof of
/// freshness, chain consistency, key custody or completeness of other state files.
#[derive(Debug, PartialEq, Eq)]
pub struct RestorePolicy {
    required: bool,
    sha256: Option<[u8; 32]>,
}

impl RestorePolicy {
    pub fn from_env() -> Result<Self, String> {
        fn optional(name: &str) -> Result<Option<String>, String> {
            match std::env::var(name) {
                Ok(value) => Ok(Some(value)),
                Err(std::env::VarError::NotPresent) => Ok(None),
                Err(std::env::VarError::NotUnicode(_)) => {
                    Err("restore configuration must be valid UTF-8".into())
                }
            }
        }
        Self::parse(
            optional("DARKPERP_REQUIRE_RESTORE")?.as_deref(),
            optional("DARKPERP_RESTORE_SHA256")?.as_deref(),
        )
    }

    pub(super) fn parse(required: Option<&str>, checkpoint: Option<&str>) -> Result<Self, String> {
        let required = match required {
            None | Some("0") => false,
            Some("1") => true,
            _ => return Err("DARKPERP_REQUIRE_RESTORE must be 0 or 1".into()),
        };
        let sha256 = match checkpoint {
            None => None,
            Some(value) => {
                if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err("DARKPERP_RESTORE_SHA256 must be exactly 64 hex digits".into());
                }
                let nibble = |b: u8| match b {
                    b'0'..=b'9' => b - b'0',
                    b'a'..=b'f' => b - b'a' + 10,
                    b'A'..=b'F' => b - b'A' + 10,
                    _ => unreachable!("validated ASCII hex"),
                };
                let mut bytes = [0; 32];
                for (output, pair) in bytes.iter_mut().zip(value.as_bytes().as_chunks::<2>().0) {
                    *output = (nibble(pair[0]) << 4) | nibble(pair[1]);
                }
                Some(bytes)
            }
        };
        Ok(Self {
            required: required || sha256.is_some(),
            sha256,
        })
    }

    /// Read once, bind the checkpoint to those bytes, then give the SAME bytes
    /// to the existing authenticated snapshot opener. No exists()/reopen gap.
    pub fn read_for_boot(&self, path: Option<&Path>) -> Result<Option<Vec<u8>>, String> {
        let Some(path) = path else {
            return if self.required {
                Err("required restore has no DARKPERP_STATE path".into())
            } else {
                Ok(None)
            };
        };
        let bytes = match read_file(path) {
            Ok(bytes) => bytes,
            Err(error) if !self.required && error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(None);
            }
            Err(_) => return Err("configured snapshot cannot be read; refusing fresh start".into()),
        };
        if let Some(expected) = self.sha256 {
            let actual: [u8; 32] = Sha256::digest(&bytes).into();
            if actual != expected {
                return Err("restore checkpoint SHA-256 mismatch; preserve snapshot".into());
            }
        }
        Ok(Some(bytes))
    }
}

/// Bound the actual descriptor read (including a concurrent file growth), not
/// merely a racy metadata check followed by an unbounded `std::fs::read`.
pub fn read_file(path: &Path) -> std::io::Result<Vec<u8>> {
    let file = std::fs::File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "regular snapshot file required",
        ));
    }
    if metadata.len() > MAX_SEALED_BYTES as u64 {
        return Err(size_error());
    }
    let mut bytes = Vec::new();
    file.take(MAX_SEALED_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_SEALED_BYTES {
        return Err(size_error());
    }
    Ok(bytes)
}

fn size_error() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "snapshot exceeds 64 MiB payload limit; preserve file for offline reconciliation",
    )
}

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

/// The versioned tag: the version word bound over the tag of the ciphertext.
fn mac_version(seed: &[u8; 32], nonce: &Digest, ciphertext: &[u8], version: u64) -> Digest {
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
    let tag = mac_version(seed, &nonce, &ciphertext, VERSION);

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
    if sealed.len() > MAX_SEALED_BYTES {
        return Err(size_error().to_string());
    }
    if sealed.len() < 8 + 32 + 32 {
        return Err("snapshot too short".into());
    }
    if &sealed[..8] != MAGIC {
        return Err("snapshot magic/version mismatch (this gateway reads only DPSNAP10)".into());
    }
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&sealed[8..40]);
    let mut tag = [0u8; 32];
    tag.copy_from_slice(&sealed[40..72]);
    let ciphertext = &sealed[72..];
    let expected = mac_version(seed, &nonce, ciphertext, VERSION);
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
    if bytes.len() > MAX_SEALED_BYTES {
        return Err(size_error());
    }
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
    // The boundary observer and its entire worker protocol exist only in Unix
    // test binaries. Production has no environment-selectable failpoint.
    #[cfg(all(test, unix))]
    crash_tests::at_boundary(path, crash_tests::Boundary::TempCreated);
    let result = (|| {
        f.write_all(bytes)?;
        #[cfg(all(test, unix))]
        crash_tests::at_boundary(path, crash_tests::Boundary::DataWritten);
        f.sync_all()?;
        #[cfg(all(test, unix))]
        crash_tests::at_boundary(path, crash_tests::Boundary::FileSynced);
        std::fs::rename(&tmp, path)?;
        #[cfg(all(test, unix))]
        crash_tests::at_boundary(path, crash_tests::Boundary::Renamed);
        directory.sync_all()?;
        #[cfg(all(test, unix))]
        crash_tests::at_boundary(path, crash_tests::Boundary::DirectorySynced);
        Ok(())
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

    struct RestoreScratch(std::path::PathBuf);
    impl RestoreScratch {
        fn new() -> Self {
            let mut random = [0; 16];
            getrandom::getrandom(&mut random).unwrap();
            let suffix: String = random.iter().map(|b| format!("{b:02x}")).collect();
            let path = std::env::temp_dir().join(format!("arcora-restore-policy-{suffix}"));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for RestoreScratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn restore_policy_parsing_is_strict_and_never_echoes_values() {
        assert!(!RestorePolicy::parse(None, None).unwrap().required);
        assert!(!RestorePolicy::parse(Some("0"), None).unwrap().required);
        assert!(RestorePolicy::parse(Some("1"), None).unwrap().required);
        for value in ["", "true", "yes", "2", " 1", "private-sentinel", "é"] {
            let error = RestorePolicy::parse(Some(value), None).unwrap_err();
            assert!(!error.contains("private-sentinel"));
        }
        for value in [
            "".to_string(),
            "aa".repeat(31),
            "gg".repeat(32),
            "é".repeat(32),
            format!("0x{}", "aa".repeat(32)),
            "private-sentinel".into(),
        ] {
            assert!(RestorePolicy::parse(None, Some(&value)).is_err());
        }
    }

    #[test]
    fn restore_checkpoint_implies_required_and_normalizes_hex_case() {
        let lower = RestorePolicy::parse(Some("0"), Some(&"ab".repeat(32))).unwrap();
        let upper = RestorePolicy::parse(None, Some(&"AB".repeat(32))).unwrap();
        assert_eq!(lower, upper);
        assert!(lower.required);
        assert_eq!(lower.sha256, Some([0xab; 32]));
    }

    #[test]
    fn restore_missing_path_never_falls_back_when_required() {
        let scratch = RestoreScratch::new();
        let missing = scratch.0.join("not-present");
        for policy in [
            RestorePolicy::parse(Some("1"), None).unwrap(),
            RestorePolicy::parse(None, Some(&"00".repeat(32))).unwrap(),
        ] {
            assert!(policy.read_for_boot(None).is_err());
            assert!(policy.read_for_boot(Some(&missing)).is_err());
            assert!(!missing.exists());
        }
        let fresh = RestorePolicy::parse(None, None).unwrap();
        assert_eq!(fresh.read_for_boot(None).unwrap(), None);
        assert_eq!(fresh.read_for_boot(Some(&missing)).unwrap(), None);
    }

    #[test]
    fn restore_checkpoint_uses_the_exact_bytes_later_authenticated() {
        let scratch = RestoreScratch::new();
        let path = scratch.0.join("snapshot");
        let sealed = seal(b"checkpoint payload", &[7; 32]);
        std::fs::write(&path, &sealed).unwrap();
        let digest: String = Sha256::digest(&sealed)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let policy = RestorePolicy::parse(None, Some(&digest)).unwrap();
        let checked = policy.read_for_boot(Some(&path)).unwrap().unwrap();
        // Replacing a file after intake cannot replace the already checked bytes.
        std::fs::write(&path, seal(b"other checkpoint", &[7; 32])).unwrap();
        assert_eq!(open(&checked, &[7; 32]).unwrap(), b"checkpoint payload");
        assert!(open(&checked, &[8; 32]).is_err());
        assert!(policy.read_for_boot(Some(&path)).is_err());
    }

    #[test]
    fn restore_directory_and_corrupt_snapshot_do_not_become_fresh_genesis() {
        let scratch = RestoreScratch::new();
        let policy = RestorePolicy::parse(Some("1"), None).unwrap();
        assert!(policy.read_for_boot(Some(&scratch.0)).is_err());
        let path = scratch.0.join("short");
        std::fs::write(&path, b"bad").unwrap();
        let bytes = policy.read_for_boot(Some(&path)).unwrap().unwrap();
        assert!(open(&bytes, &[7; 32]).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"bad");
    }

    #[test]
    fn seal_open_round_trip() {
        let seed = [9u8; 32];
        let plain = b"the engine state".to_vec();
        let sealed = seal(&plain, &seed);
        assert_eq!(open(&sealed, &seed).unwrap(), plain);
    }

    /// Every earlier envelope is refused, including one a genuine earlier binary
    /// would have authenticated: v7-v9 under their versioned tag, v5/v6 under the
    /// unversioned one. Nothing before v10 is read.
    #[test]
    fn v10_authenticates_its_version_and_refuses_every_earlier_envelope() {
        let seed = [42; 32];
        let sealed = seal(b"an earlier plaintext", &seed);
        assert_eq!(&sealed[..8], b"DPSNAP10");
        assert_eq!(open(&sealed, &seed).unwrap(), b"an earlier plaintext");
        let nonce: Digest = sealed[8..40].try_into().unwrap();
        for (magic, version) in [
            (b"DPSNAP9\0", Some(9)),
            (b"DPSNAP8\0", Some(8)),
            (b"DPSNAP7\0", Some(7)),
            (b"DPSNAP6\0", None),
            (b"DPSNAP5\0", None),
            (b"DPSNAP4\0", None),
        ] {
            let mut old = sealed.clone();
            old[..8].copy_from_slice(magic);
            assert!(open(&old, &seed).is_err(), "{magic:?} header rewrite");
            let tag = match version {
                Some(v) => mac_version(&seed, &nonce, &old[72..], v),
                None => mac(&seed, &nonce, &old[72..]),
            };
            old[40..72].copy_from_slice(&tag);
            assert!(
                open(&old, &seed).is_err(),
                "{magic:?} authentic earlier file"
            );
        }
        // A v10 header over an earlier version's tag fails authentication.
        let mut downgraded = sealed.clone();
        downgraded[40..72].copy_from_slice(&mac_version(&seed, &nonce, &sealed[72..], 9));
        assert!(open(&downgraded, &seed).is_err());
    }

    /// Test-side only: authenticate a genuine earlier file under its own version's
    /// tag (v7-v9 versioned, v5/v6 unversioned) and decrypt it. `open` has no such
    /// path; this exists to show what the refused files carry.
    fn open_earlier(sealed: &[u8], seed: &[u8; 32], version: Option<u64>) -> Vec<u8> {
        let nonce: Digest = sealed[8..40].try_into().unwrap();
        let ciphertext = &sealed[72..];
        let tag = match version {
            Some(v) => mac_version(seed, &nonce, ciphertext, v),
            None => mac(seed, &nonce, ciphertext),
        };
        assert!(ct_eq(&tag, &sealed[40..72].try_into().unwrap()));
        let ks = keystream(seed, &nonce, ciphertext.len());
        ciphertext.iter().zip(ks).map(|(c, k)| c ^ k).collect()
    }

    /// Every frozen v5-v9 file is refused by its envelope magic. The payloads they
    /// authenticate under their own versions are no v10 layout either: re-sealed
    /// under the current envelope, each snapshot payload is refused by its header
    /// and the v9 journal by its magic, so nothing earlier is ever decoded.
    #[test]
    fn frozen_earlier_payloads_are_refused_by_their_headers_too() {
        let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/snapshots");
        let read = |name: &str| std::fs::read(fixtures.join(name)).unwrap();
        let legacy: Vec<u8> = include_str!("deposit_ingestion/legacy-v5.hex")
            .trim()
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        let refused = "snapshot magic/version mismatch (this gateway reads only DPSNAP10)";
        for (name, sealed, seed, version) in [
            ("legacy-v5.hex", legacy, [42; 32], None),
            ("v5", read("v5/sealed.bin"), [0xC3; 32], None),
            ("v6", read("v6/sealed.bin"), [0xC3; 32], None),
            ("v7", read("v7/sealed.bin"), [0xC3; 32], Some(7)),
            ("v8", read("v8/sealed.bin"), [0xC3; 32], Some(8)),
            ("v9", read("v9/state.snapshot"), [0x65; 32], Some(9)),
        ] {
            assert_eq!(open(&sealed, &seed).unwrap_err(), refused, "{name}");
            let plain = open_earlier(&sealed, &seed, version);
            let current = open(&seal(&plain, &seed), &seed).unwrap();
            match crate::Gw::boot_restored(&current) {
                Err(error) => assert_eq!(
                    error,
                    "snapshot payload is not the v10 gateway state layout; earlier layouts are not read",
                    "{name}"
                ),
                Ok(_) => panic!("{name}: an earlier payload was decoded"),
            }
        }
        let journal = read("v9/state.snapshot.rollback");
        assert_eq!(&journal[..8], b"DPSNAP9\0");
        let plain = open_earlier(&journal, &[0x65; 32], Some(9));
        assert_eq!(&plain[..8], b"DPRBJL5\0");
        assert_eq!(
            crate::rollback_journal::open(&seal(&plain, &[0x65; 32]), &[0x65; 32]).err(),
            Some("journal magic/version mismatch".to_string())
        );
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

    /// Pin the MAGIC VALUE, not just that some magic is checked: a revert of the
    /// constant would make an earlier build's well-formed file decode positionally
    /// into this layout. The magic lives in the SEALED ENVELOPE
    /// (`MAGIC ‖ nonce ‖ tag ‖ ciphertext`); the rollback journal additionally
    /// carries its own magic inside a snapshot-sealed body.
    #[test]
    fn a_stale_snapshot_magic_is_refused() {
        assert_eq!(MAGIC, b"DPSNAP10");
        assert_eq!(VERSION, 10);
        let seed = [42u8; 32];
        let mut sealed = seal(b"a valid payload", &seed);
        sealed[..8].copy_from_slice(b"DPSNAP9\0");
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

// Real process-kill verification of this writer; excluded from production and
// unsupported platforms rather than pretending another termination is SIGKILL.
#[cfg(all(test, unix))]
#[path = "snapshot_crash_tests.rs"]
mod crash_tests;

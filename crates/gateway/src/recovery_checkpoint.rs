//! Bind an explicit journal presence/absence to the selected snapshot checkpoint.
//! Expected hashes are public operator inputs, not evidence of freshness. The
//! snapshot already contains deposit count/tip/anchor; there is no cursor sidecar.
use crate::{rollback_journal, snapshot};
use sha2::{Digest as _, Sha256};
use std::path::Path;

#[derive(Debug, PartialEq, Eq)]
pub enum JournalPolicy {
    Legacy,
    Absent,
    Pinned([u8; 32]),
}

fn optional_env(name: &str) -> Result<Option<String>, String> {
    match std::env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(_) => Err("recovery checkpoint configuration must be UTF-8".into()),
    }
}

fn hash(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("recovery checkpoint requires exactly 64 ASCII hex digits".into());
    }
    let mut bytes = [0; 32];
    for (dst, pair) in bytes.iter_mut().zip(value.as_bytes().as_chunks::<2>().0) {
        let digit = |b: u8| {
            if b <= b'9' {
                b - b'0'
            } else {
                b.to_ascii_lowercase() - b'a' + 10
            }
        };
        *dst = digit(pair[0]) * 16 + digit(pair[1]);
    }
    Ok(bytes)
}

impl JournalPolicy {
    pub fn from_env() -> Result<Self, String> {
        Self::parse(
            optional_env("DARKPERP_RESTORE_JOURNAL")?.as_deref(),
            optional_env("DARKPERP_RESTORE_SHA256")?.as_deref(),
        )
    }

    pub(super) fn parse(
        journal: Option<&str>,
        snapshot_hash: Option<&str>,
    ) -> Result<Self, String> {
        let Some(journal) = journal else {
            return Ok(Self::Legacy);
        };
        // An isolated journal pin could silently approve an unrelated snapshot.
        // Require the existing snapshot pin to bind the complete selected pair.
        hash(snapshot_hash.ok_or("journal checkpoint requires DARKPERP_RESTORE_SHA256")?)?;
        if journal == "absent" {
            Ok(Self::Absent)
        } else {
            Ok(Self::Pinned(hash(journal)?))
        }
    }

    pub fn read_for_boot(&self, state: Option<&Path>) -> Result<Option<Vec<u8>>, String> {
        let Some(state) = state else {
            return if *self == Self::Legacy {
                Ok(None)
            } else {
                Err("journal checkpoint requires state path".into())
            };
        };
        let path = rollback_journal::journal_path(state);
        // Treat dangling links and directories as errors, not a missing backup.
        match std::fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return match self {
                    Self::Pinned(_) => {
                        Err("expected rollback journal is missing; preserve snapshot".into())
                    }
                    _ => Ok(None),
                };
            }
            Err(_) => return Err("cannot inspect rollback journal; refusing startup".into()),
            Ok(meta) if !meta.is_file() => {
                return Err("regular rollback journal file required".into())
            }
            Ok(_) => {}
        }
        if *self == Self::Absent {
            return Err("checkpoint requires no journal but a sidecar exists".into());
        }
        let bytes = snapshot::read_file(&path)
            .map_err(|_| "rollback journal cannot be read".to_string())?;
        if let Self::Pinned(expected) = self {
            let actual: [u8; 32] = Sha256::digest(&bytes).into();
            if actual != *expected {
                return Err("rollback journal checkpoint mismatch; preserve both files".into());
            }
        }
        Ok(Some(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Scratch(std::path::PathBuf);
    impl Scratch {
        fn new() -> Self {
            let mut nonce = [0; 16];
            getrandom::getrandom(&mut nonce).unwrap();
            let suffix: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
            let path = std::env::temp_dir().join(format!("arcora-pair-{suffix}"));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn state(&self) -> std::path::PathBuf {
            self.0.join("state.snapshot")
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn hex(bytes: &[u8]) -> String {
        Sha256::digest(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    #[test]
    fn journal_policy_is_explicit_and_requires_snapshot_pin() {
        assert_eq!(
            JournalPolicy::parse(None, None).unwrap(),
            JournalPolicy::Legacy
        );
        let pin = "ab".repeat(32);
        assert_eq!(
            JournalPolicy::parse(Some("absent"), Some(&pin)).unwrap(),
            JournalPolicy::Absent
        );
        assert_eq!(
            JournalPolicy::parse(Some(&pin.to_uppercase()), Some(&pin)).unwrap(),
            JournalPolicy::Pinned([0xab; 32])
        );
        for value in ["absent", "", "true", "0", "private-sentinel"] {
            assert!(JournalPolicy::parse(Some(value), None).is_err());
        }
        for value in ["", "0x", "AB", "private-sentinel", "ABSENT", "é"] {
            let error = JournalPolicy::parse(Some(value), Some(&pin)).unwrap_err();
            assert!(!error.contains("private-sentinel"));
        }
        assert!(JournalPolicy::parse(Some("absent"), Some("bad")).is_err());
    }

    #[test]
    fn missing_and_unexpected_sidecar_never_become_clean_checkpoint() {
        let dir = Scratch::new();
        let state = dir.state();
        let pinned = JournalPolicy::Pinned([1; 32]);
        assert!(pinned.read_for_boot(None).is_err());
        assert!(pinned.read_for_boot(Some(&state)).is_err());
        assert!(JournalPolicy::Absent
            .read_for_boot(Some(&state))
            .unwrap()
            .is_none());
        let journal = rollback_journal::journal_path(&state);
        std::fs::write(&journal, b"keep").unwrap();
        assert!(JournalPolicy::Absent.read_for_boot(Some(&state)).is_err());
        assert!(pinned.read_for_boot(Some(&state)).is_err());
        assert_eq!(std::fs::read(journal).unwrap(), b"keep");
    }

    #[test]
    fn checked_bytes_survive_path_replacement_and_still_require_mac() {
        let dir = Scratch::new();
        let state = dir.state();
        let path = rollback_journal::journal_path(&state);
        let bytes = snapshot::seal(b"not a valid journal payload", &[7; 32]);
        std::fs::write(&path, &bytes).unwrap();
        let policy = JournalPolicy::parse(Some(&hex(&bytes)), Some(&"ab".repeat(32))).unwrap();
        let checked = policy.read_for_boot(Some(&state)).unwrap().unwrap();
        std::fs::write(&path, b"replacement").unwrap();
        assert_eq!(checked, bytes);
        assert!(policy.read_for_boot(Some(&state)).is_err());
        assert!(rollback_journal::open(&checked, &[7; 32]).is_err());
        assert!(rollback_journal::open(&checked, &[8; 32]).is_err());
    }

    #[test]
    fn legacy_intake_keeps_existing_journals_instead_of_ignoring_them() {
        let dir = Scratch::new();
        let state = dir.state();
        let policy = JournalPolicy::Legacy;
        assert!(policy.read_for_boot(None).unwrap().is_none());
        assert!(policy.read_for_boot(Some(&state)).unwrap().is_none());
        let jp = rollback_journal::journal_path(&state);
        std::fs::write(&jp, b"untrusted").unwrap();
        assert_eq!(
            policy.read_for_boot(Some(&state)).unwrap().unwrap(),
            b"untrusted"
        );
        std::fs::remove_file(&jp).unwrap();
        std::fs::create_dir(&jp).unwrap();
        assert!(policy.read_for_boot(Some(&state)).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn dangling_or_regular_symlink_is_never_an_absent_journal() {
        let dir = Scratch::new();
        let state = dir.state();
        let jp = rollback_journal::journal_path(&state);
        let target = dir.0.join("target");
        std::os::unix::fs::symlink(&target, &jp).unwrap();
        for policy in [
            JournalPolicy::Legacy,
            JournalPolicy::Absent,
            JournalPolicy::Pinned([0; 32]),
        ] {
            assert!(policy.read_for_boot(Some(&state)).is_err());
        }
        std::fs::write(target, b"test").unwrap();
        assert!(JournalPolicy::Legacy.read_for_boot(Some(&state)).is_err());
    }
}

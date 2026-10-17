//! The highest nonce this gateway has handed to a sequencer-key transaction,
//! made durable before the transaction is broadcast. Recovery compares it with
//! the sequencer's nonce at a finalized block: once that nonce is past it, every
//! register, settle or other sequencer transaction this gateway ever signed is
//! mined or can never be mined, so a window whose anchor is absent then cannot
//! gain one later.
//!
//! The file is sealed like the snapshot and never deleted by the gateway. It is
//! created at boot when no rollback journal exists; a journal without the file is
//! an unknown fence, which recovery treats as not passed.
use std::path::{Path, PathBuf};

const MAGIC: &[u8; 8] = b"DPNFNC1\0";

/// What the fence knows about past sequencer-key broadcasts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Ceiling {
    /// The file is missing while a journal exists: nothing is known.
    Unknown,
    /// No sequencer-key transaction has been broadcast since the file was created.
    None,
    /// The highest nonce handed to a sequencer-key transaction.
    Nonce(u64),
}
impl Ceiling {
    /// Whether an account nonce of `finalized` (the next unused nonce at a
    /// finalized block) is past every recorded broadcast.
    pub(crate) fn passed_by(self, finalized: u64) -> bool {
        match self {
            Self::Unknown => false,
            Self::None => true,
            Self::Nonce(n) => finalized > n,
        }
    }
}

pub(crate) struct NonceFence {
    path: PathBuf,
    seed: [u8; 32],
    ceiling: std::sync::Mutex<Ceiling>,
}

/// `<state>.l1-nonce`, next to the snapshot and its rollback journal.
pub(crate) fn fence_path(state_path: &Path) -> PathBuf {
    let mut os = state_path.as_os_str().to_os_string();
    os.push(".l1-nonce");
    PathBuf::from(os)
}

fn encode(ceiling: Option<u64>) -> Vec<u8> {
    let mut plain = MAGIC.to_vec();
    match ceiling {
        None => plain.push(0),
        Some(n) => {
            plain.push(1);
            plain.extend_from_slice(&n.to_be_bytes());
        }
    }
    plain
}

fn decode(plain: &[u8]) -> Result<Ceiling, String> {
    let body = plain
        .strip_prefix(MAGIC.as_slice())
        .ok_or("nonce fence magic/version mismatch")?;
    match body {
        [0] => Ok(Ceiling::None),
        [1, rest @ ..] if rest.len() == 8 => Ok(Ceiling::Nonce(u64::from_be_bytes(
            rest.try_into().map_err(|_| "nonce fence length")?,
        ))),
        _ => Err("malformed nonce fence".into()),
    }
}

impl NonceFence {
    /// Load the fence, or create it when it is missing and no journal exists.
    /// A missing file next to a journal stays `Unknown` and is not created, so
    /// that journal can never be voided against a fence that forgot its sends.
    pub(crate) fn open(
        path: PathBuf,
        seed: [u8; 32],
        journal_exists: bool,
    ) -> Result<Self, String> {
        let ceiling = match crate::snapshot::read_file(&path) {
            Ok(sealed) => {
                let plain = crate::snapshot::open(&sealed, &seed)
                    .map_err(|e| format!("nonce fence open: {e}"))?;
                decode(&plain)?
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if journal_exists {
                    Ceiling::Unknown
                } else {
                    write(&path, &seed, None)?;
                    Ceiling::None
                }
            }
            Err(e) => return Err(format!("nonce fence read: {e}")),
        };
        Ok(Self {
            path,
            seed,
            ceiling: std::sync::Mutex::new(ceiling),
        })
    }

    pub(crate) fn ceiling(&self) -> Ceiling {
        *self.ceiling.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Record that a sequencer-key transaction with nonce `n` is about to be
    /// broadcast. Durable before it returns; an error means the caller must not
    /// broadcast. Once a send is recorded an unknown fence becomes known again,
    /// but only for nonces from `n` on, so it stays `Unknown` for the journal that
    /// was found without it until a later send covers every earlier nonce.
    pub(crate) fn cover(&self, n: u64) -> Result<(), String> {
        let mut ceiling = self
            .ceiling
            .lock()
            .map_err(|_| "nonce fence lock poisoned")?;
        match *ceiling {
            Ceiling::Nonce(m) if m >= n => return Ok(()),
            Ceiling::Unknown => return Ok(()),
            _ => {}
        }
        write(&self.path, &self.seed, Some(n))?;
        *ceiling = Ceiling::Nonce(n);
        Ok(())
    }
}

impl NonceFence {
    /// Called once the journal found at boot without a fence is resolved: no
    /// later journal depends on the forgotten sends, so recording restarts from
    /// the next send. A known fence is left as it is.
    pub(crate) fn start_fresh_if_unknown(&self) -> Result<(), String> {
        let mut ceiling = self
            .ceiling
            .lock()
            .map_err(|_| "nonce fence lock poisoned")?;
        if *ceiling == Ceiling::Unknown {
            write(&self.path, &self.seed, None)?;
            *ceiling = Ceiling::None;
        }
        Ok(())
    }
}

fn write(path: &Path, seed: &[u8; 32], ceiling: Option<u64>) -> Result<(), String> {
    let sealed = crate::snapshot::seal(&encode(ceiling), seed);
    crate::snapshot::write_atomic(path, &sealed).map_err(|e| format!("nonce fence write: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let mut rnd = [0u8; 8];
        getrandom::getrandom(&mut rnd).unwrap();
        let suffix: String = rnd.iter().map(|b| format!("{b:02x}")).collect();
        std::env::temp_dir().join(format!("darkperp-fence-{tag}-{suffix}"))
    }

    #[test]
    fn fence_is_created_without_a_journal_and_records_the_highest_nonce() {
        let path = scratch("fresh");
        let fence = NonceFence::open(path.clone(), [7; 32], false).unwrap();
        assert_eq!(fence.ceiling(), Ceiling::None);
        assert!(fence.ceiling().passed_by(0));
        fence.cover(4).unwrap();
        fence.cover(2).unwrap();
        assert_eq!(fence.ceiling(), Ceiling::Nonce(4));
        assert!(!fence.ceiling().passed_by(4));
        assert!(fence.ceiling().passed_by(5));
        // Durable and sealed under the seed.
        let reopened = NonceFence::open(path.clone(), [7; 32], true).unwrap();
        assert_eq!(reopened.ceiling(), Ceiling::Nonce(4));
        assert!(NonceFence::open(path.clone(), [8; 32], false).is_err());
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn a_journal_without_its_fence_is_never_fenced() {
        let path = scratch("lost");
        let fence = NonceFence::open(path.clone(), [7; 32], true).unwrap();
        assert_eq!(fence.ceiling(), Ceiling::Unknown);
        assert!(!fence.ceiling().passed_by(u64::MAX));
        assert!(!path.exists(), "an unknown fence is not recreated");
        fence.cover(9).unwrap();
        assert_eq!(fence.ceiling(), Ceiling::Unknown);
        assert!(!path.exists());
        // Once that journal is resolved, recording restarts from the next send.
        fence.start_fresh_if_unknown().unwrap();
        assert_eq!(fence.ceiling(), Ceiling::None);
        fence.cover(11).unwrap();
        assert_eq!(
            NonceFence::open(path.clone(), [7; 32], true)
                .unwrap()
                .ceiling(),
            Ceiling::Nonce(11)
        );
        fence.start_fresh_if_unknown().unwrap();
        assert_eq!(fence.ceiling(), Ceiling::Nonce(11), "a known fence is kept");
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn malformed_fences_are_refused() {
        for plain in [
            b"DPNFNC1\0".to_vec(),
            b"DPNFNC1\0\x02".to_vec(),
            b"DPNFNC1\0\x01\0\0".to_vec(),
            b"DPNFNC0\0\0".to_vec(),
        ] {
            assert!(decode(&plain).is_err());
        }
        assert_eq!(decode(&encode(Some(3))).unwrap(), Ceiling::Nonce(3));
        assert_eq!(decode(&encode(None)).unwrap(), Ceiling::None);
    }
}

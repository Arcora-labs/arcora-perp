//! Fail-closed seal-root resolution (SEC-020). There is NO public default: an
//! unset root refuses to start rather than sealing under a repo-public constant.
//! An explicit `DEV_INSECURE=1` dev root is allowed only in non-prod builds and
//! is loudly logged by the caller.

/// A distinct, clearly-named dev root — NOT the old fail-open `[0x5E; 32]`.
const DEV_INSECURE_SEAL_ROOT: [u8; 32] = *b"DEV-INSECURE-seal-root-NOTPROD!!";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealRootError {
    /// No `PROVER_SEAL_ROOT` and not `DEV_INSECURE` — refuse to start (fail-closed).
    Unset,
    /// `PROVER_SEAL_ROOT` was set but not 32-byte hex.
    BadHex,
    /// `DEV_INSECURE=1` while `prod` — the insecure escape is prod-forbidden.
    DevInsecureInProd,
}

impl std::fmt::Display for SealRootError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            SealRootError::Unset => "PROVER_SEAL_ROOT unset and DEV_INSECURE not enabled — refusing to seal under a public default (SEC-020)",
            SealRootError::BadHex => "PROVER_SEAL_ROOT is not 32-byte hex",
            SealRootError::DevInsecureInProd => "DEV_INSECURE is forbidden when PROD=1",
        };
        f.write_str(s)
    }
}
impl std::error::Error for SealRootError {}

/// Resolve the secret seal root, fail-closed. `prod` is the caller's production flag.
pub fn resolve_seal_root(prod: bool) -> Result<[u8; 32], SealRootError> {
    if let Ok(hex) = std::env::var("PROVER_SEAL_ROOT") {
        let bytes = hex::decode(hex.trim_start_matches("0x")).map_err(|_| SealRootError::BadHex)?;
        if bytes.len() != 32 {
            return Err(SealRootError::BadHex);
        }
        let mut root = [0u8; 32];
        root.copy_from_slice(&bytes);
        return Ok(root);
    }
    if std::env::var("DEV_INSECURE").as_deref() == Ok("1") {
        if prod {
            return Err(SealRootError::DevInsecureInProd);
        }
        return Ok(DEV_INSECURE_SEAL_ROOT);
    }
    Err(SealRootError::Unset)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Serialize env-mutating tests: cargo runs tests in threads sharing the process env.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    fn with_env<F: FnOnce()>(vars: &[(&str, Option<&str>)], f: F) {
        let _g = ENV_LOCK.lock().unwrap();
        let saved: Vec<_> = vars
            .iter()
            .map(|(k, _)| (*k, std::env::var(k).ok()))
            .collect();
        for (k, v) in vars {
            match v {
                Some(v) => std::env::set_var(k, v),
                None => std::env::remove_var(k),
            }
        }
        f();
        for (k, v) in saved {
            match v {
                Some(v) => std::env::set_var(k, v),
                None => std::env::remove_var(k),
            }
        }
    }

    #[test]
    fn unset_and_not_dev_refuses() {
        with_env(
            &[("PROVER_SEAL_ROOT", None), ("DEV_INSECURE", None)],
            || {
                assert!(matches!(
                    resolve_seal_root(false),
                    Err(SealRootError::Unset)
                ));
            },
        );
    }

    #[test]
    fn explicit_hex_is_used() {
        let hex = "0x".to_string() + &"11".repeat(32);
        with_env(
            &[("PROVER_SEAL_ROOT", Some(&hex)), ("DEV_INSECURE", None)],
            || {
                assert_eq!(resolve_seal_root(true).unwrap(), [0x11u8; 32]);
            },
        );
    }

    #[test]
    fn dev_insecure_gives_non_5e_root_in_nonprod() {
        with_env(
            &[("PROVER_SEAL_ROOT", None), ("DEV_INSECURE", Some("1"))],
            || {
                let root = resolve_seal_root(false).unwrap();
                assert_ne!(
                    root, [0x5Eu8; 32],
                    "dev root must not be the old fail-open constant"
                );
            },
        );
    }

    #[test]
    fn dev_insecure_refused_in_prod() {
        with_env(
            &[("PROVER_SEAL_ROOT", None), ("DEV_INSECURE", Some("1"))],
            || {
                assert!(matches!(
                    resolve_seal_root(true),
                    Err(SealRootError::DevInsecureInProd)
                ));
            },
        );
    }

    #[test]
    fn bad_hex_errors() {
        with_env(
            &[("PROVER_SEAL_ROOT", Some("zz")), ("DEV_INSECURE", None)],
            || {
                assert!(matches!(
                    resolve_seal_root(true),
                    Err(SealRootError::BadHex)
                ));
            },
        );
    }
}

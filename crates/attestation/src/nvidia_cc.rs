//! NVIDIA GB10 (Grace-Blackwell) CC attestor over `nv-local-gpu-verifier`.
//! Phase 1: the ONLY guarantee is fail-closed — `quote`/`verify` return
//! `CcNotEnabled` unless the local verifier reports CC on. When Phase 2 enables
//! GB10 CC mode, `collect_evidence`/`verify_evidence` fill in; the trait is stable.
use crate::{AttestError, Attestor, Digest};

/// The NVIDIA GB10 confidential-compute attestation backend. Phase 1 carries no
/// verifier plumbing — only the CC state probed at construction, which gates
/// every operation fail-closed.
pub struct NvidiaCcAttestor {
    cc_enabled: bool,
    // Phase 2: venv verifier path, e.g. ~/nvattest-venv/bin/python -m verifier.cc_admin
}

impl NvidiaCcAttestor {
    /// Detect CC state by invoking the local verifier once at construction.
    pub fn detect() -> Self {
        Self {
            cc_enabled: probe_cc_enabled(),
        }
    }

    #[cfg(test)]
    pub fn with_cc_state(cc_enabled: bool) -> Self {
        Self { cc_enabled }
    }
}

impl Attestor for NvidiaCcAttestor {
    fn quote(&self, _nonce: &[u8; 32]) -> Result<Vec<u8>, AttestError> {
        if !self.cc_enabled {
            return Err(AttestError::CcNotEnabled);
        }
        // Phase 2: `nv-local-gpu-verifier` collect_gpu_evidence(nonce) → serialized evidence.
        Err(AttestError::Backend(
            "NVIDIA CC evidence collection is Phase 2".into(),
        ))
    }

    fn verify(
        &self,
        _quote: &[u8],
        _expected: &Digest,
        _nonce: &[u8; 32],
    ) -> Result<Digest, AttestError> {
        if !self.cc_enabled {
            return Err(AttestError::CcNotEnabled);
        }
        Err(AttestError::Backend(
            "NVIDIA CC evidence verification is Phase 2".into(),
        ))
    }
}

/// Probe CC state without requiring CC: the verifier prints "confidential compute is False"
/// and exits non-zero when CC is off. Absence of the tool ⇒ treat as CC-off (fail-closed).
fn probe_cc_enabled() -> bool {
    // Non-fatal, best-effort; any error ⇒ false (fail-closed).
    false // Phase 2 replaces with a real `python -m verifier.cc_admin` probe.
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AttestError, Attestor};

    #[test]
    fn quote_fails_closed_when_cc_disabled() {
        let att = NvidiaCcAttestor::with_cc_state(false); // inject: is_cc_enabled == false (today's GB10)
        assert!(matches!(
            att.quote(&[0u8; 32]),
            Err(AttestError::CcNotEnabled)
        ));
        assert!(matches!(
            att.verify(&[], &[0u8; 32], &[0u8; 32]),
            Err(AttestError::CcNotEnabled)
        ));
    }

    #[test]
    fn cc_on_stub_path_never_returns_ok() {
        // Phase 1 has NO valid Ok path: even with CC forced on, the stubbed
        // evidence collection/verification must surface `Backend`, never `Ok`.
        let att = NvidiaCcAttestor::with_cc_state(true);
        assert!(matches!(
            att.quote(&[0u8; 32]),
            Err(AttestError::Backend(_))
        ));
        assert!(matches!(
            att.verify(&[], &[0u8; 32], &[0u8; 32]),
            Err(AttestError::Backend(_))
        ));
    }
}

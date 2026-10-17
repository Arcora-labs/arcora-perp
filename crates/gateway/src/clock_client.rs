//! Gateway clock protocol selector. Registration is a chain mutation, so callers
//! MUST durably persist an unproved intent before prove_and_prepare is called.
use crate::{
    prover_client::{
        PreflightRefusal, ProverClient, ProverClientError, RegisterPreconditions, RemoteProveResp,
    },
    L1,
};
use perp_core::clock::ClockContext;
use sequencer::WindowWitness;
use std::sync::Arc;
pub(crate) struct ClockProverClient {
    pub inner: Arc<dyn ProverClient>,
    pub l1: L1,
}
impl ProverClient for ClockProverClient {
    fn clock_enabled(&self) -> bool {
        true
    }
    fn clock_context(&self, w: &WindowWitness) -> Result<Option<ClockContext>, ProverClientError> {
        self.l1
            .register_clock(w)
            .map(Some)
            .map_err(ProverClientError::Http)
    }
    fn prove(&self, _: &WindowWitness) -> Result<RemoteProveResp, ProverClientError> {
        Err(ProverClientError::Decode(
            "clock client requires version-2 context".into(),
        ))
    }
    fn prove_clocked(
        &self,
        w: &WindowWitness,
        c: &ClockContext,
    ) -> Result<RemoteProveResp, ProverClientError> {
        if self.l1.clock_stopping() {
            return Err(ProverClientError::Http(
                "clock proof cancelled; retain exact journal".into(),
            ));
        }
        self.inner.prove_clocked(w, c)
    }
    fn public_identity(
        &self,
    ) -> Result<Option<crate::prover_client::ProverPublicIdentity>, String> {
        self.inner.public_identity()
    }
    fn register_preconditions(&self) -> Result<Option<RegisterPreconditions>, PreflightRefusal> {
        self.register_preconditions_with(crate::strict_production())
            .map(Some)
    }
    /// After the seal only local work remains: the prover's request-size check,
    /// with the limit read before the seal, and the sealed window's batch and
    /// phase against the settlement's. A timed window must register within
    /// `clockSkewMs` of its last operation, so no L1 or prover read happens here.
    fn preflight(
        &self,
        w: &WindowWitness,
        phase: u8,
        pre: Option<&RegisterPreconditions>,
    ) -> Result<(), PreflightRefusal> {
        let pre = pre.ok_or_else(|| {
            PreflightRefusal::Refused(
                "the registration preconditions were not read before the seal".into(),
            )
        })?;
        self.inner.preflight(w, phase, Some(pre))?;
        pre.admit(w.batch_id, phase)
    }
}

impl ClockProverClient {
    /// Everything the registration preflight needs that does not depend on the
    /// window, read before admission pauses: in production with a remote prover,
    /// its program against the on-chain SP1 adapter (whose vkey is read once),
    /// then the clock binding, batch count and wind-down phase at the latest block.
    pub(crate) fn register_preconditions_with(
        &self,
        production: bool,
    ) -> Result<RegisterPreconditions, PreflightRefusal> {
        // A transient identity failure is not a property of the window: the size
        // check then falls back to the transport limit.
        let identity = self.inner.public_identity().ok().flatten();
        if production {
            if let Some(identity) = &identity {
                check_program_identity(
                    identity,
                    self.l1.clock_program_vkey(),
                    expected_elf_sha256()?,
                )
                .map_err(PreflightRefusal::Refused)?;
            }
        }
        let (batch_count, phase) = self
            .l1
            .clock_register_state()
            .map_err(PreflightRefusal::Refused)?;
        Ok(RegisterPreconditions {
            batch_count,
            phase,
            prover_body_bytes: identity.map(|i| i.body_bytes),
        })
    }
}

/// `PROVER_EXPECTED_ELF_SHA256` (64 hex): the guest ELF hash of the release or
/// candidate route in use. Optional; when set the prover must report it.
fn expected_elf_sha256() -> Result<Option<[u8; 32]>, PreflightRefusal> {
    match std::env::var("PROVER_EXPECTED_ELF_SHA256") {
        Err(_) => Ok(None),
        Ok(v) if v.is_empty() => Ok(None),
        Ok(v) => crate::parse_hex32(&format!("0x{}", v.trim_start_matches("0x")))
            .map(Some)
            .ok_or_else(|| {
                PreflightRefusal::Refused("PROVER_EXPECTED_ELF_SHA256 is not 32-byte hex".into())
            }),
    }
}

/// The prover's program must be the one the on-chain SP1 adapter verifies.
pub(crate) fn check_program_identity(
    identity: &crate::prover_client::ProverPublicIdentity,
    onchain_vkey: Result<perp_core::Digest, String>,
    expected_elf: Option<[u8; 32]>,
) -> Result<(), String> {
    let onchain = onchain_vkey.map_err(|e| format!("on-chain programVKey: {e}"))?;
    if identity.program_vkey != onchain {
        return Err(format!(
            "the prover reports program vkey {} but the clock verifier route verifies {}; \
             the window is not registered",
            crate::hex32(&identity.program_vkey),
            crate::hex32(&onchain)
        ));
    }
    if let Some(elf) = expected_elf {
        if identity.elf_sha256 != elf {
            return Err(
                "the prover's guest ELF hash differs from PROVER_EXPECTED_ELF_SHA256; the window is not registered"
                    .into(),
            );
        }
    }
    Ok(())
}

/// A journaled clock intent's classification at one finalized block.
pub(crate) struct DeadIntentCheck {
    pub evidence: crate::rollback_journal::DeadIntentEvidence,
    /// Set when the intent can never settle, with what recovery does about it.
    pub dead: Option<(
        crate::rollback_journal::DeadIntent,
        crate::rollback_journal::DeadIntentAction,
    )>,
}

/// Read the dead-intent evidence for a journal's clock intent
/// (`ClockIntent::of(journal)`) at one finalized block and classify it.
pub(crate) fn check_dead_intent(
    l1: &L1,
    intent: crate::rollback_journal::ClockIntent,
) -> Result<DeadIntentCheck, String> {
    if !l1.clock_enabled() {
        return Err("clock mode not configured".into());
    }
    let evidence = l1.dead_intent_evidence(&intent)?;
    Ok(classify(intent, evidence))
}

/// The pure half of [`check_dead_intent`].
pub(crate) fn classify(
    intent: crate::rollback_journal::ClockIntent,
    evidence: crate::rollback_journal::DeadIntentEvidence,
) -> DeadIntentCheck {
    use crate::rollback_journal::{classify_dead_intent, dead_intent_action};
    let dead = classify_dead_intent(intent.batch, intent.phase, &evidence)
        .map(|d| (d, dead_intent_action(d, intent.phase, intent.timed)));
    DeadIntentCheck { evidence, dead }
}

/// Version gate for the exact-resume path, hoisted out of `resume_exact` so it
/// is unit-testable without an L1 handle. The reviewed v2 resume re-submits the
/// window through the v2 prover/L1 (`prove_and_prepare` → `settle_proved`); a
/// candidate-bound journal (DPRBJL6 envelope) must NOT take that path until real
/// v3 submission is wired — reject it and let the caller HOLD with the WAL kept.
pub(crate) fn ensure_resume_supported(
    envelope: Option<&crate::rollback_journal::ArchiveEnvelope>,
) -> Result<(), String> {
    if envelope.is_some() {
        return Err(
            "candidate-bound journal: exact v2 resume is unsupported until v3 submission is wired"
                .into(),
        );
    }
    Ok(())
}

/// Reconstruct only from the encrypted WAL, never from the current live op log.
/// Re-proving is safe after session expiry: the receipt itself stays immutable.
pub(crate) fn resume_exact(
    l1: &L1,
    client: &dyn ProverClient,
    journal: &mut crate::rollback_journal::RollbackJournal,
    envelope: Option<&crate::rollback_journal::ArchiveEnvelope>,
    path: &std::path::Path,
    seed: &[u8; 32],
) -> Result<(u64, String, u128), String> {
    // BEFORE any L1 read, clock registration, prove, or journal rewrite: a
    // candidate-bound journal can never be resumed through the v2 path.
    ensure_resume_supported(envelope)?;
    if !client.clock_enabled() || !l1.clock_enabled() {
        return Err("clock resume requires version 2".into());
    }
    let expected = crate::prover_client::prepare_unproved(&journal.witness, &journal.ww)?;
    let mut recorded = journal
        .prepared
        .clone()
        .ok_or("clock resume requires durable intent")?;
    recorded.outcome.proof.clear();
    if postcard::to_allocvec(&recorded).map_err(|_| "intent encode")?
        != postcard::to_allocvec(&expected).map_err(|_| "intent encode")?
    {
        return Err("journal does not match its immutable witness".into());
    }
    let (batch, root, _) = l1.settlement_observation()?;
    if batch != journal.batch_id
        || !root.eq_ignore_ascii_case(&crate::hex32(&expected.outcome.prev_root))
    {
        return Err("clock resume batch/root changed".into());
    }
    // Reuse a durable proof after a crash. It is still tied to the same receipt;
    // no new timestamp or re-proving is needed merely because the reply was lost.
    let prepared = match journal.prepared.as_ref() {
        Some(p)
            if p.outcome.proof.starts_with(perp_core::clock::PROOF_MAGIC)
                && p.outcome.proof.len() > perp_core::clock::PROOF_MAGIC.len() + 32 =>
        {
            p.clone()
        }
        _ => crate::prover_client::prove_and_prepare(client, &journal.witness, &journal.ww)?,
    };
    journal.prepared = Some(prepared.clone());
    // The rewrite keeps the journal's authenticated version: a candidate v6
    // journal must stay v6 (envelope intact), a legacy journal stays v5.
    crate::rollback_journal::write_versioned(path, journal, envelope, seed)?;
    l1.settle_proved(&prepared.outcome)?;
    l1.settlement_observation()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prover_client::{tests_support::sample_window, MockProverClient};

    /// The post-seal check is local. The bridge here points at a closed port, so
    /// any L1 read would fail the check instead of passing it.
    #[test]
    fn the_post_seal_check_compares_the_sealed_window_without_reading_l1() {
        let client = ClockProverClient {
            inner: Arc::new(MockProverClient),
            l1: L1::test_clocked_reader("http://127.0.0.1:9".into(), [1; 20], 84532),
        };
        let (w, _) = sample_window();
        let pre = |batch_count, phase| RegisterPreconditions {
            batch_count,
            phase,
            prover_body_bytes: None,
        };
        client.preflight(&w, 0, Some(&pre(w.batch_id, 0))).unwrap();
        assert!(matches!(
            client.preflight(&w, 0, Some(&pre(w.batch_id, 1))),
            Err(PreflightRefusal::WrongPhase(e)) if e.contains("close-only")
        ));
        assert!(matches!(
            client.preflight(&w, 0, Some(&pre(w.batch_id + 1, 0))),
            Err(PreflightRefusal::Refused(e)) if e.contains("next batch")
        ));
        // Without what was read before the seal nothing is registered.
        assert!(matches!(
            client.preflight(&w, 0, None),
            Err(PreflightRefusal::Refused(e)) if e.contains("before the seal")
        ));
    }
}

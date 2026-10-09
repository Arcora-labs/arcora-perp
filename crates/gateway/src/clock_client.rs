//! Gateway clock protocol selector. Registration is a chain mutation, so callers
//! MUST durably persist an unproved intent before prove_and_prepare is called.
use crate::{
    prover_client::{ProverClient, ProverClientError, RemoteProveResp},
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
}

/// Reconstruct only from the encrypted WAL, never from the current live op log.
/// Re-proving is safe after session expiry: the receipt itself stays immutable.
pub(crate) fn resume_exact(
    l1: &L1,
    client: &dyn ProverClient,
    journal: &mut crate::rollback_journal::RollbackJournal,
    path: &std::path::Path,
    seed: &[u8; 32],
) -> Result<(u64, String, u128), String> {
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
    crate::rollback_journal::write(path, journal, seed)?;
    l1.settle_proved(&prepared.outcome)?;
    l1.settlement_observation()
}

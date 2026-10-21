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

/// Whether a registration may be sent when the window has no anchor at the
/// latest block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RegisterMode {
    /// Send the window's registration, unless it is past its registration skew.
    SendIfAbsent,
    /// Prove only against an anchor that already exists; never send.
    ExistingOnly,
}

pub(crate) struct ClockProverClient {
    pub inner: Arc<dyn ProverClient>,
    pub l1: L1,
    pub register: RegisterMode,
}
impl ClockProverClient {
    /// The same prover and bridge, registering nothing: a window without an
    /// anchor fails with an error that asks the caller to classify it again.
    pub(crate) fn existing_only(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            l1: self.l1.clone(),
            register: RegisterMode::ExistingOnly,
        }
    }
}
impl ProverClient for ClockProverClient {
    fn clock_enabled(&self) -> bool {
        true
    }
    fn clock_context(&self, w: &WindowWitness) -> Result<Option<ClockContext>, ProverClientError> {
        self.l1
            .register_clock_with(w, self.register)
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
    ///
    /// In production a remote prover whose identity cannot be read registers
    /// nothing: its program is compared before every registration, so the sealed
    /// window is rolled back without being registered, as after a refused
    /// preflight, and the settle loop retries. An in-process client has no identity
    /// and nothing to compare. Outside production a failed identity read only means
    /// the request-size check falls back to the transport limit.
    pub(crate) fn register_preconditions_with(
        &self,
        production: bool,
    ) -> Result<RegisterPreconditions, PreflightRefusal> {
        let identity = match self.inner.public_identity() {
            Ok(identity) => identity,
            Err(e) if production => {
                return Err(PreflightRefusal::Refused(format!(
                    "the prover's identity could not be read ({e}); its program and guest \
                     ELF are compared before a window registers, so the window is not \
                     registered"
                )))
            }
            Err(_) => None,
        };
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

pub(crate) const EXPECTED_ELF_VAR: &str = "PROVER_EXPECTED_ELF_SHA256";

/// `PROVER_EXPECTED_ELF_SHA256` (64 hex): the guest ELF hash of the release
/// route in use. When set, the prover must report it before a window registers;
/// production boot with a remote prover requires it (see
/// [`require_expected_elf_at_boot`]).
fn expected_elf_sha256() -> Result<Option<[u8; 32]>, PreflightRefusal> {
    parse_expected_elf_sha256(std::env::var(EXPECTED_ELF_VAR).ok().as_deref())
        .map_err(PreflightRefusal::Refused)
}

/// Unset or empty is `None`; anything else must be 32-byte hex, with or
/// without `0x`.
pub(crate) fn parse_expected_elf_sha256(value: Option<&str>) -> Result<Option<[u8; 32]>, String> {
    match value {
        None | Some("") => Ok(None),
        Some(v) => crate::parse_hex32(&format!("0x{}", v.trim_start_matches("0x")))
            .map(Some)
            .ok_or_else(|| format!("{EXPECTED_ELF_VAR} is not 32-byte hex")),
    }
}

/// The boot check for the expected guest ELF hash. `required` is strict
/// production with a remote prover and real proofs, the posture in which the
/// registration preflight compares the prover's reported ELF hash with it: the
/// value must then be set and valid. Otherwise it may be unset, but a value that
/// is set must still parse.
pub(crate) fn require_expected_elf_at_boot(
    required: bool,
    value: Option<&str>,
) -> Result<(), String> {
    match parse_expected_elf_sha256(value)? {
        None if required => Err(format!(
            "{EXPECTED_ELF_VAR} must be set in production with a remote prover: the reviewed \
             guest ELF hash the prover has to report before any window registers"
        )),
        _ => Ok(()),
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
#[derive(Clone, Copy, Debug)]
pub(crate) struct DeadIntentCheck {
    pub evidence: crate::rollback_journal::DeadIntentEvidence,
    /// The classification, with the basis of a dead one.
    pub classified: crate::rollback_journal::Classified,
    /// Set when the intent can never settle, with what recovery does about it.
    pub dead: Option<(
        crate::rollback_journal::DeadIntent,
        crate::rollback_journal::DeadIntentAction,
    )>,
}

/// Read the dead-intent evidence for a journal's clock intent
/// (`ClockIntent::of(journal)`) at one finalized block and classify it. The
/// nonce fence is the one recorded so far, every sequencer-key send included.
pub(crate) fn check_dead_intent(
    l1: &L1,
    intent: crate::rollback_journal::ClockIntent,
) -> Result<DeadIntentCheck, String> {
    if !l1.clock_enabled() {
        return Err("clock mode not configured".into());
    }
    let evidence = l1.dead_intent_evidence(&intent, l1.nonce_ceiling())?;
    Ok(classify(intent, evidence))
}

/// The pure half of [`check_dead_intent`].
pub(crate) fn classify(
    intent: crate::rollback_journal::ClockIntent,
    evidence: crate::rollback_journal::DeadIntentEvidence,
) -> DeadIntentCheck {
    use crate::rollback_journal::{classify_dead_intent, dead_intent_action, Classified};
    let classified = classify_dead_intent(&intent, &evidence);
    let dead = match classified {
        Classified::Dead(d, _) => Some((d, dead_intent_action(d, intent.phase, intent.timed))),
        Classified::MaySettle | Classified::Inconsistent(_) => None,
    };
    DeadIntentCheck {
        evidence,
        classified,
        dead,
    }
}

/// Version gate for the exact-resume path, hoisted out of `resume_exact` so it
/// is unit-testable without an L1 handle. The reviewed v2 resume re-submits the
/// window through the v2 prover/L1 (`prove_and_prepare` → `settle_proved`); a
/// candidate-bound journal (DPRBJL8 envelope) must NOT take that path until real
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

/// How an exact resume runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ResumeMode {
    /// At boot: the window was classified at one finalized block just before.
    Boot,
    /// From a running settle loop. Immediately before the settle broadcast, the
    /// window's anchor must still be registered, and its receipt not cancelled,
    /// at the latest block. `reprove` drops a durable proof and proves again
    /// against the same anchor.
    Recovery { reprove: bool },
}

/// The settlement side of an exact resume. [`L1`] is the only production
/// implementation; the trait lets a test follow the order of reads and sends.
pub(crate) trait ResumeChain {
    fn clock_enabled(&self) -> bool;
    /// Batch count, state root and bond at one finalized block.
    fn settlement_observation(&self) -> Result<(u64, String, u128), String>;
    /// See [`L1::clock_anchor_live_at_latest`].
    fn anchor_live_at_latest(
        &self,
        batch: u64,
        phase: u8,
        receipt: &perp_core::Digest,
    ) -> Result<(), String>;
    /// Broadcast the settle and wait for it ([`L1::settle_proved`]).
    fn settle_proved(&self, out: &crate::prover_client::ProveOutcome) -> Result<String, String>;
}
impl ResumeChain for L1 {
    fn clock_enabled(&self) -> bool {
        L1::clock_enabled(self)
    }
    fn settlement_observation(&self) -> Result<(u64, String, u128), String> {
        L1::settlement_observation(self)
    }
    fn anchor_live_at_latest(
        &self,
        batch: u64,
        phase: u8,
        receipt: &perp_core::Digest,
    ) -> Result<(), String> {
        self.clock_anchor_live_at_latest(batch, phase, receipt)
    }
    fn settle_proved(&self, out: &crate::prover_client::ProveOutcome) -> Result<String, String> {
        L1::settle_proved(self, out)
    }
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
    resume_exact_with(l1, client, journal, envelope, path, seed, ResumeMode::Boot)
}

/// [`resume_exact`] in `mode`.
pub(crate) fn resume_exact_with(
    chain: &dyn ResumeChain,
    client: &dyn ProverClient,
    journal: &mut crate::rollback_journal::RollbackJournal,
    envelope: Option<&crate::rollback_journal::ArchiveEnvelope>,
    path: &std::path::Path,
    seed: &[u8; 32],
    mode: ResumeMode,
) -> Result<(u64, String, u128), String> {
    // BEFORE any L1 read, clock registration, prove, or journal rewrite: a
    // candidate-bound journal can never be resumed through the v2 path.
    ensure_resume_supported(envelope)?;
    if !client.clock_enabled() || !chain.clock_enabled() {
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
    let (batch, root, _) = chain.settlement_observation()?;
    if batch != journal.batch_id
        || !root.eq_ignore_ascii_case(&crate::hex32(&expected.outcome.prev_root))
    {
        return Err("clock resume batch/root changed".into());
    }
    let reprove = mode == ResumeMode::Recovery { reprove: true };
    let journaled_receipt = journal
        .prepared
        .as_ref()
        .and_then(|p| proof_receipt(&p.outcome.proof));
    // Reuse a durable proof after a crash. It is still tied to the same receipt;
    // no new timestamp or re-proving is needed merely because the reply was lost.
    let prepared = match journal.prepared.as_ref() {
        Some(p)
            if !reprove
                && p.outcome.proof.starts_with(perp_core::clock::PROOF_MAGIC)
                && p.outcome.proof.len() > perp_core::clock::PROOF_MAGIC.len() + 32 =>
        {
            p.clone()
        }
        _ => crate::prover_client::prove_and_prepare(client, &journal.witness, &journal.ww)?,
    };
    // A re-proof is bound to the anchor the journal's proof was bound to.
    if reprove
        && journaled_receipt.is_some_and(|r| proof_receipt(&prepared.outcome.proof) != Some(r))
    {
        return Err(
            "the new proof is bound to another anchor than the journal's; reclassify".into(),
        );
    }
    journal.prepared = Some(prepared.clone());
    // The rewrite keeps the journal's authenticated version: a candidate v6
    // journal must stay v6 (envelope intact), a legacy journal stays v5.
    crate::rollback_journal::write_versioned(path, journal, envelope, seed)?;
    if let ResumeMode::Recovery { .. } = mode {
        // A cancel finalized after the classification, or still unfinalized, is
        // visible here; nothing is sent then, so no nonce is recorded.
        let receipt = proof_receipt(&prepared.outcome.proof)
            .ok_or("a clock proof carries no receipt; reclassify")?;
        chain.anchor_live_at_latest(
            journal.batch_id,
            prepared.outcome.wind_down_phase,
            &receipt,
        )?;
    }
    chain.settle_proved(&prepared.outcome)?;
    chain.settlement_observation()
}

/// The receipt inside a clock-tagged proof (`PROOF_MAGIC ‖ receipt ‖ inner`).
fn proof_receipt(proof: &[u8]) -> Option<perp_core::Digest> {
    proof
        .strip_prefix(perp_core::clock::PROOF_MAGIC)
        .and_then(|body| body.get(..32))
        .and_then(|r| r.try_into().ok())
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
            register: RegisterMode::SendIfAbsent,
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

    /// A remote prover whose identity read fails.
    struct UnreadableIdentity;
    impl ProverClient for UnreadableIdentity {
        fn prove(&self, _: &WindowWitness) -> Result<RemoteProveResp, ProverClientError> {
            unreachable!("registration preconditions never prove")
        }
        fn public_identity(
            &self,
        ) -> Result<Option<crate::prover_client::ProverPublicIdentity>, String> {
            Err("prover identity: timed out".into())
        }
    }

    /// In production a prover whose identity cannot be read registers no window:
    /// the refusal names the identity and comes before any L1 read. Outside
    /// production the failed read is tolerated and the preconditions go on to L1
    /// (here a closed port, so they stop there instead).
    #[test]
    fn production_registers_nothing_without_the_prover_identity() {
        let client = ClockProverClient {
            inner: Arc::new(UnreadableIdentity),
            l1: L1::test_clocked_reader("http://127.0.0.1:9".into(), [1; 20], 84532),
            register: RegisterMode::SendIfAbsent,
        };
        match client.register_preconditions_with(true) {
            Err(PreflightRefusal::Refused(e)) => {
                assert!(e.contains("identity could not be read"), "{e}");
                assert!(e.contains("timed out"), "{e}");
            }
            other => panic!("expected an identity refusal, got {other:?}"),
        }
        match client.register_preconditions_with(false) {
            Err(PreflightRefusal::Refused(e)) => {
                assert!(!e.contains("identity"), "tolerated outside production: {e}")
            }
            other => panic!("expected the L1 read to fail, got {other:?}"),
        }
        // An in-process client has no identity to compare and is not refused for it.
        let local = ClockProverClient {
            inner: Arc::new(MockProverClient),
            l1: L1::test_clocked_reader("http://127.0.0.1:9".into(), [1; 20], 84532),
            register: RegisterMode::SendIfAbsent,
        };
        match local.register_preconditions_with(true) {
            Err(PreflightRefusal::Refused(e)) => assert!(!e.contains("identity"), "{e}"),
            other => panic!("expected the L1 read to fail, got {other:?}"),
        }
    }

    /// Production with a remote prover refuses to boot without the expected
    /// guest ELF hash; a malformed value is refused in every posture.
    #[test]
    fn production_boot_requires_the_expected_guest_elf_hash() {
        let hash = "ab".repeat(32);
        for value in [None, Some("")] {
            let refused = require_expected_elf_at_boot(true, value).unwrap_err();
            assert!(refused.contains(EXPECTED_ELF_VAR), "{refused}");
            require_expected_elf_at_boot(false, value).unwrap();
        }
        for required in [true, false] {
            require_expected_elf_at_boot(required, Some(&hash)).unwrap();
            require_expected_elf_at_boot(required, Some(&format!("0x{hash}"))).unwrap();
            assert!(require_expected_elf_at_boot(required, Some("0x12")).is_err());
            assert!(require_expected_elf_at_boot(required, Some(&"zz".repeat(32))).is_err());
        }
        assert_eq!(parse_expected_elf_sha256(Some(&hash)), Ok(Some([0xab; 32])));
        assert_eq!(parse_expected_elf_sha256(None), Ok(None));
    }

    /// A settlement at batch `batch` and root `root` whose latest-block anchor
    /// check answers `latest`. Each call is recorded, and a settle records its
    /// nonce in `fence` first, as every sequencer-key send does.
    struct FakeChain {
        batch: u64,
        root: String,
        latest: Result<(), String>,
        calls: std::sync::Mutex<Vec<&'static str>>,
        fence: crate::l1::NonceFence,
        fence_path: std::path::PathBuf,
    }
    impl FakeChain {
        fn new(batch: u64, root: &str, latest: Result<(), String>) -> Self {
            let fence_path = scratch("fence");
            Self {
                batch,
                root: root.into(),
                latest,
                calls: Default::default(),
                fence: crate::l1::NonceFence::open(fence_path.clone(), [3; 32], false).unwrap(),
                fence_path,
            }
        }
        fn calls(&self) -> Vec<&'static str> {
            self.calls.lock().unwrap().clone()
        }
    }
    impl Drop for FakeChain {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.fence_path);
        }
    }
    impl ResumeChain for FakeChain {
        fn clock_enabled(&self) -> bool {
            true
        }
        fn settlement_observation(&self) -> Result<(u64, String, u128), String> {
            self.calls.lock().unwrap().push("observe");
            Ok((self.batch, self.root.clone(), 0))
        }
        fn anchor_live_at_latest(
            &self,
            batch: u64,
            phase: u8,
            receipt: &perp_core::Digest,
        ) -> Result<(), String> {
            self.calls.lock().unwrap().push("recheck");
            assert_eq!((batch, phase), (self.batch, 0));
            assert_ne!(receipt, &[0; 32]);
            self.latest.clone()
        }
        fn settle_proved(
            &self,
            out: &crate::prover_client::ProveOutcome,
        ) -> Result<String, String> {
            self.calls.lock().unwrap().push("settle");
            assert!(proof_receipt(&out.proof).is_some());
            self.fence.cover(9)?;
            Ok("0xsettle".into())
        }
    }

    /// The mock prover behind an anchor that already exists.
    struct Anchored(ClockContext);
    impl ProverClient for Anchored {
        fn clock_enabled(&self) -> bool {
            true
        }
        fn clock_context(
            &self,
            _: &WindowWitness,
        ) -> Result<Option<ClockContext>, ProverClientError> {
            Ok(Some(self.0))
        }
        fn prove(&self, w: &WindowWitness) -> Result<RemoteProveResp, ProverClientError> {
            MockProverClient.prove(w)
        }
        fn prove_clocked(
            &self,
            w: &WindowWitness,
            c: &ClockContext,
        ) -> Result<RemoteProveResp, ProverClientError> {
            MockProverClient.prove_clocked(w, c)
        }
    }

    fn scratch(tag: &str) -> std::path::PathBuf {
        let mut rnd = [0u8; 8];
        getrandom::getrandom(&mut rnd).unwrap();
        let suffix: String = rnd.iter().map(|b| format!("{b:02x}")).collect();
        std::env::temp_dir().join(format!("darkperp-resume-{tag}-{suffix}"))
    }

    /// A sealed window, the anchor its registration made, and its journal with a
    /// durable proof bound to that anchor (inner proof `[7; 32]`).
    fn anchored_journal() -> (
        crate::rollback_journal::RollbackJournal,
        ClockContext,
        String,
    ) {
        let (w, ww) = sample_window();
        let d = perp_core::commitment::derive_roots(&mut w.pre_state.clone(), &w.ops, &w.manifest)
            .unwrap();
        let b = perp_core::clock::TimeBounds::derive(&w.ops).unwrap();
        let c = ClockContext {
            chain_id: 84532,
            verifier: [0x11; 20],
            settlement: [0x22; 20],
            batch_id: w.batch_id,
            previous_root: d.prev_state_root,
            base_commitment: d.commitment::<perp_core::Keccak256>(),
            phase: d.wind_down_phase,
            first_ms: b.first_ms,
            last_ms: b.last_ms,
            timed_ops: b.count,
            anchored_at_ms: b.last_ms,
            max_window_ms: 10_000,
            clock_skew_ms: 2_000,
        };
        let mut prepared = crate::prover_client::prepare_unproved(&w, &ww).unwrap();
        let root = crate::hex32(&prepared.outcome.prev_root);
        prepared.outcome.proof = perp_core::clock::PROOF_MAGIC.to_vec();
        prepared.outcome.proof.extend(c.receipt());
        prepared.outcome.proof.extend([7; 32]);
        let journal = crate::rollback_journal::RollbackJournal {
            batch_id: w.batch_id,
            witness: w,
            ww,
            prepared: Some(prepared),
        };
        (journal, c, root)
    }

    fn proof_of(j: &crate::rollback_journal::RollbackJournal) -> Vec<u8> {
        j.prepared.as_ref().unwrap().outcome.proof.clone()
    }

    #[test]
    fn the_recovery_settle_rechecks_the_anchor_at_latest() {
        let (journal, c, root) = anchored_journal();
        let (path, seed) = (scratch("journal"), [5; 32]);
        let recovery = ResumeMode::Recovery { reprove: false };
        // Cancelled, gone or replaced at the latest block, or unreadable there:
        // nothing is sent, so no nonce is recorded.
        for refusal in [
            "clock anchor cancelled at the latest block; nothing sent; reclassify",
            "clock anchor no longer registered at the latest block; nothing sent; reclassify",
            "the latest anchor read failed (timed out); nothing sent; reclassify",
        ] {
            let chain = FakeChain::new(journal.batch_id, &root, Err(refusal.into()));
            let mut j = journal.clone();
            assert_eq!(
                resume_exact_with(&chain, &Anchored(c), &mut j, None, &path, &seed, recovery),
                Err(refusal.to_string())
            );
            assert_eq!(chain.calls(), ["observe", "recheck"]);
            assert_eq!(chain.fence.ceiling(), crate::l1::Ceiling::None);
        }
        // A live anchor: the recheck comes immediately before the settle.
        let chain = FakeChain::new(journal.batch_id, &root, Ok(()));
        let mut j = journal.clone();
        resume_exact_with(&chain, &Anchored(c), &mut j, None, &path, &seed, recovery).unwrap();
        assert_eq!(chain.calls(), ["observe", "recheck", "settle", "observe"]);
        assert_eq!(chain.fence.ceiling(), crate::l1::Ceiling::Nonce(9));
        // The durable proof is reused.
        assert_eq!(proof_of(&j), proof_of(&journal));
        // At boot the window was just classified; there is no latest recheck.
        let chain = FakeChain::new(journal.batch_id, &root, Err("not read at boot".into()));
        let mut j = journal.clone();
        resume_exact_with(
            &chain,
            &Anchored(c),
            &mut j,
            None,
            &path,
            &seed,
            ResumeMode::Boot,
        )
        .unwrap();
        assert_eq!(chain.calls(), ["observe", "settle", "observe"]);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_recovery_reprove_proves_again_against_the_same_anchor() {
        let (journal, c, root) = anchored_journal();
        let (path, seed) = (scratch("journal"), [5; 32]);
        let reprove = ResumeMode::Recovery { reprove: true };
        let chain = FakeChain::new(journal.batch_id, &root, Ok(()));
        let mut j = journal.clone();
        resume_exact_with(&chain, &Anchored(c), &mut j, None, &path, &seed, reprove).unwrap();
        let (old, new) = (
            &journal.prepared.as_ref().unwrap().outcome.proof,
            &j.prepared.as_ref().unwrap().outcome.proof,
        );
        assert_ne!(new, old, "the durable proof was dropped");
        assert_eq!(proof_receipt(new), Some(c.receipt()));
        assert_eq!(
            crate::rollback_journal::read(&path, &seed)
                .unwrap()
                .unwrap()
                .prepared
                .unwrap()
                .outcome
                .proof,
            *new,
            "the journal holds the new proof"
        );
        assert_eq!(chain.calls(), ["observe", "recheck", "settle", "observe"]);
        // A proof bound to another anchor is refused before the journal is
        // rewritten, and nothing is sent.
        let other = ClockContext {
            anchored_at_ms: c.anchored_at_ms + 1,
            ..c
        };
        assert_ne!(other.receipt(), c.receipt());
        let chain = FakeChain::new(journal.batch_id, &root, Ok(()));
        let mut j = journal.clone();
        let refused = resume_exact_with(
            &chain,
            &Anchored(other),
            &mut j,
            None,
            &path,
            &seed,
            reprove,
        )
        .unwrap_err();
        assert!(refused.ends_with("; reclassify"), "{refused}");
        assert_eq!(proof_of(&j), proof_of(&journal));
        assert_eq!(chain.calls(), ["observe"]);
        assert_eq!(chain.fence.ceiling(), crate::l1::Ceiling::None);
        assert_eq!(
            crate::rollback_journal::read(&path, &seed)
                .unwrap()
                .unwrap()
                .prepared
                .unwrap()
                .outcome
                .proof,
            *new,
            "the journal on disk is unchanged"
        );
        let _ = std::fs::remove_file(&path);
    }
}

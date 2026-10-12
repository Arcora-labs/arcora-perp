//! Owned OFFLINE handoff over the unchanged #50 normal/liquidation corpus.
//! Transport observations, proof bytes, sender and outcomes are explicit mocks.
//! These tests assert cooperative local ownership, not RPC or exactly-once chain execution.
use crate::{
    candidate_broadcast::{
        build_plan, plan_bytes, plan_hash, Action, BridgeTarget, BroadcastError,
        BroadcastTransport, Outcome, OutcomeStatus, OutcomeValue, Plan, RunMode, SettlementEffect,
    },
    candidate_broadcast_store::{
        decode_sealed, BroadcastStore, Record as BroadcastRecord, StoreError as BroadcastStoreError,
    },
    candidate_handoff::{HandoffCoordinator, HandoffError},
    candidate_preparation::PreparationError,
    candidate_preparation_store::{CoordinationStore, StoreError as PreparationStoreError},
    candidate_preparation_tests::{PrepFixture, SOURCE_SEED},
    candidate_protocol::{
        CandidateProofResponse, ClockObservation, PreparedCandidate, ProtocolRequest,
        ReportObservation,
    },
    candidate_recovery::{
        request_bytes, Anchored, FinalityContext, Lookup, LookupState, PreparationTransport,
        PreparedCut, RegistrationAnchor, RunMode as PreparationMode,
    },
    candidate_recovery_store::{Record as SourceRecord, RecoveryStore, Stage},
    candidate_registration::Registration,
};
use perp_core::clock::ClockContext;
use serde_json::Value;
use std::{
    fs::{File, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

pub(crate) const BROADCAST_SEED: [u8; 32] = [0xd7; 32];
pub(crate) const SENDER: [u8; 20] = [0xc1; 20];
pub(crate) const NONCE: u64 = 7;
const FIXTURES: &str = "../../docs/audits/2026-10-11-chainlink-native-contract-bridge/fixtures";

fn bytes<const N: usize>(value: &Value, key: &str) -> [u8; N] {
    let value = value[key].as_str().unwrap().strip_prefix("0x").unwrap();
    assert_eq!(value.len(), N * 2);
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

/// Children borrow the parent's private temporary directory and never create
/// another scratch that could leak after SIGKILL. Construction writes no cut.
pub(crate) struct HandoffFixture {
    pub(crate) prep: PrepFixture,
    pub(crate) bridge: BridgeTarget,
}
impl HandoffFixture {
    pub(crate) fn new(flow: usize) -> Self {
        Self::from_prep(PrepFixture::new(flow), flow)
    }
    pub(crate) fn for_process(parent_dir: &Path) -> Self {
        Self::from_prep(PrepFixture::for_process(parent_dir), 0)
    }
    fn from_prep(prep: PrepFixture, flow: usize) -> Self {
        let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join(FIXTURES);
        let corpus: Value =
            serde_json::from_slice(&std::fs::read(fixtures.join("bridge.json")).unwrap()).unwrap();
        let context = &corpus["cases"][flow]["target_context"];
        Self {
            prep,
            bridge: BridgeTarget {
                sp1_adapter: bytes(context, "sp1_adapter"),
                sp1_gateway: bytes(context, "sp1_gateway"),
                prefix_vault: bytes(context, "prefix_vault"),
                sp1_adapter_code_hash: bytes(context, "sp1_adapter_code_hash"),
                sp1_gateway_code_hash: bytes(context, "sp1_gateway_code_hash"),
                prefix_vault_code_hash: bytes(context, "prefix_vault_code_hash"),
            },
        }
    }
    pub(crate) fn coordinator(&self) -> HandoffCoordinator {
        HandoffCoordinator::new(self.prep.source_path.clone(), SOURCE_SEED, BROADCAST_SEED).unwrap()
    }
    pub(crate) fn prepare(&self) -> PreparedCut {
        let coordinator = self.coordinator();
        let mut transport = Prepare {
            fixture: &self.prep,
            calls: 0,
        };
        let cut = coordinator
            .prepare(
                PreparationMode::Fresh,
                &self.prep.request,
                &self.prep.trusted,
                &mut transport,
            )
            .unwrap();
        assert_eq!(transport.calls, 8);
        assert_eq!(cut.record, self.source());
        assert_eq!(cut.record.stage, Stage::Prepared);
        cut
    }
    pub(crate) fn source(&self) -> SourceRecord {
        RecoveryStore::new(self.prep.source_path.clone(), SOURCE_SEED)
            .load()
            .unwrap()
            .unwrap()
    }
    pub(crate) fn plan(&self) -> Plan {
        build_plan(
            &self.source(),
            &self.prep.request,
            &self.prep.trusted,
            &self.bridge,
            SENDER,
            NONCE,
        )
        .unwrap()
    }
}

struct Prepare<'a> {
    fixture: &'a PrepFixture,
    calls: usize,
}
impl PreparationTransport for Prepare<'_> {
    fn register_clock(&mut self, clock: &ClockContext) -> Result<(), ()> {
        self.calls += 1;
        assert_eq!(*clock, self.fixture.clock.value.context);
        Ok(())
    }
    fn lookup_clock(&mut self, clock: &ClockContext) -> Result<Lookup<ClockObservation>, ()> {
        self.calls += 1;
        assert_eq!(*clock, self.fixture.clock.value.context);
        Ok(Lookup::Finalized(self.fixture.clock_read()))
    }
    fn register_reports(&mut self, registration: &Registration) -> Result<(), ()> {
        self.calls += 1;
        assert_eq!(
            registration.input_hash,
            self.fixture.reports.value.input_hash
        );
        assert_eq!(
            registration.evidence_hash,
            self.fixture.reports.value.evidence_hash
        );
        Ok(())
    }
    fn lookup_reports(
        &mut self,
        registration: &Registration,
    ) -> Result<Lookup<ReportObservation>, ()> {
        self.calls += 1;
        assert_eq!(
            registration.input_hash,
            self.fixture.reports.value.input_hash
        );
        Ok(Lookup::Finalized(self.fixture.report_read()))
    }
    fn prove(&mut self, request: &ProtocolRequest) -> Result<CandidateProofResponse, ()> {
        self.calls += 1;
        assert_eq!(
            request_bytes(request).unwrap(),
            request_bytes(&self.fixture.request).unwrap()
        );
        Ok(self.fixture.response())
    }
}

pub(crate) fn success(plan: &Plan) -> Outcome {
    Anchored {
        value: OutcomeValue {
            attempt_id: plan.attempt_id,
            mock_tx_id: plan.mock_tx_id,
            plan_hash: plan_hash(plan).unwrap(),
            target: plan.target.clone(),
            call_hash: plan.call_hash,
            public_values: plan.public_values,
            status: OutcomeStatus::Success(Box::new(SettlementEffect {
                post_root: plan.roots[2],
                batch_count: plan.batch_id + 1,
                batch_id: plan.batch_id,
                manifest_hash: plan.roots[1],
                ordered_root: plan.roots[3],
                rejected_root: plan.roots[5],
                settled_at_block: 50,
                withdrawal_root: plan.roots[4],
                withdrawal_epoch: plan.batch_id,
                publication_count: 1,
                consumed_deposit_count: plan.consumed_deposit_count,
                consumed_deposit_tip: plan.consumed_deposit_tip,
            })),
        },
        anchor: RegistrationAnchor {
            block_number: 50,
            block_hash: [0x50; 32],
            tx_hash: plan.mock_tx_id,
        },
        finality: FinalityContext {
            canonical_block_hash: [0x50; 32],
            finalized_block_number: 55,
            finalized_block_hash: [0x55; 32],
        },
    }
}

#[derive(Clone, Copy, Debug)]
enum Failure {
    Write,
    Rename,
    DirectorySync,
}
impl Failure {
    fn inject(self, coordinator: &HandoffCoordinator) {
        match self {
            Self::Write => coordinator.fail_next_write(),
            Self::Rename => coordinator.fail_next_rename(),
            Self::DirectorySync => coordinator.fail_next_directory_sync(),
        }
    }
    fn error(self) -> HandoffError {
        HandoffError::Broadcast(BroadcastError::Store(match self {
            Self::Write | Self::Rename => BroadcastStoreError::Write,
            Self::DirectorySync => BroadcastStoreError::AmbiguousWrite,
        }))
    }
}
#[derive(Clone, Copy, Debug)]
enum Attack {
    SourceAppend,
    SourceReplace,
    BindingAppend,
    SourceLockReplace,
    BroadcastAppend,
    BroadcastReplace,
    BroadcastLockReplace,
}
impl Attack {
    fn path(self, coordinator: &HandoffCoordinator) -> &Path {
        match self {
            Self::SourceAppend | Self::SourceReplace => coordinator.source_path(),
            Self::BindingAppend => coordinator.binding_path(),
            Self::SourceLockReplace => coordinator.source_lock_path(),
            Self::BroadcastAppend | Self::BroadcastReplace => coordinator.broadcast_path(),
            Self::BroadcastLockReplace => coordinator.broadcast_lock_path(),
        }
    }
    fn apply(self, coordinator: &HandoffCoordinator) {
        let path = self.path(coordinator);
        match self {
            Self::SourceAppend | Self::BindingAppend | Self::BroadcastAppend => {
                let mut file = OpenOptions::new().append(true).open(path).unwrap();
                file.write_all(&[0]).unwrap();
                file.sync_all().unwrap();
            }
            _ => {
                // Keep the old inode open; same bytes on another inode cannot
                // evade FileCut fences or be hidden by filesystem inode reuse.
                let _old = File::open(path).unwrap();
                let contents = std::fs::read(path).unwrap();
                let replacement = path.with_extension("foreign-test-replacement");
                let mut file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&replacement)
                    .unwrap();
                file.write_all(&contents).unwrap();
                file.sync_all().unwrap();
                std::fs::rename(replacement, path).unwrap();
            }
        }
    }
}

struct Mock<'a> {
    fixture: &'a HandoffFixture,
    coordinator: &'a HandoffCoordinator,
    expected: Plan,
    calls: Vec<Action>,
    pending_before_lookup: Option<Vec<u8>>,
    failure: Option<(Action, Failure)>,
    callback_failure: Option<Action>,
    attack: Option<(Action, Attack)>,
    callback_after_attack_fails: bool,
    recheck: Option<(Anchored<ClockObservation>, Anchored<ReportObservation>)>,
    lookup: Option<Lookup<OutcomeValue>>,
}
impl<'a> Mock<'a> {
    fn new(fixture: &'a HandoffFixture, coordinator: &'a HandoffCoordinator) -> Self {
        Self {
            fixture,
            coordinator,
            expected: fixture.plan(),
            calls: vec![],
            pending_before_lookup: None,
            failure: None,
            callback_failure: None,
            attack: None,
            callback_after_attack_fails: false,
            recheck: None,
            lookup: None,
        }
    }
    fn run(&mut self, mode: RunMode) -> Result<Outcome, HandoffError> {
        self.coordinator.handoff(
            mode,
            &self.fixture.prep.request,
            &self.fixture.prep.trusted,
            &self.fixture.bridge,
            SENDER,
            NONCE,
            self,
        )
    }
    fn action(&mut self, action: Action, plan: &Plan) -> Result<(), ()> {
        assert_eq!(plan, &self.expected);
        assert_eq!(self.fixture.source().stage, Stage::Prepared);
        assert_eq!(
            self.fixture.source().request,
            request_bytes(&self.fixture.prep.request).unwrap()
        );
        // Independent handles contend on both actual kernel locks at every
        // callback, rather than merely observing a wrapper-local flag.
        let source =
            CoordinationStore::new(self.fixture.prep.source_path.clone(), SOURCE_SEED).unwrap();
        assert!(matches!(
            source.try_lease(),
            Err(PreparationStoreError::Busy)
        ));
        let broadcast = BroadcastStore::new(
            self.coordinator.broadcast_path().to_path_buf(),
            BROADCAST_SEED,
        )
        .unwrap();
        assert!(matches!(
            broadcast.try_lease(),
            Err(BroadcastStoreError::Busy)
        ));
        self.calls.push(action);
        if action == Action::Recheck {
            assert!(!self.coordinator.broadcast_path().exists());
        } else {
            let bytes = std::fs::read(self.coordinator.broadcast_path()).unwrap();
            let cut = decode_sealed(&bytes, &BROADCAST_SEED).unwrap();
            assert_eq!(cut.plan, plan_bytes(plan).unwrap());
            assert!(cut.outcome.is_none());
            self.pending_before_lookup = Some(bytes);
        }
        if let Some((at, failure)) = self.failure {
            if at == action {
                failure.inject(self.coordinator);
            }
        }
        if let Some((at, attack)) = self.attack {
            if at == action {
                attack.apply(self.coordinator);
                if self.callback_after_attack_fails {
                    return Err(());
                }
            }
        }
        if self.callback_failure == Some(action) {
            return Err(());
        }
        Ok(())
    }
}
impl BroadcastTransport for Mock<'_> {
    fn recheck(
        &mut self,
        plan: &Plan,
    ) -> Result<(Anchored<ClockObservation>, Anchored<ReportObservation>), ()> {
        self.action(Action::Recheck, plan)?;
        Ok(self.recheck.clone().unwrap_or_else(|| {
            (
                self.fixture.prep.clock_read(),
                self.fixture.prep.report_read(),
            )
        }))
    }
    fn broadcast(&mut self, plan: &Plan) -> Result<(), ()> {
        self.action(Action::Broadcast, plan)
    }
    fn lookup(&mut self, plan: &Plan) -> Result<Lookup<OutcomeValue>, ()> {
        self.action(Action::Lookup, plan)?;
        Ok(self
            .lookup
            .clone()
            .unwrap_or_else(|| Lookup::Finalized(success(plan))))
    }
}

struct NoCalls;
impl BroadcastTransport for NoCalls {
    fn recheck(
        &mut self,
        _: &Plan,
    ) -> Result<(Anchored<ClockObservation>, Anchored<ReportObservation>), ()> {
        panic!("guard refusal invoked recheck")
    }
    fn broadcast(&mut self, _: &Plan) -> Result<(), ()> {
        panic!("guard refusal invoked broadcast")
    }
    fn lookup(&mut self, _: &Plan) -> Result<Lookup<OutcomeValue>, ()> {
        panic!("guard refusal invoked lookup")
    }
}

fn disk_cut(coordinator: &HandoffCoordinator) -> BroadcastRecord {
    decode_sealed(
        &std::fs::read(coordinator.broadcast_path()).unwrap(),
        &BROADCAST_SEED,
    )
    .unwrap()
}
fn pending(fixture: &HandoffFixture, coordinator: &HandoffCoordinator) -> Vec<u8> {
    let mut lost = Mock::new(fixture, coordinator);
    lost.callback_failure = Some(Action::Broadcast);
    assert_eq!(
        lost.run(RunMode::Fresh),
        Err(HandoffError::Broadcast(BroadcastError::Callback(
            Action::Broadcast
        )))
    );
    assert_eq!(lost.calls, [Action::Recheck, Action::Broadcast]);
    let bytes = std::fs::read(coordinator.broadcast_path()).unwrap();
    assert!(disk_cut(coordinator).outcome.is_none());
    bytes
}

#[test]
fn handoff_both_real_lifecycle_inputs_prepare_then_settle_exact_native_plan() {
    for flow in 0..2 {
        let fixture = HandoffFixture::new(flow);
        let prepared = fixture.prepare();
        let coordinator = fixture.coordinator();
        let source_before = std::fs::read(coordinator.source_path()).unwrap();
        let binding_before = std::fs::read(coordinator.binding_path()).unwrap();
        let plan = fixture.plan();
        assert_eq!(plan.public_values, prepared.prepared.native.commitment);
        assert_eq!(plan.consumed_deposit_count, 9);
        assert_ne!(plan.consumed_deposit_tip, [0; 32]);
        let mut mock = Mock::new(&fixture, &coordinator);
        assert_eq!(mock.run(RunMode::Fresh).unwrap(), success(&plan));
        assert_eq!(
            mock.calls,
            [Action::Recheck, Action::Broadcast, Action::Lookup]
        );
        assert_eq!(disk_cut(&coordinator).plan, plan_bytes(&plan).unwrap());
        assert_eq!(
            std::fs::read(coordinator.source_path()).unwrap(),
            source_before
        );
        assert_eq!(
            std::fs::read(coordinator.binding_path()).unwrap(),
            binding_before
        );
        let final_bytes = std::fs::read(coordinator.broadcast_path()).unwrap();
        // New handles must validate and return the saved terminal result without
        // registrations, proving, recheck, broadcast, or lookup.
        let successor = fixture.coordinator();
        assert_eq!(
            successor
                .handoff(
                    RunMode::Resume,
                    &fixture.prep.request,
                    &fixture.prep.trusted,
                    &fixture.bridge,
                    SENDER,
                    NONCE,
                    &mut NoCalls
                )
                .unwrap(),
            success(&plan)
        );
        assert_eq!(
            std::fs::read(successor.broadcast_path()).unwrap(),
            final_bytes
        );
        assert_eq!(
            successor.handoff(
                RunMode::Fresh,
                &fixture.prep.request,
                &fixture.prep.trusted,
                &fixture.bridge,
                SENDER,
                NONCE,
                &mut NoCalls
            ),
            Err(HandoffError::Broadcast(BroadcastError::Store(
                BroadcastStoreError::Exists
            )))
        );
    }
}

#[test]
fn handoff_pending_resume_never_rechecks_or_broadcasts_and_preserves_hold_states() {
    let fixture = HandoffFixture::new(0);
    fixture.prepare();
    let coordinator = fixture.coordinator();
    let bytes = pending(&fixture, &coordinator);
    for (lookup, expected) in [
        (Lookup::Pending, LookupState::Pending),
        (Lookup::Absent, LookupState::Absent),
        (Lookup::Unknown, LookupState::Unknown),
        (Lookup::Reorg, LookupState::Reorg),
    ] {
        let successor = fixture.coordinator();
        let mut mock = Mock::new(&fixture, &successor);
        mock.lookup = Some(lookup);
        assert_eq!(
            mock.run(RunMode::Resume),
            Err(HandoffError::Broadcast(BroadcastError::Hold(expected)))
        );
        assert_eq!(mock.calls, [Action::Lookup]);
        assert_eq!(std::fs::read(successor.broadcast_path()).unwrap(), bytes);
    }
    let mut success_mock = Mock::new(&fixture, &coordinator);
    assert_eq!(
        success_mock.run(RunMode::Resume).unwrap(),
        success(&fixture.plan())
    );
    assert_eq!(success_mock.calls, [Action::Lookup]);
}

#[test]
fn handoff_reverted_finalized_attempt_is_terminal_and_never_resubmitted() {
    for flow in 0..2 {
        let fixture = HandoffFixture::new(flow);
        fixture.prepare();
        let coordinator = fixture.coordinator();
        let mut outcome = success(&fixture.plan());
        outcome.value.status = OutcomeStatus::Reverted(b"mock settlement reverted".to_vec());
        let mut mock = Mock::new(&fixture, &coordinator);
        mock.lookup = Some(Lookup::Finalized(outcome.clone()));
        assert_eq!(mock.run(RunMode::Fresh).unwrap(), outcome);
        let successor = fixture.coordinator();
        assert_eq!(
            successor
                .handoff(
                    RunMode::Resume,
                    &fixture.prep.request,
                    &fixture.prep.trusted,
                    &fixture.bridge,
                    SENDER,
                    NONCE,
                    &mut NoCalls
                )
                .unwrap(),
            outcome
        );
    }
}

#[test]
fn handoff_missing_or_partial_prepared_source_has_no_implicit_adoption() {
    let fixture = HandoffFixture::new(0);
    let coordinator = fixture.coordinator();
    assert_eq!(
        coordinator.handoff(
            RunMode::Fresh,
            &fixture.prep.request,
            &fixture.prep.trusted,
            &fixture.bridge,
            SENDER,
            NONCE,
            &mut NoCalls
        ),
        Err(HandoffError::Preparation(PreparationError::MissingBinding))
    );
    assert!(!coordinator.source_path().exists());
    assert!(!coordinator.binding_path().exists());
    assert!(!coordinator.broadcast_path().exists());
    // Explicit adoption of a valid Intent is allowed; handoff still requires
    // durable Prepared and cannot silently run registration or proving.
    let store = RecoveryStore::new(fixture.prep.source_path.clone(), SOURCE_SEED);
    let intent = store
        .create(&request_bytes(&fixture.prep.request).unwrap())
        .unwrap();
    coordinator
        .attach_existing(&fixture.prep.request, &fixture.prep.trusted)
        .unwrap();
    let before = std::fs::read(coordinator.source_path()).unwrap();
    assert!(coordinator
        .handoff(
            RunMode::Fresh,
            &fixture.prep.request,
            &fixture.prep.trusted,
            &fixture.bridge,
            SENDER,
            NONCE,
            &mut NoCalls
        )
        .is_err());
    assert_eq!(fixture.source(), intent);
    assert_eq!(std::fs::read(coordinator.source_path()).unwrap(), before);
    assert!(!coordinator.broadcast_path().exists());
}

#[test]
fn handoff_resume_without_attempt_does_not_invent_pending_or_call_transport() {
    let fixture = HandoffFixture::new(0);
    fixture.prepare();
    let coordinator = fixture.coordinator();
    assert_eq!(
        coordinator.handoff(
            RunMode::Resume,
            &fixture.prep.request,
            &fixture.prep.trusted,
            &fixture.bridge,
            SENDER,
            NONCE,
            &mut NoCalls
        ),
        Err(HandoffError::Broadcast(BroadcastError::Store(
            BroadcastStoreError::Missing
        )))
    );
    assert!(!coordinator.broadcast_path().exists());
}

#[test]
fn handoff_each_independent_lease_is_busy_before_any_callback() {
    let fixture = HandoffFixture::new(0);
    fixture.prepare();
    let coordinator = fixture.coordinator();
    let source_store =
        CoordinationStore::new(fixture.prep.source_path.clone(), SOURCE_SEED).unwrap();
    {
        let _source = source_store.try_lease().unwrap();
        assert_eq!(
            coordinator.handoff(
                RunMode::Fresh,
                &fixture.prep.request,
                &fixture.prep.trusted,
                &fixture.bridge,
                SENDER,
                NONCE,
                &mut NoCalls
            ),
            Err(HandoffError::Preparation(PreparationError::Store(
                PreparationStoreError::Busy
            )))
        );
    }
    let broadcast_store =
        BroadcastStore::new(coordinator.broadcast_path().to_path_buf(), BROADCAST_SEED).unwrap();
    {
        let _broadcast = broadcast_store.try_lease().unwrap();
        assert_eq!(
            coordinator.handoff(
                RunMode::Fresh,
                &fixture.prep.request,
                &fixture.prep.trusted,
                &fixture.bridge,
                SENDER,
                NONCE,
                &mut NoCalls
            ),
            Err(HandoffError::Broadcast(BroadcastError::Store(
                BroadcastStoreError::Busy
            )))
        );
        // Failure acquiring the second lease releases the first one.
        assert!(source_store.try_lease().is_ok());
    }
    let mut mock = Mock::new(&fixture, &coordinator);
    mock.run(RunMode::Fresh).unwrap();
    // Mock::action independently checks both leases at all three callbacks.
    assert_eq!(mock.calls.len(), 3);
}

#[test]
fn handoff_pending_write_failures_stop_before_broadcast_and_require_explicit_resume() {
    for failure in [Failure::Write, Failure::Rename, Failure::DirectorySync] {
        let fixture = HandoffFixture::new(0);
        fixture.prepare();
        let coordinator = fixture.coordinator();
        let source_before = std::fs::read(coordinator.source_path()).unwrap();
        let mut mock = Mock::new(&fixture, &coordinator);
        mock.failure = Some((Action::Recheck, failure));
        assert_eq!(mock.run(RunMode::Fresh), Err(failure.error()));
        assert_eq!(mock.calls, [Action::Recheck]);
        assert_eq!(
            std::fs::read(coordinator.source_path()).unwrap(),
            source_before
        );
        let successor = fixture.coordinator();
        match failure {
            Failure::Write | Failure::Rename => {
                assert!(!successor.broadcast_path().exists());
                assert_eq!(
                    successor.handoff(
                        RunMode::Resume,
                        &fixture.prep.request,
                        &fixture.prep.trusted,
                        &fixture.bridge,
                        SENDER,
                        NONCE,
                        &mut NoCalls
                    ),
                    Err(HandoffError::Broadcast(BroadcastError::Store(
                        BroadcastStoreError::Missing
                    )))
                );
            }
            Failure::DirectorySync => {
                let before = std::fs::read(successor.broadcast_path()).unwrap();
                assert!(disk_cut(&successor).outcome.is_none());
                let mut resume = Mock::new(&fixture, &successor);
                resume.lookup = Some(Lookup::Absent);
                assert_eq!(
                    resume.run(RunMode::Resume),
                    Err(HandoffError::Broadcast(BroadcastError::Hold(
                        LookupState::Absent
                    )))
                );
                assert_eq!(resume.calls, [Action::Lookup]);
                assert_eq!(std::fs::read(successor.broadcast_path()).unwrap(), before);
            }
        }
    }
}

#[test]
fn handoff_outcome_write_failures_keep_pending_or_visible_terminal_without_resending() {
    for failure in [Failure::Write, Failure::Rename, Failure::DirectorySync] {
        let fixture = HandoffFixture::new(0);
        fixture.prepare();
        let coordinator = fixture.coordinator();
        let source_before = std::fs::read(coordinator.source_path()).unwrap();
        let mut mock = Mock::new(&fixture, &coordinator);
        mock.failure = Some((Action::Lookup, failure));
        assert_eq!(mock.run(RunMode::Fresh), Err(failure.error()));
        assert_eq!(
            mock.calls,
            [Action::Recheck, Action::Broadcast, Action::Lookup]
        );
        assert_eq!(
            std::fs::read(coordinator.source_path()).unwrap(),
            source_before
        );
        let successor = fixture.coordinator();
        match failure {
            Failure::Write | Failure::Rename => {
                assert_eq!(
                    std::fs::read(successor.broadcast_path()).unwrap(),
                    mock.pending_before_lookup.unwrap()
                );
                assert!(disk_cut(&successor).outcome.is_none());
                let mut resume = Mock::new(&fixture, &successor);
                assert_eq!(
                    resume.run(RunMode::Resume).unwrap(),
                    success(&fixture.plan())
                );
                assert_eq!(resume.calls, [Action::Lookup]);
            }
            Failure::DirectorySync => {
                assert!(disk_cut(&successor).outcome.is_some());
                assert_eq!(
                    successor
                        .handoff(
                            RunMode::Resume,
                            &fixture.prep.request,
                            &fixture.prep.trusted,
                            &fixture.bridge,
                            SENDER,
                            NONCE,
                            &mut NoCalls
                        )
                        .unwrap(),
                    success(&fixture.plan())
                );
            }
        }
    }
}

#[test]
fn handoff_source_binding_and_lock_changes_at_every_callback_stop_next_action() {
    for action in [Action::Recheck, Action::Broadcast, Action::Lookup] {
        for attack in [
            Attack::SourceAppend,
            Attack::SourceReplace,
            Attack::BindingAppend,
            Attack::SourceLockReplace,
            Attack::BroadcastLockReplace,
        ] {
            let fixture = HandoffFixture::new(0);
            fixture.prepare();
            let coordinator = fixture.coordinator();
            let source_before = std::fs::read(coordinator.source_path()).unwrap();
            let mut mock = Mock::new(&fixture, &coordinator);
            mock.attack = Some((action, attack));
            // Mutation is checked even when the same callback returns failure.
            mock.callback_after_attack_fails = true;
            let error = mock.run(RunMode::Fresh).unwrap_err();
            assert!(!matches!(
                error,
                HandoffError::Broadcast(BroadcastError::Callback(_))
            ));
            let count = match action {
                Action::Recheck => 1,
                Action::Broadcast => 2,
                Action::Lookup => 3,
            };
            assert_eq!(mock.calls.len(), count);
            if action == Action::Recheck {
                assert!(!coordinator.broadcast_path().exists());
            } else {
                assert!(disk_cut(&coordinator).outcome.is_none());
            }
            // Foreign edits are deliberately not rolled back. Only an attack
            // on the source changes its content; the coordinator never writes it.
            if !matches!(attack, Attack::SourceAppend) {
                assert_eq!(
                    std::fs::read(coordinator.source_path()).unwrap(),
                    source_before
                );
            }
        }
    }
}

#[test]
fn handoff_broadcast_record_tamper_and_replacement_stop_before_outcome_save() {
    for action in [Action::Broadcast, Action::Lookup] {
        for attack in [Attack::BroadcastAppend, Attack::BroadcastReplace] {
            let fixture = HandoffFixture::new(0);
            fixture.prepare();
            let coordinator = fixture.coordinator();
            let mut mock = Mock::new(&fixture, &coordinator);
            mock.attack = Some((action, attack));
            assert!(mock.run(RunMode::Fresh).is_err());
            assert_eq!(
                mock.calls.len(),
                if action == Action::Broadcast { 2 } else { 3 }
            );
            if matches!(attack, Attack::BroadcastReplace) {
                assert!(disk_cut(&coordinator).outcome.is_none());
            } else {
                assert!(decode_sealed(
                    &std::fs::read(coordinator.broadcast_path()).unwrap(),
                    &BROADCAST_SEED
                )
                .is_err());
            }
        }
    }
}

#[test]
fn handoff_nonce_sender_bridge_and_request_changes_cannot_choose_another_lane() {
    let fixture = HandoffFixture::new(0);
    fixture.prepare();
    let coordinator = fixture.coordinator();
    let before = pending(&fixture, &coordinator);
    let fixed_path = coordinator.broadcast_path().to_path_buf();
    for (sender, nonce) in [([0xc2; 20], NONCE), (SENDER, NONCE + 1)] {
        let successor = fixture.coordinator();
        assert_eq!(successor.broadcast_path(), fixed_path);
        assert_eq!(
            successor.handoff(
                RunMode::Resume,
                &fixture.prep.request,
                &fixture.prep.trusted,
                &fixture.bridge,
                sender,
                nonce,
                &mut NoCalls
            ),
            Err(HandoffError::PlanMismatch)
        );
        assert_eq!(std::fs::read(successor.broadcast_path()).unwrap(), before);
    }
    let mut bridge = fixture.bridge.clone();
    bridge.sp1_gateway[0] ^= 1;
    assert_eq!(
        coordinator.handoff(
            RunMode::Resume,
            &fixture.prep.request,
            &fixture.prep.trusted,
            &bridge,
            SENDER,
            NONCE,
            &mut NoCalls
        ),
        Err(HandoffError::PlanMismatch)
    );
    let mut request: ProtocolRequest =
        postcard::from_bytes(&request_bytes(&fixture.prep.request).unwrap()).unwrap();
    request.target.settlement[0] ^= 1;
    assert!(coordinator
        .handoff(
            RunMode::Resume,
            &request,
            &fixture.prep.trusted,
            &fixture.bridge,
            SENDER,
            NONCE,
            &mut NoCalls
        )
        .is_err());
    assert_eq!(fixture.coordinator().broadcast_path(), fixed_path);
    assert_eq!(std::fs::read(coordinator.broadcast_path()).unwrap(), before);
}

fn replace_source(path: &Path, record: &SourceRecord) {
    let fields = [
        record.request.as_slice(),
        record.clock.as_deref().unwrap_or_default(),
        record.reports.as_deref().unwrap_or_default(),
        record.prepared.as_deref().unwrap_or_default(),
    ];
    let mut plain = b"DPCINT4\0".to_vec();
    plain.extend_from_slice(&[
        4,
        match record.stage {
            Stage::Intent => 0,
            Stage::ClockPending => 1,
            Stage::ClockObserved => 2,
            Stage::ReportsPending => 3,
            Stage::ReportsObserved => 4,
            Stage::Prepared => 5,
        },
    ]);
    for field in fields {
        plain.extend_from_slice(&(field.len() as u32).to_be_bytes());
        plain.extend_from_slice(field);
    }
    std::fs::write(path, crate::snapshot::seal(&plain, &SOURCE_SEED)).unwrap();
    let decoded = RecoveryStore::new(path.to_path_buf(), SOURCE_SEED)
        .load()
        .unwrap()
        .unwrap();
    assert_eq!(
        &decoded, record,
        "replacement must be an authenticated exact DPCINT4 cut"
    );
}

#[test]
fn handoff_authenticated_changed_proof_cannot_replace_the_pending_attempt() {
    let fixture = HandoffFixture::new(0);
    fixture.prepare();
    let coordinator = fixture.coordinator();
    let before = pending(&fixture, &coordinator);
    let fixed_path = coordinator.broadcast_path().to_path_buf();
    let mut source = fixture.source();
    let mut prepared: PreparedCandidate =
        postcard::from_bytes(source.prepared.as_deref().unwrap()).unwrap();
    prepared.response.proof.push(0xa7);
    source.prepared = Some(postcard::to_allocvec(&prepared).unwrap());
    replace_source(&fixture.prep.source_path, &source);
    crate::candidate_recovery::validate_stored_cut(
        &source,
        &fixture.prep.request,
        &fixture.prep.trusted,
    )
    .unwrap();
    let successor = fixture.coordinator();
    assert_eq!(successor.broadcast_path(), fixed_path);
    assert_eq!(
        successor.handoff(
            RunMode::Resume,
            &fixture.prep.request,
            &fixture.prep.trusted,
            &fixture.bridge,
            SENDER,
            NONCE,
            &mut NoCalls
        ),
        Err(HandoffError::PlanMismatch)
    );
    assert_eq!(std::fs::read(successor.broadcast_path()).unwrap(), before);
}

#[test]
fn handoff_recheck_epoch_anchor_and_finality_refusals_precede_pending_publication() {
    for mutation in 0..4 {
        let fixture = HandoffFixture::new(0);
        fixture.prepare();
        let coordinator = fixture.coordinator();
        let mut clock = fixture.prep.clock_read();
        let mut reports = fixture.prep.report_read();
        match mutation {
            0 => reports.value.epoch.started_at += 1,
            1 => clock.anchor.tx_hash[0] ^= 1,
            2 => reports.value.uptime_ready = false,
            _ => {
                clock.finality.finalized_block_number = 46;
                clock.finality.finalized_block_hash = [0x46; 32];
                // Individually valid reports still regress from the new tip.
            }
        }
        let mut mock = Mock::new(&fixture, &coordinator);
        mock.recheck = Some((clock, reports));
        assert!(mock.run(RunMode::Fresh).is_err());
        assert_eq!(mock.calls, [Action::Recheck]);
        assert!(!coordinator.broadcast_path().exists());
    }
}

#[test]
fn handoff_outcome_identity_effect_and_finality_refusals_keep_exact_pending() {
    for mutation in 0..6 {
        let fixture = HandoffFixture::new(0);
        fixture.prepare();
        let coordinator = fixture.coordinator();
        let before = pending(&fixture, &coordinator);
        let mut outcome = success(&fixture.plan());
        match mutation {
            0 => outcome.value.attempt_id[0] ^= 1,
            1 => outcome.value.public_values[0] ^= 1,
            2 => outcome.anchor.tx_hash[0] ^= 1,
            3 => {
                let OutcomeStatus::Success(effect) = &mut outcome.value.status else {
                    unreachable!()
                };
                effect.consumed_deposit_count -= 1;
            }
            4 => {
                let OutcomeStatus::Success(effect) = &mut outcome.value.status else {
                    unreachable!()
                };
                effect.publication_count = 2;
            }
            _ => {
                outcome.anchor.block_number = 43;
                outcome.anchor.block_hash = [0x43; 32];
                outcome.finality.canonical_block_hash = [0x43; 32];
                outcome.finality.finalized_block_number = 44;
                outcome.finality.finalized_block_hash = [0x44; 32];
            }
        }
        let mut mock = Mock::new(&fixture, &coordinator);
        mock.lookup = Some(Lookup::Finalized(outcome));
        assert!(mock.run(RunMode::Resume).is_err());
        assert_eq!(mock.calls, [Action::Lookup]);
        assert_eq!(std::fs::read(coordinator.broadcast_path()).unwrap(), before);
    }
}

#[test]
fn handoff_callback_failures_leave_only_acknowledged_attempt_and_resume_lookup_only() {
    for action in [Action::Recheck, Action::Broadcast, Action::Lookup] {
        let fixture = HandoffFixture::new(0);
        fixture.prepare();
        let coordinator = fixture.coordinator();
        let mut mock = Mock::new(&fixture, &coordinator);
        mock.callback_failure = Some(action);
        assert_eq!(
            mock.run(RunMode::Fresh),
            Err(HandoffError::Broadcast(BroadcastError::Callback(action)))
        );
        if action == Action::Recheck {
            assert!(!coordinator.broadcast_path().exists());
        } else {
            let successor = fixture.coordinator();
            let mut resume = Mock::new(&fixture, &successor);
            assert_eq!(
                resume.run(RunMode::Resume).unwrap(),
                success(&fixture.plan())
            );
            assert_eq!(resume.calls, [Action::Lookup]);
        }
    }
}

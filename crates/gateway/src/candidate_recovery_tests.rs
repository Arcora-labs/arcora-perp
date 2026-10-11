//! Offline registration recovery from actual A3 flows and owned mocked reads.
//! Canonical/finalized hints here are not cryptographic chain finality proofs.
use crate::{
    candidate_protocol::{
        CandidateProofResponse, ClockObservation, PreparedCandidate, ProgramIdentity,
        ProtocolRequest, ReportObservation, TargetIdentity, TrustedRequest, UptimeObservation,
    },
    candidate_recovery::*,
    candidate_recovery_store::{Record, RecoveryStore, Stage},
    candidate_registration::{registration, Registration, UptimeEpoch},
    price_lifecycle_tests::{protocol_fixture, protocol_price_free_fixture, Fixture},
};
use chainlink_oracle::binding::WIRE_MAGIC;
use perp_core::clock::ClockContext;
use std::{collections::VecDeque, path::PathBuf, sync::Arc};

const SEED: [u8; 32] = [0x65; 32];

struct Rig {
    guard: Fixture,
    request: ProtocolRequest,
    trusted: TrustedRequest,
    clock: ClockContext,
    registration: Registration,
}
impl Rig {
    fn new(flow: u8) -> Self {
        let (guard, witness, material) = if flow == 2 {
            protocol_price_free_fixture()
        } else {
            protocol_fixture(flow == 1)
        };
        let target = TargetIdentity {
            chain_id: witness.policy.chain_id,
            network: witness.policy.network,
            clock_verifier: witness.clock.3.verifier,
            settlement: witness.clock.3.settlement,
            oracle_wrapper: witness.policy.oracle_wrapper,
            verifier_proxy: witness.policy.verifier_proxy,
            policy_hash: witness.policy.hash().unwrap(),
            clock_version: 2,
            uptime_feed: [7; 20],
            grace_seconds: 60,
            settlement_code_hash: [0x11; 32],
            clock_code_hash: [0x12; 32],
            wrapper_code_hash: [0x13; 32],
            proxy_code_hash: [0x14; 32],
            uptime_code_hash: [0x15; 32],
        };
        let initial_uptime = if flow == 2 {
            UptimeObservation {
                epoch: UptimeEpoch {
                    round_id: [0; 10],
                    started_at: 0,
                },
                ready: false,
                observed_at_seconds: 0,
            }
        } else {
            UptimeObservation {
                epoch: UptimeEpoch {
                    round_id: [1; 10],
                    started_at: 1_000,
                },
                ready: true,
                observed_at_seconds: witness.clock.3.anchored_at_ms / 1000,
            }
        };
        let clock = witness.clock.3;
        let registration = registration(&witness.policy, &clock, &material.entries).unwrap();
        let mut bytes = WIRE_MAGIC.to_vec();
        bytes.extend(postcard::to_allocvec(&witness).unwrap());
        let request = ProtocolRequest {
            program: ProgramIdentity::pinned(),
            target: target.clone(),
            witness: bytes,
            material,
            initial_uptime,
        };
        let trusted = TrustedRequest::extracted(&request, target, initial_uptime);
        Self {
            guard,
            request,
            trusted,
            clock,
            registration,
        }
    }
    fn path(&self, name: &str) -> PathBuf {
        self.guard.protocol_dir().join(name)
    }
    fn clock_read(&self) -> Anchored<ClockObservation> {
        Anchored {
            value: ClockObservation {
                target: self.request.target.clone(),
                context: self.clock,
                receipt: self.clock.receipt(),
                registration_block: 42,
                registration_block_hash: [0x42; 32],
            },
            anchor: RegistrationAnchor {
                block_number: 42,
                block_hash: [0x42; 32],
                tx_hash: [0xa1; 32],
            },
            finality: FinalityContext {
                canonical_block_hash: [0x42; 32],
                finalized_block_number: 45,
                finalized_block_hash: [0x45; 32],
            },
        }
    }
    fn report_read(&self) -> Anchored<ReportObservation> {
        let native = chainlink_oracle::binding::run_encoded(&self.request.witness).unwrap();
        Anchored {
            value: ReportObservation {
                target: self.request.target.clone(),
                clock_commitment: native.clock_commitment,
                input_hash: self.registration.input_hash,
                evidence_hash: native.evidence_hash,
                epoch: self.request.initial_uptime.epoch,
                uptime_ready: self.request.initial_uptime.ready,
                observed_at_seconds: self.request.initial_uptime.observed_at_seconds,
            },
            anchor: RegistrationAnchor {
                block_number: 43,
                block_hash: [0x43; 32],
                tx_hash: [0xa2; 32],
            },
            finality: FinalityContext {
                canonical_block_hash: [0x43; 32],
                finalized_block_number: 45,
                finalized_block_hash: [0x45; 32],
            },
        }
    }
    fn response(&self) -> CandidateProofResponse {
        CandidateProofResponse {
            program: self.request.program.clone(),
            public_values: chainlink_oracle::binding::run_encoded(&self.request.witness)
                .unwrap()
                .commitment
                .to_vec(),
            proof: b"mock proof, not SP1 authenticity".to_vec(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Call {
    RegisterClock,
    LookupClock,
    RegisterReports,
    LookupReports,
    Prove,
    Broadcast,
}

const FRESH: [Call; 11] = [
    Call::RegisterClock,
    Call::LookupClock,
    Call::LookupClock,
    Call::RegisterReports,
    Call::LookupReports,
    Call::LookupClock,
    Call::LookupReports,
    Call::Prove,
    Call::LookupClock,
    Call::LookupReports,
    Call::Broadcast,
];
const FRESH_STAGES: [Stage; 11] = [
    Stage::ClockPending,
    Stage::ClockPending,
    Stage::ClockObserved,
    Stage::ReportsPending,
    Stage::ReportsPending,
    Stage::ReportsObserved,
    Stage::ReportsObserved,
    Stage::ReportsObserved,
    Stage::Prepared,
    Stage::Prepared,
    Stage::Prepared,
];

struct Mock {
    path: PathBuf,
    store: Arc<RecoveryStore>,
    expected_request: Vec<u8>,
    expected_clock: ClockContext,
    expected_abi: Vec<u8>,
    clock: Anchored<ClockObservation>,
    reports: Anchored<ReportObservation>,
    response: CandidateProofResponse,
    clocks: VecDeque<Lookup<ClockObservation>>,
    report_reads: VecDeque<Lookup<ReportObservation>>,
    calls: Vec<Call>,
    stages: Vec<Stage>,
    fail_at: Option<usize>,
    fail_save_at: Option<usize>,
    before_failed_save: Option<Vec<u8>>,
    proofs: Vec<Vec<u8>>,
    broadcast_values: Vec<PreparedCandidate>,
}
impl Mock {
    fn new(rig: &Rig, path: PathBuf, store: Arc<RecoveryStore>) -> Self {
        Self {
            path,
            store,
            expected_request: postcard::to_allocvec(&rig.request).unwrap(),
            expected_clock: rig.clock,
            expected_abi: rig.registration.entries_abi.clone(),
            clock: rig.clock_read(),
            reports: rig.report_read(),
            response: rig.response(),
            clocks: VecDeque::new(),
            report_reads: VecDeque::new(),
            calls: vec![],
            stages: vec![],
            fail_at: None,
            fail_save_at: None,
            before_failed_save: None,
            proofs: vec![],
            broadcast_values: vec![],
        }
    }
    fn action(&mut self, call: Call) -> Result<(), ()> {
        let record = self
            .store
            .load()
            .unwrap()
            .expect("durable record before every callback");
        assert_eq!(record.request, self.expected_request);
        let index = self.calls.len();
        self.calls.push(call);
        self.stages.push(record.stage);
        if self.fail_save_at == Some(index) {
            self.before_failed_save = Some(std::fs::read(&self.path).unwrap());
            self.store.fail_next_write();
        }
        if self.fail_at == Some(index) {
            Err(())
        } else {
            Ok(())
        }
    }
}
impl RecoveryTransport for Mock {
    fn register_clock(&mut self, clock: &ClockContext) -> Result<(), ()> {
        self.action(Call::RegisterClock)?;
        assert_eq!(*clock, self.expected_clock);
        assert_eq!(self.stages.last(), Some(&Stage::ClockPending));
        Ok(())
    }
    fn lookup_clock(&mut self, clock: &ClockContext) -> Result<Lookup<ClockObservation>, ()> {
        self.action(Call::LookupClock)?;
        assert_eq!(*clock, self.expected_clock);
        Ok(self
            .clocks
            .pop_front()
            .unwrap_or_else(|| Lookup::Finalized(self.clock.clone())))
    }
    fn register_reports(&mut self, registration: &Registration) -> Result<(), ()> {
        self.action(Call::RegisterReports)?;
        assert_eq!(registration.entries_abi, self.expected_abi);
        assert_eq!(self.stages.last(), Some(&Stage::ReportsPending));
        Ok(())
    }
    fn lookup_reports(
        &mut self,
        registration: &Registration,
    ) -> Result<Lookup<ReportObservation>, ()> {
        self.action(Call::LookupReports)?;
        assert_eq!(registration.entries_abi, self.expected_abi);
        Ok(self
            .report_reads
            .pop_front()
            .unwrap_or_else(|| Lookup::Finalized(self.reports.clone())))
    }
    fn prove(&mut self, request: &ProtocolRequest) -> Result<CandidateProofResponse, ()> {
        self.action(Call::Prove)?;
        assert_eq!(
            postcard::to_allocvec(request).unwrap(),
            self.expected_request
        );
        assert_eq!(self.stages.last(), Some(&Stage::ReportsObserved));
        self.proofs.push(request.witness.clone());
        Ok(self.response.clone())
    }
    fn broadcast(&mut self, prepared: &PreparedCandidate) -> Result<(), ()> {
        self.action(Call::Broadcast)?;
        assert_eq!(self.stages.last(), Some(&Stage::Prepared));
        self.broadcast_values.push(prepared.clone());
        Ok(())
    }
}
fn new_store(rig: &Rig, name: &str) -> (PathBuf, Arc<RecoveryStore>) {
    let path = rig.path(name);
    (path.clone(), Arc::new(RecoveryStore::new(path, SEED)))
}
fn run(
    rig: &Rig,
    mode: RunMode,
    store: &RecoveryStore,
    mock: &mut Mock,
) -> Result<PreparedCandidate, RecoveryError> {
    execute(mode, &rig.request, &rig.trusted, store, mock)
}
fn action(call: Call) -> RecoveryAction {
    match call {
        Call::RegisterClock => RecoveryAction::RegisterClock,
        Call::LookupClock => RecoveryAction::LookupClock,
        Call::RegisterReports => RecoveryAction::RegisterReports,
        Call::LookupReports => RecoveryAction::LookupReports,
        Call::Prove => RecoveryAction::Prove,
        Call::Broadcast => RecoveryAction::Broadcast,
    }
}

#[test]
fn recovery_actual_normal_liquidation_and_price_free_have_durable_exact_stages() {
    for flow in [0, 1, 2] {
        let rig = Rig::new(flow);
        let (path, store) = new_store(&rig, "success.recovery");
        let mut mock = Mock::new(&rig, path, store.clone());
        let prepared = run(&rig, RunMode::Fresh, &store, &mut mock).unwrap();
        assert_eq!(mock.calls, FRESH);
        assert_eq!(mock.stages, FRESH_STAGES);
        assert_eq!(
            mock.proofs.as_slice(),
            std::slice::from_ref(&rig.request.witness)
        );
        assert_eq!(
            mock.broadcast_values.as_slice(),
            std::slice::from_ref(&prepared)
        );
        assert_eq!(store.load().unwrap().unwrap().stage, Stage::Prepared);
        if flow == 2 {
            assert_eq!(
                prepared.reports.epoch,
                UptimeEpoch {
                    round_id: [0; 10],
                    started_at: 0
                }
            );
        }
        let before = std::fs::read(&mock.path).unwrap();
        let reopened = Arc::new(RecoveryStore::new(mock.path.clone(), SEED));
        let mut resumed = Mock::new(&rig, mock.path.clone(), reopened.clone());
        assert_eq!(
            run(&rig, RunMode::Resume, &reopened, &mut resumed).unwrap(),
            prepared
        );
        assert_eq!(
            resumed.calls,
            [Call::LookupClock, Call::LookupReports, Call::Broadcast]
        );
        assert!(resumed.proofs.is_empty());
        assert_eq!(std::fs::read(&mock.path).unwrap(), before);
    }
}

#[test]
fn recovery_fresh_existing_and_resume_missing_never_call_transport() {
    let rig = Rig::new(0);
    let (path, store) = new_store(&rig, "modes.recovery");
    let mut mock = Mock::new(&rig, path.clone(), store.clone());
    assert_eq!(
        run(&rig, RunMode::Resume, &store, &mut mock),
        Err(RecoveryError::MissingResume)
    );
    assert!(mock.calls.is_empty());
    assert!(!path.exists());
    store
        .create(&postcard::to_allocvec(&rig.request).unwrap())
        .unwrap();
    let bytes = std::fs::read(&path).unwrap();
    assert_eq!(
        run(&rig, RunMode::Fresh, &store, &mut mock),
        Err(RecoveryError::ExistingFresh)
    );
    assert!(mock.calls.is_empty());
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
}

#[test]
fn recovery_each_callback_fault_preserves_prior_attempt_counts_and_durable_stage() {
    let rig = Rig::new(0);
    for (index, call) in FRESH.iter().enumerate() {
        let (path, store) = new_store(&rig, &format!("fault-{index}.recovery"));
        let mut mock = Mock::new(&rig, path.clone(), store.clone());
        mock.fail_at = Some(index);
        assert_eq!(
            run(&rig, RunMode::Fresh, &store, &mut mock),
            Err(RecoveryError::Callback(action(*call)))
        );
        assert_eq!(mock.calls, FRESH[..=index]);
        let record = RecoveryStore::new(path, SEED).load().unwrap().unwrap();
        assert_eq!(record.stage, FRESH_STAGES[index]);
        assert_eq!(record.request, postcard::to_allocvec(&rig.request).unwrap());
    }
}

#[test]
fn recovery_intermediate_crash_restart_never_duplicates_registration() {
    let rig = Rig::new(1);
    for (index, stage, expected) in [
        (
            1,
            Stage::ClockPending,
            vec![
                Call::LookupClock,
                Call::LookupClock,
                Call::LookupReports,
                Call::LookupClock,
                Call::LookupReports,
                Call::Prove,
                Call::LookupClock,
                Call::LookupReports,
                Call::Broadcast,
            ],
        ),
        (
            2,
            Stage::ClockObserved,
            vec![
                Call::LookupClock,
                Call::LookupReports,
                Call::LookupClock,
                Call::LookupReports,
                Call::Prove,
                Call::LookupClock,
                Call::LookupReports,
                Call::Broadcast,
            ],
        ),
        (
            4,
            Stage::ReportsPending,
            vec![
                Call::LookupClock,
                Call::LookupReports,
                Call::LookupClock,
                Call::LookupReports,
                Call::Prove,
                Call::LookupClock,
                Call::LookupReports,
                Call::Broadcast,
            ],
        ),
        (
            7,
            Stage::ReportsObserved,
            vec![
                Call::LookupClock,
                Call::LookupReports,
                Call::Prove,
                Call::LookupClock,
                Call::LookupReports,
                Call::Broadcast,
            ],
        ),
        (
            8,
            Stage::Prepared,
            vec![Call::LookupClock, Call::LookupReports, Call::Broadcast],
        ),
    ] {
        let (path, store) = new_store(&rig, &format!("restart-{index}.recovery"));
        let mut first = Mock::new(&rig, path.clone(), store.clone());
        first.fail_at = Some(index);
        assert!(run(&rig, RunMode::Fresh, &store, &mut first).is_err());
        assert_eq!(first.calls, FRESH[..=index]);
        let record = store.load().unwrap().unwrap();
        assert_eq!(record.stage, stage);
        let before = std::fs::read(&path).unwrap();
        let reopened = Arc::new(RecoveryStore::new(path.clone(), SEED));
        let mut retry = Mock::new(&rig, path.clone(), reopened.clone());
        let prepared = run(&rig, RunMode::Resume, &reopened, &mut retry).unwrap();
        assert_eq!(retry.calls, expected, "{stage:?}");
        assert!(!retry.calls.contains(&Call::RegisterClock));
        assert!(!retry.calls.contains(&Call::RegisterReports));
        let after = reopened.load().unwrap().unwrap();
        assert_eq!(after.request, record.request);
        assert_eq!(prepared.response, rig.response());
        if stage == Stage::Prepared {
            assert_eq!(std::fs::read(&path).unwrap(), before);
            assert!(retry.proofs.is_empty());
        }
    }
}

#[test]
fn recovery_known_wrong_request_pins_refuse_before_durability_and_callbacks() {
    let rig = Rig::new(0);
    for reason in ["version", "program", "target", "material", "clock", "epoch"] {
        let mut bad = rig.request.clone();
        match reason {
            "version" => bad.program.wire_magic = *perp_core::clock::WIRE_MAGIC,
            "program" => bad.program.vkey[0] ^= 1,
            "target" => bad.target.proxy_code_hash[0] ^= 1,
            "material" => bad.material.entries[0].base_report[576] ^= 1,
            "clock" => {
                let mut w: chainlink_oracle::binding::CandidateWitness =
                    postcard::from_bytes(&bad.witness[8..]).unwrap();
                w.clock.3.anchored_at_ms += 100;
                bad.witness = WIRE_MAGIC.to_vec();
                bad.witness.extend(postcard::to_allocvec(&w).unwrap());
            }
            "epoch" => bad.initial_uptime.epoch.round_id[0] ^= 1,
            _ => unreachable!(),
        }
        let (path, store) = new_store(&rig, &format!("invalid-{reason}.recovery"));
        let mut mock = Mock::new(&rig, path.clone(), store.clone());
        assert!(execute(RunMode::Fresh, &bad, &rig.trusted, &store, &mut mock).is_err());
        assert!(mock.calls.is_empty(), "{reason}");
        assert!(!path.exists());
    }
}

fn hold_clock(state: LookupState) -> Lookup<ClockObservation> {
    match state {
        LookupState::Pending => Lookup::Pending,
        LookupState::Absent => Lookup::Absent,
        LookupState::Unknown => Lookup::Unknown,
        LookupState::Reorg => Lookup::Reorg,
    }
}
fn hold_report(state: LookupState) -> Lookup<ReportObservation> {
    match state {
        LookupState::Pending => Lookup::Pending,
        LookupState::Absent => Lookup::Absent,
        LookupState::Unknown => Lookup::Unknown,
        LookupState::Reorg => Lookup::Reorg,
    }
}
#[test]
fn recovery_pending_absent_unknown_and_reorg_stop_fresh_and_resume_later_calls() {
    let rig = Rig::new(0);
    for state in [
        LookupState::Pending,
        LookupState::Absent,
        LookupState::Unknown,
        LookupState::Reorg,
    ] {
        for report in [false, true] {
            let (path, store) = new_store(&rig, &format!("hold-{state:?}-{report}.recovery"));
            let mut mock = Mock::new(&rig, path.clone(), store.clone());
            if report {
                mock.report_reads.push_back(hold_report(state));
            } else {
                mock.clocks.push_back(hold_clock(state));
            }
            assert_eq!(
                run(&rig, RunMode::Fresh, &store, &mut mock),
                Err(RecoveryError::Hold(state))
            );
            assert_eq!(
                mock.calls,
                if report {
                    FRESH[..5].to_vec()
                } else {
                    FRESH[..2].to_vec()
                }
            );
            let before = std::fs::read(&path).unwrap();
            let stage = store.load().unwrap().unwrap().stage;
            assert_eq!(
                stage,
                if report {
                    Stage::ReportsPending
                } else {
                    Stage::ClockPending
                }
            );
            let reopened = Arc::new(RecoveryStore::new(path.clone(), SEED));
            let mut retry = Mock::new(&rig, path.clone(), reopened.clone());
            if report {
                retry.report_reads.push_back(hold_report(state));
            } else {
                retry.clocks.push_back(hold_clock(state));
            }
            assert_eq!(
                run(&rig, RunMode::Resume, &reopened, &mut retry),
                Err(RecoveryError::Hold(state))
            );
            assert_eq!(
                retry.calls,
                if report {
                    vec![Call::LookupClock, Call::LookupReports]
                } else {
                    vec![Call::LookupClock]
                }
            );
            assert_eq!(std::fs::read(&path).unwrap(), before);
        }
    }
}

#[test]
fn recovery_pre_attempt_absent_resume_only_looks_up_and_keeps_pending_cut() {
    let rig = Rig::new(0);
    for observed_clock in [false, true] {
        let (path, store) = new_store(&rig, &format!("pre-attempt-{observed_clock}.recovery"));
        if observed_clock {
            let mut first = Mock::new(&rig, path.clone(), store.clone());
            first.fail_at = Some(2);
            assert_eq!(
                run(&rig, RunMode::Fresh, &store, &mut first),
                Err(RecoveryError::Callback(RecoveryAction::LookupClock))
            );
            assert_eq!(first.calls, FRESH[..3]);
        } else {
            store
                .create(&postcard::to_allocvec(&rig.request).unwrap())
                .unwrap();
        }
        let original = store.load().unwrap().unwrap();
        assert_eq!(
            original.stage,
            if observed_clock {
                Stage::ClockObserved
            } else {
                Stage::Intent
            }
        );
        let reopened = Arc::new(RecoveryStore::new(path.clone(), SEED));
        let mut retry = Mock::new(&rig, path.clone(), reopened.clone());
        if observed_clock {
            retry.report_reads.push_back(Lookup::Absent);
        } else {
            retry.clocks.push_back(Lookup::Absent);
        }
        assert_eq!(
            run(&rig, RunMode::Resume, &reopened, &mut retry),
            Err(RecoveryError::Hold(LookupState::Absent))
        );
        assert_eq!(
            retry.calls,
            if observed_clock {
                vec![Call::LookupClock, Call::LookupReports]
            } else {
                vec![Call::LookupClock]
            }
        );
        let pending = reopened.load().unwrap().unwrap();
        assert_eq!(
            pending.stage,
            if observed_clock {
                Stage::ReportsPending
            } else {
                Stage::ClockPending
            }
        );
        assert_eq!(pending.request, original.request);
        assert_eq!(pending.clock, original.clock);
        assert_eq!(pending.reports, original.reports);
        assert!(pending.prepared.is_none());
        assert!(retry.proofs.is_empty());
        assert!(retry.broadcast_values.is_empty());
        // Only the conservative pending marker may advance. A later absent
        // lookup must retain that exact cut and must not register anything.
        let before = std::fs::read(&path).unwrap();
        let mut again = Mock::new(&rig, path.clone(), reopened.clone());
        if observed_clock {
            again.report_reads.push_back(Lookup::Absent);
        } else {
            again.clocks.push_back(Lookup::Absent);
        }
        assert_eq!(
            run(&rig, RunMode::Resume, &reopened, &mut again),
            Err(RecoveryError::Hold(LookupState::Absent))
        );
        assert_eq!(again.calls, retry.calls);
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
}

#[test]
fn recovery_clock_receipt_and_finality_refusals_stop_before_reports_registration() {
    let rig = Rig::new(0);
    for reason in [
        "tx-zero",
        "block-zero",
        "hash-zero",
        "canonical",
        "not-finalized",
        "tip-zero",
        "tip-hash-zero",
        "same-height-tip",
        "inner-block",
        "inner-hash",
        "receipt",
        "target",
    ] {
        let (path, store) = new_store(&rig, &format!("clock-{reason}.recovery"));
        let mut mock = Mock::new(&rig, path, store.clone());
        let mut bad = rig.clock_read();
        match reason {
            "tx-zero" => bad.anchor.tx_hash = [0; 32],
            "block-zero" => bad.anchor.block_number = 0,
            "hash-zero" => bad.anchor.block_hash = [0; 32],
            "canonical" => bad.finality.canonical_block_hash[0] ^= 1,
            "not-finalized" => bad.finality.finalized_block_number = 41,
            "tip-zero" => bad.finality.finalized_block_number = 0,
            "tip-hash-zero" => bad.finality.finalized_block_hash = [0; 32],
            "same-height-tip" => {
                bad.finality.finalized_block_number = 42;
                bad.finality.finalized_block_hash = [0x99; 32];
            }
            "inner-block" => bad.value.registration_block = 43,
            "inner-hash" => bad.value.registration_block_hash[0] ^= 1,
            "receipt" => bad.value.receipt[0] ^= 1,
            "target" => bad.value.target.settlement_code_hash[0] ^= 1,
            _ => unreachable!(),
        }
        mock.clocks.push_back(Lookup::Finalized(bad));
        assert!(
            run(&rig, RunMode::Fresh, &store, &mut mock).is_err(),
            "{reason}"
        );
        assert_eq!(mock.calls, FRESH[..2], "{reason}");
        assert_eq!(store.load().unwrap().unwrap().stage, Stage::ClockPending);
    }
}

#[test]
fn recovery_report_order_epoch_record_and_finality_refusals_stop_before_prove() {
    let rig = Rig::new(1);
    for reason in [
        "older-block",
        "same-block-wrong-hash",
        "tx-zero",
        "canonical",
        "not-finalized",
        "tip-regression",
        "tip-hash-swap",
        "epoch",
        "down",
        "old-time",
        "input",
        "evidence",
        "target",
        "clock",
    ] {
        let (path, store) = new_store(&rig, &format!("report-{reason}.recovery"));
        let mut mock = Mock::new(&rig, path, store.clone());
        let mut bad = rig.report_read();
        match reason {
            "older-block" => {
                bad.anchor.block_number = 41;
                bad.anchor.block_hash = [0x41; 32];
                bad.finality.canonical_block_hash = bad.anchor.block_hash;
            }
            "same-block-wrong-hash" => bad.anchor.block_number = 42,
            "tx-zero" => bad.anchor.tx_hash = [0; 32],
            "canonical" => bad.finality.canonical_block_hash[0] ^= 1,
            "not-finalized" => bad.finality.finalized_block_number = 42,
            "tip-regression" => {
                bad.finality.finalized_block_number = 44;
                bad.finality.finalized_block_hash = [0x44; 32];
            }
            "tip-hash-swap" => bad.finality.finalized_block_hash = [0x99; 32],
            "epoch" => bad.value.epoch.round_id[0] ^= 1,
            "down" => bad.value.uptime_ready = false,
            "old-time" => bad.value.observed_at_seconds -= 1,
            "input" => bad.value.input_hash[0] ^= 1,
            "evidence" => bad.value.evidence_hash[0] ^= 1,
            "target" => bad.value.target.uptime_code_hash[0] ^= 1,
            "clock" => bad.value.clock_commitment[0] ^= 1,
            _ => unreachable!(),
        }
        mock.report_reads.push_back(Lookup::Finalized(bad));
        assert!(
            run(&rig, RunMode::Fresh, &store, &mut mock).is_err(),
            "{reason}"
        );
        assert_eq!(mock.calls, FRESH[..5], "{reason}");
        assert_eq!(store.load().unwrap().unwrap().stage, Stage::ReportsPending);
    }
}

#[test]
fn recovery_same_height_matching_hash_and_advanced_finality_are_accepted() {
    let rig = Rig::new(0);
    let (path, store) = new_store(&rig, "same-height.recovery");
    let mut mock = Mock::new(&rig, path.clone(), store.clone());
    mock.reports.anchor.block_number = mock.clock.anchor.block_number;
    mock.reports.anchor.block_hash = mock.clock.anchor.block_hash;
    mock.reports.finality.canonical_block_hash = mock.clock.anchor.block_hash;
    let prepared = run(&rig, RunMode::Fresh, &store, &mut mock).unwrap();
    let before = std::fs::read(&path).unwrap();
    let reopened = Arc::new(RecoveryStore::new(path.clone(), SEED));
    let mut retry = Mock::new(&rig, path.clone(), reopened.clone());
    retry.reports = mock.reports.clone();
    for finality in [&mut retry.clock.finality, &mut retry.reports.finality] {
        finality.finalized_block_number = 46;
        finality.finalized_block_hash = [0x46; 32];
    }
    retry.reports.value.observed_at_seconds += 10;
    let resumed = run(&rig, RunMode::Resume, &reopened, &mut retry).unwrap();
    assert_eq!(resumed, prepared);
    assert_eq!(
        retry.calls,
        [Call::LookupClock, Call::LookupReports, Call::Broadcast]
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

#[test]
fn recovery_saved_tx_block_hash_epoch_and_prepared_recheck_never_refresh() {
    let rig = Rig::new(0);
    for reason in [
        "clock-tx",
        "clock-block",
        "clock-hash",
        "report-tx",
        "report-block",
        "report-hash",
        "epoch",
        "target",
        "unknown",
        "reorg",
        "not-finalized",
        "tip-regression-after-clock-advance",
        "tip-hash-swap-after-clock-advance",
    ] {
        let (path, store) = new_store(&rig, &format!("recheck-{reason}.recovery"));
        let mut first = Mock::new(&rig, path.clone(), store.clone());
        first.fail_at = Some(8);
        assert!(run(&rig, RunMode::Fresh, &store, &mut first).is_err());
        let before = std::fs::read(&path).unwrap();
        assert_eq!(store.load().unwrap().unwrap().stage, Stage::Prepared);
        let reopened = Arc::new(RecoveryStore::new(path.clone(), SEED));
        let mut retry = Mock::new(&rig, path.clone(), reopened.clone());
        let clock_failure =
            reason.starts_with("clock-") || matches!(reason, "unknown" | "reorg" | "not-finalized");
        match reason {
            "clock-tx" => retry.clock.anchor.tx_hash[0] ^= 1,
            "clock-block" => {
                retry.clock.anchor.block_number = 44;
                retry.clock.value.registration_block = 44;
            }
            "clock-hash" => {
                retry.clock.anchor.block_hash[0] ^= 1;
                retry.clock.value.registration_block_hash = retry.clock.anchor.block_hash;
                retry.clock.finality.canonical_block_hash = retry.clock.anchor.block_hash;
            }
            "report-tx" => retry.reports.anchor.tx_hash[0] ^= 1,
            "report-block" => retry.reports.anchor.block_number = 44,
            "report-hash" => {
                retry.reports.anchor.block_hash[0] ^= 1;
                retry.reports.finality.canonical_block_hash = retry.reports.anchor.block_hash;
            }
            "epoch" => retry.reports.value.epoch.round_id[0] ^= 1,
            "target" => retry.reports.value.target.wrapper_code_hash[0] ^= 1,
            "unknown" => retry.clocks.push_back(Lookup::Unknown),
            "reorg" => retry.clocks.push_back(Lookup::Reorg),
            "not-finalized" => retry.clock.finality.finalized_block_number = 41,
            "tip-regression-after-clock-advance" => {
                retry.clock.finality.finalized_block_number = 46;
                retry.clock.finality.finalized_block_hash = [0x46; 32];
            }
            "tip-hash-swap-after-clock-advance" => {
                retry.clock.finality.finalized_block_number = 46;
                retry.clock.finality.finalized_block_hash = [0x46; 32];
                retry.reports.finality.finalized_block_number = 46;
                retry.reports.finality.finalized_block_hash = [0x99; 32];
            }
            _ => unreachable!(),
        }
        let result = run(&rig, RunMode::Resume, &reopened, &mut retry);
        if reason.starts_with("tip-") {
            assert_eq!(result, Err(RecoveryError::Finality), "{reason}");
        } else {
            assert!(result.is_err(), "{reason}");
        }
        assert_eq!(
            retry.calls,
            if clock_failure {
                vec![Call::LookupClock]
            } else {
                vec![Call::LookupClock, Call::LookupReports]
            },
            "{reason}"
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert!(retry.proofs.is_empty());
        assert!(retry.broadcast_values.is_empty());
    }
}

#[test]
fn recovery_invalid_proof_response_stops_after_attempted_prove_before_prepared() {
    let rig = Rig::new(0);
    for reason in ["program", "public-width", "public-value", "empty-proof"] {
        let (path, store) = new_store(&rig, &format!("proof-{reason}.recovery"));
        let mut mock = Mock::new(&rig, path, store.clone());
        match reason {
            "program" => mock.response.program.vkey[0] ^= 1,
            "public-width" => {
                mock.response.public_values.pop();
            }
            "public-value" => mock.response.public_values[0] ^= 1,
            "empty-proof" => mock.response.proof.clear(),
            _ => unreachable!(),
        }
        assert!(run(&rig, RunMode::Fresh, &store, &mut mock).is_err());
        assert_eq!(mock.calls, FRESH[..8]);
        assert_eq!(store.load().unwrap().unwrap().stage, Stage::ReportsObserved);
        assert!(mock.broadcast_values.is_empty());
    }
}

#[test]
fn recovery_save_failures_preserve_exact_cut_and_stop_subsequent_actions() {
    let rig = Rig::new(0);
    let (path, store) = new_store(&rig, "initial-write.recovery");
    store.fail_next_write();
    let mut mock = Mock::new(&rig, path.clone(), store.clone());
    assert_eq!(
        run(&rig, RunMode::Fresh, &store, &mut mock),
        Err(RecoveryError::Durability)
    );
    assert!(mock.calls.is_empty());
    assert!(!path.exists());
    store
        .create(&postcard::to_allocvec(&rig.request).unwrap())
        .unwrap();
    let before = std::fs::read(&path).unwrap();
    store.fail_next_write();
    assert_eq!(
        run(&rig, RunMode::Resume, &store, &mut mock),
        Err(RecoveryError::Durability)
    );
    assert!(mock.calls.is_empty());
    assert_eq!(std::fs::read(&path).unwrap(), before);
    for (index, stage) in [
        (1, Stage::ClockPending),
        (2, Stage::ClockObserved),
        (4, Stage::ReportsPending),
        (7, Stage::ReportsObserved),
    ] {
        let (path, store) = new_store(&rig, &format!("save-{index}.recovery"));
        let mut mock = Mock::new(&rig, path.clone(), store.clone());
        mock.fail_save_at = Some(index);
        assert_eq!(
            run(&rig, RunMode::Fresh, &store, &mut mock),
            Err(RecoveryError::Durability)
        );
        assert_eq!(mock.calls, FRESH[..=index]);
        assert_eq!(store.load().unwrap().unwrap().stage, stage);
        assert_eq!(
            std::fs::read(&path).unwrap(),
            mock.before_failed_save.unwrap()
        );
        let reopened = Arc::new(RecoveryStore::new(path.clone(), SEED));
        let mut retry = Mock::new(&rig, path, reopened.clone());
        run(&rig, RunMode::Resume, &reopened, &mut retry).unwrap();
        assert!(!retry.calls.contains(&Call::RegisterClock));
        assert!(!retry.calls.contains(&Call::RegisterReports));
    }
}

#[test]
fn recovery_rename_failure_and_postpublication_ambiguity_require_reload() {
    let rig = Rig::new(0);
    for ambiguous in [false, true] {
        let (path, store) = new_store(&rig, &format!("publication-{ambiguous}.recovery"));
        store
            .create(&postcard::to_allocvec(&rig.request).unwrap())
            .unwrap();
        let before = std::fs::read(&path).unwrap();
        if ambiguous {
            store.fail_next_directory_sync();
        } else {
            store.fail_next_rename();
        }
        let mut mock = Mock::new(&rig, path.clone(), store.clone());
        assert_eq!(
            run(&rig, RunMode::Resume, &store, &mut mock),
            Err(RecoveryError::Durability)
        );
        assert!(mock.calls.is_empty());
        let reopened = Arc::new(RecoveryStore::new(path.clone(), SEED));
        let record = reopened.load().unwrap().unwrap();
        assert_eq!(
            record.stage,
            if ambiguous {
                Stage::ClockPending
            } else {
                Stage::Intent
            }
        );
        if !ambiguous {
            assert_eq!(std::fs::read(&path).unwrap(), before);
        }
        let mut retry = Mock::new(&rig, path, reopened.clone());
        run(&rig, RunMode::Resume, &reopened, &mut retry).unwrap();
        assert!(!retry.calls.contains(&Call::RegisterClock));
        assert!(!retry.calls.contains(&Call::RegisterReports));
    }
}

#[test]
fn recovery_changed_trusted_request_cannot_cross_resume_saved_intent() {
    let rig = Rig::new(0);
    let (path, store) = new_store(&rig, "changed-request.recovery");
    let mut first = Mock::new(&rig, path.clone(), store.clone());
    first.fail_at = Some(1);
    assert!(run(&rig, RunMode::Fresh, &store, &mut first).is_err());
    let before = std::fs::read(&path).unwrap();
    for reason in ["clock", "epoch"] {
        let mut changed = rig.request.clone();
        match reason {
            "clock" => {
                let mut w: chainlink_oracle::binding::CandidateWitness =
                    postcard::from_bytes(&changed.witness[8..]).unwrap();
                w.clock.3.anchored_at_ms += 100;
                changed.witness = WIRE_MAGIC.to_vec();
                changed.witness.extend(postcard::to_allocvec(&w).unwrap());
            }
            "epoch" => changed.initial_uptime.epoch.round_id[0] ^= 1,
            _ => unreachable!(),
        }
        let trust =
            TrustedRequest::extracted(&changed, rig.trusted.target.clone(), changed.initial_uptime);
        let reopened = Arc::new(RecoveryStore::new(path.clone(), SEED));
        let mut retry = Mock::new(&rig, path.clone(), reopened.clone());
        assert_eq!(
            execute(RunMode::Resume, &changed, &trust, &reopened, &mut retry),
            Err(RecoveryError::RequestMismatch)
        );
        assert!(retry.calls.is_empty());
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
}

fn encode_frame(record: &Record) -> Vec<u8> {
    let mut bytes = b"DPCINT4\0".to_vec();
    bytes.push(4);
    bytes.push(match record.stage {
        Stage::Intent => 0,
        Stage::ClockPending => 1,
        Stage::ClockObserved => 2,
        Stage::ReportsPending => 3,
        Stage::ReportsObserved => 4,
        Stage::Prepared => 5,
    });
    for field in [
        record.request.as_slice(),
        record.clock.as_deref().unwrap_or(&[]),
        record.reports.as_deref().unwrap_or(&[]),
        record.prepared.as_deref().unwrap_or(&[]),
    ] {
        bytes.extend_from_slice(&(field.len() as u32).to_be_bytes());
        bytes.extend_from_slice(field);
    }
    bytes
}
fn install_frame(path: &std::path::Path, frame: &[u8]) {
    std::fs::write(path, crate::snapshot::seal(frame, &SEED)).unwrap();
}

#[test]
fn recovery_authenticated_malformed_version_trailing_and_tampered_records_call_nothing() {
    let rig = Rig::new(0);
    for reason in [
        "version",
        "legacy",
        "stage",
        "trailing",
        "length",
        "request",
        "shape",
        "authentication",
    ] {
        let (path, store) = new_store(&rig, &format!("frame-{reason}.recovery"));
        let mut record = store
            .create(&postcard::to_allocvec(&rig.request).unwrap())
            .unwrap();
        match reason {
            "request" => record.request[0] ^= 1,
            "shape" => record.clock = Some(vec![1]),
            _ => {}
        }
        let mut raw = encode_frame(&record);
        match reason {
            "version" => raw[8] = 3,
            "legacy" => raw[..8].copy_from_slice(b"DPCINT3\0"),
            "stage" => raw[9] = 99,
            "trailing" => raw.push(0),
            "length" => raw[10..14].fill(0xff),
            _ => {}
        }
        install_frame(&path, &raw);
        if reason == "authentication" {
            let mut bytes = std::fs::read(&path).unwrap();
            *bytes.last_mut().unwrap() ^= 1;
            std::fs::write(&path, bytes).unwrap();
        }
        let before = std::fs::read(&path).unwrap();
        let reopened = Arc::new(RecoveryStore::new(path.clone(), SEED));
        let mut mock = Mock::new(&rig, path.clone(), reopened.clone());
        assert!(
            run(&rig, RunMode::Resume, &reopened, &mut mock).is_err(),
            "{reason}"
        );
        assert!(mock.calls.is_empty(), "{reason}");
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
}

#[test]
fn recovery_authenticated_noncanonical_and_semantically_wrong_saved_payloads_call_nothing() {
    let rig = Rig::new(0);
    let (source_path, source) = new_store(&rig, "payload-source.recovery");
    let mut good = Mock::new(&rig, source_path, source.clone());
    run(&rig, RunMode::Fresh, &source, &mut good).unwrap();
    let saved = source.load().unwrap().unwrap();
    for reason in [
        "clock-trailing",
        "clock-noncanonical",
        "clock-receipt",
        "report-trailing",
        "report-epoch",
        "prepared-trailing",
        "prepared-program",
        "prepared-native",
    ] {
        let (path, store) = new_store(&rig, &format!("payload-{reason}.recovery"));
        let mut record = saved.clone();
        match reason {
            "clock-trailing" => record.clock.as_mut().unwrap().push(0),
            "clock-noncanonical" => {
                let bytes = record.clock.as_mut().unwrap();
                let last = (0..bytes.len()).find(|i| bytes[*i] & 0x80 == 0).unwrap();
                bytes[last] |= 0x80;
                bytes.insert(last + 1, 0);
                let same: Anchored<ClockObservation> = postcard::from_bytes(bytes).unwrap();
                assert_eq!(same, rig.clock_read());
                assert_ne!(postcard::to_allocvec(&same).unwrap(), *bytes);
            }
            "clock-receipt" => {
                let mut clock = rig.clock_read();
                clock.value.receipt[0] ^= 1;
                record.clock = Some(postcard::to_allocvec(&clock).unwrap());
            }
            "report-trailing" => record.reports.as_mut().unwrap().push(0),
            "report-epoch" => {
                let mut reports = rig.report_read();
                reports.value.epoch.round_id[0] ^= 1;
                record.reports = Some(postcard::to_allocvec(&reports).unwrap());
            }
            "prepared-trailing" => record.prepared.as_mut().unwrap().push(0),
            "prepared-program" | "prepared-native" => {
                let mut prepared: PreparedCandidate =
                    postcard::from_bytes(record.prepared.as_ref().unwrap()).unwrap();
                if reason == "prepared-program" {
                    prepared.response.program.vkey[0] ^= 1;
                } else {
                    prepared.native.commitment[0] ^= 1;
                }
                record.prepared = Some(postcard::to_allocvec(&prepared).unwrap());
            }
            _ => unreachable!(),
        }
        install_frame(&path, &encode_frame(&record));
        let before = std::fs::read(&path).unwrap();
        let reopened = Arc::new(RecoveryStore::new(path.clone(), SEED));
        let mut retry = Mock::new(&rig, path.clone(), reopened.clone());
        assert!(
            run(&rig, RunMode::Resume, &reopened, &mut retry).is_err(),
            "{reason}"
        );
        assert!(retry.calls.is_empty(), "{reason}");
        assert_eq!(std::fs::read(&path).unwrap(), before);
        drop(store);
    }
}

//! Fixed #50 lifecycle inputs for the OFFLINE preparation coordinator only.
//! Original containers/witnesses are read unchanged; observations and proof
//! bytes are caller-owned mocks, not DON, RPC or cryptographic proof evidence.
use crate::{
    candidate_preparation::{PreparationError, RegistrationCoordinator},
    candidate_preparation_store::StoreError as FsError,
    candidate_protocol::{
        sha256, CandidateProofResponse, ClockObservation, PreparedCandidate, ProgramIdentity,
        ProtocolRequest, ReportObservation, TargetIdentity, TrustedRequest, UptimeObservation,
    },
    candidate_recovery::{
        execute, prepare_only, request_bytes, validate_stored_cut, Anchored, FinalityContext,
        Lookup, LookupState, PreparationTransport, RecoveryAction, RecoveryError,
        RecoveryTransport, RegistrationAnchor, RunMode,
    },
    candidate_recovery_store::{Record, RecoveryStore, Stage},
    candidate_registration::{registration, Registration, UptimeEpoch},
    report_archive_binding::CandidateMaterial,
};
use chainlink_oracle::binding::{CandidateWitness, WIRE_MAGIC};
use perp_core::clock::ClockContext;
use serde_json::Value;
use std::{
    collections::VecDeque,
    path::{Path, PathBuf},
};

pub(crate) const SOURCE_SEED: [u8; 32] = [0xc8; 32];
const FIXTURES: &str = "../../docs/audits/2026-10-11-chainlink-native-contract-bridge/fixtures";

struct OwnedDir(PathBuf);
impl OwnedDir {
    fn new() -> Self {
        use std::os::unix::fs::DirBuilderExt;
        let mut random = [0; 16];
        getrandom::getrandom(&mut random).unwrap();
        let path = std::env::temp_dir().join(format!(
            "arcora-preparation-{}-{}",
            std::process::id(),
            crate::hex0x(&random)
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        Self(path.canonicalize().unwrap())
    }
}
impl Drop for OwnedDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn unhex(value: &str) -> Vec<u8> {
    let value = value.trim_start_matches("0x");
    assert!(value.len().is_multiple_of(2));
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|bytes| u8::from_str_radix(std::str::from_utf8(bytes).unwrap(), 16).unwrap())
        .collect()
}
fn bytes<const N: usize>(value: &Value, key: &str) -> [u8; N] {
    unhex(value[key].as_str().unwrap()).try_into().unwrap()
}

pub(crate) struct PrepFixture {
    _owned: Option<OwnedDir>,
    pub(crate) directory: PathBuf,
    pub(crate) source_path: PathBuf,
    pub(crate) request: ProtocolRequest,
    pub(crate) trusted: TrustedRequest,
    pub(crate) clock: Anchored<ClockObservation>,
    pub(crate) reports: Anchored<ReportObservation>,
    response: CandidateProofResponse,
}
impl PrepFixture {
    pub(crate) fn new(flow: usize) -> Self {
        let owned = OwnedDir::new();
        let mut fixture = Self::in_directory(&owned.0, flow);
        fixture._owned = Some(owned);
        fixture
    }
    /// IPC children borrow the parent's private scratch. They create no extra
    /// temporary directory that would survive a hard kill outside that scope.
    pub(crate) fn for_process(parent_dir: &Path) -> Self {
        Self::in_directory(parent_dir, 0)
    }
    fn in_directory(directory: &Path, flow: usize) -> Self {
        use std::os::unix::fs::MetadataExt;
        assert_eq!(
            directory.canonicalize().unwrap().as_os_str(),
            directory.as_os_str()
        );
        assert_eq!(
            std::fs::symlink_metadata(directory).unwrap().mode() & 0o7777,
            0o700
        );
        let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join(FIXTURES);
        let name = ["normal-lifecycle", "liquidation"][flow];
        let wire = std::fs::read(fixtures.join(format!("{name}.witness.bin"))).unwrap();
        assert_eq!(&wire[..8], WIRE_MAGIC);
        let witness: CandidateWitness = postcard::from_bytes(&wire[8..]).unwrap();
        assert_eq!(postcard::to_allocvec(&witness).unwrap(), wire[8..]);
        let material_bytes = std::fs::read(fixtures.join(format!("{name}.material.bin"))).unwrap();
        let material: CandidateMaterial = postcard::from_bytes(&material_bytes).unwrap();
        assert_eq!(postcard::to_allocvec(&material).unwrap(), material_bytes);
        let corpus: Value =
            serde_json::from_slice(&std::fs::read(fixtures.join("bridge.json")).unwrap()).unwrap();
        let context = &corpus["cases"][flow]["target_context"];
        let uptime = UptimeObservation {
            epoch: UptimeEpoch {
                round_id: bytes(context, "uptime_round_id"),
                started_at: context["uptime_started_at"].as_u64().unwrap(),
            },
            ready: true,
            observed_at_seconds: witness.clock.3.anchored_at_ms / 1000,
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
            uptime_feed: bytes(context, "uptime_feed"),
            grace_seconds: context["grace_seconds"].as_u64().unwrap(),
            settlement_code_hash: bytes(context, "settlement_code_hash"),
            clock_code_hash: bytes(context, "clock_verifier_code_hash"),
            wrapper_code_hash: bytes(context, "oracle_wrapper_code_hash"),
            proxy_code_hash: bytes(context, "verifier_proxy_code_hash"),
            uptime_code_hash: bytes(context, "uptime_feed_code_hash"),
        };
        let request = ProtocolRequest {
            program: ProgramIdentity::pinned(),
            target: target.clone(),
            witness: wire,
            material,
            initial_uptime: uptime,
        };
        let trusted = TrustedRequest::extracted(&request, target.clone(), uptime);
        let native = chainlink_oracle::binding::run_encoded(&request.witness).unwrap();
        let registration =
            registration(&witness.policy, &witness.clock.3, &request.material.entries).unwrap();
        let clock = Anchored {
            value: ClockObservation {
                target: target.clone(),
                context: witness.clock.3,
                receipt: witness.clock.3.receipt(),
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
        };
        let reports = Anchored {
            value: ReportObservation {
                target,
                clock_commitment: native.clock_commitment,
                input_hash: registration.input_hash,
                evidence_hash: native.evidence_hash,
                epoch: uptime.epoch,
                uptime_ready: true,
                observed_at_seconds: uptime.observed_at_seconds,
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
        };
        Self {
            _owned: None,
            directory: directory.to_path_buf(),
            source_path: directory.join("prepared.dpcint4"),
            request,
            trusted,
            clock,
            reports,
            response: CandidateProofResponse {
                program: ProgramIdentity::pinned(),
                public_values: native.commitment.to_vec(),
                proof: b"arcora-native-contract-bridge-mock-proof-v1".to_vec(),
            },
        }
    }
    pub(crate) fn coordinator(&self) -> RegistrationCoordinator {
        RegistrationCoordinator::new(self.source_path.clone(), SOURCE_SEED).unwrap()
    }
    pub(crate) fn clock_read(&self) -> Anchored<ClockObservation> {
        self.clock.clone()
    }
    pub(crate) fn report_read(&self) -> Anchored<ReportObservation> {
        self.reports.clone()
    }
    pub(crate) fn response(&self) -> CandidateProofResponse {
        self.response.clone()
    }
    fn store(&self) -> RecoveryStore {
        RecoveryStore::new(self.source_path.clone(), SOURCE_SEED)
    }
    fn prepared(&self) -> PreparedCandidate {
        PreparedCandidate {
            request_sha256: sha256(&request_bytes(&self.request).unwrap()),
            native: chainlink_oracle::binding::run_encoded(&self.request.witness).unwrap(),
            clock: self.clock.value.clone(),
            reports: self.reports.value.clone(),
            response: self.response(),
        }
    }
    fn seed_cut(&self, stage: Stage) -> Record {
        let store = self.store();
        let mut cut = store
            .create(&request_bytes(&self.request).unwrap())
            .unwrap();
        for next_stage in [
            Stage::ClockPending,
            Stage::ClockObserved,
            Stage::ReportsPending,
            Stage::ReportsObserved,
            Stage::Prepared,
        ] {
            if cut.stage == stage {
                break;
            }
            let mut next = cut.clone();
            next.stage = next_stage;
            match next_stage {
                Stage::ClockObserved => {
                    next.clock = Some(postcard::to_allocvec(&self.clock).unwrap())
                }
                Stage::ReportsObserved => {
                    next.reports = Some(postcard::to_allocvec(&self.reports).unwrap())
                }
                Stage::Prepared => {
                    next.prepared = Some(postcard::to_allocvec(&self.prepared()).unwrap())
                }
                _ => {}
            }
            cut = store.advance(&cut, next).unwrap();
        }
        assert_eq!(cut.stage, stage);
        cut
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
const FRESH: [Call; 8] = [
    Call::RegisterClock,
    Call::LookupClock,
    Call::LookupClock,
    Call::RegisterReports,
    Call::LookupReports,
    Call::LookupClock,
    Call::LookupReports,
    Call::Prove,
];
const FRESH_STAGES: [Stage; 8] = [
    Stage::ClockPending,
    Stage::ClockPending,
    Stage::ClockObserved,
    Stage::ReportsPending,
    Stage::ReportsPending,
    Stage::ReportsObserved,
    Stage::ReportsObserved,
    Stage::ReportsObserved,
];

struct NoCalls;
impl PreparationTransport for NoCalls {
    fn register_clock(&mut self, _: &ClockContext) -> Result<(), ()> {
        panic!("busy/missing path called registration")
    }
    fn lookup_clock(&mut self, _: &ClockContext) -> Result<Lookup<ClockObservation>, ()> {
        panic!("busy/missing path called lookup")
    }
    fn register_reports(&mut self, _: &Registration) -> Result<(), ()> {
        panic!("busy/missing path called registration")
    }
    fn lookup_reports(&mut self, _: &Registration) -> Result<Lookup<ReportObservation>, ()> {
        panic!("busy/missing path called lookup")
    }
    fn prove(&mut self, _: &ProtocolRequest) -> Result<CandidateProofResponse, ()> {
        panic!("busy/missing path called prove")
    }
}

#[derive(Clone, Copy)]
enum SourceAttack {
    Replace,
    Append,
    Permissions,
}
#[derive(Clone, Copy)]
enum SaveFailure {
    Write,
    Rename,
    DirectorySync,
}
struct Mock<'a> {
    fixture: &'a PrepFixture,
    coordinator: Option<&'a RegistrationCoordinator>,
    calls: Vec<Call>,
    stages: Vec<Stage>,
    clocks: VecDeque<Lookup<ClockObservation>>,
    reports: VecDeque<Lookup<ReportObservation>>,
    fail_at: Option<usize>,
    source_failure: Option<(usize, SaveFailure)>,
    attack: Option<SourceAttack>,
    attack_bytes: Option<Vec<u8>>,
    before_failed_save: Option<Vec<u8>>,
}
impl<'a> Mock<'a> {
    fn new(fixture: &'a PrepFixture, coordinator: Option<&'a RegistrationCoordinator>) -> Self {
        Self {
            fixture,
            coordinator,
            calls: vec![],
            stages: vec![],
            clocks: VecDeque::new(),
            reports: VecDeque::new(),
            fail_at: None,
            source_failure: None,
            attack: None,
            attack_bytes: None,
            before_failed_save: None,
        }
    }
    fn action(&mut self, call: Call) -> Result<(), ()> {
        let cut = self.fixture.store().load().unwrap().unwrap();
        assert_eq!(cut.request, request_bytes(&self.fixture.request).unwrap());
        let index = self.calls.len();
        self.calls.push(call);
        self.stages.push(cut.stage);
        if let Some(coordinator) = self.coordinator {
            let second = self.fixture.coordinator();
            assert_eq!(
                second.run_prepared(
                    RunMode::Resume,
                    &self.fixture.request,
                    &self.fixture.trusted,
                    &mut NoCalls
                ),
                Err(PreparationError::Store(FsError::Busy))
            );
            if let Some((at, failure)) = self.source_failure {
                if index == at {
                    self.before_failed_save =
                        Some(std::fs::read(&self.fixture.source_path).unwrap());
                    match failure {
                        SaveFailure::Write => coordinator.fail_next_source_write(),
                        SaveFailure::Rename => coordinator.fail_next_source_rename(),
                        SaveFailure::DirectorySync => coordinator.fail_next_source_directory_sync(),
                    }
                }
            }
        }
        if index == 0 {
            if let Some(attack) = self.attack {
                use std::{
                    io::Write,
                    os::unix::fs::{OpenOptionsExt, PermissionsExt},
                };
                match attack {
                    SourceAttack::Replace => {
                        let sealed = std::fs::read(&self.fixture.source_path).unwrap();
                        std::fs::rename(
                            &self.fixture.source_path,
                            self.fixture.directory.join("displaced.dpcint4"),
                        )
                        .unwrap();
                        let mut file = std::fs::OpenOptions::new()
                            .write(true)
                            .create_new(true)
                            .mode(0o600)
                            .open(&self.fixture.source_path)
                            .unwrap();
                        file.write_all(&sealed).unwrap();
                    }
                    SourceAttack::Append => {
                        std::fs::OpenOptions::new()
                            .append(true)
                            .open(&self.fixture.source_path)
                            .unwrap()
                            .write_all(&[0xff])
                            .unwrap();
                    }
                    SourceAttack::Permissions => std::fs::set_permissions(
                        &self.fixture.source_path,
                        std::fs::Permissions::from_mode(0o644),
                    )
                    .unwrap(),
                }
                self.attack_bytes = Some(std::fs::read(&self.fixture.source_path).unwrap());
            }
        }
        if self.fail_at == Some(index) {
            Err(())
        } else {
            Ok(())
        }
    }
}
impl PreparationTransport for Mock<'_> {
    fn register_clock(&mut self, clock: &ClockContext) -> Result<(), ()> {
        self.action(Call::RegisterClock)?;
        assert_eq!(clock, &self.fixture.clock.value.context);
        Ok(())
    }
    fn lookup_clock(&mut self, clock: &ClockContext) -> Result<Lookup<ClockObservation>, ()> {
        self.action(Call::LookupClock)?;
        assert_eq!(clock, &self.fixture.clock.value.context);
        Ok(self
            .clocks
            .pop_front()
            .unwrap_or_else(|| Lookup::Finalized(self.fixture.clock_read())))
    }
    fn register_reports(&mut self, registration: &Registration) -> Result<(), ()> {
        self.action(Call::RegisterReports)?;
        assert_eq!(
            registration.input_hash,
            self.fixture.reports.value.input_hash
        );
        Ok(())
    }
    fn lookup_reports(
        &mut self,
        registration: &Registration,
    ) -> Result<Lookup<ReportObservation>, ()> {
        self.action(Call::LookupReports)?;
        assert_eq!(
            registration.input_hash,
            self.fixture.reports.value.input_hash
        );
        Ok(self
            .reports
            .pop_front()
            .unwrap_or_else(|| Lookup::Finalized(self.fixture.report_read())))
    }
    fn prove(&mut self, request: &ProtocolRequest) -> Result<CandidateProofResponse, ()> {
        self.action(Call::Prove)?;
        assert_eq!(
            request_bytes(request).unwrap(),
            request_bytes(&self.fixture.request).unwrap()
        );
        Ok(self.fixture.response())
    }
}
impl RecoveryTransport for Mock<'_> {
    fn register_clock(&mut self, clock: &ClockContext) -> Result<(), ()> {
        PreparationTransport::register_clock(self, clock)
    }
    fn lookup_clock(&mut self, clock: &ClockContext) -> Result<Lookup<ClockObservation>, ()> {
        PreparationTransport::lookup_clock(self, clock)
    }
    fn register_reports(&mut self, registration: &Registration) -> Result<(), ()> {
        PreparationTransport::register_reports(self, registration)
    }
    fn lookup_reports(
        &mut self,
        registration: &Registration,
    ) -> Result<Lookup<ReportObservation>, ()> {
        PreparationTransport::lookup_reports(self, registration)
    }
    fn prove(&mut self, request: &ProtocolRequest) -> Result<CandidateProofResponse, ()> {
        PreparationTransport::prove(self, request)
    }
    fn broadcast(&mut self, prepared: &PreparedCandidate) -> Result<(), ()> {
        self.action(Call::Broadcast)?;
        assert_eq!(prepared, &self.fixture.prepared());
        Ok(())
    }
}

#[test]
fn preparation_fixed_normal_and_liquidation_stop_at_exact_durable_prepared() {
    for flow in [0, 1] {
        let fixture = PrepFixture::new(flow);
        let coordinator = fixture.coordinator();
        assert_eq!(coordinator.source_path(), fixture.source_path);
        let mut mock = Mock::new(&fixture, Some(&coordinator));
        let cut = coordinator
            .run_prepared(
                RunMode::Fresh,
                &fixture.request,
                &fixture.trusted,
                &mut mock,
            )
            .unwrap();
        assert_eq!(mock.calls, FRESH);
        assert_eq!(mock.stages, FRESH_STAGES);
        assert_eq!(cut.record.stage, Stage::Prepared);
        assert_eq!(cut.prepared, fixture.prepared());
        assert_eq!(fixture.store().load().unwrap(), Some(cut.record.clone()));
        validate_stored_cut(&cut.record, &fixture.request, &fixture.trusted).unwrap();
        let before_source = std::fs::read(&fixture.source_path).unwrap();
        let before_binding = std::fs::read(coordinator.binding_path()).unwrap();
        let resumed_coordinator = fixture.coordinator();
        let resumed = resumed_coordinator
            .run_prepared(
                RunMode::Resume,
                &fixture.request,
                &fixture.trusted,
                &mut NoCalls,
            )
            .unwrap();
        assert_eq!(resumed, cut);
        assert_eq!(std::fs::read(&fixture.source_path).unwrap(), before_source);
        assert_eq!(
            std::fs::read(coordinator.binding_path()).unwrap(),
            before_binding
        );
        assert_eq!(
            coordinator.run_prepared(
                RunMode::Fresh,
                &fixture.request,
                &fixture.trusted,
                &mut NoCalls
            ),
            Err(PreparationError::ExistingFresh)
        );
    }
}

#[test]
fn preparation_all_six_stage_adoptions_are_callback_free_and_resume_without_registration() {
    for (stage, expected) in [
        (
            Stage::Intent,
            vec![
                Call::LookupClock,
                Call::LookupClock,
                Call::LookupReports,
                Call::LookupClock,
                Call::LookupReports,
                Call::Prove,
            ],
        ),
        (
            Stage::ClockPending,
            vec![
                Call::LookupClock,
                Call::LookupClock,
                Call::LookupReports,
                Call::LookupClock,
                Call::LookupReports,
                Call::Prove,
            ],
        ),
        (
            Stage::ClockObserved,
            vec![
                Call::LookupClock,
                Call::LookupReports,
                Call::LookupClock,
                Call::LookupReports,
                Call::Prove,
            ],
        ),
        (
            Stage::ReportsPending,
            vec![
                Call::LookupClock,
                Call::LookupReports,
                Call::LookupClock,
                Call::LookupReports,
                Call::Prove,
            ],
        ),
        (
            Stage::ReportsObserved,
            vec![Call::LookupClock, Call::LookupReports, Call::Prove],
        ),
        (Stage::Prepared, vec![]),
    ] {
        let fixture = PrepFixture::new(1);
        let original = fixture.seed_cut(stage);
        let before = std::fs::read(&fixture.source_path).unwrap();
        let coordinator = fixture.coordinator();
        assert_eq!(
            coordinator.run_prepared(
                RunMode::Resume,
                &fixture.request,
                &fixture.trusted,
                &mut NoCalls
            ),
            Err(PreparationError::MissingBinding)
        );
        let binding = coordinator
            .attach_existing(&fixture.request, &fixture.trusted)
            .unwrap();
        assert_eq!(binding.request_sha256, sha256(&original.request));
        assert_eq!(std::fs::read(&fixture.source_path).unwrap(), before);
        assert_eq!(
            coordinator.attach_existing(&fixture.request, &fixture.trusted),
            Ok(binding)
        );
        assert_eq!(
            coordinator.run_prepared(
                RunMode::Fresh,
                &fixture.request,
                &fixture.trusted,
                &mut NoCalls
            ),
            Err(PreparationError::ExistingFresh)
        );
        let mut mock = Mock::new(&fixture, Some(&coordinator));
        let cut = coordinator
            .run_prepared(
                RunMode::Resume,
                &fixture.request,
                &fixture.trusted,
                &mut mock,
            )
            .unwrap();
        assert_eq!(mock.calls, expected, "{stage:?}");
        assert_eq!(cut.prepared, fixture.prepared());
        assert_eq!(cut.record.request, original.request);
        if original.clock.is_some() {
            assert_eq!(cut.record.clock, original.clock);
        }
        if original.reports.is_some() {
            assert_eq!(cut.record.reports, original.reports);
        }
        if original.prepared.is_some() {
            assert_eq!(cut.record.prepared, original.prepared);
        }
        if stage == Stage::Prepared {
            assert_eq!(std::fs::read(&fixture.source_path).unwrap(), before);
        }
    }
}

#[test]
fn preparation_missing_source_binding_and_orphan_binding_never_reset_fresh() {
    let fixture = PrepFixture::new(0);
    let coordinator = fixture.coordinator();
    assert_eq!(
        coordinator.run_prepared(
            RunMode::Resume,
            &fixture.request,
            &fixture.trusted,
            &mut NoCalls
        ),
        Err(PreparationError::MissingBinding)
    );
    assert_eq!(
        coordinator.attach_existing(&fixture.request, &fixture.trusted),
        Err(PreparationError::MissingSource)
    );
    coordinator.fail_next_source_write();
    assert!(coordinator
        .run_prepared(
            RunMode::Fresh,
            &fixture.request,
            &fixture.trusted,
            &mut NoCalls
        )
        .is_err());
    assert!(coordinator.binding_path().exists());
    assert!(!fixture.source_path.exists());
    let binding = std::fs::read(coordinator.binding_path()).unwrap();
    let resumed = fixture.coordinator();
    assert_eq!(
        resumed.run_prepared(
            RunMode::Resume,
            &fixture.request,
            &fixture.trusted,
            &mut NoCalls
        ),
        Err(PreparationError::MissingSource)
    );
    assert_eq!(
        resumed.run_prepared(
            RunMode::Fresh,
            &fixture.request,
            &fixture.trusted,
            &mut NoCalls
        ),
        Err(PreparationError::ExistingFresh)
    );
    assert_eq!(
        resumed.attach_existing(&fixture.request, &fixture.trusted),
        Err(PreparationError::MissingSource)
    );
    assert_eq!(std::fs::read(coordinator.binding_path()).unwrap(), binding);
}

#[test]
fn preparation_wrong_request_and_binding_mismatch_refuse_without_callbacks() {
    let fixture = PrepFixture::new(0);
    fixture.seed_cut(Stage::Prepared);
    let coordinator = fixture.coordinator();
    let mut changed = fixture.request.clone();
    changed.target.grace_seconds += 1;
    let trusted =
        TrustedRequest::extracted(&changed, changed.target.clone(), changed.initial_uptime);
    let source = std::fs::read(&fixture.source_path).unwrap();
    assert_eq!(
        coordinator.attach_existing(&changed, &trusted),
        Err(PreparationError::Recovery(RecoveryError::RequestMismatch))
    );
    assert!(!coordinator.binding_path().exists());
    coordinator
        .attach_existing(&fixture.request, &fixture.trusted)
        .unwrap();
    assert_eq!(
        coordinator.run_prepared(RunMode::Resume, &changed, &trusted, &mut NoCalls),
        Err(PreparationError::BindingMismatch)
    );
    assert_eq!(std::fs::read(&fixture.source_path).unwrap(), source);
}

#[test]
fn preparation_malformed_authenticated_anchor_and_prepared_cuts_are_not_adopted() {
    for case in 0..4 {
        let fixture = PrepFixture::new(0);
        let store = fixture.store();
        let mut cut = fixture.seed_cut(if case == 3 {
            Stage::ReportsObserved
        } else {
            Stage::ClockPending
        });
        let mut next = cut.clone();
        if case == 3 {
            let mut prepared = fixture.prepared();
            prepared.response.public_values[0] ^= 1;
            next.stage = Stage::Prepared;
            next.prepared = Some(postcard::to_allocvec(&prepared).unwrap());
        } else {
            let mut clock = fixture.clock_read();
            if case == 0 {
                clock.anchor.tx_hash = [0; 32];
            }
            if case == 1 {
                clock.value.registration_block += 1;
            }
            next.stage = Stage::ClockObserved;
            let mut bytes = postcard::to_allocvec(&clock).unwrap();
            if case == 2 {
                bytes.push(0);
            }
            next.clock = Some(bytes);
        }
        cut = store.advance(&cut, next).unwrap();
        assert!(validate_stored_cut(&cut, &fixture.request, &fixture.trusted).is_err());
        let before = std::fs::read(&fixture.source_path).unwrap();
        let coordinator = fixture.coordinator();
        assert!(coordinator
            .attach_existing(&fixture.request, &fixture.trusted)
            .is_err());
        assert!(!coordinator.binding_path().exists());
        assert_eq!(std::fs::read(&fixture.source_path).unwrap(), before);
    }
}

#[test]
fn preparation_wrong_key_tampered_and_foreign_source_never_create_binding() {
    for case in 0..3 {
        let fixture = PrepFixture::new(0);
        fixture.seed_cut(Stage::Prepared);
        if case != 0 {
            let mut bytes = std::fs::read(&fixture.source_path).unwrap();
            if case == 1 {
                let last = bytes.len() - 1;
                bytes[last] ^= 1;
            }
            if case == 2 {
                bytes = crate::snapshot::seal(b"DPCINT3\0foreign-format", &SOURCE_SEED);
            }
            std::fs::write(&fixture.source_path, &bytes).unwrap();
        }
        let before = std::fs::read(&fixture.source_path).unwrap();
        let coordinator = RegistrationCoordinator::new(
            fixture.source_path.clone(),
            if case == 0 { [0xd8; 32] } else { SOURCE_SEED },
        )
        .unwrap();
        assert!(coordinator
            .attach_existing(&fixture.request, &fixture.trusted)
            .is_err());
        assert!(!coordinator.binding_path().exists());
        assert_eq!(std::fs::read(&fixture.source_path).unwrap(), before);
    }
}

#[test]
fn preparation_callback_source_replacement_change_and_permissions_stop_without_overwrite() {
    for attack in [
        SourceAttack::Replace,
        SourceAttack::Append,
        SourceAttack::Permissions,
    ] {
        let fixture = PrepFixture::new(0);
        let coordinator = fixture.coordinator();
        let mut mock = Mock::new(&fixture, Some(&coordinator));
        mock.attack = Some(attack);
        let error = coordinator
            .run_prepared(
                RunMode::Fresh,
                &fixture.request,
                &fixture.trusted,
                &mut mock,
            )
            .unwrap_err();
        assert_eq!(mock.calls, [Call::RegisterClock]);
        assert_eq!(mock.stages, [Stage::ClockPending]);
        assert_eq!(
            error,
            PreparationError::Store(if matches!(attack, SourceAttack::Permissions) {
                FsError::Permissions
            } else {
                FsError::Identity
            })
        );
        assert_eq!(
            std::fs::read(&fixture.source_path).unwrap(),
            mock.attack_bytes.unwrap()
        );
    }
}

#[test]
fn preparation_callback_failures_preserve_the_exact_checkpoint() {
    for index in 0..FRESH.len() {
        let fixture = PrepFixture::new(0);
        let coordinator = fixture.coordinator();
        let mut mock = Mock::new(&fixture, Some(&coordinator));
        mock.fail_at = Some(index);
        assert_eq!(
            coordinator.run_prepared(
                RunMode::Fresh,
                &fixture.request,
                &fixture.trusted,
                &mut mock
            ),
            Err(PreparationError::Recovery(RecoveryError::Callback(
                match FRESH[index] {
                    Call::RegisterClock => RecoveryAction::RegisterClock,
                    Call::LookupClock => RecoveryAction::LookupClock,
                    Call::RegisterReports => RecoveryAction::RegisterReports,
                    Call::LookupReports => RecoveryAction::LookupReports,
                    Call::Prove => RecoveryAction::Prove,
                    Call::Broadcast => unreachable!(),
                }
            )))
        );
        assert_eq!(mock.calls, FRESH[..=index]);
        assert_eq!(
            fixture.store().load().unwrap().unwrap().stage,
            FRESH_STAGES[index]
        );
    }
}

#[test]
fn preparation_binding_publication_failures_stop_before_intent() {
    for failure in [
        SaveFailure::Write,
        SaveFailure::Rename,
        SaveFailure::DirectorySync,
    ] {
        let fixture = PrepFixture::new(0);
        let coordinator = fixture.coordinator();
        match failure {
            SaveFailure::Write => coordinator.fail_next_binding_write(),
            SaveFailure::Rename => coordinator.fail_next_binding_rename(),
            SaveFailure::DirectorySync => coordinator.fail_next_binding_directory_sync(),
        }
        let error = coordinator
            .run_prepared(
                RunMode::Fresh,
                &fixture.request,
                &fixture.trusted,
                &mut NoCalls,
            )
            .unwrap_err();
        assert_eq!(
            error,
            PreparationError::Store(if matches!(failure, SaveFailure::DirectorySync) {
                FsError::AmbiguousWrite
            } else {
                FsError::Write
            })
        );
        assert!(!fixture.source_path.exists());
        assert_eq!(
            coordinator.binding_path().exists(),
            matches!(failure, SaveFailure::DirectorySync)
        );
        if matches!(failure, SaveFailure::DirectorySync) {
            let reloaded = fixture.coordinator();
            assert_eq!(
                reloaded.run_prepared(
                    RunMode::Resume,
                    &fixture.request,
                    &fixture.trusted,
                    &mut NoCalls
                ),
                Err(PreparationError::MissingSource)
            );
            assert_eq!(
                reloaded.run_prepared(
                    RunMode::Fresh,
                    &fixture.request,
                    &fixture.trusted,
                    &mut NoCalls
                ),
                Err(PreparationError::ExistingFresh)
            );
        }
    }
}

#[test]
fn preparation_source_checkpoint_failures_keep_old_cut_or_stop_on_published_ambiguity() {
    for (index, next_stage) in [
        (1, Stage::ClockObserved),
        (2, Stage::ReportsPending),
        (4, Stage::ReportsObserved),
        (7, Stage::Prepared),
    ] {
        for failure in [
            SaveFailure::Write,
            SaveFailure::Rename,
            SaveFailure::DirectorySync,
        ] {
            let fixture = PrepFixture::new(0);
            let coordinator = fixture.coordinator();
            let mut mock = Mock::new(&fixture, Some(&coordinator));
            mock.source_failure = Some((index, failure));
            assert!(coordinator
                .run_prepared(
                    RunMode::Fresh,
                    &fixture.request,
                    &fixture.trusted,
                    &mut mock
                )
                .is_err());
            assert_eq!(mock.calls, FRESH[..=index]);
            let disk = fixture.store().load().unwrap().unwrap();
            if matches!(failure, SaveFailure::DirectorySync) {
                assert_eq!(disk.stage, next_stage);
            } else {
                assert_eq!(disk.stage, FRESH_STAGES[index]);
                assert_eq!(
                    std::fs::read(&fixture.source_path).unwrap(),
                    mock.before_failed_save.unwrap()
                );
            }
            let reopened = fixture.coordinator();
            let mut retry = Mock::new(&fixture, Some(&reopened));
            let cut = reopened
                .run_prepared(
                    RunMode::Resume,
                    &fixture.request,
                    &fixture.trusted,
                    &mut retry,
                )
                .unwrap();
            assert_eq!(cut.prepared, fixture.prepared());
            assert!(!retry.calls.contains(&Call::RegisterClock));
            assert!(!retry.calls.contains(&Call::RegisterReports));
            if index == 7 {
                assert_eq!(mock.calls.iter().filter(|c| **c == Call::Prove).count(), 1);
                assert_eq!(
                    retry.calls.iter().filter(|c| **c == Call::Prove).count(),
                    usize::from(!matches!(failure, SaveFailure::DirectorySync))
                );
            }
        }
    }
}

#[test]
fn preparation_ambiguous_initial_intent_reloads_without_registration() {
    let fixture = PrepFixture::new(0);
    let coordinator = fixture.coordinator();
    coordinator.fail_next_source_directory_sync();
    assert!(coordinator
        .run_prepared(
            RunMode::Fresh,
            &fixture.request,
            &fixture.trusted,
            &mut NoCalls
        )
        .is_err());
    assert_eq!(
        fixture.store().load().unwrap().unwrap().stage,
        Stage::Intent
    );
    let resumed = fixture.coordinator();
    let mut mock = Mock::new(&fixture, Some(&resumed));
    resumed
        .run_prepared(
            RunMode::Resume,
            &fixture.request,
            &fixture.trusted,
            &mut mock,
        )
        .unwrap();
    assert_eq!(
        mock.calls,
        [
            Call::LookupClock,
            Call::LookupClock,
            Call::LookupReports,
            Call::LookupClock,
            Call::LookupReports,
            Call::Prove
        ]
    );
}

#[test]
fn preparation_clock_pending_save_failures_precede_every_callback_and_resume_without_registration()
{
    for failure in [
        SaveFailure::Write,
        SaveFailure::Rename,
        SaveFailure::DirectorySync,
    ] {
        let fixture = PrepFixture::new(0);
        fixture.seed_cut(Stage::Intent);
        let coordinator = fixture.coordinator();
        coordinator
            .attach_existing(&fixture.request, &fixture.trusted)
            .unwrap();
        let before_source = std::fs::read(&fixture.source_path).unwrap();
        let before_binding = std::fs::read(coordinator.binding_path()).unwrap();
        match failure {
            SaveFailure::Write => coordinator.fail_next_source_write(),
            SaveFailure::Rename => coordinator.fail_next_source_rename(),
            SaveFailure::DirectorySync => coordinator.fail_next_source_directory_sync(),
        }
        let error = coordinator
            .run_prepared(
                RunMode::Resume,
                &fixture.request,
                &fixture.trusted,
                &mut NoCalls,
            )
            .unwrap_err();
        let expected_error = if matches!(failure, SaveFailure::DirectorySync) {
            crate::candidate_recovery_store::StoreError::AmbiguousWrite
        } else {
            crate::candidate_recovery_store::StoreError::Write
        };
        assert_eq!(
            error,
            PreparationError::Store(FsError::Source(expected_error))
        );
        let cut = fixture.store().load().unwrap().unwrap();
        assert_eq!(cut.request, request_bytes(&fixture.request).unwrap());
        if matches!(failure, SaveFailure::DirectorySync) {
            assert_eq!(cut.stage, Stage::ClockPending);
        } else {
            assert_eq!(cut.stage, Stage::Intent);
            assert_eq!(std::fs::read(&fixture.source_path).unwrap(), before_source);
        }
        assert_eq!(
            std::fs::read(coordinator.binding_path()).unwrap(),
            before_binding
        );

        let resumed = fixture.coordinator();
        let mut mock = Mock::new(&fixture, Some(&resumed));
        let prepared = resumed
            .run_prepared(
                RunMode::Resume,
                &fixture.request,
                &fixture.trusted,
                &mut mock,
            )
            .unwrap();
        assert_eq!(
            mock.calls,
            [
                Call::LookupClock,
                Call::LookupClock,
                Call::LookupReports,
                Call::LookupClock,
                Call::LookupReports,
                Call::Prove
            ]
        );
        assert_eq!(prepared.record.stage, Stage::Prepared);
        assert_eq!(prepared.prepared, fixture.prepared());
        assert_eq!(
            std::fs::read(coordinator.binding_path()).unwrap(),
            before_binding
        );
    }
}

#[test]
fn preparation_pending_absent_unknown_reorg_never_reregister() {
    for stage in [Stage::ClockPending, Stage::ReportsPending] {
        for state in [
            LookupState::Pending,
            LookupState::Absent,
            LookupState::Unknown,
            LookupState::Reorg,
        ] {
            let fixture = PrepFixture::new(0);
            fixture.seed_cut(stage);
            let coordinator = fixture.coordinator();
            coordinator
                .attach_existing(&fixture.request, &fixture.trusted)
                .unwrap();
            let mut mock = Mock::new(&fixture, Some(&coordinator));
            let lookup = match state {
                LookupState::Pending => Lookup::Pending,
                LookupState::Absent => Lookup::Absent,
                LookupState::Unknown => Lookup::Unknown,
                LookupState::Reorg => Lookup::Reorg,
            };
            if stage == Stage::ClockPending {
                mock.clocks.push_back(lookup);
            } else {
                mock.reports.push_back(match state {
                    LookupState::Pending => Lookup::Pending,
                    LookupState::Absent => Lookup::Absent,
                    LookupState::Unknown => Lookup::Unknown,
                    LookupState::Reorg => Lookup::Reorg,
                });
            }
            assert_eq!(
                coordinator.run_prepared(
                    RunMode::Resume,
                    &fixture.request,
                    &fixture.trusted,
                    &mut mock
                ),
                Err(PreparationError::Recovery(RecoveryError::Hold(state)))
            );
            assert_eq!(
                mock.calls,
                if stage == Stage::ClockPending {
                    vec![Call::LookupClock]
                } else {
                    vec![Call::LookupClock, Call::LookupReports]
                }
            );
            assert_eq!(fixture.store().load().unwrap().unwrap().stage, stage);
        }
    }
}

#[test]
fn preparation_concrete_helper_has_no_broadcast_tail() {
    let fixture = PrepFixture::new(0);
    let store = fixture.store();
    let mut mock = Mock::new(&fixture, None);
    let cut = prepare_only(
        RunMode::Fresh,
        &fixture.request,
        &fixture.trusted,
        &store,
        &mut mock,
    )
    .unwrap();
    assert_eq!(mock.calls, FRESH);
    assert_eq!(cut.prepared, fixture.prepared());
    assert_eq!(
        prepare_only(
            RunMode::Resume,
            &fixture.request,
            &fixture.trusted,
            &store,
            &mut NoCalls
        ),
        Ok(cut)
    );
}

#[test]
fn preparation_legacy_driver_still_has_eleven_fresh_and_three_resume_callbacks() {
    let fixture = PrepFixture::new(0);
    let store = fixture.store();
    let mut mock = Mock::new(&fixture, None);
    let prepared = execute(
        RunMode::Fresh,
        &fixture.request,
        &fixture.trusted,
        &store,
        &mut mock,
    )
    .unwrap();
    let mut expected = FRESH.to_vec();
    expected.extend([Call::LookupClock, Call::LookupReports, Call::Broadcast]);
    assert_eq!(mock.calls, expected);
    let mut stages = FRESH_STAGES.to_vec();
    stages.extend([Stage::Prepared; 3]);
    assert_eq!(mock.stages, stages);
    let before = std::fs::read(&fixture.source_path).unwrap();
    let mut retry = Mock::new(&fixture, None);
    assert_eq!(
        execute(
            RunMode::Resume,
            &fixture.request,
            &fixture.trusted,
            &store,
            &mut retry
        ),
        Ok(prepared)
    );
    assert_eq!(
        retry.calls,
        [Call::LookupClock, Call::LookupReports, Call::Broadcast]
    );
    assert_eq!(std::fs::read(&fixture.source_path).unwrap(), before);
}

#[test]
fn preparation_legacy_tail_keeps_the_fresh_invocation_watermark() {
    let fixture = PrepFixture::new(0);
    let store = fixture.store();
    let mut mock = Mock::new(&fixture, None);
    let mut high_clock = fixture.clock_read();
    high_clock.finality.finalized_block_number = 46;
    high_clock.finality.finalized_block_hash = [0x46; 32];
    let mut high_reports = fixture.report_read();
    high_reports.finality.finalized_block_number = 46;
    high_reports.finality.finalized_block_hash = [0x46; 32];
    mock.clocks.extend([
        Lookup::Finalized(fixture.clock_read()),
        Lookup::Finalized(fixture.clock_read()),
        Lookup::Finalized(high_clock),
        Lookup::Finalized(fixture.clock_read()),
    ]);
    mock.reports.extend([
        Lookup::Finalized(fixture.report_read()),
        Lookup::Finalized(high_reports),
    ]);
    assert_eq!(
        execute(
            RunMode::Fresh,
            &fixture.request,
            &fixture.trusted,
            &store,
            &mut mock
        ),
        Err(RecoveryError::Finality)
    );
    let mut expected = FRESH.to_vec();
    expected.push(Call::LookupClock);
    assert_eq!(mock.calls, expected);
    assert!(!mock.calls.contains(&Call::Broadcast));
    assert_eq!(
        fixture.store().load().unwrap().unwrap().stage,
        Stage::Prepared
    );
}

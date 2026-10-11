//! Actual A3 operations plus owned files and mock transports only.
use crate::{
    candidate_intent::{IntentStage, IntentStore},
    candidate_protocol::*,
    candidate_registration::{registration, Registration, UptimeEpoch},
    price_lifecycle_tests::{protocol_fixture, protocol_price_free_fixture, Fixture},
};
use chainlink_oracle::binding::{CandidateWitness, WIRE_MAGIC};
use perp_core::clock::ClockContext;
use std::{path::PathBuf, sync::Arc};

const SEED: [u8; 32] = [0x63; 32];
const ACTIONS: [Action; 7] = [
    Action::RegisterClock,
    Action::ObserveClock,
    Action::RegisterReports,
    Action::ObserveReports,
    Action::Prove,
    Action::Recheck,
    Action::Broadcast,
];

struct Rig {
    guard: Fixture,
    request: ProtocolRequest,
    trusted: TrustedRequest,
}
impl Rig {
    fn new(liquidation: bool) -> Self {
        let (guard, witness, material) = protocol_fixture(liquidation);
        Self::from_fixture(guard, witness, material)
    }
    fn price_free() -> Self {
        let (guard, witness, material) = protocol_price_free_fixture();
        Self::from_fixture(guard, witness, material)
    }
    fn from_fixture(
        guard: Fixture,
        witness: CandidateWitness,
        material: crate::report_archive_binding::CandidateMaterial,
    ) -> Self {
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
        let initial_uptime = if witness.clock.3.timed_ops == 0 {
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
        }
    }
    fn store(&self, name: &str) -> (PathBuf, Arc<IntentStore>) {
        let path = self.guard.protocol_dir().join(name);
        (path.clone(), Arc::new(IntentStore::new(path, SEED)))
    }
}

#[derive(Clone, Copy)]
enum Corrupt {
    ClockReceipt,
    ClockTarget,
    ReportInput,
    ReportEvidence,
    ReportEpoch,
    ReportOldObservation,
    ProofProgram,
    ProofWidth,
    ProofCommitment,
    EmptyProof,
    RecheckClock,
    RecheckRecord,
    RecheckEpoch,
    RecheckTarget,
}
struct Mock {
    calls: Vec<Action>,
    fail: Option<Action>,
    corrupt: Option<Corrupt>,
    fail_prepared_save: bool,
    store: Arc<IntentStore>,
    clock: ClockObservation,
    reports: ReportObservation,
    response: CandidateProofResponse,
    expected_request: Vec<u8>,
    clock_inputs: Vec<ClockContext>,
    report_inputs: Vec<Vec<u8>>,
    prove_inputs: Vec<Vec<u8>>,
}
impl Mock {
    fn new(request: &ProtocolRequest, store: Arc<IntentStore>) -> Self {
        let witness: CandidateWitness = postcard::from_bytes(&request.witness[8..]).unwrap();
        let native = chainlink_oracle::binding::run_encoded(&request.witness).unwrap();
        let registration =
            registration(&witness.policy, &witness.clock.3, &request.material.entries).unwrap();
        Self {
            calls: vec![],
            fail: None,
            corrupt: None,
            fail_prepared_save: false,
            store,
            clock: ClockObservation {
                target: request.target.clone(),
                context: witness.clock.3,
                receipt: witness.clock.3.receipt(),
                registration_block: 42,
                registration_block_hash: [0x42; 32],
            },
            reports: ReportObservation {
                target: request.target.clone(),
                clock_commitment: native.clock_commitment,
                input_hash: registration.input_hash,
                evidence_hash: native.evidence_hash,
                epoch: request.initial_uptime.epoch,
                uptime_ready: true,
                observed_at_seconds: witness.clock.3.anchored_at_ms / 1000,
            },
            response: CandidateProofResponse {
                program: request.program.clone(),
                public_values: native.commitment.to_vec(),
                proof: b"owned mock proof; not SP1 authenticity".to_vec(),
            },
            expected_request: postcard::to_allocvec(request).unwrap(),
            clock_inputs: vec![],
            report_inputs: vec![],
            prove_inputs: vec![],
        }
    }
    fn action(&mut self, action: Action) -> Result<(), ()> {
        self.calls.push(action);
        // The authenticated immutable request must exist before EVERY mock
        // external action, including retries and broadcast.
        assert_eq!(
            self.store.load().unwrap().unwrap().request,
            self.expected_request
        );
        if self.fail == Some(action) {
            Err(())
        } else {
            Ok(())
        }
    }
}
impl OfflineTransport for Mock {
    fn register_clock(&mut self, clock: &ClockContext) -> Result<(), ()> {
        self.action(Action::RegisterClock)?;
        self.clock_inputs.push(*clock);
        Ok(())
    }
    fn observe_clock(&mut self, _: &ClockContext) -> Result<ClockObservation, ()> {
        self.action(Action::ObserveClock)?;
        let mut value = self.clock.clone();
        match self.corrupt {
            Some(Corrupt::ClockReceipt) => value.receipt[0] ^= 1,
            Some(Corrupt::ClockTarget) => value.target.chain_id += 1,
            _ => {}
        }
        Ok(value)
    }
    fn register_reports(&mut self, registration: &Registration) -> Result<(), ()> {
        self.action(Action::RegisterReports)?;
        self.report_inputs.push(registration.entries_abi.clone());
        assert_eq!(registration.input_hash, self.reports.input_hash);
        Ok(())
    }
    fn observe_reports(&mut self, _: &Registration) -> Result<ReportObservation, ()> {
        self.action(Action::ObserveReports)?;
        let mut value = self.reports.clone();
        match self.corrupt {
            Some(Corrupt::ReportInput) => value.input_hash[0] ^= 1,
            Some(Corrupt::ReportEvidence) => value.evidence_hash[0] ^= 1,
            Some(Corrupt::ReportEpoch) => value.uptime_ready = false,
            Some(Corrupt::ReportOldObservation) => value.observed_at_seconds -= 1,
            _ => {}
        }
        Ok(value)
    }
    fn prove(&mut self, request: &ProtocolRequest) -> Result<CandidateProofResponse, ()> {
        self.action(Action::Prove)?;
        self.prove_inputs.push(request.witness.clone());
        assert_eq!(
            postcard::to_allocvec(request).unwrap(),
            self.expected_request
        );
        let mut value = self.response.clone();
        match self.corrupt {
            Some(Corrupt::ProofProgram) => value.program.vkey[0] ^= 1,
            Some(Corrupt::ProofWidth) => {
                value.public_values.pop();
            }
            Some(Corrupt::ProofCommitment) => value.public_values[0] ^= 1,
            Some(Corrupt::EmptyProof) => value.proof.clear(),
            _ => {}
        }
        if self.fail_prepared_save {
            self.store.fail_next_save();
        }
        Ok(value)
    }
    fn recheck(
        &mut self,
        _: &PreparedCandidate,
    ) -> Result<(ClockObservation, ReportObservation), ()> {
        self.action(Action::Recheck)?;
        assert_eq!(
            self.store.load().unwrap().unwrap().stage,
            IntentStage::Prepared
        );
        let mut clock = self.clock.clone();
        let mut reports = self.reports.clone();
        reports.observed_at_seconds += 10; // later status read; source reports never change
        match self.corrupt {
            Some(Corrupt::RecheckClock) => clock.registration_block_hash[0] ^= 1,
            Some(Corrupt::RecheckRecord) => reports.input_hash[0] ^= 1,
            Some(Corrupt::RecheckEpoch) => reports.epoch.round_id[0] ^= 1,
            Some(Corrupt::RecheckTarget) => reports.target.uptime_feed[0] ^= 1,
            _ => {}
        }
        Ok((clock, reports))
    }
    fn broadcast(&mut self, _: &PreparedCandidate) -> Result<(), ()> {
        self.action(Action::Broadcast)
    }
}

#[test]
fn candidate_protocol_actual_close_withdraw_and_liquidation_complete_offline_stages() {
    for liquidation in [false, true] {
        let rig = Rig::new(liquidation);
        let (_, store) = rig.store("success.intent");
        let mut mock = Mock::new(&rig.request, store.clone());
        let result = execute(&rig.request, &rig.trusted, &store, &mut mock).unwrap();
        assert_eq!(mock.calls, ACTIONS);
        assert_eq!(result.response.public_values, result.native.commitment);
        assert_eq!(store.load().unwrap().unwrap().stage, IntentStage::Prepared);
        assert_eq!(
            mock.prove_inputs.as_slice(),
            std::slice::from_ref(&rig.request.witness)
        );
        assert_eq!(
            rig.request.material.refs.len(),
            rig.request.material.entries.len()
        );
    }
}

#[test]
fn candidate_protocol_known_invalid_identity_material_and_capacity_call_nothing() {
    let rig = Rig::new(false);
    for reason in [
        "wire",
        "witness-wire",
        "sdk",
        "elf",
        "vkey",
        "chain",
        "network",
        "clock-version",
        "wrapper",
        "proxy",
        "settlement",
        "uptime",
        "grace",
        "policy",
        "material-policy",
        "archive-id",
        "full-report",
        "evidence",
        "capacity",
        "runtime-zero",
        "uptime-down",
        "uptime-unknown",
        "uptime-grace",
        "epoch-pin",
        "reordered",
        "dropped",
        "extra",
        "oversized-body",
    ] {
        let mut bad = rig.request.clone();
        match reason {
            "wire" => bad.program.wire_magic = *perp_core::clock::WIRE_MAGIC,
            "witness-wire" => bad.witness[..8].copy_from_slice(perp_core::clock::WIRE_MAGIC),
            "sdk" => bad.program.sdk_release = "v2".into(),
            "elf" => bad.program.elf_sha256[0] ^= 1,
            "vkey" => bad.program.vkey[0] ^= 1,
            "chain" => bad.target.chain_id = 1,
            "network" => bad.target.network = 1,
            "clock-version" => bad.target.clock_version = 1,
            "wrapper" => bad.target.oracle_wrapper[0] ^= 1,
            "proxy" => bad.target.verifier_proxy[0] ^= 1,
            "settlement" => bad.target.settlement[0] ^= 1,
            "uptime" => bad.target.uptime_feed = [0; 20],
            "grace" => bad.target.grace_seconds = 0,
            "policy" => bad.target.policy_hash[0] ^= 1,
            "material-policy" => bad.material.policy.network = 1,
            "archive-id" => {
                bad.material.refs[0].archive_id =
                    chainlink_streams_client::report_archive::ArchiveId::parse(&"ff".repeat(32))
                        .unwrap()
            }
            "full-report" => bad.material.entries[0].base_report[576] ^= 1,
            "evidence" => bad.material.evidence[0].now_ms += 1,
            "capacity" => bad
                .material
                .entries
                .resize(129, bad.material.entries[0].clone()),
            "runtime-zero" => bad.target.wrapper_code_hash = [0; 32],
            "uptime-down" => bad.initial_uptime.ready = false,
            "uptime-unknown" => bad.initial_uptime.epoch.round_id = [0; 10],
            "uptime-grace" => bad.initial_uptime.epoch.started_at = 1_940,
            "epoch-pin" => bad.initial_uptime.epoch.round_id[0] ^= 1,
            "reordered" => {
                let different = bad
                    .material
                    .evidence
                    .iter()
                    .position(|e| {
                        (e.market_id, e.now_ms)
                            != (
                                bad.material.evidence[0].market_id,
                                bad.material.evidence[0].now_ms,
                            )
                    })
                    .unwrap();
                bad.material.evidence.swap(0, different);
                bad.material.refs.swap(0, different);
                bad.material.entries.swap(0, different);
            }
            "dropped" => {
                bad.material.evidence.pop();
                bad.material.refs.pop();
                bad.material.entries.pop();
            }
            "extra" => {
                bad.material.evidence.push(bad.material.evidence[0].clone());
                bad.material.refs.push(bad.material.refs[0].clone());
                bad.material.entries.push(bad.material.entries[0].clone());
            }
            "oversized-body" => bad.material.evidence[0].base.0.push(0),
            _ => unreachable!(),
        }
        let (path, store) = rig.store(&format!("invalid-{reason}.intent"));
        let mut mock = Mock::new(&rig.request, store.clone());
        let mut trusted = rig.trusted.clone();
        if reason.starts_with("uptime-") {
            trusted.initial_uptime = bad.initial_uptime;
        }
        if reason == "runtime-zero" {
            trusted.target = bad.target.clone();
        }
        if matches!(reason, "reordered" | "dropped" | "extra") {
            // Even newly trusted extraction labels cannot make evidence differ
            // from the immutable native witness operation sequence.
            bad.material.material_hash = bad.material.recomputed_hash().unwrap();
            trusted.material_hash = bad.material.material_hash;
        }
        assert!(
            execute(&bad, &trusted, &store, &mut mock).is_err(),
            "{reason}"
        );
        assert!(
            mock.calls.is_empty(),
            "{reason} must fail before all callbacks"
        );
        assert!(!path.exists(), "{reason} cannot persist an invalid intent");
    }
}

#[test]
fn candidate_protocol_each_later_callback_fault_stops_only_subsequent_actions() {
    let rig = Rig::new(false);
    for (i, action) in ACTIONS.iter().enumerate() {
        let (path, store) = rig.store(&format!("fault-{i}.intent"));
        let mut mock = Mock::new(&rig.request, store.clone());
        mock.fail = Some(*action);
        assert_eq!(
            execute(&rig.request, &rig.trusted, &store, &mut mock),
            Err(ProtocolError::Callback(*action))
        );
        assert_eq!(mock.calls, ACTIONS[..=i]);
        let reloaded = IntentStore::new(path, SEED).load().unwrap().unwrap();
        assert_eq!(
            reloaded.request,
            postcard::to_allocvec(&rig.request).unwrap()
        );
        assert_eq!(
            reloaded.stage,
            if i >= 5 {
                IntentStage::Prepared
            } else {
                IntentStage::Intent
            }
        );
    }
}

#[test]
fn candidate_protocol_receipt_report_epoch_and_typed_response_faults_hold() {
    let rig = Rig::new(true);
    for (i, (corrupt, completed)) in [
        (Corrupt::ClockReceipt, 2),
        (Corrupt::ClockTarget, 2),
        (Corrupt::ReportInput, 4),
        (Corrupt::ReportEvidence, 4),
        (Corrupt::ReportEpoch, 4),
        (Corrupt::ReportOldObservation, 4),
        (Corrupt::ProofProgram, 5),
        (Corrupt::ProofWidth, 5),
        (Corrupt::ProofCommitment, 5),
        (Corrupt::EmptyProof, 5),
        (Corrupt::RecheckClock, 6),
        (Corrupt::RecheckRecord, 6),
        (Corrupt::RecheckEpoch, 6),
        (Corrupt::RecheckTarget, 6),
    ]
    .into_iter()
    .enumerate()
    {
        let (_, store) = rig.store(&format!("corrupt-{i}.intent"));
        let mut mock = Mock::new(&rig.request, store.clone());
        mock.corrupt = Some(corrupt);
        assert!(execute(&rig.request, &rig.trusted, &store, &mut mock).is_err());
        assert_eq!(mock.calls, ACTIONS[..completed]);
        assert!(!mock.calls.contains(&Action::Broadcast));
    }
}

#[test]
fn candidate_protocol_failed_intent_and_prepared_save_preserve_recovery_cut() {
    let rig = Rig::new(false);
    let (path, store) = rig.store("durability.intent");
    let mut mock = Mock::new(&rig.request, store.clone());
    store.fail_next_save();
    assert_eq!(
        execute(&rig.request, &rig.trusted, &store, &mut mock),
        Err(ProtocolError::Durability)
    );
    assert!(mock.calls.is_empty());
    assert!(!path.exists());
    let request_bytes = postcard::to_allocvec(&rig.request).unwrap();
    store.save_intent(&request_bytes).unwrap();
    let previous = std::fs::read(&path).unwrap();
    mock.fail_prepared_save = true;
    assert_eq!(
        execute(&rig.request, &rig.trusted, &store, &mut mock),
        Err(ProtocolError::Durability)
    );
    assert_eq!(mock.calls, ACTIONS[..5]);
    assert_eq!(std::fs::read(&path).unwrap(), previous);
    let reopened = Arc::new(IntentStore::new(path, SEED));
    assert_eq!(reopened.load().unwrap().unwrap().stage, IntentStage::Intent);
    let mut retry = Mock::new(&rig.request, reopened.clone());
    execute(&rig.request, &rig.trusted, &reopened, &mut retry).unwrap();
    assert_eq!(retry.clock_inputs, mock.clock_inputs);
    assert_eq!(retry.report_inputs, mock.report_inputs);
    assert_eq!(retry.prove_inputs, mock.prove_inputs);
}

#[test]
fn candidate_protocol_prepared_restart_reuses_exact_request_without_v2_or_refresh() {
    let rig = Rig::new(false);
    let (path, store) = rig.store("restart.intent");
    let mut mock = Mock::new(&rig.request, store.clone());
    mock.fail = Some(Action::Recheck);
    assert_eq!(
        execute(&rig.request, &rig.trusted, &store, &mut mock),
        Err(ProtocolError::Callback(Action::Recheck))
    );
    let previous = std::fs::read(&path).unwrap();
    let reopened = Arc::new(IntentStore::new(path.clone(), SEED));
    let mut retry = Mock::new(&rig.request, reopened.clone());
    execute(&rig.request, &rig.trusted, &reopened, &mut retry).unwrap();
    assert_eq!(retry.calls, [Action::Recheck, Action::Broadcast]);
    assert_eq!(std::fs::read(&path).unwrap(), previous);
    let mut v2 = rig.request.clone();
    v2.program.wire_magic = *perp_core::clock::WIRE_MAGIC;
    let mut blocked = Mock::new(&rig.request, reopened.clone());
    assert_eq!(
        execute(&v2, &rig.trusted, &reopened, &mut blocked),
        Err(ProtocolError::Version)
    );
    assert!(blocked.calls.is_empty());
    let mut changed = rig.request.clone();
    let mut witness: CandidateWitness = postcard::from_bytes(&changed.witness[8..]).unwrap();
    witness.clock.3.anchored_at_ms += 100; // still native-valid; retry may not re-anchor
    changed.witness = WIRE_MAGIC.to_vec();
    changed
        .witness
        .extend(postcard::to_allocvec(&witness).unwrap());
    let changed_trust = TrustedRequest::extracted(
        &changed,
        rig.trusted.target.clone(),
        rig.trusted.initial_uptime,
    );
    assert_eq!(
        execute(&changed, &changed_trust, &reopened, &mut blocked),
        Err(ProtocolError::Durability)
    );
    assert!(blocked.calls.is_empty());
    assert_eq!(std::fs::read(&path).unwrap(), previous);
    let record = reopened.load().unwrap().unwrap();
    assert_eq!(record.request, postcard::to_allocvec(&rig.request).unwrap());
}

#[test]
fn candidate_protocol_pending_restart_changed_epoch_cannot_resume_old_intent() {
    let rig = Rig::new(false);
    let (path, store) = rig.store("pending-epoch.intent");
    let mut first = Mock::new(&rig.request, store.clone());
    first.fail = Some(Action::ObserveClock);
    assert!(execute(&rig.request, &rig.trusted, &store, &mut first).is_err());
    assert_eq!(first.calls, ACTIONS[..2]);
    assert_eq!(store.load().unwrap().unwrap().stage, IntentStage::Intent);
    let before = std::fs::read(&path).unwrap();
    let mut fresh = rig.request.clone();
    fresh.initial_uptime.epoch.round_id[9] ^= 1;
    let trusted =
        TrustedRequest::extracted(&fresh, rig.trusted.target.clone(), fresh.initial_uptime);
    let reopened = Arc::new(IntentStore::new(path.clone(), SEED));
    let mut retry = Mock::new(&fresh, reopened.clone());
    assert_eq!(
        execute(&fresh, &trusted, &reopened, &mut retry),
        Err(ProtocolError::Durability)
    );
    assert!(retry.calls.is_empty());
    assert_eq!(std::fs::read(&path).unwrap(), before);
    let mut stale = Mock::new(&rig.request, reopened.clone());
    stale.reports.epoch = fresh.initial_uptime.epoch;
    assert_eq!(
        execute(&rig.request, &rig.trusted, &reopened, &mut stale),
        Err(ProtocolError::Observation)
    );
    assert_eq!(stale.calls, ACTIONS[..4]);
    assert!(!stale.calls.contains(&Action::Prove));
    assert!(!stale.calls.contains(&Action::Broadcast));
}

#[test]
fn candidate_protocol_price_free_wind_down_uses_zero_epoch_and_exact_restart() {
    let rig = Rig::price_free();
    assert!(rig.request.material.entries.is_empty());
    assert!(rig.request.material.refs.is_empty());
    let (path, store) = rig.store("price-free.intent");
    let mut first = Mock::new(&rig.request, store.clone());
    first.fail = Some(Action::Recheck);
    assert_eq!(
        execute(&rig.request, &rig.trusted, &store, &mut first),
        Err(ProtocolError::Callback(Action::Recheck))
    );
    assert_eq!(first.calls, ACTIONS[..6]);
    assert_eq!(
        first.reports.epoch,
        UptimeEpoch {
            round_id: [0; 10],
            started_at: 0
        }
    );
    let before = std::fs::read(&path).unwrap();
    let reopened = Arc::new(IntentStore::new(path.clone(), SEED));
    let mut retry = Mock::new(&rig.request, reopened.clone());
    execute(&rig.request, &rig.trusted, &reopened, &mut retry).unwrap();
    assert_eq!(retry.calls, [Action::Recheck, Action::Broadcast]);
    assert_eq!(std::fs::read(&path).unwrap(), before);
    for reason in ["v2", "nonzero-epoch", "healthy-status"] {
        let mut bad = rig.request.clone();
        match reason {
            "v2" => bad.program.wire_magic = *perp_core::clock::WIRE_MAGIC,
            "nonzero-epoch" => bad.initial_uptime.epoch.round_id[0] = 1,
            "healthy-status" => bad.initial_uptime.ready = true,
            _ => unreachable!(),
        }
        let trusted =
            TrustedRequest::extracted(&bad, rig.trusted.target.clone(), bad.initial_uptime);
        let (path, store) = rig.store(&format!("price-free-{reason}.intent"));
        let mut mock = Mock::new(&rig.request, store.clone());
        assert!(execute(&bad, &trusted, &store, &mut mock).is_err());
        assert!(mock.calls.is_empty());
        assert!(!path.exists());
    }
}

#[test]
fn candidate_protocol_malformed_or_trailing_witness_calls_nothing() {
    let rig = Rig::new(false);
    for reason in ["truncated", "trailing", "malformed"] {
        let mut bad = rig.request.clone();
        match reason {
            "truncated" => {
                bad.witness.pop();
            }
            "trailing" => bad.witness.push(0),
            "malformed" => bad.witness = [WIRE_MAGIC.as_slice(), &[0xff; 16]].concat(),
            _ => unreachable!(),
        }
        let trusted =
            TrustedRequest::extracted(&bad, rig.trusted.target.clone(), rig.trusted.initial_uptime);
        let (path, store) = rig.store(&format!("witness-{reason}.intent"));
        let mut mock = Mock::new(&rig.request, store.clone());
        assert_eq!(
            execute(&bad, &trusted, &store, &mut mock),
            Err(ProtocolError::Version)
        );
        assert!(mock.calls.is_empty());
        assert!(!path.exists());
    }
}

#[test]
fn candidate_protocol_authenticated_invalid_prepared_payload_never_calls_recheck() {
    let rig = Rig::new(false);
    let (_, valid_store) = rig.store("valid-prepared.intent");
    let mut mock = Mock::new(&rig.request, valid_store.clone());
    let valid = execute(&rig.request, &rig.trusted, &valid_store, &mut mock).unwrap();
    let request_bytes = postcard::to_allocvec(&rig.request).unwrap();
    for reason in [
        "trailing",
        "truncated",
        "request",
        "native",
        "epoch",
        "receipt",
        "response",
        "noncanonical",
    ] {
        let mut prepared = valid.clone();
        match reason {
            "request" => prepared.request_sha256[0] ^= 1,
            "native" => prepared.native.commitment[0] ^= 1,
            "epoch" => prepared.reports.epoch.round_id[0] ^= 1,
            "receipt" => prepared.clock.receipt[0] ^= 1,
            "response" => prepared.response.public_values[0] ^= 1,
            _ => {}
        }
        let mut payload = postcard::to_allocvec(&prepared).unwrap();
        match reason {
            "trailing" => payload.push(0),
            "truncated" => {
                payload.pop();
            }
            "noncanonical" => {
                // request digest + four native digests precede target.chain_id.
                // Give its final unsigned-varint byte an unnecessary zero group.
                let last = (160..payload.len())
                    .find(|i| payload[*i] & 0x80 == 0)
                    .unwrap();
                payload[last] |= 0x80;
                payload.insert(last + 1, 0);
                let decoded: PreparedCandidate = postcard::from_bytes(&payload).unwrap();
                assert_eq!(decoded, valid, "alternate integers are semantically equal");
                assert_ne!(postcard::to_allocvec(&decoded).unwrap(), payload);
            }
            _ => {}
        }
        let (path, store) = rig.store(&format!("invalid-prepared-{reason}.intent"));
        store.save_intent(&request_bytes).unwrap();
        store.save_prepared(&request_bytes, &payload).unwrap();
        let before = std::fs::read(&path).unwrap();
        let reopened = Arc::new(IntentStore::new(path.clone(), SEED));
        let mut retry = Mock::new(&rig.request, reopened.clone());
        assert_eq!(
            execute(&rig.request, &rig.trusted, &reopened, &mut retry),
            Err(ProtocolError::Recovery),
            "{reason}"
        );
        assert!(retry.calls.is_empty(), "{reason}");
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
}

/// Exact original A3 archive containers for independent Solidity ABI parity.
#[test]
#[ignore = "explicit fresh-directory export of owned synthetic original A3 material"]
fn export_actual_a3_candidate_registration_parity() {
    let path = PathBuf::from(
        std::env::var_os("ARCORA_CHAINLINK_PROTOCOL_PARITY_EXPORT")
            .expect("explicit fresh destination"),
    );
    std::fs::create_dir(&path).unwrap();
    let mut cases = vec![];
    let mut cpu_cases = vec![];
    for (name, liquidation) in [("normal-lifecycle", false), ("liquidation", true)] {
        let rig = Rig::new(liquidation);
        let witness: CandidateWitness = postcard::from_bytes(&rig.request.witness[8..]).unwrap();
        let registered = registration(
            &witness.policy,
            &witness.clock.3,
            &rig.request.material.entries,
        )
        .unwrap();
        let native = chainlink_oracle::binding::run_encoded(&rig.request.witness).unwrap();
        assert_eq!(registered.evidence_hash, native.evidence_hash);
        let witness_file = format!("{name}.witness.bin");
        std::fs::write(path.join(&witness_file), &rig.request.witness).unwrap();
        std::fs::write(
            path.join(format!("{name}.native-public.bin")),
            native.commitment,
        )
        .unwrap();
        cpu_cases.push(serde_json::json!({"name":name,"witness_file":witness_file,"witness_sha256":crate::hex0x(&sha256(&rig.request.witness))[2..],
            "witness_bytes":rig.request.witness.len(),"outcome":"PASS","native_error":null,"expected_commitment":crate::hex0x(&native.commitment)[2..],
            "op_count":witness.clock.1.len(),"evidence_count":witness.evidence.len()}));
        let reference_sha = if liquidation {
            "5910ca22fd419bb53d29df9a11c15e6e7c90eee55210ef99000349c86a37a14d"
        } else {
            "587d8a9f065a04c4df2a441e4cbabfd2d407accc117772f1ee8745bcae4eb980"
        };
        let reference_compared = if let Some(dir) =
            std::env::var_os("ARCORA_CHAINLINK_PROTOCOL_REFERENCE_DIR")
        {
            let bytes =
                std::fs::read(PathBuf::from(dir).join(format!("{name}.witness.bin"))).unwrap();
            assert_eq!(&crate::hex0x(&sha256(&bytes))[2..], reference_sha);
            chainlink_oracle::binding::run_encoded(&bytes).unwrap();
            let reference: CandidateWitness = postcard::from_bytes(&bytes[8..]).unwrap();
            assert_eq!(reference.policy, witness.policy);
            assert_eq!(
                postcard::to_allocvec(&reference.evidence).unwrap(),
                postcard::to_allocvec(&witness.evidence).unwrap()
            );
            assert_eq!(
                (
                    reference.clock.3.first_ms,
                    reference.clock.3.last_ms,
                    reference.clock.3.timed_ops
                ),
                (
                    witness.clock.3.first_ms,
                    witness.clock.3.last_ms,
                    witness.clock.3.timed_ops
                )
            );
            let kind = |ops: &[perp_core::engine::BatchOp]| {
                ops.iter()
                    .filter_map(|op| match op {
                        perp_core::engine::BatchOp::Fill { .. } => Some("Fill"),
                        perp_core::engine::BatchOp::AccrueFunding { .. } => Some("AccrueFunding"),
                        perp_core::engine::BatchOp::Liquidate { .. } => Some("Liquidate"),
                        perp_core::engine::BatchOp::Unbind { .. } => Some("Unbind"),
                        _ => None,
                    })
                    .collect::<Vec<_>>()
            };
            assert_eq!(kind(&reference.clock.1), kind(&witness.clock.1));
            true
        } else {
            false
        };
        let entries:Vec<_>=rig.request.material.entries.iter().map(|entry|serde_json::json!({
            "market_id":entry.market_id,"now_ms":entry.now_ms,"base_full_report":crate::hex0x(&entry.base_report),"quote_full_report":crate::hex0x(&entry.quote_report),
            "base_body":crate::hex0x(&chainlink_oracle::report::body_from_full_report(&entry.base_report).unwrap().0),
            "quote_body":crate::hex0x(&chainlink_oracle::report::body_from_full_report(&entry.quote_report).unwrap().0)
        })).collect();
        cases.push(serde_json::json!({"name":name,"entries_abi":crate::hex0x(&registered.entries_abi),"input_hash":crate::hex0x(&registered.input_hash),
            "evidence_hash":crate::hex0x(&registered.evidence_hash),"policy_hash":crate::hex0x(&witness.policy.hash().unwrap()),
            "first_ms":witness.clock.3.first_ms,"last_ms":witness.clock.3.last_ms,"timed_ops":witness.clock.3.timed_ops,"entries":entries,
            "policy":witness.policy,"clock":witness.clock.3,"original_entries":rig.request.material.entries,
            "reference_a3_witness_sha256":reference_sha,"reference_flow_compared":reference_compared,"new_random_account_witness_identity_claim":false,
            "witness_sha256":crate::hex0x(&sha256(&rig.request.witness))}));
    }
    let sources = serde_json::json!({"candidate_registration.rs":crate::hex0x(&sha256(include_bytes!("candidate_registration.rs"))),
        "report_archive_binding.rs":crate::hex0x(&sha256(include_bytes!("report_archive_binding.rs"))),
        "price_lifecycle_tests.rs":crate::hex0x(&sha256(include_bytes!("price_lifecycle_tests.rs"))),
        "candidate_protocol_tests.rs":crate::hex0x(&sha256(include_bytes!("candidate_protocol_tests.rs")))});
    let manifest = serde_json::json!({"schema":"arcora-candidate-registration-parity-v1","synthetic":true,"original_archive_containers":true,"real_don_verified":false,"proof_generated":false,"candidate_submission":"HOLD","sources_sha256":sources,"cases":cases});
    std::fs::write(
        path.join("registration-parity.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
    let cpu = serde_json::json!({"synthetic":true,"real_don_verified":false,"proof_generated":false,"candidate_submission":"HOLD","sources_sha256":sources,"cases":cpu_cases});
    std::fs::write(
        path.join("manifest.json"),
        serde_json::to_vec_pretty(&cpu).unwrap(),
    )
    .unwrap();
}

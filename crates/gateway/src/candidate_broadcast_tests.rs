//! Fixed #50 normal/liquidation inputs and caller-owned offline outcomes only.
use crate::{
    candidate_broadcast::*,
    candidate_broadcast_store::{decode_sealed, BroadcastStore, StoreError},
    candidate_protocol::{
        sha256, CandidateProofResponse, ClockObservation, PreparedCandidate, ProgramIdentity,
        ProtocolRequest, ReportObservation, TargetIdentity, TrustedRequest, UptimeObservation,
    },
    candidate_recovery::{Anchored, FinalityContext, Lookup, RegistrationAnchor},
    candidate_recovery_store::{Record as SourceRecord, RecoveryStore, Stage},
    candidate_registration::{registration, UptimeEpoch},
    report_archive_binding::CandidateMaterial,
};
use chainlink_oracle::binding::{CandidateWitness, WIRE_MAGIC};
use serde_json::Value;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

const SEED: [u8; 32] = [0xb7; 32];
const SOURCE_SEED: [u8; 32] = [0xb8; 32];
const FIXTURES: &str = "../../docs/audits/2026-10-11-chainlink-native-contract-bridge/fixtures";

struct OwnedDir(PathBuf);
impl OwnedDir {
    fn new() -> Self {
        let mut random = [0; 16];
        getrandom::getrandom(&mut random).unwrap();
        let p = std::env::temp_dir().join(format!(
            "arcora-broadcast-{}-{}",
            std::process::id(),
            crate::hex0x(&random)
        ));
        std::fs::create_dir(&p).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self(std::fs::canonicalize(p).unwrap())
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
        .chunks_exact(2)
        .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
        .collect()
}
fn bytes<const N: usize>(v: &Value, key: &str) -> [u8; N] {
    unhex(v[key].as_str().unwrap()).try_into().unwrap()
}
struct Rig {
    dir: OwnedDir,
    source: RecoveryStore,
    request: ProtocolRequest,
    trusted: TrustedRequest,
    bridge: BridgeTarget,
    clock: Anchored<ClockObservation>,
    reports: Anchored<ReportObservation>,
}
impl Rig {
    fn new(flow: usize) -> Self {
        let dir = OwnedDir::new();
        let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join(FIXTURES);
        let name = ["normal-lifecycle", "liquidation"][flow];
        let wire = std::fs::read(fixtures.join(format!("{name}.witness.bin"))).unwrap();
        assert_eq!(&wire[..8], WIRE_MAGIC);
        let witness: CandidateWitness = postcard::from_bytes(&wire[8..]).unwrap();
        let material: CandidateMaterial = postcard::from_bytes(
            &std::fs::read(fixtures.join(format!("{name}.material.bin"))).unwrap(),
        )
        .unwrap();
        let corpus: Value =
            serde_json::from_slice(&std::fs::read(fixtures.join("bridge.json")).unwrap()).unwrap();
        let v = &corpus["cases"][flow]["target_context"];
        let initial = UptimeObservation {
            epoch: UptimeEpoch {
                round_id: bytes(v, "uptime_round_id"),
                started_at: v["uptime_started_at"].as_u64().unwrap(),
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
            uptime_feed: bytes(v, "uptime_feed"),
            grace_seconds: v["grace_seconds"].as_u64().unwrap(),
            settlement_code_hash: bytes(v, "settlement_code_hash"),
            clock_code_hash: bytes(v, "clock_verifier_code_hash"),
            wrapper_code_hash: bytes(v, "oracle_wrapper_code_hash"),
            proxy_code_hash: bytes(v, "verifier_proxy_code_hash"),
            uptime_code_hash: bytes(v, "uptime_feed_code_hash"),
        };
        let bridge = BridgeTarget {
            sp1_adapter: bytes(v, "sp1_adapter"),
            sp1_gateway: bytes(v, "sp1_gateway"),
            prefix_vault: bytes(v, "prefix_vault"),
            sp1_adapter_code_hash: bytes(v, "sp1_adapter_code_hash"),
            sp1_gateway_code_hash: bytes(v, "sp1_gateway_code_hash"),
            prefix_vault_code_hash: bytes(v, "prefix_vault_code_hash"),
        };
        let request = ProtocolRequest {
            program: ProgramIdentity::pinned(),
            target: target.clone(),
            witness: wire,
            material,
            initial_uptime: initial,
        };
        let trusted = TrustedRequest::extracted(&request, target.clone(), initial);
        let native = chainlink_oracle::binding::run_encoded(&request.witness).unwrap();
        let reg =
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
                input_hash: reg.input_hash,
                evidence_hash: native.evidence_hash,
                epoch: initial.epoch,
                uptime_ready: initial.ready,
                observed_at_seconds: initial.observed_at_seconds,
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
        let prepared = PreparedCandidate {
            request_sha256: sha256(&postcard::to_allocvec(&request).unwrap()),
            native,
            clock: clock.value.clone(),
            reports: reports.value.clone(),
            response: CandidateProofResponse {
                program: request.program.clone(),
                public_values: native.commitment.to_vec(),
                proof: b"arcora-native-contract-bridge-mock-proof-v1".to_vec(),
            },
        };
        let source = RecoveryStore::new(dir.0.join("prepared.dpcint4"), SOURCE_SEED);
        let mut cut = source
            .create(&postcard::to_allocvec(&request).unwrap())
            .unwrap();
        for stage in [
            Stage::ClockPending,
            Stage::ClockObserved,
            Stage::ReportsPending,
            Stage::ReportsObserved,
            Stage::Prepared,
        ] {
            let mut next = cut.clone();
            next.stage = stage;
            match stage {
                Stage::ClockObserved => next.clock = Some(postcard::to_allocvec(&clock).unwrap()),
                Stage::ReportsObserved => {
                    next.reports = Some(postcard::to_allocvec(&reports).unwrap())
                }
                Stage::Prepared => next.prepared = Some(postcard::to_allocvec(&prepared).unwrap()),
                _ => {}
            }
            cut = source.advance(&cut, next).unwrap();
        }
        Self {
            dir,
            source,
            request,
            trusted,
            bridge,
            clock,
            reports,
        }
    }
    fn path(&self, name: &str) -> PathBuf {
        self.dir.0.join(name)
    }
    fn store(&self, name: &str) -> BroadcastStore {
        BroadcastStore::new(self.path(name), SEED).unwrap()
    }
    fn plan(&self) -> Plan {
        build_plan(
            &self.source.load().unwrap().unwrap(),
            &self.request,
            &self.trusted,
            &self.bridge,
            [0xc1; 20],
            7,
        )
        .unwrap()
    }
}

fn success(plan: &Plan) -> Outcome {
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
struct Mock<'a> {
    rig: &'a Rig,
    store: &'a BroadcastStore,
    path: PathBuf,
    expected: Plan,
    calls: Vec<Action>,
    result: Option<Lookup<OutcomeValue>>,
    lost_reply: bool,
    outcome_failure: u8,
    preflight: Option<(Anchored<ClockObservation>, Anchored<ReportObservation>)>,
    gate: Option<(std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>)>,
}
impl<'a> Mock<'a> {
    fn new(rig: &'a Rig, store: &'a BroadcastStore, name: &str) -> Self {
        let expected = rig.plan();
        let result = Some(Lookup::Finalized(success(&expected)));
        Self {
            rig,
            store,
            path: rig.path(name),
            expected,
            calls: vec![],
            result,
            lost_reply: false,
            outcome_failure: 0,
            preflight: None,
            gate: None,
        }
    }
    fn run(&mut self, mode: RunMode) -> Result<Outcome, BroadcastError> {
        execute(
            self.store,
            mode,
            &self.rig.source,
            &self.rig.request,
            &self.rig.trusted,
            &self.rig.bridge,
            [0xc1; 20],
            7,
            self,
        )
    }
}
impl BroadcastTransport for Mock<'_> {
    fn recheck(
        &mut self,
        plan: &Plan,
    ) -> Result<(Anchored<ClockObservation>, Anchored<ReportObservation>), ()> {
        assert_eq!(plan, &self.expected);
        self.calls.push(Action::Recheck);
        Ok(self
            .preflight
            .clone()
            .unwrap_or_else(|| (self.rig.clock.clone(), self.rig.reports.clone())))
    }
    fn broadcast(&mut self, plan: &Plan) -> Result<(), ()> {
        assert_eq!(plan, &self.expected);
        self.calls.push(Action::Broadcast);
        let cut = decode_sealed(&std::fs::read(&self.path).unwrap(), &SEED).unwrap();
        assert_eq!(cut.plan, plan_bytes(plan).unwrap());
        assert!(cut.outcome.is_none());
        if let Some((ready, release)) = &self.gate {
            ready.send(()).unwrap();
            release
                .recv_timeout(std::time::Duration::from_secs(20))
                .unwrap();
        }
        match self.outcome_failure {
            1 => self.store.fail_next_write(),
            2 => self.store.fail_next_rename(),
            3 => self.store.fail_next_directory_sync(),
            _ => {}
        }
        if self.lost_reply {
            Err(())
        } else {
            Ok(())
        }
    }
    fn lookup(&mut self, plan: &Plan) -> Result<Lookup<OutcomeValue>, ()> {
        assert_eq!(plan, &self.expected);
        self.calls.push(Action::Lookup);
        self.result.take().ok_or(())
    }
}

#[test]
fn broadcast_fixed_bridge_plans_pin_all_roots_exact_abi_and_mock_identity() {
    for flow in 0..2 {
        let rig = Rig::new(flow);
        let plan = rig.plan();
        let corpus: Value = serde_json::from_slice(
            &std::fs::read(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join(FIXTURES)
                    .join("bridge.json"),
            )
            .unwrap(),
        )
        .unwrap();
        let case = &corpus["cases"][flow];
        for (i, key) in [
            "prev_state_root",
            "manifest_hash",
            "new_state_root",
            "ordered_root",
            "withdrawals_root",
            "rejected_root",
            "deposits_root",
        ]
        .iter()
        .enumerate()
        {
            assert_eq!(plan.roots[i], bytes(case.get("roots").unwrap(), key));
        }
        assert_eq!(plan.public_values, bytes(case, "candidate_commitment"));
        assert_eq!(plan.consumed_deposit_count, 9);
        assert_eq!(plan.consumed_deposit_tip, plan.roots[6]);
        assert_eq!(plan.batch_id, 0);
        assert_eq!(plan.phase, 0);
        // Independent byte layout assertion, including dynamic padding and uint64.
        let proof = unhex(case["mock_proof"].as_str().unwrap());
        let selector = perp_core::clock::keccak(
            b"settleBatch(bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,uint64,bytes)",
        );
        assert_eq!(&plan.calldata[..4], &selector[..4]);
        for i in 0..7 {
            assert_eq!(&plan.calldata[4 + i * 32..4 + (i + 1) * 32], &plan.roots[i]);
        }
        assert_eq!(
            &plan.calldata[4 + 7 * 32..4 + 8 * 32],
            &perp_core::clock::abi_u64(9)
        );
        assert_eq!(
            &plan.calldata[4 + 8 * 32..4 + 9 * 32],
            &perp_core::clock::abi_u64(288)
        );
        assert_eq!(
            &plan.calldata[292..324],
            &perp_core::clock::abi_u64(proof.len() as u64)
        );
        assert_eq!(&plan.calldata[324..324 + proof.len()], proof);
        assert!(plan.calldata[324 + proof.len()..].iter().all(|b| *b == 0));
        assert_ne!(plan.attempt_id, [0; 32]);
        assert_ne!(plan.mock_tx_id, [0; 32]);
        assert_ne!(plan.attempt_id, plan.mock_tx_id);
        let mut changed = plan.clone();
        changed.mock_nonce += 1;
        assert!(validate_plan(
            &changed,
            &rig.source.load().unwrap().unwrap(),
            &rig.request,
            &rig.trusted,
            &rig.bridge,
            [0xc1; 20],
            7
        )
        .is_err());
    }
}
#[test]
fn broadcast_both_flows_pending_precedes_one_call_and_terminal_is_noop() {
    for flow in 0..2 {
        let rig = Rig::new(flow);
        let store = rig.store("success");
        let original = std::fs::read(rig.path("prepared.dpcint4")).unwrap();
        let mut mock = Mock::new(&rig, &store, "success");
        let result = mock.run(RunMode::Fresh).unwrap();
        assert_eq!(
            mock.calls,
            [Action::Recheck, Action::Broadcast, Action::Lookup]
        );
        assert_eq!(result, success(&rig.plan()));
        let saved = std::fs::read(rig.path("success")).unwrap();
        let reopened = rig.store("success");
        let mut terminal = Mock::new(&rig, &reopened, "success");
        assert_eq!(terminal.run(RunMode::Resume).unwrap(), result);
        assert!(terminal.calls.is_empty());
        assert_eq!(std::fs::read(rig.path("success")).unwrap(), saved);
        assert_eq!(
            std::fs::read(rig.path("prepared.dpcint4")).unwrap(),
            original
        );
        let mut fresh = Mock::new(&rig, &reopened, "success");
        assert_eq!(
            fresh.run(RunMode::Fresh),
            Err(BroadcastError::Store(StoreError::Exists))
        );
        assert!(fresh.calls.is_empty());
    }
}
#[test]
fn broadcast_accepted_lost_reply_reopens_lookup_only() {
    for flow in 0..2 {
        let rig = Rig::new(flow);
        let store = rig.store("lost");
        let mut mock = Mock::new(&rig, &store, "lost");
        mock.lost_reply = true;
        assert_eq!(
            mock.run(RunMode::Fresh),
            Err(BroadcastError::Callback(Action::Broadcast))
        );
        assert_eq!(mock.calls, [Action::Recheck, Action::Broadcast]);
        let pending = decode_sealed(&std::fs::read(rig.path("lost")).unwrap(), &SEED).unwrap();
        assert!(pending.outcome.is_none());
        let reopened = rig.store("lost");
        let mut resume = Mock::new(&rig, &reopened, "lost");
        assert_eq!(resume.run(RunMode::Resume).unwrap(), success(&rig.plan()));
        assert_eq!(resume.calls, [Action::Lookup]);
    }
}
#[test]
fn broadcast_outcome_write_rename_and_uncertain_ack_never_resend() {
    let rig = Rig::new(0);
    for failure in 1..=3 {
        let name = format!("outcome-{failure}");
        let store = rig.store(&name);
        let mut mock = Mock::new(&rig, &store, &name);
        mock.outcome_failure = failure;
        assert_eq!(
            mock.run(RunMode::Fresh),
            Err(BroadcastError::Store(if failure == 3 {
                StoreError::AmbiguousWrite
            } else {
                StoreError::Write
            }))
        );
        assert_eq!(
            mock.calls,
            [Action::Recheck, Action::Broadcast, Action::Lookup]
        );
        let reopened = rig.store(&name);
        let mut resume = Mock::new(&rig, &reopened, &name);
        assert_eq!(resume.run(RunMode::Resume).unwrap(), success(&rig.plan()));
        assert_eq!(
            resume.calls,
            if failure == 3 {
                vec![]
            } else {
                vec![Action::Lookup]
            }
        );
    }
}
#[test]
fn broadcast_pending_publication_failures_stop_before_callback() {
    let rig = Rig::new(1);
    for failure in 1..=3 {
        let name = format!("pending-{failure}");
        let store = rig.store(&name);
        match failure {
            1 => store.fail_next_write(),
            2 => store.fail_next_rename(),
            _ => store.fail_next_directory_sync(),
        }
        let mut mock = Mock::new(&rig, &store, &name);
        assert_eq!(
            mock.run(RunMode::Fresh),
            Err(BroadcastError::Store(if failure == 3 {
                StoreError::AmbiguousWrite
            } else {
                StoreError::Write
            }))
        );
        assert_eq!(mock.calls, [Action::Recheck]);
        let reopened = rig.store(&name);
        let mut resume = Mock::new(&rig, &reopened, &name);
        resume.result = Some(Lookup::Absent);
        if failure == 3 {
            assert_eq!(
                resume.run(RunMode::Resume),
                Err(BroadcastError::Hold(
                    crate::candidate_recovery::LookupState::Absent
                ))
            );
            assert_eq!(resume.calls, [Action::Lookup]);
        } else {
            assert_eq!(
                resume.run(RunMode::Resume),
                Err(BroadcastError::Store(StoreError::Missing))
            );
            assert!(resume.calls.is_empty());
        }
    }
}
#[test]
fn broadcast_crash_cut_before_callback_holds_every_nonfinal_lookup() {
    let rig = Rig::new(0);
    for (i, lookup) in [
        Lookup::Absent,
        Lookup::Pending,
        Lookup::Unknown,
        Lookup::Reorg,
    ]
    .into_iter()
    .enumerate()
    {
        let name = format!("crash-{i}");
        let store = rig.store(&name);
        let cut = store
            .try_lease()
            .unwrap()
            .create_pending(&plan_bytes(&rig.plan()).unwrap())
            .unwrap();
        let initial = std::fs::read(rig.path(&name)).unwrap();
        let mut mock = Mock::new(&rig, &store, &name);
        mock.result = Some(lookup);
        assert!(matches!(
            mock.run(RunMode::Resume),
            Err(BroadcastError::Hold(_))
        ));
        assert_eq!(mock.calls, [Action::Lookup]);
        assert_eq!(std::fs::read(rig.path(&name)).unwrap(), initial);
        assert_eq!(store.try_lease().unwrap().load().unwrap().unwrap(), cut);
    }
}
#[test]
fn broadcast_finalized_revert_is_distinct_terminal_and_zero_callback_resume() {
    let rig = Rig::new(1);
    let store = rig.store("revert");
    let mut outcome = success(&rig.plan());
    outcome.value.status = OutcomeStatus::Reverted(b"mock receipt status zero".to_vec());
    let mut mock = Mock::new(&rig, &store, "revert");
    mock.result = Some(Lookup::Finalized(outcome.clone()));
    assert_eq!(mock.run(RunMode::Fresh).unwrap(), outcome);
    let mut terminal = Mock::new(&rig, &store, "revert");
    terminal.preflight = Some((rig.clock.clone(), {
        let mut r = rig.reports.clone();
        r.value.uptime_ready = false;
        r
    }));
    assert_eq!(terminal.run(RunMode::Resume).unwrap(), outcome);
    assert!(terminal.calls.is_empty());
}
#[test]
fn broadcast_authenticated_plan_mutations_refuse_before_any_callback() {
    let rig = Rig::new(0);
    let plan = rig.plan();
    let mut changes = Vec::new();
    macro_rules! changed {
        ($field:ident,$value:expr) => {{
            let mut p = plan.clone();
            p.$field = $value;
            changes.push(p);
        }};
    }
    for root in 0..7 {
        let mut p = plan.clone();
        p.roots[root][0] ^= 1;
        changes.push(p);
    }
    changed!(consumed_deposit_count, 10);
    changed!(consumed_deposit_tip, [0x81; 32]);
    changed!(public_values, [0x82; 32]);
    changed!(mock_nonce, 8);
    changed!(mock_tx_id, [0x83; 32]);
    changed!(attempt_id, [0x84; 32]);
    changed!(source_cut_sha256, [0x85; 32]);
    changed!(prepared_sha256, [0x86; 32]);
    changed!(batch_id, 1);
    changed!(phase, 1);
    let mut p = plan.clone();
    p.calldata[324] ^= 1;
    changes.push(p);
    let mut p = plan.clone();
    p.target.settlement_code_hash[0] ^= 1;
    changes.push(p);
    let mut p = plan.clone();
    p.bridge_target.sp1_gateway_code_hash[0] ^= 1;
    changes.push(p);
    let mut p = plan.clone();
    p.clock.anchor.tx_hash[0] ^= 1;
    changes.push(p);
    for (i, altered) in changes.into_iter().enumerate() {
        let name = format!("plan-{i}");
        let store = rig.store(&name);
        store
            .try_lease()
            .unwrap()
            .create_pending(&plan_bytes(&altered).unwrap())
            .unwrap();
        let mut mock = Mock::new(&rig, &store, &name);
        assert_eq!(
            mock.run(RunMode::Resume),
            Err(BroadcastError::PlanMismatch),
            "alteration {i}"
        );
        assert!(mock.calls.is_empty());
    }
}
#[test]
fn broadcast_changed_config_request_or_nonce_cannot_refresh_pending_attempt() {
    let rig = Rig::new(0);
    let store = rig.store("pins");
    store
        .try_lease()
        .unwrap()
        .create_pending(&plan_bytes(&rig.plan()).unwrap())
        .unwrap();
    let mut bridge = rig.bridge.clone();
    bridge.sp1_adapter[0] ^= 1;
    let mut mock = Mock::new(&rig, &store, "pins");
    assert!(execute(
        &store,
        RunMode::Resume,
        &rig.source,
        &rig.request,
        &rig.trusted,
        &bridge,
        [0xc1; 20],
        7,
        &mut mock
    )
    .is_err());
    assert!(mock.calls.is_empty());
    let mut mock = Mock::new(&rig, &store, "pins");
    assert!(execute(
        &store,
        RunMode::Resume,
        &rig.source,
        &rig.request,
        &rig.trusted,
        &rig.bridge,
        [0xc1; 20],
        8,
        &mut mock
    )
    .is_err());
    assert!(mock.calls.is_empty());
    let mut request = rig.request.clone();
    request.witness[10] ^= 1;
    let mut mock = Mock::new(&rig, &store, "pins");
    assert!(execute(
        &store,
        RunMode::Resume,
        &rig.source,
        &request,
        &rig.trusted,
        &rig.bridge,
        [0xc1; 20],
        7,
        &mut mock
    )
    .is_err());
    assert!(mock.calls.is_empty());
}
#[test]
fn broadcast_wrong_finalized_result_identity_effect_and_finality_stay_pending() {
    let rig = Rig::new(1);
    let good = success(&rig.plan());
    let mut changes = vec![];
    macro_rules! alter {
        ($body:expr) => {{
            let mut o = good.clone();
            ($body)(&mut o);
            changes.push(o);
        }};
    }
    alter!(|o: &mut Outcome| o.value.attempt_id[0] ^= 1);
    alter!(|o: &mut Outcome| o.value.mock_tx_id[0] ^= 1);
    alter!(|o: &mut Outcome| o.value.plan_hash[0] ^= 1);
    alter!(|o: &mut Outcome| o.value.call_hash[0] ^= 1);
    alter!(|o: &mut Outcome| o.value.public_values[0] ^= 1);
    alter!(|o: &mut Outcome| o.value.target.chain_id += 1);
    alter!(|o: &mut Outcome| o.anchor.tx_hash[0] ^= 1);
    alter!(|o: &mut Outcome| o.anchor.block_number = 0);
    alter!(|o: &mut Outcome| o.anchor.block_hash[0] ^= 1);
    alter!(|o: &mut Outcome| o.finality.finalized_block_number = 44);
    alter!(|o: &mut Outcome| {
        o.finality.finalized_block_number = 45;
        o.finality.finalized_block_hash = [0x99; 32];
        o.anchor.block_number = 43;
        o.anchor.block_hash = [0x43; 32];
        o.finality.canonical_block_hash = [0x43; 32];
    });
    for field in 0..13 {
        let mut o = good.clone();
        let OutcomeStatus::Success(e) = &mut o.value.status else {
            unreachable!()
        };
        match field {
            0 => e.post_root[0] ^= 1,
            1 => e.batch_count += 1,
            2 => e.batch_id += 1,
            3 => e.manifest_hash[0] ^= 1,
            4 => e.ordered_root[0] ^= 1,
            5 => e.rejected_root[0] ^= 1,
            6 => e.settled_at_block += 1,
            7 => e.withdrawal_root[0] ^= 1,
            8 => e.withdrawal_epoch += 1,
            9 => e.publication_count = 0,
            10 => e.publication_count = 2,
            11 => e.consumed_deposit_count += 1,
            _ => e.consumed_deposit_tip[0] ^= 1,
        };
        changes.push(o);
    }
    for (i, bad) in changes.into_iter().enumerate() {
        let name = format!("result-{i}");
        let store = rig.store(&name);
        store
            .try_lease()
            .unwrap()
            .create_pending(&plan_bytes(&rig.plan()).unwrap())
            .unwrap();
        let bytes = std::fs::read(rig.path(&name)).unwrap();
        let mut mock = Mock::new(&rig, &store, &name);
        mock.result = Some(Lookup::Finalized(bad));
        assert!(mock.run(RunMode::Resume).is_err(), "alteration {i}");
        assert_eq!(mock.calls, [Action::Lookup]);
        assert_eq!(std::fs::read(rig.path(&name)).unwrap(), bytes);
    }
}
#[test]
fn broadcast_bad_preflight_finality_epoch_identity_or_readiness_prevents_pending() {
    let rig = Rig::new(0);
    for i in 0..6 {
        let name = format!("preflight-{i}");
        let store = rig.store(&name);
        let mut clock = rig.clock.clone();
        let mut reports = rig.reports.clone();
        match i {
            0 => clock.anchor.tx_hash[0] ^= 1,
            1 => reports.value.uptime_ready = false,
            2 => reports.value.epoch.round_id[9] ^= 1,
            3 => reports.finality.finalized_block_number = 44,
            4 => reports.anchor.block_hash[0] ^= 1,
            _ => reports.value.input_hash[0] ^= 1,
        }
        let mut mock = Mock::new(&rig, &store, &name);
        mock.preflight = Some((clock, reports));
        assert!(mock.run(RunMode::Fresh).is_err());
        assert_eq!(mock.calls, [Action::Recheck]);
        assert!(!rig.path(&name).exists());
    }
}
#[test]
fn broadcast_saved_opaque_outcome_semantics_and_trailing_bytes_precede_callbacks() {
    let rig = Rig::new(0);
    for i in 0..3 {
        let name = format!("saved-{i}");
        let store = rig.store(&name);
        let lease = store.try_lease().unwrap();
        let pending = lease
            .create_pending(&plan_bytes(&rig.plan()).unwrap())
            .unwrap();
        let mut outcome = success(&rig.plan());
        if i == 0 {
            outcome.value.mock_tx_id[0] ^= 1;
        }
        let mut encoded = outcome_bytes(&outcome).unwrap();
        if i == 1 {
            encoded.push(0);
        }
        if i == 2 {
            encoded = vec![0xff; 12];
        }
        lease.finish(&pending, &encoded).unwrap();
        drop(lease);
        let mut mock = Mock::new(&rig, &store, &name);
        assert!(mock.run(RunMode::Resume).is_err());
        assert!(mock.calls.is_empty());
    }
    let store = rig.store("plan-tail");
    let mut bytes = plan_bytes(&rig.plan()).unwrap();
    bytes.push(0);
    store.try_lease().unwrap().create_pending(&bytes).unwrap();
    let mut mock = Mock::new(&rig, &store, "plan-tail");
    assert!(mock.run(RunMode::Resume).is_err());
    assert!(mock.calls.is_empty());
}
#[test]
fn broadcast_lease_serializes_same_and_independent_handles_through_callback() {
    for independent in [false, true] {
        let rig = Rig::new(0);
        let owner = Arc::new(rig.store("race"));
        let contender = if independent {
            Arc::new(rig.store("race"))
        } else {
            owner.clone()
        };
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        std::thread::scope(|scope| {
            let rig_ref = &rig;
            let owner_ref = &*owner;
            let handle = scope.spawn(move || {
                let mut mock = Mock::new(rig_ref, owner_ref, "race");
                mock.gate = Some((ready_tx, release_rx));
                let result = mock.run(RunMode::Fresh);
                (result, mock.calls)
            });
            ready_rx
                .recv_timeout(std::time::Duration::from_secs(20))
                .unwrap();
            let mut mock = Mock::new(&rig, &contender, "race");
            assert_eq!(
                mock.run(RunMode::Resume),
                Err(BroadcastError::Store(StoreError::Busy))
            );
            assert!(mock.calls.is_empty());
            release_tx.send(()).unwrap();
            let (result, calls) = handle.join().unwrap();
            assert_eq!(result.unwrap(), success(&rig.plan()));
            assert_eq!(calls, [Action::Recheck, Action::Broadcast, Action::Lookup]);
        });
        let mut resume = Mock::new(&rig, &contender, "race");
        resume.run(RunMode::Resume).unwrap();
        assert!(resume.calls.is_empty());
    }
}

fn replace_source(rig: &Rig, record: &SourceRecord) {
    let fields = [
        record.request.as_slice(),
        record.clock.as_deref().unwrap_or_default(),
        record.reports.as_deref().unwrap_or_default(),
        record.prepared.as_deref().unwrap_or_default(),
    ];
    let mut plain = b"DPCINT4\0".to_vec();
    plain.push(4);
    plain.push(match record.stage {
        Stage::Intent => 0,
        Stage::ClockPending => 1,
        Stage::ClockObserved => 2,
        Stage::ReportsPending => 3,
        Stage::ReportsObserved => 4,
        Stage::Prepared => 5,
    });
    for field in fields {
        plain.extend_from_slice(&(field.len() as u32).to_le_bytes());
    }
    for field in fields {
        plain.extend_from_slice(field);
    }
    std::fs::write(
        rig.path("prepared.dpcint4"),
        crate::snapshot::seal(&plain, &SOURCE_SEED),
    )
    .unwrap();
}
#[test]
fn broadcast_wrong_terminal_prepared_source_is_rejected_without_callbacks() {
    for mutation in 0..9 {
        let rig = Rig::new(0);
        let store = rig.store("bad-source");
        let mut record = rig.source.load().unwrap().unwrap();
        match mutation {
            0 => record.request.push(0),
            1 => {
                record.stage = Stage::ReportsObserved;
                record.prepared = None;
            }
            2 => record.prepared.as_mut().unwrap().push(0),
            3..=6 => {
                let mut prepared: PreparedCandidate =
                    postcard::from_bytes(record.prepared.as_ref().unwrap()).unwrap();
                match mutation {
                    3 => prepared.response.public_values[0] ^= 1,
                    4 => prepared.response.public_values.push(0),
                    5 => prepared.response.proof.clear(),
                    _ => prepared.clock.receipt[0] ^= 1,
                };
                record.prepared = Some(postcard::to_allocvec(&prepared).unwrap());
            }
            7 => {
                let mut saved: Anchored<ClockObservation> =
                    postcard::from_bytes(record.clock.as_ref().unwrap()).unwrap();
                saved.finality.finalized_block_number = 0;
                record.clock = Some(postcard::to_allocvec(&saved).unwrap());
            }
            _ => {
                let mut saved: Anchored<ReportObservation> =
                    postcard::from_bytes(record.reports.as_ref().unwrap()).unwrap();
                saved.value.epoch.round_id[9] ^= 1;
                record.reports = Some(postcard::to_allocvec(&saved).unwrap());
            }
        }
        let mut mock = Mock::new(&rig, &store, "bad-source");
        replace_source(&rig, &record);
        assert!(
            mock.run(RunMode::Fresh).is_err(),
            "source mutation {mutation}"
        );
        assert!(mock.calls.is_empty());
        assert!(!rig.path("bad-source").exists());
    }
}

pub(crate) fn setup_dispatcher_source(directory: &Path) {
    let rig = Rig::new(0);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(directory.join("dispatcher.source")).unwrap();
    use std::io::Write;
    file.write_all(&std::fs::read(rig.path("prepared.dpcint4")).unwrap())
        .unwrap();
    file.sync_all().unwrap();
}
fn process_emit(phase: &str, plan: &Plan, calls: &[Action]) {
    use std::io::Write;
    let message = serde_json::json!({"phase":phase,"calls":calls.iter().map(|c|format!("{c:?}")).collect::<Vec<_>>(),"pending_creates":usize::from(calls.contains(&Action::Broadcast)),"lookups":calls.iter().filter(|c|**c==Action::Lookup).count(),"broadcasts":calls.iter().filter(|c|**c==Action::Broadcast).count(),"plan_sha256":crate::hex0x(&sha256(&plan_bytes(plan).unwrap()))});
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "\nARCORA_BROADCAST_LOCK_IPC {message}").unwrap();
    stdout.flush().unwrap();
}
pub(crate) fn dispatcher_child(directory: &Path, role: &str) {
    struct Transport<'a> {
        mock: Mock<'a>,
        directory: &'a Path,
        hold: bool,
    }
    impl BroadcastTransport for Transport<'_> {
        fn recheck(
            &mut self,
            p: &Plan,
        ) -> Result<(Anchored<ClockObservation>, Anchored<ReportObservation>), ()> {
            self.mock.recheck(p)
        }
        fn broadcast(&mut self, p: &Plan) -> Result<(), ()> {
            self.mock.broadcast(p)?;
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            use std::io::Write;
            let mut file = options
                .open(self.directory.join("dispatcher.broadcast-marker"))
                .unwrap();
            file.write_all(b"1").unwrap();
            file.sync_all().unwrap();
            if self.hold {
                process_emit("READY", p, &self.mock.calls);
                let mut command = String::new();
                std::io::stdin().read_line(&mut command).unwrap();
                assert_eq!(command, "RELEASE\n");
            }
            Ok(())
        }
        fn lookup(&mut self, p: &Plan) -> Result<Lookup<OutcomeValue>, ()> {
            self.mock.lookup(p)
        }
    }
    let mut rig = Rig::new(0);
    // Keep hard-killed child scratch within the parent's owned cleanup scope.
    let scratch = directory.join(format!("dispatcher-scratch-{}", std::process::id()));
    std::fs::rename(&rig.dir.0, &scratch).unwrap();
    rig.dir.0 = scratch;
    rig.source = RecoveryStore::new(directory.join("dispatcher.source"), SOURCE_SEED);
    let store = BroadcastStore::new(directory.join("dispatcher.pending"), SEED).unwrap();
    let mut mock = Mock::new(&rig, &store, "unused");
    mock.path = directory.join("dispatcher.pending");
    let mut transport = Transport {
        mock,
        directory,
        hold: role == "hold",
    };
    let result = execute(
        &store,
        if role == "hold" {
            RunMode::Fresh
        } else {
            RunMode::Resume
        },
        &rig.source,
        &rig.request,
        &rig.trusted,
        &rig.bridge,
        [0xc1; 20],
        7,
        &mut transport,
    );
    match role {
        "hold" => {
            result.unwrap();
        }
        "contend" => {
            assert_eq!(result, Err(BroadcastError::Store(StoreError::Busy)));
            assert!(transport.mock.calls.is_empty());
            process_emit("BUSY", &transport.mock.expected, &transport.mock.calls);
        }
        "resume" => {
            assert_eq!(result.unwrap(), success(&transport.mock.expected));
            assert_eq!(transport.mock.calls, [Action::Lookup]);
            process_emit("OUTCOME", &transport.mock.expected, &transport.mock.calls);
        }
        _ => panic!("unknown owned child mode"),
    }
}

#[test]
fn broadcast_nested_postcard_allocation_lengths_and_revert_bounds_fail_closed() {
    let rig = Rig::new(0);
    let plan = rig.plan();
    let mut encoded = plan_bytes(&plan).unwrap();
    let vector = postcard::to_allocvec(&plan.calldata).unwrap();
    let start = encoded
        .windows(vector.len())
        .position(|w| w == vector)
        .unwrap();
    let prefix = vector.len() - plan.calldata.len();
    encoded.splice(start..start + prefix, [0xff, 0xff, 0xff, 0xff, 0x0f]);
    assert!(decode_plan(&encoded).is_err());
    let store = rig.store("nested-plan");
    store.try_lease().unwrap().create_pending(&encoded).unwrap();
    let mut mock = Mock::new(&rig, &store, "nested-plan");
    assert!(mock.run(RunMode::Resume).is_err());
    assert!(mock.calls.is_empty());
    let mut outcome = success(&plan);
    let revert = b"nested-revert-length-prefix".to_vec();
    outcome.value.status = OutcomeStatus::Reverted(revert.clone());
    let mut encoded = outcome_bytes(&outcome).unwrap();
    let vector = postcard::to_allocvec(&revert).unwrap();
    let start = encoded
        .windows(vector.len())
        .position(|w| w == vector)
        .unwrap();
    let prefix = vector.len() - revert.len();
    encoded.splice(start..start + prefix, [0xff, 0xff, 0xff, 0xff, 0x0f]);
    assert!(decode_outcome(&encoded).is_err());
    let store = rig.store("nested-outcome");
    let lease = store.try_lease().unwrap();
    let pending = lease.create_pending(&plan_bytes(&plan).unwrap()).unwrap();
    lease.finish(&pending, &encoded).unwrap();
    drop(lease);
    let mut mock = Mock::new(&rig, &store, "nested-outcome");
    assert!(mock.run(RunMode::Resume).is_err());
    assert!(mock.calls.is_empty());
    outcome.value.status = OutcomeStatus::Reverted(vec![1; MAX_REVERT_BYTES + 1]);
    assert!(validate_outcome(&plan, &outcome).is_err());
    let store = rig.store("oversize-revert");
    store
        .try_lease()
        .unwrap()
        .create_pending(&plan_bytes(&plan).unwrap())
        .unwrap();
    let mut mock = Mock::new(&rig, &store, "oversize-revert");
    mock.result = Some(Lookup::Finalized(outcome));
    assert!(mock.run(RunMode::Resume).is_err());
    assert_eq!(mock.calls, [Action::Lookup]);
}

//! Offline candidate protocol specification. Compiled only by gateway tests.
//! Every transport action is a caller-owned mock; this cannot activate a live
//! prover, clock registration, settlement route or candidate submission.
use crate::{
    candidate_intent::{IntentStage, IntentStore},
    candidate_registration::{registration, validate_epoch, Registration, UptimeEpoch},
    report_archive_binding::CandidateMaterial,
};
use chainlink_oracle::binding::{CandidateOutput, CandidateWitness};
use perp_core::clock::ClockContext;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

type Digest = [u8; 32];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ProgramIdentity {
    pub wire_magic: [u8; 8],
    pub sdk_release: String,
    pub elf_sha256: Digest,
    pub vkey: Digest,
}
impl ProgramIdentity {
    pub(crate) fn pinned() -> Self {
        Self {
            wire_magic: *chainlink_oracle::binding::WIRE_MAGIC,
            sdk_release: "6.1.0".into(),
            elf_sha256: crate::parse_hex32(
                "0x48a8eb8e6acd96057a72ca74db5077ac9e85d30d2ec830518ef1f1ac3832ef1f",
            )
            .unwrap(),
            vkey: crate::parse_hex32(
                "0x006aa3cfa389566dd318c9bf12f3946a623555e5f624359037e2d5c4d35ad590",
            )
            .unwrap(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct TargetIdentity {
    pub chain_id: u64,
    pub network: u8,
    pub clock_verifier: [u8; 20],
    pub settlement: [u8; 20],
    pub oracle_wrapper: [u8; 20],
    pub verifier_proxy: [u8; 20],
    pub policy_hash: Digest,
    pub clock_version: u8,
    pub uptime_feed: [u8; 20],
    pub grace_seconds: u64,
    pub settlement_code_hash: Digest,
    pub clock_code_hash: Digest,
    pub wrapper_code_hash: Digest,
    pub proxy_code_hash: Digest,
    pub uptime_code_hash: Digest,
}

/// Independently obtained status for this explicitly configured uptime feed.
/// The offline harness receives it from its caller; it performs no RPC read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct UptimeObservation {
    pub epoch: UptimeEpoch,
    pub ready: bool,
    pub observed_at_seconds: u64,
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct ProtocolRequest {
    pub program: ProgramIdentity,
    pub target: TargetIdentity,
    pub witness: Vec<u8>,
    pub material: CandidateMaterial,
    pub initial_uptime: UptimeObservation,
}

/// Pins supplied by the trusted archive extraction/configuration boundary.
/// A material checksum is not an independent proof of archive provenance.
#[derive(Clone)]
pub(crate) struct TrustedRequest {
    pub target: TargetIdentity,
    pub witness_sha256: Digest,
    pub material_hash: Digest,
    pub initial_uptime: UptimeObservation,
}
impl TrustedRequest {
    pub(crate) fn extracted(
        request: &ProtocolRequest,
        configured_target: TargetIdentity,
        initial_uptime: UptimeObservation,
    ) -> Self {
        Self {
            target: configured_target,
            witness_sha256: sha256(&request.witness),
            material_hash: request.material.material_hash,
            initial_uptime,
        }
    }
}
pub(crate) fn sha256(bytes: &[u8]) -> Digest {
    Sha256::digest(bytes).into()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ClockObservation {
    pub target: TargetIdentity,
    pub context: ClockContext,
    pub receipt: Digest,
    pub registration_block: u64,
    pub registration_block_hash: Digest,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ReportObservation {
    pub target: TargetIdentity,
    pub clock_commitment: Digest,
    pub input_hash: Digest,
    pub evidence_hash: Digest,
    pub epoch: UptimeEpoch,
    pub uptime_ready: bool,
    pub observed_at_seconds: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CandidateProofResponse {
    pub program: ProgramIdentity,
    pub public_values: Vec<u8>,
    /// Opaque mock proof bytes. This harness never authenticates an SP1 proof.
    pub proof: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PreparedCandidate {
    pub request_sha256: Digest,
    pub native: CandidateOutput,
    pub clock: ClockObservation,
    pub reports: ReportObservation,
    pub response: CandidateProofResponse,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Action {
    RegisterClock,
    ObserveClock,
    RegisterReports,
    ObserveReports,
    Prove,
    Recheck,
    Broadcast,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProtocolError {
    Version,
    Program,
    Target,
    Policy,
    Evidence,
    Capacity,
    Native,
    Uptime,
    Durability,
    Recovery,
    Observation,
    Response,
    Callback(Action),
}

pub(crate) trait OfflineTransport {
    fn register_clock(&mut self, clock: &ClockContext) -> Result<(), ()>;
    fn observe_clock(&mut self, clock: &ClockContext) -> Result<ClockObservation, ()>;
    fn register_reports(&mut self, registration: &Registration) -> Result<(), ()>;
    fn observe_reports(&mut self, registration: &Registration) -> Result<ReportObservation, ()>;
    fn prove(&mut self, request: &ProtocolRequest) -> Result<CandidateProofResponse, ()>;
    fn recheck(
        &mut self,
        prepared: &PreparedCandidate,
    ) -> Result<(ClockObservation, ReportObservation), ()>;
    fn broadcast(&mut self, prepared: &PreparedCandidate) -> Result<(), ()>;
}

pub(crate) struct Validated {
    clock: ClockContext,
    native: CandidateOutput,
    registration: Registration,
}
impl Validated {
    pub(crate) fn clock(&self) -> &ClockContext {
        &self.clock
    }
    pub(crate) fn native(&self) -> CandidateOutput {
        self.native
    }
    pub(crate) fn registration(&self) -> &Registration {
        &self.registration
    }
}
pub(crate) fn validate(
    request: &ProtocolRequest,
    trusted: &TrustedRequest,
) -> Result<Validated, ProtocolError> {
    if request.program.wire_magic != *chainlink_oracle::binding::WIRE_MAGIC
        || !request
            .witness
            .starts_with(chainlink_oracle::binding::WIRE_MAGIC)
    {
        return Err(ProtocolError::Version);
    }
    if request.program != ProgramIdentity::pinned() {
        return Err(ProtocolError::Program);
    }
    if request.target != trusted.target
        || !matches!(
            (request.target.chain_id, request.target.network),
            (84532, 0) | (8453, 1)
        )
        || request.target.clock_version != 2
        || request.target.uptime_feed == [0; 20]
        || request.target.grace_seconds == 0
        || request.target.clock_verifier == [0; 20]
        || request.target.settlement == [0; 20]
        || request.target.oracle_wrapper == [0; 20]
        || request.target.verifier_proxy == [0; 20]
        || [
            request.target.settlement_code_hash,
            request.target.clock_code_hash,
            request.target.wrapper_code_hash,
            request.target.proxy_code_hash,
            request.target.uptime_code_hash,
        ]
        .contains(&[0; 32])
    {
        return Err(ProtocolError::Target);
    }
    if request.witness.len() > chainlink_oracle::binding::MAX_WITNESS_BYTES
        || request.material.entries.len() > chainlink_oracle::binding::MAX_ENTRIES
    {
        return Err(ProtocolError::Capacity);
    }
    let (witness, tail): (CandidateWitness, _) =
        postcard::take_from_bytes(&request.witness[8..]).map_err(|_| ProtocolError::Version)?;
    if !tail.is_empty() {
        return Err(ProtocolError::Version);
    }
    if postcard::to_allocvec(&witness)
        .map_err(|_| ProtocolError::Version)?
        .as_slice()
        != &request.witness[8..]
    {
        return Err(ProtocolError::Version);
    }
    let clock = witness.clock.3;
    if request.initial_uptime != trusted.initial_uptime {
        return Err(ProtocolError::Uptime);
    }
    if clock.timed_ops == 0 {
        if request.initial_uptime
            != (UptimeObservation {
                epoch: UptimeEpoch {
                    round_id: [0; 10],
                    started_at: 0,
                },
                ready: false,
                observed_at_seconds: 0,
            })
        {
            return Err(ProtocolError::Uptime);
        }
    } else if !request.initial_uptime.ready
        || validate_epoch(
            request.initial_uptime.epoch,
            request.initial_uptime.observed_at_seconds,
            request.target.grace_seconds,
            Some(clock.first_ms),
        )
        .is_err()
    {
        return Err(ProtocolError::Uptime);
    }
    if witness.policy != request.material.policy
        || witness.policy.hash().map_err(|_| ProtocolError::Policy)? != request.target.policy_hash
        || witness.policy.chain_id != request.target.chain_id
        || witness.policy.network != request.target.network
        || witness.policy.oracle_wrapper != request.target.oracle_wrapper
        || witness.policy.verifier_proxy != request.target.verifier_proxy
        || request.material.policy_binding
            != chainlink_streams_client::report_pair::policy_binding(&witness.policy)
                .map_err(|_| ProtocolError::Policy)?
    {
        return Err(ProtocolError::Policy);
    }
    if clock.chain_id != request.target.chain_id
        || clock.verifier != request.target.clock_verifier
        || clock.settlement != request.target.settlement
    {
        return Err(ProtocolError::Target);
    }
    if request.material.material_hash != trusted.material_hash
        || request
            .material
            .recomputed_hash()
            .map_err(|_| ProtocolError::Evidence)?
            != trusted.material_hash
        || sha256(&request.witness) != trusted.witness_sha256
        || postcard::to_allocvec(&witness.evidence).map_err(|_| ProtocolError::Evidence)?
            != postcard::to_allocvec(&request.material.evidence)
                .map_err(|_| ProtocolError::Evidence)?
        || request.material.refs.len() != witness.evidence.len()
        || request.material.entries.len() != witness.evidence.len()
    {
        return Err(ProtocolError::Evidence);
    }
    for (reference, evidence) in request.material.refs.iter().zip(&witness.evidence) {
        if (reference.market_id, reference.now_ms) != (evidence.market_id, evidence.now_ms) {
            return Err(ProtocolError::Evidence);
        }
    }
    let native = chainlink_oracle::binding::run_encoded(&request.witness)
        .map_err(|_| ProtocolError::Native)?;
    let registration = registration(&witness.policy, &clock, &request.material.entries)
        .map_err(|_| ProtocolError::Evidence)?;
    if registration.evidence_hash != native.evidence_hash {
        return Err(ProtocolError::Evidence);
    }
    Ok(Validated {
        clock,
        native,
        registration,
    })
}

pub(crate) fn valid_clock(
    request: &ProtocolRequest,
    clock: &ClockContext,
    observation: &ClockObservation,
) -> bool {
    observation.target == request.target
        && observation.context == *clock
        && observation.receipt == clock.receipt()
        && observation.registration_block != 0
        && observation.registration_block_hash != [0; 32]
}
pub(crate) fn valid_reports(
    request: &ProtocolRequest,
    valid: &Validated,
    observation: &ReportObservation,
) -> bool {
    observation.target == request.target
        && observation.clock_commitment == valid.native.clock_commitment
        && observation.input_hash == valid.registration.input_hash
        && observation.evidence_hash == valid.native.evidence_hash
        && (valid.clock.timed_ops == 0 || observation.uptime_ready)
        && observation.epoch == request.initial_uptime.epoch
        && observation.observed_at_seconds >= request.initial_uptime.observed_at_seconds
        && validate_epoch(
            observation.epoch,
            observation.observed_at_seconds,
            request.target.grace_seconds,
            (valid.clock.timed_ops != 0).then_some(valid.clock.first_ms),
        )
        .is_ok()
}
pub(crate) fn valid_response(
    request: &ProtocolRequest,
    native: CandidateOutput,
    response: &CandidateProofResponse,
) -> bool {
    response.program == request.program
        && response.public_values.len() == 32
        && response.public_values.as_slice() == native.commitment
        && !response.proof.is_empty()
        && response.proof.len() <= 1024 * 1024
}

/// One canonical Prepared decoder shared by both offline runners. Exposing the
/// validated plan does not let staged recovery weaken these response bindings.
pub(crate) fn decode_prepared(
    request: &ProtocolRequest,
    valid: &Validated,
    payload: &[u8],
) -> Result<PreparedCandidate, ProtocolError> {
    let request_bytes = postcard::to_allocvec(request).map_err(|_| ProtocolError::Capacity)?;
    let (prepared, rest): (PreparedCandidate, _) =
        postcard::take_from_bytes(payload).map_err(|_| ProtocolError::Recovery)?;
    if !rest.is_empty()
        || postcard::to_allocvec(&prepared).map_err(|_| ProtocolError::Recovery)? != payload
        || prepared.request_sha256 != sha256(&request_bytes)
        || prepared.native != valid.native
        || !valid_clock(request, &valid.clock, &prepared.clock)
        || !valid_reports(request, valid, &prepared.reports)
        || !valid_response(request, valid.native, &prepared.response)
    {
        return Err(ProtocolError::Recovery);
    }
    Ok(prepared)
}

pub(crate) fn valid_recheck(
    request: &ProtocolRequest,
    valid: &Validated,
    prepared: &PreparedCandidate,
    clock: &ClockObservation,
    reports: &ReportObservation,
) -> bool {
    clock == &prepared.clock
        && valid_reports(request, valid, reports)
        && reports.target == prepared.reports.target
        && reports.clock_commitment == prepared.reports.clock_commitment
        && reports.input_hash == prepared.reports.input_hash
        && reports.evidence_hash == prepared.reports.evidence_hash
        && reports.epoch == prepared.reports.epoch
        && reports.observed_at_seconds >= prepared.reports.observed_at_seconds
}

/// Persist immutable intent before any mock registration. Every later failure
/// preserves earlier completed mock calls and prevents subsequent actions.
pub(crate) fn execute(
    request: &ProtocolRequest,
    trusted: &TrustedRequest,
    store: &IntentStore,
    transport: &mut impl OfflineTransport,
) -> Result<PreparedCandidate, ProtocolError> {
    let valid = validate(request, trusted)?;
    let bytes = postcard::to_allocvec(request).map_err(|_| ProtocolError::Capacity)?;
    let intent = store
        .save_intent(&bytes)
        .map_err(|_| ProtocolError::Durability)?;
    let prepared = if intent.stage == IntentStage::Prepared {
        let payload = intent.prepared.ok_or(ProtocolError::Recovery)?;
        decode_prepared(request, &valid, &payload)?
    } else {
        transport
            .register_clock(&valid.clock)
            .map_err(|_| ProtocolError::Callback(Action::RegisterClock))?;
        let clock = transport
            .observe_clock(&valid.clock)
            .map_err(|_| ProtocolError::Callback(Action::ObserveClock))?;
        if !valid_clock(request, &valid.clock, &clock) {
            return Err(ProtocolError::Observation);
        }
        transport
            .register_reports(&valid.registration)
            .map_err(|_| ProtocolError::Callback(Action::RegisterReports))?;
        let reports = transport
            .observe_reports(&valid.registration)
            .map_err(|_| ProtocolError::Callback(Action::ObserveReports))?;
        if !valid_reports(request, &valid, &reports) {
            return Err(ProtocolError::Observation);
        }
        let response = transport
            .prove(request)
            .map_err(|_| ProtocolError::Callback(Action::Prove))?;
        if !valid_response(request, valid.native, &response) {
            return Err(ProtocolError::Response);
        }
        let prepared = PreparedCandidate {
            request_sha256: sha256(&bytes),
            native: valid.native,
            clock,
            reports,
            response,
        };
        let payload = postcard::to_allocvec(&prepared).map_err(|_| ProtocolError::Capacity)?;
        store
            .save_prepared(&bytes, &payload)
            .map_err(|_| ProtocolError::Durability)?;
        prepared
    };
    let (clock, reports) = transport
        .recheck(&prepared)
        .map_err(|_| ProtocolError::Callback(Action::Recheck))?;
    // observed_at can advance on a later read, but the original epoch, record,
    // anchor block/receipt and all deployment identities must remain exact.
    if !valid_recheck(request, &valid, &prepared, &clock, &reports) {
        return Err(ProtocolError::Observation);
    }
    transport
        .broadcast(&prepared)
        .map_err(|_| ProtocolError::Callback(Action::Broadcast))?;
    Ok(prepared)
}

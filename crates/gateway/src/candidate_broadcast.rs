//! Offline broadcast recovery from an immutable, terminal DPCINT4 Prepared cut.
//! All actions, transaction identities and finality assertions are caller-owned
//! mocks. This cannot enable a live transport, authenticate a proof or establish
//! exactly-once chain delivery. The cooperative lease spans the entire invocation.
use crate::{
    candidate_broadcast_store::{BroadcastStore, StoreError, MAX_OUTCOME_BYTES, MAX_PLAN_BYTES},
    candidate_protocol::{
        decode_prepared, sha256, valid_clock, valid_recheck, valid_reports, validate,
        ClockObservation, PreparedCandidate, ProgramIdentity, ProtocolError, ProtocolRequest,
        ReportObservation, TargetIdentity, TrustedRequest, Validated,
    },
    candidate_recovery::{Anchored, FinalityContext, Lookup, LookupState},
    candidate_recovery_store::{
        Record as SourceRecord, RecoveryStore, Stage, MAX_OBSERVATION_BYTES, MAX_PREPARED_BYTES,
        MAX_REQUEST_BYTES,
    },
};
use chainlink_oracle::binding::{CandidateOutput, CandidateWitness};
use perp_core::{
    clock::{abi_u64, keccak},
    commitment::derive_roots,
    hash::{Digest, Keccak256},
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

const MAX_PROOF_BYTES: usize = 1024 * 1024;
pub(crate) const MAX_CALLDATA_BYTES: usize = 4 + 9 * 32 + 32 + MAX_PROOF_BYTES;
pub(crate) const MAX_REVERT_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RunMode {
    Fresh,
    Resume,
}

/// Additional explicitly configured observer pins absent from the old DTO.
/// These are not independently authenticated runtime identities.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct BridgeTarget {
    pub(crate) sp1_adapter: [u8; 20],
    pub(crate) sp1_gateway: [u8; 20],
    pub(crate) prefix_vault: [u8; 20],
    pub(crate) sp1_adapter_code_hash: Digest,
    pub(crate) sp1_gateway_code_hash: Digest,
    pub(crate) prefix_vault_code_hash: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Plan {
    pub(crate) source_cut_sha256: Digest,
    pub(crate) request_sha256: Digest,
    pub(crate) prepared_sha256: Digest,
    pub(crate) witness_sha256: Digest,
    pub(crate) target: TargetIdentity,
    pub(crate) bridge_target: BridgeTarget,
    pub(crate) program: ProgramIdentity,
    pub(crate) mock_sender: [u8; 20],
    pub(crate) mock_nonce: u64,
    pub(crate) batch_id: u64,
    pub(crate) phase: u8,
    /// prev, manifest, new, ordered, withdrawals, rejected, deposits.
    pub(crate) roots: [Digest; 7],
    pub(crate) consumed_deposit_count: u64,
    pub(crate) consumed_deposit_tip: Digest,
    pub(crate) native: CandidateOutput,
    pub(crate) public_values: Digest,
    #[serde(deserialize_with = "deserialize_calldata")]
    pub(crate) calldata: Vec<u8>,
    pub(crate) call_hash: Digest,
    pub(crate) clock: Anchored<ClockObservation>,
    pub(crate) reports: Anchored<ReportObservation>,
    /// Domain-separated offline identity, NOT a signed Ethereum transaction hash.
    pub(crate) mock_tx_id: Digest,
    pub(crate) attempt_id: Digest,
}

/// Exact effects of the fixed local mock-prefix settlement harness. Deposit
/// count/tip is a prefix-gate assertion, not stored settlement state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SettlementEffect {
    pub(crate) post_root: Digest,
    pub(crate) batch_count: u64,
    pub(crate) batch_id: u64,
    pub(crate) manifest_hash: Digest,
    pub(crate) ordered_root: Digest,
    pub(crate) rejected_root: Digest,
    pub(crate) settled_at_block: u64,
    pub(crate) withdrawal_root: Digest,
    pub(crate) withdrawal_epoch: u64,
    pub(crate) publication_count: u64,
    pub(crate) consumed_deposit_count: u64,
    pub(crate) consumed_deposit_tip: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum OutcomeStatus {
    Success(Box<SettlementEffect>),
    /// A finalized mock receipt with revert status. No global rollback claim.
    Reverted(#[serde(deserialize_with = "deserialize_revert")] Vec<u8>),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct OutcomeValue {
    pub(crate) attempt_id: Digest,
    pub(crate) mock_tx_id: Digest,
    pub(crate) plan_hash: Digest,
    pub(crate) target: TargetIdentity,
    pub(crate) call_hash: Digest,
    pub(crate) public_values: Digest,
    pub(crate) status: OutcomeStatus,
}
pub(crate) type Outcome = Anchored<OutcomeValue>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Action {
    Recheck,
    Broadcast,
    Lookup,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BroadcastError {
    Store(StoreError),
    Protocol(ProtocolError),
    MissingSource,
    SourceStage,
    SourceMismatch,
    Bounds,
    Malformed,
    Target,
    Phase,
    Native,
    PlanMismatch,
    Observation,
    AnchorMismatch,
    Finality,
    Outcome,
    Hold(LookupState),
    Callback(Action),
}

pub(crate) trait BroadcastTransport {
    fn recheck(
        &mut self,
        plan: &Plan,
    ) -> Result<(Anchored<ClockObservation>, Anchored<ReportObservation>), ()>;
    fn broadcast(&mut self, plan: &Plan) -> Result<(), ()>;
    fn lookup(&mut self, plan: &Plan) -> Result<Lookup<OutcomeValue>, ()>;
}

fn encode<T: Serialize>(value: &T, bound: usize) -> Result<Vec<u8>, BroadcastError> {
    let bytes = postcard::to_allocvec(value).map_err(|_| BroadcastError::Malformed)?;
    if bytes.is_empty() || bytes.len() > bound {
        return Err(BroadcastError::Bounds);
    }
    Ok(bytes)
}
fn decode<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
    bound: usize,
) -> Result<T, BroadcastError> {
    if bytes.is_empty() || bytes.len() > bound {
        return Err(BroadcastError::Bounds);
    }
    let (value, tail) = postcard::take_from_bytes(bytes).map_err(|_| BroadcastError::Malformed)?;
    if !tail.is_empty() || encode(&value, bound)? != bytes {
        return Err(BroadcastError::Malformed);
    }
    Ok(value)
}

fn bounded_vec<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
    bound: usize,
) -> Result<Vec<u8>, D::Error> {
    struct Visitor(usize);
    impl<'de> serde::de::Visitor<'de> for Visitor {
        type Value = Vec<u8>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(formatter, "a byte sequence of at most {} bytes", self.0)
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<u8>, A::Error> {
            let hint = seq.size_hint().unwrap_or(0);
            if hint > self.0 {
                return Err(serde::de::Error::custom("byte sequence exceeds bound"));
            }
            let mut value = Vec::with_capacity(hint);
            while let Some(byte) = seq.next_element()? {
                if value.len() == self.0 {
                    return Err(serde::de::Error::custom("byte sequence exceeds bound"));
                }
                value.push(byte);
            }
            Ok(value)
        }
    }
    deserializer.deserialize_seq(Visitor(bound))
}
fn deserialize_calldata<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<u8>, D::Error> {
    bounded_vec(deserializer, MAX_CALLDATA_BYTES)
}
fn deserialize_revert<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<u8>, D::Error> {
    bounded_vec(deserializer, MAX_REVERT_BYTES)
}

fn domain_hash<T: Serialize>(domain: &[u8], value: &T) -> Result<Digest, BroadcastError> {
    let bytes = encode(value, MAX_PLAN_BYTES)?;
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(bytes);
    Ok(hash.finalize().into())
}

/// Hash the exact canonical logical cut without allocating its 40 MiB frame or
/// depending on the random sealing nonce. Only terminal Prepared is accepted.
pub(crate) fn source_cut_hash(source: &SourceRecord) -> Result<Digest, BroadcastError> {
    if source.stage != Stage::Prepared {
        return Err(BroadcastError::SourceStage);
    }
    let fields = [
        (&source.request[..], MAX_REQUEST_BYTES),
        (
            source.clock.as_deref().ok_or(BroadcastError::SourceStage)?,
            MAX_OBSERVATION_BYTES,
        ),
        (
            source
                .reports
                .as_deref()
                .ok_or(BroadcastError::SourceStage)?,
            MAX_OBSERVATION_BYTES,
        ),
        (
            source
                .prepared
                .as_deref()
                .ok_or(BroadcastError::SourceStage)?,
            MAX_PREPARED_BYTES,
        ),
    ];
    let mut hash = Sha256::new();
    hash.update(b"arcora:offline-prepared-cut:v1\0");
    for (bytes, bound) in fields {
        if bytes.is_empty() || bytes.len() > bound {
            return Err(BroadcastError::Bounds);
        }
        hash.update((bytes.len() as u64).to_le_bytes());
        hash.update(bytes);
    }
    Ok(hash.finalize().into())
}

#[derive(Default)]
struct Watermark(Option<(u64, Digest)>);
impl Watermark {
    fn observe(&mut self, context: &FinalityContext) -> Result<(), BroadcastError> {
        if let Some((height, hash)) = self.0 {
            if context.finalized_block_number < height
                || (context.finalized_block_number == height
                    && context.finalized_block_hash != hash)
            {
                return Err(BroadcastError::Finality);
            }
        }
        self.0 = Some((context.finalized_block_number, context.finalized_block_hash));
        Ok(())
    }
}
fn valid_anchor<T>(observation: &Anchored<T>) -> Result<(), BroadcastError> {
    let anchor = &observation.anchor;
    let finality = &observation.finality;
    if anchor.block_number == 0
        || anchor.block_hash == [0; 32]
        || anchor.tx_hash == [0; 32]
        || finality.finalized_block_hash == [0; 32]
        || finality.canonical_block_hash != anchor.block_hash
        || finality.finalized_block_number < anchor.block_number
        || (finality.finalized_block_number == anchor.block_number
            && finality.finalized_block_hash != anchor.block_hash)
    {
        return Err(BroadcastError::Finality);
    }
    Ok(())
}
fn valid_clock_anchor(
    request: &ProtocolRequest,
    valid: &Validated,
    clock: &Anchored<ClockObservation>,
) -> Result<(), BroadcastError> {
    valid_anchor(clock)?;
    if !valid_clock(request, valid.clock(), &clock.value) {
        return Err(BroadcastError::Observation);
    }
    if clock.value.registration_block != clock.anchor.block_number
        || clock.value.registration_block_hash != clock.anchor.block_hash
    {
        return Err(BroadcastError::AnchorMismatch);
    }
    Ok(())
}
fn valid_report_anchor(
    request: &ProtocolRequest,
    valid: &Validated,
    clock: &Anchored<ClockObservation>,
    reports: &Anchored<ReportObservation>,
) -> Result<(), BroadcastError> {
    valid_anchor(reports)?;
    if !valid_reports(request, valid, &reports.value) {
        return Err(BroadcastError::Observation);
    }
    if reports.anchor.block_number < clock.anchor.block_number
        || (reports.anchor.block_number == clock.anchor.block_number
            && reports.anchor.block_hash != clock.anchor.block_hash)
    {
        return Err(BroadcastError::AnchorMismatch);
    }
    Ok(())
}

struct PreparedSource {
    valid: Validated,
    prepared: PreparedCandidate,
    clock: Anchored<ClockObservation>,
    reports: Anchored<ReportObservation>,
}
fn source_prepared(
    source: &SourceRecord,
    request: &ProtocolRequest,
    trusted: &TrustedRequest,
) -> Result<PreparedSource, BroadcastError> {
    source_cut_hash(source)?;
    // Bound externally supplied vectors before canonical serialization.
    if request.witness.len() > chainlink_oracle::binding::MAX_WITNESS_BYTES
        || request.material.entries.len() > chainlink_oracle::binding::MAX_ENTRIES
        || request.material.refs.len() > chainlink_oracle::binding::MAX_ENTRIES
        || request.material.evidence.len() > chainlink_oracle::binding::MAX_ENTRIES
        || request.material.entries.iter().any(|entry| {
            entry.base_report.len() > chainlink_oracle::report::MAX_FULL_REPORT
                || entry.quote_report.len() > chainlink_oracle::report::MAX_FULL_REPORT
        })
    {
        return Err(BroadcastError::Bounds);
    }
    if encode(request, MAX_REQUEST_BYTES)? != source.request {
        return Err(BroadcastError::SourceMismatch);
    }
    let valid = validate(request, trusted).map_err(BroadcastError::Protocol)?;
    let clock: Anchored<ClockObservation> = decode(
        source.clock.as_deref().ok_or(BroadcastError::SourceStage)?,
        MAX_OBSERVATION_BYTES,
    )?;
    let reports: Anchored<ReportObservation> = decode(
        source
            .reports
            .as_deref()
            .ok_or(BroadcastError::SourceStage)?,
        MAX_OBSERVATION_BYTES,
    )?;
    valid_clock_anchor(request, &valid, &clock)?;
    valid_report_anchor(request, &valid, &clock, &reports)?;
    let mut watermark = Watermark::default();
    watermark.observe(&clock.finality)?;
    watermark.observe(&reports.finality)?;
    let prepared = decode_prepared(
        request,
        &valid,
        source
            .prepared
            .as_deref()
            .ok_or(BroadcastError::SourceStage)?,
    )
    .map_err(BroadcastError::Protocol)?;
    if prepared.clock != clock.value || prepared.reports != reports.value {
        return Err(BroadcastError::Observation);
    }
    Ok(PreparedSource {
        valid,
        prepared,
        clock,
        reports,
    })
}

pub(crate) fn settlement_calldata(
    roots: &[Digest; 7],
    count: u64,
    proof: &[u8],
) -> Result<Vec<u8>, BroadcastError> {
    if proof.is_empty() || proof.len() > MAX_PROOF_BYTES {
        return Err(BroadcastError::Bounds);
    }
    let padded = proof.len().checked_add(31).ok_or(BroadcastError::Bounds)? / 32 * 32;
    let size = 4 + 9 * 32 + 32 + padded;
    if size > MAX_CALLDATA_BYTES {
        return Err(BroadcastError::Bounds);
    }
    let selector = keccak(
        b"settleBatch(bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,uint64,bytes)",
    );
    let mut bytes = Vec::with_capacity(size);
    bytes.extend_from_slice(&selector[..4]);
    for root in roots {
        bytes.extend_from_slice(root);
    }
    bytes.extend_from_slice(&abi_u64(count));
    bytes.extend_from_slice(&abi_u64(9 * 32));
    bytes.extend_from_slice(&abi_u64(proof.len() as u64));
    bytes.extend_from_slice(proof);
    bytes.resize(size, 0);
    Ok(bytes)
}

fn valid_bridge(target: &TargetIdentity, bridge: &BridgeTarget) -> Result<(), BroadcastError> {
    let addresses = [
        target.clock_verifier,
        target.settlement,
        target.oracle_wrapper,
        target.verifier_proxy,
        target.uptime_feed,
        bridge.sp1_adapter,
        bridge.sp1_gateway,
        bridge.prefix_vault,
    ];
    if addresses.contains(&[0; 20])
        || addresses
            .iter()
            .enumerate()
            .any(|(i, address)| addresses[..i].contains(address))
        || [
            bridge.sp1_adapter_code_hash,
            bridge.sp1_gateway_code_hash,
            bridge.prefix_vault_code_hash,
        ]
        .contains(&[0; 32])
    {
        return Err(BroadcastError::Target);
    }
    Ok(())
}

fn mock_tx_id(plan: &Plan) -> Result<Digest, BroadcastError> {
    domain_hash(
        b"arcora:offline-mock-transaction:v1\0",
        &(
            plan.target.chain_id,
            plan.mock_sender,
            plan.mock_nonce,
            plan.target.settlement,
            plan.call_hash,
        ),
    )
}
fn attempt_id(plan: &Plan) -> Result<Digest, BroadcastError> {
    let mut unsigned = plan.clone();
    unsigned.attempt_id = [0; 32];
    domain_hash(b"arcora:offline-broadcast-attempt:v1\0", &unsigned)
}
pub(crate) fn plan_bytes(plan: &Plan) -> Result<Vec<u8>, BroadcastError> {
    encode(plan, MAX_PLAN_BYTES)
}
pub(crate) fn plan_hash(plan: &Plan) -> Result<Digest, BroadcastError> {
    domain_hash(b"arcora:offline-broadcast-plan:v1\0", plan)
}
pub(crate) fn decode_plan(bytes: &[u8]) -> Result<Plan, BroadcastError> {
    decode(bytes, MAX_PLAN_BYTES)
}
pub(crate) fn outcome_bytes(outcome: &Outcome) -> Result<Vec<u8>, BroadcastError> {
    encode(outcome, MAX_OUTCOME_BYTES)
}
pub(crate) fn decode_outcome(bytes: &[u8]) -> Result<Outcome, BroadcastError> {
    decode(bytes, MAX_OUTCOME_BYTES)
}

pub(crate) fn build_plan(
    source: &SourceRecord,
    request: &ProtocolRequest,
    trusted: &TrustedRequest,
    bridge_target: &BridgeTarget,
    mock_sender: [u8; 20],
    mock_nonce: u64,
) -> Result<Plan, BroadcastError> {
    let decoded = source_prepared(source, request, trusted)?;
    make_plan(
        source,
        request,
        bridge_target,
        mock_sender,
        mock_nonce,
        &decoded,
    )
}

fn make_plan(
    source: &SourceRecord,
    request: &ProtocolRequest,
    bridge_target: &BridgeTarget,
    mock_sender: [u8; 20],
    mock_nonce: u64,
    decoded: &PreparedSource,
) -> Result<Plan, BroadcastError> {
    let valid = &decoded.valid;
    let prepared = &decoded.prepared;
    valid_bridge(&request.target, bridge_target)?;
    if mock_sender == [0; 20] {
        return Err(BroadcastError::Target);
    }
    let witness: CandidateWitness = decode(
        &request.witness[8..],
        chainlink_oracle::binding::MAX_WITNESS_BYTES,
    )?;
    let mut post = witness.clock.0.clone();
    let derived = derive_roots(&mut post, &witness.clock.1, &witness.clock.2)
        .map_err(|_| BroadcastError::Native)?;
    if derived.wind_down_phase != 0 || valid.clock().phase != 0 {
        return Err(BroadcastError::Phase);
    }
    if derived.commitment::<Keccak256>() != valid.clock().base_commitment
        || derived.prev_state_root != valid.clock().previous_root
        || derived.deposits_root != post.consumed_deposit_tip
        || valid.clock().batch_id.checked_add(1).is_none()
    {
        return Err(BroadcastError::Native);
    }
    let roots = [
        derived.prev_state_root,
        derived.manifest_hash,
        derived.new_state_root,
        derived.ordered_root,
        derived.withdrawals_root,
        derived.rejected_root,
        derived.deposits_root,
    ];
    let calldata = settlement_calldata(
        &roots,
        post.consumed_deposit_count,
        &prepared.response.proof,
    )?;
    let public_values = prepared
        .response
        .public_values
        .as_slice()
        .try_into()
        .map_err(|_| BroadcastError::Malformed)?;
    let mut plan = Plan {
        source_cut_sha256: source_cut_hash(source)?,
        request_sha256: prepared.request_sha256,
        prepared_sha256: sha256(
            source
                .prepared
                .as_deref()
                .ok_or(BroadcastError::SourceStage)?,
        ),
        witness_sha256: sha256(&request.witness),
        target: request.target.clone(),
        bridge_target: bridge_target.clone(),
        program: request.program.clone(),
        mock_sender,
        mock_nonce,
        batch_id: valid.clock().batch_id,
        phase: derived.wind_down_phase,
        roots,
        consumed_deposit_count: post.consumed_deposit_count,
        consumed_deposit_tip: post.consumed_deposit_tip,
        native: valid.native(),
        public_values,
        call_hash: keccak(&calldata),
        calldata,
        clock: decoded.clock.clone(),
        reports: decoded.reports.clone(),
        mock_tx_id: [0; 32],
        attempt_id: [0; 32],
    };
    plan.mock_tx_id = mock_tx_id(&plan)?;
    plan.attempt_id = attempt_id(&plan)?;
    plan_bytes(&plan)?;
    Ok(plan)
}

pub(crate) fn validate_plan(
    plan: &Plan,
    source: &SourceRecord,
    request: &ProtocolRequest,
    trusted: &TrustedRequest,
    bridge_target: &BridgeTarget,
    mock_sender: [u8; 20],
    mock_nonce: u64,
) -> Result<(), BroadcastError> {
    if *plan
        != build_plan(
            source,
            request,
            trusted,
            bridge_target,
            mock_sender,
            mock_nonce,
        )?
    {
        return Err(BroadcastError::PlanMismatch);
    }
    Ok(())
}

fn source_watermark(plan: &Plan) -> Result<Watermark, BroadcastError> {
    valid_anchor(&plan.clock)?;
    valid_anchor(&plan.reports)?;
    let mut watermark = Watermark::default();
    watermark.observe(&plan.clock.finality)?;
    watermark.observe(&plan.reports.finality)?;
    Ok(watermark)
}
fn validate_outcome_with_watermark(
    plan: &Plan,
    outcome: &Outcome,
    watermark: &mut Watermark,
) -> Result<(), BroadcastError> {
    if plan.phase != 0
        || plan.mock_tx_id != mock_tx_id(plan)?
        || plan.attempt_id != attempt_id(plan)?
        || plan.call_hash != keccak(&plan.calldata)
        || plan.public_values != plan.native.commitment
    {
        return Err(BroadcastError::PlanMismatch);
    }
    valid_anchor(outcome)?;
    let value = &outcome.value;
    if value.attempt_id != plan.attempt_id
        || value.mock_tx_id != plan.mock_tx_id
        || outcome.anchor.tx_hash != plan.mock_tx_id
        || value.plan_hash != plan_hash(plan)?
        || value.target != plan.target
        || value.call_hash != plan.call_hash
        || value.public_values != plan.public_values
    {
        return Err(BroadcastError::Outcome);
    }
    if outcome.anchor.block_number < plan.reports.anchor.block_number
        || (outcome.anchor.block_number == plan.reports.anchor.block_number
            && outcome.anchor.block_hash != plan.reports.anchor.block_hash)
    {
        return Err(BroadcastError::AnchorMismatch);
    }
    watermark.observe(&outcome.finality)?;
    match &value.status {
        OutcomeStatus::Success(effect) => {
            if effect.post_root != plan.roots[2]
                || Some(effect.batch_count) != plan.batch_id.checked_add(1)
                || effect.batch_id != plan.batch_id
                || effect.manifest_hash != plan.roots[1]
                || effect.ordered_root != plan.roots[3]
                || effect.rejected_root != plan.roots[5]
                || effect.settled_at_block != outcome.anchor.block_number
                || effect.withdrawal_root != plan.roots[4]
                || effect.withdrawal_epoch != plan.batch_id
                || effect.publication_count != 1
                || effect.consumed_deposit_count != plan.consumed_deposit_count
                || effect.consumed_deposit_tip != plan.consumed_deposit_tip
            {
                return Err(BroadcastError::Outcome);
            }
        }
        OutcomeStatus::Reverted(bytes) => {
            if bytes.len() > MAX_REVERT_BYTES {
                return Err(BroadcastError::Bounds);
            }
        }
    }
    Ok(())
}
/// Pure validation against original durable mock anchors. Fresh execution also
/// applies its later invocation-local preflight watermark. Neither is RPC proof.
pub(crate) fn validate_outcome(plan: &Plan, outcome: &Outcome) -> Result<(), BroadcastError> {
    validate_outcome_with_watermark(plan, outcome, &mut source_watermark(plan)?)
}

/// One owned attempt. Pending publication precedes broadcast; Resume performs
/// only lookup, and terminal Outcome returns without any transport callbacks.
#[allow(clippy::too_many_arguments)]
pub(crate) fn execute(
    store: &BroadcastStore,
    mode: RunMode,
    source_store: &RecoveryStore,
    request: &ProtocolRequest,
    trusted: &TrustedRequest,
    bridge_target: &BridgeTarget,
    mock_sender: [u8; 20],
    mock_nonce: u64,
    transport: &mut impl BroadcastTransport,
) -> Result<Outcome, BroadcastError> {
    let lease = store.try_lease().map_err(BroadcastError::Store)?;
    lease.check().map_err(BroadcastError::Store)?;
    let existing = lease.load().map_err(BroadcastError::Store)?;
    match (mode, &existing) {
        (RunMode::Fresh, Some(_)) => return Err(BroadcastError::Store(StoreError::Exists)),
        (RunMode::Resume, None) => return Err(BroadcastError::Store(StoreError::Missing)),
        _ => {}
    }
    let source = source_store
        .load()
        .map_err(|_| BroadcastError::SourceMismatch)?
        .ok_or(BroadcastError::MissingSource)?;
    let decoded = source_prepared(&source, request, trusted)?;
    let plan = make_plan(
        &source,
        request,
        bridge_target,
        mock_sender,
        mock_nonce,
        &decoded,
    )?;
    let expected_plan = plan_bytes(&plan)?;
    let mut watermark = source_watermark(&plan)?;
    let pending = if let Some(record) = existing {
        let saved = decode_plan(&record.plan)?;
        if saved != plan || record.plan != expected_plan {
            return Err(BroadcastError::PlanMismatch);
        }
        if let Some(bytes) = &record.outcome {
            let outcome = decode_outcome(bytes)?;
            validate_outcome(&plan, &outcome)?;
            lease.check().map_err(BroadcastError::Store)?;
            return Ok(outcome);
        }
        record
    } else {
        lease.check().map_err(BroadcastError::Store)?;
        let (clock, reports) = transport
            .recheck(&plan)
            .map_err(|_| BroadcastError::Callback(Action::Recheck))?;
        lease.check().map_err(BroadcastError::Store)?;
        valid_clock_anchor(request, &decoded.valid, &clock)?;
        valid_report_anchor(request, &decoded.valid, &clock, &reports)?;
        if clock.anchor != plan.clock.anchor
            || reports.anchor != plan.reports.anchor
            || !valid_recheck(
                request,
                &decoded.valid,
                &decoded.prepared,
                &clock.value,
                &reports.value,
            )
        {
            return Err(BroadcastError::Observation);
        }
        watermark.observe(&clock.finality)?;
        watermark.observe(&reports.finality)?;
        let pending = lease
            .create_pending(&expected_plan)
            .map_err(BroadcastError::Store)?;
        lease.check().map_err(BroadcastError::Store)?;
        transport
            .broadcast(&plan)
            .map_err(|_| BroadcastError::Callback(Action::Broadcast))?;
        pending
    };
    lease.check().map_err(BroadcastError::Store)?;
    let outcome = match transport
        .lookup(&plan)
        .map_err(|_| BroadcastError::Callback(Action::Lookup))?
    {
        Lookup::Finalized(outcome) => outcome,
        Lookup::Pending => return Err(BroadcastError::Hold(LookupState::Pending)),
        Lookup::Absent => return Err(BroadcastError::Hold(LookupState::Absent)),
        Lookup::Unknown => return Err(BroadcastError::Hold(LookupState::Unknown)),
        Lookup::Reorg => return Err(BroadcastError::Hold(LookupState::Reorg)),
    };
    lease.check().map_err(BroadcastError::Store)?;
    validate_outcome_with_watermark(&plan, &outcome, &mut watermark)?;
    lease
        .finish(&pending, &outcome_bytes(&outcome)?)
        .map_err(BroadcastError::Store)?;
    Ok(outcome)
}

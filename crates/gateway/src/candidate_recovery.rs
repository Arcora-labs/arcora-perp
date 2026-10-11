//! Test-only registration recovery specification. All observations and actions
//! come from caller-owned offline mocks; finality metadata is a consistency
//! assertion, not an RPC, consensus, transaction or SP1 proof.
//!
//! Pending markers precede ambiguous registration callbacks. Resume only looks
//! up their outcomes, and never turns an absent/unknown/reorg outcome into a new
//! registration. Prepared is durable before mock broadcast, whose transaction
//! outcome and exactly-once recovery remain outside this specification.
use crate::{
    candidate_protocol::{
        decode_prepared, sha256, valid_clock, valid_recheck, valid_reports, valid_response,
        validate, CandidateProofResponse, ClockObservation, PreparedCandidate, ProtocolError,
        ProtocolRequest, ReportObservation, TrustedRequest, Validated,
    },
    candidate_recovery_store::{Record, RecoveryStore, Stage, StoreError},
    candidate_registration::Registration,
};
use perp_core::clock::ClockContext;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

const MAX_REQUEST_BYTES: usize = 24 * 1024 * 1024;
const MAX_OBSERVATION_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RunMode {
    Fresh,
    Resume,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RegistrationAnchor {
    pub(crate) block_number: u64,
    pub(crate) block_hash: [u8; 32],
    pub(crate) tx_hash: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct FinalityContext {
    pub(crate) canonical_block_hash: [u8; 32],
    pub(crate) finalized_block_number: u64,
    pub(crate) finalized_block_hash: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Anchored<T> {
    pub(crate) value: T,
    pub(crate) anchor: RegistrationAnchor,
    pub(crate) finality: FinalityContext,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Lookup<T> {
    Finalized(Anchored<T>),
    Pending,
    Absent,
    Unknown,
    Reorg,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LookupState {
    Pending,
    Absent,
    Unknown,
    Reorg,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RecoveryAction {
    RegisterClock,
    LookupClock,
    RegisterReports,
    LookupReports,
    Prove,
    Broadcast,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RecoveryError {
    Protocol(ProtocolError),
    Durability,
    MissingResume,
    ExistingFresh,
    RequestMismatch,
    Malformed,
    Observation,
    Finality,
    AnchorMismatch,
    Hold(LookupState),
    Callback(RecoveryAction),
}

pub(crate) trait RecoveryTransport {
    fn register_clock(&mut self, clock: &ClockContext) -> Result<(), ()>;
    fn lookup_clock(&mut self, clock: &ClockContext) -> Result<Lookup<ClockObservation>, ()>;
    fn register_reports(&mut self, registration: &Registration) -> Result<(), ()>;
    fn lookup_reports(
        &mut self,
        registration: &Registration,
    ) -> Result<Lookup<ReportObservation>, ()>;
    fn prove(&mut self, request: &ProtocolRequest) -> Result<CandidateProofResponse, ()>;
    fn broadcast(&mut self, prepared: &PreparedCandidate) -> Result<(), ()>;
}

/// Registration preparation cannot call broadcast through this interface.
pub(crate) trait PreparationTransport {
    fn register_clock(&mut self, clock: &ClockContext) -> Result<(), ()>;
    fn lookup_clock(&mut self, clock: &ClockContext) -> Result<Lookup<ClockObservation>, ()>;
    fn register_reports(&mut self, registration: &Registration) -> Result<(), ()>;
    fn lookup_reports(
        &mut self,
        registration: &Registration,
    ) -> Result<Lookup<ReportObservation>, ()>;
    fn prove(&mut self, request: &ProtocolRequest) -> Result<CandidateProofResponse, ()>;
}

/// A coordinator can guard all acknowledged source cuts while retaining the
/// existing DPCINT4 bytes and compare-and-advance semantics. Implementations
/// return the exact checkpoint whose publication has been acknowledged.
pub(crate) trait PreparationCheckpointStore {
    fn load(&self) -> Result<Option<Record>, StoreError>;
    fn create(&self, request: &[u8]) -> Result<Record, StoreError>;
    fn advance(&self, expected: &Record, next: Record) -> Result<Record, StoreError>;
}
impl PreparationCheckpointStore for RecoveryStore {
    fn load(&self) -> Result<Option<Record>, StoreError> {
        RecoveryStore::load(self)
    }
    fn create(&self, request: &[u8]) -> Result<Record, StoreError> {
        RecoveryStore::create(self, request)
    }
    fn advance(&self, expected: &Record, next: Record) -> Result<Record, StoreError> {
        RecoveryStore::advance(self, expected, next)
    }
}

struct LegacyPreparation<'a, T>(&'a mut T);
impl<T: RecoveryTransport> PreparationTransport for LegacyPreparation<'_, T> {
    fn register_clock(&mut self, clock: &ClockContext) -> Result<(), ()> {
        self.0.register_clock(clock)
    }
    fn lookup_clock(&mut self, clock: &ClockContext) -> Result<Lookup<ClockObservation>, ()> {
        self.0.lookup_clock(clock)
    }
    fn register_reports(&mut self, registration: &Registration) -> Result<(), ()> {
        self.0.register_reports(registration)
    }
    fn lookup_reports(
        &mut self,
        registration: &Registration,
    ) -> Result<Lookup<ReportObservation>, ()> {
        self.0.lookup_reports(registration)
    }
    fn prove(&mut self, request: &ProtocolRequest) -> Result<CandidateProofResponse, ()> {
        self.0.prove(request)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PreparedCut {
    pub(crate) record: Record,
    pub(crate) prepared: PreparedCandidate,
}

/// Saved checkpoints establish the restart baseline. Later mock reads may
/// advance this invocation-local watermark, but never rewrite original saved
/// anchor/value bytes. No cross-restart tip history or ancestry is asserted.
#[derive(Default)]
struct Watermark(Option<(u64, [u8; 32])>);
impl Watermark {
    fn observe(&mut self, context: &FinalityContext) -> Result<(), RecoveryError> {
        if let Some((height, hash)) = self.0 {
            if context.finalized_block_number < height
                || (context.finalized_block_number == height
                    && context.finalized_block_hash != hash)
            {
                return Err(RecoveryError::Finality);
            }
        }
        self.0 = Some((context.finalized_block_number, context.finalized_block_hash));
        Ok(())
    }
}

struct Saved {
    clock: Option<Anchored<ClockObservation>>,
    reports: Option<Anchored<ReportObservation>>,
    prepared: Option<PreparedCandidate>,
    watermark: Watermark,
}

/// The historical tail must receive this same Saved watermark. Decoding its
/// original checkpoint again would lose advances observed during this run.
struct PreparedProgress {
    record: Record,
    valid: Validated,
    saved: Saved,
}

fn valid_anchor<T>(observation: &Anchored<T>) -> Result<(), RecoveryError> {
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
        return Err(RecoveryError::Finality);
    }
    Ok(())
}

fn valid_anchored_clock(
    request: &ProtocolRequest,
    valid: &Validated,
    clock: &Anchored<ClockObservation>,
) -> Result<(), RecoveryError> {
    valid_anchor(clock)?;
    if !valid_clock(request, valid.clock(), &clock.value) {
        return Err(RecoveryError::Observation);
    }
    if clock.value.registration_block != clock.anchor.block_number
        || clock.value.registration_block_hash != clock.anchor.block_hash
    {
        return Err(RecoveryError::AnchorMismatch);
    }
    Ok(())
}

fn valid_anchored_reports(
    request: &ProtocolRequest,
    valid: &Validated,
    clock: &Anchored<ClockObservation>,
    reports: &Anchored<ReportObservation>,
) -> Result<(), RecoveryError> {
    valid_anchor(reports)?;
    if !valid_reports(request, valid, &reports.value) {
        return Err(RecoveryError::Observation);
    }
    if reports.anchor.block_number < clock.anchor.block_number
        || (reports.anchor.block_number == clock.anchor.block_number
            && reports.anchor.block_hash != clock.anchor.block_hash)
    {
        return Err(RecoveryError::AnchorMismatch);
    }
    Ok(())
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, RecoveryError> {
    postcard::to_allocvec(value).map_err(|_| RecoveryError::Malformed)
}

pub(crate) fn request_bytes(request: &ProtocolRequest) -> Result<Vec<u8>, RecoveryError> {
    let bytes = encode(request)?;
    if bytes.is_empty() || bytes.len() > MAX_REQUEST_BYTES {
        return Err(RecoveryError::Protocol(ProtocolError::Capacity));
    }
    Ok(bytes)
}

fn decode_observation<T: DeserializeOwned + Serialize>(bytes: &[u8]) -> Result<T, RecoveryError> {
    if bytes.is_empty() || bytes.len() > MAX_OBSERVATION_BYTES {
        return Err(RecoveryError::Malformed);
    }
    let (value, tail): (T, _) =
        postcard::take_from_bytes(bytes).map_err(|_| RecoveryError::Malformed)?;
    if !tail.is_empty() || encode(&value)? != bytes {
        return Err(RecoveryError::Malformed);
    }
    Ok(value)
}

/// Validate every saved payload before any lookup or registration callback.
fn saved(
    record: &Record,
    request: &ProtocolRequest,
    valid: &Validated,
) -> Result<Saved, RecoveryError> {
    let shape = match record.stage {
        Stage::Intent | Stage::ClockPending => (false, false, false),
        Stage::ClockObserved | Stage::ReportsPending => (true, false, false),
        Stage::ReportsObserved => (true, true, false),
        Stage::Prepared => (true, true, true),
    };
    if shape
        != (
            record.clock.is_some(),
            record.reports.is_some(),
            record.prepared.is_some(),
        )
    {
        return Err(RecoveryError::Malformed);
    }
    let clock: Option<Anchored<ClockObservation>> = record
        .clock
        .as_deref()
        .map(decode_observation)
        .transpose()?;
    let reports: Option<Anchored<ReportObservation>> = record
        .reports
        .as_deref()
        .map(decode_observation)
        .transpose()?;
    let mut watermark = Watermark::default();
    if let Some(clock) = &clock {
        valid_anchored_clock(request, valid, clock)?;
        watermark.observe(&clock.finality)?;
    }
    if let Some(reports) = &reports {
        let clock = clock.as_ref().ok_or(RecoveryError::Malformed)?;
        valid_anchored_reports(request, valid, clock, reports)?;
        watermark.observe(&reports.finality)?;
    }
    let prepared = record
        .prepared
        .as_deref()
        .map(|bytes| decode_prepared(request, valid, bytes).map_err(RecoveryError::Protocol))
        .transpose()?;
    if let Some(prepared) = &prepared {
        if clock.as_ref().map(|o| &o.value) != Some(&prepared.clock)
            || reports.as_ref().map(|o| &o.value) != Some(&prepared.reports)
        {
            return Err(RecoveryError::Observation);
        }
    }
    Ok(Saved {
        clock,
        reports,
        prepared,
        watermark,
    })
}

/// Pure semantic validation for explicit adoption and guarded source reads.
/// Authentication and framing remain the responsibility of the checkpoint
/// store. No lookup, registration, proof or timestamp refresh occurs here.
pub(crate) fn validate_stored_cut(
    record: &Record,
    request: &ProtocolRequest,
    trusted: &TrustedRequest,
) -> Result<(), RecoveryError> {
    let valid = validate(request, trusted).map_err(RecoveryError::Protocol)?;
    if record.request != request_bytes(request)? {
        return Err(RecoveryError::RequestMismatch);
    }
    saved(record, request, &valid)?;
    Ok(())
}

fn finalized<T>(lookup: Lookup<T>) -> Result<Anchored<T>, RecoveryError> {
    match lookup {
        Lookup::Finalized(observation) => Ok(observation),
        Lookup::Pending => Err(RecoveryError::Hold(LookupState::Pending)),
        Lookup::Absent => Err(RecoveryError::Hold(LookupState::Absent)),
        Lookup::Unknown => Err(RecoveryError::Hold(LookupState::Unknown)),
        Lookup::Reorg => Err(RecoveryError::Hold(LookupState::Reorg)),
    }
}

fn lookup_clock(
    request: &ProtocolRequest,
    valid: &Validated,
    transport: &mut impl PreparationTransport,
) -> Result<Anchored<ClockObservation>, RecoveryError> {
    let clock = finalized(
        transport
            .lookup_clock(valid.clock())
            .map_err(|_| RecoveryError::Callback(RecoveryAction::LookupClock))?,
    )?;
    valid_anchored_clock(request, valid, &clock)?;
    Ok(clock)
}

fn lookup_reports(
    request: &ProtocolRequest,
    valid: &Validated,
    clock: &Anchored<ClockObservation>,
    transport: &mut impl PreparationTransport,
) -> Result<Anchored<ReportObservation>, RecoveryError> {
    let reports = finalized(
        transport
            .lookup_reports(valid.registration())
            .map_err(|_| RecoveryError::Callback(RecoveryAction::LookupReports))?,
    )?;
    valid_anchored_reports(request, valid, clock, &reports)?;
    Ok(reports)
}

fn reconcile_clock(
    request: &ProtocolRequest,
    valid: &Validated,
    original: &Anchored<ClockObservation>,
    watermark: &mut Watermark,
    transport: &mut impl PreparationTransport,
) -> Result<Anchored<ClockObservation>, RecoveryError> {
    let current = lookup_clock(request, valid, transport)?;
    if current.anchor != original.anchor {
        return Err(RecoveryError::AnchorMismatch);
    }
    if current.value != original.value {
        return Err(RecoveryError::Observation);
    }
    watermark.observe(&current.finality)?;
    Ok(current)
}

fn same_report_record(original: &ReportObservation, current: &ReportObservation) -> bool {
    current.target == original.target
        && current.clock_commitment == original.clock_commitment
        && current.input_hash == original.input_hash
        && current.evidence_hash == original.evidence_hash
        && current.epoch == original.epoch
        && current.observed_at_seconds >= original.observed_at_seconds
}

fn reconcile_reports(
    request: &ProtocolRequest,
    valid: &Validated,
    clock: &Anchored<ClockObservation>,
    original: &Anchored<ReportObservation>,
    watermark: &mut Watermark,
    transport: &mut impl PreparationTransport,
) -> Result<Anchored<ReportObservation>, RecoveryError> {
    let current = lookup_reports(request, valid, clock, transport)?;
    if current.anchor != original.anchor {
        return Err(RecoveryError::AnchorMismatch);
    }
    if !same_report_record(&original.value, &current.value) {
        return Err(RecoveryError::Observation);
    }
    watermark.observe(&current.finality)?;
    Ok(current)
}

fn advance(
    store: &impl PreparationCheckpointStore,
    record: &mut Record,
    next: Record,
) -> Result<(), RecoveryError> {
    // Any failure, including ambiguous post-rename durability, ends this run
    // before its next callback. Resume must reload and reconcile the disk cut.
    *record = store
        .advance(record, next)
        .map_err(|_| RecoveryError::Durability)?;
    Ok(())
}

fn drive_prepared(
    mode: RunMode,
    request: &ProtocolRequest,
    trusted: &TrustedRequest,
    store: &impl PreparationCheckpointStore,
    transport: &mut impl PreparationTransport,
) -> Result<PreparedProgress, RecoveryError> {
    let valid = validate(request, trusted).map_err(RecoveryError::Protocol)?;
    let request_bytes = request_bytes(request)?;
    let mut record = match mode {
        RunMode::Fresh => store.create(&request_bytes).map_err(|error| match error {
            StoreError::Exists => RecoveryError::ExistingFresh,
            _ => RecoveryError::Durability,
        })?,
        RunMode::Resume => store
            .load()
            .map_err(|_| RecoveryError::Durability)?
            .ok_or(RecoveryError::MissingResume)?,
    };
    if record.request != request_bytes {
        return Err(RecoveryError::RequestMismatch);
    }
    let mut saved = saved(&record, request, &valid)?;

    if record.stage == Stage::Intent {
        let mut next = record.clone();
        next.stage = Stage::ClockPending;
        advance(store, &mut record, next)?;
        if mode == RunMode::Fresh {
            transport
                .register_clock(valid.clock())
                .map_err(|_| RecoveryError::Callback(RecoveryAction::RegisterClock))?;
        }
    }
    if record.stage == Stage::ClockPending {
        let clock = lookup_clock(request, &valid, transport)?;
        saved.watermark.observe(&clock.finality)?;
        let mut next = record.clone();
        next.stage = Stage::ClockObserved;
        next.clock = Some(encode(&clock)?);
        advance(store, &mut record, next)?;
        saved.clock = Some(clock);
    }
    let reconciled_clock = if record.stage == Stage::ClockObserved {
        let original_clock = saved.clock.as_ref().ok_or(RecoveryError::Malformed)?;
        let current_clock = reconcile_clock(
            request,
            &valid,
            original_clock,
            &mut saved.watermark,
            transport,
        )?;
        let mut next = record.clone();
        next.stage = Stage::ReportsPending;
        advance(store, &mut record, next)?;
        Some(current_clock)
    } else {
        None
    };
    if record.stage == Stage::ReportsPending {
        let original_clock = saved.clock.as_ref().ok_or(RecoveryError::Malformed)?;
        let current_clock = match reconciled_clock {
            Some(clock) => clock,
            None => reconcile_clock(
                request,
                &valid,
                original_clock,
                &mut saved.watermark,
                transport,
            )?,
        };
        if mode == RunMode::Fresh {
            transport
                .register_reports(valid.registration())
                .map_err(|_| RecoveryError::Callback(RecoveryAction::RegisterReports))?;
        }
        let reports = lookup_reports(request, &valid, &current_clock, transport)?;
        saved.watermark.observe(&reports.finality)?;
        let mut next = record.clone();
        next.stage = Stage::ReportsObserved;
        next.reports = Some(encode(&reports)?);
        advance(store, &mut record, next)?;
        saved.reports = Some(reports);
    }
    if record.stage == Stage::ReportsObserved {
        let original_clock = saved.clock.as_ref().ok_or(RecoveryError::Malformed)?;
        let original_reports = saved.reports.as_ref().ok_or(RecoveryError::Malformed)?;
        let current_clock = reconcile_clock(
            request,
            &valid,
            original_clock,
            &mut saved.watermark,
            transport,
        )?;
        reconcile_reports(
            request,
            &valid,
            &current_clock,
            original_reports,
            &mut saved.watermark,
            transport,
        )?;
        let response = transport
            .prove(request)
            .map_err(|_| RecoveryError::Callback(RecoveryAction::Prove))?;
        if !valid_response(request, valid.native(), &response) {
            return Err(RecoveryError::Protocol(ProtocolError::Response));
        }
        let prepared = PreparedCandidate {
            request_sha256: sha256(&request_bytes),
            native: valid.native(),
            clock: original_clock.value.clone(),
            reports: original_reports.value.clone(),
            response,
        };
        let mut next = record.clone();
        next.stage = Stage::Prepared;
        next.prepared = Some(encode(&prepared)?);
        advance(store, &mut record, next)?;
        saved.prepared = Some(prepared);
    }
    if record.stage != Stage::Prepared {
        return Err(RecoveryError::Malformed);
    }
    Ok(PreparedProgress {
        record,
        valid,
        saved,
    })
}

/// Stop immediately after the exact Prepared cut is durably acknowledged.
/// Prepared resume validates its saved payloads and makes no callbacks.
pub(crate) fn prepare_with_checkpoints(
    mode: RunMode,
    request: &ProtocolRequest,
    trusted: &TrustedRequest,
    store: &impl PreparationCheckpointStore,
    transport: &mut impl PreparationTransport,
) -> Result<PreparedCut, RecoveryError> {
    let progress = drive_prepared(mode, request, trusted, store, transport)?;
    Ok(PreparedCut {
        record: progress.record,
        prepared: progress.saved.prepared.ok_or(RecoveryError::Malformed)?,
    })
}

pub(crate) fn prepare_only(
    mode: RunMode,
    request: &ProtocolRequest,
    trusted: &TrustedRequest,
    store: &RecoveryStore,
    transport: &mut impl PreparationTransport,
) -> Result<PreparedCut, RecoveryError> {
    prepare_with_checkpoints(mode, request, trusted, store, transport)
}

/// Historical behavior: reconcile again after Prepared and call the old mock
/// broadcast. Its callback schedule and invocation-local watermark are retained.
pub(crate) fn execute(
    mode: RunMode,
    request: &ProtocolRequest,
    trusted: &TrustedRequest,
    store: &RecoveryStore,
    transport: &mut impl RecoveryTransport,
) -> Result<PreparedCandidate, RecoveryError> {
    let mut transport = LegacyPreparation(transport);
    let PreparedProgress {
        valid, mut saved, ..
    } = drive_prepared(mode, request, trusted, store, &mut transport)?;
    let prepared = saved.prepared.ok_or(RecoveryError::Malformed)?;
    let original_clock = saved.clock.as_ref().ok_or(RecoveryError::Malformed)?;
    let original_reports = saved.reports.as_ref().ok_or(RecoveryError::Malformed)?;
    let current_clock = reconcile_clock(
        request,
        &valid,
        original_clock,
        &mut saved.watermark,
        &mut transport,
    )?;
    let current_reports = reconcile_reports(
        request,
        &valid,
        &current_clock,
        original_reports,
        &mut saved.watermark,
        &mut transport,
    )?;
    if !valid_recheck(
        request,
        &valid,
        &prepared,
        &current_clock.value,
        &current_reports.value,
    ) {
        return Err(RecoveryError::Observation);
    }
    transport
        .0
        .broadcast(&prepared)
        .map_err(|_| RecoveryError::Callback(RecoveryAction::Broadcast))?;
    Ok(prepared)
}

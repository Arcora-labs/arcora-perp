//! Offline registration coordination through durable Prepared only.
//! No broadcast capability, live transport or cross-path uniqueness is claimed.
use crate::{
    candidate_preparation_store::{Binding, CoordinationStore, Lease, StoreError},
    candidate_protocol::{
        sha256, validate, CandidateProofResponse, ClockObservation, ProtocolRequest,
        ReportObservation, TrustedRequest,
    },
    candidate_recovery::{
        prepare_with_checkpoints, request_bytes, validate_stored_cut, Lookup,
        PreparationCheckpointStore, PreparationTransport, PreparedCut, RecoveryAction,
        RecoveryError, RunMode,
    },
    candidate_recovery_store::{Record, Stage, StoreError as SourceError},
    candidate_registration::Registration,
};
use perp_core::clock::ClockContext;
use std::{
    cell::Cell,
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PreparationError {
    Store(StoreError),
    Recovery(RecoveryError),
    ExistingFresh,
    MissingBinding,
    MissingSource,
    BindingMismatch,
}
impl From<StoreError> for PreparationError {
    fn from(value: StoreError) -> Self {
        Self::Store(value)
    }
}
impl From<RecoveryError> for PreparationError {
    fn from(value: RecoveryError) -> Self {
        Self::Recovery(value)
    }
}

/// Read-only view of one immutable, authenticated Prepared cut. The source
/// lease stays owned by this object; no raw store or source write is exposed.
/// Handoff callers check it before and after every callback/publication.
pub(crate) struct BoundPrepared<'a> {
    lease: Lease<'a>,
    request: &'a ProtocolRequest,
    trusted: &'a TrustedRequest,
    binding: Binding,
    record: Record,
}
impl BoundPrepared<'_> {
    pub(crate) fn record(&self) -> &Record {
        &self.record
    }

    pub(crate) fn check(&self) -> Result<(), PreparationError> {
        self.lease.check()?;
        let binding = self
            .lease
            .load_binding()?
            .ok_or(PreparationError::MissingBinding)?;
        if binding != self.binding
            || binding.request_sha256 != sha256(&request_bytes(self.request)?)
        {
            return Err(PreparationError::BindingMismatch);
        }
        let current = self
            .lease
            .load_source()?
            .ok_or(PreparationError::MissingSource)?;
        if current != self.record || current.stage != Stage::Prepared {
            return Err(RecoveryError::Malformed.into());
        }
        // Validate the complete canonical payload against the original trusted
        // request every time. A same-logical-value reseal/replacement still
        // fails the lease's physical FileCut; this seam never refreshes it.
        validate_stored_cut(&current, self.request, self.trusted)?;
        self.lease.check()?;
        Ok(())
    }
}

pub(crate) struct RegistrationCoordinator {
    store: CoordinationStore,
}
impl RegistrationCoordinator {
    pub(crate) fn new(source_path: PathBuf, seed: [u8; 32]) -> Result<Self, PreparationError> {
        Ok(Self {
            store: CoordinationStore::new(source_path, seed)?,
        })
    }
    pub(crate) fn source_path(&self) -> &Path {
        self.store.source_path()
    }
    pub(crate) fn binding_path(&self) -> &Path {
        self.store.binding_path()
    }
    pub(crate) fn lock_path(&self) -> &Path {
        self.store.lock_path()
    }
    pub(crate) fn fail_next_binding_write(&self) {
        self.store.fail_next_binding_write();
    }
    pub(crate) fn fail_next_binding_rename(&self) {
        self.store.fail_next_binding_rename();
    }
    pub(crate) fn fail_next_binding_directory_sync(&self) {
        self.store.fail_next_binding_directory_sync();
    }
    pub(crate) fn fail_next_source_write(&self) {
        self.store.fail_next_source_write();
    }
    pub(crate) fn fail_next_source_rename(&self) {
        self.store.fail_next_source_rename();
    }
    pub(crate) fn fail_next_source_directory_sync(&self) {
        self.store.fail_next_source_directory_sync();
    }

    /// Acquire before validation, and return only an already bound complete
    /// Prepared cut. Missing/partial sources have no adoption or write fallback.
    pub(crate) fn lease_prepared<'a>(
        &'a self,
        request: &'a ProtocolRequest,
        trusted: &'a TrustedRequest,
    ) -> Result<BoundPrepared<'a>, PreparationError> {
        let lease = self.store.try_lease()?;
        validate(request, trusted).map_err(RecoveryError::Protocol)?;
        let request_hash = sha256(&request_bytes(request)?);
        let binding = lease
            .load_binding()?
            .ok_or(PreparationError::MissingBinding)?;
        if binding.request_sha256 != request_hash {
            return Err(PreparationError::BindingMismatch);
        }
        let record = lease
            .load_source()?
            .ok_or(PreparationError::MissingSource)?;
        if record.stage != Stage::Prepared {
            return Err(RecoveryError::Malformed.into());
        }
        validate_stored_cut(&record, request, trusted)?;
        let bound = BoundPrepared {
            lease,
            request,
            trusted,
            binding,
            record,
        };
        bound.check()?;
        Ok(bound)
    }

    pub(crate) fn run_prepared(
        &self,
        mode: RunMode,
        request: &ProtocolRequest,
        trusted: &TrustedRequest,
        transport: &mut impl PreparationTransport,
    ) -> Result<PreparedCut, PreparationError> {
        // Acquire before decoding/validation and retain through the final read.
        let lease = self.store.try_lease()?;
        validate(request, trusted).map_err(RecoveryError::Protocol)?;
        let bytes = request_bytes(request)?;
        let request_hash = sha256(&bytes);
        let binding = lease.load_binding()?;
        match mode {
            RunMode::Fresh => {
                if binding.is_some() || lease.source_exists()? {
                    return Err(PreparationError::ExistingFresh);
                }
                // An acknowledged binding precedes Intent. Failure afterwards
                // leaves an orphan HOLD; neither mode silently restarts it.
                lease.create_binding(request_hash)?;
            }
            RunMode::Resume => {
                let binding = binding.ok_or(PreparationError::MissingBinding)?;
                if binding.request_sha256 != request_hash {
                    return Err(PreparationError::BindingMismatch);
                }
                let record = lease
                    .load_source()?
                    .ok_or(PreparationError::MissingSource)?;
                validate_stored_cut(&record, request, trusted)?;
            }
        }
        let gate = Gate {
            lease: &lease,
            request,
            trusted,
            request_hash,
            fault: Cell::new(None),
        };
        let checkpoints = GuardedCheckpoints { gate: &gate };
        let mut guarded = GuardedTransport {
            gate: &gate,
            transport,
        };
        let result = prepare_with_checkpoints(mode, request, trusted, &checkpoints, &mut guarded);
        // Preserve filesystem/semantic failures rather than disguising them as
        // a transport rejection or a generic durability error from the driver.
        if let Some(error) = gate.fault.get() {
            return Err(error);
        }
        let cut = result?;
        let record = gate.record()?;
        let prepared_bytes =
            postcard::to_allocvec(&cut.prepared).map_err(|_| RecoveryError::Malformed)?;
        if record != cut.record
            || record.stage != Stage::Prepared
            || record.prepared.as_deref() != Some(prepared_bytes.as_slice())
        {
            return Err(RecoveryError::Malformed.into());
        }
        lease.check()?;
        Ok(cut)
    }

    /// Explicit adoption requires quiescent historical writers. It validates
    /// the exact authenticated staged cut before binding, without callbacks.
    pub(crate) fn attach_existing(
        &self,
        request: &ProtocolRequest,
        trusted: &TrustedRequest,
    ) -> Result<Binding, PreparationError> {
        let lease = self.store.try_lease()?;
        validate(request, trusted).map_err(RecoveryError::Protocol)?;
        let request_hash = sha256(&request_bytes(request)?);
        let existing = lease.load_binding()?;
        let record = match existing {
            Some(binding) => {
                if binding.request_sha256 != request_hash {
                    return Err(PreparationError::BindingMismatch);
                }
                lease
                    .load_source()?
                    .ok_or(PreparationError::MissingSource)?
            }
            None => lease
                .inspect_adoption_source()?
                .ok_or(PreparationError::MissingSource)?,
        };
        validate_stored_cut(&record, request, trusted)?;
        if sha256(&record.request) != request_hash {
            return Err(PreparationError::BindingMismatch);
        }
        let binding = match existing {
            Some(binding) => binding,
            None => lease.create_binding(request_hash)?,
        };
        let reloaded = lease
            .load_source()?
            .ok_or(PreparationError::MissingSource)?;
        if reloaded != record {
            return Err(RecoveryError::Malformed.into());
        }
        lease.check()?;
        Ok(binding)
    }
}

struct Gate<'a, 'b> {
    lease: &'a Lease<'b>,
    request: &'a ProtocolRequest,
    trusted: &'a TrustedRequest,
    request_hash: [u8; 32],
    fault: Cell<Option<PreparationError>>,
}
impl Gate<'_, '_> {
    fn binding(&self) -> Result<(), PreparationError> {
        self.lease.check()?;
        let binding = self
            .lease
            .load_binding()?
            .ok_or(PreparationError::MissingBinding)?;
        if binding.request_sha256 != self.request_hash {
            return Err(PreparationError::BindingMismatch);
        }
        Ok(())
    }
    fn record(&self) -> Result<Record, PreparationError> {
        self.binding()?;
        let record = self
            .lease
            .load_source()?
            .ok_or(PreparationError::MissingSource)?;
        if sha256(&record.request) != self.request_hash {
            return Err(PreparationError::BindingMismatch);
        }
        validate_stored_cut(&record, self.request, self.trusted)?;
        Ok(record)
    }
    fn callback_stage(&self, action: RecoveryAction) -> Result<(), PreparationError> {
        let stage = self.record()?.stage;
        let allowed = match action {
            RecoveryAction::RegisterClock => stage == Stage::ClockPending,
            RecoveryAction::LookupClock => matches!(
                stage,
                Stage::ClockPending
                    | Stage::ClockObserved
                    | Stage::ReportsPending
                    | Stage::ReportsObserved
            ),
            RecoveryAction::RegisterReports => stage == Stage::ReportsPending,
            RecoveryAction::LookupReports => {
                matches!(stage, Stage::ReportsPending | Stage::ReportsObserved)
            }
            RecoveryAction::Prove => stage == Stage::ReportsObserved,
            RecoveryAction::Broadcast => false,
        };
        if !allowed {
            return Err(RecoveryError::Malformed.into());
        }
        Ok(())
    }
    fn remember(&self, error: PreparationError) {
        if self.fault.get().is_none() {
            self.fault.set(Some(error));
        }
    }
}
struct GuardedCheckpoints<'a, 'b> {
    gate: &'a Gate<'a, 'b>,
}
impl GuardedCheckpoints<'_, '_> {
    fn operation<T>(&self, result: Result<T, PreparationError>) -> Result<T, SourceError> {
        result.map_err(|error| {
            self.gate.remember(error);
            match error {
                PreparationError::Store(StoreError::Source(error)) => error,
                PreparationError::Store(StoreError::AmbiguousWrite) => SourceError::AmbiguousWrite,
                _ => SourceError::Write,
            }
        })
    }
}
impl PreparationCheckpointStore for GuardedCheckpoints<'_, '_> {
    fn load(&self) -> Result<Option<Record>, SourceError> {
        self.operation(self.gate.record().map(Some))
    }
    fn create(&self, request: &[u8]) -> Result<Record, SourceError> {
        self.operation((|| {
            self.gate.binding()?;
            if sha256(request) != self.gate.request_hash {
                return Err(PreparationError::BindingMismatch);
            }
            let record = self.gate.lease.create_source(request)?;
            if self.gate.record()? != record {
                return Err(RecoveryError::Malformed.into());
            }
            Ok(record)
        })())
    }
    fn advance(&self, expected: &Record, next: Record) -> Result<Record, SourceError> {
        self.operation((|| {
            if self.gate.record()? != *expected {
                return Err(PreparationError::Store(StoreError::Source(
                    SourceError::Conflict,
                )));
            }
            let record = self.gate.lease.advance_source(expected, next)?;
            if self.gate.record()? != record {
                return Err(RecoveryError::Malformed.into());
            }
            Ok(record)
        })())
    }
}
struct GuardedTransport<'a, 'b, T> {
    gate: &'a Gate<'a, 'b>,
    transport: &'a mut T,
}
impl<T: PreparationTransport> GuardedTransport<'_, '_, T> {
    fn call<R>(
        &mut self,
        action: RecoveryAction,
        callback: impl FnOnce(&mut T) -> Result<R, ()>,
    ) -> Result<R, ()> {
        if let Err(error) = self.gate.callback_stage(action) {
            self.gate.remember(error);
            return Err(());
        }
        let result = callback(self.transport);
        if let Err(error) = self.gate.callback_stage(action) {
            self.gate.remember(error);
            return Err(());
        }
        result
    }
}
impl<T: PreparationTransport> PreparationTransport for GuardedTransport<'_, '_, T> {
    fn register_clock(&mut self, clock: &ClockContext) -> Result<(), ()> {
        self.call(RecoveryAction::RegisterClock, |t| t.register_clock(clock))
    }
    fn lookup_clock(&mut self, clock: &ClockContext) -> Result<Lookup<ClockObservation>, ()> {
        self.call(RecoveryAction::LookupClock, |t| t.lookup_clock(clock))
    }
    fn register_reports(&mut self, registration: &Registration) -> Result<(), ()> {
        self.call(RecoveryAction::RegisterReports, |t| {
            t.register_reports(registration)
        })
    }
    fn lookup_reports(
        &mut self,
        registration: &Registration,
    ) -> Result<Lookup<ReportObservation>, ()> {
        self.call(RecoveryAction::LookupReports, |t| {
            t.lookup_reports(registration)
        })
    }
    fn prove(&mut self, request: &ProtocolRequest) -> Result<CandidateProofResponse, ()> {
        self.call(RecoveryAction::Prove, |t| t.prove(request))
    }
}

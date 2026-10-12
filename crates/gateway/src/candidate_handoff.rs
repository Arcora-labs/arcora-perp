//! Offline handoff from an owned bound Prepared cut to one fixed broadcast lane.
//! Both cooperative local leases remain held through callbacks and readback.
use crate::{
    candidate_broadcast::{
        build_plan, decode_outcome, execute_with_checkpoints, plan_bytes, validate_outcome,
        BridgeTarget, BroadcastCheckpoints, BroadcastError, BroadcastSource, BroadcastTransport,
        Outcome, OutcomeValue, Plan, RunMode,
    },
    candidate_broadcast_store::{BroadcastStore, Lease as BroadcastLease, Record, StoreError},
    candidate_preparation::{BoundPrepared, PreparationError, RegistrationCoordinator},
    candidate_preparation_store::Binding,
    candidate_protocol::{ClockObservation, ProtocolRequest, ReportObservation, TrustedRequest},
    candidate_recovery::{
        Anchored, Lookup, PreparationTransport, PreparedCut, RunMode as PrepMode,
    },
    candidate_recovery_store::Record as SourceRecord,
};
use std::{
    cell::Cell,
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HandoffError {
    Preparation(PreparationError),
    Broadcast(BroadcastError),
    PlanMismatch,
    SourceMismatch,
    BroadcastMismatch,
}
impl From<PreparationError> for HandoffError {
    fn from(value: PreparationError) -> Self {
        Self::Preparation(value)
    }
}
impl From<BroadcastError> for HandoffError {
    fn from(value: BroadcastError) -> Self {
        Self::Broadcast(value)
    }
}
impl From<StoreError> for HandoffError {
    fn from(value: StoreError) -> Self {
        Self::Broadcast(BroadcastError::Store(value))
    }
}

pub(crate) struct HandoffCoordinator {
    source: RegistrationCoordinator,
    broadcast: BroadcastStore,
    broadcast_path: PathBuf,
    broadcast_lock_path: PathBuf,
}
impl HandoffCoordinator {
    pub(crate) fn new(
        source_path: PathBuf,
        source_seed: [u8; 32],
        broadcast_seed: [u8; 32],
    ) -> Result<Self, HandoffError> {
        let source = RegistrationCoordinator::new(source_path, source_seed)?;
        // The existing physical source lane selects exactly one broadcast path.
        // Request/proof/sender/nonce never contribute to the path selection.
        let lane = source
            .lock_path()
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|n| n.strip_prefix(".dpcreg1-"))
            .and_then(|n| n.strip_suffix(".lock"))
            .ok_or(HandoffError::SourceMismatch)?;
        if lane.len() != 64
            || !lane
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            return Err(HandoffError::SourceMismatch);
        }
        let parent = source
            .source_path()
            .parent()
            .ok_or(HandoffError::SourceMismatch)?;
        let broadcast_path = parent.join(format!(".dpchandoff1-{lane}.dpcbtx1"));
        let mut name = broadcast_path.as_os_str().to_os_string();
        name.push(".lock");
        let broadcast_lock_path = PathBuf::from(name);
        let broadcast = BroadcastStore::new(broadcast_path.clone(), broadcast_seed)?;
        Ok(Self {
            source,
            broadcast,
            broadcast_path,
            broadcast_lock_path,
        })
    }
    pub(crate) fn source_path(&self) -> &Path {
        self.source.source_path()
    }
    pub(crate) fn binding_path(&self) -> &Path {
        self.source.binding_path()
    }
    pub(crate) fn source_lock_path(&self) -> &Path {
        self.source.lock_path()
    }
    pub(crate) fn broadcast_path(&self) -> &Path {
        &self.broadcast_path
    }
    pub(crate) fn broadcast_lock_path(&self) -> &Path {
        &self.broadcast_lock_path
    }
    pub(crate) fn fail_next_write(&self) {
        self.broadcast.fail_next_write();
    }
    pub(crate) fn fail_next_rename(&self) {
        self.broadcast.fail_next_rename();
    }
    pub(crate) fn fail_next_directory_sync(&self) {
        self.broadcast.fail_next_directory_sync();
    }
    pub(crate) fn prepare(
        &self,
        mode: PrepMode,
        request: &ProtocolRequest,
        trusted: &TrustedRequest,
        transport: &mut impl PreparationTransport,
    ) -> Result<PreparedCut, HandoffError> {
        Ok(self
            .source
            .run_prepared(mode, request, trusted, transport)?)
    }
    pub(crate) fn attach_existing(
        &self,
        request: &ProtocolRequest,
        trusted: &TrustedRequest,
    ) -> Result<Binding, HandoffError> {
        Ok(self.source.attach_existing(request, trusted)?)
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn handoff(
        &self,
        mode: RunMode,
        request: &ProtocolRequest,
        trusted: &TrustedRequest,
        bridge: &BridgeTarget,
        sender: [u8; 20],
        nonce: u64,
        transport: &mut impl BroadcastTransport,
    ) -> Result<Outcome, HandoffError> {
        // Fixed, nonblocking order: source first, broadcast second. Neither is
        // released until final source and outcome readback have been checked.
        let source = self.source.lease_prepared(request, trusted)?;
        let broadcast = self.broadcast.try_lease()?;
        source.check()?;
        broadcast.check()?;
        let plan = build_plan(source.record(), request, trusted, bridge, sender, nonce)?;
        let bytes = plan_bytes(&plan)?;
        let gate = Gate {
            source: &source,
            broadcast: &broadcast,
            plan: &plan,
            bytes: &bytes,
            fault: Cell::new(None),
        };
        let checkpoints = Checkpoints { gate: &gate };
        let source_view = Source { gate: &gate };
        let mut guarded = Transport {
            gate: &gate,
            transport,
        };
        let result = execute_with_checkpoints(
            &checkpoints,
            mode,
            &source_view,
            request,
            trusted,
            bridge,
            sender,
            nonce,
            &mut guarded,
        );
        if let Some(error) = gate.fault.get() {
            return Err(error);
        }
        let outcome = result?;
        gate.check()?;
        let record = broadcast.load()?.ok_or(HandoffError::BroadcastMismatch)?;
        let saved = record
            .outcome
            .as_deref()
            .ok_or(HandoffError::BroadcastMismatch)?;
        if record.plan != bytes || decode_outcome(saved)? != outcome {
            return Err(HandoffError::BroadcastMismatch);
        }
        validate_outcome(&plan, &outcome)?;
        gate.check()?;
        Ok(outcome)
    }
}

struct Gate<'a, 'b> {
    source: &'a BoundPrepared<'b>,
    broadcast: &'a BroadcastLease<'b>,
    plan: &'a Plan,
    bytes: &'a [u8],
    fault: Cell<Option<HandoffError>>,
}
impl Gate<'_, '_> {
    fn remember(&self, error: HandoffError) -> HandoffError {
        if self.fault.get().is_none() {
            self.fault.set(Some(error));
        }
        self.fault.get().unwrap()
    }
    fn record(&self, record: &Record) -> Result<(), HandoffError> {
        if record.plan != self.bytes {
            return Err(HandoffError::PlanMismatch);
        }
        if let Some(bytes) = &record.outcome {
            validate_outcome(self.plan, &decode_outcome(bytes)?)?;
        }
        Ok(())
    }
    fn check(&self) -> Result<(), HandoffError> {
        if let Some(error) = self.fault.get() {
            return Err(error);
        }
        let result = (|| {
            self.source.check()?;
            self.broadcast.check()?;
            if let Some(record) = self.broadcast.load()? {
                self.record(&record)?;
            }
            self.source.check()?;
            self.broadcast.check()?;
            Ok(())
        })();
        result.map_err(|error| self.remember(error))
    }
    fn store_check(&self) -> Result<(), StoreError> {
        self.check().map_err(|_| StoreError::Identity)
    }
    fn returned(&self, record: &Record) -> Result<(), StoreError> {
        self.store_check()?;
        let actual = self.broadcast.load().inspect_err(|e| {
            self.remember((*e).into());
        })?;
        if actual.as_ref() != Some(record) {
            self.remember(HandoffError::BroadcastMismatch);
            return Err(StoreError::Identity);
        }
        self.store_check()
    }
}
struct Source<'a, 'b> {
    gate: &'a Gate<'a, 'b>,
}
impl BroadcastSource for Source<'_, '_> {
    fn load(&self) -> Result<Option<SourceRecord>, BroadcastError> {
        self.gate
            .check()
            .map_err(|_| BroadcastError::SourceMismatch)?;
        let record = self.gate.source.record().clone();
        self.gate
            .check()
            .map_err(|_| BroadcastError::SourceMismatch)?;
        Ok(Some(record))
    }
}
struct Checkpoints<'a, 'b> {
    gate: &'a Gate<'a, 'b>,
}
impl BroadcastCheckpoints for Checkpoints<'_, '_> {
    fn check(&self) -> Result<(), StoreError> {
        self.gate.store_check()
    }
    fn load(&self) -> Result<Option<Record>, StoreError> {
        self.gate.store_check()?;
        let record = self.gate.broadcast.load().inspect_err(|e| {
            self.gate.remember((*e).into());
        })?;
        self.gate.store_check()?;
        Ok(record)
    }
    fn create_pending(&self, plan: &[u8]) -> Result<Record, StoreError> {
        self.gate.store_check()?;
        if plan != self.gate.bytes {
            self.gate.remember(HandoffError::PlanMismatch);
            return Err(StoreError::Malformed);
        }
        let record = self.gate.broadcast.create_pending(plan).inspect_err(|e| {
            self.gate.remember((*e).into());
        })?;
        self.gate.returned(&record)?;
        Ok(record)
    }
    fn finish(&self, expected: &Record, outcome: &[u8]) -> Result<Record, StoreError> {
        self.gate.store_check()?;
        let record = self
            .gate
            .broadcast
            .finish(expected, outcome)
            .inspect_err(|e| {
                self.gate.remember((*e).into());
            })?;
        self.gate.returned(&record)?;
        Ok(record)
    }
}
struct Transport<'a, 'b, T> {
    gate: &'a Gate<'a, 'b>,
    transport: &'a mut T,
}
impl<T: BroadcastTransport> Transport<'_, '_, T> {
    fn call<R>(
        &mut self,
        plan: &Plan,
        callback: impl FnOnce(&mut T) -> Result<R, ()>,
    ) -> Result<R, ()> {
        self.gate.check().map_err(|_| ())?;
        if plan != self.gate.plan {
            self.gate.remember(HandoffError::PlanMismatch);
            return Err(());
        }
        let result = callback(self.transport);
        // Check even when the transport rejects: mutation must not be laundered
        // into a generic callback error and must never refresh the source cut.
        self.gate.check().map_err(|_| ())?;
        result
    }
}
impl<T: BroadcastTransport> BroadcastTransport for Transport<'_, '_, T> {
    fn recheck(
        &mut self,
        plan: &Plan,
    ) -> Result<(Anchored<ClockObservation>, Anchored<ReportObservation>), ()> {
        self.call(plan, |t| t.recheck(plan))
    }
    fn broadcast(&mut self, plan: &Plan) -> Result<(), ()> {
        self.call(plan, |t| t.broadcast(plan))
    }
    fn lookup(&mut self, plan: &Plan) -> Result<Lookup<OutcomeValue>, ()> {
        self.call(plan, |t| t.lookup(plan))
    }
}

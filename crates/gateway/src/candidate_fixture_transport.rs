//! Test-only candidate fixture HTTP transport over an explicitly owned loopback.
//! The peer, opaque proof bytes, observations and outcomes are synthetic fixtures.
//! The optional sealed fixture proves configured software key possession only;
//! it is neither a prover service nor approved transport or chain delivery.
//! Existing coordinators remain the sole checkpoint and cooperative lease authority.
use crate::{
    candidate_broadcast::{
        plan_bytes, settlement_calldata, validate_outcome, BridgeTarget, BroadcastTransport,
        OutcomeValue, Plan,
    },
    candidate_fixture_seal::{
        sealed_wire_bound, SealedChannel, MIN_SEALED_FRAME, SEALED_CONTENT_TYPE,
        SEALED_EXCHANGE_PATH,
    },
    candidate_protocol::{
        sha256, valid_clock, valid_reports, valid_response, validate, CandidateProofResponse,
        ClockObservation, ProgramIdentity, ProtocolRequest, ReportObservation, TrustedRequest,
        Validated,
    },
    candidate_recovery::{request_bytes, Anchored, Lookup, PreparationTransport},
    candidate_registration::{Registration, MAX_ENTRIES_ABI_BYTES},
};
use perp_core::clock::{keccak, ClockContext};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpStream},
    sync::{
        atomic::{AtomicU64, Ordering},
        OnceLock,
    },
    time::{Duration, Instant},
};

pub(crate) const EXCHANGE_PATH: &str = "/candidate-fixture/v1/exchange";
pub(crate) const CONTENT_TYPE: &str = "application/x-arcora-candidate-fixture-v1";
pub(crate) const MAX_FRAME_BYTES: usize = 20 * 1024 * 1024;
pub(crate) const MAX_HEADER_BYTES: usize = 8192;
pub(crate) const FRAME_HEADER_BYTES: usize = 160;
pub(crate) const DEFAULT_DEADLINE: Duration = Duration::from_secs(2);
const MAX_PROOF_BYTES: usize = 1024 * 1024;
const REQUEST_MAGIC: &[u8; 8] = b"DPCFREQ1";
const RESPONSE_MAGIC: &[u8; 8] = b"DPCFRES1";
const VERSION: u16 = 1;
// Random process seed avoids deterministic ID reuse on restart. It supplies
// fixture correlation, not authentication or durable/global nonce uniqueness.
static NEXT_EXCHANGE: OnceLock<Result<AtomicU64, TransportError>> = OnceLock::new();

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TransportError {
    Sealed,
    Endpoint,
    Request,
    Plan,
    Payload,
    Bounds,
    Framing,
    Scope,
    Http,
    Response,
    Replay,
    Deadline,
    Io,
    ExchangeExhausted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Operation {
    RegisterClock = 1,
    LookupClock = 2,
    RegisterReports = 3,
    LookupReports = 4,
    ProveFixture = 5,
    Recheck = 6,
    BroadcastFixture = 7,
    LookupOutcome = 8,
}
impl Operation {
    fn from_byte(value: u8) -> Result<Self, TransportError> {
        match value {
            1 => Ok(Self::RegisterClock),
            2 => Ok(Self::LookupClock),
            3 => Ok(Self::RegisterReports),
            4 => Ok(Self::LookupReports),
            5 => Ok(Self::ProveFixture),
            6 => Ok(Self::Recheck),
            7 => Ok(Self::BroadcastFixture),
            8 => Ok(Self::LookupOutcome),
            _ => Err(TransportError::Framing),
        }
    }
}

/// Scope bytes are fixed: fixture-only and HOLD are true; proof authentication,
/// chain observation, operator approval and candidate submission are all false.
/// This DTO exposes no mutable capability declaration or private environment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WireFrame {
    pub(crate) operation: Operation,
    pub(crate) request_sha256: [u8; 32],
    pub(crate) program_sha256: [u8; 32],
    pub(crate) exchange_id: u64,
    pub(crate) request_payload_sha256: [u8; 32],
    pub(crate) request_payload_len: u32,
    pub(crate) payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RegistrationPayload {
    #[serde(deserialize_with = "deserialize_entries")]
    pub(crate) entries_abi: Vec<u8>,
    pub(crate) input_hash: [u8; 32],
    pub(crate) evidence_hash: [u8; 32],
}
impl From<&Registration> for RegistrationPayload {
    fn from(value: &Registration) -> Self {
        Self {
            entries_abi: value.entries_abi.clone(),
            input_hash: value.input_hash,
            evidence_hash: value.evidence_hash,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum WireLookup<T> {
    Finalized(Anchored<T>),
    Pending,
    Absent,
    Unknown,
    Reorg,
}
impl<T> From<WireLookup<T>> for Lookup<T> {
    fn from(value: WireLookup<T>) -> Self {
        match value {
            WireLookup::Finalized(value) => Self::Finalized(value),
            WireLookup::Pending => Self::Pending,
            WireLookup::Absent => Self::Absent,
            WireLookup::Unknown => Self::Unknown,
            WireLookup::Reorg => Self::Reorg,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RecheckPayload {
    pub(crate) clock: Anchored<ClockObservation>,
    pub(crate) reports: Anchored<ReportObservation>,
}

/// Fixed-width program descriptor avoids allocating peer-supplied SDK strings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct WireProgram {
    pub(crate) wire_magic: [u8; 8],
    pub(crate) sdk_release: [u8; 5],
    pub(crate) elf_sha256: [u8; 32],
    pub(crate) vkey: [u8; 32],
}
impl WireProgram {
    fn from_program(program: &ProgramIdentity) -> Result<Self, TransportError> {
        Ok(Self {
            wire_magic: program.wire_magic,
            sdk_release: program
                .sdk_release
                .as_bytes()
                .try_into()
                .map_err(|_| TransportError::Payload)?,
            elf_sha256: program.elf_sha256,
            vkey: program.vkey,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ProofPayload {
    pub(crate) program: WireProgram,
    pub(crate) public_values: [u8; 32],
    #[serde(deserialize_with = "deserialize_proof")]
    pub(crate) proof: Vec<u8>,
}
impl ProofPayload {
    pub(crate) fn from_response(value: &CandidateProofResponse) -> Result<Self, TransportError> {
        if value.proof.is_empty() || value.proof.len() > MAX_PROOF_BYTES {
            return Err(TransportError::Bounds);
        }
        Ok(Self {
            program: WireProgram::from_program(&value.program)?,
            public_values: value
                .public_values
                .as_slice()
                .try_into()
                .map_err(|_| TransportError::Payload)?,
            proof: value.proof.clone(),
        })
    }
}

fn bounded_vec<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
    bound: usize,
) -> Result<Vec<u8>, D::Error> {
    struct Visitor(usize);
    impl<'de> serde::de::Visitor<'de> for Visitor {
        type Value = Vec<u8>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(formatter, "at most {} fixture bytes", self.0)
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<u8>, A::Error> {
            let hint = seq.size_hint().unwrap_or(0);
            if hint > self.0 {
                return Err(serde::de::Error::custom("fixture byte bound"));
            }
            let mut bytes = Vec::with_capacity(hint);
            while let Some(byte) = seq.next_element()? {
                if bytes.len() == self.0 {
                    return Err(serde::de::Error::custom("fixture byte bound"));
                }
                bytes.push(byte);
            }
            Ok(bytes)
        }
    }
    deserializer.deserialize_seq(Visitor(bound))
}
fn deserialize_proof<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    bounded_vec(d, MAX_PROOF_BYTES)
}
fn deserialize_entries<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    bounded_vec(d, MAX_ENTRIES_ABI_BYTES)
}

pub(crate) fn encode_payload<T: Serialize>(value: &T) -> Result<Vec<u8>, TransportError> {
    let bytes = postcard::to_allocvec(value).map_err(|_| TransportError::Payload)?;
    if bytes.len() > MAX_FRAME_BYTES - FRAME_HEADER_BYTES {
        return Err(TransportError::Bounds);
    }
    Ok(bytes)
}
pub(crate) fn decode_payload<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
) -> Result<T, TransportError> {
    if bytes.len() > MAX_FRAME_BYTES - FRAME_HEADER_BYTES {
        return Err(TransportError::Bounds);
    }
    let (value, tail) = postcard::take_from_bytes(bytes).map_err(|_| TransportError::Payload)?;
    if !tail.is_empty() || encode_payload(&value)? != bytes {
        return Err(TransportError::Payload);
    }
    Ok(value)
}

fn encode_frame(
    frame: &WireFrame,
    payload: &[u8],
    response: bool,
) -> Result<Vec<u8>, TransportError> {
    if payload.len() > MAX_FRAME_BYTES - FRAME_HEADER_BYTES
        || frame.exchange_id == 0
        || frame.request_sha256 == [0; 32]
        || frame.program_sha256 == [0; 32]
        || frame.request_payload_len as usize > MAX_FRAME_BYTES - FRAME_HEADER_BYTES
    {
        return Err(TransportError::Bounds);
    }
    if !response
        && (frame.request_payload_sha256 != sha256(payload)
            || frame.request_payload_len as usize != payload.len())
    {
        return Err(TransportError::Framing);
    }
    let mut bytes = Vec::with_capacity(FRAME_HEADER_BYTES + payload.len());
    bytes.extend_from_slice(if response {
        RESPONSE_MAGIC
    } else {
        REQUEST_MAGIC
    });
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    bytes.extend_from_slice(&[frame.operation as u8, 3, 0, 0, 0, 0]);
    bytes.extend_from_slice(&frame.request_sha256);
    bytes.extend_from_slice(&frame.program_sha256);
    bytes.extend_from_slice(&frame.exchange_id.to_be_bytes());
    bytes.extend_from_slice(&frame.request_payload_sha256);
    bytes.extend_from_slice(&frame.request_payload_len.to_be_bytes());
    bytes.extend_from_slice(&sha256(payload));
    bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    bytes.extend_from_slice(payload);
    Ok(bytes)
}
pub(crate) fn encode_request(frame: &WireFrame) -> Result<Vec<u8>, TransportError> {
    encode_frame(frame, &frame.payload, false)
}
pub(crate) fn encode_response(
    request: &WireFrame,
    payload: &[u8],
) -> Result<Vec<u8>, TransportError> {
    encode_frame(request, payload, true)
}
fn decode_frame(bytes: &[u8], response: bool) -> Result<WireFrame, TransportError> {
    if bytes.len() < FRAME_HEADER_BYTES || bytes.len() > MAX_FRAME_BYTES {
        return Err(TransportError::Bounds);
    }
    if &bytes[..8]
        != if response {
            RESPONSE_MAGIC
        } else {
            REQUEST_MAGIC
        }
        || u16::from_be_bytes(bytes[8..10].try_into().unwrap()) != VERSION
        || bytes[13..16] != [0, 0, 0]
    {
        return Err(TransportError::Framing);
    }
    if bytes[11] != 3 || bytes[12] != 0 {
        return Err(TransportError::Scope);
    }
    let operation = Operation::from_byte(bytes[10])?;
    let request_sha256 = bytes[16..48].try_into().unwrap();
    let program_sha256 = bytes[48..80].try_into().unwrap();
    let exchange_id = u64::from_be_bytes(bytes[80..88].try_into().unwrap());
    let request_payload_sha256 = bytes[88..120].try_into().unwrap();
    let request_payload_len = u32::from_be_bytes(bytes[120..124].try_into().unwrap());
    let payload_hash: [u8; 32] = bytes[124..156].try_into().unwrap();
    let payload_len = u32::from_be_bytes(bytes[156..160].try_into().unwrap()) as usize;
    if payload_len > MAX_FRAME_BYTES - FRAME_HEADER_BYTES
        || request_payload_len as usize > MAX_FRAME_BYTES - FRAME_HEADER_BYTES
        || exchange_id == 0
        || request_sha256 == [0; 32]
        || program_sha256 == [0; 32]
    {
        return Err(TransportError::Bounds);
    }
    if bytes.len() != FRAME_HEADER_BYTES + payload_len
        || sha256(&bytes[FRAME_HEADER_BYTES..]) != payload_hash
        || (!response
            && (request_payload_len as usize != payload_len
                || request_payload_sha256 != payload_hash))
    {
        return Err(TransportError::Framing);
    }
    Ok(WireFrame {
        operation,
        request_sha256,
        program_sha256,
        exchange_id,
        request_payload_sha256,
        request_payload_len,
        payload: bytes[FRAME_HEADER_BYTES..].to_vec(),
    })
}
pub(crate) fn decode_request(bytes: &[u8]) -> Result<WireFrame, TransportError> {
    decode_frame(bytes, false)
}
pub(crate) fn decode_response(bytes: &[u8]) -> Result<WireFrame, TransportError> {
    decode_frame(bytes, true)
}

pub(crate) struct FixtureTransport {
    endpoint: SocketAddr,
    request: ProtocolRequest,
    request_bytes: Vec<u8>,
    request_sha256: [u8; 32],
    program_sha256: [u8; 32],
    valid: Validated,
    bridge: BridgeTarget,
    sender: [u8; 20],
    nonce: u64,
    deadline: Duration,
    last_error: Option<TransportError>,
    pinned_plan: Option<Vec<u8>>,
    roots: [[u8; 32]; 7],
    count: u64,
    batch_id: u64,
    sealed_channel: Option<SealedChannel>,
}

impl FixtureTransport {
    pub(crate) fn new(
        endpoint: SocketAddr,
        request: &ProtocolRequest,
        trusted: &TrustedRequest,
        bridge: &BridgeTarget,
        sender: [u8; 20],
        nonce: u64,
    ) -> Result<Self, TransportError> {
        if !matches!(endpoint, SocketAddr::V4(value) if *value.ip() == Ipv4Addr::LOCALHOST && value.port() != 0)
        {
            return Err(TransportError::Endpoint);
        }
        let valid = validate(request, trusted).map_err(|_| TransportError::Request)?;
        let bytes = request_bytes(request).map_err(|_| TransportError::Bounds)?;
        if bytes.len() > MAX_FRAME_BYTES - FRAME_HEADER_BYTES {
            return Err(TransportError::Bounds);
        }
        let addresses = [
            request.target.clock_verifier,
            request.target.settlement,
            request.target.oracle_wrapper,
            request.target.verifier_proxy,
            request.target.uptime_feed,
            bridge.sp1_adapter,
            bridge.sp1_gateway,
            bridge.prefix_vault,
        ];
        if sender == [0; 20]
            || addresses.contains(&[0; 20])
            || addresses
                .iter()
                .enumerate()
                .any(|(i, value)| addresses[..i].contains(value))
            || [
                bridge.sp1_adapter_code_hash,
                bridge.sp1_gateway_code_hash,
                bridge.prefix_vault_code_hash,
            ]
            .contains(&[0; 32])
            || valid.clock().phase != 0
        {
            return Err(TransportError::Request);
        }
        let witness: chainlink_oracle::binding::CandidateWitness =
            decode_payload(&request.witness[8..])?;
        let mut state = witness.clock.0;
        let roots =
            perp_core::commitment::derive_roots(&mut state, &witness.clock.1, &witness.clock.2)
                .map_err(|_| TransportError::Request)?;
        let program_sha256 = sha256(&encode_payload(&request.program)?);
        Ok(Self {
            endpoint,
            request: request.clone(),
            request_sha256: sha256(&bytes),
            request_bytes: bytes,
            program_sha256,
            valid,
            bridge: bridge.clone(),
            sender,
            nonce,
            deadline: DEFAULT_DEADLINE,
            last_error: None,
            pinned_plan: None,
            roots: [
                roots.prev_state_root,
                roots.manifest_hash,
                roots.new_state_root,
                roots.ordered_root,
                roots.withdrawals_root,
                roots.rejected_root,
                roots.deposits_root,
            ],
            count: state.consumed_deposit_count,
            batch_id: witness.clock.2.batch_id,
            sealed_channel: None,
        })
    }

    pub(crate) fn with_sealed_channel(
        mut self,
        channel: SealedChannel,
    ) -> Result<Self, TransportError> {
        if !channel.matches_request(&self.request_sha256, &self.program_sha256) {
            return Err(TransportError::Sealed);
        }
        self.sealed_channel = Some(channel);
        Ok(self)
    }

    pub(crate) fn last_error(&self) -> Option<TransportError> {
        self.last_error
    }

    pub(crate) fn set_deadline(&mut self, deadline: Duration) -> Result<(), TransportError> {
        if deadline.is_zero() || deadline > DEFAULT_DEADLINE {
            return Err(TransportError::Deadline);
        }
        self.deadline = deadline;
        Ok(())
    }

    fn remember<T>(&mut self, result: Result<T, TransportError>) -> Result<T, ()> {
        match result {
            Ok(value) => {
                self.last_error = None;
                Ok(value)
            }
            Err(error) => {
                self.last_error = Some(error);
                Err(())
            }
        }
    }

    fn next_exchange() -> Result<u64, TransportError> {
        let counter = NEXT_EXCHANGE
            .get_or_init(|| {
                let mut seed = [0; 8];
                getrandom::getrandom(&mut seed).map_err(|_| TransportError::Io)?;
                let seed = u64::from_be_bytes(seed);
                if seed == 0 || seed == u64::MAX {
                    return Err(TransportError::ExchangeExhausted);
                }
                Ok(AtomicU64::new(seed))
            })
            .as_ref()
            .map_err(|error| *error)?;
        let mut id = counter.load(Ordering::Relaxed);
        loop {
            let next = id.checked_add(1).ok_or(TransportError::ExchangeExhausted)?;
            match counter.compare_exchange_weak(id, next, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => return Ok(id),
                Err(current) => id = current,
            }
        }
    }

    fn exchange(
        &self,
        operation: Operation,
        payload: Vec<u8>,
        deadline: Instant,
    ) -> Result<Vec<u8>, TransportError> {
        if payload.len() > MAX_FRAME_BYTES - FRAME_HEADER_BYTES {
            return Err(TransportError::Bounds);
        }
        let frame = WireFrame {
            operation,
            request_sha256: self.request_sha256,
            program_sha256: self.program_sha256,
            exchange_id: Self::next_exchange()?,
            request_payload_sha256: sha256(&payload),
            request_payload_len: payload.len() as u32,
            payload,
        };
        let inner = encode_request(&frame)?;
        let inner_response_bound = FRAME_HEADER_BYTES
            .checked_add(response_bound(operation))
            .ok_or(TransportError::Bounds)?;
        let (body, path, content_type, minimum, maximum) = match &self.sealed_channel {
            Some(channel) => (
                channel
                    .wrap_request(&inner)
                    .map_err(|_| TransportError::Sealed)?,
                SEALED_EXCHANGE_PATH,
                SEALED_CONTENT_TYPE,
                MIN_SEALED_FRAME,
                sealed_wire_bound(inner_response_bound).map_err(|_| TransportError::Bounds)?,
            ),
            None => (
                inner,
                EXCHANGE_PATH,
                CONTENT_TYPE,
                FRAME_HEADER_BYTES,
                inner_response_bound,
            ),
        };
        let headers = format!(
            "POST {path} HTTP/1.1\r\nHost: {}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            self.endpoint, body.len(),
        );
        let mut socket =
            TcpStream::connect_timeout(&self.endpoint, remaining(deadline)?).map_err(io_error)?;
        write_deadline(&mut socket, headers.as_bytes(), deadline)?;
        write_deadline(&mut socket, &body, deadline)?;
        let response = read_http(&mut socket, deadline, content_type, minimum, maximum)?;
        let response = match &self.sealed_channel {
            Some(channel) => channel
                .open_response(&response, &frame)
                .map_err(|_| TransportError::Sealed)?,
            None => response,
        };
        let response = decode_response(&response)?;
        if response.exchange_id != frame.exchange_id {
            return Err(TransportError::Replay);
        }
        if response.operation != frame.operation
            || response.request_sha256 != frame.request_sha256
            || response.program_sha256 != frame.program_sha256
            || response.request_payload_sha256 != frame.request_payload_sha256
            || response.request_payload_len != frame.request_payload_len
        {
            return Err(TransportError::Response);
        }
        remaining(deadline)?;
        Ok(response.payload)
    }

    fn call<T: DeserializeOwned + Serialize>(
        &self,
        operation: Operation,
        payload: Vec<u8>,
    ) -> Result<T, TransportError> {
        let deadline = Instant::now()
            .checked_add(self.deadline)
            .ok_or(TransportError::Deadline)?;
        let response = self.exchange(operation, payload, deadline)?;
        let value = decode_payload(&response)?;
        remaining(deadline)?;
        Ok(value)
    }

    fn plan_payload(&mut self, plan: &Plan) -> Result<Vec<u8>, TransportError> {
        if plan.request_sha256 != self.request_sha256
            || plan.witness_sha256 != sha256(&self.request.witness)
            || plan.target != self.request.target
            || plan.bridge_target != self.bridge
            || plan.program != self.request.program
            || plan.mock_sender != self.sender
            || plan.mock_nonce != self.nonce
            || plan.batch_id != self.batch_id
            || plan.phase != 0
            || plan.roots != self.roots
            || plan.consumed_deposit_count != self.count
            || plan.consumed_deposit_tip != self.roots[6]
            || plan.native != self.valid.native()
            || plan.public_values != self.valid.native().commitment
            || plan.source_cut_sha256 == [0; 32]
            || plan.prepared_sha256 == [0; 32]
            || !valid_clock(&self.request, self.valid.clock(), &plan.clock.value)
            || !valid_reports(&self.request, &self.valid, &plan.reports.value)
            || plan.call_hash != keccak(&plan.calldata)
        {
            return Err(TransportError::Plan);
        }
        // Parse only the known nine-word calldata layout, then use the original
        // canonical encoder to check selector, lengths, offset and zero padding.
        const LENGTH: usize = 4 + 9 * 32;
        const PROOF: usize = LENGTH + 32;
        if plan.calldata.len() < PROOF || plan.calldata[LENGTH..LENGTH + 24] != [0; 24] {
            return Err(TransportError::Plan);
        }
        let len = u64::from_be_bytes(plan.calldata[LENGTH + 24..PROOF].try_into().unwrap());
        if len == 0 || len > MAX_PROOF_BYTES as u64 {
            return Err(TransportError::Bounds);
        }
        let end = PROOF
            .checked_add(len as usize)
            .ok_or(TransportError::Bounds)?;
        let proof = plan.calldata.get(PROOF..end).ok_or(TransportError::Plan)?;
        if settlement_calldata(&plan.roots, plan.consumed_deposit_count, proof)
            .map_err(|_| TransportError::Plan)?
            != plan.calldata
        {
            return Err(TransportError::Plan);
        }
        let bytes = plan_bytes(plan).map_err(|_| TransportError::Bounds)?;
        if self
            .pinned_plan
            .as_ref()
            .is_some_and(|previous| previous != &bytes)
        {
            return Err(TransportError::Plan);
        }
        self.pinned_plan.get_or_insert_with(|| bytes.clone());
        Ok(bytes)
    }
}

fn remaining(deadline: Instant) -> Result<Duration, TransportError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|value| !value.is_zero())
        .ok_or(TransportError::Deadline)
}
fn io_error(error: std::io::Error) -> TransportError {
    match error.kind() {
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => TransportError::Deadline,
        _ => TransportError::Io,
    }
}
fn write_deadline(
    socket: &mut TcpStream,
    mut bytes: &[u8],
    deadline: Instant,
) -> Result<(), TransportError> {
    while !bytes.is_empty() {
        socket
            .set_write_timeout(Some(remaining(deadline)?))
            .map_err(io_error)?;
        match socket.write(&bytes[..bytes.len().min(4096)]) {
            Ok(0) => return Err(TransportError::Io),
            Ok(count) => bytes = &bytes[count..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(io_error(error)),
        }
    }
    remaining(deadline)?;
    Ok(())
}
fn read_deadline(
    socket: &mut TcpStream,
    bytes: &mut [u8],
    deadline: Instant,
) -> Result<usize, TransportError> {
    loop {
        socket
            .set_read_timeout(Some(remaining(deadline)?))
            .map_err(io_error)?;
        match socket.read(bytes) {
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            value => {
                let count = value.map_err(io_error)?;
                remaining(deadline)?;
                return Ok(count);
            }
        }
    }
}
fn response_bound(operation: Operation) -> usize {
    match operation {
        Operation::RegisterClock | Operation::RegisterReports | Operation::BroadcastFixture => 0,
        Operation::ProveFixture => MAX_PROOF_BYTES + 1024,
        Operation::Recheck => 2 * 64 * 1024,
        Operation::LookupClock | Operation::LookupReports | Operation::LookupOutcome => 64 * 1024,
    }
}
fn read_http(
    socket: &mut TcpStream,
    deadline: Instant,
    expected_content_type: &str,
    minimum_length: usize,
    maximum_length: usize,
) -> Result<Vec<u8>, TransportError> {
    let mut header = Vec::new();
    let mut byte = [0];
    while !header.ends_with(b"\r\n\r\n") {
        if header.len() == MAX_HEADER_BYTES {
            return Err(TransportError::Bounds);
        }
        if read_deadline(socket, &mut byte, deadline)? == 0 {
            return Err(TransportError::Http);
        }
        header.push(byte[0]);
    }
    if !header.is_ascii() {
        return Err(TransportError::Http);
    }
    let header = std::str::from_utf8(&header).map_err(|_| TransportError::Http)?;
    let mut lines = header[..header.len() - 4].split("\r\n");
    if lines.next() != Some("HTTP/1.1 200 OK") {
        return Err(TransportError::Http);
    }
    let mut length = None;
    let mut content_type = false;
    let mut connection = false;
    for line in lines {
        let (key, value) = line.split_once(": ").ok_or(TransportError::Http)?;
        if key.eq_ignore_ascii_case("content-length") && length.is_none() {
            if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(TransportError::Http);
            }
            let parsed: usize = value.parse().map_err(|_| TransportError::Bounds)?;
            if parsed.to_string() != value {
                return Err(TransportError::Http);
            }
            length = Some(parsed);
        } else if key.eq_ignore_ascii_case("content-type")
            && !content_type
            && value == expected_content_type
        {
            content_type = true;
        } else if key.eq_ignore_ascii_case("connection") && !connection && value == "close" {
            connection = true;
        } else {
            // Includes duplicate fields, Transfer-Encoding, redirects, content
            // encodings, auth/cookies and any unrecognized fixture header.
            return Err(TransportError::Http);
        }
    }
    let length = length.ok_or(TransportError::Http)?;
    if !content_type || !connection {
        return Err(TransportError::Http);
    }
    if !(minimum_length..=maximum_length).contains(&length) {
        return Err(TransportError::Bounds);
    }
    let mut body = vec![0; length];
    let mut received = 0;
    while received < length {
        let end = length.min(received + 4096);
        let count = read_deadline(socket, &mut body[received..end], deadline)?;
        if count == 0 {
            return Err(TransportError::Framing);
        }
        received += count;
    }
    if read_deadline(socket, &mut byte, deadline)? != 0 {
        return Err(TransportError::Framing);
    }
    Ok(body)
}

impl PreparationTransport for FixtureTransport {
    fn register_clock(&mut self, clock: &ClockContext) -> Result<(), ()> {
        let result = if clock != self.valid.clock() {
            Err(TransportError::Request)
        } else {
            encode_payload(clock).and_then(|bytes| self.call::<()>(Operation::RegisterClock, bytes))
        };
        self.remember(result)
    }
    fn lookup_clock(&mut self, clock: &ClockContext) -> Result<Lookup<ClockObservation>, ()> {
        let result = (|| {
            if clock != self.valid.clock() {
                return Err(TransportError::Request);
            }
            let value: WireLookup<ClockObservation> =
                self.call(Operation::LookupClock, encode_payload(clock)?)?;
            if let WireLookup::Finalized(observation) = &value {
                if !valid_clock(&self.request, self.valid.clock(), &observation.value) {
                    return Err(TransportError::Response);
                }
            }
            Ok(value.into())
        })();
        self.remember(result)
    }
    fn register_reports(&mut self, registration: &Registration) -> Result<(), ()> {
        let value = RegistrationPayload::from(registration);
        let expected = RegistrationPayload::from(self.valid.registration());
        let result = if value != expected {
            Err(TransportError::Request)
        } else {
            encode_payload(&value)
                .and_then(|bytes| self.call::<()>(Operation::RegisterReports, bytes))
        };
        self.remember(result)
    }
    fn lookup_reports(
        &mut self,
        registration: &Registration,
    ) -> Result<Lookup<ReportObservation>, ()> {
        let result = (|| {
            let value = RegistrationPayload::from(registration);
            if value != RegistrationPayload::from(self.valid.registration()) {
                return Err(TransportError::Request);
            }
            let value: WireLookup<ReportObservation> =
                self.call(Operation::LookupReports, encode_payload(&value)?)?;
            if let WireLookup::Finalized(observation) = &value {
                if !valid_reports(&self.request, &self.valid, &observation.value) {
                    return Err(TransportError::Response);
                }
            }
            Ok(value.into())
        })();
        self.remember(result)
    }
    fn prove(&mut self, request: &ProtocolRequest) -> Result<CandidateProofResponse, ()> {
        let result = (|| {
            let bytes = request_bytes(request).map_err(|_| TransportError::Bounds)?;
            if bytes != self.request_bytes {
                return Err(TransportError::Request);
            }
            let value: ProofPayload = self.call(Operation::ProveFixture, bytes)?;
            if value.program != WireProgram::from_program(&self.request.program)? {
                return Err(TransportError::Response);
            }
            let value = CandidateProofResponse {
                program: self.request.program.clone(),
                public_values: value.public_values.to_vec(),
                proof: value.proof,
            };
            if !valid_response(&self.request, self.valid.native(), &value) {
                return Err(TransportError::Response);
            }
            Ok(value)
        })();
        self.remember(result)
    }
}
impl BroadcastTransport for FixtureTransport {
    fn recheck(
        &mut self,
        plan: &Plan,
    ) -> Result<(Anchored<ClockObservation>, Anchored<ReportObservation>), ()> {
        let result = (|| {
            let payload = self.plan_payload(plan)?;
            let value: RecheckPayload = self.call(Operation::Recheck, payload)?;
            if value.clock.value != plan.clock.value
                || !valid_reports(&self.request, &self.valid, &value.reports.value)
                || value.reports.value.epoch != plan.reports.value.epoch
                || value.reports.value.observed_at_seconds < plan.reports.value.observed_at_seconds
            {
                return Err(TransportError::Response);
            }
            Ok((value.clock, value.reports))
        })();
        self.remember(result)
    }
    fn broadcast(&mut self, plan: &Plan) -> Result<(), ()> {
        let result = self
            .plan_payload(plan)
            .and_then(|bytes| self.call::<()>(Operation::BroadcastFixture, bytes));
        self.remember(result)
    }
    fn lookup(&mut self, plan: &Plan) -> Result<Lookup<OutcomeValue>, ()> {
        let result = (|| {
            let payload = self.plan_payload(plan)?;
            let value: WireLookup<OutcomeValue> = self.call(Operation::LookupOutcome, payload)?;
            if let WireLookup::Finalized(outcome) = &value {
                validate_outcome(plan, outcome).map_err(|_| TransportError::Response)?;
            }
            Ok(value.into())
        })();
        self.remember(result)
    }
}

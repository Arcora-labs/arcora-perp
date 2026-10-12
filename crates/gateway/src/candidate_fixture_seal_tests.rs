//! Signed/sealed owned loopback fixtures, over the unchanged #50 native corpus.
//! Software fixture keys, opaque proof bytes and all remote outcomes are synthetic.
//! No production service, approved operator, real DON/proof or custody is accepted.
use crate::{
    candidate_broadcast::{plan_bytes, OutcomeValue, Plan, RunMode},
    candidate_broadcast_store::{decode_sealed, Record as BroadcastRecord},
    candidate_fixture_seal::{
        open_frame, seal_frame, sealed_wire_bound, ChannelPins, Direction, FixtureKeys,
        FrameContext, ReplayReceiver, SealError, SealedChannel, MAX_REPLAY_CAPACITY,
        MAX_SEALED_FRAME, MIN_SEALED_FRAME, SEALED_CONTENT_TYPE, SEALED_EXCHANGE_PATH,
        SEALED_HEADER_BYTES, SEALED_OVERHEAD,
    },
    candidate_fixture_transport::{
        decode_payload, decode_request, decode_response, encode_payload, encode_request,
        encode_response, FixtureTransport, Operation, ProofPayload, RecheckPayload,
        RegistrationPayload, WireFrame, WireLookup, MAX_HEADER_BYTES,
    },
    candidate_handoff_tests::{success, HandoffFixture, BROADCAST_SEED, NONCE, SENDER},
    candidate_preparation_tests::SOURCE_SEED,
    candidate_protocol::{sha256, validate, ClockObservation, ReportObservation},
    candidate_recovery::{request_bytes, Anchored, RunMode as PrepMode},
    candidate_recovery_store::{RecoveryStore, Stage},
};
use k256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, OnceLock,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

const PREP_ACTIONS: [Operation; 8] = [
    Operation::RegisterClock,
    Operation::LookupClock,
    Operation::LookupClock,
    Operation::RegisterReports,
    Operation::LookupReports,
    Operation::LookupClock,
    Operation::LookupReports,
    Operation::ProveFixture,
];
const PREP_STAGES: [Stage; 8] = [
    Stage::ClockPending,
    Stage::ClockPending,
    Stage::ClockObserved,
    Stage::ReportsPending,
    Stage::ReportsPending,
    Stage::ReportsObserved,
    Stage::ReportsObserved,
    Stage::ReportsObserved,
];

fn session() -> [u8; 32] {
    let mut value = [0; 32];
    getrandom::getrandom(&mut value).unwrap();
    assert_ne!(value, [0; 32]);
    value
}
fn pins(fixture: &HandoffFixture, client: &FixtureKeys, server: &FixtureKeys) -> ChannelPins {
    ChannelPins {
        session_id: session(),
        local: client.public_keys(),
        remote: server.public_keys(),
        request_sha256: sha256(&request_bytes(&fixture.prep.request).unwrap()),
        program_sha256: sha256(&encode_payload(&fixture.prep.request.program).unwrap()),
    }
}
fn frame(fixture: &HandoffFixture, operation: Operation, id: u64) -> WireFrame {
    let valid = validate(&fixture.prep.request, &fixture.prep.trusted).unwrap();
    let payload = match operation {
        Operation::RegisterClock | Operation::LookupClock => encode_payload(valid.clock()).unwrap(),
        Operation::RegisterReports | Operation::LookupReports => {
            encode_payload(&RegistrationPayload::from(valid.registration())).unwrap()
        }
        Operation::ProveFixture => request_bytes(&fixture.prep.request).unwrap(),
        Operation::BroadcastFixture | Operation::LookupOutcome | Operation::Recheck => {
            if !fixture.prep.source_path.exists() {
                fixture.prepare();
            }
            plan_bytes(&fixture.plan()).unwrap()
        }
    };
    WireFrame {
        operation,
        request_sha256: sha256(&request_bytes(&fixture.prep.request).unwrap()),
        program_sha256: sha256(&encode_payload(&fixture.prep.request.program).unwrap()),
        exchange_id: id,
        request_payload_sha256: sha256(&payload),
        request_payload_len: payload.len() as u32,
        payload,
    }
}

#[derive(Clone, Copy)]
enum FaultKind {
    LostAck,
    RequestCipher,
    RequestPlaintext,
    ResponseCipher,
    ResponsePlaintext,
    ResponseReflection,
}
struct Fault {
    operation: Operation,
    kind: FaultKind,
}
#[derive(Clone)]
struct Event {
    operation: Operation,
    stage: Stage,
}
#[derive(Default)]
struct Remote {
    events: Vec<Event>,
    clocks: usize,
    reports: usize,
    proofs: usize,
    broadcasts: usize,
    authenticated_refusals: Vec<SealError>,
    requests: Vec<Vec<u8>>,
    responses: Vec<Vec<u8>>,
}
struct Data {
    request: Vec<u8>,
    clock: Anchored<ClockObservation>,
    reports: Anchored<ReportObservation>,
    registration: RegistrationPayload,
    proof: ProofPayload,
    program_sha256: [u8; 32],
    source_path: PathBuf,
    broadcast_path: PathBuf,
    plan: Arc<Mutex<Option<Vec<u8>>>>,
}
struct Server {
    endpoint: SocketAddr,
    remote: Arc<Mutex<Remote>>,
    plan: Arc<Mutex<Option<Vec<u8>>>>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
    channel: Mutex<Option<SealedChannel>>,
    keys: Arc<FixtureKeys>,
    pins: ChannelPins,
}
impl Server {
    fn new(fixture: &HandoffFixture, fault: Option<Fault>) -> Self {
        let client = FixtureKeys::random().unwrap();
        let keys = Arc::new(FixtureKeys::random().unwrap());
        let client_pins = pins(fixture, &client, &keys);
        let server_pins = client_pins.reverse();
        let channel = SealedChannel::new(client, client_pins, 256).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap();
        let valid = validate(&fixture.prep.request, &fixture.prep.trusted).unwrap();
        let plan = Arc::new(Mutex::new(None));
        let data = Data {
            request: request_bytes(&fixture.prep.request).unwrap(),
            clock: fixture.prep.clock_read(),
            reports: fixture.prep.report_read(),
            registration: RegistrationPayload::from(valid.registration()),
            proof: ProofPayload::from_response(&fixture.prep.response()).unwrap(),
            program_sha256: client_pins.program_sha256,
            source_path: fixture.prep.source_path.clone(),
            broadcast_path: fixture.coordinator().broadcast_path().to_path_buf(),
            plan: plan.clone(),
        };
        let remote = Arc::new(Mutex::new(Remote::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let worker_remote = remote.clone();
        let worker_stop = stop.clone();
        let worker_keys = keys.clone();
        let worker = thread::spawn(move || {
            let mut fault = fault;
            let mut receiver = ReplayReceiver::new(256).unwrap();
            for incoming in listener.incoming() {
                let mut socket = incoming.unwrap();
                if worker_stop.load(Ordering::SeqCst) {
                    break;
                }
                socket
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                socket
                    .set_write_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut outer = read_http(&mut socket);
                worker_remote.lock().unwrap().requests.push(outer.clone());
                // Fault injection models wire corruption before peer auth. It
                // cannot move source lookup, native decode or effects earlier.
                if fault
                    .as_ref()
                    .is_some_and(|f| matches!(f.kind, FaultKind::RequestCipher))
                {
                    *outer.last_mut().unwrap() ^= 1;
                    fault.take();
                } else if fault
                    .as_ref()
                    .is_some_and(|f| matches!(f.kind, FaultKind::RequestPlaintext))
                {
                    outer = encode_request(&frame_from_clock(&data, 7)).unwrap();
                    fault.take();
                }
                let inner = match receiver.open_request(&worker_keys, &server_pins, &outer) {
                    Ok(inner) => inner,
                    Err(error) => {
                        worker_remote
                            .lock()
                            .unwrap()
                            .authenticated_refusals
                            .push(error);
                        continue;
                    }
                };
                let request = decode_request(&inner).unwrap();
                assert_eq!(request.request_sha256, sha256(&data.request));
                let source = RecoveryStore::new(data.source_path.clone(), SOURCE_SEED)
                    .load()
                    .unwrap()
                    .unwrap();
                let mut remote = worker_remote.lock().unwrap();
                remote.events.push(Event {
                    operation: request.operation,
                    stage: source.stage,
                });
                let payload = response_payload(&data, &request, &mut remote);
                let reply = encode_response(&request, &payload).unwrap();
                let mut sealed =
                    seal_frame(&worker_keys, &server_pins, Direction::Response, &reply).unwrap();
                let kind = if fault
                    .as_ref()
                    .is_some_and(|f| f.operation == request.operation)
                {
                    Some(fault.take().unwrap().kind)
                } else {
                    None
                };
                match kind {
                    Some(FaultKind::ResponseCipher) => {
                        *sealed.last_mut().unwrap() ^= 1;
                    }
                    Some(FaultKind::ResponsePlaintext) => sealed = reply,
                    Some(FaultKind::ResponseReflection) => sealed = outer,
                    _ => {}
                }
                remote.responses.push(sealed.clone());
                drop(remote);
                if matches!(kind, Some(FaultKind::LostAck)) {
                    continue;
                }
                write_http(&mut socket, &sealed);
            }
        });
        Self {
            endpoint,
            remote,
            plan,
            stop,
            worker: Some(worker),
            channel: Mutex::new(Some(channel)),
            keys,
            pins: server_pins,
        }
    }
    fn adapter(&self, fixture: &HandoffFixture) -> FixtureTransport {
        FixtureTransport::new(
            self.endpoint,
            &fixture.prep.request,
            &fixture.prep.trusted,
            &fixture.bridge,
            SENDER,
            NONCE,
        )
        .unwrap()
        .with_sealed_channel(self.channel.lock().unwrap().take().unwrap())
        .unwrap()
    }
    fn pin_plan(&self, fixture: &HandoffFixture) -> Plan {
        let plan = fixture.plan();
        *self.plan.lock().unwrap() = Some(plan_bytes(&plan).unwrap());
        plan
    }
    fn actions(&self) -> Vec<Operation> {
        self.remote
            .lock()
            .unwrap()
            .events
            .iter()
            .map(|event| event.operation)
            .collect()
    }
    fn effects(&self) -> (usize, usize, usize, usize) {
        let r = self.remote.lock().unwrap();
        (r.clocks, r.reports, r.proofs, r.broadcasts)
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.endpoint);
        self.worker.take().unwrap().join().unwrap();
    }
}
fn frame_from_clock(data: &Data, id: u64) -> WireFrame {
    let payload = encode_payload(&data.clock.value.context).unwrap();
    WireFrame {
        operation: Operation::RegisterClock,
        request_sha256: sha256(&data.request),
        program_sha256: data.program_sha256,
        exchange_id: id,
        request_payload_sha256: sha256(&payload),
        request_payload_len: payload.len() as u32,
        payload,
    }
}
fn read_http(socket: &mut TcpStream) -> Vec<u8> {
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        assert!(header.len() < MAX_HEADER_BYTES);
        let mut byte = [0];
        socket.read_exact(&mut byte).unwrap();
        header.push(byte[0]);
    }
    let header = std::str::from_utf8(&header).unwrap();
    let mut lines = header.split("\r\n");
    assert_eq!(
        lines.next(),
        Some(format!("POST {SEALED_EXCHANGE_PATH} HTTP/1.1").as_str())
    );
    let lengths: Vec<_> = lines
        .clone()
        .filter_map(|line| line.strip_prefix("Content-Length: "))
        .collect();
    assert_eq!(lengths.len(), 1);
    let len: usize = lengths[0].parse().unwrap();
    assert!(len <= MAX_SEALED_FRAME);
    assert!(lines.any(|line| line == format!("Content-Type: {SEALED_CONTENT_TYPE}")));
    let mut body = vec![0; len];
    socket.read_exact(&mut body).unwrap();
    body
}
fn write_http(socket: &mut TcpStream, body: &[u8]) {
    let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: {SEALED_CONTENT_TYPE}\r\nConnection: close\r\n\r\n", body.len());
    if socket.write_all(head.as_bytes()).is_ok() {
        let _ = socket.write_all(body);
    }
}
fn broadcast_record(path: &Path) -> Option<BroadcastRecord> {
    path.is_file()
        .then(|| decode_sealed(&std::fs::read(path).unwrap(), &BROADCAST_SEED).unwrap())
}
fn response_payload(data: &Data, request: &WireFrame, remote: &mut Remote) -> Vec<u8> {
    match request.operation {
        Operation::RegisterClock | Operation::LookupClock => {
            assert_eq!(
                request.payload,
                encode_payload(&data.clock.value.context).unwrap()
            );
            if request.operation == Operation::RegisterClock {
                assert_eq!(remote.events.last().unwrap().stage, Stage::ClockPending);
                remote.clocks += 1;
                encode_payload(&()).unwrap()
            } else if remote.clocks > 0 {
                encode_payload(&WireLookup::Finalized(data.clock.clone())).unwrap()
            } else {
                encode_payload(&WireLookup::<ClockObservation>::Absent).unwrap()
            }
        }
        Operation::RegisterReports | Operation::LookupReports => {
            assert_eq!(request.payload, encode_payload(&data.registration).unwrap());
            if request.operation == Operation::RegisterReports {
                assert_eq!(remote.events.last().unwrap().stage, Stage::ReportsPending);
                remote.reports += 1;
                encode_payload(&()).unwrap()
            } else if remote.reports > 0 {
                encode_payload(&WireLookup::Finalized(data.reports.clone())).unwrap()
            } else {
                encode_payload(&WireLookup::<ReportObservation>::Absent).unwrap()
            }
        }
        Operation::ProveFixture => {
            assert_eq!(request.payload, data.request);
            assert_eq!(remote.events.last().unwrap().stage, Stage::ReportsObserved);
            remote.proofs += 1;
            encode_payload(&data.proof).unwrap()
        }
        Operation::Recheck | Operation::BroadcastFixture | Operation::LookupOutcome => {
            assert_eq!(remote.events.last().unwrap().stage, Stage::Prepared);
            let expected = data.plan.lock().unwrap().clone().unwrap();
            assert_eq!(request.payload, expected);
            let plan: Plan = decode_payload(&request.payload).unwrap();
            if request.operation == Operation::Recheck {
                encode_payload(&RecheckPayload {
                    clock: data.clock.clone(),
                    reports: data.reports.clone(),
                })
                .unwrap()
            } else {
                let pending = broadcast_record(&data.broadcast_path).unwrap();
                assert_eq!(pending.plan, expected);
                assert!(pending.outcome.is_none());
                if request.operation == Operation::BroadcastFixture {
                    remote.broadcasts += 1;
                    encode_payload(&()).unwrap()
                } else if remote.broadcasts > 0 {
                    encode_payload(&WireLookup::Finalized(success(&plan))).unwrap()
                } else {
                    encode_payload(&WireLookup::<OutcomeValue>::Absent).unwrap()
                }
            }
        }
    }
}

fn prepare(
    fixture: &HandoffFixture,
    adapter: &mut FixtureTransport,
    mode: PrepMode,
) -> Result<crate::candidate_recovery::PreparedCut, crate::candidate_handoff::HandoffError> {
    fixture
        .coordinator()
        .prepare(mode, &fixture.prep.request, &fixture.prep.trusted, adapter)
}
fn handoff(
    fixture: &HandoffFixture,
    adapter: &mut FixtureTransport,
    mode: RunMode,
) -> Result<crate::candidate_broadcast::Outcome, crate::candidate_handoff::HandoffError> {
    fixture.coordinator().handoff(
        mode,
        &fixture.prep.request,
        &fixture.prep.trusted,
        &fixture.bridge,
        SENDER,
        NONCE,
        adapter,
    )
}
fn positive(flow: usize) {
    let fixture = HandoffFixture::new(flow);
    let server = Server::new(&fixture, None);
    let mut adapter = server.adapter(&fixture);
    let cut = prepare(&fixture, &mut adapter, PrepMode::Fresh).unwrap();
    assert_eq!(cut.record.stage, Stage::Prepared);
    assert_eq!(cut.prepared.response, fixture.prep.response());
    assert_eq!(
        cut.prepared.native,
        chainlink_oracle::binding::run_encoded(&fixture.prep.request.witness).unwrap()
    );
    assert_eq!(server.actions(), PREP_ACTIONS);
    assert_eq!(
        server
            .remote
            .lock()
            .unwrap()
            .events
            .iter()
            .map(|e| e.stage)
            .collect::<Vec<_>>(),
        PREP_STAGES
    );
    let plan = server.pin_plan(&fixture);
    let outcome = handoff(&fixture, &mut adapter, RunMode::Fresh).unwrap();
    assert_eq!(outcome, success(&plan));
    assert_eq!(server.effects(), (1, 1, 1, 1));
    let mut actions = PREP_ACTIONS.to_vec();
    actions.extend([
        Operation::Recheck,
        Operation::BroadcastFixture,
        Operation::LookupOutcome,
    ]);
    assert_eq!(server.actions(), actions);
    let coordinator = fixture.coordinator();
    let source = std::fs::read(coordinator.source_path()).unwrap();
    let target = std::fs::read(coordinator.broadcast_path()).unwrap();
    assert_eq!(
        prepare(&fixture, &mut adapter, PrepMode::Resume).unwrap(),
        cut
    );
    assert_eq!(
        handoff(&fixture, &mut adapter, RunMode::Resume).unwrap(),
        outcome
    );
    assert_eq!(server.actions(), actions);
    assert_eq!(std::fs::read(coordinator.source_path()).unwrap(), source);
    assert_eq!(std::fs::read(coordinator.broadcast_path()).unwrap(), target);
    let remote = server.remote.lock().unwrap();
    assert!(remote.authenticated_refusals.is_empty());
    for wire in remote.requests.iter().chain(&remote.responses) {
        assert!(decode_request(wire).is_err() && decode_response(wire).is_err());
        assert!(!wire
            .windows(fixture.prep.request.witness.len())
            .any(|w| w == fixture.prep.request.witness));
        for entry in &fixture.prep.request.material.entries {
            for literal in [&entry.base_report, &entry.quote_report] {
                assert!(!wire.windows(literal.len()).any(|w| w == literal.as_slice()));
            }
        }
    }
    for wire in &remote.requests {
        let inner = open_frame(&server.keys, &server.pins, Direction::Request, wire, None).unwrap();
        let request = decode_request(&inner).unwrap();
        assert_eq!(request.request_sha256, server.pins.request_sha256);
        assert_eq!(request.program_sha256, server.pins.program_sha256);
    }
}
fn baselines() {
    static PASSED: OnceLock<()> = OnceLock::new();
    PASSED.get_or_init(|| {
        positive(0);
        positive(1);
    });
}

#[test]
fn candidate_fixture_sealed_both_native_flows_prepare_handoff_and_terminal_replay() {
    baselines();
}

struct Pair {
    fixture: HandoffFixture,
    client: FixtureKeys,
    server: FixtureKeys,
    pins: ChannelPins,
}
impl Pair {
    fn new() -> Self {
        let fixture = HandoffFixture::new(0);
        let client = FixtureKeys::random().unwrap();
        let server = FixtureKeys::random().unwrap();
        let pins = pins(&fixture, &client, &server);
        Self {
            fixture,
            client,
            server,
            pins,
        }
    }
    fn request(&self, operation: Operation, id: u64) -> (WireFrame, Vec<u8>, Vec<u8>) {
        let request = frame(&self.fixture, operation, id);
        let inner = encode_request(&request).unwrap();
        let outer = seal_frame(&self.client, &self.pins, Direction::Request, &inner).unwrap();
        (request, inner, outer)
    }
}

#[test]
fn candidate_fixture_sealed_codec_exact_roundtrip_fresh_cipher_and_response_context() {
    baselines();
    let pair = Pair::new();
    let (request, inner, outer) = pair.request(Operation::ProveFixture, 42);
    let second = seal_frame(&pair.client, &pair.pins, Direction::Request, &inner).unwrap();
    assert_ne!(outer, second);
    let context = FrameContext::from_frame(&request).unwrap();
    assert_eq!(
        open_frame(
            &pair.server,
            &pair.pins.reverse(),
            Direction::Request,
            &outer,
            Some(&context)
        )
        .unwrap(),
        inner
    );
    let payload =
        encode_payload(&ProofPayload::from_response(&pair.fixture.prep.response()).unwrap())
            .unwrap();
    let response = encode_response(&request, &payload).unwrap();
    let response_outer = seal_frame(
        &pair.server,
        &pair.pins.reverse(),
        Direction::Response,
        &response,
    )
    .unwrap();
    assert_eq!(
        open_frame(
            &pair.client,
            &pair.pins,
            Direction::Response,
            &response_outer,
            Some(&context)
        )
        .unwrap(),
        response
    );
    assert!(outer.len() > inner.len());
    assert!(!outer.windows(inner.len()).any(|bytes| bytes == inner));
}

#[test]
fn candidate_fixture_sealed_codec_configured_keys_and_session_refusals() {
    baselines();
    let pair = Pair::new();
    let (_, _, outer) = pair.request(Operation::RegisterClock, 42);
    let wrong = FixtureKeys::random().unwrap();
    assert!(open_frame(
        &wrong,
        &pair.pins.reverse(),
        Direction::Request,
        &outer,
        None
    )
    .is_err());
    for which in 0..7 {
        let mut pins = pair.pins.reverse();
        match which {
            0 => pins.remote.signing = wrong.public_keys().signing,
            1 => pins.remote.x25519 = wrong.public_keys().x25519,
            2 => pins.local.signing = wrong.public_keys().signing,
            3 => pins.local.x25519 = wrong.public_keys().x25519,
            4 => pins.session_id = session(),
            5 => pins.request_sha256[0] ^= 1,
            6 => pins.program_sha256[0] ^= 1,
            _ => unreachable!(),
        }
        assert!(open_frame(&pair.server, &pins, Direction::Request, &outer, None).is_err());
    }
    assert!(open_frame(
        &pair.server,
        &pair.pins.reverse(),
        Direction::Response,
        &outer,
        None
    )
    .is_err());
    assert!(open_frame(&pair.client, &pair.pins, Direction::Request, &outer, None).is_err());
}

#[test]
fn candidate_fixture_sealed_codec_exact_operation_exchange_payload_context_refusals() {
    baselines();
    let pair = Pair::new();
    let (request, _, outer) = pair.request(Operation::RegisterClock, 42);
    let expected = FrameContext::from_frame(&request).unwrap();
    for which in 0..6 {
        let mut context = expected;
        match which {
            0 => context.operation = Operation::LookupClock,
            1 => context.exchange_id += 1,
            2 => context.request_sha256[0] ^= 1,
            3 => context.program_sha256[0] ^= 1,
            4 => context.request_payload_sha256[0] ^= 1,
            5 => context.request_payload_len += 1,
            _ => unreachable!(),
        }
        assert_eq!(
            open_frame(
                &pair.server,
                &pair.pins.reverse(),
                Direction::Request,
                &outer,
                Some(&context)
            ),
            Err(SealError::Context)
        );
    }
}

#[test]
fn candidate_fixture_sealed_codec_header_cipher_signature_and_tag_tamper_refusals() {
    baselines();
    let pair = Pair::new();
    let (_, _, outer) = pair.request(Operation::RegisterClock, 42);
    // Includes magic/version/direction/scope/approval/reserved/session/peer keys,
    // request/program/action/exchange/hash/length/inner digest and box/tag/signature.
    let positions = [
        0,
        9,
        10,
        11,
        12,
        13,
        16,
        48,
        81,
        114,
        146,
        178,
        210,
        242,
        243,
        246,
        254,
        289,
        290,
        294,
        326,
        SEALED_HEADER_BYTES,
        SEALED_HEADER_BYTES + 1,
        SEALED_HEADER_BYTES + 33,
        SEALED_HEADER_BYTES + 57,
        outer.len() - 65,
        outer.len() - 64,
        outer.len() - 1,
    ];
    for position in positions {
        let mut altered = outer.clone();
        altered[position] ^= 1;
        assert!(
            open_frame(
                &pair.server,
                &pair.pins.reverse(),
                Direction::Request,
                &altered,
                None
            )
            .is_err(),
            "field {position}"
        );
    }
}

#[test]
fn candidate_fixture_sealed_codec_length_bounds_trailing_and_plain_frame_refused() {
    baselines();
    let pair = Pair::new();
    let (_, inner, outer) = pair.request(Operation::RegisterClock, 42);
    assert_eq!(
        sealed_wire_bound(crate::candidate_fixture_transport::FRAME_HEADER_BYTES).unwrap(),
        MIN_SEALED_FRAME
    );
    assert_eq!(
        sealed_wire_bound(crate::candidate_fixture_transport::MAX_FRAME_BYTES).unwrap(),
        MAX_SEALED_FRAME
    );
    assert_eq!(
        MAX_SEALED_FRAME - crate::candidate_fixture_transport::MAX_FRAME_BYTES,
        SEALED_OVERHEAD
    );
    assert!(sealed_wire_bound(0).is_err());
    assert!(sealed_wire_bound(usize::MAX).is_err());
    assert!(open_frame(
        &pair.server,
        &pair.pins.reverse(),
        Direction::Request,
        &inner,
        None
    )
    .is_err());
    for length in [
        0,
        8,
        SEALED_HEADER_BYTES,
        MIN_SEALED_FRAME - 1,
        outer.len() - 1,
    ] {
        assert!(open_frame(
            &pair.server,
            &pair.pins.reverse(),
            Direction::Request,
            &outer[..length],
            None
        )
        .is_err());
    }
    let mut trailing = outer.clone();
    trailing.push(0);
    assert_eq!(
        open_frame(
            &pair.server,
            &pair.pins.reverse(),
            Direction::Request,
            &trailing,
            None
        ),
        Err(SealError::Bounds)
    );
    let mut huge = outer;
    huge[290..294].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(
        open_frame(
            &pair.server,
            &pair.pins.reverse(),
            Direction::Request,
            &huge,
            None
        ),
        Err(SealError::Bounds)
    );
}

#[test]
fn candidate_fixture_sealed_codec_canonical_peer_keys_and_low_order_refusals() {
    baselines();
    let pair = Pair::new();
    let (_, inner, _) = pair.request(Operation::RegisterClock, 42);
    for which in 0..5 {
        let mut pins = pair.pins;
        match which {
            0 => pins.remote.signing[0] = 4,
            1 => pins.remote.x25519 = [0; 32],
            2 => {
                pins.remote.x25519 = [0; 32];
                pins.remote.x25519[0] = 1;
            }
            3 => {
                pins.remote.x25519 = [0xff; 32];
                pins.remote.x25519[0] = 0xed;
                pins.remote.x25519[31] = 0x7f;
            }
            4 => pins.remote.x25519[31] |= 0x80,
            _ => unreachable!(),
        }
        assert!(seal_frame(&pair.client, &pins, Direction::Request, &inner).is_err());
    }
    let mut equal = pair.pins;
    equal.remote = equal.local;
    assert_eq!(
        seal_frame(&pair.client, &equal, Direction::Request, &inner),
        Err(SealError::Pins)
    );
    assert!(FixtureKeys::from_seed([0; 32], [1; 32]).is_err());
}

#[test]
fn candidate_fixture_sealed_receiver_cipher_replay_and_mutation_new_exchange_refused() {
    baselines();
    for operation in [
        Operation::RegisterClock,
        Operation::RegisterReports,
        Operation::BroadcastFixture,
    ] {
        let pair = Pair::new();
        let (_, inner, outer) = pair.request(operation, 42);
        let mut receiver = ReplayReceiver::new(4).unwrap();
        assert_eq!(
            receiver
                .open_request(&pair.server, &pair.pins.reverse(), &outer)
                .unwrap(),
            inner
        );
        assert_eq!(
            receiver.open_request(&pair.server, &pair.pins.reverse(), &outer),
            Err(SealError::Replay)
        );
        let (_, _, again) = pair.request(operation, 43);
        assert_eq!(
            receiver.open_request(&pair.server, &pair.pins.reverse(), &again),
            Err(SealError::Replay)
        );
        let (_, _, read) = pair.request(Operation::LookupClock, 44);
        receiver
            .open_request(&pair.server, &pair.pins.reverse(), &read)
            .unwrap();
        let (_, _, read) = pair.request(Operation::LookupClock, 45);
        receiver
            .open_request(&pair.server, &pair.pins.reverse(), &read)
            .unwrap();
    }
}

#[test]
fn candidate_fixture_sealed_replay_capacity_holds_without_eviction_or_rejected_slot() {
    baselines();
    assert!(ReplayReceiver::new(0).is_err());
    assert!(ReplayReceiver::new(MAX_REPLAY_CAPACITY + 1).is_err());
    assert!(ReplayReceiver::new(MAX_REPLAY_CAPACITY).is_ok());
    let pair = Pair::new();
    let (_, inner, first) = pair.request(Operation::LookupClock, 1);
    let mut receiver = ReplayReceiver::new(1).unwrap();
    let mut corrupt = first.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    assert!(receiver
        .open_request(&pair.server, &pair.pins.reverse(), &corrupt)
        .is_err());
    assert_eq!(
        receiver
            .open_request(&pair.server, &pair.pins.reverse(), &first)
            .unwrap(),
        inner
    );
    let (_, _, next) = pair.request(Operation::LookupClock, 2);
    assert_eq!(
        receiver.open_request(&pair.server, &pair.pins.reverse(), &next),
        Err(SealError::Capacity)
    );
    assert_eq!(
        receiver.open_request(&pair.server, &pair.pins.reverse(), &first),
        Err(SealError::Replay)
    );
    assert_eq!(
        receiver.open_request(&pair.server, &pair.pins.reverse(), &next),
        Err(SealError::Capacity)
    );
}

#[test]
fn candidate_fixture_sealed_receiver_session_pins_do_not_reset_replay_memory() {
    baselines();
    let pair = Pair::new();
    let (_, inner, first) = pair.request(Operation::RegisterClock, 1);
    let mut receiver = ReplayReceiver::new(4).unwrap();
    receiver
        .open_request(&pair.server, &pair.pins.reverse(), &first)
        .unwrap();
    let mut new_pins = pair.pins;
    new_pins.session_id = session();
    let fresh_session = seal_frame(&pair.client, &new_pins, Direction::Request, &inner).unwrap();
    assert_eq!(
        receiver.open_request(&pair.server, &new_pins.reverse(), &fresh_session),
        Err(SealError::Pins)
    );
    assert_eq!(
        receiver.open_request(&pair.server, &pair.pins.reverse(), &first),
        Err(SealError::Replay)
    );
    // New receiver/session deliberately has no previous durable history. This
    // demonstrates the scope rather than claiming cross-session exactly-once.
    let mut fresh = ReplayReceiver::new(4).unwrap();
    assert_eq!(
        fresh
            .open_request(&pair.server, &new_pins.reverse(), &fresh_session)
            .unwrap(),
        inner
    );
}

#[test]
fn candidate_fixture_sealed_client_response_requires_prior_wrap_exact_context_once() {
    baselines();
    let pair = Pair::new();
    let request = frame(&pair.fixture, Operation::LookupClock, 1);
    let inner = encode_request(&request).unwrap();
    let response = encode_response(
        &request,
        &encode_payload(&WireLookup::Finalized(pair.fixture.prep.clock_read())).unwrap(),
    )
    .unwrap();
    let outer = seal_frame(
        &pair.server,
        &pair.pins.reverse(),
        Direction::Response,
        &response,
    )
    .unwrap();
    let channel = SealedChannel::new(pair.client, pair.pins, 2).unwrap();
    assert_eq!(*channel.pins(), pair.pins);
    assert_eq!(
        channel.open_response(&outer, &request),
        Err(SealError::Context)
    );
    channel.wrap_request(&inner).unwrap();
    assert_eq!(channel.open_response(&outer, &request).unwrap(), response);
    assert_eq!(
        channel.open_response(&outer, &request),
        Err(SealError::Replay)
    );
    assert_eq!(channel.wrap_request(&inner), Err(SealError::Replay));
    let mut other = request;
    other.exchange_id += 1;
    assert_eq!(
        channel.open_response(&outer, &other),
        Err(SealError::Context)
    );
}

#[test]
fn candidate_fixture_sealed_with_channel_wrong_request_program_pins_is_pre_wire() {
    baselines();
    for which in 0..2 {
        let pair = Pair::new();
        let mut pins = pair.pins;
        if which == 0 {
            pins.request_sha256[0] ^= 1;
        } else {
            pins.program_sha256[0] ^= 1;
        }
        let channel = SealedChannel::new(pair.client, pins, 16).unwrap();
        let endpoint: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let plain = FixtureTransport::new(
            endpoint,
            &pair.fixture.prep.request,
            &pair.fixture.prep.trusted,
            &pair.fixture.bridge,
            SENDER,
            NONCE,
        )
        .unwrap();
        assert!(plain.with_sealed_channel(channel).is_err());
        assert!(!pair.fixture.prep.source_path.exists());
    }
}

#[test]
fn candidate_fixture_sealed_invalid_request_auth_or_plaintext_has_zero_peer_effects() {
    baselines();
    for kind in [FaultKind::RequestCipher, FaultKind::RequestPlaintext] {
        let fixture = HandoffFixture::new(0);
        let server = Server::new(
            &fixture,
            Some(Fault {
                operation: Operation::RegisterClock,
                kind,
            }),
        );
        let mut adapter = server.adapter(&fixture);
        assert!(prepare(&fixture, &mut adapter, PrepMode::Fresh).is_err());
        assert_eq!(fixture.source().stage, Stage::ClockPending);
        assert!(server.actions().is_empty());
        assert_eq!(server.effects(), (0, 0, 0, 0));
        assert_eq!(
            server.remote.lock().unwrap().authenticated_refusals.len(),
            1
        );
        assert!(adapter.last_error().is_some());
        assert!(!fixture.coordinator().broadcast_path().exists());
    }
}

#[test]
fn candidate_fixture_sealed_bad_ack_after_effect_keeps_pending_no_plain_fallback() {
    baselines();
    for kind in [
        FaultKind::ResponseCipher,
        FaultKind::ResponsePlaintext,
        FaultKind::ResponseReflection,
    ] {
        let fixture = HandoffFixture::new(0);
        let server = Server::new(
            &fixture,
            Some(Fault {
                operation: Operation::RegisterClock,
                kind,
            }),
        );
        let mut adapter = server.adapter(&fixture);
        assert!(prepare(&fixture, &mut adapter, PrepMode::Fresh).is_err());
        assert_eq!(fixture.source().stage, Stage::ClockPending);
        assert_eq!(server.actions(), [Operation::RegisterClock]);
        assert_eq!(server.effects(), (1, 0, 0, 0));
        let pending = std::fs::read(fixture.coordinator().source_path()).unwrap();
        assert!(prepare(&fixture, &mut adapter, PrepMode::Fresh).is_err());
        assert_eq!(
            std::fs::read(fixture.coordinator().source_path()).unwrap(),
            pending
        );
        assert_eq!(server.effects(), (1, 0, 0, 0));
        assert_eq!(server.actions(), [Operation::RegisterClock]);
        assert!(prepare(&fixture, &mut adapter, PrepMode::Resume).is_err());
        assert_eq!(fixture.source().stage, Stage::ReportsPending);
        assert_eq!(server.effects(), (1, 0, 0, 0));
        assert_eq!(
            server.actions(),
            [
                Operation::RegisterClock,
                Operation::LookupClock,
                Operation::LookupClock,
                Operation::LookupReports
            ]
        );
    }
}

#[test]
fn candidate_fixture_sealed_lost_clock_ack_resumes_lookups_and_holds_absent_reports() {
    baselines();
    let fixture = HandoffFixture::new(0);
    let server = Server::new(
        &fixture,
        Some(Fault {
            operation: Operation::RegisterClock,
            kind: FaultKind::LostAck,
        }),
    );
    let mut adapter = server.adapter(&fixture);
    assert!(prepare(&fixture, &mut adapter, PrepMode::Fresh).is_err());
    assert_eq!(fixture.source().stage, Stage::ClockPending);
    assert_eq!(server.effects(), (1, 0, 0, 0));
    assert_eq!(server.actions(), [Operation::RegisterClock]);
    assert!(prepare(&fixture, &mut adapter, PrepMode::Resume).is_err());
    assert_eq!(fixture.source().stage, Stage::ReportsPending);
    assert_eq!(
        server.actions(),
        [
            Operation::RegisterClock,
            Operation::LookupClock,
            Operation::LookupClock,
            Operation::LookupReports
        ]
    );
    assert_eq!(server.effects(), (1, 0, 0, 0));
}

#[test]
fn candidate_fixture_sealed_lost_report_ack_reconciles_without_reregistration() {
    baselines();
    let fixture = HandoffFixture::new(0);
    let server = Server::new(
        &fixture,
        Some(Fault {
            operation: Operation::RegisterReports,
            kind: FaultKind::LostAck,
        }),
    );
    let mut adapter = server.adapter(&fixture);
    assert!(prepare(&fixture, &mut adapter, PrepMode::Fresh).is_err());
    assert_eq!(fixture.source().stage, Stage::ReportsPending);
    assert_eq!(server.effects(), (1, 1, 0, 0));
    prepare(&fixture, &mut adapter, PrepMode::Resume).unwrap();
    assert_eq!(fixture.source().stage, Stage::Prepared);
    assert_eq!(server.effects(), (1, 1, 1, 0));
    assert_eq!(
        &server.actions()[4..],
        [
            Operation::LookupClock,
            Operation::LookupReports,
            Operation::LookupClock,
            Operation::LookupReports,
            Operation::ProveFixture
        ]
    );
}

#[test]
fn candidate_fixture_sealed_lost_broadcast_ack_keeps_same_plan_resume_lookup_only() {
    baselines();
    let fixture = HandoffFixture::new(0);
    let server = Server::new(
        &fixture,
        Some(Fault {
            operation: Operation::BroadcastFixture,
            kind: FaultKind::LostAck,
        }),
    );
    let mut adapter = server.adapter(&fixture);
    prepare(&fixture, &mut adapter, PrepMode::Fresh).unwrap();
    let plan = server.pin_plan(&fixture);
    let coordinator = fixture.coordinator();
    let prepared = std::fs::read(coordinator.source_path()).unwrap();
    assert!(handoff(&fixture, &mut adapter, RunMode::Fresh).is_err());
    let pending = broadcast_record(coordinator.broadcast_path()).unwrap();
    assert_eq!(pending.plan, plan_bytes(&plan).unwrap());
    assert!(pending.outcome.is_none());
    assert_eq!(server.effects(), (1, 1, 1, 1));
    assert_eq!(
        handoff(&fixture, &mut adapter, RunMode::Resume).unwrap(),
        success(&plan)
    );
    assert_eq!(server.actions().last(), Some(&Operation::LookupOutcome));
    assert_eq!(server.actions().len(), 11);
    assert_eq!(server.effects(), (1, 1, 1, 1));
    let count = server.actions().len();
    assert_eq!(
        handoff(&fixture, &mut adapter, RunMode::Resume).unwrap(),
        success(&plan)
    );
    assert_eq!(server.actions().len(), count);
    assert_eq!(std::fs::read(coordinator.source_path()).unwrap(), prepared);
}

#[test]
fn candidate_fixture_sealed_captured_request_replay_over_actual_http_has_no_effect() {
    baselines();
    let fixture = HandoffFixture::new(0);
    let server = Server::new(&fixture, None);
    let mut adapter = server.adapter(&fixture);
    prepare(&fixture, &mut adapter, PrepMode::Fresh).unwrap();
    let plan = server.pin_plan(&fixture);
    handoff(&fixture, &mut adapter, RunMode::Fresh).unwrap();
    let wire = server.remote.lock().unwrap().requests[0].clone();
    let count = server.actions().len();
    let source = std::fs::read(fixture.coordinator().source_path()).unwrap();
    let outcome = std::fs::read(fixture.coordinator().broadcast_path()).unwrap();
    let mut socket = TcpStream::connect_timeout(&server.endpoint, Duration::from_secs(2)).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let header = format!("POST {SEALED_EXCHANGE_PATH} HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\nContent-Type: {SEALED_CONTENT_TYPE}\r\nConnection: close\r\n\r\n", server.endpoint, wire.len());
    socket.write_all(header.as_bytes()).unwrap();
    socket.write_all(&wire).unwrap();
    let mut byte = [0];
    assert_eq!(socket.read(&mut byte).unwrap(), 0);
    assert_eq!(server.actions().len(), count);
    assert_eq!(server.effects(), (1, 1, 1, 1));
    assert_eq!(
        server.remote.lock().unwrap().authenticated_refusals,
        [SealError::Replay]
    );
    assert_eq!(
        std::fs::read(fixture.coordinator().source_path()).unwrap(),
        source
    );
    assert_eq!(
        std::fs::read(fixture.coordinator().broadcast_path()).unwrap(),
        outcome
    );
    assert_eq!(fixture.plan(), plan);
}

// Deliberately independent domain construction: an owned fixture signer can
// authenticate an invalid box, so signature-first tamper tests alone cannot
// establish the AEAD, box-version or contributory-ephemeral refusal branches.
fn signing_domain(header: &[u8]) -> Vec<u8> {
    let mut bytes = b"arcora/candidate-fixture/sealed/v1\0".to_vec();
    bytes.extend_from_slice(b"/candidate-fixture/sealed/v1/exchange");
    bytes.push(0);
    bytes.extend_from_slice(b"application/x-arcora-candidate-fixture-sealed-v1");
    bytes.push(0);
    bytes.extend_from_slice(header);
    bytes
}
fn resign(outer: &mut [u8], signer: &SigningKey) {
    let end = outer.len() - 64;
    let mut digest = Sha256::new();
    digest.update(signing_domain(&outer[..SEALED_HEADER_BYTES]));
    digest.update(&outer[SEALED_HEADER_BYTES..end]);
    let signature: Signature = signer.sign_prehash(&digest.finalize()).unwrap();
    let signature = signature.normalize_s().unwrap_or(signature);
    outer[end..].copy_from_slice(&signature.to_bytes());
}
fn authenticated_box(
    header: &[u8],
    inner: &[u8],
    recipient: &[u8; 32],
    signer: &SigningKey,
) -> Vec<u8> {
    let mut aad = vec![0xc7];
    aad.extend_from_slice(&signing_domain(header));
    let sealed = sealed_box::seal(recipient, inner, &aad, rand::rngs::OsRng).to_bytes();
    let mut outer = header.to_vec();
    outer.extend_from_slice(&sealed);
    outer.resize(outer.len() + 64, 0);
    resign(&mut outer, signer);
    outer
}

#[test]
fn candidate_fixture_sealed_authenticated_invalid_box_and_inner_bindings_refuse_exactly() {
    baselines();
    let fixture = HandoffFixture::new(0);
    // Fresh caller-owned random seeds let this negative fixture independently
    // sign malformed boxes. Codec secrets are never exposed or serialized.
    let mut sign_seed = [0; 32];
    let mut client_x_seed = [0; 32];
    let mut server_sign_seed = [0; 32];
    let mut server_x_seed = [0; 32];
    for seed in [
        &mut sign_seed,
        &mut client_x_seed,
        &mut server_sign_seed,
        &mut server_x_seed,
    ] {
        getrandom::getrandom(seed).unwrap();
    }
    let client = FixtureKeys::from_seed(sign_seed, client_x_seed).unwrap();
    let server = FixtureKeys::from_seed(server_sign_seed, server_x_seed).unwrap();
    let pins = pins(&fixture, &client, &server);
    let signer = SigningKey::from_slice(&sign_seed).unwrap();
    let request = frame(&fixture, Operation::RegisterClock, 42);
    let inner = encode_request(&request).unwrap();
    let outer = seal_frame(&client, &pins, Direction::Request, &inner).unwrap();
    let expected = FrameContext::from_frame(&request).unwrap();
    assert_eq!(
        open_frame(
            &server,
            &pins.reverse(),
            Direction::Request,
            &outer,
            Some(&expected)
        )
        .unwrap(),
        inner
    );
    let header = &outer[..SEALED_HEADER_BYTES];
    let independently_signed =
        authenticated_box(header, &inner, &server.public_keys().x25519, &signer);
    assert_eq!(
        open_frame(
            &server,
            &pins.reverse(),
            Direction::Request,
            &independently_signed,
            Some(&expected)
        )
        .unwrap(),
        inner
    );

    let mut tag = outer.clone();
    let tag_index = tag.len() - 65;
    tag[tag_index] ^= 1;
    resign(&mut tag, &signer);
    assert_eq!(
        open_frame(&server, &pins.reverse(), Direction::Request, &tag, None),
        Err(SealError::Decryption)
    );
    let mut aad = outer.clone();
    aad[254] ^= 1;
    resign(&mut aad, &signer);
    assert_eq!(
        open_frame(&server, &pins.reverse(), Direction::Request, &aad, None),
        Err(SealError::Decryption)
    );
    let mut wrong_version = outer.clone();
    wrong_version[SEALED_HEADER_BYTES] = 2;
    resign(&mut wrong_version, &signer);
    assert_eq!(
        open_frame(
            &server,
            &pins.reverse(),
            Direction::Request,
            &wrong_version,
            None
        ),
        Err(SealError::Framing)
    );
    for kind in 0..4 {
        let mut wrong_ephemeral = outer.clone();
        let key = &mut wrong_ephemeral[SEALED_HEADER_BYTES + 1..SEALED_HEADER_BYTES + 33];
        match kind {
            0 => key.fill(0),
            1 => {
                key.fill(0);
                key[0] = 1;
            }
            2 => {
                key.fill(0xff);
                key[0] = 0xed;
                key[31] = 0x7f;
            }
            3 => key[31] |= 0x80,
            _ => unreachable!(),
        }
        resign(&mut wrong_ephemeral, &signer);
        assert_eq!(
            open_frame(
                &server,
                &pins.reverse(),
                Direction::Request,
                &wrong_ephemeral,
                None
            ),
            Err(SealError::Key)
        );
    }
    // Re-encrypt under deliberately changed authenticated headers. Independent
    // primitive open succeeds, proving these reach the post-decrypt binding.
    let (server_secret, _) = dark_perp_attestation::ephemeral_keypair(&server_x_seed);
    for position in [294, 242] {
        let mut changed_header = header.to_vec();
        if position == 242 {
            changed_header[position] = Operation::LookupClock as u8;
        } else {
            changed_header[position] ^= 1;
        }
        let changed = authenticated_box(
            &changed_header,
            &inner,
            &server.public_keys().x25519,
            &signer,
        );
        let mut aad = vec![0xc7];
        aad.extend_from_slice(&signing_domain(&changed_header));
        let box_bytes = &changed[SEALED_HEADER_BYTES..changed.len() - 64];
        let box_value = sealed_box::SealedBox::from_bytes(box_bytes).unwrap();
        assert_eq!(
            sealed_box::unseal(&server_secret.to_bytes(), &box_value, &aad).unwrap(),
            inner
        );
        assert_eq!(
            open_frame(&server, &pins.reverse(), Direction::Request, &changed, None),
            Err(SealError::Context)
        );
    }
    let low = Signature::from_slice(&outer[outer.len() - 64..]).unwrap();
    assert!(low.normalize_s().is_none());
    let order = [
        0xffu8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36,
        0x41, 0x41,
    ];
    let mut high_outer = outer;
    let offset = high_outer.len() - 32;
    let mut borrow = 0u16;
    for i in (0..32).rev() {
        let sub = u16::from(high_outer[offset + i]) + borrow;
        let original = u16::from(order[i]);
        high_outer[offset + i] = (256 + original - sub) as u8;
        borrow = u16::from(original < sub);
    }
    assert_eq!(borrow, 0);
    let high = Signature::from_slice(&high_outer[high_outer.len() - 64..]).unwrap();
    assert_eq!(high.normalize_s().unwrap(), low);
    assert_eq!(
        open_frame(
            &server,
            &pins.reverse(),
            Direction::Request,
            &high_outer,
            None
        ),
        Err(SealError::Signature)
    );
}

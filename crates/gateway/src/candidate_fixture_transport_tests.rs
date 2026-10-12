//! Actual owned loopback HTTP over the unchanged #50 corpus. Native replay,
//! report/clock effects and opaque proof bytes are explicit test fixtures.
//! No public service, DON, real SP1 proof or chain delivery is accepted here.
use crate::{
    candidate_broadcast::{plan_bytes, BroadcastTransport, OutcomeValue, Plan, RunMode},
    candidate_broadcast_store::{decode_sealed, Record as BroadcastRecord},
    candidate_fixture_transport::{
        decode_payload, decode_request, encode_payload, encode_response, FixtureTransport,
        Operation, ProofPayload, RecheckPayload, RegistrationPayload, TransportError, WireFrame,
        WireLookup, CONTENT_TYPE, EXCHANGE_PATH, FRAME_HEADER_BYTES, MAX_FRAME_BYTES,
        MAX_HEADER_BYTES,
    },
    candidate_handoff_tests::{success, HandoffFixture, BROADCAST_SEED, NONCE, SENDER},
    candidate_preparation_tests::SOURCE_SEED,
    candidate_protocol::{sha256, validate, ClockObservation, ReportObservation},
    candidate_recovery::{request_bytes, Anchored, PreparationTransport, RunMode as PrepMode},
    candidate_recovery_store::{RecoveryStore, Stage},
};
use perp_core::clock::ClockContext;
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc, Mutex, OnceLock,
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

#[derive(Clone, Copy)]
enum WireFault {
    Magic,
    Version,
    UnknownOperation,
    DifferentOperation,
    Scope,
    FalseFlags,
    Reserved,
    Request,
    Program,
    Exchange,
    RequestPayloadHash,
    RequestPayloadLength,
    PayloadHash,
    PayloadLength,
    Trailing,
}
#[derive(Clone, Copy)]
enum HttpFault {
    DuplicateLength,
    ConflictingLength,
    MissingLength,
    Chunked,
    Compressed,
    Redirect,
    WrongContentType,
    WrongVersion,
    OversizedHeader,
    OversizedBody,
    Truncated,
    Trailing,
}
#[derive(Clone, Copy)]
enum ProofFault {
    Program,
    PublicValues,
    Empty,
    ClaimedLength,
    NoncanonicalLength,
    Trailing,
}
#[derive(Clone, Copy)]
enum FaultKind {
    LostAck,
    Stall,
    Wire(WireFault),
    Http(HttpFault),
    Proof(ProofFault),
    ReplayPrior,
    Lookup(u8),
    OutcomeLookup(u8),
    ClockAnchor,
    ReportInput,
    ReportEpoch,
    OutcomeEffect,
    OutcomeFinality,
}
struct Fault {
    operation: Operation,
    occurrence: usize,
    kind: FaultKind,
}
#[derive(Clone, Debug)]
struct Event {
    operation: Operation,
    stage: Stage,
    exchange_id: u64,
}
#[derive(Default)]
struct Remote {
    events: Vec<Event>,
    clocks: usize,
    reports: usize,
    broadcasts: usize,
    proofs: usize,
    replies: Vec<(Operation, Vec<u8>)>,
}

struct FixtureData {
    request: Vec<u8>,
    clock: Anchored<ClockObservation>,
    reports: Anchored<ReportObservation>,
    registration: RegistrationPayload,
    proof: ProofPayload,
    source_path: PathBuf,
    broadcast_path: PathBuf,
    // Native plan derivation occurs in the existing owned coordinator after
    // Prepared. The server compares its opaque bytes before any Plan decode.
    plan: Arc<Mutex<Option<Vec<u8>>>>,
}
struct Server {
    endpoint: SocketAddr,
    remote: Arc<Mutex<Remote>>,
    plan: Arc<Mutex<Option<Vec<u8>>>>,
    stop: Arc<AtomicBool>,
    release_stall: mpsc::Sender<()>,
    worker: Option<JoinHandle<()>>,
}
impl Server {
    fn new(fixture: &HandoffFixture, fault: Option<Fault>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = listener.local_addr().unwrap();
        let validated = validate(&fixture.prep.request, &fixture.prep.trusted).unwrap();
        let coordinator = fixture.coordinator();
        let plan = Arc::new(Mutex::new(None));
        let data = FixtureData {
            request: request_bytes(&fixture.prep.request).unwrap(),
            clock: fixture.prep.clock_read(),
            reports: fixture.prep.report_read(),
            registration: RegistrationPayload::from(validated.registration()),
            proof: ProofPayload::from_response(&fixture.prep.response()).unwrap(),
            source_path: fixture.prep.source_path.clone(),
            broadcast_path: coordinator.broadcast_path().to_path_buf(),
            plan: plan.clone(),
        };
        let remote = Arc::new(Mutex::new(Remote::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let (release_stall, stalled) = mpsc::channel();
        let worker_remote = remote.clone();
        let worker_stop = stop.clone();
        let worker = thread::spawn(move || {
            let mut fault = fault;
            for accepted in listener.incoming() {
                let mut stream = accepted.unwrap();
                if worker_stop.load(Ordering::SeqCst) {
                    break;
                }
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let request = read_request(&mut stream);
                let source = RecoveryStore::new(data.source_path.clone(), SOURCE_SEED)
                    .load()
                    .unwrap()
                    .unwrap();
                assert_eq!(request.request_sha256, sha256(&data.request));
                let mut state = worker_remote.lock().unwrap();
                let occurrence = state
                    .events
                    .iter()
                    .filter(|event| event.operation == request.operation)
                    .count()
                    + 1;
                state.events.push(Event {
                    operation: request.operation,
                    stage: source.stage,
                    exchange_id: request.exchange_id,
                });
                let kind = if fault.as_ref().is_some_and(|value| {
                    value.operation == request.operation && value.occurrence == occurrence
                }) {
                    Some(fault.take().unwrap().kind)
                } else {
                    None
                };
                let mut payload = response_payload(&data, &request, &mut state);
                if let Some(kind) = kind {
                    mutate_payload(kind, request.operation, &mut payload);
                }
                let mut response = encode_response(&request, &payload).unwrap();
                if let Some(FaultKind::Wire(kind)) = kind {
                    mutate_frame(kind, &mut response);
                }
                if let Some(FaultKind::ReplayPrior) = kind {
                    response = state
                        .replies
                        .iter()
                        .rev()
                        .find(|(operation, _)| *operation == request.operation)
                        .unwrap()
                        .1
                        .clone();
                }
                state.replies.push((request.operation, response.clone()));
                drop(state);
                match kind {
                    Some(FaultKind::LostAck) => continue,
                    Some(FaultKind::Stall) => {
                        let _ = stalled.recv();
                        continue;
                    }
                    Some(FaultKind::Http(kind)) => write_http(&mut stream, &response, Some(kind)),
                    _ => write_http(&mut stream, &response, None),
                }
            }
        });
        Self {
            endpoint,
            remote,
            plan,
            stop,
            release_stall,
            worker: Some(worker),
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
        let remote = self.remote.lock().unwrap();
        (
            remote.clocks,
            remote.reports,
            remote.proofs,
            remote.broadcasts,
        )
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = self.release_stall.send(());
        let _ = TcpStream::connect(self.endpoint);
        if let Some(worker) = self.worker.take() {
            worker.join().unwrap();
        }
    }
}

fn read_request(stream: &mut TcpStream) -> WireFrame {
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        assert!(header.len() < MAX_HEADER_BYTES);
        let mut byte = [0];
        stream.read_exact(&mut byte).unwrap();
        header.push(byte[0]);
    }
    let header = std::str::from_utf8(&header).unwrap();
    let mut lines = header.split("\r\n");
    assert_eq!(
        lines.next(),
        Some(format!("POST {EXCHANGE_PATH} HTTP/1.1").as_str())
    );
    let lengths: Vec<_> = lines
        .clone()
        .filter_map(|line| line.strip_prefix("Content-Length: "))
        .collect();
    assert_eq!(lengths.len(), 1);
    let length: usize = lengths[0].parse().unwrap();
    assert!(length <= MAX_FRAME_BYTES);
    assert!(lines.any(|line| line == format!("Content-Type: {CONTENT_TYPE}")));
    let mut body = vec![0; length];
    stream.read_exact(&mut body).unwrap();
    decode_request(&body).unwrap()
}

fn response_payload(data: &FixtureData, request: &WireFrame, state: &mut Remote) -> Vec<u8> {
    match request.operation {
        Operation::RegisterClock | Operation::LookupClock => {
            assert_eq!(
                request.payload,
                encode_payload(&data.clock.value.context).unwrap()
            );
            if request.operation == Operation::RegisterClock {
                assert_eq!(state.events.last().unwrap().stage, Stage::ClockPending);
                state.clocks += 1;
                encode_payload(&()).unwrap()
            } else if state.clocks > 0 {
                encode_payload(&WireLookup::Finalized(data.clock.clone())).unwrap()
            } else {
                encode_payload(&WireLookup::<ClockObservation>::Absent).unwrap()
            }
        }
        Operation::RegisterReports | Operation::LookupReports => {
            assert_eq!(request.payload, encode_payload(&data.registration).unwrap());
            if request.operation == Operation::RegisterReports {
                assert_eq!(state.events.last().unwrap().stage, Stage::ReportsPending);
                state.reports += 1;
                encode_payload(&()).unwrap()
            } else if state.reports > 0 {
                encode_payload(&WireLookup::Finalized(data.reports.clone())).unwrap()
            } else {
                encode_payload(&WireLookup::<ReportObservation>::Absent).unwrap()
            }
        }
        Operation::ProveFixture => {
            assert_eq!(state.events.last().unwrap().stage, Stage::ReportsObserved);
            // The exact pinned full request is compared as opaque bytes before
            // parsing any untrusted nested length prefix.
            assert_eq!(request.payload, data.request);
            state.proofs += 1;
            encode_payload(&data.proof).unwrap()
        }
        Operation::Recheck | Operation::BroadcastFixture | Operation::LookupOutcome => {
            assert_eq!(state.events.last().unwrap().stage, Stage::Prepared);
            let expected = data.plan.lock().unwrap().clone().unwrap();
            assert_eq!(request.payload, expected);
            let plan: Plan = decode_payload(&request.payload).unwrap();
            match request.operation {
                Operation::Recheck => encode_payload(&RecheckPayload {
                    clock: data.clock.clone(),
                    reports: data.reports.clone(),
                })
                .unwrap(),
                Operation::BroadcastFixture => {
                    let pending = broadcast_record(&data.broadcast_path).unwrap();
                    assert_eq!(pending.plan, expected);
                    assert!(pending.outcome.is_none());
                    state.broadcasts += 1;
                    encode_payload(&()).unwrap()
                }
                Operation::LookupOutcome => {
                    let pending = broadcast_record(&data.broadcast_path).unwrap();
                    assert_eq!(pending.plan, expected);
                    assert!(pending.outcome.is_none());
                    if state.broadcasts > 0 {
                        encode_payload(&WireLookup::Finalized(success(&plan))).unwrap()
                    } else {
                        encode_payload(&WireLookup::<OutcomeValue>::Absent).unwrap()
                    }
                }
                _ => unreachable!(),
            }
        }
    }
}

fn mutate_payload(kind: FaultKind, operation: Operation, payload: &mut Vec<u8>) {
    match kind {
        FaultKind::Proof(kind) => {
            assert_eq!(operation, Operation::ProveFixture);
            let mut proof: ProofPayload = decode_payload(payload).unwrap();
            match kind {
                ProofFault::Program => proof.program.vkey[0] ^= 1,
                ProofFault::PublicValues => proof.public_values[0] ^= 1,
                ProofFault::Empty => proof.proof.clear(),
                ProofFault::ClaimedLength => {
                    // 77 fixed program bytes + exact32 public; malicious usize
                    // length is rejected by the NEW bounded Vec visitor.
                    payload.truncate(109);
                    payload.extend_from_slice(&[255; 9]);
                    payload.push(1);
                    return;
                }
                ProofFault::NoncanonicalLength => {
                    assert!(proof.proof.len() < 128);
                    let prefix = payload[109] | 128;
                    payload.splice(109..110, [prefix, 0]);
                    return;
                }
                ProofFault::Trailing => {
                    payload.push(0);
                    return;
                }
            }
            *payload = encode_payload(&proof).unwrap();
        }
        FaultKind::Lookup(state) => {
            assert_eq!(operation, Operation::LookupClock);
            let value: WireLookup<ClockObservation> = match state {
                0 => WireLookup::Pending,
                1 => WireLookup::Absent,
                2 => WireLookup::Unknown,
                3 => WireLookup::Reorg,
                _ => unreachable!(),
            };
            *payload = encode_payload(&value).unwrap();
        }
        FaultKind::OutcomeLookup(state) => {
            assert_eq!(operation, Operation::LookupOutcome);
            let value: WireLookup<OutcomeValue> = match state {
                0 => WireLookup::Pending,
                1 => WireLookup::Absent,
                2 => WireLookup::Unknown,
                3 => WireLookup::Reorg,
                _ => unreachable!(),
            };
            *payload = encode_payload(&value).unwrap();
        }
        FaultKind::ClockAnchor => {
            let mut value: WireLookup<ClockObservation> = decode_payload(payload).unwrap();
            if let WireLookup::Finalized(observation) = &mut value {
                observation.anchor.block_hash[0] ^= 1;
            }
            *payload = encode_payload(&value).unwrap();
        }
        FaultKind::ReportInput | FaultKind::ReportEpoch => {
            let mut value: WireLookup<ReportObservation> = decode_payload(payload).unwrap();
            if let WireLookup::Finalized(observation) = &mut value {
                if matches!(kind, FaultKind::ReportInput) {
                    observation.value.input_hash[0] ^= 1;
                } else {
                    observation.value.epoch.round_id[0] ^= 1;
                }
            }
            *payload = encode_payload(&value).unwrap();
        }
        FaultKind::OutcomeEffect | FaultKind::OutcomeFinality => {
            let mut value: WireLookup<OutcomeValue> = decode_payload(payload).unwrap();
            if let WireLookup::Finalized(outcome) = &mut value {
                if matches!(kind, FaultKind::OutcomeFinality) {
                    outcome.finality.finalized_block_number = 44;
                } else if let crate::candidate_broadcast::OutcomeStatus::Success(effect) =
                    &mut outcome.value.status
                {
                    effect.consumed_deposit_count += 1;
                }
            }
            *payload = encode_payload(&value).unwrap();
        }
        _ => {}
    }
}
fn mutate_frame(kind: WireFault, bytes: &mut Vec<u8>) {
    match kind {
        WireFault::Magic => bytes[0] ^= 1,
        WireFault::Version => bytes[9] = 2,
        WireFault::UnknownOperation => bytes[10] = 255,
        WireFault::DifferentOperation => bytes[10] = Operation::LookupClock as u8,
        WireFault::Scope => bytes[11] = 1,
        WireFault::FalseFlags => bytes[12] = 1,
        WireFault::Reserved => bytes[13] = 1,
        WireFault::Request => bytes[16] ^= 1,
        WireFault::Program => bytes[48] ^= 1,
        WireFault::Exchange => bytes[87] ^= 1,
        WireFault::RequestPayloadHash => bytes[88] ^= 1,
        WireFault::RequestPayloadLength => bytes[123] ^= 1,
        WireFault::PayloadHash => bytes[124] ^= 1,
        WireFault::PayloadLength => bytes[159] = 1,
        WireFault::Trailing => bytes.push(0),
    }
}
fn write_http(stream: &mut TcpStream, body: &[u8], fault: Option<HttpFault>) {
    let mut head = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: {CONTENT_TYPE}\r\nConnection: close\r\n", body.len());
    match fault {
        Some(HttpFault::DuplicateLength) => {
            head.push_str(&format!("Content-Length: {}\r\n", body.len()))
        }
        Some(HttpFault::ConflictingLength) => head.push_str("Content-Length: 1\r\n"),
        Some(HttpFault::MissingLength) => {
            head = head.replace(&format!("Content-Length: {}\r\n", body.len()), "")
        }
        Some(HttpFault::Chunked) => head.push_str("Transfer-Encoding: chunked\r\n"),
        Some(HttpFault::Compressed) => head.push_str("Content-Encoding: gzip\r\n"),
        Some(HttpFault::Redirect) => head = head.replace("200 OK", "302 Found"),
        Some(HttpFault::WrongContentType) => head = head.replace(CONTENT_TYPE, "application/json"),
        Some(HttpFault::WrongVersion) => head = head.replace("HTTP/1.1", "HTTP/1.0"),
        Some(HttpFault::OversizedHeader) => {
            head.push_str(&format!("Padding: {}\r\n", "x".repeat(MAX_HEADER_BYTES)))
        }
        Some(HttpFault::OversizedBody) => {
            head = head.replace(
                &format!("Content-Length: {}", body.len()),
                &format!("Content-Length: {}", MAX_FRAME_BYTES + 1),
            )
        }
        _ => {}
    }
    head.push_str("\r\n");
    // Refusals may close before the server finishes its synthetic reply.
    if stream.write_all(head.as_bytes()).is_err() {
        return;
    }
    if matches!(fault, Some(HttpFault::Truncated)) {
        let _ = stream.write_all(&body[..body.len() - 1]);
    } else {
        let _ = stream.write_all(body);
    }
    if matches!(fault, Some(HttpFault::Trailing)) {
        let _ = stream.write_all(b"extra");
    }
}
fn broadcast_record(path: &PathBuf) -> Option<BroadcastRecord> {
    path.is_file()
        .then(|| decode_sealed(&std::fs::read(path).unwrap(), &BROADCAST_SEED).unwrap())
}

fn positive(flow: usize) {
    let fixture = HandoffFixture::new(flow);
    let server = Server::new(&fixture, None);
    let mut adapter = server.adapter(&fixture);
    let coordinator = fixture.coordinator();
    let cut = coordinator
        .prepare(
            PrepMode::Fresh,
            &fixture.prep.request,
            &fixture.prep.trusted,
            &mut adapter,
        )
        .unwrap();
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
            .map(|event| event.stage)
            .collect::<Vec<_>>(),
        PREP_STAGES
    );
    let plan = server.pin_plan(&fixture);
    let outcome = coordinator
        .handoff(
            RunMode::Fresh,
            &fixture.prep.request,
            &fixture.prep.trusted,
            &fixture.bridge,
            SENDER,
            NONCE,
            &mut adapter,
        )
        .unwrap();
    assert_eq!(outcome, success(&plan));
    let mut expected = PREP_ACTIONS.to_vec();
    expected.extend([
        Operation::Recheck,
        Operation::BroadcastFixture,
        Operation::LookupOutcome,
    ]);
    assert_eq!(server.actions(), expected);
    assert_eq!(server.effects(), (1, 1, 1, 1));
    let source_bytes = std::fs::read(coordinator.source_path()).unwrap();
    let outcome_bytes = std::fs::read(coordinator.broadcast_path()).unwrap();
    let count = server.actions().len();
    let mut resumed = server.adapter(&fixture);
    assert_eq!(
        coordinator
            .prepare(
                PrepMode::Resume,
                &fixture.prep.request,
                &fixture.prep.trusted,
                &mut resumed
            )
            .unwrap(),
        cut
    );
    assert_eq!(
        coordinator
            .handoff(
                RunMode::Resume,
                &fixture.prep.request,
                &fixture.prep.trusted,
                &fixture.bridge,
                SENDER,
                NONCE,
                &mut resumed
            )
            .unwrap(),
        outcome
    );
    assert_eq!(server.actions().len(), count);
    assert_eq!(
        std::fs::read(coordinator.source_path()).unwrap(),
        source_bytes
    );
    assert_eq!(
        std::fs::read(coordinator.broadcast_path()).unwrap(),
        outcome_bytes
    );
    let mut exchange_ids: Vec<_> = server
        .remote
        .lock()
        .unwrap()
        .events
        .iter()
        .map(|event| event.exchange_id)
        .collect();
    exchange_ids.sort_unstable();
    exchange_ids.dedup();
    assert_eq!(exchange_ids.len(), count);
    assert!(adapter.last_error().is_none());
}
fn baselines() {
    // All matrices use the same compiled transport and fixed corpus. Every
    // semantic refusal waits for these two actual HTTP/native positive flows;
    // each fault still owns a fresh fixture, listener, state and durable lane.
    // Repeating identical fsync-heavy baselines per variant adds no new input.
    static PASSED: OnceLock<()> = OnceLock::new();
    PASSED.get_or_init(|| {
        positive(0);
        positive(1);
    });
}

#[test]
fn candidate_fixture_http_both_native_flows_prepare_handoff_and_terminal_replay() {
    baselines();
}

#[test]
fn candidate_fixture_http_lost_clock_ack_resumes_lookups_and_holds_absent_reports() {
    baselines();
    let fixture = HandoffFixture::new(0);
    let server = Server::new(
        &fixture,
        Some(Fault {
            operation: Operation::RegisterClock,
            occurrence: 1,
            kind: FaultKind::LostAck,
        }),
    );
    let coordinator = fixture.coordinator();
    let mut adapter = server.adapter(&fixture);
    assert!(coordinator
        .prepare(
            PrepMode::Fresh,
            &fixture.prep.request,
            &fixture.prep.trusted,
            &mut adapter
        )
        .is_err());
    assert_eq!(fixture.source().stage, Stage::ClockPending);
    assert_eq!(server.actions(), [Operation::RegisterClock]);
    assert_eq!(server.effects(), (1, 0, 0, 0));
    let pending = std::fs::read(coordinator.source_path()).unwrap();
    assert!(coordinator
        .prepare(
            PrepMode::Fresh,
            &fixture.prep.request,
            &fixture.prep.trusted,
            &mut adapter
        )
        .is_err());
    assert_eq!(std::fs::read(coordinator.source_path()).unwrap(), pending);
    let mut resumed = server.adapter(&fixture);
    assert!(coordinator
        .prepare(
            PrepMode::Resume,
            &fixture.prep.request,
            &fixture.prep.trusted,
            &mut resumed
        )
        .is_err());
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
    assert!(!coordinator.broadcast_path().exists());
}

#[test]
fn candidate_fixture_http_lost_report_ack_reconciles_existing_effect_without_reregistration() {
    baselines();
    let fixture = HandoffFixture::new(0);
    let server = Server::new(
        &fixture,
        Some(Fault {
            operation: Operation::RegisterReports,
            occurrence: 1,
            kind: FaultKind::LostAck,
        }),
    );
    let coordinator = fixture.coordinator();
    let mut adapter = server.adapter(&fixture);
    assert!(coordinator
        .prepare(
            PrepMode::Fresh,
            &fixture.prep.request,
            &fixture.prep.trusted,
            &mut adapter
        )
        .is_err());
    assert_eq!(fixture.source().stage, Stage::ReportsPending);
    assert_eq!(server.effects(), (1, 1, 0, 0));
    let mut resumed = server.adapter(&fixture);
    coordinator
        .prepare(
            PrepMode::Resume,
            &fixture.prep.request,
            &fixture.prep.trusted,
            &mut resumed,
        )
        .unwrap();
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
fn candidate_fixture_http_lost_broadcast_ack_keeps_same_lane_and_resume_lookup_only() {
    baselines();
    let fixture = HandoffFixture::new(0);
    let server = Server::new(
        &fixture,
        Some(Fault {
            operation: Operation::BroadcastFixture,
            occurrence: 1,
            kind: FaultKind::LostAck,
        }),
    );
    let coordinator = fixture.coordinator();
    let mut adapter = server.adapter(&fixture);
    coordinator
        .prepare(
            PrepMode::Fresh,
            &fixture.prep.request,
            &fixture.prep.trusted,
            &mut adapter,
        )
        .unwrap();
    let plan = server.pin_plan(&fixture);
    let prepared = std::fs::read(coordinator.source_path()).unwrap();
    assert!(coordinator
        .handoff(
            RunMode::Fresh,
            &fixture.prep.request,
            &fixture.prep.trusted,
            &fixture.bridge,
            SENDER,
            NONCE,
            &mut adapter
        )
        .is_err());
    let pending = broadcast_record(&coordinator.broadcast_path().to_path_buf()).unwrap();
    assert_eq!(pending.plan, plan_bytes(&plan).unwrap());
    assert!(pending.outcome.is_none());
    assert_eq!(server.effects(), (1, 1, 1, 1));
    let mut resumed = server.adapter(&fixture);
    assert_eq!(
        coordinator
            .handoff(
                RunMode::Resume,
                &fixture.prep.request,
                &fixture.prep.trusted,
                &fixture.bridge,
                SENDER,
                NONCE,
                &mut resumed
            )
            .unwrap(),
        success(&plan)
    );
    assert_eq!(server.actions().last(), Some(&Operation::LookupOutcome));
    assert_eq!(server.actions().len(), 11);
    assert_eq!(server.effects(), (1, 1, 1, 1));
    assert_eq!(std::fs::read(coordinator.source_path()).unwrap(), prepared);
}

#[test]
fn candidate_fixture_http_local_constructor_pins_refuse_without_connections() {
    for index in 0..10 {
        baselines();
        let fixture = HandoffFixture::new(0);
        let server = Server::new(&fixture, None);
        let mut request = fixture.prep.request.clone();
        let mut trusted = fixture.prep.trusted.clone();
        let mut bridge = fixture.bridge.clone();
        let mut sender = SENDER;
        let mut endpoint = server.endpoint;
        match index {
            0 => request.program.wire_magic = *b"DPCLK2\0\0",
            1 => request.program.elf_sha256[0] ^= 1,
            2 => request.program.vkey[0] ^= 1,
            3 => request.program.sdk_release = "6.2.0".into(),
            4 => request.witness[0] ^= 1,
            5 => trusted.material_hash[0] ^= 1,
            6 => bridge.sp1_gateway = bridge.sp1_adapter,
            7 => bridge.prefix_vault_code_hash = [0; 32],
            8 => sender = [0; 20],
            9 => endpoint = SocketAddr::from(([192, 0, 2, 1], server.endpoint.port())),
            _ => unreachable!(),
        }
        assert!(
            FixtureTransport::new(endpoint, &request, &trusted, &bridge, sender, NONCE).is_err()
        );
        assert!(server.actions().is_empty());
        assert_eq!(server.effects(), (0, 0, 0, 0));
        assert!(!fixture.prep.source_path.exists());
    }
}

#[test]
fn candidate_fixture_http_local_callback_payload_changes_refuse_without_connections() {
    for index in 0..4 {
        baselines();
        let fixture = HandoffFixture::new(0);
        let server = Server::new(&fixture, None);
        let mut adapter = server.adapter(&fixture);
        let validated = validate(&fixture.prep.request, &fixture.prep.trusted).unwrap();
        let mut registration = validated.registration().clone();
        let result = match index {
            0 => {
                let mut clock: ClockContext = *validated.clock();
                clock.anchored_at_ms += 1;
                adapter.register_clock(&clock)
            }
            1 => {
                registration.input_hash[0] ^= 1;
                adapter.register_reports(&registration)
            }
            2 => {
                registration.entries_abi[0] ^= 1;
                adapter.register_reports(&registration)
            }
            3 => {
                let mut request = fixture.prep.request.clone();
                request.material.entries[0].base_report[0] ^= 1;
                adapter.prove(&request).map(|_| ())
            }
            _ => unreachable!(),
        };
        assert!(result.is_err());
        assert_eq!(adapter.last_error(), Some(TransportError::Request));
        assert!(server.actions().is_empty());
        assert_eq!(server.effects(), (0, 0, 0, 0));
    }
}

#[test]
fn candidate_fixture_http_response_frame_scope_identity_and_exchange_guards() {
    for kind in [
        WireFault::Magic,
        WireFault::Version,
        WireFault::UnknownOperation,
        WireFault::DifferentOperation,
        WireFault::Scope,
        WireFault::FalseFlags,
        WireFault::Reserved,
        WireFault::Request,
        WireFault::Program,
        WireFault::Exchange,
        WireFault::RequestPayloadHash,
        WireFault::RequestPayloadLength,
        WireFault::PayloadHash,
        WireFault::PayloadLength,
        WireFault::Trailing,
    ] {
        baselines();
        let fixture = HandoffFixture::new(0);
        let server = Server::new(
            &fixture,
            Some(Fault {
                operation: Operation::RegisterClock,
                occurrence: 1,
                kind: FaultKind::Wire(kind),
            }),
        );
        let mut adapter = server.adapter(&fixture);
        let coordinator = fixture.coordinator();
        assert!(coordinator
            .prepare(
                PrepMode::Fresh,
                &fixture.prep.request,
                &fixture.prep.trusted,
                &mut adapter
            )
            .is_err());
        assert!(adapter.last_error().is_some());
        assert_eq!(fixture.source().stage, Stage::ClockPending);
        // A refused post-effect response cannot promise that the remote effect
        // never happened. Only exact Pending/no-later-callback is claimed.
        assert_eq!(server.actions(), [Operation::RegisterClock]);
        assert_eq!(server.effects(), (1, 0, 0, 0));
        assert!(!coordinator.broadcast_path().exists());
    }
}

#[test]
fn candidate_fixture_http_response_header_body_bounds_and_truncation_guards() {
    for kind in [
        HttpFault::DuplicateLength,
        HttpFault::ConflictingLength,
        HttpFault::MissingLength,
        HttpFault::Chunked,
        HttpFault::Compressed,
        HttpFault::Redirect,
        HttpFault::WrongContentType,
        HttpFault::WrongVersion,
        HttpFault::OversizedHeader,
        HttpFault::OversizedBody,
        HttpFault::Truncated,
        HttpFault::Trailing,
    ] {
        baselines();
        let fixture = HandoffFixture::new(0);
        let server = Server::new(
            &fixture,
            Some(Fault {
                operation: Operation::RegisterClock,
                occurrence: 1,
                kind: FaultKind::Http(kind),
            }),
        );
        let mut adapter = server.adapter(&fixture);
        let coordinator = fixture.coordinator();
        assert!(coordinator
            .prepare(
                PrepMode::Fresh,
                &fixture.prep.request,
                &fixture.prep.trusted,
                &mut adapter
            )
            .is_err());
        assert!(adapter.last_error().is_some());
        assert_eq!(fixture.source().stage, Stage::ClockPending);
        assert_eq!(server.actions(), [Operation::RegisterClock]);
        assert_eq!(server.effects(), (1, 0, 0, 0));
    }
}

#[test]
fn candidate_fixture_http_exact_proof_program_native_and_nested_length_guards() {
    for kind in [
        ProofFault::Program,
        ProofFault::PublicValues,
        ProofFault::Empty,
        ProofFault::ClaimedLength,
        ProofFault::NoncanonicalLength,
        ProofFault::Trailing,
    ] {
        baselines();
        let fixture = HandoffFixture::new(0);
        let server = Server::new(
            &fixture,
            Some(Fault {
                operation: Operation::ProveFixture,
                occurrence: 1,
                kind: FaultKind::Proof(kind),
            }),
        );
        let mut adapter = server.adapter(&fixture);
        let coordinator = fixture.coordinator();
        assert!(coordinator
            .prepare(
                PrepMode::Fresh,
                &fixture.prep.request,
                &fixture.prep.trusted,
                &mut adapter
            )
            .is_err());
        assert!(adapter.last_error().is_some());
        assert_eq!(fixture.source().stage, Stage::ReportsObserved);
        assert_eq!(server.actions(), PREP_ACTIONS);
        assert_eq!(server.effects(), (1, 1, 1, 0));
        assert!(fixture.source().prepared.is_none());
        assert!(!coordinator.broadcast_path().exists());
    }
}

#[test]
fn candidate_fixture_http_replayed_same_operation_response_rejected_by_exchange_id() {
    baselines();
    let fixture = HandoffFixture::new(0);
    let server = Server::new(
        &fixture,
        Some(Fault {
            operation: Operation::LookupClock,
            occurrence: 2,
            kind: FaultKind::ReplayPrior,
        }),
    );
    let mut adapter = server.adapter(&fixture);
    let coordinator = fixture.coordinator();
    assert!(coordinator
        .prepare(
            PrepMode::Fresh,
            &fixture.prep.request,
            &fixture.prep.trusted,
            &mut adapter
        )
        .is_err());
    assert_eq!(adapter.last_error(), Some(TransportError::Replay));
    assert_eq!(fixture.source().stage, Stage::ClockObserved);
    assert_eq!(
        server.actions(),
        [
            Operation::RegisterClock,
            Operation::LookupClock,
            Operation::LookupClock
        ]
    );
    assert_eq!(server.effects(), (1, 0, 0, 0));
}

#[test]
fn candidate_fixture_http_lookup_states_hold_and_do_not_retry_registration() {
    for state in 0..4 {
        baselines();
        let fixture = HandoffFixture::new(0);
        let server = Server::new(
            &fixture,
            Some(Fault {
                operation: Operation::LookupClock,
                occurrence: 1,
                kind: FaultKind::Lookup(state),
            }),
        );
        let mut adapter = server.adapter(&fixture);
        let coordinator = fixture.coordinator();
        assert!(coordinator
            .prepare(
                PrepMode::Fresh,
                &fixture.prep.request,
                &fixture.prep.trusted,
                &mut adapter
            )
            .is_err());
        assert_eq!(fixture.source().stage, Stage::ClockPending);
        assert_eq!(
            server.actions(),
            [Operation::RegisterClock, Operation::LookupClock]
        );
        assert_eq!(server.effects(), (1, 0, 0, 0));
        assert!(adapter.last_error().is_none()); // Valid transport, caller HOLD.
    }
}

#[test]
fn candidate_fixture_http_observation_anchor_input_and_epoch_changes_hold() {
    for (operation, kind, stage) in [
        (
            Operation::LookupClock,
            FaultKind::ClockAnchor,
            Stage::ClockPending,
        ),
        (
            Operation::LookupReports,
            FaultKind::ReportInput,
            Stage::ReportsPending,
        ),
        (
            Operation::LookupReports,
            FaultKind::ReportEpoch,
            Stage::ReportsPending,
        ),
    ] {
        baselines();
        let fixture = HandoffFixture::new(0);
        let server = Server::new(
            &fixture,
            Some(Fault {
                operation,
                occurrence: 1,
                kind,
            }),
        );
        let mut adapter = server.adapter(&fixture);
        let coordinator = fixture.coordinator();
        assert!(coordinator
            .prepare(
                PrepMode::Fresh,
                &fixture.prep.request,
                &fixture.prep.trusted,
                &mut adapter
            )
            .is_err());
        assert_eq!(fixture.source().stage, stage);
        assert_eq!(server.effects().2, 0);
        assert_eq!(server.actions().last(), Some(&operation));
        assert!(!coordinator.broadcast_path().exists());
    }
}

#[test]
fn candidate_fixture_http_local_plan_nonce_roles_roots_and_exact_lane_refuse() {
    for index in 0..5 {
        baselines();
        let fixture = HandoffFixture::new(0);
        fixture.prepare();
        let server = Server::new(&fixture, None);
        let mut adapter = server.adapter(&fixture);
        let mut plan = server.pin_plan(&fixture);
        match index {
            0 => plan.mock_nonce += 1,
            1 => plan.mock_sender[0] ^= 1,
            2 => plan.bridge_target.prefix_vault[0] ^= 1,
            3 => plan.roots[6][0] ^= 1,
            4 => {
                adapter.recheck(&plan).unwrap();
                plan.source_cut_sha256[0] ^= 1;
            }
            _ => unreachable!(),
        }
        let before = server.actions().len();
        assert!(adapter.broadcast(&plan).is_err());
        assert_eq!(adapter.last_error(), Some(TransportError::Plan));
        assert_eq!(server.actions().len(), before);
        assert_eq!(server.effects(), (0, 0, 0, 0));
    }
}

#[test]
fn candidate_fixture_http_outcome_effect_and_finality_refusals_preserve_pending() {
    for kind in [FaultKind::OutcomeEffect, FaultKind::OutcomeFinality] {
        baselines();
        let fixture = HandoffFixture::new(0);
        let server = Server::new(
            &fixture,
            Some(Fault {
                operation: Operation::LookupOutcome,
                occurrence: 1,
                kind,
            }),
        );
        let mut adapter = server.adapter(&fixture);
        let coordinator = fixture.coordinator();
        coordinator
            .prepare(
                PrepMode::Fresh,
                &fixture.prep.request,
                &fixture.prep.trusted,
                &mut adapter,
            )
            .unwrap();
        server.pin_plan(&fixture);
        let prepared = std::fs::read(coordinator.source_path()).unwrap();
        assert!(coordinator
            .handoff(
                RunMode::Fresh,
                &fixture.prep.request,
                &fixture.prep.trusted,
                &fixture.bridge,
                SENDER,
                NONCE,
                &mut adapter
            )
            .is_err());
        assert!(
            broadcast_record(&coordinator.broadcast_path().to_path_buf())
                .unwrap()
                .outcome
                .is_none()
        );
        assert_eq!(std::fs::read(coordinator.source_path()).unwrap(), prepared);
        assert_eq!(server.effects(), (1, 1, 1, 1));
        assert_eq!(server.actions().len(), 11);
    }
}

#[test]
fn candidate_fixture_http_stalled_owned_peer_has_finite_deadline_and_one_effect() {
    baselines();
    let fixture = HandoffFixture::new(0);
    let server = Server::new(
        &fixture,
        Some(Fault {
            operation: Operation::RegisterClock,
            occurrence: 1,
            kind: FaultKind::Stall,
        }),
    );
    let mut adapter = server.adapter(&fixture);
    assert!(adapter.set_deadline(Duration::ZERO).is_err());
    assert!(adapter.set_deadline(Duration::from_secs(3)).is_err());
    adapter.set_deadline(Duration::from_millis(200)).unwrap();
    let coordinator = fixture.coordinator();
    assert!(coordinator
        .prepare(
            PrepMode::Fresh,
            &fixture.prep.request,
            &fixture.prep.trusted,
            &mut adapter
        )
        .is_err());
    assert_eq!(adapter.last_error(), Some(TransportError::Deadline));
    assert_eq!(fixture.source().stage, Stage::ClockPending);
    assert_eq!(server.actions(), [Operation::RegisterClock]);
    assert_eq!(server.effects(), (1, 0, 0, 0));
    // Server is released and joined by Drop using a channel and owned listener
    // wakeup; no sleep/retry or uncontrolled orphan thread is introduced.
}

#[test]
fn candidate_fixture_http_registration_nested_size_hint_is_bounded_before_allocation() {
    baselines();
    let mut hostile = vec![255; 9];
    hostile.push(1);
    hostile.extend([0; 64]);
    assert!(decode_payload::<RegistrationPayload>(&hostile).is_err());
    let fixture = HandoffFixture::new(0);
    let server = Server::new(&fixture, None);
    assert_eq!(FRAME_HEADER_BYTES, 160);
    assert_eq!(MAX_FRAME_BYTES, 20 * 1024 * 1024);
    assert!(server.actions().is_empty());
}

#[test]
fn candidate_fixture_http_reports_observed_resume_can_repeat_mock_prove_only() {
    baselines();
    let fixture = HandoffFixture::new(0);
    let server = Server::new(
        &fixture,
        Some(Fault {
            operation: Operation::ProveFixture,
            occurrence: 1,
            kind: FaultKind::Proof(ProofFault::PublicValues),
        }),
    );
    let mut adapter = server.adapter(&fixture);
    let coordinator = fixture.coordinator();
    assert!(coordinator
        .prepare(
            PrepMode::Fresh,
            &fixture.prep.request,
            &fixture.prep.trusted,
            &mut adapter
        )
        .is_err());
    assert_eq!(fixture.source().stage, Stage::ReportsObserved);
    assert_eq!(server.effects(), (1, 1, 1, 0));
    let before = server.actions().len();
    let mut resumed = server.adapter(&fixture);
    let cut = coordinator
        .prepare(
            PrepMode::Resume,
            &fixture.prep.request,
            &fixture.prep.trusted,
            &mut resumed,
        )
        .unwrap();
    assert_eq!(
        &server.actions()[before..],
        [
            Operation::LookupClock,
            Operation::LookupReports,
            Operation::ProveFixture
        ]
    );
    assert_eq!(cut.record.stage, Stage::Prepared);
    assert_eq!(cut.prepared.response, fixture.prep.response());
    assert_eq!(server.effects(), (1, 1, 2, 0));
    // One exchange per callback is not global exactly-once mock proving.
}

#[test]
fn candidate_fixture_http_unknown_broadcast_outcomes_resume_lookup_only_same_attempt() {
    for state in 0..4 {
        baselines();
        let fixture = HandoffFixture::new(0);
        let server = Server::new(
            &fixture,
            Some(Fault {
                operation: Operation::LookupOutcome,
                occurrence: 1,
                kind: FaultKind::OutcomeLookup(state),
            }),
        );
        let coordinator = fixture.coordinator();
        let mut adapter = server.adapter(&fixture);
        coordinator
            .prepare(
                PrepMode::Fresh,
                &fixture.prep.request,
                &fixture.prep.trusted,
                &mut adapter,
            )
            .unwrap();
        let plan = server.pin_plan(&fixture);
        assert!(coordinator
            .handoff(
                RunMode::Fresh,
                &fixture.prep.request,
                &fixture.prep.trusted,
                &fixture.bridge,
                SENDER,
                NONCE,
                &mut adapter
            )
            .is_err());
        let pending = broadcast_record(&coordinator.broadcast_path().to_path_buf()).unwrap();
        assert_eq!(pending.plan, plan_bytes(&plan).unwrap());
        assert!(pending.outcome.is_none());
        assert_eq!(server.effects(), (1, 1, 1, 1));
        let before = server.actions().len();
        let mut resumed = server.adapter(&fixture);
        assert_eq!(
            coordinator
                .handoff(
                    RunMode::Resume,
                    &fixture.prep.request,
                    &fixture.prep.trusted,
                    &fixture.bridge,
                    SENDER,
                    NONCE,
                    &mut resumed
                )
                .unwrap(),
            success(&plan)
        );
        assert_eq!(&server.actions()[before..], [Operation::LookupOutcome]);
        assert_eq!(server.effects(), (1, 1, 1, 1));
    }
}

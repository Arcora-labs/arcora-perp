//! Real owned IPC processes exercise the preparation coordinator itself.
//! Registrations, finality and proof responses are offline mocks only.
#![cfg(unix)]

use crate::{
    candidate_preparation::{PreparationError, RegistrationCoordinator},
    candidate_preparation_store::{CoordinationStore, StoreError},
    candidate_preparation_tests::{PrepFixture, SOURCE_SEED},
    candidate_protocol::{
        sha256, CandidateProofResponse, ClockObservation, ProtocolRequest, ReportObservation,
    },
    candidate_recovery::{
        request_bytes, validate_stored_cut, Lookup, PreparationTransport, RunMode,
    },
    candidate_recovery_store::{Record, RecoveryStore, Stage},
    candidate_registration::Registration,
};
use perp_core::clock::ClockContext;
use std::{
    fs::OpenOptions,
    io::{BufRead, BufReader, Read, Write},
    os::unix::{fs::MetadataExt, fs::OpenOptionsExt, fs::PermissionsExt, process::ExitStatusExt},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::mpsc::{self, Receiver},
    thread::JoinHandle,
    time::Duration,
};

const CHILD_TEST: &str = "candidate_preparation_lock_tests::preparation_lock_owned_child";
const DIRECTORY_ENV: &str = "ARCORA_PREPARATION_LOCK_CHILD_DIRECTORY";
const MODE_ENV: &str = "ARCORA_PREPARATION_LOCK_CHILD_MODE";
const PREFIX: &str = "ARCORA_PREPARATION_LOCK_IPC ";
const OWNER_MARKER: &[u8] = b"arcora-offline-preparation-owned-process-fixture-v1";
const IPC_TIMEOUT: Duration = Duration::from_secs(30);
const CLOCK_MARKER: &str = "clock-registration-marker";
const REPORTS_MARKER: &str = "report-registration-marker";

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "arcora-preparation-lock-{}-{}",
            std::process::id(),
            crate::hex0x(&crate::csprng_bytes32())
        ));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = path.canonicalize().unwrap();
        write_new(&path.join("owned-fixture"), OWNER_MARKER);
        Self(path)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn write_new(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
    std::fs::File::open(path.parent().unwrap())
        .unwrap()
        .sync_all()
        .unwrap();
}

enum Event {
    Message(serde_json::Value),
    Eof,
    Invalid(String),
}

struct Worker {
    child: Child,
    events: Receiver<Event>,
    stdout: Option<JoinHandle<String>>,
    stderr: Option<JoinHandle<String>>,
}
impl Worker {
    fn spawn(directory: &Scratch, mode: &str) -> Self {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                CHILD_TEST,
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(DIRECTORY_ENV, &directory.0)
            .env(MODE_ENV, mode)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let mut stderr = child.stderr.take().unwrap();
        let (sender, events) = mpsc::channel();
        let stdout = std::thread::spawn(move || {
            let mut collected = String::new();
            for line in BufReader::new(stdout).lines() {
                let line = match line {
                    Ok(line) => line,
                    Err(error) => {
                        let _ = sender.send(Event::Invalid(error.to_string()));
                        break;
                    }
                };
                collected.push_str(&line);
                collected.push('\n');
                if let Some(message) = line.strip_prefix(PREFIX) {
                    let event = match serde_json::from_str(message) {
                        Ok(message) => Event::Message(message),
                        Err(error) => Event::Invalid(error.to_string()),
                    };
                    let _ = sender.send(event);
                }
            }
            let _ = sender.send(Event::Eof);
            collected
        });
        let stderr = std::thread::spawn(move || {
            let mut text = String::new();
            stderr.read_to_string(&mut text).unwrap();
            text
        });
        Self {
            child,
            events,
            stdout: Some(stdout),
            stderr: Some(stderr),
        }
    }

    fn message(&mut self, phase: &str) -> serde_json::Value {
        match self.events.recv_timeout(IPC_TIMEOUT) {
            Ok(Event::Message(message)) if message["phase"] == phase => message,
            event => self.fail(&format!("expected {phase}, got {}", describe(event))),
        }
    }

    fn finish(&mut self) -> ExitStatus {
        // Only EOF from this directly owned child's pipe permits wait(). No
        // sleeps/polling and no unbounded wait on a still-live barrier worker.
        match self.events.recv_timeout(IPC_TIMEOUT) {
            Ok(Event::Eof) => {}
            event => self.fail(&format!("expected stdout EOF, got {}", describe(event))),
        }
        let status = self.child.wait().unwrap();
        let stdout = self.stdout.take().unwrap().join().unwrap();
        let stderr = self.stderr.take().unwrap().join().unwrap();
        assert!(
            status.success(),
            "owned child failed: {status}; stdout={stdout}; stderr={stderr}"
        );
        status
    }

    fn kill(&mut self) {
        assert!(self.child.try_wait().unwrap().is_none());
        self.child.kill().unwrap();
        let status = self.child.wait().unwrap();
        assert_eq!(status.signal(), Some(9), "must be actual owned SIGKILL");
        match self.events.recv_timeout(IPC_TIMEOUT) {
            Ok(Event::Eof) => {}
            event => self.fail(&format!("killed child EOF missing: {}", describe(event))),
        }
        self.stdout.take().unwrap().join().unwrap();
        self.stderr.take().unwrap().join().unwrap();
    }

    fn fail(&mut self, reason: &str) -> ! {
        let _ = self.child.kill();
        let status = self.child.wait().unwrap();
        let stdout = self.stdout.take().unwrap().join().unwrap();
        let stderr = self.stderr.take().unwrap().join().unwrap();
        panic!("{reason}; owned child {status}; stdout={stdout}; stderr={stderr}");
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        // Kill only this test's direct child, including assertion/timeout paths.
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
        if let Some(reader) = self.stdout.take() {
            let _ = reader.join();
        }
        if let Some(reader) = self.stderr.take() {
            let _ = reader.join();
        }
    }
}

fn describe(event: Result<Event, mpsc::RecvTimeoutError>) -> String {
    match event {
        Ok(Event::Message(message)) => message.to_string(),
        Ok(Event::Eof) => "EOF".into(),
        Ok(Event::Invalid(error)) => format!("invalid IPC: {error}"),
        Err(error) => error.to_string(),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cut {
    Clock,
    Reports,
}
impl Cut {
    fn name(self) -> &'static str {
        match self {
            Self::Clock => "clock",
            Self::Reports => "reports",
        }
    }
    fn stage(self) -> Stage {
        match self {
            Self::Clock => Stage::ClockPending,
            Self::Reports => Stage::ReportsPending,
        }
    }
}

fn source(fixture: &PrepFixture) -> Record {
    RecoveryStore::new(fixture.source_path.clone(), SOURCE_SEED)
        .load()
        .unwrap()
        .unwrap()
}

fn marker(directory: &Path, name: &str) -> usize {
    match std::fs::read(directory.join(name)) {
        Ok(bytes) => {
            assert_eq!(bytes, b"1");
            1
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
        Err(error) => panic!("owned marker read failed: {error}"),
    }
}

fn emit(phase: &str, fixture: &PrepFixture, calls: &[&str]) {
    let record = source(fixture);
    let message = serde_json::json!({
        "phase": phase,
        "calls": calls,
        "stage": format!("{:?}", record.stage),
        "request_sha256": crate::hex0x(&sha256(&record.request)),
        "clock_registrations": marker(&fixture.directory, CLOCK_MARKER),
        "report_registrations": marker(&fixture.directory, REPORTS_MARKER),
    });
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "\n{PREFIX}{message}").unwrap();
    stdout.flush().unwrap();
}

struct Transport<'a> {
    fixture: &'a PrepFixture,
    calls: Vec<&'static str>,
    hold: Option<Cut>,
}
impl Transport<'_> {
    fn check_held(&self) -> Record {
        // This is a distinct handle/fd, even inside the holder's process. The
        // actual coordinator must retain its kernel lease during every callback.
        let competing =
            CoordinationStore::new(self.fixture.source_path.clone(), SOURCE_SEED).unwrap();
        assert!(matches!(competing.try_lease(), Err(StoreError::Busy)));
        let record = source(self.fixture);
        assert_eq!(
            record.request,
            postcard::to_allocvec(&self.fixture.request).unwrap()
        );
        record
    }
    fn registered(&mut self, cut: Cut) {
        let record = self.check_held();
        assert_eq!(record.stage, cut.stage());
        let (action, name) = match cut {
            Cut::Clock => ("RegisterClock", CLOCK_MARKER),
            Cut::Reports => ("RegisterReports", REPORTS_MARKER),
        };
        self.calls.push(action);
        // A second registration would fail create_new even if a callback count
        // were accidentally reset in a successor process.
        write_new(&self.fixture.directory.join(name), b"1");
        if self.hold == Some(cut) {
            emit("READY", self.fixture, &self.calls);
            let mut release = String::new();
            std::io::stdin().read_line(&mut release).unwrap();
            assert_eq!(release, "RELEASE\n");
        }
    }
}
impl PreparationTransport for Transport<'_> {
    fn register_clock(&mut self, _clock: &ClockContext) -> Result<(), ()> {
        self.registered(Cut::Clock);
        Ok(())
    }
    fn lookup_clock(&mut self, _clock: &ClockContext) -> Result<Lookup<ClockObservation>, ()> {
        self.check_held();
        self.calls.push("LookupClock");
        Ok(Lookup::Finalized(self.fixture.clock_read()))
    }
    fn register_reports(&mut self, _registration: &Registration) -> Result<(), ()> {
        self.registered(Cut::Reports);
        Ok(())
    }
    fn lookup_reports(
        &mut self,
        _registration: &Registration,
    ) -> Result<Lookup<ReportObservation>, ()> {
        self.check_held();
        self.calls.push("LookupReports");
        Ok(Lookup::Finalized(self.fixture.report_read()))
    }
    fn prove(&mut self, request: &ProtocolRequest) -> Result<CandidateProofResponse, ()> {
        assert_eq!(self.check_held().stage, Stage::ReportsObserved);
        assert_eq!(
            request_bytes(request).unwrap(),
            request_bytes(&self.fixture.request).unwrap()
        );
        self.calls.push("Prove");
        Ok(self.fixture.response())
    }
}

fn lock_identity(coordinator: &RegistrationCoordinator) -> (u64, u64, u32) {
    let metadata = std::fs::metadata(coordinator.lock_path()).unwrap();
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    assert_eq!(metadata.nlink(), 1);
    assert_eq!(metadata.len(), 0);
    (metadata.dev(), metadata.ino(), metadata.uid())
}

fn exercise_cut(cut: Cut) {
    let directory = Scratch::new();
    let fixture = PrepFixture::for_process(&directory.0);
    let coordinator = fixture.coordinator();
    assert!(!fixture.source_path.exists());
    assert!(!coordinator.binding_path().exists());

    let mut holder = Worker::spawn(&directory, &format!("{}-holder", cut.name()));
    let ready = holder.message("READY");
    assert_eq!(ready["stage"], format!("{:?}", cut.stage()));
    assert_eq!(ready["clock_registrations"], 1);
    let report_markers = usize::from(cut == Cut::Reports);
    assert_eq!(ready["report_registrations"], report_markers);
    let expected_holder_calls = match cut {
        Cut::Clock => serde_json::json!(["RegisterClock"]),
        Cut::Reports => serde_json::json!([
            "RegisterClock",
            "LookupClock",
            "LookupClock",
            "RegisterReports"
        ]),
    };
    assert_eq!(ready["calls"], expected_holder_calls);
    let original = source(&fixture);
    assert_eq!(original.stage, cut.stage());
    let original_bytes = std::fs::read(&fixture.source_path).unwrap();
    let binding_bytes = std::fs::read(coordinator.binding_path()).unwrap();
    let identity = lock_identity(&coordinator);
    let request_hash = crate::hex0x(&sha256(&original.request));
    assert_eq!(ready["request_sha256"], request_hash);

    let mut contender = Worker::spawn(&directory, &format!("{}-contender", cut.name()));
    let busy = contender.message("BUSY");
    assert_eq!(busy["calls"], serde_json::json!([]));
    assert_eq!(busy["request_sha256"], request_hash);
    assert_eq!(busy["clock_registrations"], 1);
    assert_eq!(busy["report_registrations"], report_markers);
    contender.finish();
    assert_eq!(std::fs::read(&fixture.source_path).unwrap(), original_bytes);
    assert_eq!(
        std::fs::read(coordinator.binding_path()).unwrap(),
        binding_bytes
    );
    assert_eq!(lock_identity(&coordinator), identity);

    // READY comes from the actual registration callback after the authenticated
    // pending cut is durable. SIGKILL bypasses destructors and releases the lease.
    holder.kill();
    assert_eq!(std::fs::read(&fixture.source_path).unwrap(), original_bytes);
    let mut successor = Worker::spawn(&directory, &format!("{}-successor", cut.name()));
    let prepared = successor.message("PREPARED");
    let calls = prepared["calls"].as_array().unwrap();
    let expected_successor_calls = match cut {
        Cut::Clock => serde_json::json!([
            "LookupClock",
            "LookupClock",
            "LookupReports",
            "LookupClock",
            "LookupReports",
            "Prove"
        ]),
        Cut::Reports => serde_json::json!([
            "LookupClock",
            "LookupReports",
            "LookupClock",
            "LookupReports",
            "Prove"
        ]),
    };
    assert_eq!(prepared["calls"], expected_successor_calls);
    assert!(!calls.is_empty());
    assert!(calls
        .iter()
        .all(|x| matches!(x.as_str(), Some("LookupClock" | "LookupReports" | "Prove"))));
    assert!(calls.iter().any(|x| x == "LookupClock"));
    assert!(calls.iter().any(|x| x == "LookupReports"));
    assert_eq!(calls.iter().filter(|x| *x == "Prove").count(), 1);
    assert_eq!(prepared["stage"], "Prepared");
    assert_eq!(prepared["request_sha256"], request_hash);
    assert_eq!(prepared["clock_registrations"], 1);
    assert_eq!(prepared["report_registrations"], report_markers);
    successor.finish();

    let final_record = source(&fixture);
    assert_eq!(final_record.stage, Stage::Prepared);
    assert_eq!(final_record.request, original.request);
    if let Some(clock) = original.clock {
        assert_eq!(final_record.clock.as_ref(), Some(&clock));
    }
    assert_eq!(
        final_record.clock,
        Some(postcard::to_allocvec(&fixture.clock).unwrap())
    );
    assert_eq!(
        final_record.reports,
        Some(postcard::to_allocvec(&fixture.reports).unwrap())
    );
    validate_stored_cut(&final_record, &fixture.request, &fixture.trusted).unwrap();
    assert_ne!(std::fs::read(&fixture.source_path).unwrap(), original_bytes);
    assert_eq!(
        std::fs::read(coordinator.binding_path()).unwrap(),
        binding_bytes
    );
    assert_eq!(lock_identity(&coordinator), identity);
    assert_eq!(marker(&directory.0, CLOCK_MARKER), 1);
    assert_eq!(marker(&directory.0, REPORTS_MARKER), report_markers);
}

#[test]
fn preparation_lock_clock_pending_sigkill_resumes_only_original_lookups() {
    exercise_cut(Cut::Clock);
}

#[test]
fn preparation_lock_reports_pending_sigkill_preserves_original_clock_and_no_registration() {
    exercise_cut(Cut::Reports);
}

#[test]
#[ignore = "owned IPC child only; invoked exactly by preparation coordinator tests"]
fn preparation_lock_owned_child() {
    let directory =
        PathBuf::from(std::env::var_os(DIRECTORY_ENV).expect("owned fixture directory"));
    let directory = directory.canonicalize().unwrap();
    assert!(directory
        .file_name()
        .unwrap()
        .to_string_lossy()
        .starts_with("arcora-preparation-lock-"));
    assert_eq!(
        std::fs::read(directory.join("owned-fixture")).unwrap(),
        OWNER_MARKER
    );
    let mode = std::env::var(MODE_ENV).unwrap();
    let (cut, role) = mode.split_once('-').unwrap();
    let cut = match cut {
        "clock" => Cut::Clock,
        "reports" => Cut::Reports,
        _ => panic!("unknown owned cut"),
    };
    assert!(["holder", "contender", "successor"].contains(&role));
    let fixture = PrepFixture::for_process(&directory);
    let coordinator = fixture.coordinator();
    let mut transport = Transport {
        fixture: &fixture,
        calls: Vec::new(),
        hold: (role == "holder").then_some(cut),
    };
    let result = coordinator.run_prepared(
        if role == "holder" {
            RunMode::Fresh
        } else {
            RunMode::Resume
        },
        &fixture.request,
        &fixture.trusted,
        &mut transport,
    );
    match role {
        "contender" => {
            assert!(matches!(
                result,
                Err(PreparationError::Store(StoreError::Busy))
            ));
            assert!(transport.calls.is_empty());
            assert_eq!(source(&fixture).stage, cut.stage());
            emit("BUSY", &fixture, &transport.calls);
        }
        "successor" => {
            let cut = result.unwrap();
            assert_eq!(cut.record, source(&fixture));
            assert_eq!(cut.record.stage, Stage::Prepared);
            assert!(transport
                .calls
                .iter()
                .all(|x| matches!(*x, "LookupClock" | "LookupReports" | "Prove")));
            emit("PREPARED", &fixture, &transport.calls);
        }
        "holder" => panic!("owned holder returned before SIGKILL: {result:?}"),
        _ => unreachable!(),
    }
}

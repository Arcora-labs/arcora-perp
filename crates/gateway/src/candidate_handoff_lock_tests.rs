//! Real owned-process SIGKILL coverage for the OFFLINE handoff coordinator.
//! Actual preparation/handoff paths use fixed lifecycle inputs. Broadcast,
//! outcome/finality and proof bytes remain caller-owned mocks, never RPC/proof.
#![cfg(unix)]
use crate::{
    candidate_broadcast::{plan_hash, Action, BroadcastTransport, OutcomeValue, Plan, RunMode},
    candidate_broadcast_store::{BroadcastStore, StoreError as BroadcastStoreError},
    candidate_handoff::{HandoffCoordinator, HandoffError},
    candidate_handoff_tests::{success, HandoffFixture, BROADCAST_SEED, NONCE, SENDER},
    candidate_preparation::PreparationError,
    candidate_preparation_store::{CoordinationStore, StoreError as PreparationStoreError},
    candidate_protocol::{ClockObservation, ReportObservation},
    candidate_recovery::{Anchored, Lookup},
};
use std::{
    fs::OpenOptions,
    io::{BufRead, BufReader, Read, Write},
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        process::ExitStatusExt,
    },
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::mpsc::{self, Receiver},
    thread::JoinHandle,
    time::Duration,
};
const CHILD_TEST: &str = "candidate_handoff_lock_tests::handoff_lock_owned_child";
const DIRECTORY_ENV: &str = "ARCORA_HANDOFF_LOCK_CHILD_DIRECTORY";
const MODE_ENV: &str = "ARCORA_HANDOFF_LOCK_CHILD_MODE";
const PREFIX: &str = "ARCORA_HANDOFF_LOCK_IPC ";
const OWNER_MARKER: &[u8] = b"arcora-offline-handoff-owned-process-fixture-v1";
const IPC_TIMEOUT: Duration = Duration::from_secs(30);
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "arcora-handoff-lock-{}-{}",
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

fn lock_identity(path: &Path) -> (u64, u64, u32) {
    let metadata = std::fs::symlink_metadata(path).unwrap();
    assert!(metadata.is_file());
    assert_eq!(metadata.nlink(), 1);
    assert_eq!(metadata.mode() & 0o7777, 0o600);
    assert_eq!(metadata.len(), 0);
    (metadata.dev(), metadata.ino(), metadata.uid())
}
fn emit(phase: &str, expected: &Plan, calls: &[Action]) {
    let message = serde_json::json!({
        "phase":phase,
        "calls":calls.iter().map(|action| format!("{action:?}")).collect::<Vec<_>>(),
        "plan_sha256":crate::hex0x(&plan_hash(expected).unwrap()),
        "attempt_id":crate::hex0x(&expected.attempt_id),
        "mock_tx_id":crate::hex0x(&expected.mock_tx_id),
        "mock_sender":crate::hex0x(&expected.mock_sender),
        "mock_nonce":expected.mock_nonce,
        "broadcasts":calls.iter().filter(|action| **action==Action::Broadcast).count(),
        "lookups":calls.iter().filter(|action| **action==Action::Lookup).count(),
        "rechecks":calls.iter().filter(|action| **action==Action::Recheck).count(),
    });
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "\n{PREFIX}{message}").unwrap();
    stdout.flush().unwrap();
}
fn same_plan(message: &serde_json::Value, expected: &Plan) {
    assert_eq!(
        message["plan_sha256"],
        crate::hex0x(&plan_hash(expected).unwrap())
    );
    assert_eq!(message["attempt_id"], crate::hex0x(&expected.attempt_id));
    assert_eq!(message["mock_tx_id"], crate::hex0x(&expected.mock_tx_id));
    assert_eq!(message["mock_sender"], crate::hex0x(&SENDER));
    assert_eq!(message["mock_nonce"], NONCE);
}
struct ProcessTransport<'a> {
    coordinator: &'a HandoffCoordinator,
    directory: &'a Path,
    role: &'a str,
    expected: Plan,
    calls: Vec<Action>,
}
impl ProcessTransport<'_> {
    fn action(&mut self, plan: &Plan, action: Action) {
        assert_ne!(
            self.role, "contend",
            "a contending handoff must make no callback"
        );
        assert_ne!(
            self.role, "terminal",
            "a terminal handoff must make no callback"
        );
        assert_eq!(plan, &self.expected);
        self.calls.push(action);
        // Independent descriptors must lose on BOTH kernel leases throughout
        // each real callback; no model-only callback bypass is exercised.
        let source = CoordinationStore::new(
            self.coordinator.source_path().to_path_buf(),
            crate::candidate_preparation_tests::SOURCE_SEED,
        )
        .unwrap();
        assert!(matches!(
            source.try_lease(),
            Err(PreparationStoreError::Busy)
        ));
        let broadcast = BroadcastStore::new(
            self.coordinator.broadcast_path().to_path_buf(),
            BROADCAST_SEED,
        )
        .unwrap();
        assert!(matches!(
            broadcast.try_lease(),
            Err(BroadcastStoreError::Busy)
        ));
    }
    fn barrier(&self) {
        emit("READY", &self.expected, &self.calls);
        let mut release = String::new();
        std::io::stdin().read_line(&mut release).unwrap();
        assert_eq!(release, "RELEASE\n");
    }
}
impl BroadcastTransport for ProcessTransport<'_> {
    fn recheck(
        &mut self,
        plan: &Plan,
    ) -> Result<(Anchored<ClockObservation>, Anchored<ReportObservation>), ()> {
        self.action(plan, Action::Recheck);
        assert!(!self.coordinator.broadcast_path().exists());
        Ok((plan.clock.clone(), plan.reports.clone()))
    }
    fn broadcast(&mut self, plan: &Plan) -> Result<(), ()> {
        self.action(plan, Action::Broadcast);
        let pending = crate::candidate_broadcast_store::decode_sealed(
            &std::fs::read(self.coordinator.broadcast_path()).unwrap(),
            &BROADCAST_SEED,
        )
        .unwrap();
        assert_eq!(
            pending.plan,
            crate::candidate_broadcast::plan_bytes(plan).unwrap()
        );
        assert!(
            pending.outcome.is_none(),
            "Pending must be durable before Broadcast"
        );
        write_new(&self.directory.join("handoff.broadcast-marker"), b"1");
        if self.role == "hold-broadcast" {
            self.barrier();
        }
        write_new(&self.directory.join("handoff.broadcast-returned"), b"1");
        Ok(())
    }
    fn lookup(&mut self, plan: &Plan) -> Result<Lookup<OutcomeValue>, ()> {
        self.action(plan, Action::Lookup);
        assert_eq!(
            std::fs::read(self.directory.join("handoff.broadcast-marker")).unwrap(),
            b"1"
        );
        if self.role == "hold-lookup" {
            // The real driver can enter this callback only after Broadcast
            // returned and its after-callback fences passed.
            assert_eq!(
                std::fs::read(self.directory.join("handoff.broadcast-returned")).unwrap(),
                b"1"
            );
            self.barrier();
        }
        Ok(Lookup::Finalized(success(plan)))
    }
}

fn sigkill_case(role: &str) {
    let directory = Scratch::new();
    let fixture = HandoffFixture::for_process(&directory.0);
    // Actual Fresh preparation occurs before this handoff-only trace. Its
    // registration/prove callbacks are not falsely counted as zero here.
    fixture.prepare();
    let coordinator = fixture.coordinator();
    let expected = fixture.plan();
    assert_eq!(expected.mock_sender, SENDER);
    assert_eq!(expected.mock_nonce, NONCE);
    let source_before = std::fs::read(coordinator.source_path()).unwrap();
    let binding_before = std::fs::read(coordinator.binding_path()).unwrap();
    let source_lock = lock_identity(coordinator.source_lock_path());
    let broadcast_lock = lock_identity(coordinator.broadcast_lock_path());
    let mut holder = Worker::spawn(&directory, role);
    let ready = holder.message("READY");
    same_plan(&ready, &expected);
    let calls = if role == "hold-broadcast" {
        serde_json::json!(["Recheck", "Broadcast"])
    } else {
        serde_json::json!(["Recheck", "Broadcast", "Lookup"])
    };
    assert_eq!(ready["calls"], calls);
    assert_eq!(ready["broadcasts"], 1);
    assert_eq!(ready["rechecks"], 1);
    assert_eq!(ready["lookups"], usize::from(role == "hold-lookup"));
    let pending_before = std::fs::read(coordinator.broadcast_path()).unwrap();
    let pending =
        crate::candidate_broadcast_store::decode_sealed(&pending_before, &BROADCAST_SEED).unwrap();
    assert!(pending.outcome.is_none());
    assert_eq!(
        pending.plan,
        crate::candidate_broadcast::plan_bytes(&expected).unwrap()
    );
    assert_eq!(
        std::fs::read(directory.0.join("handoff.broadcast-marker")).unwrap(),
        b"1"
    );
    assert_eq!(
        directory.0.join("handoff.broadcast-returned").exists(),
        role == "hold-lookup"
    );
    let direct =
        BroadcastStore::new(coordinator.broadcast_path().to_path_buf(), BROADCAST_SEED).unwrap();
    assert!(matches!(direct.try_lease(), Err(BroadcastStoreError::Busy)));
    let mut contender = Worker::spawn(&directory, "contend");
    let busy = contender.message("BUSY");
    same_plan(&busy, &expected);
    assert_eq!(busy["calls"], serde_json::json!([]));
    assert_eq!(busy["broadcasts"], 0);
    assert_eq!(busy["lookups"], 0);
    assert_eq!(busy["rechecks"], 0);
    contender.finish();
    assert_eq!(
        std::fs::read(coordinator.broadcast_path()).unwrap(),
        pending_before
    );
    assert_eq!(
        std::fs::read(coordinator.source_path()).unwrap(),
        source_before
    );
    assert_eq!(
        std::fs::read(coordinator.binding_path()).unwrap(),
        binding_before
    );
    // Only this directly owned child is SIGKILLed; no destructors release its
    // source/broadcast leases. Kernel descriptor cleanup must release both.
    holder.kill();
    assert_eq!(
        std::fs::read(coordinator.broadcast_path()).unwrap(),
        pending_before
    );
    let mut successor = Worker::spawn(&directory, "resume");
    let outcome = successor.message("OUTCOME");
    same_plan(&outcome, &expected);
    assert_eq!(outcome["calls"], serde_json::json!(["Lookup"]));
    assert_eq!(outcome["broadcasts"], 0);
    assert_eq!(outcome["lookups"], 1);
    assert_eq!(outcome["rechecks"], 0);
    successor.finish();
    let terminal_before = std::fs::read(coordinator.broadcast_path()).unwrap();
    assert_ne!(terminal_before, pending_before);
    let completed =
        crate::candidate_broadcast_store::decode_sealed(&terminal_before, &BROADCAST_SEED).unwrap();
    assert_eq!(completed.plan, pending.plan);
    let recorded =
        crate::candidate_broadcast::decode_outcome(completed.outcome.as_deref().unwrap()).unwrap();
    assert_eq!(recorded, success(&expected));
    let mut terminal = Worker::spawn(&directory, "terminal");
    let noop = terminal.message("TERMINAL");
    same_plan(&noop, &expected);
    assert_eq!(noop["calls"], serde_json::json!([]));
    assert_eq!(noop["broadcasts"], 0);
    assert_eq!(noop["lookups"], 0);
    assert_eq!(noop["rechecks"], 0);
    terminal.finish();
    assert_eq!(
        std::fs::read(coordinator.broadcast_path()).unwrap(),
        terminal_before
    );
    assert_eq!(
        std::fs::read(coordinator.source_path()).unwrap(),
        source_before
    );
    assert_eq!(
        std::fs::read(coordinator.binding_path()).unwrap(),
        binding_before
    );
    assert_eq!(lock_identity(coordinator.source_lock_path()), source_lock);
    assert_eq!(
        lock_identity(coordinator.broadcast_lock_path()),
        broadcast_lock
    );
    assert_eq!(
        std::fs::read(directory.0.join("handoff.broadcast-marker")).unwrap(),
        b"1"
    );
    assert_eq!(
        directory.0.join("handoff.broadcast-returned").exists(),
        role == "hold-lookup"
    );
}
#[test]
fn handoff_lock_sigkill_inside_broadcast_preserves_prepared_and_lookup_only_resume() {
    sigkill_case("hold-broadcast");
}
#[test]
fn handoff_lock_sigkill_inside_lookup_preserves_prepared_and_lookup_only_resume() {
    sigkill_case("hold-lookup");
}
#[test]
#[ignore = "owned IPC child only; invoked exactly by handoff kernel lease tests"]
fn handoff_lock_owned_child() {
    let path = PathBuf::from(std::env::var_os(DIRECTORY_ENV).expect("owned fixture directory"));
    let path = path.canonicalize().unwrap();
    assert!(path
        .file_name()
        .unwrap()
        .to_string_lossy()
        .starts_with("arcora-handoff-lock-"));
    assert_eq!(
        std::fs::read(path.join("owned-fixture")).unwrap(),
        OWNER_MARKER
    );
    let role = std::env::var(MODE_ENV).unwrap();
    assert!([
        "hold-broadcast",
        "hold-lookup",
        "contend",
        "resume",
        "terminal"
    ]
    .contains(&role.as_str()));
    let fixture = HandoffFixture::for_process(&path);
    let coordinator = fixture.coordinator();
    let expected = fixture.plan();
    let mode = if role.starts_with("hold-") {
        RunMode::Fresh
    } else {
        RunMode::Resume
    };
    let mut transport = ProcessTransport {
        coordinator: &coordinator,
        directory: &path,
        role: &role,
        expected: expected.clone(),
        calls: vec![],
    };
    let result = coordinator.handoff(
        mode,
        &fixture.prep.request,
        &fixture.prep.trusted,
        &fixture.bridge,
        SENDER,
        NONCE,
        &mut transport,
    );
    match role.as_str() {
        "contend" => {
            assert_eq!(
                result,
                Err(HandoffError::Preparation(PreparationError::Store(
                    PreparationStoreError::Busy
                )))
            );
            assert!(transport.calls.is_empty());
            emit("BUSY", &expected, &transport.calls);
        }
        "resume" => {
            assert_eq!(result.unwrap(), success(&expected));
            assert_eq!(transport.calls, [Action::Lookup]);
            emit("OUTCOME", &expected, &transport.calls);
        }
        "terminal" => {
            assert_eq!(result.unwrap(), success(&expected));
            assert!(transport.calls.is_empty());
            emit("TERMINAL", &expected, &transport.calls);
        }
        _ => {
            assert_eq!(result.unwrap(), success(&expected));
        }
    }
}

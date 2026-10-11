//! Actual process/IPC coverage for the offline broadcast store's kernel lease.
//! Opaque-plan modes test the lease model; dispatcher modes use fixed #50 inputs
//! and the actual offline dispatcher. Actions are mocks, never RPC or proof.
#![cfg(unix)]

use crate::candidate_broadcast_store::{BroadcastStore, StoreError};
use std::{
    fs::OpenOptions,
    io::{BufRead, BufReader, Read, Write},
    os::unix::{fs::MetadataExt, fs::PermissionsExt, process::ExitStatusExt},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::mpsc::{self, Receiver},
    thread::JoinHandle,
    time::Duration,
};

const CHILD_TEST: &str = "candidate_broadcast_lock_tests::broadcast_lock_owned_child";
const DIRECTORY_ENV: &str = "ARCORA_BROADCAST_LOCK_CHILD_DIRECTORY";
const MODE_ENV: &str = "ARCORA_BROADCAST_LOCK_CHILD_MODE";
const PREFIX: &str = "ARCORA_BROADCAST_LOCK_IPC ";
const OWNER_MARKER: &[u8] = b"arcora-offline-broadcast-owned-process-fixture-v1";
const PLAN: &[u8] = b"exact-owned-offline-broadcast-pending-plan-v1";
const SEED: [u8; 32] = [0x74; 32];
const IPC_TIMEOUT: Duration = Duration::from_secs(30);

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "arcora-broadcast-lock-{}-{}",
            std::process::id(),
            crate::hex0x(&crate::csprng_bytes32())
        ));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = path.canonicalize().unwrap();
        write_new(&path.join("owned-fixture"), OWNER_MARKER);
        Self(path)
    }

    fn record(&self) -> PathBuf {
        self.0.join("pending.bin")
    }

    fn lock(&self) -> PathBuf {
        self.0.join("pending.bin.lock")
    }

    fn store(&self) -> BroadcastStore {
        BroadcastStore::new(self.record(), SEED).unwrap()
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

    fn release(&mut self) {
        let mut input = self.child.stdin.take().unwrap();
        input.write_all(b"RELEASE\n").unwrap();
        input.flush().unwrap();
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

fn emit(phase: &str, pending_creates: usize, lookups: usize) {
    let message = serde_json::json!({
        "phase": phase,
        "pending_creates": pending_creates,
        "lookups": lookups,
        "broadcasts": 0,
        "plan_sha256": crate::hex0x(&crate::candidate_protocol::sha256(PLAN)),
    });
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "\n{PREFIX}{message}").unwrap();
    stdout.flush().unwrap();
}

fn counters(message: &serde_json::Value, pending_creates: usize, lookups: usize) {
    assert_eq!(message["pending_creates"], pending_creates);
    assert_eq!(message["lookups"], lookups);
    assert_eq!(message["broadcasts"], 0);
    assert_eq!(
        message["plan_sha256"],
        crate::hex0x(&crate::candidate_protocol::sha256(PLAN))
    );
}

fn no_callback_marker(directory: &Scratch) {
    assert!(!directory.0.join("lookup-only.json").exists());
    assert!(!directory.0.join("broadcast-marker").exists());
}

#[test]
fn broadcast_lock_processes_and_handles_refuse_while_owned_child_holds_lease() {
    let directory = Scratch::new();
    let mut holder = Worker::spawn(&directory, "hold");
    counters(&holder.message("READY"), 1, 0);
    let before = std::fs::read(directory.record()).unwrap();
    let store = directory.store();
    assert!(matches!(store.try_lease(), Err(StoreError::Busy)));
    let mut contender = Worker::spawn(&directory, "probe-busy");
    counters(&contender.message("BUSY"), 0, 0);
    contender.finish();
    no_callback_marker(&directory);
    assert_eq!(std::fs::read(directory.record()).unwrap(), before);

    holder.release();
    counters(&holder.message("RELEASED"), 1, 0);
    holder.finish();
    let lease = store.try_lease().unwrap();
    lease.check().unwrap();
    let pending = lease.load().unwrap().unwrap();
    assert_eq!(pending.plan, PLAN);
    assert!(pending.outcome.is_none());
    assert_eq!(std::fs::read(directory.record()).unwrap(), before);
    no_callback_marker(&directory);
}

#[test]
fn broadcast_lock_sigkill_releases_lease_without_refreshing_pending() {
    let directory = Scratch::new();
    let mut holder = Worker::spawn(&directory, "hold");
    counters(&holder.message("READY"), 1, 0);
    let before = std::fs::read(directory.record()).unwrap();
    let lock = std::fs::metadata(directory.lock()).unwrap();
    let identity = (lock.dev(), lock.ino(), lock.uid());
    let store = directory.store();
    assert!(matches!(store.try_lease(), Err(StoreError::Busy)));
    holder.kill();

    let mut successor = Worker::spawn(&directory, "resume-lookup-only");
    counters(&successor.message("LOOKUP_ONLY"), 0, 1);
    successor.finish();
    let lookup: serde_json::Value =
        serde_json::from_slice(&std::fs::read(directory.0.join("lookup-only.json")).unwrap())
            .unwrap();
    counters(&lookup, 0, 1);
    assert!(!directory.0.join("broadcast-marker").exists());
    assert_eq!(std::fs::read(directory.record()).unwrap(), before);
    let lock = std::fs::metadata(directory.lock()).unwrap();
    assert_eq!((lock.dev(), lock.ino(), lock.uid()), identity);
    assert_eq!(lock.nlink(), 1);
    assert_eq!(lock.permissions().mode() & 0o777, 0o600);
    assert_eq!(lock.len(), 0);
    let lease = store.try_lease().unwrap();
    lease.check().unwrap();
    let pending = lease.load().unwrap().unwrap();
    assert_eq!(pending.plan, PLAN);
    assert!(pending.outcome.is_none());
}

#[test]
fn broadcast_lock_actual_dispatcher_sigkill_resume_never_duplicates_broadcast() {
    let directory = Scratch::new();
    crate::candidate_broadcast_tests::setup_dispatcher_source(&directory.0);
    let source = directory.0.join("dispatcher.source");
    let source_before = std::fs::read(&source).unwrap();
    let pending_path = directory.0.join("dispatcher.pending");
    let lock_path = directory.0.join("dispatcher.pending.lock");
    let marker = directory.0.join("dispatcher.broadcast-marker");

    let mut holder = Worker::spawn(&directory, "dispatcher-hold");
    let ready = holder.message("READY");
    assert_eq!(ready["calls"], serde_json::json!(["Recheck", "Broadcast"]));
    assert_eq!(ready["pending_creates"], 1);
    assert_eq!(ready["lookups"], 0);
    assert_eq!(ready["broadcasts"], 1);
    let plan_sha256 = ready["plan_sha256"].as_str().unwrap().to_owned();
    crate::parse_hex32(&plan_sha256).unwrap();
    let pending_before = std::fs::read(&pending_path).unwrap();
    assert_eq!(std::fs::read(&marker).unwrap(), b"1");
    let lock = std::fs::metadata(&lock_path).unwrap();
    let identity = (lock.dev(), lock.ino(), lock.uid());

    // This independent process calls the actual dispatcher in Resume mode.
    // It loses at lease acquisition before preflight or lookup callbacks.
    let mut contender = Worker::spawn(&directory, "dispatcher-contend");
    let busy = contender.message("BUSY");
    assert_eq!(busy["calls"], serde_json::json!([]));
    assert_eq!(busy["pending_creates"], 0);
    assert_eq!(busy["lookups"], 0);
    assert_eq!(busy["broadcasts"], 0);
    assert_eq!(busy["plan_sha256"], plan_sha256);
    contender.finish();
    assert_eq!(std::fs::read(&pending_path).unwrap(), pending_before);
    assert_eq!(std::fs::read(&marker).unwrap(), b"1");
    assert_eq!(std::fs::read(&source).unwrap(), source_before);

    // The first mock Broadcast callback has been entered but not returned.
    // SIGKILL bypasses Rust destructors; its durable Pending must survive.
    holder.kill();
    assert_eq!(std::fs::read(&pending_path).unwrap(), pending_before);
    let mut successor = Worker::spawn(&directory, "dispatcher-resume");
    let outcome = successor.message("OUTCOME");
    assert_eq!(outcome["calls"], serde_json::json!(["Lookup"]));
    assert_eq!(outcome["pending_creates"], 0);
    assert_eq!(outcome["lookups"], 1);
    assert_eq!(outcome["broadcasts"], 0);
    assert_eq!(outcome["plan_sha256"], plan_sha256);
    successor.finish();
    assert_eq!(std::fs::read(&marker).unwrap(), b"1");
    assert_eq!(std::fs::read(&source).unwrap(), source_before);
    // Resume is allowed to durably promote Pending to the exact mock Outcome.
    // It cannot rewrite the plan, refresh the source cut or broadcast again.
    assert_ne!(std::fs::read(&pending_path).unwrap(), pending_before);
    let lock = std::fs::metadata(&lock_path).unwrap();
    assert_eq!((lock.dev(), lock.ino(), lock.uid()), identity);
    assert_eq!(lock.nlink(), 1);
    assert_eq!(lock.permissions().mode() & 0o777, 0o600);
    assert_eq!(lock.len(), 0);
}

#[test]
#[ignore = "owned IPC child only; invoked exactly by kernel lease tests"]
fn broadcast_lock_owned_child() {
    let path = PathBuf::from(std::env::var_os(DIRECTORY_ENV).expect("owned fixture directory"));
    let path = path.canonicalize().unwrap();
    assert!(path
        .file_name()
        .unwrap()
        .to_string_lossy()
        .starts_with("arcora-broadcast-lock-"));
    assert_eq!(
        std::fs::read(path.join("owned-fixture")).unwrap(),
        OWNER_MARKER
    );
    let mode = std::env::var(MODE_ENV).unwrap();
    if let Some(role) = mode.strip_prefix("dispatcher-") {
        assert!(["hold", "contend", "resume"].contains(&role));
        crate::candidate_broadcast_tests::dispatcher_child(&path, role);
        return;
    }
    let store = BroadcastStore::new(path.join("pending.bin"), SEED).unwrap();
    match mode.as_str() {
        "hold" => {
            let lease = store.try_lease().unwrap();
            let pending = lease.create_pending(PLAN).unwrap();
            assert_eq!(pending.plan, PLAN);
            assert!(pending.outcome.is_none());
            lease.check().unwrap();
            emit("READY", 1, 0);
            let mut release = String::new();
            std::io::stdin().read_line(&mut release).unwrap();
            assert_eq!(release, "RELEASE\n");
            lease.check().unwrap();
            assert_eq!(lease.load().unwrap().unwrap(), pending);
            drop(lease);
            emit("RELEASED", 1, 0);
        }
        "probe-busy" => {
            assert!(matches!(store.try_lease(), Err(StoreError::Busy)));
            emit("BUSY", 0, 0);
        }
        "resume-lookup-only" => {
            let lease = store.try_lease().unwrap();
            lease.check().unwrap();
            let pending = lease.load().unwrap().unwrap();
            assert_eq!(pending.plan, PLAN);
            assert!(pending.outcome.is_none());
            // This is an explicit mock lookup after exact Pending reload. It
            // does not call create_pending(), finish(), or any broadcast API.
            let marker = serde_json::json!({
                "pending_creates": 0,
                "lookups": 1,
                "broadcasts": 0,
                "plan_sha256": crate::hex0x(&crate::candidate_protocol::sha256(&pending.plan)),
            });
            lease.check().unwrap();
            write_new(
                &path.join("lookup-only.json"),
                &serde_json::to_vec(&marker).unwrap(),
            );
            assert_eq!(lease.load().unwrap().unwrap(), pending);
            emit("LOOKUP_ONLY", 0, 1);
        }
        mode => panic!("unknown owned child mode: {mode}"),
    }
}

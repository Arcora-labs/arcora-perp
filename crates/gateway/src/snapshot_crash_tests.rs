//! S6-02: deterministic process interruption at real filesystem boundaries.
//! A child of this test binary stops at a pipe barrier; its owning parent kills
//! that exact Child and checks SIGKILL. No timers choose the interruption point.
//! These observations are process-crash recovery, never simulated power failure.
use super::{open, read_file, seal, write_atomic};
use crate::{
    prover_client::{prove_and_prepare, MockProverClient},
    rollback_journal::{self, RollbackJournal},
    trading_gate::GateObservation,
    BootRecoveryOutcome, Gw,
};
use perp_core::fixed::QUOTE_SCALE;
use serde_json::json;
use sha3::{Digest as _, Keccak256};
use std::{
    cell::RefCell,
    io::{BufRead, BufReader, Read, Write},
    os::unix::process::ExitStatusExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::mpsc,
    thread::JoinHandle,
    time::Duration,
};

const SEED: [u8; 32] = [42; 32];
const READY: &str = "ARCORA_CRASH_READY";
const CHILD_TEST: &str = "snapshot::crash_tests::atomic_write_crash_worker";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Boundary {
    TempCreated,
    DataWritten,
    FileSynced,
    Renamed,
    DirectorySynced,
}
impl Boundary {
    const ALL: [Self; 5] = [
        Self::TempCreated,
        Self::DataWritten,
        Self::FileSynced,
        Self::Renamed,
        Self::DirectorySynced,
    ];
    fn name(self) -> &'static str {
        match self {
            Self::TempCreated => "temp-created-before-write",
            Self::DataWritten => "data-written-before-file-sync",
            Self::FileSynced => "file-synced-before-rename",
            Self::Renamed => "renamed-before-directory-sync",
            Self::DirectorySynced => "directory-synced-before-return",
        }
    }
    fn published(self) -> bool {
        matches!(self, Self::Renamed | Self::DirectorySynced)
    }
}

thread_local! {
    static INTERRUPT: RefCell<Option<(PathBuf, Boundary)>> = const { RefCell::new(None) };
}

pub(super) fn at_boundary(path: &Path, boundary: Boundary) {
    let stop = INTERRUPT.with(|slot| {
        slot.borrow()
            .as_ref()
            .is_some_and(|(target, stage)| target == path && *stage == boundary)
    });
    if stop {
        park(boundary.name());
    }
}

fn park(stage: &str) -> ! {
    // A flushed pipe message is the parent barrier. Keeping stdin open makes
    // read_exact block without a polling/sleep heuristic until the parent kills.
    let mut out = std::io::stdout().lock();
    writeln!(out, "\n{READY} {stage}").unwrap();
    out.flush().unwrap();
    drop(out);
    let mut byte = [0];
    let result = std::io::stdin().read_exact(&mut byte);
    panic!("crash worker resumed instead of being SIGKILLed: {result:?}");
}

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let mut random = [0; 16];
        getrandom::getrandom(&mut random).unwrap();
        let suffix: String = random.iter().map(|b| format!("{b:02x}")).collect();
        let path = std::env::temp_dir().join(format!(
            "arcora-owned-crash-{}-{suffix}",
            std::process::id()
        ));
        std::fs::create_dir(&path).unwrap();
        // Child refuses paths not explicitly marked as this harness's disposable state.
        std::fs::write(path.join("owned-fixture"), b"arcora-s6-02-test-only").unwrap();
        Self(path)
    }
    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Worker {
    child: Child,
    stdout: Option<JoinHandle<String>>,
    stderr: Option<JoinHandle<String>>,
}
impl Drop for Worker {
    fn drop(&mut self) {
        // Only a directly owned child handle is ever killed, including panics.
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

fn kill_at(dir: &Scratch, mode: &str, stage: &str) -> u32 {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            CHILD_TEST,
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("ARCORA_TEST_CRASH_ROOT", &dir.0)
        .env("ARCORA_TEST_CRASH_MODE", mode)
        .env("ARCORA_TEST_CRASH_STAGE", stage)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let pid = child.id();
    let stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let (ready_tx, ready_rx) = mpsc::channel();
    let stdout = std::thread::spawn(move || {
        let mut collected = String::new();
        for line in BufReader::new(stdout).lines() {
            let line = line.unwrap();
            if let Some(stage) = line.strip_prefix(&format!("{READY} ")) {
                let _ = ready_tx.send(stage.to_owned());
            }
            collected.push_str(&line);
            collected.push('\n');
        }
        collected
    });
    let stderr = std::thread::spawn(move || {
        let mut text = String::new();
        stderr.read_to_string(&mut text).unwrap();
        text
    });
    let mut worker = Worker {
        child,
        stdout: Some(stdout),
        stderr: Some(stderr),
    };
    let arrived = ready_rx.recv_timeout(Duration::from_secs(15));
    if arrived.as_deref() != Ok(stage) {
        let _ = worker.child.kill();
        let status = worker.child.wait().unwrap();
        let out = worker.stdout.take().unwrap().join().unwrap();
        let err = worker.stderr.take().unwrap().join().unwrap();
        panic!("owned worker {pid} did not reach {mode}/{stage}: {arrived:?}, {status}; stdout={out}; stderr={err}");
    }
    assert!(
        worker.child.try_wait().unwrap().is_none(),
        "barrier worker must be alive"
    );
    worker.child.kill().unwrap();
    let status = worker.child.wait().unwrap();
    assert_eq!(
        status.signal(),
        Some(9),
        "child must die from actual SIGKILL"
    );
    pid
}

fn checksum(bytes: &[u8]) -> String {
    crate::hex0x(&Keccak256::digest(bytes))
}
fn restored(path: &Path) -> Gw {
    Gw::boot_restored(&open(&read_file(path).unwrap(), &SEED).unwrap()).unwrap()
}
fn state_bytes(gw: &Gw) -> Vec<u8> {
    gw.snapshot_plain()
}
fn write_state(path: &Path, gw: &Gw) -> Vec<u8> {
    let bytes = seal(&state_bytes(gw), &SEED);
    write_atomic(path, &bytes).unwrap();
    bytes
}

/// A real funded state and signed withdrawal, with native replay-derived roots.
/// No RPC, transaction broadcast, SP1 guest or proof backend is involved.
fn funded_fixture() -> Gw {
    let mut gw = Gw::boot();
    let sk = k256::ecdsa::SigningKey::from_slice(&[0x51; 32]).unwrap();
    let point = sk.verifying_key().to_encoded_point(false);
    let digest = Keccak256::digest(&point.as_bytes()[1..]);
    let mut signer = [0; 20];
    signer.copy_from_slice(&digest[12..]);
    let (key, owner) = gw.register_account(Some(signer));
    gw.account_deposit(&key, 0, 20_000 * QUOTE_SCALE).unwrap();
    let (amount, to, nonce) = (5_000 * QUOTE_SCALE, [7; 20], 1);
    let digest = crate::withdraw_auth_digest(gw.chain_id, &gw.vault, &owner, 0, amount, &to, nonce);
    let (signature, recovery) = sk.sign_prehash_recoverable(&digest).unwrap();
    let mut signature_bytes = [0; 65];
    signature_bytes[..64].copy_from_slice(&signature.to_bytes());
    signature_bytes[64] = 27 + recovery.to_byte();
    gw.account_withdraw(&key, 0, amount, to, nonce, &signature_bytes)
        .unwrap();
    gw
}

fn sealed_fixture() -> (Gw, RollbackJournal) {
    let mut gw = funded_fixture();
    let bid = gw.seq.state.next_batch_id;
    let (witness, ww) = gw.begin_window_settle(bid).unwrap().unwrap();
    (
        gw,
        RollbackJournal {
            batch_id: bid,
            witness,
            ww,
            prepared: None,
        },
    )
}

#[test]
#[ignore = "private subprocess worker; invoked by SIGKILL parent tests only"]
fn atomic_write_crash_worker() {
    let root =
        PathBuf::from(std::env::var_os("ARCORA_TEST_CRASH_ROOT").expect("owned fixture root"));
    assert_eq!(
        std::fs::read(root.join("owned-fixture")).unwrap(),
        b"arcora-s6-02-test-only"
    );
    let mode = std::env::var("ARCORA_TEST_CRASH_MODE").unwrap();
    let stage = std::env::var("ARCORA_TEST_CRASH_STAGE").unwrap();
    let snapshot = root.join("state");
    let journal = rollback_journal::journal_path(&snapshot);
    let target = if mode == "journal" {
        &journal
    } else {
        &snapshot
    };
    if let Some(boundary) = Boundary::ALL.into_iter().find(|b| b.name() == stage) {
        INTERRUPT.with(|slot| *slot.borrow_mut() = Some((target.clone(), boundary)));
    } else {
        assert_eq!(
            (mode.as_str(), stage.as_str()),
            ("commit", "prepared-journal-before-commit-snapshot")
        );
    }
    match mode.as_str() {
        "snapshot" => {
            write_atomic(&snapshot, &std::fs::read(root.join("candidate")).unwrap()).unwrap()
        }
        "journal" => {
            let candidate = rollback_journal::read(&root.join("candidate"), &SEED)
                .unwrap()
                .unwrap();
            rollback_journal::write(&journal, &candidate, &SEED).unwrap();
        }
        "commit" => {
            let candidate = rollback_journal::read(&root.join("candidate"), &SEED)
                .unwrap()
                .unwrap();
            let batch = candidate.batch_id;
            let new_root = crate::hex32(&candidate.prepared.as_ref().unwrap().outcome.new_root);
            rollback_journal::write(&journal, &candidate, &SEED).unwrap();
            if stage == "prepared-journal-before-commit-snapshot" {
                park(&stage);
            }
            let mut gw = restored(&snapshot);
            assert_eq!(
                crate::apply_boot_recovery(
                    &mut gw,
                    candidate,
                    batch + 1,
                    &new_root,
                    77,
                    GateObservation::Inconclusive
                ),
                BootRecoveryOutcome::DeleteJournal { mutated: true }
            );
            write_state(&snapshot, &gw);
        }
        _ => panic!("unknown worker mode"),
    }
    panic!("worker completed instead of stopping at selected boundary");
}

#[test]
fn sigkill_snapshot_atomic_boundaries_restore_exact_old_or_new_state() {
    let old = Gw::boot();
    let mut new = Gw::boot_restored(&old.snapshot_plain()).unwrap();
    let (key, _) = new.register_account(None);
    new.account_deposit(&key, 0, 13_000 * QUOTE_SCALE).unwrap();
    let old_plain = state_bytes(&old);
    let new_plain = state_bytes(&new);
    assert_ne!(old_plain, new_plain);
    for boundary in Boundary::ALL {
        let dir = Scratch::new();
        let target = dir.path("state");
        let old_sealed = write_state(&target, &old);
        let new_sealed = seal(&new_plain, &SEED);
        std::fs::write(dir.path("candidate"), &new_sealed).unwrap();
        let pid = kill_at(&dir, "snapshot", boundary.name());
        let bytes = read_file(&target).unwrap();
        let expected = if boundary.published() {
            &new_sealed
        } else {
            &old_sealed
        };
        assert_eq!(
            &bytes, expected,
            "no torn/partial publication at {boundary:?}"
        );
        let back = restored(&target);
        assert_eq!(
            state_bytes(&back),
            if boundary.published() {
                new_plain.clone()
            } else {
                old_plain.clone()
            }
        );
        // A stale killed-worker temporary file cannot prevent the next valid write.
        write_atomic(&target, &new_sealed).unwrap();
        assert_eq!(read_file(&target).unwrap(), new_sealed);
        println!(
            "S6_CRASH_CASE {}",
            json!({"kind":"snapshot","boundary":boundary.name(),"owned_pid":pid,"signal":9,"published":boundary.published(),"restored_keccak256":checksum(&bytes),"state_root":crate::hex32(&back.seq.state.state_root()),"next_write":"pass"})
        );
    }
}

#[test]
fn sigkill_initial_journal_publication_retains_preseal_state() {
    for boundary in Boundary::ALL {
        let dir = Scratch::new();
        let state_path = dir.path("state");
        let target = rollback_journal::journal_path(&state_path);
        let mut gw = funded_fixture();
        let before = state_bytes(&gw);
        let old_bytes = write_state(&state_path, &gw);
        let batch_id = gw.seq.state.next_batch_id;
        let (witness, ww) = gw.begin_window_settle(batch_id).unwrap().unwrap();
        let journal = RollbackJournal {
            batch_id,
            witness,
            ww,
            prepared: None,
        };
        let expected = prove_and_prepare(&MockProverClient, &journal.witness, &journal.ww).unwrap();
        rollback_journal::write(&dir.path("candidate"), &journal, &SEED).unwrap();
        let candidate_plain = open(&read_file(&dir.path("candidate")).unwrap(), &SEED).unwrap();
        let pid = kill_at(&dir, "journal", boundary.name());
        assert_eq!(read_file(&state_path).unwrap(), old_bytes);
        let mut back = restored(&state_path);
        assert_eq!(state_bytes(&back), before);
        let found = rollback_journal::read(&target, &SEED).unwrap();
        assert_eq!(found.is_some(), boundary.published());
        if let Some(stage1) = found {
            assert!(stage1.prepared.is_none());
            assert_eq!(
                open(&read_file(&target).unwrap(), &SEED).unwrap(),
                candidate_plain
            );
            assert_eq!(
                crate::apply_boot_recovery(
                    &mut back,
                    stage1,
                    batch_id,
                    "0x00",
                    0,
                    GateObservation::Inconclusive
                ),
                BootRecoveryOutcome::DeleteJournal { mutated: false }
            );
            assert_eq!(state_bytes(&back), before);
        }
        let (again, withdrawals) = back.begin_window_settle(batch_id).unwrap().unwrap();
        let replay = prove_and_prepare(&MockProverClient, &again, &withdrawals).unwrap();
        assert_eq!(replay.outcome.new_root, expected.outcome.new_root);
        assert_eq!(replay.withdraw_proofs, expected.withdraw_proofs);
        println!(
            "S6_CRASH_CASE {}",
            json!({
                "kind":"initial-stage1-journal", "boundary":boundary.name(),
                "owned_pid":pid, "signal":9, "journal_present":boundary.published(),
                "restored_keccak256":checksum(&old_bytes), "preseal_state":"unchanged",
                "replay_root_and_withdrawals":"pass"
            })
        );
    }
}

#[test]
fn sigkill_journal_atomic_boundaries_preserve_valid_stage_and_ambiguity() {
    for boundary in Boundary::ALL {
        let dir = Scratch::new();
        let (gw, mut journal) = sealed_fixture();
        let target = rollback_journal::journal_path(&dir.path("state"));
        write_state(&dir.path("state"), &gw);
        rollback_journal::write(&target, &journal, &SEED).unwrap();
        let old_bytes = read_file(&target).unwrap();
        let old_plain = open(&old_bytes, &SEED).unwrap();
        journal.prepared =
            Some(prove_and_prepare(&MockProverClient, &journal.witness, &journal.ww).unwrap());
        rollback_journal::write(&dir.path("candidate"), &journal, &SEED).unwrap();
        let new_plain = open(&read_file(&dir.path("candidate")).unwrap(), &SEED).unwrap();
        let pid = kill_at(&dir, "journal", boundary.name());
        let bytes = read_file(&target).unwrap();
        assert_eq!(
            open(&bytes, &SEED).unwrap(),
            if boundary.published() {
                new_plain
            } else {
                old_plain
            }
        );
        if !boundary.published() {
            assert_eq!(bytes, old_bytes);
        }
        let back = rollback_journal::read(&target, &SEED).unwrap().unwrap();
        assert_eq!(back.prepared.is_some(), boundary.published());
        let mut gw = restored(&dir.path("state"));
        let before = state_bytes(&gw);
        let result = crate::apply_boot_recovery(
            &mut gw,
            back,
            journal.batch_id,
            "0x00",
            0,
            GateObservation::Inconclusive,
        );
        if boundary.published() {
            assert_eq!(result, BootRecoveryOutcome::KeepJournal);
            assert_eq!(state_bytes(&gw), before);
            assert_eq!(
                read_file(&target).unwrap(),
                bytes,
                "ambiguous journal retained byte-exact"
            );
        } else {
            assert_eq!(result, BootRecoveryOutcome::DeleteJournal { mutated: true });
            assert_eq!(gw.seq.state.next_batch_id, journal.batch_id);
            let (again, withdrawals) = gw.begin_window_settle(journal.batch_id).unwrap().unwrap();
            let expected = journal.prepared.as_ref().unwrap();
            let replay = prove_and_prepare(&MockProverClient, &again, &withdrawals).unwrap();
            assert_eq!(replay.outcome.new_root, expected.outcome.new_root);
            assert_eq!(replay.withdraw_proofs, expected.withdraw_proofs);
        }
        println!(
            "S6_CRASH_CASE {}",
            json!({"kind":"journal-stage1-to-prepared","boundary":boundary.name(),"owned_pid":pid,"signal":9,"prepared":boundary.published(),"restored_keccak256":checksum(&bytes),"recovery":format!("{result:?}")})
        );
    }
}

#[test]
fn sigkill_prepared_journal_commit_snapshot_gaps_recover_without_double_commit() {
    let stages: Vec<_> = std::iter::once("prepared-journal-before-commit-snapshot")
        .chain(Boundary::ALL.into_iter().map(Boundary::name))
        .collect();
    for stage in stages {
        let dir = Scratch::new();
        let target = dir.path("state");
        let journal_path = rollback_journal::journal_path(&target);
        let (gw, mut journal) = sealed_fixture();
        let old_bytes = write_state(&target, &gw);
        rollback_journal::write(&journal_path, &journal, &SEED).unwrap();
        let prepared = prove_and_prepare(&MockProverClient, &journal.witness, &journal.ww).unwrap();
        let root = crate::hex32(&prepared.outcome.new_root);
        let proofs = prepared.withdraw_proofs.clone();
        journal.prepared = Some(prepared);
        rollback_journal::write(&dir.path("candidate"), &journal, &SEED).unwrap();
        let old_plain = state_bytes(&gw);
        let mut committed = Gw::boot_restored(&old_plain).unwrap();
        let copy = rollback_journal::read(&dir.path("candidate"), &SEED)
            .unwrap()
            .unwrap();
        assert_eq!(
            crate::apply_boot_recovery(
                &mut committed,
                copy,
                journal.batch_id + 1,
                &root,
                77,
                GateObservation::Inconclusive
            ),
            BootRecoveryOutcome::DeleteJournal { mutated: true }
        );
        let committed_plain = state_bytes(&committed);
        assert_ne!(old_plain, committed_plain);
        let pid = kill_at(&dir, "commit", stage);
        let bytes = read_file(&target).unwrap();
        let retained = read_file(&journal_path).unwrap();
        assert!(rollback_journal::read(&journal_path, &SEED)
            .unwrap()
            .unwrap()
            .prepared
            .is_some());
        let published = matches!(
            stage,
            "renamed-before-directory-sync" | "directory-synced-before-return"
        );
        if !published {
            assert_eq!(bytes, old_bytes);
        }
        let mut back = restored(&target);
        assert_eq!(
            state_bytes(&back),
            if published {
                committed_plain
            } else {
                old_plain
            }
        );
        // A stale chain observation must retain even an already-committed snapshot.
        let before = state_bytes(&back);
        let pending = rollback_journal::read(&journal_path, &SEED)
            .unwrap()
            .unwrap();
        assert_eq!(
            crate::apply_boot_recovery(
                &mut back,
                pending,
                journal.batch_id,
                "0x00",
                0,
                GateObservation::Inconclusive
            ),
            BootRecoveryOutcome::KeepJournal
        );
        assert_eq!(state_bytes(&back), before);
        assert_eq!(read_file(&journal_path).unwrap(), retained);
        let landed = rollback_journal::read(&journal_path, &SEED)
            .unwrap()
            .unwrap();
        let resolution = crate::apply_boot_recovery(
            &mut back,
            landed,
            journal.batch_id + 1,
            &root,
            77,
            GateObservation::Inconclusive,
        );
        assert_eq!(
            resolution,
            BootRecoveryOutcome::DeleteJournal {
                mutated: !published
            }
        );
        assert_eq!(back.withdraw_proofs, proofs);
        assert_eq!(back.l1_status.as_ref().unwrap().settled_root, root);
        assert_eq!(back.seq.state.next_batch_id, journal.batch_id + 1);
        // Persist first, then delete, exactly as the boot caller does; a second
        // restoration must already be committed with no need to replay the journal.
        crate::finish_boot_recovery(&back, !published, &target, &journal_path, &SEED);
        assert!(!journal_path.exists());
        let final_state = restored(&target);
        assert_eq!(state_bytes(&final_state), state_bytes(&back));
        assert_eq!(final_state.withdraw_proofs, proofs);
        println!(
            "S6_CRASH_CASE {}",
            json!({"kind":"prepared-journal-to-commit-snapshot","boundary":stage,"owned_pid":pid,"signal":9,"commit_snapshot_published":published,"restored_keccak256":checksum(&bytes),"retained_journal_keccak256":checksum(&retained),"recovery":format!("{resolution:?}"),"restore_after_resolution":"pass"})
        );
    }
}

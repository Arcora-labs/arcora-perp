//! Native gateway/HTTP/journal integration. The loopback peer uses host replay
//! and CommitmentProver, NOT SP1, a real attestation service, or an L1 verifier.
//! Chain observations below are explicit fixtures, never claimed RPC evidence.
use super::*;
use crate::prover_client::{prove_and_prepare, HttpProverClient, ProverClient};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

const SEED: [u8; 32] = [0x36; 32];
const STALE: [u8; 32] = [0x51; 32];
const FRESH: [u8; 32] = [0x62; 32];
const MEASUREMENT: Digest = [0xAB; 32];
const CHILD_ENV: &str = "ARCORA_SETTLEMENT_NATIVE_CHILD";

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "arcora-settlement-native-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn state(&self) -> PathBuf {
        self.0.join("state")
    }
    fn journal(&self) -> PathBuf {
        rollback_journal::journal_path(&self.state())
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// HttpProverClient's public constructor reads env. Isolate those settings from
// every other concurrently running test instead of racing global set_var calls.
fn in_isolated_process(test: &str, body: impl FnOnce()) {
    if std::env::var(CHILD_ENV).ok().as_deref() == Some(test) {
        body();
        return;
    }
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            &format!("continuation_settlement_tests::{test}"),
            "--nocapture",
        ])
        .env(CHILD_ENV, test)
        .env("PROVER_SEAL_ROOT", "37".repeat(32))
        .env("PROVER_TIMEOUT_SECS", "10")
        .env_remove("DEV_INSECURE")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(45);
    while child.try_wait().unwrap().is_none() {
        if std::time::Instant::now() >= deadline {
            child.kill().unwrap();
            let output = child.wait_with_output().unwrap();
            panic!(
                "native child exceeded 45s: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "child failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

struct Fixture {
    gw: Gw,
    key: [u8; 32],
    order: Digest,
    leaf: Digest,
    dir: Scratch,
}
impl Fixture {
    fn new() -> Self {
        let mut gw = Gw::boot();
        gw.window_settle_mode = true;
        gw.seq.set_retain_tick_snapshots(false);
        let sk = k256::ecdsa::SigningKey::from_slice(&[0x73; 32]).unwrap();
        let public = sk.verifying_key().to_encoded_point(false);
        let hash = <sha3::Keccak256 as sha3::Digest>::digest(&public.as_bytes()[1..]);
        let signer = hash[12..].try_into().unwrap();
        let (key, owner) = gw.register_account(Some(signer));
        gw.account_deposit(&key, 0, 20_000 * QUOTE_SCALE).unwrap();
        let amount = 5_000 * QUOTE_SCALE;
        let to = [7; 20];
        let digest = withdraw_auth_digest(gw.chain_id, &gw.vault, &owner, 0, amount, &to, 1);
        let (sig, recovery) = sk.sign_prehash_recoverable(&digest).unwrap();
        let mut signature = [0; 65];
        signature[..64].copy_from_slice(&sig.to_bytes());
        signature[64] = 27 + recovery.to_byte();
        let withdrawal = gw
            .account_withdraw(&key, 0, amount, to, 1, &signature)
            .unwrap();
        gw.place_order(&OrderReq {
            market_id: 0,
            side: "Buy".into(),
            size: (SIZE_SCALE / 10).to_string(),
            limit_price: "0".into(),
            tif: "Ioc".into(),
            ..Default::default()
        })
        .unwrap();
        let order = gw.orders[0].order_hash;
        for _ in 0..(SETTLE_TICKS * 2) {
            gw.tick();
        }
        let fixture = Self {
            gw,
            key,
            order,
            leaf: withdrawal.leaf(),
            dir: Scratch::new(),
        };
        fixture.assert_uncommitted();
        fixture
    }
    fn assert_uncommitted(&self) {
        assert_eq!(self.gw.finality_str(&self.order), "MATCHED");
        assert!(self.gw.withdraw_proofs.is_empty());
        assert!(self.gw.l1_status.is_none());
        let response = self.gw.v1_withdrawals_json(&self.key).unwrap();
        let withdrawals = response["withdrawals"].as_array().unwrap();
        assert_eq!(
            withdrawals.len(),
            1,
            "fixture must exercise a real pending withdrawal"
        );
        assert_eq!(withdrawals[0]["claimable"], false);
        assert_eq!(withdrawals[0]["proof"], serde_json::json!([]));
    }
    fn seal_and_persist(&mut self) -> rollback_journal::RollbackJournal {
        let batch = self.gw.seq.state.next_batch_id;
        let journal =
            begin_journaled_window_settle(&mut self.gw, batch, Some(&self.dir.journal()), &SEED)
                .unwrap()
                .unwrap();
        assert!(journal.witness.manifest.ordered.contains(&self.order));
        assert_eq!(journal.ww.len(), 1);
        assert_eq!(journal.ww[0].leaf(), self.leaf);
        persist_recovery(&self.gw, &self.dir.state(), &SEED).unwrap();
        journal
    }
    fn restore(&mut self) {
        let plain = snapshot::open(&std::fs::read(self.dir.state()).unwrap(), &SEED).unwrap();
        self.gw = Gw::boot_restored(&plain).unwrap();
        // Main installs its role's finality policy after restoring the snapshot.
        self.gw.window_settle_mode = true;
        self.gw.seq.set_retain_tick_snapshots(false);
    }
    fn read_journal(&self) -> rollback_journal::RollbackJournal {
        rollback_journal::read(&self.dir.journal(), &SEED)
            .unwrap()
            .unwrap()
    }
    fn rollback_unsubmitted(&mut self, journal: rollback_journal::RollbackJournal) {
        assert!(
            journal.prepared.is_none(),
            "only stage 1 proves no broadcast occurred"
        );
        let batch = journal.batch_id;
        assert_eq!(
            apply_boot_recovery(
                &mut self.gw,
                journal,
                batch,
                "0x00",
                0,
                trading_gate::GateObservation::Inconclusive
            ),
            BootRecoveryOutcome::DeleteJournal { mutated: true }
        );
        finish_boot_recovery(
            &self.gw,
            true,
            &self.dir.state(),
            &self.dir.journal(),
            &SEED,
        );
        assert!(!self.dir.journal().exists());
        self.assert_uncommitted();
    }
    fn restart_and_reseal(&mut self) -> rollback_journal::RollbackJournal {
        let original = self.seal_and_persist();
        let bytes = postcard::to_allocvec(&original.witness).unwrap();
        self.restore();
        self.rollback_unsubmitted(self.read_journal());
        self.restore();
        let retry = self.seal_and_persist();
        assert_eq!(
            postcard::to_allocvec(&retry.witness).unwrap(),
            bytes,
            "known-unsubmitted restart must retry the identical window"
        );
        retry
    }
}

#[derive(Clone, Copy)]
enum Reply {
    Honest,
    Unauthorized,
    WrongPreviousRoot,
    WrongPhase,
}

fn read_request(stream: &mut TcpStream) -> (String, prover::SealedWitness) {
    // Accepted sockets inherit the listener's nonblocking mode on macOS. The
    // parser below is deliberately blocking with bounded read/write timeouts.
    stream.set_nonblocking(false).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut wire = Vec::new();
    let header_end = loop {
        let mut chunk = [0; 4096];
        let n = stream.read(&mut chunk).unwrap();
        assert!(n > 0, "request ended before headers");
        wire.extend_from_slice(&chunk[..n]);
        if let Some(index) = wire.windows(4).position(|w| w == b"\r\n\r\n") {
            break index + 4;
        }
        assert!(wire.len() < 16 * 1024, "oversized test request headers");
    };
    let headers = String::from_utf8(wire[..header_end].to_vec())
        .unwrap()
        .to_ascii_lowercase();
    assert!(headers.starts_with("post /prove http/1.1\r\n"));
    let length: usize = headers
        .lines()
        .find_map(|line| line.strip_prefix("content-length:").map(str::trim))
        .unwrap()
        .parse()
        .unwrap();
    assert!(length < 2 * 1024 * 1024, "bounded native fixture body");
    if headers.contains("expect: 100-continue") {
        stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").unwrap();
    }
    while wire.len() < header_end + length {
        let mut chunk = [0; 8192];
        let n = stream.read(&mut chunk).unwrap();
        assert!(n > 0, "truncated request body");
        wire.extend_from_slice(&chunk[..n]);
    }
    let body: serde_json::Value =
        serde_json::from_slice(&wire[header_end..header_end + length]).unwrap();
    let sealed = decode_hex(body["sealed"].as_str().unwrap()).unwrap();
    (headers, postcard::from_bytes(&sealed).unwrap())
}

fn native_prover(secret: [u8; 32]) -> prover::AttestedProver<prover::CommitmentProver> {
    prover::AttestedProver::new(
        prover::CommitmentProver::new(MEASUREMENT),
        prover::AttestedSealProvider {
            session_secret: secret,
            measurement: MEASUREMENT,
        },
    )
}

// Two real HTTP requests exercise curl, parsing, re-auth, refreshed-key sealing
// and native witness opening. A scripted 401 models server-side expiry/rotation.
fn peer(reply: Reply) -> (String, std::thread::JoinHandle<usize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let thread = std::thread::spawn(move || {
        for attempt in 0..2 {
            let deadline = std::time::Instant::now() + Duration::from_secs(15);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            std::time::Instant::now() < deadline,
                            "expected prover request {attempt}"
                        );
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(e) => panic!("accept: {e}"),
                }
            };
            let (headers, sealed) = read_request(&mut stream);
            let expected = if attempt == 0 {
                "stale-session"
            } else {
                "fresh-session"
            };
            assert!(headers.contains(&format!("authorization: bearer {expected}\r\n")));
            let secret = if attempt == 0 { STALE } else { FRESH };
            let mut proof = native_prover(secret)
                .prove_batch(&sealed)
                .expect("request opens under its matching session secret");
            let wrong = if attempt == 0 { FRESH } else { STALE };
            assert_eq!(
                native_prover(wrong).prove_batch(&sealed).unwrap_err(),
                prover::ProverError::SealAuthFailed,
                "refresh must change the actual sealing key"
            );
            let (status, body) = if attempt == 0 || matches!(reply, Reply::Unauthorized) {
                (401, "expired session".to_owned())
            } else {
                match reply {
                    Reply::WrongPreviousRoot => proof.public.prev_state_root[0] ^= 1,
                    Reply::WrongPhase => proof.public.wind_down_phase = 2,
                    _ => (),
                }
                (
                    200,
                    serde_json::json!({
                        "prev_root": hex32(&proof.public.prev_state_root),
                        "commitment": hex32(&proof.public.commitment::<Keccak256>()),
                        "proof": hex0x(&proof.proof_bytes),
                    })
                    .to_string(),
                )
            };
            write!(
                stream,
                "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
        }
        2
    });
    (url, thread)
}

fn client(url: &str) -> (HttpProverClient, Arc<AtomicUsize>) {
    let count = Arc::new(AtomicUsize::new(0));
    let calls = count.clone();
    let client = HttpProverClient::from_env(url, false)
        .unwrap()
        .with_session_token(Some("stale-session".into()))
        .with_session_secret(Some(STALE), 1)
        .with_rehandshake(Box::new(move || {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(("fresh-session".into(), FRESH, u64::MAX))
        }));
    (client, count)
}

#[test]
fn restart_expired_session_retry_pending_then_durable_roll_forward() {
    in_isolated_process(
        "restart_expired_session_retry_pending_then_durable_roll_forward",
        || {
            let mut f = Fixture::new();
            let mut journal = f.restart_and_reseal();
            let (url, server) = peer(Reply::Honest);
            let (client, refreshes) = client(&url);
            let prepared = prove_and_prepare(&client, &journal.witness, &journal.ww).unwrap();
            assert_eq!(server.join().unwrap(), 2);
            assert_eq!(refreshes.load(Ordering::SeqCst), 1);
            f.assert_uncommitted(); // proof completion alone grants nothing
            let root = hex32(&prepared.outcome.new_root);
            let withdrawal_root = prepared.outcome.withdrawals_root;
            let batch = journal.batch_id;
            journal.prepared = Some(prepared);
            after_settle_journal(Some(&f.dir.journal()), &journal, &SEED, || ()).unwrap();
            let journal_bytes = std::fs::read(f.dir.journal()).unwrap();
            f.restore();
            let before = f.gw.snapshot_plain();
            // Pending, wrong root, and wrong batch are all inconclusive. A prepared
            // journal must survive every one, because its transaction may still land.
            for (chain_batch, chain_root) in [
                (batch, hex32(&f.gw.last_settled_root)),
                (batch + 1, hex32(&[0xEE; 32])),
                (batch + 2, root.clone()),
            ] {
                let pending = f.read_journal();
                assert_eq!(
                    apply_boot_recovery(
                        &mut f.gw,
                        pending,
                        chain_batch,
                        &chain_root,
                        0,
                        trading_gate::GateObservation::Inconclusive
                    ),
                    BootRecoveryOutcome::KeepJournal
                );
                assert_eq!(f.gw.snapshot_plain(), before);
                assert_eq!(std::fs::read(f.dir.journal()).unwrap(), journal_bytes);
                f.assert_uncommitted();
            }
            let landed = f.read_journal();
            assert_eq!(
                apply_boot_recovery(
                    &mut f.gw,
                    landed,
                    batch + 1,
                    &root,
                    0,
                    trading_gate::GateObservation::Inconclusive
                ),
                BootRecoveryOutcome::DeleteJournal { mutated: true }
            );
            finish_boot_recovery(&f.gw, true, &f.dir.state(), &f.dir.journal(), &SEED);
            assert!(!f.dir.journal().exists());
            f.restore();
            assert_eq!(f.gw.finality_str(&f.order), "SETTLED");
            let (published, proof) = &f.gw.withdraw_proofs[&f.leaf];
            assert_eq!(*published, withdrawal_root);
            assert!(withdrawals::verify(*published, f.leaf, proof));
            assert_eq!(
                f.gw.v1_withdrawals_json(&f.key).unwrap()["withdrawals"][0]["claimable"],
                true
            );
            assert_eq!(f.gw.l1_status.as_ref().unwrap().settled_root, root);
            let committed = f.gw.snapshot_plain();
            // A leftover durable journal after a crash in deletion is stale; no
            // duplicate finality, withdrawal insertion, or balance mutation.
            std::fs::write(f.dir.journal(), journal_bytes).unwrap();
            let stale = f.read_journal();
            assert_eq!(
                apply_boot_recovery(
                    &mut f.gw,
                    stale,
                    batch + 1,
                    &root,
                    0,
                    trading_gate::GateObservation::Inconclusive
                ),
                BootRecoveryOutcome::DeleteJournal { mutated: false }
            );
            finish_boot_recovery(&f.gw, false, &f.dir.state(), &f.dir.journal(), &SEED);
            assert_eq!(f.gw.snapshot_plain(), committed);
        },
    );
}

fn rejected_after_refresh(reply: Reply, expected: &str) {
    let mut f = Fixture::new();
    let journal = f.restart_and_reseal();
    let witness = postcard::to_allocvec(&journal.witness).unwrap();
    let durable = std::fs::read(f.dir.journal()).unwrap();
    let (url, server) = peer(reply);
    let (client, refreshes) = client(&url);
    let error = match prove_and_prepare(&client, &journal.witness, &journal.ww) {
        Ok(_) => panic!("invalid prover reply must not prepare settlement"),
        Err(error) => error,
    };
    assert!(error.contains(expected), "{error}");
    assert_eq!(server.join().unwrap(), 2);
    assert_eq!(refreshes.load(Ordering::SeqCst), 1);
    assert_eq!(std::fs::read(f.dir.journal()).unwrap(), durable);
    assert!(f.read_journal().prepared.is_none());
    f.assert_uncommitted();
    f.restore();
    f.rollback_unsubmitted(f.read_journal());
    let retry = f.seal_and_persist();
    assert_eq!(postcard::to_allocvec(&retry.witness).unwrap(), witness);
    f.assert_uncommitted();
}

#[test]
fn restart_second_401_is_terminal_and_unsubmitted_window_reseals() {
    in_isolated_process(
        "restart_second_401_is_terminal_and_unsubmitted_window_reseals",
        || rejected_after_refresh(Reply::Unauthorized, "Unauthorized"),
    );
}

#[test]
fn restart_previous_root_mismatch_after_reauth_never_prepares_or_claims() {
    in_isolated_process(
        "restart_previous_root_mismatch_after_reauth_never_prepares_or_claims",
        || rejected_after_refresh(Reply::WrongPreviousRoot, "prev_root"),
    );
}

#[test]
fn restart_phase_commitment_mismatch_after_reauth_never_prepares_or_claims() {
    // Only change the remote ordinary window's commitment phase; this executes
    // no wind-down operations and makes no guest/contract parity claim.
    in_isolated_process(
        "restart_phase_commitment_mismatch_after_reauth_never_prepares_or_claims",
        || rejected_after_refresh(Reply::WrongPhase, "commitment mismatch"),
    );
}

struct MustNotProve;
impl ProverClient for MustNotProve {
    fn prove(
        &self,
        _: &WindowWitness,
    ) -> Result<prover_client::RemoteProveResp, prover_client::ProverClientError> {
        panic!("invalid local manifest must reject before transport")
    }
}

fn invalid_manifest_after_restart(wrong_batch: bool) {
    let mut f = Fixture::new();
    let journal = f.restart_and_reseal();
    let durable = std::fs::read(f.dir.journal()).unwrap();
    let mut witness = journal.witness.clone();
    if wrong_batch {
        witness.manifest.batch_id += 1;
    } else {
        witness.manifest.previous_state_root[0] ^= 1;
    }
    let error = match prove_and_prepare(&MustNotProve, &witness, &journal.ww) {
        Err(error) => error,
        Ok(_) => panic!("malformed manifest unexpectedly prepared"),
    };
    assert!(error.contains("ManifestMismatch"), "{error}");
    assert_eq!(std::fs::read(f.dir.journal()).unwrap(), durable);
    f.assert_uncommitted();
}

#[test]
fn restart_wrong_manifest_batch_refuses_before_transport() {
    invalid_manifest_after_restart(true);
}

#[test]
fn restart_wrong_manifest_previous_root_refuses_before_transport() {
    invalid_manifest_after_restart(false);
}

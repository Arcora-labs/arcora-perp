//! Fixed native diagnostics, not an admission limit or production capacity test.
//! No gateway boot, account ingress, network, actual proof, or durable WAL I/O.
use super::*;
use perp_core::clock::{ClockContext, TimeBounds};
use perp_core::engine::BatchOp;
use perp_core::fixed::{PRICE_SCALE, QUOTE_SCALE};
use perp_core::note::owner_from_spend_key;
use perp_core::oracle::{oracle_digest, OracleSig, OracleTranscript};
use perp_core::Note;
use sequencer::Sequencer;
use std::sync::atomic::{AtomicUsize, Ordering};

const CASES: [(&str, usize, usize); 3] = [
    ("notes64_withdrawals16", 64, 16),
    ("notes160_withdrawals16", 160, 16),
    ("notes160_withdrawals48", 160, 48),
];
const SEAL_ROOT: Digest = [0x91; 32];
const MEASUREMENT: Digest = [0xab; 32];

fn bytes<T: serde::Serialize>(value: &T) -> Vec<u8> {
    postcard::to_allocvec(value).unwrap()
}

fn oracle(at: u64) -> OracleTranscript {
    let key = k256::ecdsa::SigningKey::from_slice(&[7; 32]).unwrap();
    let (price, confidence) = (100_000 * PRICE_SCALE, 10 * PRICE_SCALE);
    OracleTranscript {
        price,
        publish_time_ms: at,
        confidence,
        backup_twap: price,
        signature: OracleSig::sign(&key, &oracle_digest(0, price, at, confidence, price)),
    }
}

struct Fixture {
    name: &'static str,
    notes: usize,
    witness: WindowWitness,
    withdrawals: Vec<Withdrawal>,
    prepared: PreparedSettle,
    clock: ClockContext,
    post_bytes: Vec<u8>,
}

fn fixture(case: usize) -> Fixture {
    let (name, count, withdrawal_count) = CASES[case];
    // PR65's unchanged native, funded Sequencer. Only value-preserving native
    // Unbind/Withdraw and a signed funding tick are added. No fabricated deposits.
    let mut seq: Sequencer = postcard::from_bytes(include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/audits/2026-10-14-seal-window-ownership/baseline-export/",
        "normal-00-before_first_seal_seq.bin"
    )))
    .unwrap();
    let owner = owner_from_spend_key::<Keccak256>(&[1; 32]);
    let mut notes = Vec::with_capacity(count);
    for index in 0..count {
        let mut blinding = [0xe1; 32];
        blinding[..8].copy_from_slice(&(index as u64).to_be_bytes());
        let at = 3_000 + index as u64;
        seq.apply(&BatchOp::Unbind {
            owner,
            market_id: 0,
            amount: QUOTE_SCALE,
            blinding,
            oracle: oracle(at),
            now_ms: at,
        })
        .unwrap();
        notes.push(Note::new(owner, 0, QUOTE_SCALE, blinding));
    }
    let bootstrap = seq.seal_window();
    let mut boot_post = bootstrap.pre_state.clone();
    let boot_roots = derive_roots(&mut boot_post, &bootstrap.ops, &bootstrap.manifest).unwrap();
    assert_eq!(boot_roots.new_state_root, seq.state.state_root());
    assert_eq!(seq.state.notes.len(), count);
    // Drop construction history before constructing the measured input.
    drop((bootstrap, boot_post));
    seq.apply(&BatchOp::AccrueFunding {
        market_id: 0,
        mark: 100_000 * PRICE_SCALE,
        oracle: oracle(5_000),
        now_ms: 5_000,
    })
    .unwrap();
    let mut withdrawals = Vec::with_capacity(withdrawal_count);
    for (index, note) in notes.iter().take(withdrawal_count).enumerate() {
        let to = [u8::try_from(index + 1).unwrap(); 20];
        let nonce = 1_000 + index as u64;
        seq.apply(&BatchOp::Withdraw {
            note_commitment: note.commitment::<Keccak256>(),
            spend_key: [1; 32],
            to: Some(to),
            nonce,
        })
        .unwrap();
        withdrawals.push(Withdrawal {
            owner,
            to,
            amount: QUOTE_SCALE as u128,
            nonce,
        });
    }
    let witness = seq.seal_window();
    assert_eq!(witness.pre_state.notes.len(), count);
    assert_eq!(seq.state.notes.len(), count - withdrawal_count);
    let post_bytes = bytes(&seq.state);
    let prepared = prepare_unproved(&witness, &withdrawals).unwrap();
    assert_eq!(prepared.outcome.new_root, seq.state.state_root());
    let bounds = TimeBounds::derive(&witness.ops).unwrap();
    assert_eq!(bounds.count, 1);
    let clock = ClockContext {
        chain_id: 84532,
        verifier: [1; 20],
        settlement: [2; 20],
        batch_id: witness.batch_id,
        previous_root: prepared.outcome.prev_root,
        base_commitment: prepared.outcome.commitment,
        phase: prepared.outcome.wind_down_phase,
        first_ms: bounds.first_ms,
        last_ms: bounds.last_ms,
        timed_ops: bounds.count,
        anchored_at_ms: bounds.last_ms,
        max_window_ms: 60_000,
        clock_skew_ms: 2_000,
    };
    Fixture {
        name,
        notes: count,
        witness,
        withdrawals,
        prepared,
        clock,
        post_bytes,
    }
}

struct CachedClient<'a> {
    f: &'a Fixture,
    clocked: bool,
    contexts: AtomicUsize,
    proves: AtomicUsize,
}
impl<'a> CachedClient<'a> {
    fn new(f: &'a Fixture, clocked: bool) -> Self {
        Self {
            f,
            clocked,
            contexts: AtomicUsize::new(0),
            proves: AtomicUsize::new(0),
        }
    }
    fn response(&self) -> RemoteProveResp {
        self.proves.fetch_add(1, Ordering::Relaxed);
        let o = &self.f.prepared.outcome;
        RemoteProveResp {
            roots: RemoteRoots {
                prev_root: Some(o.prev_root),
                manifest_hash: Some(o.manifest_hash),
                new_root: Some(o.new_root),
                ordered_root: Some(o.ordered_root),
                withdrawals_root: Some(o.withdrawals_root),
                rejected_root: Some(o.rejected_root),
                deposits_root: Some(o.deposits_root),
            },
            commitment: if self.clocked {
                self.f.clock.commitment()
            } else {
                o.commitment
            },
            proof: vec![0x6a; 32], // Synthetic cached bytes, never a real proof.
        }
    }
}
impl ProverClient for CachedClient<'_> {
    fn clock_enabled(&self) -> bool {
        self.clocked
    }
    fn clock_context(&self, _: &WindowWitness) -> Result<Option<ClockContext>, ProverClientError> {
        self.contexts.fetch_add(1, Ordering::Relaxed);
        Ok(self.clocked.then_some(self.f.clock))
    }
    fn prove(&self, _: &WindowWitness) -> Result<RemoteProveResp, ProverClientError> {
        assert!(!self.clocked, "no clock downgrade");
        Ok(self.response())
    }
    fn prove_clocked(
        &self,
        _: &WindowWitness,
        clock: &ClockContext,
    ) -> Result<RemoteProveResp, ProverClientError> {
        assert!(self.clocked);
        assert_eq!(*clock, self.f.clock);
        Ok(self.response())
    }
}

fn assert_prepared(f: &Fixture, actual: &PreparedSettle, clocked: Option<bool>) {
    let mut base = actual.clone();
    base.outcome.proof.clear();
    assert_eq!(bytes(&base), bytes(&f.prepared));
    let mut proof = Vec::new();
    if let Some(clocked) = clocked {
        if clocked {
            proof.extend_from_slice(perp_core::clock::PROOF_MAGIC);
            proof.extend_from_slice(&f.clock.receipt());
        }
        proof.extend_from_slice(&[0x6a; 32]);
    }
    assert_eq!(actual.outcome.proof, proof);
    assert_eq!(actual.withdraw_proofs.len(), f.withdrawals.len());
    for (index, withdrawal) in f.withdrawals.iter().enumerate() {
        // The native sorted-pair tree promotes an unpaired node unchanged.
        // For 48 leaves, the last 16 therefore have one fewer sibling.
        let expected_path = match f.withdrawals.len() {
            16 => 4,
            48 if index < 32 => 6,
            48 => 5,
            _ => panic!("unsupported fixed fixture"),
        };
        let (root, path) = &actual.withdraw_proofs[&withdrawal.leaf()];
        assert_eq!(*root, actual.outcome.withdrawals_root);
        assert_eq!(path.len(), expected_path);
        assert!(perp_core::merkle::verify(*root, withdrawal.leaf(), path));
    }
}

fn sealed_hex(f: &Fixture, clocked: bool) -> String {
    seal_witness_with_clock(
        &f.witness,
        &SEAL_ROOT,
        &MEASUREMENT,
        None,
        clocked.then_some(&f.clock),
    )
    .unwrap()
}

fn frame_sizes(f: &Fixture) -> serde_json::Value {
    let w = &f.witness;
    let mut sizes = serde_json::Map::new();
    for (name, value) in [
        ("pre_state_postcard_bytes", bytes(&w.pre_state).len()),
        ("witness_postcard_bytes", bytes(w).len()),
        ("prepared_intent_postcard_bytes", bytes(&f.prepared).len()),
        (
            "withdrawal_list_postcard_bytes",
            bytes(&f.withdrawals).len(),
        ),
    ] {
        sizes.insert(name.into(), value.into());
    }
    for clocked in [false, true] {
        let prefix = if clocked { "clocked" } else { "legacy" };
        let wire = if clocked {
            [
                perp_core::clock::WIRE_MAGIC,
                bytes(&(&w.pre_state, &w.ops, &w.manifest, &f.clock)).as_slice(),
            ]
            .concat()
        } else {
            bytes(&(&w.pre_state, &w.ops, &w.manifest))
        };
        let hexed = sealed_hex(f, clocked);
        let encoded: Vec<u8> = hexed
            .strip_prefix("0x")
            .unwrap()
            .as_bytes()
            .chunks_exact(2)
            .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
            .collect();
        let expected = prover::SealedWitness::seal(
            &wire,
            &prover::SoftwareSealProvider::new(SEAL_ROOT, MEASUREMENT),
            MEASUREMENT,
            seal_nonce(&SEAL_ROOT, &wire),
        )
        .unwrap();
        assert_eq!(encoded, bytes(&expected));
        assert_eq!(
            bytes(&postcard::from_bytes::<prover::SealedWitness>(&encoded).unwrap()),
            encoded
        );
        let body = serde_json::json!({"sealed": hexed}).to_string();
        assert_eq!(body.len(), prove_request_json_bytes(encoded.len()).unwrap());
        sizes.insert(format!("{prefix}_plaintext_bytes"), wire.len().into());
        sizes.insert(
            format!("{prefix}_sealed_envelope_bytes"),
            encoded.len().into(),
        );
        sizes.insert(format!("{prefix}_request_json_bytes"), body.len().into());
    }
    // Actual in-memory v5 journal frame, validated by the production decoder.
    // No write/fsync/recovery acceptance is inferred from this codec exercise.
    let journal = crate::rollback_journal::RollbackJournal {
        batch_id: w.batch_id,
        witness: w.clone(),
        ww: f.withdrawals.clone(),
        prepared: Some(f.prepared.clone()),
    };
    let plain = [b"DPRBJL5\0".as_slice(), bytes(&journal).as_slice()].concat();
    let sealed = crate::snapshot::seal(&plain, &[0x44; 32]);
    match crate::rollback_journal::open_versioned(&sealed, &[0x44; 32]).unwrap() {
        crate::rollback_journal::OpenedJournal::Legacy(decoded) => {
            assert_eq!(bytes(&decoded), bytes(&journal))
        }
        _ => panic!("wrong journal version"),
    }
    sizes.insert(
        "legacy_journal_intent_in_memory_bytes".into(),
        sealed.len().into(),
    );
    serde_json::Value::Object(sizes)
}

fn metadata(f: &Fixture) -> serde_json::Value {
    use sha2::{Digest as _, Sha256};
    serde_json::json!({
        "fixture": f.name, "pre_live_notes": f.notes,
        "post_live_notes": f.notes - f.withdrawals.len(), "withdrawals": f.withdrawals.len(),
        "ops": f.witness.ops.len(), "timed_ops": f.clock.timed_ops,
        "claim_count": f.prepared.withdraw_proofs.len(),
        "claim_path_siblings": f.prepared.withdraw_proofs.values().map(|(_, p)| p.len()).collect::<Vec<_>>(),
        "witness_sha256": format!("{:x}", Sha256::digest(bytes(&f.witness))),
        "prepared_intent_sha256": format!("{:x}", Sha256::digest(bytes(&f.prepared))),
        "frames": frame_sizes(f), "proof": "synthetic_cached_stub", "seal": "software_test_keys",
    })
}

fn assert_fixture(f: &Fixture) {
    let before = bytes(&(&f.witness, &f.withdrawals));
    let mut post = f.witness.pre_state.clone();
    let roots = derive_roots(&mut post, &f.witness.ops, &f.witness.manifest).unwrap();
    assert_eq!(bytes(&post), f.post_bytes);
    assert_eq!(
        roots.commitment::<Keccak256>(),
        f.prepared.outcome.commitment
    );
    f.clock
        .validate(f.witness.batch_id, &roots, &f.witness.ops)
        .unwrap();
    assert_eq!(f.witness.ops.len(), f.withdrawals.len() + 1);
    assert_eq!(f.prepared.outcome.new_deposit_count, 2);
    assert!(f.prepared.outcome.post_mode_is_normal);
    assert_prepared(f, &f.prepared, None);
    let decoded: WindowWitness = postcard::from_bytes(&bytes(&f.witness)).unwrap();
    assert_eq!(bytes(&decoded), bytes(&f.witness));
    for clocked in [false, true] {
        let client = CachedClient::new(f, clocked);
        let prepared = prove_and_prepare(&client, &f.witness, &f.withdrawals).unwrap();
        assert_prepared(f, &prepared, Some(clocked));
        assert_eq!(client.contexts.load(Ordering::Relaxed), 1);
        assert_eq!(client.proves.load(Ordering::Relaxed), 1);
    }
    assert_eq!(bytes(&(&f.witness, &f.withdrawals)), before);
}

macro_rules! case_tests {
    ($correct:ident, $rss:ident, $index:expr) => {
        #[test]
        fn $correct() {
            let f = fixture($index);
            assert_fixture(&f);
            let m = metadata(&f);
            // Rebuilding from the fixed source must reproduce the exact input/output.
            let rebuilt = fixture($index);
            assert_eq!(bytes(&f.witness), bytes(&rebuilt.witness));
            assert_eq!(bytes(&f.prepared), bytes(&rebuilt.prepared));
            println!("FINITE_FIXTURE {m}");
        }
        #[test]
        #[ignore = "whole fresh-child RSS diagnostic; invoke separately with the runner"]
        fn $rss() {
            let f = fixture($index);
            assert_fixture(&f);
            println!("FINITE_RSS_FIXTURE {}", metadata(&f));
            std::hint::black_box(f);
        }
    };
}
case_tests!(native_64_16, rss_64_16, 0);
case_tests!(native_160_16, rss_160_16, 1);
case_tests!(native_160_48, rss_160_48, 2);

#[test]
fn finite_committed_withdrawal_mutations_refused_before_callbacks() {
    for case in 0..CASES.len() {
        let f = fixture(case);
        let before = bytes(&(&f.witness, &f.withdrawals));
        for variant in 0..4 {
            let mut withdrawals = f.withdrawals.clone();
            match variant {
                0 => withdrawals[0].to[0] ^= 1,
                1 => withdrawals[0].amount += 1,
                2 => withdrawals[0].nonce += 1,
                _ => {
                    withdrawals.pop();
                }
            }
            let client = CachedClient::new(&f, true);
            let error = prove_and_prepare(&client, &f.witness, &withdrawals).unwrap_err();
            assert!(error.contains("withdrawals root mismatch"));
            assert_eq!(client.contexts.load(Ordering::Relaxed), 0);
            assert_eq!(client.proves.load(Ordering::Relaxed), 0);
        }
        assert_eq!(bytes(&(&f.witness, &f.withdrawals)), before);
    }
}

#[cfg(target_os = "macos")]
mod observation {
    use super::*;
    use std::{hint::black_box, time::Instant};
    unsafe extern "C" {
        fn clock_gettime_nsec_np(clock_id: std::os::raw::c_int) -> u64;
    }
    fn thread_cpu_ns() -> u64 {
        // Same scalar-only Darwin thread CPU clock as PR67, not elapsed wall time.
        let value = unsafe { clock_gettime_nsec_np(16) };
        assert!(value > 0, "thread CPU clock unavailable");
        value
    }
    fn measure<T, R>(
        f: &Fixture,
        phase: &str,
        mut setup: impl FnMut() -> T,
        mut run: impl FnMut(T) -> R,
        check: impl Fn(&R),
    ) {
        check(&run(setup()));
        for round in 0..5 {
            let inputs: Vec<T> = (0..10).map(|_| setup()).collect();
            let mut outputs = Vec::with_capacity(10);
            let wall = Instant::now();
            let cpu = thread_cpu_ns();
            for input in inputs {
                outputs.push(black_box(run(black_box(input))));
            }
            let thread_cpu_ns = thread_cpu_ns().checked_sub(cpu).unwrap();
            let wall_ns = wall.elapsed().as_nanos();
            // Setup, checks and output destruction are excluded. Input destruction
            // and result pushes are included. Overlapping phases are NOT additive.
            for output in &outputs {
                check(output);
            }
            println!(
                "FINITE_CPU_SAMPLE {}",
                serde_json::json!({
                    "fixture": f.name, "phase": phase, "round": round,
                    "repetitions": 10, "thread_cpu_ns": thread_cpu_ns, "wall_ns": wall_ns,
                })
            );
        }
    }
    #[test]
    #[ignore = "bounded release thread CPU diagnostic; invoke with one test thread"]
    fn finite_preparation_cpu() {
        for case in 0..CASES.len() {
            let f = fixture(case);
            assert_fixture(&f);
            let before = bytes(&(&f.witness, &f.withdrawals));
            measure(
                &f,
                "state_clone",
                || &f.witness.pre_state,
                |s| s.clone(),
                |s| assert_eq!(bytes(s), bytes(&f.witness.pre_state)),
            );
            measure(
                &f,
                "native_replay_owned",
                || f.witness.pre_state.clone(),
                |mut s| derive_roots(&mut s, &f.witness.ops, &f.witness.manifest).unwrap(),
                |r| assert_eq!(r.commitment::<Keccak256>(), f.prepared.outcome.commitment),
            );
            measure(
                &f,
                "claim_paths",
                || &f.withdrawals,
                |withdrawals| {
                    let leaves: Vec<Digest> = withdrawals.iter().map(|w| w.leaf()).collect();
                    let root = merkle_root(&leaves);
                    withdrawals
                        .iter()
                        .enumerate()
                        .map(|(i, w)| (w.leaf(), (root, merkle_proof(&leaves, i))))
                        .collect::<BTreeMap<_, _>>()
                },
                |paths| assert_eq!(bytes(paths), bytes(&f.prepared.withdraw_proofs)),
            );
            measure(
                &f,
                "prepare_unproved_total",
                || &f.witness,
                |w| prepare_unproved(w, &f.withdrawals).unwrap(),
                |p| assert_prepared(&f, p, None),
            );
            for clocked in [false, true] {
                let client = CachedClient::new(&f, clocked);
                let phase = if clocked {
                    "clocked_prepare_cached_stub_total"
                } else {
                    "legacy_prepare_cached_stub_total"
                };
                measure(
                    &f,
                    phase,
                    || &client,
                    |c| prove_and_prepare(c, &f.witness, &f.withdrawals).unwrap(),
                    |p| assert_prepared(&f, p, Some(clocked)),
                );
                assert_eq!(client.contexts.load(Ordering::Relaxed), 51);
                assert_eq!(client.proves.load(Ordering::Relaxed), 51);
                let reference = sealed_hex(&f, clocked);
                let phase = if clocked {
                    "clocked_software_seal_hex"
                } else {
                    "legacy_software_seal_hex"
                };
                measure(
                    &f,
                    phase,
                    || &f,
                    |f| sealed_hex(f, clocked),
                    |v| assert_eq!(*v, reference),
                );
            }
            assert_eq!(bytes(&(&f.witness, &f.withdrawals)), before);
        }
    }
}

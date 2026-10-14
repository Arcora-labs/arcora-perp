//! Bounded diagnostic preparation measurements; no production instrumentation.
//! The committed PR65 inputs are reused unchanged. No gateway boot, environment,
//! service, filesystem archive, proof generation, or live clock registration.
use crate::prover_client::{
    prepare_unproved, prove_and_prepare, PreparedSettle, ProverClient, ProverClientError,
    RemoteProveResp, RemoteRoots,
};
use perp_core::clock::{ClockContext, TimeBounds};
use perp_core::commitment::{derive_roots, DerivedRoots};
use perp_core::hash::Keccak256;
use sequencer::{Sequencer, WindowWitness};
use std::sync::atomic::{AtomicUsize, Ordering};

macro_rules! golden {
    ($name:literal) => {
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/audits/2026-10-14-seal-window-ownership/baseline-export/",
            $name
        )) as &[u8]
    };
}

struct Fixture {
    name: &'static str,
    sequencer: Sequencer,
    sequencer_bytes: &'static [u8],
    witness: WindowWitness,
    witness_bytes: &'static [u8],
    prepared: PreparedSettle,
    clock: ClockContext,
}

fn fixtures() -> Vec<Fixture> {
    [
        (
            "normal",
            golden!("normal-00-before_first_seal_seq.bin"),
            golden!("normal-01-first_witness.bin"),
        ),
        (
            "rollback_resealed",
            golden!("rollback-06-after_rollback_seq.bin"),
            golden!("rollback-07-resealed_witness.bin"),
        ),
    ]
    .into_iter()
    .map(|(name, sequencer_bytes, witness_bytes)| {
        let sequencer = postcard::from_bytes(sequencer_bytes).unwrap();
        let witness: WindowWitness = postcard::from_bytes(witness_bytes).unwrap();
        let prepared = prepare_unproved(&witness, &[]).unwrap();
        let bounds = TimeBounds::derive(&witness.ops).unwrap();
        assert!(!witness.ops.is_empty() && bounds.count > 0);
        assert!(prepared.withdraw_proofs.is_empty());
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
            sequencer,
            sequencer_bytes,
            witness,
            witness_bytes,
            prepared,
            clock,
        }
    })
    .collect()
}

fn preview(seq: &Sequencer) -> WindowWitness {
    let bytes = postcard::to_allocvec(seq).unwrap();
    let mut copied: Sequencer = postcard::from_bytes(&bytes).unwrap();
    // Preserve the actual snapshot-preview serde defaults. Restoring the original
    // enclave here would measure a different path from the current production cut.
    copied.seal_window()
}

fn roots(f: &Fixture) -> DerivedRoots {
    derive_roots(
        &mut f.witness.pre_state.clone(),
        &f.witness.ops,
        &f.witness.manifest,
    )
    .unwrap()
}

fn validate_clock(f: &Fixture, derived: &DerivedRoots) -> [u8; 32] {
    f.clock
        .validate(f.witness.batch_id, derived, &f.witness.ops)
        .unwrap();
    f.clock.commitment()
}

/// Precomputed diagnostic response; the timed callback never replays or proves.
struct CachedClient<'a> {
    f: &'a Fixture,
    clock: Option<ClockContext>,
    commitment: [u8; 32],
    context_calls: AtomicUsize,
    prove_calls: AtomicUsize,
}

impl<'a> CachedClient<'a> {
    fn new(f: &'a Fixture, clock: Option<ClockContext>) -> Self {
        Self {
            f,
            clock,
            commitment: clock.map_or(f.prepared.outcome.commitment, |c| c.commitment()),
            context_calls: AtomicUsize::new(0),
            prove_calls: AtomicUsize::new(0),
        }
    }

    fn response(&self) -> RemoteProveResp {
        self.prove_calls.fetch_add(1, Ordering::Relaxed);
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
            commitment: self.commitment,
            // Deliberately synthetic bytes, never a valid proof claim.
            proof: vec![0x6a; 32],
        }
    }
}

impl ProverClient for CachedClient<'_> {
    fn prove(&self, _: &WindowWitness) -> Result<RemoteProveResp, ProverClientError> {
        assert!(self.clock.is_none(), "clock path must not downgrade");
        Ok(self.response())
    }
    fn clock_enabled(&self) -> bool {
        self.clock.is_some()
    }
    fn clock_context(&self, _: &WindowWitness) -> Result<Option<ClockContext>, ProverClientError> {
        self.context_calls.fetch_add(1, Ordering::Relaxed);
        Ok(self.clock)
    }
    fn prove_clocked(
        &self,
        _: &WindowWitness,
        c: &ClockContext,
    ) -> Result<RemoteProveResp, ProverClientError> {
        assert_eq!(Some(*c), self.clock);
        Ok(self.response())
    }
}

fn assert_prepared(f: &Fixture, actual: &PreparedSettle, clocked: Option<bool>) {
    let mut base = actual.clone();
    base.outcome.proof.clear();
    assert_eq!(
        postcard::to_allocvec(&base).unwrap(),
        postcard::to_allocvec(&f.prepared).unwrap()
    );
    if let Some(clocked) = clocked {
        let mut expected = Vec::new();
        if clocked {
            expected.extend_from_slice(perp_core::clock::PROOF_MAGIC);
            expected.extend_from_slice(&f.clock.receipt());
        }
        expected.extend_from_slice(&[0x6a; 32]);
        assert_eq!(actual.outcome.proof, expected);
    } else {
        assert!(actual.outcome.proof.is_empty());
    }
}

fn assert_inputs(f: &Fixture) {
    assert!(matches!(f.name, "normal" | "rollback_resealed"));
    assert_eq!(
        postcard::to_allocvec(&f.sequencer).unwrap(),
        f.sequencer_bytes
    );
    assert_eq!(postcard::to_allocvec(&f.witness).unwrap(), f.witness_bytes);
}

fn assert_fixture(f: &Fixture) {
    assert_inputs(f);
    let first = preview(&f.sequencer);
    assert_eq!(
        postcard::to_allocvec(&first).unwrap(),
        postcard::to_allocvec(&preview(&f.sequencer)).unwrap()
    );
    assert_eq!(first.batch_id, f.witness.batch_id);
    assert_eq!(
        postcard::to_allocvec(&first.pre_state).unwrap(),
        postcard::to_allocvec(&f.witness.pre_state).unwrap()
    );
    assert_eq!(
        postcard::to_allocvec(&first.ops).unwrap(),
        postcard::to_allocvec(&f.witness.ops).unwrap()
    );
    assert_eq!(first.manifest.enclave_measurement, [0; 32]);
    assert_eq!(first.manifest.sequencer_pubkey_epoch, 0);
    assert_eq!(
        roots(f).commitment::<Keccak256>(),
        f.prepared.outcome.commitment
    );
    assert_eq!(validate_clock(f, &roots(f)), f.clock.commitment());
    for clocked in [false, true] {
        let client = CachedClient::new(f, clocked.then_some(f.clock));
        let actual = prove_and_prepare(&client, &f.witness, &[]).unwrap();
        assert_prepared(f, &actual, Some(clocked));
        assert_eq!(client.context_calls.load(Ordering::Relaxed), 1);
        assert_eq!(client.prove_calls.load(Ordering::Relaxed), 1);
    }
    let mut invalid = f.clock;
    invalid.timed_ops += 1;
    let client = CachedClient::new(f, Some(invalid));
    assert!(prove_and_prepare(&client, &f.witness, &[])
        .unwrap_err()
        .contains("clock context"));
    assert_eq!(client.context_calls.load(Ordering::Relaxed), 1);
    assert_eq!(client.prove_calls.load(Ordering::Relaxed), 0);
    assert_inputs(f);
}

#[test]
fn small_preparation_profile_correctness() {
    for f in fixtures() {
        assert_fixture(&f);
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
        // macOS SDK _time.h: CLOCK_THREAD_CPUTIME_ID = 16. This test-only call
        // accepts a scalar clock id and returns a scalar; no pointers are passed.
        let time = unsafe { clock_gettime_nsec_np(16) };
        assert!(
            time > 0,
            "thread CPU clock unavailable; no wall-time fallback"
        );
        time
    }

    fn measure<T, R>(
        f: &Fixture,
        phase: &str,
        mut setup: impl FnMut() -> T,
        mut run: impl FnMut(T) -> R,
        check: impl Fn(&R),
    ) {
        const ROUNDS: usize = 5;
        const REPETITIONS: usize = 10;
        check(&run(setup())); // One warmup, outside the timed batch.
        for round in 0..ROUNDS {
            let inputs: Vec<T> = (0..REPETITIONS).map(|_| setup()).collect();
            let mut outputs = Vec::with_capacity(REPETITIONS);
            let wall = Instant::now();
            let cpu = thread_cpu_ns();
            for input in inputs {
                outputs.push(black_box(run(black_box(input))));
            }
            let cpu_ns = thread_cpu_ns().checked_sub(cpu).unwrap();
            let wall_ns = wall.elapsed().as_nanos();
            // Assertions and result cleanup are outside the measurement. Input
            // destruction and result-vector pushes occur inside it. Setup is
            // separately excluded; phase samples must not be summed as a total.
            for result in &outputs {
                check(result);
            }
            assert_inputs(f);
            println!(
                "PREPARATION_CPU_SAMPLE {}",
                serde_json::json!({
                    "fixture": f.name, "phase": phase, "round": round,
                    "repetitions": REPETITIONS, "thread_cpu_ns": cpu_ns,
                    "wall_ns": wall_ns, "sequencer_bytes": f.sequencer_bytes.len(),
                    "witness_bytes": f.witness_bytes.len(), "ops": f.witness.ops.len(),
                    "notes": f.witness.pre_state.notes.len(),
                    "timed_ops": f.clock.timed_ops, "withdrawals": 0,
                    "preview_enclave": "serde_placeholder", "proof": "synthetic_cached_stub"
                })
            );
        }
    }

    #[test]
    #[ignore = "bounded macOS thread-CPU diagnostic; run explicitly with one test thread"]
    fn observe_small_preparation_cpu() {
        for f in fixtures() {
            assert_fixture(&f);
            let reference = postcard::to_allocvec(&preview(&f.sequencer)).unwrap();
            measure(
                &f,
                "seq_encode",
                || &f.sequencer,
                |seq| postcard::to_allocvec(seq).unwrap(),
                |b| assert_eq!(b, f.sequencer_bytes),
            );
            measure(
                &f,
                "seq_decode",
                || f.sequencer_bytes,
                |b| postcard::from_bytes::<Sequencer>(b).unwrap(),
                |seq| assert_eq!(postcard::to_allocvec(seq).unwrap(), f.sequencer_bytes),
            );
            measure(
                &f,
                "seq_seal_owned",
                || postcard::from_bytes::<Sequencer>(f.sequencer_bytes).unwrap(),
                |mut seq| seq.seal_window(),
                |w| assert_eq!(postcard::to_allocvec(w).unwrap(), reference),
            );
            measure(
                &f,
                "snapshot_preview_total",
                || &f.sequencer,
                preview,
                |w| assert_eq!(postcard::to_allocvec(w).unwrap(), reference),
            );
            measure(
                &f,
                "state_clone",
                || &f.witness.pre_state,
                |state| (*state).clone(),
                |state| {
                    assert_eq!(
                        postcard::to_allocvec(state).unwrap(),
                        postcard::to_allocvec(&f.witness.pre_state).unwrap()
                    )
                },
            );
            measure(
                &f,
                "replay_owned",
                || f.witness.pre_state.clone(),
                |mut state| {
                    derive_roots(
                        &mut state,
                        black_box(&f.witness.ops),
                        black_box(&f.witness.manifest),
                    )
                    .unwrap()
                },
                |r| assert_eq!(r.commitment::<Keccak256>(), f.prepared.outcome.commitment),
            );
            measure(
                &f,
                "prepare_unproved_total",
                || &f.witness,
                |w| prepare_unproved(w, &[]).unwrap(),
                |p| assert_prepared(&f, p, None),
            );
            measure(
                &f,
                "clock_validate_derived",
                || (&f, roots(&f)),
                |(f, r)| validate_clock(f, &r),
                |c| assert_eq!(*c, f.clock.commitment()),
            );
            measure(
                &f,
                "clock_extra_replay_validate",
                || &f,
                |f| validate_clock(f, &roots(f)),
                |c| assert_eq!(*c, f.clock.commitment()),
            );
            for clocked in [false, true] {
                let client = CachedClient::new(&f, clocked.then_some(f.clock));
                measure(
                    &f,
                    if clocked {
                        "clocked_prepare_cached_stub_total"
                    } else {
                        "legacy_prepare_cached_stub_total"
                    },
                    || (&client, &f.witness),
                    |(client, w)| prove_and_prepare(client, w, &[]).unwrap(),
                    |p| assert_prepared(&f, p, Some(clocked)),
                );
                // Five ten-call batches + one warmup; no callback does a replay.
                assert_eq!(client.context_calls.load(Ordering::Relaxed), 51);
                assert_eq!(client.prove_calls.load(Ordering::Relaxed), 51);
            }
            assert_inputs(&f);
        }
    }
}

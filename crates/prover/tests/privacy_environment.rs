//! Run environment mutations in child processes, never in parallel test threads.
//! The backend is a canary, not SP1: these tests establish refusal BEFORE key
//! release or plaintext backend access, not successful confidential hardware.
use perp_core::hash::Digest;
use prover::{AttestedProver, Prover, PublicInputs, SealKeyProvider, SealedWitness};
use std::{
    ffi::OsString,
    process::Command,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

const VARIABLES: [&str; 3] = ["SP1_DUMP", "SP1_DUMP_SHARD_DIR", "TRACE_FILE"];

fn run_child(variable: Option<&str>, value: Option<OsString>, deny: bool) {
    let mut child = Command::new(std::env::current_exe().unwrap());
    child.args([
        "--ignored",
        "--exact",
        "privacy_environment_worker",
        "--nocapture",
    ]);
    for variable in VARIABLES {
        child.env_remove(variable);
    }
    child.env("ARCORA_PRIVACY_EXPECT_DENY", if deny { "1" } else { "0" });
    if let Some(variable) = variable {
        child.env(variable, value.unwrap());
    }
    let result = child.output().unwrap();
    assert!(
        result.status.success(),
        "isolated {variable:?} case failed:\n{}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
fn diagnostic_outputs_are_refused_before_key_release_or_backend_access() {
    for (variable, values) in [
        (
            "SP1_DUMP",
            vec!["1", "true", "TRUE", "TrUe", "", "yes", " false "],
        ),
        (
            "SP1_DUMP_SHARD_DIR",
            vec!["/private/test-only", "", "false", "0"],
        ),
        ("TRACE_FILE", vec!["/private/test-only", "", "false", "0"]),
    ] {
        for value in values {
            run_child(Some(variable), Some(value.into()), true);
        }
    }
}

#[test]
fn unset_or_explicitly_disabled_dump_preserves_normal_proving() {
    run_child(None, None, false);
    for value in ["0", "false", "FALSE", "FaLsE"] {
        run_child(Some("SP1_DUMP"), Some(value.into()), false);
    }
}

#[cfg(unix)]
#[test]
fn non_utf8_diagnostic_configuration_fails_closed() {
    use std::os::unix::ffi::OsStringExt;
    for variable in VARIABLES {
        run_child(Some(variable), Some(OsString::from_vec(vec![0xff])), true);
    }
}

struct CountingProvider(Arc<AtomicUsize>);
impl SealKeyProvider for CountingProvider {
    fn seal_key(&self, _: &Digest, _: &Digest) -> Option<Digest> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Some([42; 32])
    }
}

struct CountingBackend(Arc<AtomicUsize>);
impl Prover for CountingBackend {
    fn measurement(&self) -> Digest {
        [7; 32]
    }

    fn prove(&self, _: &PublicInputs, witness: &[u8]) -> Vec<u8> {
        self.0.fetch_add(1, Ordering::SeqCst);
        assert_eq!(witness, b"private witness canary");
        vec![1]
    }
}

#[test]
#[ignore = "isolated environment worker; invoked by the parent tests"]
fn privacy_environment_worker() {
    let deny = std::env::var("ARCORA_PRIVACY_EXPECT_DENY").unwrap() == "1";
    let releases = Arc::new(AtomicUsize::new(0));
    let accesses = Arc::new(AtomicUsize::new(0));
    let sealed = SealedWitness::seal(
        b"private witness canary",
        &CountingProvider(Arc::new(AtomicUsize::new(0))),
        [7; 32],
        [8; 32],
    )
    .unwrap();
    let prover = AttestedProver::new(
        CountingBackend(accesses.clone()),
        CountingProvider(releases.clone()),
    );
    let public = PublicInputs {
        prev_state_root: [0; 32],
        batch_manifest_hash: [0; 32],
        new_state_root: [0; 32],
        ordered_root: [0; 32],
        withdrawals_root: [0; 32],
        rejected_root: [0; 32],
        deposits_root: [0; 32],
        wind_down_phase: 0,
        clock_receipt: None,
    };
    let sealed_result = prover.prove_sealed(&sealed, &public);
    // The canary is deliberately not a postcard batch. In a denied environment,
    // even this path must refuse before key release/native witness decoding.
    let batch_result = prover.prove_batch(&sealed);
    if deny {
        assert_eq!(releases.load(Ordering::SeqCst), 0, "released a seal key");
        assert_eq!(accesses.load(Ordering::SeqCst), 0, "backend saw plaintext");
        assert!(sealed_result.is_err());
        assert!(batch_result.is_err());
    } else {
        assert!(sealed_result.is_ok());
        assert!(batch_result.is_err());
        assert_eq!(releases.load(Ordering::SeqCst), 2);
        assert_eq!(accesses.load(Ordering::SeqCst), 1);
    }
}

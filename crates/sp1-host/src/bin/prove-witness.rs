//! Dry-run proofs: prove each given clock witness with the guest given by `--elf`
//! and record what it cost. Synthetic, public test data only; never contacts a
//! chain or a proving network, and keeps no proof file.
//!
//! For each witness, in order:
//! - the native twin (`prover::public_from_witness`) must accept it; its
//!   commitment is the expected public value;
//! - the guest executes it, which must succeed and commit that value (cycles and
//!   SP1 gas are recorded);
//! - the proof is generated in the chosen mode (`groth16`, the on-chain proof, by
//!   default; or `compressed`, which stops before the wrap), and the SDK verifier
//!   must accept it with the expected public value. A Groth16 proof must also pass
//!   the payload guards `clock-proof` applies.
//!
//! Setup runs once. The proving client is the CPU prover, or SP1's GPU prover when
//! built with `--features cuda`. The record (`--out`, a new file) is rewritten
//! after every witness, so a stopped run keeps what it measured. Wall times are
//! this host's.
//!
//! Usage: `prove-witness --elf GUEST_ELF --out NEW_JSON [--mode groth16|compressed]
//! WITNESS...`
use perp_core::hash::Keccak256;
use serde_json::{json, Value};
use sp1_host::{hex, sha256};
use sp1_sdk::{
    Elf, HashableKey, ProveRequest, Prover, ProverClient, ProvingKey, SP1Stdin, StatusCode,
};
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Instant;

const USAGE: &str = "usage: prove-witness --elf GUEST_ELF --out NEW_JSON \
     [--mode groth16|compressed] WITNESS...";
const MAX_ELF_BYTES: u64 = 16 * 1024 * 1024;
/// The prover service's sealed-body limit bounds every witness it can be sent.
const MAX_WITNESS_BYTES: u64 = 512 * 1024 * 1024;

/// The backend that runs setup and the proofs, recorded in the output.
const PROVER_BACKEND: &str = if cfg!(feature = "cuda") {
    "cuda"
} else {
    "cpu"
};

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Groth16,
    Compressed,
}

impl Mode {
    fn name(self) -> &'static str {
        match self {
            Mode::Groth16 => "groth16",
            Mode::Compressed => "compressed",
        }
    }
}

struct Args {
    elf: PathBuf,
    out: PathBuf,
    mode: Mode,
    witnesses: Vec<PathBuf>,
}

fn parse_args(args: &[String]) -> Result<Args, String> {
    let (mut elf, mut out, mut mode, mut witnesses) = (None, None, None, Vec::new());
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        let mut value = || rest.next().cloned().ok_or_else(|| USAGE.to_string());
        match arg.as_str() {
            "--elf" if elf.is_none() => elf = Some(PathBuf::from(value()?)),
            "--out" if out.is_none() => out = Some(PathBuf::from(value()?)),
            "--mode" if mode.is_none() => {
                mode = Some(match value()?.as_str() {
                    "groth16" => Mode::Groth16,
                    "compressed" => Mode::Compressed,
                    _ => return Err(USAGE.into()),
                })
            }
            other if !other.starts_with("--") => witnesses.push(PathBuf::from(other)),
            _ => return Err(USAGE.into()),
        }
    }
    if witnesses.is_empty() {
        return Err(USAGE.into());
    }
    Ok(Args {
        elf: elf.ok_or(USAGE)?,
        out: out.ok_or(USAGE)?,
        mode: mode.unwrap_or(Mode::Groth16),
        witnesses,
    })
}

/// Read a bounded regular (non-symlink) file.
fn read_bounded(path: &Path, limit: u64, what: &str) -> Result<Vec<u8>, String> {
    let metadata = std::fs::symlink_metadata(path).map_err(|e| format!("{what}: {e}"))?;
    if !metadata.file_type().is_file() {
        return Err(format!("{what} must be a regular non-symlink file"));
    }
    let mut bytes = Vec::new();
    File::open(path)
        .and_then(|file| file.take(limit + 1).read_to_end(&mut bytes))
        .map_err(|e| format!("{what}: {e}"))?;
    if bytes.len() as u64 > limit {
        return Err(format!("{what} exceeds {limit} bytes"));
    }
    Ok(bytes)
}

/// The setup and proving client: the CPU prover.
#[cfg(not(feature = "cuda"))]
async fn proving_client() -> sp1_sdk::CpuProver {
    ProverClient::builder().cpu().build().await
}

/// The setup and proving client: SP1's GPU prover (`sp1-gpu-server`, CUDA device 0).
#[cfg(feature = "cuda")]
async fn proving_client() -> sp1_sdk::CudaProver {
    ProverClient::builder().cuda().build().await
}

/// Execute, prove and verify one witness. Returns its record.
async fn prove_one<P: Prover>(client: &P, pk: &P::ProvingKey, mode: Mode, path: &Path) -> Value {
    let bytes = read_bounded(path, MAX_WITNESS_BYTES, "witness").unwrap_or_else(|e| panic!("{e}"));
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.trim_end_matches(".witness.bin").to_string())
        .expect("witness file name");
    let started = Instant::now();
    let expected = prover::public_from_witness(&bytes)
        .unwrap_or_else(|e| panic!("{name}: native twin refused the witness: {e:?}"))
        .commitment::<Keccak256>();
    let native_s = started.elapsed().as_secs_f64();

    let mut stdin = SP1Stdin::new();
    stdin.write_vec(bytes.clone());
    let started = Instant::now();
    let (values, report) = client
        .execute(pk.elf().clone(), stdin)
        .calculate_gas(true)
        .expected_exit_code(StatusCode::SUCCESS)
        .await
        .unwrap_or_else(|e| panic!("{name}: guest execution: {e}"));
    let execute_s = started.elapsed().as_secs_f64();
    assert_eq!(
        values.as_slice(),
        expected,
        "{name}: native and guest commitments differ"
    );
    let cycles = report.total_instruction_count();
    eprintln!("PROVE_START {name} mode={} cycles={cycles}", mode.name());

    let mut stdin = SP1Stdin::new();
    stdin.write_vec(bytes.clone());
    let request = client.prove(pk, stdin);
    let request = match mode {
        Mode::Groth16 => request.groth16(),
        Mode::Compressed => request.compressed(),
    };
    let started = Instant::now();
    let proof = request
        .await
        .unwrap_or_else(|e| panic!("{name}: {} proof: {e}", mode.name()));
    let prove_s = started.elapsed().as_secs_f64();
    let started = Instant::now();
    client
        .verify(&proof, pk.verifying_key(), None)
        .unwrap_or_else(|e| panic!("{name}: SDK verifier: {e}"));
    let verify_s = started.elapsed().as_secs_f64();
    assert_eq!(
        proof.public_values.as_slice(),
        expected,
        "{name}: proof public value"
    );
    let proof_bytes = match mode {
        Mode::Groth16 => sp1_host::groth16_payload_for_verification(&proof, &expected)
            .unwrap_or_else(|e| panic!("{name}: {e}")),
        Mode::Compressed => bincode::serialize(&proof.proof).expect("proof bytes"),
    };
    eprintln!(
        "PROVED {name} mode={} cycles={cycles} prove_wall_s={prove_s:.1} cycles_per_s={:.0}",
        mode.name(),
        cycles as f64 / prove_s
    );
    json!({
        "name": name,
        "witness_bytes": bytes.len(),
        "witness_sha256": sha256(&bytes),
        "commitment": format!("0x{}", hex(&expected)),
        "native_guest_equal": true,
        "cycles": cycles,
        "gas": report.gas(),
        "native_twin_wall_s": native_s,
        "guest_execute_wall_s": execute_s,
        "prove_wall_s": prove_s,
        "verify_wall_s": verify_s,
        "sdk_verified": true,
        "proof_bytes": proof_bytes.len(),
        "proof_sha256": sha256(&proof_bytes),
    })
}

#[tokio::main]
async fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let args = parse_args(&argv).unwrap_or_else(|e| panic!("{e}"));
    let elf_bytes =
        read_bounded(&args.elf, MAX_ELF_BYTES, "guest ELF").unwrap_or_else(|e| panic!("{e}"));
    assert!(
        elf_bytes.starts_with(b"\x7fELF"),
        "guest ELF input is not an ELF file"
    );
    // Reserve the output first, so a run never overwrites earlier evidence.
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args.out)
        .expect("new output file");
    let client = proving_client().await;
    let started = Instant::now();
    let pk = client
        .setup(Elf::from(elf_bytes.clone()))
        .await
        .expect("real setup");
    let setup_s = started.elapsed().as_secs_f64();
    let vkey = pk.verifying_key().bytes32_raw();
    let mut runs = Vec::new();
    for path in &args.witnesses {
        runs.push(prove_one(&client, &pk, args.mode, path).await);
        let report = json!({
            "kind": "pkg3-dry-run-proofs",
            "sdk_version": "6.1.0",
            "prover_backend": PROVER_BACKEND,
            "mode": args.mode.name(),
            "elf_sha256": sha256(&elf_bytes),
            "program_vkey": format!("0x{}", hex(&vkey)),
            "setup_wall_s": setup_s,
            "host_os": std::env::consts::OS,
            "host_arch": std::env::consts::ARCH,
            "runs": runs,
        });
        std::fs::write(&args.out, serde_json::to_vec_pretty(&report).expect("json"))
            .expect("write output");
    }
}

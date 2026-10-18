//! Real local SP1 execution and optional Groth16 proof of the clock-bound normal
//! fixture. Uses only synthetic data and public fixture keys; never submits
//! transactions.
//!
//! The guest is the explicit `--elf` artifact, refused unless its SHA-256 equals
//! the reviewed guest pin; no build-script ELF is embedded. Modes:
//! - default: execute the fixture and its negatives, then derive the setup key;
//! - `--no-prove`: execution only, on the execute-only light client: no proving
//!   stack is built, no setup is run and no key file is written;
//! - `--prove`: as default, then generate and verify a Groth16 proof.
//!
//! The fixture and every negative are encoded by `sp1_host::encode_clock_witness`.
use perp_core::hash::Keccak256;
use serde_json::{json, Value};
use sp1_host::{
    clock_negative_cases, framing_negative_cases, hex, normal_witness, sha256, witness_bytes,
    NegativeCase,
};
use sp1_sdk::{
    Elf, HashableKey, ProveRequest, Prover, ProverClient, ProvingKey, SP1Stdin, StatusCode,
};
use std::{fs::File, io::Read, path::Path};

/// REVIEWED_GUEST["elf"] in scripts/local-verification/verify_clock_proof.py.
const REVIEWED_ELF: &str = "df59a19b310258b4d01d0d5e3cfa31bb7de9ca2f4ea7c2302cf76650c79967c5";
const MAX_ELF_BYTES: u64 = 16 * 1024 * 1024;
const USAGE: &str =
    "usage: clock-proof --elf REVIEWED_ELF NEW_OUTPUT_DIRECTORY [--prove | --no-prove]";

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Setup,
    ExecuteOnly,
    Prove,
}

/// Read a bounded regular (non-symlink) file and refuse any program but the reviewed one.
fn reviewed_elf(path: &Path) -> Result<Vec<u8>, String> {
    let metadata = std::fs::symlink_metadata(path).map_err(|e| format!("guest ELF: {e}"))?;
    if !metadata.file_type().is_file() {
        return Err("guest ELF must be a regular non-symlink file".into());
    }
    let mut bytes = Vec::new();
    File::open(path)
        .and_then(|file| file.take(MAX_ELF_BYTES + 1).read_to_end(&mut bytes))
        .map_err(|e| format!("guest ELF: {e}"))?;
    if bytes.len() as u64 > MAX_ELF_BYTES || !bytes.starts_with(b"\x7fELF") {
        return Err("guest ELF input is not a bounded ELF file".into());
    }
    if sha256(&bytes) != REVIEWED_ELF {
        return Err("guest ELF differs from the reviewed guest pin".into());
    }
    Ok(bytes)
}

/// Execute the fixture witness `bytes` (it must succeed and commit `expected`) and
/// each negative (natively refused with its expected error, and in the guest a
/// panic with no public values) on `client`. Returns the fixture's cycle count and
/// the negatives' evidence.
async fn execute_fixture<P: Prover>(
    client: &P,
    elf: &Elf,
    bytes: &[u8],
    expected: &[u8],
    negatives: &[NegativeCase],
) -> (u64, Vec<Value>) {
    let mut stdin = SP1Stdin::new();
    stdin.write_vec(bytes.to_vec());
    let (values, report) = client
        .execute(elf.clone(), stdin)
        .expected_exit_code(StatusCode::SUCCESS)
        .await
        .expect("clock guest execution");
    assert_eq!(values.as_slice(), expected);
    let mut evidence = Vec::new();
    for case in negatives {
        assert_eq!(
            prover::public_from_witness(&case.bytes),
            Err(case.expected_error),
            "{}",
            case.name
        );
        let mut input = SP1Stdin::new();
        input.write_vec(case.bytes.clone());
        let (v, r) = client
            .execute(elf.clone(), input)
            .expected_exit_code(StatusCode::PANIC)
            .await
            .expect("actual guest rejects the negative witness");
        assert_eq!(r.exit_code, 1);
        assert!(v.as_slice().is_empty());
        evidence.push(json!({"name":case.name,"guest_exit":r.exit_code,"public_bytes":v.as_slice().len(),
            "witness_sha256":sha256(&case.bytes),"native_error":format!("{:?}", case.expected_error)}));
    }
    let cycles = report.total_instruction_count();
    println!("CLOCK_NATIVE_GUEST_PARITY_PASS cycles={cycles}");
    (cycles, evidence)
}

fn parse_args(args: &[String]) -> Result<(String, String, Mode), String> {
    let (mut elf, mut dir, mut mode) = (None, None, None);
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--elf" if elf.is_none() => elf = Some(rest.next().ok_or(USAGE)?.clone()),
            "--prove" if mode.is_none() => mode = Some(Mode::Prove),
            "--no-prove" if mode.is_none() => mode = Some(Mode::ExecuteOnly),
            other if !other.starts_with("--") && dir.is_none() => dir = Some(other.to_string()),
            _ => return Err(USAGE.into()),
        }
    }
    match (elf, dir) {
        (Some(elf), Some(dir)) => Ok((elf, dir, mode.unwrap_or(Mode::Setup))),
        _ => Err(USAGE.into()),
    }
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (elf_path, dir, mode) = parse_args(&args).unwrap_or_else(|e| panic!("{e}"));
    let elf_bytes = reviewed_elf(Path::new(&elf_path)).unwrap_or_else(|e| panic!("{e}"));
    let elf = Elf::from(elf_bytes.clone());
    if mode == Mode::Prove {
        let base = std::env::var_os("SP1_GROTH16_CIRCUIT_PATH")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                std::path::PathBuf::from(std::env::var_os("HOME").expect("HOME required"))
                    .join(".sp1/circuits/groth16")
            });
        sp1_host::check_groth16_prerequisites(&base.join("v6.1.0"))
            .expect("install complete official SP1 6.1.0 circuit artifacts before --prove; a partial archive is not sufficient");
    }
    let dir = std::path::PathBuf::from(dir);
    std::fs::create_dir(&dir).expect("fresh output directory");
    let w = normal_witness();
    let bytes = witness_bytes(&w);
    let public = prover::public_from_witness(&bytes).unwrap();
    let expected = public.commitment::<Keccak256>();
    assert_eq!(
        expected,
        w.3.commitment(),
        "native twin binds the fixture clock"
    );
    // The five clock negatives first, then every framing the guest refuses.
    let negative_cases: Vec<NegativeCase> = clock_negative_cases(&w)
        .into_iter()
        .chain(framing_negative_cases(&w))
        .collect();
    std::fs::write(dir.join("clock.witness.bin"), &bytes).unwrap();
    std::fs::write(dir.join("guest.elf"), &elf_bytes).unwrap();
    let evidence = |cycles: u64, negatives: Vec<Value>| {
        json!({"kind":"clock-pkg3-native-guest","sdk_version":"6.1.0",
            "elf_sha256":sha256(&elf_bytes),"witness_sha256":sha256(&bytes),
            "native_guest_equal":true,"cycles":cycles,"negatives":negatives,
            "commitment":format!("0x{}",hex(&expected)),"proof_generated":false,"target_contract_verified":false})
    };
    if mode == Mode::ExecuteOnly {
        // Execution only: the light client executes without building the CPU
        // proving stack, and no setup runs, so no setup key is derived or recorded.
        let client = ProverClient::builder().light().build().await;
        let (cycles, negatives) =
            execute_fixture(&client, &elf, &bytes, &expected, &negative_cases).await;
        let mut evidence = evidence(cycles, negatives);
        evidence["setup_performed"] = json!(false);
        std::fs::write(
            dir.join("execution.json"),
            serde_json::to_vec_pretty(&evidence).unwrap(),
        )
        .unwrap();
        return;
    }
    let client = ProverClient::builder().cpu().build().await;
    let (cycles, negatives) =
        execute_fixture(&client, &elf, &bytes, &expected, &negative_cases).await;
    let mut evidence = evidence(cycles, negatives);
    let pk = client.setup(elf).await.expect("real setup");
    let vkey = pk.verifying_key().bytes32_raw();
    std::fs::write(dir.join("program-vkey.bin"), vkey).unwrap();
    evidence["program_vkey"] = json!(format!("0x{}", hex(&vkey)));
    std::fs::write(
        dir.join("execution.json"),
        serde_json::to_vec_pretty(&evidence).unwrap(),
    )
    .unwrap();
    if mode == Mode::Prove {
        println!("CLOCK_GROTH16_START local CPU");
        let mut input = SP1Stdin::new();
        input.write_vec(bytes);
        let proof = client
            .prove(&pk, input)
            .groth16()
            .await
            .expect("real local Groth16 proof");
        let raw = sp1_host::groth16_payload_for_verification(&proof, &expected).unwrap();
        client
            .verify(&proof, pk.verifying_key(), None)
            .expect("local SP1 verifier");
        std::fs::write(dir.join("proof.bin"), raw).unwrap();
        std::fs::write(
            dir.join("proof.sdk.json"),
            serde_json::to_vec(&proof).unwrap(),
        )
        .unwrap();
        std::fs::write(
            dir.join("public-values.bin"),
            proof.public_values.as_slice(),
        )
        .unwrap();
        evidence["proof_generated"] = json!(true);
        evidence["local_sdk_verified"] = json!(true);
        std::fs::write(
            dir.join("proof-evidence.json"),
            serde_json::to_vec_pretty(&evidence).unwrap(),
        )
        .unwrap();
        println!("CLOCK_GROTH16_VERIFIED");
    }
}

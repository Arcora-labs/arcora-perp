//! Execute the ordinary synthetic deposit/withdraw witness in native code and SP1.
//! Optional: --check-negatives --output-dir NEW_DIRECTORY. No proof or chain writes.

use perp_core::hash::Keccak256;
use serde_json::json;
use sp1_host::{
    hex, native_from_bytes, normal_negative_cases, normal_witness, options, roots_json, sha256,
    witness_bytes, Artifacts,
};
use sp1_sdk::{include_elf, Elf, Prover, ProverClient, SP1Stdin, StatusCode};

const ELF: Elf = include_elf!("perp-core-guest");

#[tokio::main]
async fn main() {
    let options = options(std::env::args().skip(1), true).expect("valid CLI arguments");
    let bytes = witness_bytes(&normal_witness());
    let (roots, deposit_count) = native_from_bytes(&bytes).expect("valid normal native transition");
    let native_commit = roots.commitment::<Keccak256>();
    let mut artifacts = options
        .output_dir
        .as_deref()
        .map(Artifacts::new)
        .transpose()
        .expect("fresh output directory");
    if let Some(output) = artifacts.as_mut() {
        output.write("normal.witness.bin", &bytes).unwrap();
        output.write("guest.elf", &ELF).unwrap();
    }
    let mut stdin = SP1Stdin::new();
    stdin.write_vec(bytes.clone());
    let client = ProverClient::builder().cpu().build().await;
    let (public_values, report) = client
        .execute(ELF, stdin)
        .expected_exit_code(StatusCode::SUCCESS)
        .await
        .expect("normal guest executes");
    assert_eq!(
        report.exit_code, 0,
        "normal guest must terminate successfully"
    );
    let zk_commit: [u8; 32] = public_values
        .as_slice()
        .try_into()
        .expect("32-byte commitment");
    assert_eq!(
        native_commit, zk_commit,
        "native and zkVM commitments MUST match"
    );
    println!("witness sha256    = {}", sha256(&bytes));
    println!("cycles            = {}", report.total_instruction_count());
    println!("native commitment = 0x{}", hex(&native_commit));
    println!("zkVM   commitment = 0x{}", hex(&zk_commit));
    println!("MATCH: native perp-core == SP1 guest");

    let mut negatives = Vec::new();
    if options.check_negatives {
        for case in normal_negative_cases() {
            assert_eq!(
                native_from_bytes(&case.bytes).unwrap_err(),
                case.expected_error
            );
            if let Some(output) = artifacts.as_mut() {
                output
                    .write(&format!("{}.witness.bin", case.name), &case.bytes)
                    .unwrap();
            }
            let mut stdin = SP1Stdin::new();
            stdin.write_vec(case.bytes.clone());
            // Require an actual guest panic with no commitment. Infrastructure and
            // executor failures are errors, never passing negative cases.
            let (public_values, report) = client
                .execute(ELF, stdin)
                .expected_exit_code(StatusCode::PANIC)
                .await
                .expect("negative guest reaches expected rejection");
            assert_eq!(report.exit_code, 1, "negative guest must reject");
            assert!(
                public_values.as_slice().is_empty(),
                "rejected guest must not commit a public value"
            );
            println!(
                "REJECTED: {} native={:?} guest_exit={} public_bytes=0",
                case.name, case.expected_error, report.exit_code
            );
            negatives.push(json!({
                "case": case.name, "witness_sha256": sha256(&case.bytes),
                "native_error": format!("{:?}", case.expected_error),
                "guest_exit_code": report.exit_code, "public_values_bytes": 0,
                "cycles": report.total_instruction_count()
            }));
        }
    }
    if let Some(mut output) = artifacts {
        output
            .write("normal.public-values.bin", public_values.as_slice())
            .unwrap();
        output.finish(json!({
            "kind": "ordinary-native-guest-execution", "sdk_version": "6.1.0",
            "witness_sha256": sha256(&bytes), "native_deserialized_same_witness": true,
            "native_guest_equal": true, "guest_exit_code": report.exit_code,
            "cycles": report.total_instruction_count(), "roots": roots_json(&roots, deposit_count),
            "negative_checks_requested": options.check_negatives, "negatives": negatives,
            "proof_generated": false, "a06_executed": false,
            "scope": "Synthetic ordinary deposit/withdraw only; no observed L1 deposit, proof or token lifecycle. Does not close combined S5-02."
        })).unwrap();
    }
}

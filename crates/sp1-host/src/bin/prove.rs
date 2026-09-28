//! Real local CPU Groth16 proof for the shared ordinary synthetic witness.
//! Optional: --output-dir NEW_DIRECTORY. Never selects a network or mock prover.

use perp_core::hash::Keccak256;
use serde_json::json;
use sp1_host::{
    groth16_payload_for_verification, hex, native_from_bytes, normal_witness, options, roots_json,
    sha256, witness_bytes, Artifacts,
};
use sp1_sdk::{
    include_elf, Elf, HashableKey, ProveRequest, Prover, ProverClient, ProvingKey, SP1Stdin,
};

const ELF: Elf = include_elf!("perp-core-guest");

#[tokio::main]
async fn main() {
    let options = options(std::env::args().skip(1), false).expect("valid CLI arguments");
    let bytes = witness_bytes(&normal_witness());
    let (d, deposit_count) = native_from_bytes(&bytes).expect("valid normal native transition");
    let expected = d.commitment::<Keccak256>();
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
    println!("PREV_ROOT=0x{}", hex(&d.prev_state_root));
    println!("MANIFEST_HASH=0x{}", hex(&d.manifest_hash));
    println!("NEW_ROOT=0x{}", hex(&d.new_state_root));
    println!("ORDERED_ROOT=0x{}", hex(&d.ordered_root));
    println!("WITHDRAWALS_ROOT=0x{}", hex(&d.withdrawals_root));
    println!("REJECTED_ROOT=0x{}", hex(&d.rejected_root));
    println!("DEPOSITS_ROOT=0x{}", hex(&d.deposits_root));
    println!("NEW_DEPOSIT_COUNT={deposit_count}");
    println!("COMMITMENT=0x{}", hex(&expected));
    println!("WITNESS_SHA256={}", sha256(&bytes));

    let mut stdin = SP1Stdin::new();
    stdin.write_vec(bytes.clone());
    let client = ProverClient::builder().cpu().build().await;
    let pk = client.setup(ELF).await.expect("local SP1 setup");
    let vkey = pk.verifying_key().bytes32_raw();
    println!("VKEY=0x{}", hex(&vkey));
    if let Some(output) = artifacts.as_mut() {
        output.write("program-vkey.bin", &vkey).unwrap();
    }

    println!("PROVING_START groth16 (local CPU and Docker gnark wrapping)");
    let proof = client
        .prove(&pk, stdin)
        .groth16()
        .await
        .expect("real local Groth16 proof");
    let proof_bytes = groth16_payload_for_verification(&proof, &expected)
        .expect("real Groth16 payload with matching commitment");
    client
        .verify(&proof, pk.verifying_key(), None)
        .expect("real proof must pass local SP1 verification");

    // No successful proof artifact is emitted until local verification passes.
    println!("PROOF=0x{}", hex(&proof_bytes));
    println!("PUBLIC_VALUES=0x{}", hex(proof.public_values.as_slice()));
    println!("LOCAL_SDK_VERIFIED=true");
    if let Some(mut output) = artifacts {
        output.write("proof.bin", &proof_bytes).unwrap();
        output
            .write("public-values.bin", proof.public_values.as_slice())
            .unwrap();
        // SDK JSON preserves the full proof for deserialization and local re-verification.
        output
            .write("proof.sdk.json", &serde_json::to_vec(&proof).unwrap())
            .unwrap();
        output.finish(json!({
            "kind": "ordinary-local-groth16-proof", "sdk_version": "6.1.0", "proof_sp1_version": proof.sp1_version,
            "witness_sha256": sha256(&bytes), "native_deserialized_same_witness": true,
            "roots": roots_json(&d, deposit_count), "program_vkey": format!("0x{}", hex(&vkey)),
            "proof_generated": true, "local_sdk_verified": true, "native_guest_equal": true,
            "target_verifier_executed": false, "a06_executed": false,
            "scope": "Synthetic ordinary deposit/withdraw; local proof verification is not target-contract acceptance or a full token lifecycle."
        })).unwrap();
    }
    println!("PROVING_DONE");
}

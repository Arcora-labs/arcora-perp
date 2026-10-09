//! Finish an interrupted local SP1 run from its actual Gnark wrapper output.
//! No proof is fabricated: deserialize the real wrapper result, restore the exact
//! SDK envelope, and cryptographically verify it before writing success artifacts.
use perp_core::hash::Keccak256;
use serde_json::{json, Value};
use sp1_host::{groth16_payload_for_verification, hex, sha256};
use sp1_sdk::{
    include_elf, Elf, HashableKey, Prover, ProverClient, ProvingKey, SP1Proof,
    SP1ProofWithPublicValues, SP1PublicValues,
};
use sp1_verifier::ProofBn254;
use std::{fs, path::PathBuf};
const ELF: Elf = include_elf!("perp-core-guest");

#[tokio::main]
async fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    assert_eq!(
        a.len(),
        4,
        "usage: finish-clock-wrapper EXECUTION_DIR BN254_OUTPUT CIRCUIT_DIR NEW_OUTPUT_DIR"
    );
    let original = PathBuf::from(&a[0]);
    let raw_path = PathBuf::from(&a[1]);
    let circuit = PathBuf::from(&a[2]);
    let output = PathBuf::from(&a[3]);
    assert!(!output.exists(), "output must be new");
    let witness = fs::read(original.join("clock.witness.bin")).unwrap();
    let elf = fs::read(original.join("guest.elf")).unwrap();
    assert_eq!(
        elf.as_slice(),
        &*ELF,
        "wrapper must belong to this exact rebuilt guest"
    );
    let expected = prover::public_from_witness(&witness)
        .unwrap()
        .commitment::<Keccak256>();
    let mut record: Value =
        serde_json::from_slice(&fs::read(original.join("execution.json")).unwrap()).unwrap();
    assert_eq!(record["native_guest_equal"], true);
    assert_eq!(record["witness_sha256"], sha256(&witness));
    assert_eq!(record["elf_sha256"], sha256(&elf));
    assert_eq!(record["commitment"], format!("0x{}", hex(&expected)));
    let raw = fs::read(&raw_path).unwrap();
    assert!(
        !raw.is_empty() && raw.len() < 1024 * 1024,
        "bounded wrapper output required"
    );
    let decoded: ProofBn254 = bincode::deserialize(&raw).expect("actual Gnark bincode proof");
    assert_eq!(
        bincode::serialize(&decoded).unwrap(),
        raw,
        "no trailing or noncanonical wrapper data"
    );
    let mut groth = match decoded {
        ProofBn254::Groth16(p) => p,
        _ => panic!("Groth16 wrapper required"),
    };
    let vk_bytes = fs::read(circuit.join("groth16_vk.bin")).unwrap();
    // Mirror upstream Groth16Bn254Prover::prove: the FFI does not fill this field.
    use sha2::{Digest as _, Sha256};
    groth.groth16_vkey_hash = Sha256::digest(&vk_bytes).into();
    assert_eq!(
        hex(&groth.groth16_vkey_hash),
        "4388a21c687fdd5f218d7e3d13190cac4c5355818d3605fd5fb811df468ee696",
        "independently pinned real target verifier"
    );
    let proof = SP1ProofWithPublicValues::new(
        SP1Proof::Groth16(groth),
        SP1PublicValues::from(&expected),
        "6.1.0".into(),
    );
    let client = ProverClient::builder().cpu().build().await;
    let pk = client.setup(ELF).await.expect("actual guest setup");
    let vkey = pk.verifying_key().bytes32_raw();
    assert_eq!(fs::read(original.join("program-vkey.bin")).unwrap(), vkey);
    assert_eq!(record["program_vkey"], format!("0x{}", hex(&vkey)));
    client
        .verify(&proof, pk.verifying_key(), None)
        .expect("resumed Groth16 must pass real SDK verification");
    let payload = groth16_payload_for_verification(&proof, &expected).unwrap();
    // All guards and cryptographic verification completed before success is emitted.
    fs::create_dir(&output).unwrap();
    for name in [
        "clock.witness.bin",
        "guest.elf",
        "program-vkey.bin",
        "execution.json",
    ] {
        fs::copy(original.join(name), output.join(name)).unwrap();
    }
    fs::write(output.join("proof.bin"), &payload).unwrap();
    fs::write(output.join("public-values.bin"), expected).unwrap();
    fs::write(
        output.join("proof.sdk.json"),
        serde_json::to_vec(&proof).unwrap(),
    )
    .unwrap();
    record["proof_generated"] = json!(true);
    record["local_sdk_verified"] = json!(true);
    record["resumed_gnark_wrapper"] = json!(true);
    record["wrapper_output_sha256"] = json!(sha256(&raw));
    record["proof_sha256"] = json!(sha256(&payload));
    record["proof_sp1_version"] = json!(proof.sp1_version);
    record["target_contract_verified"] = json!(false);
    fs::write(
        output.join("proof-evidence.json"),
        serde_json::to_vec_pretty(&record).unwrap(),
    )
    .unwrap();
    println!(
        "RESUMED_CLOCK_GROTH16_SDK_VERIFIED bytes={} commitment=0x{}",
        payload.len(),
        hex(&expected)
    );
}

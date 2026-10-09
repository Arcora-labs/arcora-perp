//! Finish an interrupted local SP1 run from its actual Gnark wrapper output.
//! No proof is fabricated: deserialize the real wrapper result, restore the exact
//! SDK envelope, and cryptographically verify it before writing success artifacts.
use perp_core::hash::Keccak256;
use serde_json::{json, Value};
use sp1_host::{groth16_payload_for_verification, hex, sha256};
use sp1_sdk::{include_elf, Elf, SP1Proof, SP1ProofWithPublicValues, SP1PublicValues};
use sp1_verifier::ProofBn254;
use std::{fs, path::PathBuf};
const ELF: Elf = include_elf!("perp-core-guest");

fn main() {
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
        sp1_sdk::SP1_CIRCUIT_VERSION.to_string(),
    );
    // Reuse the independently pinned setup-derived guest key. Verification does
    // not require constructing a multi-gigabyte CPU proving backend again.
    let vkey = fs::read(original.join("program-vkey.bin")).unwrap();
    let vkey_hex = format!("0x{}", hex(&vkey));
    assert_eq!(
        vkey_hex,
        "0x0017893c7ff3395d60b57d25eaa08cf1542fc7bc3cdfd74468133562994b8353"
    );
    assert_eq!(record["program_vkey"], vkey_hex);
    let embedded_vk: &[u8] = &sp1_verifier::GROTH16_VK_BYTES;
    assert_eq!(vk_bytes.as_slice(), embedded_vk);
    let payload = groth16_payload_for_verification(&proof, &expected).unwrap();
    sp1_verifier::Groth16Verifier::verify(&payload, &expected, &vkey_hex, embedded_vk)
        .expect("actual SP1 Groth16 verification");
    let mut mutated = payload.clone();
    let end = mutated.len() - 1;
    mutated[end] ^= 1;
    assert!(
        sp1_verifier::Groth16Verifier::verify(&mutated, &expected, &vkey_hex, embedded_vk,)
            .is_err(),
        "tampered proof must fail"
    );
    let mut wrong_public = expected;
    wrong_public[0] ^= 1;
    assert!(
        sp1_verifier::Groth16Verifier::verify(&payload, &wrong_public, &vkey_hex, embedded_vk,)
            .is_err(),
        "changed public value must fail"
    );
    assert!(
        sp1_verifier::Groth16Verifier::verify(
            &payload,
            &expected,
            &format!("0x{}", "01".repeat(32)),
            embedded_vk,
        )
        .is_err(),
        "wrong guest key must fail"
    );
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
    record["local_sdk_verified"] = json!(false);
    record["rust_sp1_verifier_verified"] = json!(true);
    record["rust_verifier_version"] = json!("6.1.0");
    record["rust_verifier_negatives"] =
        json!(["tampered-proof", "wrong-public-values", "wrong-guest-key"]);
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
        "RESUMED_CLOCK_GROTH16_RUST_VERIFIED bytes={} commitment=0x{}",
        payload.len(),
        hex(&expected)
    );
}

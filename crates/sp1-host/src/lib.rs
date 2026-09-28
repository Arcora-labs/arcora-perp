//! Synthetic ordinary deposit/withdraw witness and reproducible artifacts.
//! Never constructs wind-down operations or sends chain transactions.

use perp_core::commitment::{derive_roots, DerivedRoots};
use perp_core::engine::BatchOp;
use perp_core::hash::Keccak256;
use perp_core::market::Market;
use perp_core::note::{owner_from_spend_key, Note};
use perp_core::order::BatchManifest;
use perp_core::{DefaultState, EngineError};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use sp1_sdk::{SP1Proof, SP1ProofWithPublicValues};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};

pub type Witness = (DefaultState, Vec<BatchOp>, BatchManifest);

pub fn normal_witness() -> Witness {
    // Public test values. This deposit is NOT an observed L1 event.
    let spend_key = [3u8; 32];
    let owner = owner_from_spend_key::<Keccak256>(&spend_key);
    let blind = [9u8; 32];
    let amount = 1_000_000i128;
    let mut state = DefaultState::new(16);
    state.add_market(Market::conservative(0));
    let cm = Note::new(owner, 0, amount, blind).commitment::<Keccak256>();
    let ops = vec![
        BatchOp::Deposit {
            owner,
            asset_id: 0,
            amount,
            blinding: blind,
            from: [0u8; 20],
            deposit_id: 0,
            deposit_blind: [0u8; 32],
        },
        BatchOp::Withdraw {
            note_commitment: cm,
            spend_key,
            to: Some([0xAB; 20]),
            nonce: 1,
        },
    ];
    let manifest = BatchManifest {
        previous_state_root: state.state_root(),
        batch_id: state.next_batch_id,
        ordered: vec![],
        rejected: vec![],
        oracle_updates: vec![],
        matching_rule_version: 0,
        enclave_measurement: [0u8; 32],
        sequencer_pubkey_epoch: 0,
    };
    (state, ops, manifest)
}

pub fn witness_bytes(witness: &Witness) -> Vec<u8> {
    postcard::to_allocvec(witness).expect("synthetic witness encodes")
}

/// Derive the native result from the exact bytes given to SP1.
pub fn native_from_bytes(bytes: &[u8]) -> Result<(DerivedRoots, u64), EngineError> {
    let (mut state, ops, manifest): Witness =
        postcard::from_bytes(bytes).expect("locally encoded witness decodes");
    let roots = derive_roots(&mut state, &ops, &manifest)?;
    assert_eq!(roots.wind_down_phase, 0, "this harness is ordinary-only");
    Ok((roots, state.consumed_deposit_count))
}

pub struct NegativeCase {
    pub name: &'static str,
    pub bytes: Vec<u8>,
    pub expected_error: EngineError,
}

pub fn normal_negative_cases() -> [NegativeCase; 2] {
    let mut bad_manifest = normal_witness();
    bad_manifest.2.previous_state_root[0] ^= 1;
    let mut bad_spend = normal_witness();
    match &mut bad_spend.1[1] {
        BatchOp::Withdraw { spend_key, .. } => *spend_key = [4u8; 32],
        _ => unreachable!("the second normal operation is a withdrawal"),
    }
    [
        NegativeCase {
            name: "bad-manifest",
            bytes: witness_bytes(&bad_manifest),
            expected_error: EngineError::ManifestMismatch,
        },
        NegativeCase {
            name: "unauthorized-withdrawal",
            bytes: witness_bytes(&bad_spend),
            expected_error: EngineError::BadSpendKey,
        },
    ]
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn sha256(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

/// Payload guards only. The caller MUST also use the real SDK verifier before
/// claiming proof success or writing a successful proof manifest.
pub fn groth16_payload_for_verification(
    proof: &SP1ProofWithPublicValues,
    expected: &[u8; 32],
) -> Result<Vec<u8>, &'static str> {
    if !matches!(&proof.proof, SP1Proof::Groth16(_)) {
        return Err("Groth16 proof required");
    }
    let bytes = proof.bytes();
    if bytes.len() <= 4 {
        return Err("empty/mock proof must not be accepted");
    }
    if proof.public_values.as_slice() != expected.as_slice() {
        return Err("guest/native divergence");
    }
    Ok(bytes)
}

pub fn roots_json(roots: &DerivedRoots, deposit_count: u64) -> Value {
    json!({
        "prev_root": format!("0x{}", hex(&roots.prev_state_root)),
        "manifest_hash": format!("0x{}", hex(&roots.manifest_hash)),
        "new_root": format!("0x{}", hex(&roots.new_state_root)),
        "ordered_root": format!("0x{}", hex(&roots.ordered_root)),
        "withdrawals_root": format!("0x{}", hex(&roots.withdrawals_root)),
        "rejected_root": format!("0x{}", hex(&roots.rejected_root)),
        "deposits_root": format!("0x{}", hex(&roots.deposits_root)),
        "new_deposit_count": deposit_count,
        "wind_down_phase": roots.wind_down_phase,
        "commitment": format!("0x{}", hex(&roots.commitment::<Keccak256>()))
    })
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Options {
    pub output_dir: Option<PathBuf>,
    pub check_negatives: bool,
}

pub fn options(
    args: impl IntoIterator<Item = String>,
    allow_negatives: bool,
) -> Result<Options, String> {
    let mut result = Options::default();
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--output-dir" if result.output_dir.is_none() => {
                let value = args
                    .next()
                    .filter(|v| !v.is_empty() && !v.starts_with("--"))
                    .ok_or("--output-dir requires a new directory path")?;
                result.output_dir = Some(PathBuf::from(value));
            }
            "--check-negatives" if allow_negatives && !result.check_negatives => {
                result.check_negatives = true
            }
            _ => return Err(format!("unsupported or repeated option: {arg}")),
        }
    }
    Ok(result)
}

/// A run requires a fresh directory, preserving previous evidence. Completion
/// manifest is written last, only after all requested checks succeed.
pub struct Artifacts {
    dir: PathBuf,
    entries: Map<String, Value>,
}

impl Artifacts {
    pub fn new(dir: &Path) -> io::Result<Self> {
        fs::create_dir(dir)?;
        Ok(Self {
            dir: dir.to_owned(),
            entries: Map::new(),
        })
    }

    pub fn write(&mut self, name: &str, bytes: &[u8]) -> io::Result<()> {
        let mut components = Path::new(name).components();
        if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "artifact must be a filename",
            ));
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(self.dir.join(name))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        self.entries.insert(
            name.into(),
            json!({ "sha256": sha256(bytes), "size_bytes": bytes.len() }),
        );
        Ok(())
    }

    pub fn finish(mut self, mut manifest: Value) -> io::Result<()> {
        manifest["schema_version"] = json!(1);
        manifest["artifacts"] = Value::Object(self.entries.clone());
        let bytes = serde_json::to_vec_pretty(&manifest)?;
        self.write("manifest.json", &bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normal_reference_consumes_exact_serialized_witness() {
        let bytes = witness_bytes(&normal_witness());
        let decoded: Witness = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(witness_bytes(&decoded), bytes);
        let (roots, count) = native_from_bytes(&bytes).unwrap();
        assert_eq!(count, 1);
        assert_eq!(
            hex(&roots.commitment::<Keccak256>()),
            "dba12bfa8b5b7c54bd7035e2fdc92615c9b1f653d16b2230f3a5da7a4ff57abd"
        );
        let fields = roots_json(&roots, count);
        assert_eq!(fields["new_deposit_count"], 1);
        assert_eq!(
            fields["deposits_root"],
            format!("0x{}", hex(&roots.deposits_root))
        );
        assert_eq!(fields.as_object().unwrap().len(), 10);
    }

    #[test]
    fn normal_negative_controls_reject_for_the_intended_reasons() {
        for case in normal_negative_cases() {
            assert_eq!(
                native_from_bytes(&case.bytes).unwrap_err(),
                case.expected_error,
                "{}",
                case.name
            );
            assert_ne!(case.bytes, witness_bytes(&normal_witness()));
        }
    }

    #[test]
    fn optional_cli_preserves_default_and_rejects_ambiguous_arguments() {
        assert_eq!(options(Vec::new(), true).unwrap(), Options::default());
        assert!(options(vec!["--output-dir".into()], true).is_err());
        assert!(options(vec!["--check-negatives".into()], false).is_err());
        assert!(options(
            vec!["--output-dir".into(), "--check-negatives".into()],
            true
        )
        .is_err());
    }

    #[test]
    fn artifacts_hash_exact_bytes_and_refuse_overwrite() {
        assert_eq!(
            sha256(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("sp1-host-artifacts-{}-{stamp}", std::process::id()));
        let mut artifacts = Artifacts::new(&path).unwrap();
        assert!(Artifacts::new(&path).is_err());
        artifacts.write("witness.bin", b"abc").unwrap();
        assert!(artifacts.write("witness.bin", b"changed").is_err());
        assert!(artifacts.write("../escape", b"no").is_err());
        assert!(artifacts.write("/", b"no").is_err());
        artifacts.finish(json!({"proof_generated": false})).unwrap();
        let manifest: Value =
            serde_json::from_slice(&fs::read(path.join("manifest.json")).unwrap()).unwrap();
        assert_eq!(
            manifest["artifacts"]["witness.bin"]["sha256"],
            sha256(b"abc")
        );
        assert_eq!(fs::read(path.join("witness.bin")).unwrap(), b"abc");
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn proof_payload_guard_rejects_empty_mock_and_divergent_public_values() {
        // SDK-shaped dummy payloads, with no proving or execution. Guards reject
        // these before local SDK verification could be called.
        let variant = |encoded: &str| -> SP1Proof {
            serde_json::from_value(json!({"Groth16": {
                "encoded_proof": encoded, "groth16_vkey_hash": vec![0; 32],
                "public_inputs": ["", "", "", "", ""], "raw_proof": ""
            }}))
            .unwrap()
        };
        let expected = [1u8; 32];
        let empty = SP1ProofWithPublicValues::new(
            variant(""),
            sp1_sdk::SP1PublicValues::from(&expected),
            "6.1.0".into(),
        );
        assert_eq!(
            groth16_payload_for_verification(&empty, &expected),
            Err("empty/mock proof must not be accepted")
        );
        let divergent = SP1ProofWithPublicValues::new(
            variant("00"),
            sp1_sdk::SP1PublicValues::from(&[2u8; 32]),
            "6.1.0".into(),
        );
        assert_eq!(
            groth16_payload_for_verification(&divergent, &expected),
            Err("guest/native divergence")
        );
    }
}

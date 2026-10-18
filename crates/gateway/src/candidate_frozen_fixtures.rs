//! Test support for the frozen candidate lane (`crate::FROZEN_CANDIDATE_LANE`).
//! The committed candidate fixtures stay byte-identical as history and were
//! produced over the previous state layout. Tests that replay them are ignored;
//! each converted file keeps one test that calls [`assert_refused`] over the
//! fixtures it used to replay, so the refusal itself stays checked.
use chainlink_oracle::binding::{run_encoded, CandidateWitness, WIRE_MAGIC};
use std::path::Path;

/// Committed candidate fixture directories, relative to the repository root.
pub(crate) const NATIVE_CONTRACT_BRIDGE: &str =
    "docs/audits/2026-10-11-chainlink-native-contract-bridge/fixtures";
pub(crate) const CANDIDATE_PROTOCOL: &str =
    "docs/audits/2026-10-11-chainlink-candidate-protocol/fixtures";
pub(crate) const PRICE_LIFECYCLE: &str =
    "docs/audits/2026-10-11-chainlink-price-lifecycle/fixtures";

/// The two lifecycle witnesses every converted file replayed.
pub(crate) const LIFECYCLE_WITNESSES: [&str; 2] =
    ["normal-lifecycle.witness.bin", "liquidation.witness.bin"];

fn read(directory: &str, name: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(directory)
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// Each named witness in `directory` keeps the candidate framing, its body does
/// not decode as the current `CandidateWitness` layout, and the candidate's
/// native twin refuses the whole input as an encoding error.
pub(crate) fn assert_refused(directory: &str, names: &[&str]) {
    assert!(!names.is_empty());
    for name in names {
        let wire = read(directory, name);
        assert_eq!(
            &wire[..WIRE_MAGIC.len()],
            WIRE_MAGIC,
            "{name}: the frozen fixture keeps its framing"
        );
        assert!(
            postcard::from_bytes::<CandidateWitness>(&wire[WIRE_MAGIC.len()..]).is_err(),
            "{name}: a frozen fixture must not decode as the current layout"
        );
        assert_eq!(
            run_encoded(&wire).unwrap_err(),
            chainlink_oracle::Error::Encoding,
            "{name}"
        );
    }
}

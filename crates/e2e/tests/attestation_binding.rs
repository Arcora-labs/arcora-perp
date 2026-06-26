//! End-to-end: a **real** TDX attestation drives the enclave identity and the
//! measurement-bound seal-key release.
//!
//! This ties the three pieces together that increment #4 added:
//!   1. `dark-perp-attestation` verifies a real TDX DCAP quote and yields the
//!      attested measurement (gated on an acceptable TCB);
//!   2. that measurement seeds the sequencer's `EnclaveIdentity` (so the batch
//!      manifest commits to the attested program identity);
//!   3. the prover's `SealKeyProvider` releases the witness seal key **only** for
//!      that measurement — a prover speaking for any other measurement is refused.

use dark_perp_attestation::{verify_tdx_quote, Collateral};
use prover::{SealedWitness, SoftwareSealProvider};
use sequencer::EnclaveIdentity;

const QUOTE: &[u8] = include_bytes!("../../attestation/tests/fixtures/tdx_quote");
const COLLATERAL: &[u8] =
    include_bytes!("../../attestation/tests/fixtures/tdx_quote_collateral.json");
const NOW_SECS: u64 = 1_751_624_163; // inside the collateral window

#[test]
fn attested_measurement_seeds_identity_and_gates_seal_release() {
    // 1. Verify a real TDX quote → the attested, TCB-gated measurement.
    let collateral = Collateral::from_json(COLLATERAL).expect("collateral parses");
    let att = verify_tdx_quote(QUOTE, &collateral, NOW_SECS).expect("quote verifies");
    let measurement = att
        .enclave_measurement()
        .expect("acceptable TCB releases the attested measurement");

    // 2. It seeds the enclave identity the manifest commits to.
    let enclave = EnclaveIdentity::from_seed([3u8; 32], 1, measurement);
    assert_eq!(
        enclave.measurement, measurement,
        "identity binds the attested measurement"
    );

    // 3. The TEE key-release is bound to that measurement: a provider speaking for
    //    the attested measurement can seal a witness…
    let root = [9u8; 32];
    let nonce = [0x5Au8; 32];
    let attested_provider = SoftwareSealProvider::new(root, measurement);
    let sealed = SealedWitness::seal(b"private ledger", &attested_provider, measurement, nonce);
    assert!(
        sealed.is_some(),
        "the attested measurement releases the seal key"
    );

    // …while a prover whose measurement differs by a single bit is refused the key
    //    (it cannot open or even produce the seal — measurement-bound release).
    let mut wrong = measurement;
    wrong[0] ^= 0x01;
    let wrong_provider = SoftwareSealProvider::new(root, wrong);
    let refused = SealedWitness::seal(b"private ledger", &wrong_provider, measurement, nonce);
    assert!(
        refused.is_none(),
        "a non-matching measurement is refused the seal key"
    );
}

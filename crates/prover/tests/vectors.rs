//! Cross-layer test vectors: these exact digests are asserted byte-for-byte in
//! the Solidity tests (contracts/test/CrossLayer.t.sol) so the on-chain receipt
//! signature check and proof public-input commitment match the Rust producers.
//! If either side changes its hashing, one of these locked vectors breaks.

use perp_core::hash::Keccak256;
use perp_core::order::Receipt;
use prover::PublicInputs;

fn hex(d: &[u8; 32]) -> String {
    d.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn receipt_signing_digest_vector() {
    // orderHash = 0x1212..12, seq=7, recv=1000, hint=0
    let receipt = Receipt {
        order_hash: [0x12u8; 32],
        seq_no: 7,
        recv_time_ms: 1000,
        batch_id_hint: 0,
    };
    let d = receipt.signing_digest::<Keccak256>();
    assert_eq!(
        hex(&d),
        "ea97e0063439108b01114aef8136d5c7f4cad5d900f8a3c3e48cfbc583a4ae24",
        "RECEIPT DIGEST VECTOR (update Solidity CrossLayer.t.sol to match): {}",
        hex(&d)
    );
}

#[test]
fn public_commitment_vector() {
    // prev=0x01.., manifest=0x02.., new=0x03.., ordered=0x04.., withdrawals=0x05..
    let public = PublicInputs {
        prev_state_root: [0x01u8; 32],
        batch_manifest_hash: [0x02u8; 32],
        new_state_root: [0x03u8; 32],
        ordered_root: [0x04u8; 32],
        withdrawals_root: [0x05u8; 32],
    };
    let d = public.commitment::<Keccak256>();
    assert_eq!(
        hex(&d),
        "ae9d101e248e0d3710e0566057af9d8bdc7289f4e7435ef72cca1a94114303b1",
        "PUBLIC COMMITMENT VECTOR (update Solidity CrossLayer.t.sol to match): {}",
        hex(&d)
    );
}

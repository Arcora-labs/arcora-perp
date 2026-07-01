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
    // prev=0x01.., manifest=0x02.., new=0x03.., ordered=0x04.., withdrawals=0x05..,
    // rejected=0x06.. (audit DP-004: the 6th bound root)
    let public = PublicInputs {
        prev_state_root: [0x01u8; 32],
        batch_manifest_hash: [0x02u8; 32],
        new_state_root: [0x03u8; 32],
        ordered_root: [0x04u8; 32],
        withdrawals_root: [0x05u8; 32],
        rejected_root: [0x06u8; 32],
    };
    let d = public.commitment::<Keccak256>();
    assert_eq!(
        hex(&d),
        "5fcf2d935c94f53f10bda9e8383ac4564a464ca35d2d794806dc9410d2ba2062",
        "PUBLIC COMMITMENT VECTOR (update Solidity CrossLayer.t.sol to match): {}",
        hex(&d)
    );
}

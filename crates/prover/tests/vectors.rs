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
    // (Slice 3b-4: `window_id` is an UNSIGNED plaintext hint — it is NOT part of
    // `signing_digest`, so its value here is irrelevant to the locked vector.)
    let receipt = Receipt {
        order_hash: [0x12u8; 32],
        seq_no: 7,
        recv_time_ms: 1000,
        batch_id_hint: 0,
        window_id: 1,
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
    // rejected=0x06.. (audit DP-004: the 6th bound root), deposits=0x07..
    // (SEC-019: the 7th bound root — the post-batch deposit hash-chain tip).
    // This is KAT-COMMIT7: keccak256 over the one-byte `Domain::StateRoot` tag (0x07)
    // followed by the seven 32-byte words in order — a 225-byte preimage.
    let public = PublicInputs {
        clock_receipt: None,
        prev_state_root: [0x01u8; 32],
        batch_manifest_hash: [0x02u8; 32],
        new_state_root: [0x03u8; 32],
        ordered_root: [0x04u8; 32],
        withdrawals_root: [0x05u8; 32],
        rejected_root: [0x06u8; 32],
        deposits_root: [0x07u8; 32],
        wind_down_phase: 0,
    };
    let d = public.commitment::<Keccak256>();
    assert_eq!(
        hex(&d),
        "27e3e52688359d5759ff4c7b0bea4d25a14b3c81652a4083d531592f827d8902",
        "PUBLIC COMMITMENT VECTOR (update Solidity CrossLayer.t.sol to match): {}",
        hex(&d)
    );
}

#[test]
fn a06_wind_down_phase_one_commitment_kat() {
    let p = PublicInputs {
        clock_receipt: None,
        prev_state_root: [1; 32],
        batch_manifest_hash: [2; 32],
        new_state_root: [3; 32],
        ordered_root: [4; 32],
        withdrawals_root: [5; 32],
        rejected_root: [6; 32],
        deposits_root: [7; 32],
        wind_down_phase: 1,
    };
    assert_eq!(
        hex::encode(p.commitment::<Keccak256>()),
        "10e0f1fecdde1dc0b2aad3f551163ce9ea181ecc40f44d3b935dd11c5c373b88"
    );
}

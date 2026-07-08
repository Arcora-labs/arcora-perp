//! Emits a real secp256k1 receipt-signature fixture consumed by the Solidity
//! end-to-end test (contracts/test/CrossLayer.t.sol::test_real_receipt_*). This
//! proves the *entire* §2 path crosses languages: a receipt signed by the Rust
//! enclave verifies under L1 `ecrecover`.

use perp_core::hash::Keccak256;
use perp_core::market::Market;
use perp_core::order::{Order, Side, TimeInForce};
use sequencer::{EnclaveIdentity, Sequencer};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn emit_receipt_fixture() {
    let enclave = EnclaveIdentity::from_seed([7u8; 32], 1, [0xABu8; 32]);
    let addr = hex(&enclave.eth_address());

    let mut s = Sequencer::new(enclave, 20);
    s.add_market(Market::conservative(0));

    let order = Order {
        owner: perp_core::hash::word_u64(1),
        market_id: 0,
        side: Side::Buy,
        size: 100_000_000,
        limit_price: 100_000 * perp_core::fixed::PRICE_SCALE,
        tif: TimeInForce::Gtc,
        reduce_only: false,
        nonce: 42,
        expiry_ms: 0,
        ciphertext_commit: [0x12u8; 32],
    };
    let oh = order.order_hash::<Keccak256>();
    let receipt = s.accept_order(&order, 1000);
    assert!(receipt.verify(), "round-trip recover must succeed");
    assert_eq!(
        receipt.enclave_address,
        EnclaveIdentity::from_seed([7u8; 32], 1, [0u8; 32]).eth_address()
    );

    // Locked fixture (regenerate by reading the panic message if it changes).
    // (Slice 3b-4: `window_id` is UNSIGNED — not in `signing_digest` — so the
    // receipt signature and this fixture are unchanged from the pre-3b-4 layout.)
    assert_eq!(
        format!(
            "addr={} order_hash={} seq={} v={} r={} s={}",
            addr,
            hex(&oh),
            receipt.receipt.seq_no,
            receipt.v,
            hex(&receipt.r),
            hex(&receipt.s),
        ),
        "addr=4a62316623ad457f02cdc5d997ded67a383ec569 \
         order_hash=0c1646898f0e7370046e707059dd7cb9eba4b66af66f67671f69101d508231c5 \
         seq=0 v=28 \
         r=fb8daee4e013cc0fc4a472efd1ff4acf96719a1325690f4aa714d5c6c0f07704 \
         s=797b44171434e2623f60b97ff3bd8975979761b7bce805ab84c6f27bd31bdae1",
        "RECEIPT FIXTURE (copy into Solidity CrossLayer.t.sol)"
    );
}

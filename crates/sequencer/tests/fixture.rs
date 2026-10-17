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

/// The L1 inclusion-challenge authorization for the fixture order above, signed by
/// the same enclave. `DarkPerpSettlement.challengeInclusion` accepts only this
/// signature, over `challengeAuthDigest`:
/// `keccak256(abi.encode(CHALLENGE_AUTH_TAG, chainid, settlement, orderHash, seqNo,
/// recvTimeMs, batchIdHint, beneficiary))`. The vector (chain 84532, settlement
/// 0x22…22, beneficiary 0x33…33) is pinned in contracts/test/CrossLayer.t.sol, which
/// computes it with the deployed settlement code at that fixed address.
#[test]
fn emit_challenge_authorization_fixture() {
    use sha3::{Digest as _, Keccak256 as Sha3};
    let enclave = EnclaveIdentity::from_seed([7u8; 32], 1, [0xABu8; 32]);
    let order_hash = {
        let mut h = [0u8; 32];
        for (i, b) in h.iter_mut().enumerate() {
            let pair = &"0c1646898f0e7370046e707059dd7cb9eba4b66af66f67671f69101d508231c5"
                [i * 2..i * 2 + 2];
            *b = u8::from_str_radix(pair, 16).unwrap();
        }
        h
    };
    let uint = |n: u64| {
        let mut w = [0u8; 32];
        w[24..].copy_from_slice(&n.to_be_bytes());
        w
    };
    let address = |a: [u8; 20]| {
        let mut w = [0u8; 32];
        w[12..].copy_from_slice(&a);
        w
    };
    let tag: [u8; 32] = Sha3::digest(b"arcora:l1-inclusion-challenge:v1").into();
    let mut preimage = Vec::with_capacity(256);
    for word in [
        tag,
        uint(84532),
        address([0x22; 20]),
        order_hash,
        uint(0),
        uint(1000),
        uint(0),
        address([0x33; 20]),
    ] {
        preimage.extend_from_slice(&word);
    }
    let digest: [u8; 32] = Sha3::digest(&preimage).into();
    let (r, s, v) = enclave.sign_prehash(&digest);
    assert_eq!(
        format!(
            "tag={} digest={} sig={}{}{:02x}",
            hex(&tag),
            hex(&digest),
            hex(&r),
            hex(&s),
            v
        ),
        "tag=69f32c88aac1254085ee4ba164b69f2f12fb02828e83d559eff228842bdcc42a \
         digest=c97f5f187d95859ac2b5787fc5a2b4aaab47da927688f0b2038e0a03ff6f337d \
         sig=490ce9b286399686afb9dfb81f58c2fa2622d492fb468f27682b22fc15ed8164\
4c1c3b569abd8431ff2e339bb14d1022a5ef5d58dad371b6cfe314ad28e414821b",
        "CHALLENGE AUTHORIZATION FIXTURE (copy into Solidity CrossLayer.t.sol)"
    );
}

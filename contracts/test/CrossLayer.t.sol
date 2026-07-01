// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MiniTest} from "./utils/MiniTest.sol";
import {DarkPerpSettlement} from "../src/DarkPerpSettlement.sol";
import {MockZkVerifier} from "../src/mocks/MockZkVerifier.sol";

/// @notice Locks the on-chain hashing to the Rust producers. The expected values
/// come from `crates/prover/tests/vectors.rs` (run there to regenerate). If the
/// Solidity and Rust hashing ever diverge, the on-chain slashing path could never
/// verify a real enclave receipt and proofs could never settle — so this guards
/// the whole cross-layer contract.
contract CrossLayerTest is MiniTest {
    DarkPerpSettlement internal s;

    function setUp() public {
        s = new DarkPerpSettlement(
            address(this), address(0xE), new MockZkVerifier(), bytes32(0), 100, 50, 0
        );
    }

    function test_receipt_digest_matches_rust() public view {
        // orderHash = 0x12..12, seq=7, recv=1000, hint=0
        bytes32 d = s.receiptDigest(bytes32(uint256(0x1212121212121212121212121212121212121212121212121212121212121212)), 7, 1000, 0);
        assertEq(
            d,
            0xea97e0063439108b01114aef8136d5c7f4cad5d900f8a3c3e48cfbc583a4ae24,
            "receipt digest must match perp-core::Receipt::signing_digest"
        );
    }

    function test_public_commitment_matches_rust() public view {
        bytes32 c = s.publicCommitment(
            bytes32(uint256(0x0101010101010101010101010101010101010101010101010101010101010101)),
            bytes32(uint256(0x0202020202020202020202020202020202020202020202020202020202020202)),
            bytes32(uint256(0x0303030303030303030303030303030303030303030303030303030303030303)),
            bytes32(uint256(0x0404040404040404040404040404040404040404040404040404040404040404)),
            bytes32(uint256(0x0505050505050505050505050505050505050505050505050505050505050505)),
            bytes32(uint256(0x0606060606060606060606060606060606060606060606060606060606060606))
        );
        assertEq(
            c,
            0x5fcf2d935c94f53f10bda9e8383ac4564a464ca35d2d794806dc9410d2ba2062,
            "public commitment must match crates/prover::PublicInputs::commitment"
        );
    }

    /// End-to-end: a receipt SIGNED IN RUST (crates/sequencer, secp256k1) drives
    /// the on-chain inclusion challenge via ecrecover. Fixture from
    /// `crates/sequencer/tests/fixture.rs`. This is the §2 slashing path crossing
    /// the language boundary with a real signature, not a vm.sign() stand-in.
    function test_real_rust_receipt_passes_ecrecover() public {
        address rustEnclave = 0x4a62316623ad457F02cDC5D997deD67a383EC569;
        DarkPerpSettlement d = new DarkPerpSettlement(
            address(this), rustEnclave, new MockZkVerifier(), bytes32(0), 100, 50, 0
        );
        bytes32 orderHash = 0x0c1646898f0e7370046e707059dd7cb9eba4b66af66f67671f69101d508231c5;
        uint8 v = 28;
        bytes32 r = 0xfb8daee4e013cc0fc4a472efd1ff4acf96719a1325690f4aa714d5c6c0f07704;
        bytes32 sg = 0x797b44171434e2623f60b97ff3bd8975979761b7bce805ab84c6f27bd31bdae1;

        // recover sanity: the digest the contract builds must recover the enclave
        bytes32 digest = d.receiptDigest(orderHash, 0, 1000, 0);
        assertEq(ecrecover(digest, v, r, sg), rustEnclave, "rust receipt recovers to enclave");

        // and the full challenge entrypoint accepts it (k256 produces canonical
        // low-s signatures, so the canonical check passes). challengeBond is 0 here.
        d.challengeInclusion(orderHash, 0, 1000, 0, v, r, sg);
        (address challenger,,,,, bool open) = d.challenges(orderHash);
        assertTrue(open, "challenge opened from a real rust receipt");
        assertEq(challenger, address(this), "challenger recorded");
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import {MiniTest} from "./utils/MiniTest.sol";
import {ClockBoundVerifier, IClockSettlement} from "../src/ClockBoundVerifier.sol";
import {DarkPerpSettlement} from "../src/DarkPerpSettlement.sol";
import {MockZkVerifier} from "../src/mocks/MockZkVerifier.sol";

/// Tests exercise REAL settlement entrypoints with an explicitly mock proof
/// backend. They do not establish SP1 proof soundness or deployed-vkey identity.
contract ClockBoundVerifierTest is MiniTest {
    ClockBoundVerifier c;
    DarkPerpSettlement s;
    MockZkVerifier inner;
    bytes32 constant ROOT = bytes32(uint256(1));
    bytes32 constant NEXT = bytes32(uint256(2));
    bytes32 constant M = bytes32(uint256(3));
    bytes32 constant Z = bytes32(0);

    function setUp() public {
        vm.warp(100);
        vm.roll(1);
        inner = new MockZkVerifier();
        c = new ClockBoundVerifier(inner, 10_000, 2_000);
        s = new DarkPerpSettlement(address(this), address(0x123), c, ROOT, 100, 50, 1 ether, 600, address(this), 10);
        c.bindSettlement(IClockSettlement(address(s)));
    }

    function base() internal view returns (bytes32) {
        return s.publicCommitment(s.currentStateRoot(), M, NEXT, Z, Z, Z, Z);
    }

    function register(uint64 first, uint64 last, uint64 count) internal returns (bytes32) {
        return c.register(uint64(s.batchCount()), s.currentStateRoot(), base(), first, last, count, 0);
    }

    function proof(bytes32 b, bytes32 receipt) internal view returns (bytes memory) {
        return abi.encodePacked(keccak256(abi.encode(c.DOMAIN(), b, receipt)));
    }

    function settle(bytes memory p) internal {
        s.settleBatch(s.currentStateRoot(), M, NEXT, Z, Z, Z, Z, 0, p);
    }

    function registerFails(uint64 first, uint64 last, uint64 count) internal {
        bytes memory data =
            abi.encodeCall(c.register, (uint64(s.batchCount()), s.currentStateRoot(), base(), first, last, count, 0));
        (bool ok,) = address(c).call(data);
        assertTrue(!ok, "registration must fail");
    }

    function settleFails(bytes memory pr) internal {
        bytes memory data = abi.encodeCall(s.settleBatch, (s.currentStateRoot(), M, NEXT, Z, Z, Z, Z, 0, pr));
        (bool ok,) = address(s).call(data);
        assertTrue(!ok, "settlement must fail");
    }

    function test_actual_settlement_requires_registration() public {
        bytes32 b = base();
        settleFails(abi.encodePacked(b));
        assertEq(s.batchCount(), 0, "no advance");
    }

    function test_legacy_proof_cannot_bypass_registered_clock() public {
        bytes32 b = base();
        register(99_000, 100_000, 2);
        settleFails(abi.encodePacked(b));
    }

    function test_bound_proof_settles_through_existing_entrypoint() public {
        bytes32 b = base();
        bytes32 r = register(99_000, 100_000, 2);
        settle(proof(b, r));
        assertEq(s.batchCount(), 1, "one batch");
        assertEq(s.currentStateRoot(), NEXT, "root");
    }

    function test_proof_delay_keeps_original_receipt() public {
        bytes32 b = base();
        bytes32 r = register(99_000, 100_000, 2);
        vm.warp(10_000);
        assertEq(register(99_000, 100_000, 2), r, "retry cannot restamp");
        settle(proof(b, r));
    }

    function test_registration_is_immutable_even_with_valid_new_clock() public {
        register(99_000, 100_000, 2);
        registerFails(99_001, 100_000, 2);
    }

    function test_wrong_manifest_cannot_replace_same_batch() public {
        register(99_000, 100_000, 2);
        vm.expectRevert();
        c.register(0, ROOT, bytes32(uint256(999)), 99_000, 100_000, 2, 0);
    }

    function test_clock_does_not_replace_root_continuity() public {
        bytes32 b = base();
        vm.expectRevert();
        c.register(0, NEXT, b, 99_000, 100_000, 2, 0);
    }

    function test_clock_does_not_accept_future_batch() public {
        bytes32 b = base();
        vm.expectRevert();
        c.register(1, ROOT, b, 99_000, 100_000, 2, 0);
    }

    function test_registration_requires_role_authorization() public {
        bytes32 b = base();
        vm.prank(address(0xBEEF));
        vm.expectRevert();
        c.register(0, ROOT, b, 99_000, 100_000, 2, 0);
    }

    function test_only_bound_settlement_can_call_verify() public {
        bytes32 b = base();
        bytes32 r = register(99_000, 100_000, 2);
        assertTrue(!c.verify(b, proof(b, r)), "wrong caller");
    }

    function test_previous_anchor_cannot_be_used_for_next_batch() public {
        bytes32 b = base();
        bytes32 r = register(99_000, 100_000, 2);
        bytes memory pr = proof(b, r);
        settle(pr);
        settleFails(pr);
        assertEq(s.batchCount(), 1, "no replay");
    }

    function test_batch_time_monotonicity_crosses_settlement() public {
        bytes32 b = base();
        bytes32 r = register(99_000, 100_000, 2);
        settle(proof(b, r));
        registerFails(99_000, 100_001, 2);
    }

    function test_refuses_backdated_window() public {
        registerFails(90_000, 97_999, 2);
    }

    function test_refuses_future_window() public {
        registerFails(100_000, 102_001, 2);
    }

    function test_refuses_overlong_window() public {
        registerFails(89_999, 100_000, 2);
    }

    function test_refuses_reversed_window() public {
        registerFails(100_001, 100_000, 2);
    }

    function test_price_free_window_has_canonical_zero_bounds() public {
        registerFails(100_000, 100_000, 0);
        bytes32 b = base();
        bytes32 r = register(0, 0, 0);
        settle(proof(b, r));
    }

    function test_rebinding_is_impossible() public {
        vm.expectRevert();
        c.bindSettlement(IClockSettlement(address(s)));
    }

    function test_time_overflow_rejected() public {
        vm.warp(type(uint256).max);
        registerFails(0, 0, 0);
    }

    function test_terminal_settlement_and_exit_also_require_bound_proofs() public {
        vm.roll(102);
        s.triggerCloseOnly();
        vm.roll(112);
        bytes32 b = s.windDownCommitment(ROOT, M, NEXT, Z, Z, Z, Z, 1);
        vm.expectRevert();
        s.finalSettle(ROOT, M, NEXT, Z, Z, Z, Z, 0, abi.encodePacked(b));
        bytes32 r = c.register(0, ROOT, b, 0, 0, 0, 1);
        s.finalSettle(ROOT, M, NEXT, Z, Z, Z, Z, 0, proof(b, r));
        assertTrue(s.windDownSettled(), "phase1");
        bytes32 n = bytes32(uint256(4));
        b = s.windDownCommitment(NEXT, M, n, Z, Z, Z, Z, 2);
        vm.expectRevert();
        s.finalExit(NEXT, M, n, Z, Z, Z, Z, 0, abi.encodePacked(b));
        r = c.register(1, NEXT, b, 0, 0, 0, 2);
        s.finalExit(NEXT, M, n, Z, Z, Z, Z, 0, proof(b, r));
        assertEq(s.batchCount(), 2, "phase2");
    }

    function test_solidity_v2_encoding_matches_rust() public pure {
        bytes32 domain = keccak256("arcora:clock-bound-proof:v2");
        bytes32 r = keccak256(
            abi.encode(
                domain,
                uint256(84532),
                address(0x1111111111111111111111111111111111111111),
                address(0x2222222222222222222222222222222222222222),
                uint64(7),
                bytes32(uint256(0x3333333333333333333333333333333333333333333333333333333333333333)),
                bytes32(uint256(0x4444444444444444444444444444444444444444444444444444444444444444)),
                uint8(0),
                uint64(9000),
                uint64(10000),
                uint64(2),
                uint64(11000),
                uint64(5000),
                uint64(1000)
            )
        );
        require(r == 0xcbfb7dcc2d499142a37c266092a6fa09588217870260d0141df68e3cb256f411, "Rust receipt");
        require(
            keccak256(
                abi.encode(
                    domain, bytes32(uint256(0x4444444444444444444444444444444444444444444444444444444444444444)), r
                )
            ) == 0x5b443bd8d8b1939c024bb51c33edcb759be76402d0a06b6ecd67f703261fb77b,
            "Rust commitment"
        );
    }
}

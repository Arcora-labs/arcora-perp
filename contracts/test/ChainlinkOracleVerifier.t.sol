// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import {MiniTest} from "./utils/MiniTest.sol";
import {ChainlinkOracleVerifier, IChainlinkStreamsVerifier} from "../src/ChainlinkOracleVerifier.sol";
import {ClockBoundVerifier, IClockSettlement} from "../src/ClockBoundVerifier.sol";
import {DarkPerpSettlement} from "../src/DarkPerpSettlement.sol";
import {MockZkVerifier} from "../src/mocks/MockZkVerifier.sol";

/// Explicit test double: no real DON signature validation is claimed.
contract MockStreamsForCandidate is IChainlinkStreamsVerifier {
    mapping(bytes32 => bytes) private bodies;

    function allow(bytes memory full, bytes memory body) external {
        bodies[keccak256(full)] = body;
    }

    function verify(bytes calldata full, bytes calldata metadata) external payable returns (bytes memory) {
        require(msg.value == 0 && metadata.length == 0, "no payment or metadata");
        bytes memory body = bodies[keccak256(full)];
        require(body.length != 0, "invalid mock signature");
        return body;
    }
}

contract ChainlinkOracleVerifierTest is MiniTest {
    ChainlinkOracleVerifier o;
    ClockBoundVerifier c;
    DarkPerpSettlement s;
    MockStreamsForCandidate don;
    MockZkVerifier inner;
    bytes32 constant R = bytes32(uint256(1));
    bytes32 constant N = bytes32(uint256(2));
    bytes32 constant M = bytes32(uint256(3));
    bytes32 constant Z = bytes32(0);
    bytes32 constant PH = 0x316e98693d753c35a99d0a50fdfe9aa60508c59ddd2247b8182281fd3e809365;

    function setUp() public {
        vm.chainId(84532);
        vm.warp(100);
        vm.roll(1);
        inner = new MockZkVerifier();
        don = new MockStreamsForCandidate();
        o = new ChainlinkOracleVerifier(inner, don, PH);
        c = new ClockBoundVerifier(o, 10_000, 2_000);
        s = new DarkPerpSettlement(address(this), address(0x123), c, R, 100, 50, 1 ether, 600, address(this), 10);
        c.bindSettlement(IClockSettlement(address(s)));
        o.bindClock(c);
    }

    function feed(uint8 n) internal pure returns (bytes32) {
        return (bytes32(uint256(n) * (type(uint256).max / 255)) & bytes32(type(uint256).max >> 16))
            | bytes32(uint256(3) << 240);
    }

    function body(bool quote, uint32 observed, uint32 expires) internal pure returns (bytes memory) {
        return abi.encode(
            feed(quote ? 2 : 1),
            observed,
            observed,
            uint192(0),
            uint192(0),
            expires,
            (quote ? int192(1e8) : int192(60_000e8)),
            (quote ? int192(1e8) : int192(59_999e8)),
            (quote ? int192(1e8) : int192(60_001e8))
        );
    }

    function full(bytes memory b) internal pure returns (bytes memory) {
        bytes32[3] memory context;
        bytes32[] memory rs = new bytes32[](1);
        rs[0] = bytes32(uint256(1));
        bytes32[] memory ss = new bytes32[](1);
        ss[0] = bytes32(uint256(2));
        return abi.encode(context, b, rs, ss, bytes32(0));
    }

    function entries() internal returns (ChainlinkOracleVerifier.Entry[] memory e) {
        e = new ChainlinkOracleVerifier.Entry[](1);
        bytes memory b = body(false, 100, 160);
        bytes memory q = body(true, 100, 160);
        don.allow(full(b), b);
        don.allow(full(q), q);
        e[0] = ChainlinkOracleVerifier.Entry(0, 100_000, full(b), full(q));
    }

    function base() internal view returns (bytes32) {
        return s.publicCommitment(R, M, N, Z, Z, Z, Z);
    }

    function anchor(uint64 count) internal returns (bytes32) {
        bytes32 receipt = c.register(0, R, base(), count == 0 ? 0 : 100_000, count == 0 ? 0 : 100_000, count, 0);
        return keccak256(abi.encode(c.DOMAIN(), base(), receipt));
    }

    function settle(bytes memory proof) internal {
        s.settleBatch(R, M, N, Z, Z, Z, Z, 0, proof);
    }

    function test_new_bound_route_reaches_real_settlement_with_mock_don_and_sp1() public {
        bytes32 cb = anchor(1);
        bytes32 eh = o.register(0, 0, entries());
        settle(abi.encodePacked(o.boundCommitment(cb, eh)));
        assertEq(s.currentStateRoot(), N, "root advanced");
    }

    function test_clock_or_report_registration_cannot_be_omitted() public {
        ChainlinkOracleVerifier.Entry[] memory e = entries();
        vm.expectRevert();
        o.register(0, 0, e);
        bytes32 cb = anchor(1);
        vm.expectRevert();
        settle(abi.encodePacked(cb));
    }

    function test_plain_v2_proof_is_rejected_even_after_reports_registered() public {
        bytes32 cb = anchor(1);
        o.register(0, 0, entries());
        vm.expectRevert();
        settle(abi.encodePacked(cb));
        assertEq(s.batchCount(), 0, "no settlement");
    }

    function test_registrar_and_verifier_caller_are_bound() public {
        bytes32 cb = anchor(1);
        ChainlinkOracleVerifier.Entry[] memory e = entries();
        vm.prank(address(0xBAD));
        vm.expectRevert();
        o.register(0, 0, e);
        bytes32 eh = o.register(0, 0, e);
        assertFalse(o.verify(cb, abi.encodePacked(o.boundCommitment(cb, eh))), "only clock");
    }

    function test_both_reports_are_required_and_partial_failure_is_atomic() public {
        bytes32 cb = anchor(1);
        ChainlinkOracleVerifier.Entry[] memory e = entries();
        e[0].quoteReport[0] = 0xff;
        vm.expectRevert();
        o.register(0, 0, e);
        (,, bool exists) = o.records(cb);
        assertFalse(exists, "no partial record");
    }

    function test_zero_or_extra_evidence_cannot_hide_timed_ops() public {
        anchor(1);
        ChainlinkOracleVerifier.Entry[] memory e = new ChainlinkOracleVerifier.Entry[](0);
        vm.expectRevert();
        o.register(0, 0, e);
        e = new ChainlinkOracleVerifier.Entry[](2);
        vm.expectRevert();
        o.register(0, 0, e);
    }

    function test_wrong_operation_time_is_refused() public {
        anchor(1);
        ChainlinkOracleVerifier.Entry[] memory e = entries();
        e[0].nowMs = 100_001;
        vm.expectRevert();
        o.register(0, 0, e);
    }

    function test_expired_or_future_report_is_refused() public {
        anchor(1);
        ChainlinkOracleVerifier.Entry[] memory e = entries();
        vm.warp(161);
        vm.expectRevert();
        o.register(0, 0, e);
        vm.warp(100);
        bytes memory future = body(true, 101, 160);
        e[0].quoteReport = full(future);
        don.allow(full(future), future);
        vm.expectRevert();
        o.register(0, 0, e);
    }

    function test_exact_retry_is_immutable_even_after_report_expiry() public {
        bytes32 cb = anchor(1);
        ChainlinkOracleVerifier.Entry[] memory e = entries();
        bytes32 eh = o.register(0, 0, e);
        vm.warp(1_000);
        assertEq(o.register(0, 0, e), eh, "no restamp");
        settle(abi.encodePacked(o.boundCommitment(cb, eh)));
        assertEq(s.batchCount(), 1, "proof delay is allowed");
    }

    function test_different_payload_cannot_replace_registered_evidence() public {
        anchor(1);
        ChainlinkOracleVerifier.Entry[] memory e = entries();
        o.register(0, 0, e);
        e[0].marketId = 1;
        vm.expectRevert();
        o.register(0, 0, e);
    }

    function test_wrong_batch_phase_or_changed_chain_is_refused() public {
        bytes32 cb = anchor(1);
        ChainlinkOracleVerifier.Entry[] memory e = entries();
        vm.expectRevert();
        o.register(1, 0, e);
        vm.expectRevert();
        o.register(0, 1, e);
        bytes32 eh = o.register(0, 0, e);
        vm.chainId(8453);
        vm.expectRevert();
        o.register(0, 0, e);
        bytes memory candidateProof = abi.encodePacked(o.boundCommitment(cb, eh));
        vm.expectRevert();
        settle(candidateProof);
    }

    function test_clock_cannot_be_rebound() public {
        vm.expectRevert();
        o.bindClock(c);
    }

    function test_bad_verified_body_is_refused() public {
        anchor(1);
        ChainlinkOracleVerifier.Entry[] memory e = entries();
        don.allow(e[0].quoteReport, new bytes(32));
        vm.expectRevert();
        o.register(0, 0, e);
        bytes memory bad = body(true, 100, 160);
        bad[0] = 0xff;
        don.allow(e[0].quoteReport, bad);
        vm.expectRevert();
        o.register(0, 0, e);
    }

    function test_no_oracle_operation_path_still_requires_new_bound_proof() public {
        bytes32 cb = anchor(0);
        bytes32 eh = o.register(0, 0, new ChainlinkOracleVerifier.Entry[](0));
        vm.expectRevert();
        settle(abi.encodePacked(cb));
        settle(abi.encodePacked(o.boundCommitment(cb, eh)));
    }

    function test_rust_solidity_policy_evidence_and_bound_vectors_match() public pure {
        bytes32 ph = keccak256(
            abi.encode(
                keccak256("arcora:chainlink-usdc-liquidity-envelope-policy:v1"), uint256(84532), uint256(0), uint256(1)
            )
        );
        ph = keccak256(
            abi.encode(
                ph,
                uint256(0),
                keccak256("BTC"),
                keccak256("USDC"),
                feed(1),
                uint256(8),
                feed(2),
                uint256(8),
                uint256(10_000),
                uint256(1_000)
            )
        );
        assertEq(ph, PH, "policy hash");
        bytes32 eh = keccak256(abi.encode(keccak256("arcora:chainlink-evidence:v1"), ph, uint256(1)));
        eh = keccak256(
            abi.encode(
                eh, uint256(0), uint256(100_000), keccak256(body(false, 100, 160)), keccak256(body(true, 100, 160))
            )
        );
        assertEq(eh, 0xa9908a9b909655b6998b2892e828a2acc9a6b34a79a70b7fb15c62cb7d16d342, "evidence hash");
        bytes32 bound = keccak256(
            abi.encode(
                keccak256("arcora:chainlink-bound-proof:v1"),
                bytes32(uint256(7) * (type(uint256).max / 255)),
                address(0x0404040404040404040404040404040404040404),
                address(0x0303030303030303030303030303030303030303),
                ph,
                eh
            )
        );
        assertEq(bound, 0x237fcafee06b3ff6c4de8de8b6699ad97a6b12fb82600b599f32257627934d00, "bound commitment");
    }
}

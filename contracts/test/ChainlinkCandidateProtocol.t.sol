// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import {ChainlinkCandidateFixture} from "./ChainlinkOracleVerifier.t.sol";
import {ChainlinkOracleVerifier} from "../src/ChainlinkOracleVerifier.sol";
import {ClockBoundVerifier, IClockSettlement} from "../src/ClockBoundVerifier.sol";
import {DarkPerpSettlement} from "../src/DarkPerpSettlement.sol";
import {ChainlinkCandidateProtocolVector as Vector} from "./fixtures/ChainlinkCandidateProtocolVector.sol";

/// Rust-encoded original PUBLIC synthetic archive containers from the actual A3
/// normal and liquidation flows. Real clock/oracle/settlement contracts, with
/// explicit mock DON, SP1 and uptime. The settlement proof below is a mock bound
/// hash for the contract fixture's roots, not the native A3 witness or an SP1
/// proof. No complete host-to-real-proof bridge or live registration is claimed.
contract ChainlinkCandidateProtocolTest is ChainlinkCandidateFixture {
    function extractBody(bytes memory full) internal pure returns (bytes memory reportBody) {
        (, reportBody) = abi.decode(full, (bytes32[3], bytes));
    }

    function evidenceHash(bytes32 policy, ChainlinkOracleVerifier.Entry[] memory e) internal pure returns (bytes32 h) {
        h = keccak256(abi.encode(keccak256("arcora:chainlink-evidence:v1"), policy, e.length));
        for (uint256 i = 0; i < e.length; i++) {
            h = keccak256(
                abi.encode(
                    h,
                    e[i].marketId,
                    e[i].nowMs,
                    keccak256(extractBody(e[i].baseReport)),
                    keccak256(extractBody(e[i].quoteReport))
                )
            );
        }
    }

    function assertNativeVector(Vector.Data memory v) internal pure {
        ChainlinkOracleVerifier.Entry[] memory e = abi.decode(v.entriesAbi, (ChainlinkOracleVerifier.Entry[]));
        require(e.length == v.timedOps && e.length <= 128, "entry count");
        require(keccak256(v.entriesAbi) == v.inputHash, "Rust ABI hash");
        require(keccak256(abi.encode(e)) == v.inputHash, "Solidity Entry[] ABI parity");
        require(evidenceHash(v.policyHash, e) == v.evidenceHash, "ordered body hash parity");
        require(e[0].nowMs == v.firstMs && e[e.length - 1].nowMs == v.lastMs, "clock endpoints");
    }

    function prepare(Vector.Data memory v, uint64 firstMs)
        internal
        returns (bytes32 cb, ChainlinkOracleVerifier.Entry[] memory e)
    {
        o = new ChainlinkOracleVerifier(inner, don, v.policyHash, address(uptime), 10);
        c = new ClockBoundVerifier(o, 10_000, 2_000);
        s = new DarkPerpSettlement(address(this), address(0x123), c, R, 100, 50, 1 ether, 600, address(this), 10);
        c.bindSettlement(IClockSettlement(address(s)));
        o.bindClock(c);
        vm.warp(v.lastMs / 1000);
        bytes32 receipt = c.register(0, R, base(), firstMs, v.lastMs, v.timedOps, 0);
        cb = keccak256(abi.encode(c.DOMAIN(), base(), receipt));
        e = abi.decode(v.entriesAbi, (ChainlinkOracleVerifier.Entry[]));
        for (uint256 i = 0; i < e.length; i++) {
            don.allow(e[i].baseReport, extractBody(e[i].baseReport));
            don.allow(e[i].quoteReport, extractBody(e[i].quoteReport));
        }
    }

    function assertRecord(bytes32 cb, Vector.Data memory v) internal view {
        (bytes32 evidence, bytes32 input, bool exists) = o.records(cb);
        assertTrue(exists, "complete record exists");
        assertEq(input, v.inputHash, "original full-container identity");
        assertEq(evidence, v.evidenceHash, "original ordered bodies");
    }

    function assertNoRecord(bytes32 cb) internal view {
        (,, bool exists) = o.records(cb);
        (uint80 roundId, uint64 startedAt) = o.uptimeEpochs(cb);
        assertFalse(exists, "no partial report registration");
        assertEq(uint256(roundId), 0, "no partial uptime round");
        assertEq(uint256(startedAt), 0, "no partial uptime timestamp");
        assertEq(s.batchCount(), 0, "settlement count unchanged");
        assertEq(s.currentStateRoot(), R, "settlement root unchanged");
    }

    function settleVector(Vector.Data memory v) internal {
        assertNativeVector(v);
        (bytes32 cb, ChainlinkOracleVerifier.Entry[] memory e) = prepare(v, v.firstMs);
        bytes32 h = o.register(0, 0, e);
        assertEq(h, v.evidenceHash, "actual wrapper body commitment");
        assertRecord(cb, v);
        settle(abi.encodePacked(o.boundCommitment(cb, h)));
        assertEq(s.batchCount(), 1, "real settlement entrypoint advanced");
        assertEq(s.currentStateRoot(), N, "mock fixture final root");
    }

    function test_native_normal_abi_and_mock_contract_lifecycle() public {
        settleVector(Vector.normal());
    }

    function test_native_liquidation_abi_and_mock_contract_lifecycle() public {
        settleVector(Vector.liquidation());
    }

    function test_same_bodies_different_signature_container_refuses_replacement() public {
        Vector.Data memory v = Vector.normal();
        (bytes32 cb, ChainlinkOracleVerifier.Entry[] memory e) = prepare(v, v.firstMs);
        o.register(0, 0, e);
        // The exact canonical rs location comes from the supplied container ABI.
        (,, bytes32[] memory rs) = abi.decode(e[0].baseReport, (bytes32[3], bytes, bytes32[]));
        bytes memory beforeBody = extractBody(e[0].baseReport);
        uint256 rsOffset;
        bytes memory full = e[0].baseReport;
        assembly ("memory-safe") { rsOffset := mload(add(full, 160)) }
        require(rs.length != 0 && rsOffset + 64 <= full.length, "canonical synthetic signature");
        full[rsOffset + 32] = bytes1(uint8(full[rsOffset + 32]) ^ 1);
        don.allow(full, beforeBody);
        assertEq(keccak256(extractBody(full)), keccak256(beforeBody), "body is identical");
        assertEq(evidenceHash(v.policyHash, e), v.evidenceHash, "body evidence unchanged");
        assertTrue(keccak256(abi.encode(e)) != v.inputHash, "full-container identity changed");
        vm.expectRevert(ChainlinkOracleVerifier.Replacement.selector);
        o.register(0, 0, e);
        assertRecord(cb, v);
        assertEq(s.batchCount(), 0, "replacement has no settlement effect");
    }

    function test_reordered_registered_material_cannot_replace_original() public {
        Vector.Data memory v = Vector.normal();
        (bytes32 cb, ChainlinkOracleVerifier.Entry[] memory e) = prepare(v, v.firstMs);
        o.register(0, 0, e);
        // Distinct original observation times make this a material reorder,
        // while preserving both full report objects and the total entry count.
        ChainlinkOracleVerifier.Entry memory first =
            ChainlinkOracleVerifier.Entry(e[0].marketId, e[0].nowMs, e[0].baseReport, e[0].quoteReport);
        e[0] = e[e.length - 1];
        e[e.length - 1] = first;
        assertEq(e[0].nowMs, v.lastMs, "last original entry moved first");
        assertEq(e[e.length - 1].nowMs, v.firstMs, "first original entry moved last");
        assertTrue(keccak256(abi.encode(e)) != v.inputHash, "ordered full input changes");
        assertTrue(evidenceHash(v.policyHash, e) != v.evidenceHash, "ordered evidence changes");
        vm.expectRevert(ChainlinkOracleVerifier.Replacement.selector);
        o.register(0, 0, e);
        assertRecord(cb, v);
    }

    function test_omitted_and_extra_actual_entries_fail_atomically() public {
        Vector.Data memory v = Vector.normal();
        (bytes32 cb, ChainlinkOracleVerifier.Entry[] memory e) = prepare(v, v.firstMs);
        ChainlinkOracleVerifier.Entry[] memory omitted = new ChainlinkOracleVerifier.Entry[](e.length - 1);
        for (uint256 i = 0; i < omitted.length; i++) {
            omitted[i] = e[i];
        }
        vm.expectRevert(ChainlinkOracleVerifier.Evidence.selector);
        o.register(0, 0, omitted);
        assertNoRecord(cb);
        ChainlinkOracleVerifier.Entry[] memory extra = new ChainlinkOracleVerifier.Entry[](e.length + 1);
        for (uint256 i = 0; i < e.length; i++) {
            extra[i] = e[i];
        }
        extra[e.length] = e[e.length - 1];
        vm.expectRevert(ChainlinkOracleVerifier.Evidence.selector);
        o.register(0, 0, extra);
        assertNoRecord(cb);
        vm.expectRevert(DarkPerpSettlement.BadProof.selector);
        settle(abi.encodePacked(bytes32(uint256(1))));
        assertNoRecord(cb);
    }

    function test_wrong_clock_endpoint_refuses_reports_and_settlement() public {
        Vector.Data memory v = Vector.normal();
        (bytes32 cb, ChainlinkOracleVerifier.Entry[] memory e) = prepare(v, v.firstMs - 1);
        vm.expectRevert(ChainlinkOracleVerifier.Evidence.selector);
        o.register(0, 0, e);
        assertNoRecord(cb);
        bytes memory proof = abi.encodePacked(o.boundCommitment(cb, v.evidenceHash));
        vm.expectRevert(DarkPerpSettlement.BadProof.selector);
        settle(proof);
        assertNoRecord(cb);
    }

    function test_registered_actual_entries_cannot_settle_in_different_epoch() public {
        Vector.Data memory v = Vector.liquidation();
        (bytes32 cb, ChainlinkOracleVerifier.Entry[] memory e) = prepare(v, v.firstMs);
        bytes32 h = o.register(0, 0, e);
        uptime.set(2, 0, 1); // healthy and same startedAt, distinct uint80 round
        vm.expectRevert(ChainlinkOracleVerifier.SequencerEpochChanged.selector);
        o.register(0, 0, e);
        bytes memory proof = abi.encodePacked(o.boundCommitment(cb, h));
        vm.expectRevert(DarkPerpSettlement.BadProof.selector);
        settle(proof);
        assertRecord(cb, v);
        assertEq(s.batchCount(), 0, "epoch replacement cannot advance state");
        assertEq(s.currentStateRoot(), R, "original root retained");
    }
}

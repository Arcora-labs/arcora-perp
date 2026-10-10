// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import {ChainlinkCandidateFixture} from "./ChainlinkOracleVerifier.t.sol";
import {MockSequencerUptime} from "./utils/MockSequencerUptime.sol";
import {ChainlinkOracleVerifier, IChainlinkStreamsVerifier} from "../src/ChainlinkOracleVerifier.sol";
import {ClockBoundVerifier, IClockSettlement} from "../src/ClockBoundVerifier.sol";
import {DarkPerpSettlement} from "../src/DarkPerpSettlement.sol";

/// Test-only side effect during external verification, not a Chainlink DON.
contract InterruptingStreams is IChainlinkStreamsVerifier {
    MockSequencerUptime public uptime;
    bool public interrupt = true;

    constructor(MockSequencerUptime feed) {
        uptime = feed;
    }

    function stop() external {
        interrupt = false;
    }

    function verify(bytes calldata full, bytes calldata) external payable returns (bytes memory body) {
        (, body) = abi.decode(full, (bytes32[3], bytes));
        if (interrupt) uptime.set(2, 1, 100);
    }
}

/// Real clock + settlement entrypoints; uptime, DON and SP1 are synthetic doubles.
contract ChainlinkSequencerUptimeTest is ChainlinkCandidateFixture {
    function assertNoRecord(bytes32 cb) internal view {
        (,, bool exists) = o.records(cb);
        (uint80 roundId, uint64 startedAt) = o.uptimeEpochs(cb);
        assertFalse(exists, "no partial report record");
        assertEq(uint256(roundId), 0, "no partial uptime round");
        assertEq(uint256(startedAt), 0, "no partial uptime timestamp");
        assertEq(s.batchCount(), 0, "no state advance");
    }

    function registeredProof() internal returns (bytes32 cb, bytes memory proof) {
        cb = anchor(1);
        bytes32 h = o.register(0, 0, entries());
        proof = abi.encodePacked(o.boundCommitment(cb, h));
    }

    function assertNotReady() internal view {
        (bool ready,,) = o.uptimeStatus();
        assertFalse(ready, "unsafe uptime must not appear ready");
    }

    function test_uptime_down_prevents_registration_atomically() public {
        bytes32 cb = anchor(1);
        ChainlinkOracleVerifier.Entry[] memory e = entries();
        uptime.set(2, 1, 95);
        vm.expectRevert(ChainlinkOracleVerifier.SequencerUnavailable.selector);
        o.register(0, 0, e);
        assertNoRecord(cb);
    }

    function test_uptime_noncanonical_unknown_status_and_invalid_time_fail_closed() public {
        bytes32 cb = anchor(1);
        ChainlinkOracleVerifier.Entry[] memory e = entries();
        bytes[] memory invalid = new bytes[](8);
        invalid[0] = abi.encode(uint80(1), int256(-1), uint256(1), uint256(1), uint80(1));
        invalid[1] = abi.encode(uint80(1), int256(2), uint256(1), uint256(1), uint80(1));
        invalid[2] = abi.encode(uint80(0), int256(0), uint256(1), uint256(1), uint80(0));
        invalid[3] = abi.encode(uint80(1), int256(0), uint256(0), uint256(0), uint80(1));
        invalid[4] = abi.encode(uint80(1), int256(0), uint256(101), uint256(101), uint80(1));
        invalid[5] = abi.encode(uint80(1), int256(0), type(uint256).max, uint256(1), uint80(1));
        invalid[6] = abi.encode(uint256(1) << 80, int256(0), uint256(1), uint256(1), uint80(1));
        invalid[7] = abi.encode(uint80(1), int256(0), uint256(1), uint256(1), uint256(1) << 80);
        for (uint256 i = 0; i < invalid.length; i++) {
            uptime.setRaw(invalid[i], false);
            assertNotReady();
            vm.expectRevert(ChainlinkOracleVerifier.SequencerUnavailable.selector);
            o.register(0, 0, e);
            assertNoRecord(cb);
        }
    }

    function test_uptime_revert_empty_short_and_oversized_replies_are_rejected() public {
        bytes32 cb = anchor(1);
        ChainlinkOracleVerifier.Entry[] memory e = entries();
        uint256[5] memory sizes = [uint256(0), 32, 159, 161, 16384];
        for (uint256 i = 0; i < sizes.length; i++) {
            uptime.setRaw(new bytes(sizes[i]), false);
            assertNotReady();
            vm.expectRevert(ChainlinkOracleVerifier.SequencerUnavailable.selector);
            o.register(0, 0, e);
            assertNoRecord(cb);
        }
        uptime.setRaw(new bytes(160), true);
        assertNotReady();
        vm.expectRevert(ChainlinkOracleVerifier.SequencerUnavailable.selector);
        o.register(0, 0, e);
        assertNoRecord(cb);
    }

    function test_uptime_grace_exact_boundary_is_not_ready() public {
        bytes32 cb = anchor(1);
        ChainlinkOracleVerifier.Entry[] memory e = entries();
        uptime.set(2, 0, 90); // now=100, configured grace=10
        assertNotReady();
        vm.expectRevert(ChainlinkOracleVerifier.SequencerUnavailable.selector);
        o.register(0, 0, e);
        assertNoRecord(cb);
    }

    function test_uptime_one_second_after_grace_accepts_original_operation() public {
        uptime.set(2, 0, 89); // operation=100, strictly after 89+10
        (bytes32 cb, bytes memory proof) = registeredProof();
        (uint80 roundId, uint64 startedAt) = o.uptimeEpochs(cb);
        assertEq(uint256(roundId), 2, "bound recovery round");
        assertEq(uint256(startedAt), 89, "bound recovery start");
        settle(proof);
        assertEq(s.batchCount(), 1, "normal candidate settlement");
    }

    function test_uptime_delayed_registration_cannot_launder_grace_period_execution() public {
        bytes32 cb = anchor(1);
        ChainlinkOracleVerifier.Entry[] memory e = entries();
        uptime.set(2, 0, 95); // original operation was inside grace
        vm.warp(120); // registration clock alone would now pass
        (bool ready,,) = o.uptimeStatus();
        assertTrue(ready, "current status is healthy");
        vm.expectRevert(ChainlinkOracleVerifier.SequencerUnavailable.selector);
        o.register(0, 0, e);
        assertNoRecord(cb);
    }

    function test_uptime_registration_after_recovery_refuses_pre_recovery_operations() public {
        bytes32 cb = anchor(1);
        ChainlinkOracleVerifier.Entry[] memory e = entries();
        uptime.set(3, 0, 110);
        vm.warp(125);
        vm.expectRevert(ChainlinkOracleVerifier.SequencerUnavailable.selector);
        o.register(0, 0, e);
        assertNoRecord(cb);
    }

    function test_uptime_settlement_rechecks_after_report_registration() public {
        (, bytes memory proof) = registeredProof();
        uptime.set(2, 1, 101);
        vm.warp(110);
        vm.expectRevert();
        settle(proof);
        assertEq(s.batchCount(), 0, "down after registration prevents settlement");
    }

    function test_uptime_exact_retry_does_not_bypass_current_outage() public {
        bytes32 cb = anchor(1);
        ChainlinkOracleVerifier.Entry[] memory e = entries();
        bytes32 h = o.register(0, 0, e);
        uptime.set(2, 1, 101);
        vm.warp(110);
        vm.expectRevert(ChainlinkOracleVerifier.SequencerUnavailable.selector);
        o.register(0, 0, e);
        (bytes32 stillHash,, bool exists) = o.records(cb);
        assertTrue(exists, "original record retained");
        assertEq(stillHash, h, "no restamp or replacement");
    }

    function test_uptime_pre_outage_proof_cannot_be_revived_in_new_epoch() public {
        (, bytes memory proof) = registeredProof();
        uptime.set(3, 0, 110);
        vm.warp(120); // grace boundary
        vm.expectRevert();
        settle(proof);
        vm.warp(140); // grace ended; the epoch is nevertheless different
        vm.expectRevert();
        settle(proof);
        assertEq(s.currentStateRoot(), R, "old proof not repurposed");
    }

    function test_uptime_round_change_even_with_equal_timestamp_cannot_reuse_record() public {
        (, bytes memory proof) = registeredProof();
        uptime.set(2, 0, 1);
        vm.expectRevert();
        settle(proof);
    }

    function test_uptime_start_change_even_with_equal_round_cannot_reuse_record() public {
        (, bytes memory proof) = registeredProof();
        uptime.set(1, 0, 2);
        vm.expectRevert();
        settle(proof);
    }

    function test_uptime_retry_cannot_repin_record_to_another_healthy_epoch() public {
        anchor(1);
        ChainlinkOracleVerifier.Entry[] memory e = entries();
        o.register(0, 0, e);
        uptime.set(2, 0, 1);
        vm.expectRevert(ChainlinkOracleVerifier.SequencerEpochChanged.selector);
        o.register(0, 0, e);
    }

    function test_uptime_old_unchanged_status_is_not_a_stale_price() public {
        (, bytes memory proof) = registeredProof();
        vm.warp(1_000_000);
        (bool ready, uint80 roundId, uint64 startedAt) = o.uptimeStatus();
        assertTrue(ready, "no fabricated heartbeat on a status-change feed");
        assertEq(uint256(roundId), 1, "same round");
        assertEq(uint256(startedAt), 1, "same start");
        // A registered report may outlive its expiry while an actual proof is computed.
        // This still is only a mock SP1 backend, not a real delayed proof.
        settle(proof);
    }

    function test_uptime_unavailable_at_settlement_fails_closed_without_state_change() public {
        (, bytes memory proof) = registeredProof();
        uptime.setRaw(new bytes(32), false);
        vm.expectRevert();
        settle(proof);
        assertEq(s.currentStateRoot(), R, "bad uptime never authorizes root update");
    }

    function test_uptime_constructor_requires_feed_code_and_nonzero_explicit_grace() public {
        vm.expectRevert(ChainlinkOracleVerifier.Configuration.selector);
        new ChainlinkOracleVerifier(inner, don, PH, address(0), 10);
        vm.expectRevert(ChainlinkOracleVerifier.Configuration.selector);
        new ChainlinkOracleVerifier(inner, don, PH, address(0x12345), 10);
        vm.expectRevert(ChainlinkOracleVerifier.Configuration.selector);
        new ChainlinkOracleVerifier(inner, don, PH, address(uptime), 0);
        assertEq(o.sequencerUptimeFeed(), address(uptime), "immutable explicit feed");
        assertEq(uint256(o.sequencerGraceSeconds()), 10, "fixture-only grace, not a production recommendation");
    }

    function test_uptime_price_free_batch_does_not_depend_on_feed_liveness() public {
        bytes32 cb = anchor(0);
        uptime.setRaw(new bytes(0), true);
        bytes32 h = o.register(0, 0, new ChainlinkOracleVerifier.Entry[](0));
        (uint80 roundId,) = o.uptimeEpochs(cb);
        assertEq(uint256(roundId), 0, "explicit price-free record");
        bytes memory proof = abi.encodePacked(o.boundCommitment(cb, h));
        settle(proof);
        assertEq(s.batchCount(), 1, "proof-required price-free path remains available");
    }

    function test_uptime_empty_evidence_cannot_masquerade_as_price_free() public {
        bytes32 cb = anchor(1);
        uptime.set(2, 1, 90);
        ChainlinkOracleVerifier.Entry[] memory empty = new ChainlinkOracleVerifier.Entry[](0);
        vm.expectRevert(ChainlinkOracleVerifier.Evidence.selector);
        o.register(0, 0, empty);
        assertNoRecord(cb);
    }

    function test_uptime_price_free_wind_down_and_final_exit_keep_actual_contract_routes() public {
        uptime.setRaw(new bytes(0), true);
        vm.roll(102);
        s.triggerCloseOnly();
        vm.roll(112);
        bytes32 b = s.windDownCommitment(R, M, N, Z, Z, Z, Z, 1);
        bytes32 receipt = c.register(0, R, b, 0, 0, 0, 1);
        bytes32 cb = keccak256(abi.encode(c.DOMAIN(), b, receipt));
        bytes32 h = o.register(0, 1, new ChainlinkOracleVerifier.Entry[](0));
        s.finalSettle(R, M, N, Z, Z, Z, Z, 0, abi.encodePacked(o.boundCommitment(cb, h)));
        assertTrue(s.windDownSettled(), "price-free terminal settlement");
        bytes32 next = bytes32(uint256(4));
        b = s.windDownCommitment(N, M, next, Z, Z, Z, Z, 2);
        receipt = c.register(1, N, b, 0, 0, 0, 2);
        cb = keccak256(abi.encode(c.DOMAIN(), b, receipt));
        h = o.register(1, 2, new ChainlinkOracleVerifier.Entry[](0));
        s.finalExit(N, M, next, Z, Z, Z, Z, 0, abi.encodePacked(o.boundCommitment(cb, h)));
        assertEq(s.batchCount(), 2, "final exit route");
    }

    function test_uptime_external_verifier_status_change_reverts_entire_registration() public {
        InterruptingStreams changing = new InterruptingStreams(uptime);
        o = new ChainlinkOracleVerifier(inner, changing, PH, address(uptime), 10);
        c = new ClockBoundVerifier(o, 10_000, 2_000);
        s = new DarkPerpSettlement(address(this), address(0x123), c, R, 100, 50, 1 ether, 600, address(this), 10);
        c.bindSettlement(IClockSettlement(address(s)));
        o.bindClock(c);
        bytes32 cb = anchor(1);
        ChainlinkOracleVerifier.Entry[] memory e = entries();
        vm.expectRevert(ChainlinkOracleVerifier.SequencerUnavailable.selector);
        o.register(0, 0, e);
        assertNoRecord(cb);
        changing.stop();
        bytes32 h = o.register(0, 0, e);
        settle(abi.encodePacked(o.boundCommitment(cb, h)));
        assertEq(s.batchCount(), 1, "revert did not leave lock or partial data behind");
    }
}

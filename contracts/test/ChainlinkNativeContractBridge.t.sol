// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MiniTest} from "./utils/MiniTest.sol";
import {SettlementTestConfig} from "./utils/SettlementTestConfig.sol";
import {MockSequencerUptime} from "./utils/MockSequencerUptime.sol";
import {MockSP1Verifier} from "../src/mocks/MockSP1Verifier.sol";
import {SP1ZkVerifier} from "../src/SP1ZkVerifier.sol";
import {ISP1Verifier} from "../src/interfaces/ISP1Verifier.sol";
import {ClockBoundVerifier, IClockSettlement} from "../src/ClockBoundVerifier.sol";
import {ChainlinkOracleVerifier} from "../src/ChainlinkOracleVerifier.sol";
import {DarkPerpSettlement} from "../src/DarkPerpSettlement.sol";
import {BridgeExactStreams, BridgeStrictPrefixVault} from "./mocks/ChainlinkNativeBridgeMocks.sol";
import {ChainlinkNativeContractBridgeTypes as T} from "./fixtures/ChainlinkNativeContractBridgeTypes.sol";
import {ChainlinkNativeContractBridgeSource as Source} from "./fixtures/ChainlinkNativeContractBridgeSource.sol";
import {ChainlinkNativeContractBridgeVector as Vector} from "./fixtures/ChainlinkNativeContractBridgeVector.sol";

/// New synthetic target witness from the preserved native A3 source. The actual
/// clock/oracle/settlement/SP1 adapter execute here; DON/SP1/uptime/prefix inputs
/// are explicit mocks. No proof authenticity, custody or live acceptance.
contract ChainlinkNativeContractBridgeTest is MiniTest {
    bytes32 internal constant VKEY = 0x006aa3cfa389566dd318c9bf12f3946a623555e5f624359037e2d5c4d35ad590;
    uint80 internal constant ROUND = 0x0102030405060708090a;
    uint64 internal constant STARTED = 1000;
    uint64 internal constant GRACE = 60;
    /// Not part of the clock receipt or the captured context.
    uint64 internal constant ANCHOR_TIMEOUT_MS = 3_600_000;

    struct Stack {
        MockSP1Verifier gateway;
        SP1ZkVerifier adapter;
        BridgeExactStreams don;
        MockSequencerUptime uptime;
        ChainlinkOracleVerifier oracle;
        ClockBoundVerifier clock;
        DarkPerpSettlement settlement;
        BridgeStrictPrefixVault vault;
        bytes32 receipt;
        bytes32 clockCommitment;
    }

    event log_named_bytes(string key, bytes value);

    function setUp() public {
        vm.chainId(84532);
        vm.roll(100);
        vm.warp(2001);
    }

    function body(bytes memory full) internal pure returns (bytes memory reportBody) {
        (, reportBody) = abi.decode(full, (bytes32[3], bytes));
    }

    function evidence(bytes32 policy, ChainlinkOracleVerifier.Entry[] memory entries)
        internal
        pure
        returns (bytes32 h)
    {
        h = keccak256(abi.encode(keccak256("arcora:chainlink-evidence:v1"), policy, entries.length));
        for (uint256 i; i < entries.length; i++) {
            h = keccak256(
                abi.encode(
                    h,
                    entries[i].marketId,
                    entries[i].nowMs,
                    keccak256(body(entries[i].baseReport)),
                    keccak256(body(entries[i].quoteReport))
                )
            );
        }
    }

    function deploy(T.SourceData memory d, uint64 atMs) internal returns (Stack memory x) {
        require(atMs % 1000 == 0 && d.phase == 0 && d.batchId == 0, "bridge context");
        require(d.depositCount == 9 && d.roots[6] != bytes32(0), "native prefix");
        vm.warp(atMs / 1000);
        // This CREATE order is identical in each isolated capture/replay test.
        x.gateway = new MockSP1Verifier();
        x.adapter = new SP1ZkVerifier(ISP1Verifier(address(x.gateway)), VKEY);
        x.don = new BridgeExactStreams();
        x.uptime = new MockSequencerUptime();
        x.oracle = new ChainlinkOracleVerifier(x.adapter, x.don, d.policyHash, address(x.uptime), GRACE);
        x.clock = new ClockBoundVerifier(x.oracle, d.maxWindowMs, d.clockSkewMs, ANCHOR_TIMEOUT_MS);
        x.settlement = new DarkPerpSettlement(
            SettlementTestConfig.legacy(
                address(this), address(0x123), x.clock, d.roots[0], 100, 50, 1 ether, 600, address(this), 10
            )
        );
        x.vault = new BridgeStrictPrefixVault(address(x.settlement), d.depositCount, d.roots[6]);
        x.settlement.setVault(address(x.vault));
        x.clock.bindSettlement(IClockSettlement(address(x.settlement)));
        x.oracle.bindClock(x.clock);
        x.uptime.set(ROUND, 0, STARTED);
        ChainlinkOracleVerifier.Entry[] memory entries = abi.decode(d.entriesAbi, (ChainlinkOracleVerifier.Entry[]));
        require(entries.length == d.timedOps && keccak256(abi.encode(entries)) == d.inputHash, "native full ABI");
        require(evidence(d.policyHash, entries) == d.evidenceHash, "native body evidence");
        for (uint256 i; i < entries.length; i++) {
            x.don.allow(entries[i].baseReport, body(entries[i].baseReport));
            x.don.allow(entries[i].quoteReport, body(entries[i].quoteReport));
        }
        x.don.lock();
        require(base(x.settlement, d.roots) == d.baseCommitment, "native seven-root commitment");
        x.receipt = x.clock.register(d.batchId, d.roots[0], d.baseCommitment, d.firstMs, d.lastMs, d.timedOps, d.phase);
        x.clockCommitment = keccak256(abi.encode(x.clock.DOMAIN(), d.baseCommitment, x.receipt));
    }

    function base(DarkPerpSettlement s, bytes32[7] memory r) internal pure returns (bytes32) {
        return s.publicCommitment(r[0], r[1], r[2], r[3], r[4], r[5], r[6]);
    }

    function actualContext(Stack memory x, T.SourceData memory d) internal view returns (T.Context memory c) {
        c.chainId = uint64(block.chainid);
        c.network = 0;
        c.clockVerifier = address(x.clock);
        c.settlement = address(x.settlement);
        c.oracleWrapper = address(x.oracle);
        c.verifierProxy = address(x.don);
        c.sp1Adapter = address(x.adapter);
        c.sp1Gateway = address(x.gateway);
        c.uptimeFeed = address(x.uptime);
        c.prefixVault = address(x.vault);
        c.clockVerifierCodeHash = address(x.clock).codehash;
        c.settlementCodeHash = address(x.settlement).codehash;
        c.oracleWrapperCodeHash = address(x.oracle).codehash;
        c.verifierProxyCodeHash = address(x.don).codehash;
        c.sp1AdapterCodeHash = address(x.adapter).codehash;
        c.sp1GatewayCodeHash = address(x.gateway).codehash;
        c.uptimeFeedCodeHash = address(x.uptime).codehash;
        c.prefixVaultCodeHash = address(x.vault).codehash;
        c.anchoredAtMs = x.clock.anchor(d.batchId, d.phase).anchoredAtMs;
        c.maxWindowMs = x.clock.maxWindowMs();
        c.clockSkewMs = x.clock.clockSkewMs();
        (bool ready, uint80 round, uint64 started) = x.oracle.uptimeStatus();
        require(ready, "actual mock uptime ready");
        c.uptimeRoundId = round;
        c.uptimeStartedAt = started;
        c.graceSeconds = x.oracle.sequencerGraceSeconds();
        c.registeredReceipt = x.receipt;
        c.clockCommitment = x.clockCommitment;
        c.sourceWitnessSha256 = d.sourceWitnessSha256;
        c.baseCommitment = base(x.settlement, d.roots);
        c.policyHash = x.oracle.policyHash();
        c.postConsumedDepositCount = x.vault.depositCount();
        c.postConsumedDepositTip = x.vault.depositChainTip();
        c.programVkey = x.adapter.programVKey();
    }

    function capture(T.SourceData memory d, string memory name) internal {
        Stack memory x = deploy(d, 2001000);
        bytes memory encoded = abi.encode(actualContext(x, d));
        require(encoded.length == 32 * 32, "bounded static context");
        emit log_named_bytes(name, encoded);
    }

    function test_capture_normal_context() public {
        capture(Source.normal(), "normal-lifecycle");
    }

    function test_capture_liquidation_context() public {
        capture(Source.liquidation(), "liquidation");
    }

    function mockProof() internal pure returns (bytes memory) {
        return bytes("arcora-native-contract-bridge-mock-proof-v1");
    }

    function assertContext(Stack memory x, T.SourceData memory d, T.VectorData memory v) internal view {
        assertEq(
            keccak256(abi.encode(actualContext(x, d))),
            keccak256(abi.encode(v.context)),
            "all actual target/runtime/clock/epoch/native prefix fields match captured context"
        );
        assertTrue(v.witnessSha256 != d.sourceWitnessSha256, "new target-bound witness identity");
        assertEq(x.adapter.programVKey(), VKEY, "real adapter candidate guest key");
        assertEq(address(x.adapter.gateway()), address(x.gateway), "real adapter exact tuple gateway");
        assertEq(x.clock.proofVersion(), 2, "DPCLK3 witness uses clock version2");
    }

    function registerOriginal(Stack memory x, T.SourceData memory d) internal {
        ChainlinkOracleVerifier.Entry[] memory e = abi.decode(d.entriesAbi, (ChainlinkOracleVerifier.Entry[]));
        assertEq(x.oracle.register(d.batchId, d.phase, e), d.evidenceHash, "native ordered report evidence");
        (bytes32 eh, bytes32 ih, bool exists) = x.oracle.records(x.clockCommitment);
        assertTrue(exists, "complete report record");
        assertEq(eh, d.evidenceHash, "registered body evidence");
        assertEq(ih, d.inputHash, "registered exact full containers");
        (uint80 round, uint64 started) = x.oracle.uptimeEpochs(x.clockCommitment);
        assertEq(uint256(round), uint256(ROUND), "entire uint80 epoch pinned");
        assertEq(started, STARTED, "original uptime timestamp pinned");
    }

    function ready(T.SourceData memory d, T.VectorData memory v) internal returns (Stack memory x) {
        x = deploy(d, v.context.anchoredAtMs);
        assertContext(x, d, v);
        registerOriginal(x, d);
        assertEq(
            x.oracle.boundCommitment(x.clockCommitment, d.evidenceHash),
            v.nativeCommitment,
            "actual wrappers equal exported native commitment"
        );
        x.gateway.setExpected(VKEY, abi.encodePacked(v.nativeCommitment), mockProof());
        assertEq(x.gateway.expectedPublicValues().length, 32, "exact SP1 public32 bytes");
    }

    function settleRoots(Stack memory x, bytes32[7] memory r, uint64 count, bytes memory proof) internal {
        x.settlement.settleBatch(r[0], r[1], r[2], r[3], r[4], r[5], r[6], count, proof);
    }

    function assertUnchanged(Stack memory x, T.SourceData memory d) internal view {
        assertEq(x.settlement.batchCount(), 0, "failed attempt cannot advance batch");
        assertEq(x.settlement.currentStateRoot(), d.roots[0], "native previous root retained");
        assertEq(x.vault.publicationCount(), 0, "failed attempt cannot publish withdrawals");
    }

    function assertNoReports(Stack memory x, T.SourceData memory d) internal view {
        (,, bool exists) = x.oracle.records(x.clockCommitment);
        assertFalse(exists, "no partial report record");
        (uint80 round, uint64 started) = x.oracle.uptimeEpochs(x.clockCommitment);
        assertEq(uint256(round), 0, "no partial epoch round");
        assertEq(started, 0, "no partial epoch timestamp");
        assertUnchanged(x, d);
    }

    function positive(T.SourceData memory d, T.VectorData memory v) internal {
        Stack memory x = ready(d, v);
        assertEq(x.vault.depositCount(), 9, "native post consumed deposit count");
        assertEq(x.vault.depositChainTip(), d.roots[6], "native nonzero post deposit tip");
        assertEq(x.settlement.requiredBond(), 0, "mock prefix has no collateral TVL");
        settleRoots(x, d.roots, d.depositCount, mockProof());
        assertEq(x.settlement.currentStateRoot(), d.roots[2], "exact native final state root");
        assertEq(x.settlement.batchCount(), 1, "actual native batch accepted by mock proof stack");
        (bytes32 manifest, bytes32 ordered, bytes32 rejected, uint256 atBlock) = x.settlement.batches(0);
        assertEq(manifest, d.roots[1], "native manifest root stored");
        assertEq(ordered, d.roots[3], "native ordered root stored");
        assertEq(rejected, d.roots[5], "native rejection root stored");
        assertEq(atBlock, block.number, "actual settlement block");
        assertEq(x.vault.publishedRoot(), d.roots[4], "exact native withdrawals publication");
        assertEq(x.vault.publishedEpoch(), 0, "actual batch publication epoch");
        assertEq(x.vault.publicationCount(), 1, "one mock publication");
    }

    function test_native_normal_roots_commitment_and_mock_contract_settlement() public {
        T.SourceData memory d = Source.normal();
        assertTrue(d.roots[4] != bytes32(0), "actual normal withdrawal root is nonzero");
        positive(d, Vector.normal());
    }

    function test_native_liquidation_roots_commitment_and_mock_contract_settlement() public {
        positive(Source.liquidation(), Vector.liquidation());
    }

    function sibling(ChainlinkOracleVerifier.Entry[] memory e) internal pure {
        bytes memory full = e[0].baseReport;
        bytes memory beforeBody = body(full);
        uint256 rsOffset;
        assembly ("memory-safe") { rsOffset := mload(add(full, 160)) }
        require(rsOffset % 32 == 0 && rsOffset + 64 <= full.length, "canonical rs location");
        full[rsOffset + 32] = bytes1(uint8(full[rsOffset + 32]) ^ 1);
        require(keccak256(body(full)) == keccak256(beforeBody), "same body signature sibling");
    }

    function test_same_body_signature_sibling_fails_exact_don_before_initial_registration() public {
        T.SourceData memory d = Source.normal();
        Stack memory x = deploy(d, Vector.normal().context.anchoredAtMs);
        assertContext(x, d, Vector.normal());
        ChainlinkOracleVerifier.Entry[] memory e = abi.decode(d.entriesAbi, (ChainlinkOracleVerifier.Entry[]));
        sibling(e);
        assertEq(evidence(d.policyHash, e), d.evidenceHash, "body hash unchanged");
        assertTrue(keccak256(abi.encode(e)) != d.inputHash, "full signed container hash changes");
        vm.expectRevert(BridgeExactStreams.UnpinnedContainer.selector);
        x.oracle.register(d.batchId, d.phase, e);
        assertNoReports(x, d);
    }

    function test_same_body_signature_sibling_cannot_replace_original_record() public {
        T.SourceData memory d = Source.normal();
        Stack memory x = ready(d, Vector.normal());
        ChainlinkOracleVerifier.Entry[] memory e = abi.decode(d.entriesAbi, (ChainlinkOracleVerifier.Entry[]));
        sibling(e);
        assertEq(evidence(d.policyHash, e), d.evidenceHash, "replacement body hash unchanged");
        vm.expectRevert(ChainlinkOracleVerifier.Replacement.selector);
        x.oracle.register(d.batchId, d.phase, e);
        (bytes32 eh, bytes32 ih, bool exists) = x.oracle.records(x.clockCommitment);
        assertTrue(exists, "original record remains");
        assertEq(eh, d.evidenceHash, "original evidence remains");
        assertEq(ih, d.inputHash, "original full input remains");
        assertUnchanged(x, d);
    }

    function test_same_time_reordered_native_material_cannot_use_original_native_proof() public {
        T.SourceData memory d = Source.normal();
        T.VectorData memory v = Vector.normal();
        Stack memory x = deploy(d, v.context.anchoredAtMs);
        assertContext(x, d, v);
        ChainlinkOracleVerifier.Entry[] memory e = abi.decode(d.entriesAbi, (ChainlinkOracleVerifier.Entry[]));
        require(e[0].nowMs == e[2].nowMs && e[0].marketId != e[2].marketId, "distinct same-time native entries");
        ChainlinkOracleVerifier.Entry memory first =
            ChainlinkOracleVerifier.Entry(e[0].marketId, e[0].nowMs, e[0].baseReport, e[0].quoteReport);
        e[0] = ChainlinkOracleVerifier.Entry(e[2].marketId, e[2].nowMs, e[2].baseReport, e[2].quoteReport);
        e[2] = first;
        bytes32 reordered = evidence(d.policyHash, e);
        assertTrue(
            reordered != d.evidenceHash && keccak256(abi.encode(e)) != d.inputHash, "both ordered identities change"
        );
        assertEq(x.oracle.register(d.batchId, d.phase, e), reordered, "valid pinned reports retain new order");
        assertTrue(x.oracle.boundCommitment(x.clockCommitment, reordered) != v.nativeCommitment, "native order binding");
        x.gateway.setExpected(VKEY, abi.encodePacked(v.nativeCommitment), mockProof());
        vm.expectRevert(DarkPerpSettlement.BadProof.selector);
        settleRoots(x, d.roots, d.depositCount, mockProof());
        assertUnchanged(x, d);
    }

    function test_omitted_extra_native_reports_fail_without_partial_records() public {
        T.SourceData memory d = Source.normal();
        Stack memory x = deploy(d, Vector.normal().context.anchoredAtMs);
        ChainlinkOracleVerifier.Entry[] memory e = abi.decode(d.entriesAbi, (ChainlinkOracleVerifier.Entry[]));
        ChainlinkOracleVerifier.Entry[] memory omitted = new ChainlinkOracleVerifier.Entry[](e.length - 1);
        for (uint256 i; i < omitted.length; i++) {
            omitted[i] = e[i];
        }
        vm.expectRevert(ChainlinkOracleVerifier.Evidence.selector);
        x.oracle.register(d.batchId, d.phase, omitted);
        assertNoReports(x, d);
        ChainlinkOracleVerifier.Entry[] memory extra = new ChainlinkOracleVerifier.Entry[](e.length + 1);
        for (uint256 i; i < e.length; i++) {
            extra[i] = e[i];
        }
        extra[e.length] = e[e.length - 1];
        vm.expectRevert(ChainlinkOracleVerifier.Evidence.selector);
        x.oracle.register(d.batchId, d.phase, extra);
        assertNoReports(x, d);
    }

    function test_all_seven_native_root_mutations_refuse_settlement() public {
        T.SourceData memory d = Source.normal();
        Stack memory x = ready(d, Vector.normal());
        for (uint256 i; i < 7; i++) {
            bytes32[7] memory wrong;
            for (uint256 j; j < 7; j++) {
                wrong[j] = d.roots[j];
            }
            wrong[i] = bytes32(uint256(wrong[i]) ^ 1);
            if (i == 0) vm.expectRevert(DarkPerpSettlement.BadPrevRoot.selector);
            else if (i == 6) vm.expectRevert(bytes("deposits: root != L1 chain prefix"));
            else vm.expectRevert(DarkPerpSettlement.BadProof.selector);
            settleRoots(x, wrong, d.depositCount, mockProof());
            assertUnchanged(x, d);
        }
    }

    function test_native_prefix_count_eight_or_ten_is_refused() public {
        T.SourceData memory d = Source.normal();
        Stack memory x = ready(d, Vector.normal());
        // below the head: the strict mock refuses any prefix but the exported one
        vm.expectRevert(BridgeStrictPrefixVault.WrongPrefixCount.selector);
        settleRoots(x, d.roots, 8, mockProof());
        assertUnchanged(x, d);
        // beyond the head: the settlement refuses before reading the prefix
        vm.expectRevert(DarkPerpSettlement.BadDepositCount.selector);
        settleRoots(x, d.roots, 10, mockProof());
        assertUnchanged(x, d);
    }

    function test_other_valid_evm_anchor_cannot_use_exported_native_proof() public {
        T.SourceData memory d = Source.normal();
        T.VectorData memory v = Vector.normal();
        Stack memory x = deploy(d, v.context.anchoredAtMs + 1000);
        registerOriginal(x, d);
        assertTrue(
            x.receipt != v.context.registeredReceipt && x.clockCommitment != v.context.clockCommitment,
            "valid later anchor changes native clock commitment"
        );
        assertTrue(
            x.oracle.boundCommitment(x.clockCommitment, d.evidenceHash) != v.nativeCommitment,
            "actual later anchor differs from exported native commitment"
        );
        x.gateway.setExpected(VKEY, abi.encodePacked(v.nativeCommitment), mockProof());
        vm.expectRevert(DarkPerpSettlement.BadProof.selector);
        settleRoots(x, d.roots, d.depositCount, mockProof());
        assertUnchanged(x, d);
    }

    function test_other_deployed_targets_cannot_use_exported_native_proof() public {
        T.SourceData memory d = Source.normal();
        T.VectorData memory v = Vector.normal();
        Stack memory original = ready(d, v);
        Stack memory x = deploy(d, v.context.anchoredAtMs);
        registerOriginal(x, d);
        assertTrue(
            address(x.clock) != v.context.clockVerifier && address(x.settlement) != v.context.settlement
                && address(x.oracle) != v.context.oracleWrapper && address(x.don) != v.context.verifierProxy,
            "actual second deployment has different targets"
        );
        assertTrue(
            x.oracle.boundCommitment(x.clockCommitment, d.evidenceHash) != v.nativeCommitment,
            "actual target domain differs from original native commitment"
        );
        x.gateway.setExpected(VKEY, abi.encodePacked(v.nativeCommitment), mockProof());
        vm.expectRevert(DarkPerpSettlement.BadProof.selector);
        settleRoots(x, d.roots, d.depositCount, mockProof());
        assertUnchanged(x, d);
        assertUnchanged(original, d);
    }

    function test_changed_chain_refuses_original_native_proof() public {
        T.SourceData memory d = Source.normal();
        Stack memory x = ready(d, Vector.normal());
        vm.chainId(8453);
        vm.expectRevert(DarkPerpSettlement.BadProof.selector);
        settleRoots(x, d.roots, d.depositCount, mockProof());
        assertUnchanged(x, d);
    }

    function test_real_sp1_adapter_rejects_wrong_exact_tuple_fields() public {
        T.SourceData memory d = Source.normal();
        T.VectorData memory v = Vector.normal();
        Stack memory x = ready(d, v);
        x.gateway.setExpected(bytes32(uint256(VKEY) ^ 1), abi.encodePacked(v.nativeCommitment), mockProof());
        vm.expectRevert(DarkPerpSettlement.BadProof.selector);
        settleRoots(x, d.roots, d.depositCount, mockProof());
        assertUnchanged(x, d);
        x.gateway.setExpected(VKEY, abi.encodePacked(v.nativeCommitment, bytes1(0)), mockProof());
        vm.expectRevert(DarkPerpSettlement.BadProof.selector);
        settleRoots(x, d.roots, d.depositCount, mockProof());
        assertUnchanged(x, d);
        x.gateway.setExpected(VKEY, abi.encodePacked(bytes32(uint256(v.nativeCommitment) ^ 1)), mockProof());
        vm.expectRevert(DarkPerpSettlement.BadProof.selector);
        settleRoots(x, d.roots, d.depositCount, mockProof());
        assertUnchanged(x, d);
        x.gateway.setExpected(VKEY, abi.encodePacked(v.nativeCommitment), mockProof());
        bytes memory changedProof = mockProof();
        changedProof[0] = bytes1(uint8(changedProof[0]) ^ 1);
        vm.expectRevert(DarkPerpSettlement.BadProof.selector);
        settleRoots(x, d.roots, d.depositCount, changedProof);
        assertUnchanged(x, d);
    }

    function test_changed_full_uint80_epoch_and_started_at_refuse_original_native_proof() public {
        T.SourceData memory d = Source.liquidation();
        Stack memory x = ready(d, Vector.liquidation());
        ChainlinkOracleVerifier.Entry[] memory e = abi.decode(d.entriesAbi, (ChainlinkOracleVerifier.Entry[]));
        x.uptime.set(ROUND ^ (uint80(1) << 72), 0, STARTED);
        vm.expectRevert(ChainlinkOracleVerifier.SequencerEpochChanged.selector);
        x.oracle.register(d.batchId, d.phase, e);
        vm.expectRevert(DarkPerpSettlement.BadProof.selector);
        settleRoots(x, d.roots, d.depositCount, mockProof());
        assertUnchanged(x, d);
        x.uptime.set(ROUND, 0, STARTED + 1);
        vm.expectRevert(ChainlinkOracleVerifier.SequencerEpochChanged.selector);
        x.oracle.register(d.batchId, d.phase, e);
        vm.expectRevert(DarkPerpSettlement.BadProof.selector);
        settleRoots(x, d.roots, d.depositCount, mockProof());
        assertUnchanged(x, d);
        (uint80 round, uint64 started) = x.oracle.uptimeEpochs(x.clockCommitment);
        assertEq(uint256(round), uint256(ROUND), "original full uint80 epoch retained");
        assertEq(started, STARTED, "original epoch timestamp retained");
    }
}

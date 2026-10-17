// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MiniTest} from "./utils/MiniTest.sol";
import {SettlementTestConfig} from "./utils/SettlementTestConfig.sol";
import {MockClockVerifier} from "./mocks/MockClockVerifier.sol";
import {DarkPerpSettlement} from "../src/DarkPerpSettlement.sol";
import {CollateralVault} from "../src/CollateralVault.sol";
import {ClockBoundVerifier, IClockSettlement} from "../src/ClockBoundVerifier.sol";
import {SP1ZkVerifier} from "../src/SP1ZkVerifier.sol";
import {IZkVerifier} from "../src/interfaces/IZkVerifier.sol";
import {ISP1Verifier} from "../src/interfaces/ISP1Verifier.sol";
import {MockUSDC} from "../src/mocks/MockUSDC.sol";
import {MockZkVerifier} from "../src/mocks/MockZkVerifier.sol";
import {MockSP1Verifier} from "../src/mocks/MockSP1Verifier.sol";

/// Log-recording cheatcodes, which MiniTest's `Vm` subset does not declare. Same
/// cheatcode address.
interface VmLogs {
    struct Log {
        bytes32[] topics;
        bytes data;
        address emitter;
    }

    function recordLogs() external;
    function getRecordedLogs() external returns (Log[] memory);
}

/// Answers both verifier shape probes with the expected value, but as two words.
contract WideShapeProbe {
    fallback(bytes calldata input) external returns (bytes memory) {
        bool version = input.length >= 4 && bytes4(input[:4]) == bytes4(keccak256("proofVersion()"));
        return abi.encode(version ? uint256(2) : uint256(0), uint256(0));
    }
}

/// Answers every call successfully with empty return data.
contract SilentShapeProbe {
    fallback() external {}
}

/// Reports proof version 2 but has no `settlement()` getter.
contract VersionOnlyProbe {
    uint64 public constant proofVersion = 2;
}

/// DarkPerpSettlement against a real CollateralVault and the MockClockVerifier shim.
/// This contract is the sequencer and the governance of the settlement under test.
contract DarkPerpSettlementTest is MiniTest {
    VmLogs internal constant vmLogs = VmLogs(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

    DarkPerpSettlement internal s;
    CollateralVault internal vault;
    MockUSDC internal usdc;
    MockClockVerifier internal verifier;

    uint256 internal constant ENCLAVE_PK = 0xA11CE;
    address internal enclaveSigner;
    bytes32 internal constant GENESIS = bytes32(uint256(1));
    uint256 internal constant LIVENESS = SettlementTestConfig.LIVENESS_BLOCKS;
    uint256 internal constant CHALLENGE_GRACE = SettlementTestConfig.CHALLENGE_GRACE_BLOCKS;
    uint256 internal constant CHALLENGE_BOND = SettlementTestConfig.CHALLENGE_BOND;
    uint256 internal constant INCLUSION_DEADLINE = SettlementTestConfig.INCLUSION_DEADLINE_SECS;
    uint256 internal constant GRACE = SettlementTestConfig.FINAL_SETTLE_GRACE_BLOCKS;
    uint256 internal constant PROGRESS = SettlementTestConfig.PROGRESS_BATCHES;
    uint256 internal constant CAP = SettlementTestConfig.SLASH_PAYOUT_CAP;
    uint256 internal constant USD = 1e6;
    /// The gateway signing key the vault is deployed with.
    uint256 internal constant GW_PK = 0x6A7E;
    uint256 internal constant PERMIT_TTL = 1_800;
    /// The receipt time every helper-opened challenge signs (t = 1 s).
    uint64 internal constant RECV_MS = 1_000;
    uint256 internal constant SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    bytes32 internal constant CLOSE_ONLY_TOPIC = keccak256("CloseOnlyEntered(string)");
    bytes32 internal constant BATCH_SETTLED_TOPIC = keccak256("BatchSettled(uint256,bytes32,bytes32,bytes32)");
    bytes32 internal constant FINAL_SETTLE_TOPIC = keccak256("FinalSettle(uint256,bytes32,bytes32,bytes32)");
    bytes32 internal constant CHALLENGED_TOPIC = keccak256("InclusionChallenged(bytes32,address,address,uint256)");
    bytes32 internal constant SLASHED_TOPIC = keccak256("SequencerSlashed(bytes32,address,uint256)");
    bytes32 internal constant RELEASED_TOPIC = keccak256("ChallengeReleased(bytes32)");

    /// The address an enclave authorization names (receives a fine).
    address internal constant BENEFICIARY = address(0xCAFE);
    /// A third party that submits someone else's authorization and posts the stake.
    address internal constant SUBMITTER = address(0x5B17);
    address internal constant OUTSIDER = address(0xBAD);

    uint256 internal commitNonce;

    function setUp() public {
        verifier = new MockClockVerifier();
        enclaveSigner = vm.addr(ENCLAVE_PK);
        s = new DarkPerpSettlement(_cfg());
        usdc = new MockUSDC();
        vault = new CollateralVault(address(s), address(usdc), vm.addr(GW_PK));
        s.setVault(address(vault));
    }

    // --- helpers ----------------------------------------------------------------

    function _cfg() internal view returns (DarkPerpSettlement.Config memory) {
        return SettlementTestConfig.defaults(address(this), enclaveSigner, verifier, GENESIS);
    }

    function _expectInvalidConfig(DarkPerpSettlement.Config memory c) internal {
        vm.expectRevert(DarkPerpSettlement.InvalidConfig.selector);
        new DarkPerpSettlement(c);
    }

    /// The sequencer (this contract) posts a USDC bond of `amount`.
    function _bond(uint256 amount) internal {
        usdc.mint(address(this), amount);
        usdc.approve(address(s), amount);
        s.postBond(amount);
    }

    /// Tops the bond up to exactly what a deposit of `amount` more needs.
    function _coverCapacity(uint256 amount) internal {
        uint256 need = ((vault.tvl() + amount) * s.BOND_BPS()) / 10_000;
        uint256 have = s.sequencerBond();
        if (need > have) _bond(need - have);
    }

    /// Funds `from`, approves the vault and returns a gateway permit for a deposit of
    /// `amount` under a fresh owner commitment. Does not deposit.
    function _permit(address from, uint256 amount)
        internal
        returns (bytes32 commit, uint64 validUntil, bytes memory sig)
    {
        commit = keccak256(abi.encodePacked("owner-commit", ++commitNonce));
        validUntil = uint64(block.timestamp + PERMIT_TTL);
        sig = SettlementTestConfig.permitSig(vm, GW_PK, vault, from, commit, amount, validUntil);
        usdc.mint(from, amount);
        vm.prank(from);
        usdc.approve(address(vault), amount);
    }

    /// A permitted deposit of `amount` by `from`, with the bond topped up to cover it.
    function _depositFrom(address from, uint256 amount) internal returns (uint64 id, bytes32 commit) {
        _coverCapacity(amount);
        uint64 validUntil;
        bytes memory sig;
        (commit, validUntil, sig) = _permit(from, amount);
        id = vault.depositCount();
        vm.prank(from);
        vault.deposit(amount, commit, validUntil, sig);
    }

    function _depositToVault(uint256 amount) internal returns (uint64 id) {
        (id,) = _depositFrom(address(this), amount);
    }

    /// The vault's live deposit head. Read into locals BEFORE arming `vm.expectRevert`:
    /// these are external calls, and the cheatcode binds to the very next one.
    function _head() internal view returns (bytes32 tip, uint64 count) {
        return (vault.depositChainTip(), vault.depositCount());
    }

    function _pinError() internal pure returns (bytes memory) {
        return abi.encodeWithSignature("Error(string)", "deposits: root != L1 chain prefix");
    }

    /// Settles a batch with the given roots that credits every deposit up to the head.
    function _settle(bytes32 prev, bytes32 manifest, bytes32 newRoot, bytes32 ord, bytes32 wd, bytes32 rej) internal {
        (bytes32 dTip, uint64 dCount) = _head();
        bytes32 commitment = s.publicCommitment(prev, manifest, newRoot, ord, wd, rej, dTip);
        s.settleBatch(prev, manifest, newRoot, ord, wd, rej, dTip, dCount, abi.encode(commitment));
    }

    /// Settles an empty phase-0 batch that has consumed the vault's first `n` deposits.
    function _settleEmptyAt(uint64 n) internal returns (uint256 batchId) {
        batchId = s.batchCount();
        bytes32 prev = s.currentStateRoot();
        bytes32 next = keccak256(abi.encodePacked("empty", batchId));
        bytes32 tip = vault.depositTipAt(n);
        bytes32 commitment = s.publicCommitment(prev, bytes32("e"), next, bytes32(0), bytes32(0), bytes32(0), tip);
        s.settleBatch(prev, bytes32("e"), next, bytes32(0), bytes32(0), bytes32(0), tip, n, abi.encode(commitment));
    }

    /// Settles an empty batch that credits no new deposit.
    function _keepalive() internal returns (uint256) {
        return _settleEmptyAt(s.consumedDepositCount());
    }

    /// Settles a fresh batch whose `orderedRoot` is a single-leaf tree containing
    /// `orderHash`, and returns the (batchId, proof) an inclusion answer can use.
    function _settleBatchWithOrder(bytes32 orderHash) internal returns (uint256 batchId, bytes32[] memory proof) {
        batchId = s.batchCount();
        bytes32 ordered = s.inclusionLeaf(batchId, orderHash); // single-leaf root
        bytes32 prev = s.currentStateRoot();
        bytes32 newRoot = keccak256(abi.encodePacked("next", batchId));
        (bytes32 dTip, uint64 dCount) = _head();
        bytes32 commitment = s.publicCommitment(prev, bytes32("m"), newRoot, ordered, bytes32(0), bytes32(0), dTip);
        s.settleBatch(
            prev, bytes32("m"), newRoot, ordered, bytes32(0), bytes32(0), dTip, dCount, abi.encodePacked(commitment)
        );
        proof = new bytes32[](0);
    }

    function _settleRejectionBatch(bytes32 orderHash) internal returns (uint256 batchId) {
        batchId = s.batchCount();
        bytes32 rejected = s.rejectionLeaf(batchId, orderHash); // single-leaf root
        bytes32 prev = s.currentStateRoot();
        bytes32 newRoot = keccak256(abi.encodePacked("rej", batchId));
        (bytes32 dTip, uint64 dCount) = _head();
        bytes32 commitment = s.publicCommitment(prev, bytes32("m"), newRoot, bytes32(0), bytes32(0), rejected, dTip);
        s.settleBatch(
            prev, bytes32("m"), newRoot, bytes32(0), bytes32(0), rejected, dTip, dCount, abi.encodePacked(commitment)
        );
    }

    /// The enclave's authorization for `orderHash` (seqNo 1, RECV_MS, hint 0) naming
    /// `beneficiary`.
    function _authSig(bytes32 orderHash, address beneficiary) internal view returns (bytes memory) {
        return _sigBy(ENCLAVE_PK, orderHash, beneficiary);
    }

    function _sigBy(uint256 pk, bytes32 orderHash, address beneficiary) internal view returns (bytes memory) {
        return SettlementTestConfig.challengeSig(vm, pk, s, orderHash, 1, RECV_MS, 0, beneficiary);
    }

    /// Warps to the first second a RECV_MS receipt may be challenged, plus one.
    function _ripen() internal {
        vm.warp(RECV_MS / 1000 + INCLUSION_DEADLINE + 1);
    }

    /// Opens a ripe challenge for `orderHash` authorized for `beneficiary`, submitted
    /// and staked by `staker`.
    function _openChallenge(bytes32 orderHash, address beneficiary, address staker) internal {
        bytes memory sig = _authSig(orderHash, beneficiary);
        vm.deal(staker, CHALLENGE_BOND);
        _ripen();
        vm.prank(staker);
        s.challengeInclusion{value: CHALLENGE_BOND}(orderHash, 1, RECV_MS, 0, beneficiary, sig);
    }

    /// The beneficiary opens its own challenge.
    function _openRipeChallenge(bytes32 orderHash, address challenger) internal {
        _openChallenge(orderHash, challenger, challenger);
    }

    /// Settles the phase-0 batches a slash needs after the current batch count and
    /// rolls past the grace that follows them.
    function _ripenSlash() internal {
        for (uint256 i = 0; i < PROGRESS; i++) {
            _keepalive();
        }
        vm.roll(block.number + CHALLENGE_GRACE + 1);
    }

    /// The stalled-root trigger needs a batch, deposit or open challenge to protect, so
    /// a stack holding none of them first settles one empty batch, as a live gateway would.
    function _enterCloseOnlyViaLiveness() internal {
        if (s.batchCount() == 0 && vault.depositCount() == 0 && s.openChallengeCount() == 0) _keepalive();
        vm.roll(block.number + LIVENESS + 1);
        s.triggerCloseOnly();
        assertTrue(s.closeOnly(), "close-only entered via liveness timeout");
    }

    /// Builds a fixed phase-1 fixture at the frozen consumed prefix. Read before arming
    /// `vm.expectRevert`: these are external calls.
    function _finalSettleArgs()
        internal
        view
        returns (
            bytes32 prev,
            bytes32 manifestHash,
            bytes32 newRoot,
            bytes32 wroot,
            bytes32 dTip,
            uint64 dCount,
            bytes memory proof
        )
    {
        prev = s.currentStateRoot();
        manifestHash = bytes32("m");
        newRoot = keccak256("wind-down");
        wroot = keccak256("withdrawals");
        dCount = s.consumedDepositCount();
        dTip = vault.depositTipAt(dCount);
        bytes32 commitment = s.windDownCommitment(prev, manifestHash, newRoot, bytes32(0), wroot, bytes32(0), dTip, 1);
        proof = abi.encodePacked(commitment);
    }

    function _governanceFinalSettle() internal {
        (
            bytes32 prev,
            bytes32 manifestHash,
            bytes32 newRoot,
            bytes32 wroot,
            bytes32 dTip,
            uint64 dCount,
            bytes memory proof
        ) = _finalSettleArgs();
        s.finalSettle(prev, manifestHash, newRoot, bytes32(0), wroot, bytes32(0), dTip, dCount, proof);
    }

    /// A wind-down batch of `phase` (1 = finalSettle, 2 = finalExit) claiming prefix `n`.
    function _windDownArgs(uint64 phase, uint64 n)
        internal
        view
        returns (bytes32 prev, bytes32 next, bytes32 tip, bytes memory proof)
    {
        prev = s.currentStateRoot();
        next = keccak256(abi.encodePacked("wind-down", phase, s.batchCount()));
        tip = vault.depositTipAt(n);
        proof =
            abi.encode(s.windDownCommitment(prev, bytes32("w"), next, bytes32(0), bytes32(0), bytes32(0), tip, phase));
    }

    function _windDownCall(uint64 phase, bytes32 prev, bytes32 next, bytes32 tip, uint64 n, bytes memory proof)
        internal
    {
        if (phase == 1) {
            s.finalSettle(prev, bytes32("w"), next, bytes32(0), bytes32(0), bytes32(0), tip, n, proof);
        } else {
            s.finalExit(prev, bytes32("w"), next, bytes32(0), bytes32(0), bytes32(0), tip, n, proof);
        }
    }

    function _windDown(uint64 phase, uint64 n) internal {
        (bytes32 prev, bytes32 next, bytes32 tip, bytes memory proof) = _windDownArgs(phase, n);
        _windDownCall(phase, prev, next, tip, n, proof);
    }

    function _expectWindDownRevert(uint64 phase, uint64 n, bytes4 err) internal {
        (bytes32 prev, bytes32 next, bytes32 tip, bytes memory proof) = _windDownArgs(phase, n);
        vm.expectRevert(err);
        _windDownCall(phase, prev, next, tip, n, proof);
    }

    function _find(VmLogs.Log[] memory logs, address emitter, bytes32 topic0)
        internal
        pure
        returns (uint256 count, uint256 at)
    {
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].emitter == emitter && logs[i].topics.length != 0 && logs[i].topics[0] == topic0) {
                count++;
                at = i;
            }
        }
    }

    /// Exactly one CloseOnlyEntered from `emitter` since `recordLogs`, with `want`.
    function _assertCloseOnlyReason(address emitter, string memory want) internal {
        VmLogs.Log[] memory logs = vmLogs.getRecordedLogs();
        (uint256 n, uint256 at) = _find(logs, emitter, CLOSE_ONLY_TOPIC);
        assertEq(n, 1, "close-only entered exactly once");
        assertEq(keccak256(bytes(abi.decode(logs[at].data, (string)))), keccak256(bytes(want)), "close-only reason");
    }

    function _assertNoCloseOnlyEvent(address emitter) internal {
        (uint256 n,) = _find(vmLogs.getRecordedLogs(), emitter, CLOSE_ONLY_TOPIC);
        assertEq(n, 0, "no further close-only entry");
    }

    /// Exactly one `topic` settle event and no `otherTopic` one since `recordLogs`.
    function _assertSettleEvent(
        bytes32 topic,
        bytes32 otherTopic,
        uint256 batchId,
        bytes32 prev,
        bytes32 next,
        bytes32 manifest
    ) internal {
        VmLogs.Log[] memory logs = vmLogs.getRecordedLogs();
        (uint256 n, uint256 at) = _find(logs, address(s), topic);
        assertEq(n, 1, "one settle event");
        assertEq(logs[at].topics[1], bytes32(batchId), "indexed batch id");
        assertEq(keccak256(logs[at].data), keccak256(abi.encode(prev, next, manifest)), "settle event data");
        (n,) = _find(logs, address(s), otherTopic);
        assertEq(n, 0, "no settle event of the other kind");
    }

    function _assertBatch(uint256 id, bytes32 manifest, bytes32 ordered, bytes32 rejected) internal view {
        (bytes32 m, bytes32 o, bytes32 r, uint256 at) = s.batches(id);
        assertEq(m, manifest, "batch manifest");
        assertEq(o, ordered, "batch ordered root");
        assertEq(r, rejected, "batch rejected root");
        assertEq(at, block.number, "batch settle block");
    }

    function _assertConfig(DarkPerpSettlement d, DarkPerpSettlement.Config memory c) internal view {
        assertEq(d.sequencer(), c.sequencer, "sequencer");
        assertEq(d.enclaveSigner(), c.enclaveSigner, "enclave signer");
        assertEq(address(d.verifier()), address(c.verifier), "verifier");
        assertEq(d.livenessTimeoutBlocks(), c.livenessTimeoutBlocks, "liveness");
        assertEq(d.challengeGraceBlocks(), c.challengeGraceBlocks, "challenge grace");
        assertEq(d.challengeBond(), c.challengeBond, "challenge bond");
        assertEq(d.inclusionDeadlineSecs(), c.inclusionDeadlineSecs, "inclusion deadline");
        assertEq(d.governance(), c.governance, "governance");
        assertEq(d.finalSettleGraceBlocks(), c.finalSettleGraceBlocks, "final-settle grace");
        assertEq(d.progressBatches(), c.progressBatches, "progress batches");
        assertEq(d.slashPayoutCap(), c.slashPayoutCap, "slash payout cap");
    }

    function _create(bytes memory init) internal returns (address d) {
        assembly {
            d := create(0, add(init, 0x20), mload(init))
        }
        assertTrue(d != address(0), "raw creation succeeded");
    }

    function _one(bytes32 a) internal pure returns (bytes32[] memory l) {
        l = new bytes32[](1);
        l[0] = a;
    }

    function _list(bytes32 a, bytes32 b) internal pure returns (bytes32[] memory l) {
        l = new bytes32[](2);
        (l[0], l[1]) = (a, b);
    }

    function _list(bytes32 a, bytes32 b, bytes32 c) internal pure returns (bytes32[] memory l) {
        l = new bytes32[](3);
        (l[0], l[1], l[2]) = (a, b, c);
    }

    function _list(bytes32 a, bytes32 b, bytes32 c, bytes32 d) internal pure returns (bytes32[] memory l) {
        l = new bytes32[](4);
        (l[0], l[1], l[2], l[3]) = (a, b, c, d);
    }

    function _assertPage(uint256 start, uint256 max, bytes32[] memory want) internal view {
        bytes32[] memory got = s.openChallenges(start, max);
        assertEq(got.length, want.length, "open page length");
        for (uint256 i = 0; i < want.length; i++) {
            assertEq(got[i], want[i], "open page entry");
        }
        assertEq(s.openChallengeCount(), s.openChallenges(0, 512).length, "count matches the full page");
    }

    /// The settlement holds exactly the stakes it owes: credited refunds plus open stakes.
    function _assertStakeAccounting(address a, address b) internal view {
        uint256 owed =
            s.pendingEth(a) + s.pendingEth(b) + s.pendingEth(address(this)) + s.openChallengeCount() * CHALLENGE_BOND;
        assertEq(address(s).balance, owed, "ETH held equals pending refunds plus open stakes");
    }

    // --- construction -----------------------------------------------------------

    function test_constructor_wires_the_config() public {
        vm.roll(77);
        DarkPerpSettlement.Config memory c = _cfg();
        c.governance = address(0x6007);
        c.livenessTimeoutBlocks = 123;
        c.challengeGraceBlocks = 45;
        c.challengeBond = 7;
        c.inclusionDeadlineSecs = 89;
        c.finalSettleGraceBlocks = 11;
        c.progressBatches = 3;
        c.slashPayoutCap = 5 * USD;
        DarkPerpSettlement d = new DarkPerpSettlement(c);
        _assertConfig(d, c);
        assertEq(d.currentStateRoot(), GENESIS, "genesis root");
        assertEq(d.lastProgressBlock(), 77, "the progress clock starts at deployment");
        assertEq(d.batchCount(), 0, "no batch");
        assertEq(d.vault(), address(0), "no vault until paired");
        assertFalse(d.closeOnly(), "live");
        assertEq(d.closeOnlyBlock(), 0, "no close-only block");
        assertEq(uint256(d.consumedDepositCount()), 0, "nothing consumed");
        assertEq(d.closeOnlyBatchCount(), 0, "no close-only batch count");
        assertEq(d.slashCount(), 0, "no slash");
        assertEq(d.sequencerBond(), 0, "no bond");
        assertEq(d.openChallengeCount(), 0, "no open challenge");
    }

    /// The Config tuple is static, so the constructor arguments are exactly twelve flat
    /// words in field order, and a raw deployment from those words is equivalent.
    function test_config_is_twelve_flat_constructor_words() public {
        DarkPerpSettlement.Config memory c = _cfg();
        c.genesisRoot = keccak256("genesis");
        c.livenessTimeoutBlocks = 201;
        c.challengeGraceBlocks = 202;
        c.challengeBond = 203;
        c.inclusionDeadlineSecs = 204;
        c.governance = address(0x6007);
        c.finalSettleGraceBlocks = 205;
        c.progressBatches = 6;
        c.slashPayoutCap = 207;
        bytes memory flat = bytes.concat(
            abi.encode(
                c.sequencer,
                c.enclaveSigner,
                address(c.verifier),
                c.genesisRoot,
                c.livenessTimeoutBlocks,
                c.challengeGraceBlocks
            ),
            abi.encode(
                c.challengeBond,
                c.inclusionDeadlineSecs,
                c.governance,
                c.finalSettleGraceBlocks,
                c.progressBatches,
                c.slashPayoutCap
            )
        );
        assertEq(flat.length, 12 * 32, "twelve words");
        assertEq(keccak256(SettlementTestConfig.encode(c)), keccak256(flat), "the struct encodes as the flat words");

        DarkPerpSettlement d = DarkPerpSettlement(_create(bytes.concat(type(DarkPerpSettlement).creationCode, flat)));
        _assertConfig(d, c);
        assertEq(d.currentStateRoot(), c.genesisRoot, "genesis root from word 4");
    }

    function test_constructor_refuses_invalid_config() public {
        DarkPerpSettlement.Config memory c = _cfg();
        c.sequencer = address(0);
        _expectInvalidConfig(c);
        c = _cfg();
        c.enclaveSigner = address(0);
        _expectInvalidConfig(c);
        c = _cfg();
        c.governance = address(0);
        _expectInvalidConfig(c);
        c = _cfg();
        c.verifier = IZkVerifier(address(0));
        _expectInvalidConfig(c);
        c = _cfg();
        c.verifier = IZkVerifier(address(0xC0DE)); // no code
        _expectInvalidConfig(c);
        c = _cfg();
        c.livenessTimeoutBlocks = 0;
        _expectInvalidConfig(c);
        c = _cfg();
        c.challengeGraceBlocks = 0;
        _expectInvalidConfig(c);
        c = _cfg();
        c.progressBatches = 0;
        _expectInvalidConfig(c);
        c = _cfg();
        c.progressBatches = 17;
        _expectInvalidConfig(c);
        c = _cfg();
        c.slashPayoutCap = 0;
        _expectInvalidConfig(c);
        c = _cfg();
        c.slashPayoutCap = uint256(type(uint128).max) + 1;
        _expectInvalidConfig(c);
    }

    function test_constructor_accepts_boundary_config() public {
        DarkPerpSettlement.Config memory c = _cfg();
        c.genesisRoot = bytes32(0);
        c.livenessTimeoutBlocks = 1;
        c.challengeGraceBlocks = 1;
        c.challengeBond = 0;
        c.inclusionDeadlineSecs = 0;
        c.finalSettleGraceBlocks = 0;
        c.progressBatches = 1;
        c.slashPayoutCap = 1;
        _assertConfig(new DarkPerpSettlement(c), c);
        c.progressBatches = 16;
        c.slashPayoutCap = type(uint128).max;
        _assertConfig(new DarkPerpSettlement(c), c);
    }

    /// Only a clock-shaped verifier may be wired: a bare proof verifier lacks the
    /// clock binding.
    function test_constructor_refuses_a_bare_proof_verifier() public {
        DarkPerpSettlement.Config memory c = _cfg();
        c.verifier = new MockZkVerifier();
        _expectInvalidConfig(c);
        c.verifier = new SP1ZkVerifier(ISP1Verifier(address(new MockSP1Verifier())), keccak256("vkey"));
        _expectInvalidConfig(c);
    }

    function test_constructor_refuses_a_verifier_with_the_wrong_shape() public {
        MockClockVerifier v = new MockClockVerifier();
        DarkPerpSettlement.Config memory c = _cfg();
        c.verifier = v;
        v.setShape(1, address(0));
        _expectInvalidConfig(c);
        v.setShape(3, address(0));
        _expectInvalidConfig(c);
        v.setShape(2, address(0xB0B)); // already bound to some settlement
        _expectInvalidConfig(c);
        v.setShape(2, address(0));
        assertEq(address(new DarkPerpSettlement(c).verifier()), address(v), "a fresh clock shape is accepted");
    }

    /// The shape probes must each return exactly one word; a wider answer, an empty
    /// answer or a missing getter is refused.
    function test_constructor_shape_probe_needs_exactly_one_word() public {
        DarkPerpSettlement.Config memory c = _cfg();
        c.verifier = IZkVerifier(address(new WideShapeProbe()));
        _expectInvalidConfig(c);
        c.verifier = IZkVerifier(address(new SilentShapeProbe()));
        _expectInvalidConfig(c);
        c.verifier = IZkVerifier(address(new VersionOnlyProbe()));
        _expectInvalidConfig(c);
    }

    function test_constructor_takes_only_an_unbound_clock_verifier() public {
        ClockBoundVerifier clock = new ClockBoundVerifier(new MockZkVerifier(), 30_000, 30_000, 3_600_000);
        DarkPerpSettlement.Config memory c = _cfg();
        c.verifier = clock;
        DarkPerpSettlement first = new DarkPerpSettlement(c);
        clock.bindSettlement(IClockSettlement(address(first)));
        assertEq(address(clock.settlement()), address(first), "clock bound to the first settlement");
        _expectInvalidConfig(c);
    }

    // --- ABI surface --------------------------------------------------------------

    function test_abi_version_and_constants() public view {
        assertEq(s.ABI_VERSION(), 3, "ABI version");
        assertEq(s.CHALLENGE_AUTH_TAG(), keccak256("arcora:l1-inclusion-challenge:v1"), "challenge auth tag preimage");
        assertEq(
            s.CHALLENGE_AUTH_TAG(),
            0x69f32c88aac1254085ee4ba164b69f2f12fb02828e83d559eff228842bdcc42a,
            "challenge auth tag value"
        );
        assertEq(s.BOND_BPS(), 500, "bond basis points");
    }

    /// Pins the nine-parameter signature the off-chain callers hard-code (the gateway's
    /// `SETTLE_BATCH_SIG` in `crates/gateway/src/l1.rs` and the runbooks' `cast send`
    /// lines) to the COMPILED selector. This is the check that breaks when the Solidity
    /// arity changes.
    function test_settleBatch_selector_matches_nine_param_signature() public pure {
        assertEq(
            bytes32(
                bytes4(keccak256("settleBatch(bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,uint64,bytes)"))
            ),
            bytes32(DarkPerpSettlement.settleBatch.selector),
            "nine-parameter settleBatch signature must hash to the compiled selector"
        );
    }

    function test_wind_down_selectors_keep_nine_params() public pure {
        assertEq(
            bytes32(
                bytes4(keccak256("finalSettle(bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,uint64,bytes)"))
            ),
            bytes32(DarkPerpSettlement.finalSettle.selector),
            "finalSettle signature"
        );
        assertEq(
            bytes32(
                bytes4(keccak256("finalExit(bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,uint64,bytes)"))
            ),
            bytes32(DarkPerpSettlement.finalExit.selector),
            "finalExit signature"
        );
    }

    function _sel(bytes4 compiled, bytes4 expected, string memory what) internal pure {
        assertEq(bytes32(compiled), bytes32(expected), what);
    }

    /// The selectors the gateway, tools and frontend encode by hand.
    function test_external_selectors_match_published_values() public view {
        _sel(s.settleBatch.selector, 0xf92fc4d4, "settleBatch");
        _sel(s.finalSettle.selector, 0xd74f1bd3, "finalSettle");
        _sel(s.finalExit.selector, 0x98f16b08, "finalExit");
        _sel(s.challengeInclusion.selector, 0x7422b0ea, "challengeInclusion");
        _sel(s.answerChallenge.selector, 0xa5f06b0e, "answerChallenge");
        _sel(s.answerByRejection.selector, 0x48c01f1f, "answerByRejection");
        _sel(s.answerChallenges.selector, 0x81913954, "answerChallenges");
        _sel(s.slashUnanswered.selector, 0xb7bea4ba, "slashUnanswered");
        _sel(s.releaseStaleChallenge.selector, 0x7674bee2, "releaseStaleChallenge");
        _sel(s.openChallengeCount.selector, 0x6f443c06, "openChallengeCount");
        _sel(s.openChallenges.selector, 0x555fa4f8, "openChallenges");
        _sel(s.challengeAuthDigest.selector, 0x441859ad, "challengeAuthDigest");
        _sel(s.depositGate.selector, 0x7404d348, "depositGate");
        _sel(s.depositCapacity.selector, 0xf35ce643, "depositCapacity");
        _sel(s.acceptingDeposits.selector, 0xdf334093, "acceptingDeposits");
        _sel(s.consumedDepositCount.selector, 0xbefd565d, "consumedDepositCount");
        _sel(s.closeOnlyBatchCount.selector, 0x222b486a, "closeOnlyBatchCount");
        _sel(s.slashCount.selector, 0x4d21497f, "slashCount");
        _sel(s.challengeResolved.selector, 0x7a13c668, "challengeResolved");
        _sel(s.triggerCloseOnly.selector, 0xa6f5545a, "triggerCloseOnly");
        _sel(s.enterCloseOnly.selector, 0xae0f2ffc, "enterCloseOnly");
        _sel(s.ABI_VERSION.selector, 0xf6b45cfd, "ABI_VERSION");
        _sel(s.challengeGraceBlocks.selector, 0x48fda272, "challengeGraceBlocks");
        _sel(s.progressBatches.selector, 0xe17a6484, "progressBatches");
        _sel(s.slashPayoutCap.selector, 0xf2a452c3, "slashPayoutCap");
        _sel(s.challenges.selector, 0xc1e69b66, "challenges");
        _sel(s.claimEth.selector, 0xb7cdddcb, "claimEth");
        _sel(s.claimEthTo.selector, 0xc1f631b9, "claimEthTo");
        _sel(s.claimUsdc.selector, 0x1d6ee8eb, "claimUsdc");
        _sel(s.claimUsdcTo.selector, 0x563fc441, "claimUsdcTo");
    }

    function test_removed_getters_are_gone() public view {
        (bool ok,) = address(s).staticcall(abi.encodeWithSignature("slashed()"));
        assertFalse(ok, "no slashed latch");
        (ok,) = address(s).staticcall(abi.encodeWithSignature("challengeWindowBlocks()"));
        assertFalse(ok, "no fixed challenge window");
    }

    function test_event_topics_match_published_values() public pure {
        assertEq(
            CLOSE_ONLY_TOPIC, 0x39b3b40109fead2bcf41a503c62bde8b5486e20c4da2625b2192a2a02cfafda9, "CloseOnlyEntered"
        );
        assertEq(
            CHALLENGED_TOPIC, 0x16a25995582a5d2e093efeec773455d64ba9532b4523ad1036ccf5ed3c9add0d, "InclusionChallenged"
        );
        assertEq(SLASHED_TOPIC, 0xc6dd54b9cdbc0cda7d9ccd0b3c9e52a02201dea770fa3d60de4645b82088f020, "SequencerSlashed");
        assertEq(
            RELEASED_TOPIC, 0xb09980ff5485c8f5bd046c26c9882bca2e511046120072571e5e0b3f9cdd0a35, "ChallengeReleased"
        );
        assertEq(
            DarkPerpSettlement.EthClaimed.selector,
            0x7ff4d77aecf45462926207630311e60a136b3e2736108f1229867226c20a90fc,
            "EthClaimed(account, to, amount)"
        );
        assertEq(
            DarkPerpSettlement.UsdcClaimed.selector,
            0x9fadbf0bb9aad4aa6923467bf8df4d74e07b62e1ff17d8997fed5fbdee608df2,
            "UsdcClaimed(account, to, amount)"
        );
    }

    function test_challenge_event_names_the_beneficiary_and_the_staker() public {
        bytes32 h = keccak256("evented");
        _keepalive();
        vmLogs.recordLogs();
        _openChallenge(h, BENEFICIARY, SUBMITTER);
        VmLogs.Log[] memory logs = vmLogs.getRecordedLogs();
        (uint256 n, uint256 at) = _find(logs, address(s), CHALLENGED_TOPIC);
        assertEq(n, 1, "one challenge event");
        assertEq(logs[at].topics[1], h, "indexed order hash");
        assertEq(logs[at].topics[2], bytes32(uint256(uint160(BENEFICIARY))), "indexed beneficiary");
        assertEq(keccak256(logs[at].data), keccak256(abi.encode(SUBMITTER, uint256(1))), "staker and open batch count");
    }

    function test_challenges_getter_keeps_six_words() public {
        bytes32 h = keccak256("six-words");
        _keepalive();
        vm.roll(block.number + 3);
        bytes memory sig = SettlementTestConfig.challengeSig(vm, ENCLAVE_PK, s, h, 4, RECV_MS, 9, BENEFICIARY);
        vm.deal(SUBMITTER, CHALLENGE_BOND);
        _ripen();
        vm.prank(SUBMITTER);
        s.challengeInclusion{value: CHALLENGE_BOND}(h, 4, RECV_MS, 9, BENEFICIARY, sig);

        (bool ok, bytes memory ret) = address(s).staticcall(abi.encodeWithSelector(s.challenges.selector, h));
        assertTrue(ok, "getter call");
        assertEq(ret.length, 6 * 32, "six ABI words");
        (address beneficiary, uint64 hint, uint256 openedBlock, uint256 openBatchCount, uint256 stake, bool open) =
            abi.decode(ret, (address, uint64, uint256, uint256, uint256, bool));
        assertEq(beneficiary, BENEFICIARY, "word 0: beneficiary");
        assertEq(uint256(hint), 9, "word 1: batch id hint");
        assertEq(openedBlock, block.number, "word 2: opened block");
        assertEq(openBatchCount, 1, "word 3: open batch count");
        assertEq(stake, CHALLENGE_BOND, "word 4: stake");
        assertTrue(open, "word 5: open");
    }

    // --- vault pairing --------------------------------------------------------------

    function test_local_s4_non_sequencer_cannot_configure_bond_or_settle() public {
        vm.startPrank(OUTSIDER);
        vm.expectRevert(DarkPerpSettlement.NotSequencer.selector);
        s.setVault(address(vault));
        vm.expectRevert(DarkPerpSettlement.NotSequencer.selector);
        s.postBond(0);
        vm.expectRevert(DarkPerpSettlement.NotSequencer.selector);
        s.withdrawBond(0);
        vm.expectRevert(DarkPerpSettlement.NotSequencer.selector);
        s.settleBatch(
            GENESIS, bytes32(0), bytes32(uint256(2)), bytes32(0), bytes32(0), bytes32(0), bytes32(0), 0, hex""
        );
        vm.expectRevert(DarkPerpSettlement.NotGovernance.selector);
        s.enterCloseOnly();
        vm.expectRevert(DarkPerpSettlement.NotGovernance.selector);
        s.finalSettle(
            GENESIS, bytes32(0), bytes32(uint256(2)), bytes32(0), bytes32(0), bytes32(0), bytes32(0), 0, hex""
        );
        vm.expectRevert(DarkPerpSettlement.NotGovernance.selector);
        s.finalExit(GENESIS, bytes32(0), bytes32(uint256(2)), bytes32(0), bytes32(0), bytes32(0), bytes32(0), 0, hex"");
        vm.stopPrank();
        assertEq(s.currentStateRoot(), GENESIS, "unauthorized calls preserve root");
        assertEq(s.batchCount(), 0, "unauthorized calls preserve batch identity");
        assertEq(s.sequencerBond(), 0, "unauthorized calls preserve bond");
        assertFalse(s.closeOnly(), "unauthorized calls preserve the live mode");
    }

    function test_setVault_requires_a_vault_naming_this_settlement() public {
        DarkPerpSettlement d = new DarkPerpSettlement(_cfg());
        vm.expectRevert(DarkPerpSettlement.VaultMismatch.selector);
        d.setVault(address(0xE0A)); // an EOA
        vm.expectRevert(DarkPerpSettlement.VaultMismatch.selector);
        d.setVault(address(0));
        vm.expectRevert(DarkPerpSettlement.VaultMismatch.selector);
        d.setVault(address(vault)); // a vault that names another settlement
        vm.expectRevert(DarkPerpSettlement.VaultMismatch.selector);
        d.setVault(address(usdc)); // a contract with no settlement() getter
        assertEq(d.vault(), address(0), "still unpaired");

        CollateralVault own = new CollateralVault(address(d), address(usdc), vm.addr(GW_PK));
        d.setVault(address(own));
        assertEq(d.vault(), address(own), "paired with its own vault");

        // once only, whatever the candidate
        CollateralVault second = new CollateralVault(address(d), address(usdc), vm.addr(GW_PK));
        vm.expectRevert(bytes("vault set"));
        d.setVault(address(second));
        vm.expectRevert(bytes("vault set"));
        d.setVault(address(0xE0A));
        assertEq(d.vault(), address(own), "pairing unchanged");
    }

    function test_unpaired_settlement_keeps_its_vault_closed() public {
        DarkPerpSettlement d = new DarkPerpSettlement(_cfg());
        CollateralVault v = new CollateralVault(address(d), address(usdc), vm.addr(GW_PK));
        assertFalse(d.acceptingDeposits(), "no deposits without a vault");
        assertEq(d.requiredBond(), 0, "no bond floor without a vault");
        assertEq(d.depositCapacity(), 0, "no capacity without a vault");
        vm.prank(address(v));
        assertEq(uint256(d.depositGate(1)), 3, "a vault the settlement has not paired is unpaired");

        bytes32 commit = keccak256("unpaired-commit");
        uint64 validUntil = uint64(block.timestamp + PERMIT_TTL);
        bytes memory sig = SettlementTestConfig.permitSig(vm, GW_PK, v, address(this), commit, USD, validUntil);
        usdc.mint(address(this), USD);
        usdc.approve(address(v), USD);
        vm.expectRevert(CollateralVault.DepositsPaused.selector);
        v.deposit(USD, commit, validUntil, sig);
        vm.expectRevert(DarkPerpSettlement.VaultNotSet.selector);
        d.postBond(0);

        d.setVault(address(v));
        assertTrue(d.acceptingDeposits(), "a paired vault accepts deposits");
    }

    // --- deposit gate and capacity ----------------------------------------------------

    function test_depositGate_answers_the_paired_vault_only() public {
        _bond(100 * USD);
        assertEq(uint256(s.depositGate(0)), 3, "a caller other than the vault is unpaired");
        vm.prank(address(vault));
        assertEq(uint256(s.depositGate(2_000_000_019)), 0, "the bond covers this TVL");
        vm.prank(address(vault));
        assertEq(uint256(s.depositGate(2_000_000_020)), 2, "one unit more is over capacity");
        assertEq(s.depositCapacity(), 2_000_000_019, "capacity of a 100 USDC bond");

        s.enterCloseOnly();
        vm.prank(address(vault));
        assertEq(uint256(s.depositGate(1)), 1, "close-only");
        assertEq(uint256(s.depositGate(1)), 3, "the pairing is checked before close-only");
        assertFalse(s.acceptingDeposits(), "close-only accepts no deposits");
    }

    function test_depositCapacity_follows_bond_and_tvl() public {
        assertEq(s.depositCapacity(), 19, "a zero bond admits only what rounds to a zero floor");
        _bond(100 * USD);
        _depositToVault(1_000 * USD);
        assertEq(s.sequencerBond(), 100 * USD, "no top-up needed");
        assertEq(s.requiredBond(), 50 * USD, "five percent of the TVL");
        assertEq(s.depositCapacity(), 2_000_000_019 - 1_000 * USD, "capacity shrinks by the TVL");
        assertTrue(s.acceptingDeposits(), "live and paired");
    }

    // --- settlement and the deposit pin ----------------------------------------------

    /// Lands a zero-prefix settle: no deposit exists, so the genesis tip and count 0.
    function test_settle_advances_root() public {
        bytes32 newRoot = bytes32(uint256(2));
        bytes32 manifest = keccak256("m0");
        vm.roll(block.number + 5);
        _settle(GENESIS, manifest, newRoot, bytes32(0), bytes32(0), bytes32(0));
        assertEq(s.currentStateRoot(), newRoot, "root advanced");
        assertEq(s.batchCount(), 1, "batch counted");
        assertEq(s.lastProgressBlock(), block.number, "progress recorded");
        assertEq(uint256(s.consumedDepositCount()), 0, "zero prefix consumed");
    }

    function test_settle_binds_withdrawals_root() public {
        // a proof valid for one withdrawalsRoot must NOT settle with a different one:
        // the roots are part of the commitment.
        bytes32 newRoot = bytes32(uint256(2));
        bytes32 manifest = keccak256("m");
        (bytes32 dTip, uint64 dCount) = _head();
        bytes memory proof = abi.encode(
            s.publicCommitment(GENESIS, manifest, newRoot, bytes32(0), keccak256("authorized"), bytes32(0), dTip)
        );
        vm.expectRevert(DarkPerpSettlement.BadProof.selector);
        s.settleBatch(GENESIS, manifest, newRoot, bytes32(0), keccak256("substituted"), bytes32(0), dTip, dCount, proof);
        s.settleBatch(GENESIS, manifest, newRoot, bytes32(0), keccak256("authorized"), bytes32(0), dTip, dCount, proof);
        assertEq(s.currentStateRoot(), newRoot, "settled with bound withdrawals root");
    }

    function test_settle_rejects_bad_prev_root() public {
        bytes32 wrongPrev = bytes32(uint256(99));
        bytes32 newRoot = bytes32(uint256(2));
        bytes32 manifest = keccak256("m");
        (bytes32 dTip, uint64 dCount) = _head();
        bytes memory proof =
            abi.encode(s.publicCommitment(wrongPrev, manifest, newRoot, bytes32(0), bytes32(0), bytes32(0), dTip));
        vm.expectRevert(DarkPerpSettlement.BadPrevRoot.selector);
        s.settleBatch(wrongPrev, manifest, newRoot, bytes32(0), bytes32(0), bytes32(0), dTip, dCount, proof);
    }

    function test_settle_rejects_bad_proof() public {
        verifier.setForceReject(true);
        bytes32 newRoot = bytes32(uint256(2));
        bytes32 manifest = keccak256("m");
        (bytes32 dTip, uint64 dCount) = _head();
        bytes memory proof =
            abi.encode(s.publicCommitment(GENESIS, manifest, newRoot, bytes32(0), bytes32(0), bytes32(0), dTip));
        vm.expectRevert(DarkPerpSettlement.BadProof.selector);
        s.settleBatch(GENESIS, manifest, newRoot, bytes32(0), bytes32(0), bytes32(0), dTip, dCount, proof);
    }

    function test_settle_check_order() public {
        _depositToVault(1_000 * USD);
        (bytes32 tip, uint64 n) = _head();
        bytes32 next = bytes32(uint256(2));
        bytes32 junk = keccak256("junk");
        bytes memory good =
            abi.encode(s.publicCommitment(GENESIS, bytes32(0), next, bytes32(0), bytes32(0), bytes32(0), tip));
        // prev root before the deposit pin
        vm.expectRevert(DarkPerpSettlement.BadPrevRoot.selector);
        s.settleBatch(bytes32(uint256(9)), bytes32(0), next, bytes32(0), bytes32(0), bytes32(0), junk, n + 5, hex"");
        // the count before the root
        vm.expectRevert(DarkPerpSettlement.BadDepositCount.selector);
        s.settleBatch(GENESIS, bytes32(0), next, bytes32(0), bytes32(0), bytes32(0), junk, n + 1, hex"");
        // the root before the proof
        vm.expectRevert(_pinError());
        s.settleBatch(GENESIS, bytes32(0), next, bytes32(0), bytes32(0), bytes32(0), junk, n, hex"");
        // a pinned batch still needs its proof
        vm.expectRevert(DarkPerpSettlement.BadProof.selector);
        s.settleBatch(GENESIS, bytes32(0), next, bytes32(0), bytes32(0), bytes32(0), tip, n, hex"");
        s.settleBatch(GENESIS, bytes32(0), next, bytes32(0), bytes32(0), bytes32(0), tip, n, good);
        // close-only is checked before everything else
        s.enterCloseOnly();
        vm.expectRevert(DarkPerpSettlement.InCloseOnly.selector);
        s.settleBatch(bytes32(uint256(9)), bytes32(0), next, bytes32(0), bytes32(0), bytes32(0), junk, n + 5, hex"");
    }

    function test_settle_blocked_in_close_only() public {
        _enterCloseOnlyViaLiveness();
        bytes32 prev = s.currentStateRoot();
        bytes32 newRoot = bytes32(uint256(2));
        bytes32 manifest = keccak256("m");
        (bytes32 dTip, uint64 dCount) = _head();
        bytes memory proof =
            abi.encode(s.publicCommitment(prev, manifest, newRoot, bytes32(0), bytes32(0), bytes32(0), dTip));
        vm.expectRevert(DarkPerpSettlement.InCloseOnly.selector);
        s.settleBatch(prev, manifest, newRoot, bytes32(0), bytes32(0), bytes32(0), dTip, dCount, proof);
    }

    /// Known-answer vector shared byte-for-byte with `crates/prover/tests/vectors.rs`
    /// (`public_commitment_vector`): the seven-word commitment over prev=0x01..,
    /// manifest=0x02.., new=0x03.., ordered=0x04.., withdrawals=0x05.., rejected=0x06..,
    /// deposits=0x07.. — `depositsRoot` appended last.
    bytes32 internal constant KAT_COMMIT7 = 0x27e3e52688359d5759ff4c7b0bea4d25a14b3c81652a4083d531592f827d8902;

    function test_public_commitment_7word_matches_rust() public view {
        bytes32 c = s.publicCommitment(
            bytes32(uint256(0x0101010101010101010101010101010101010101010101010101010101010101)),
            bytes32(uint256(0x0202020202020202020202020202020202020202020202020202020202020202)),
            bytes32(uint256(0x0303030303030303030303030303030303030303030303030303030303030303)),
            bytes32(uint256(0x0404040404040404040404040404040404040404040404040404040404040404)),
            bytes32(uint256(0x0505050505050505050505050505050505050505050505050505050505050505)),
            bytes32(uint256(0x0606060606060606060606060606060606060606060606060606060606060606)),
            bytes32(uint256(0x0707070707070707070707070707070707070707070707070707070707070707))
        );
        assertEq(c, KAT_COMMIT7, "7-word public commitment must match crates/prover::PublicInputs::commitment");
    }

    /// A batch may only credit deposits that happened on L1. The proof below is valid
    /// for a fabricated deposit chain (the mock verifier accepts it), so only the pin to
    /// the vault's chain stops it.
    function test_settle_reverts_on_deposit_root_mismatch() public {
        _depositToVault(1000 * USD);

        bytes32 fabricatedTip = keccak256("deposit-that-never-happened");
        uint64 count = vault.depositCount();
        bytes32 newRoot = bytes32(uint256(2));
        bytes32 manifest = keccak256("m");
        bytes memory proof = abi.encode(
            s.publicCommitment(GENESIS, manifest, newRoot, bytes32(0), bytes32(0), bytes32(0), fabricatedTip)
        );

        vm.expectRevert(_pinError());
        s.settleBatch(GENESIS, manifest, newRoot, bytes32(0), bytes32(0), bytes32(0), fabricatedTip, count, proof);
        assertEq(s.currentStateRoot(), GENESIS, "fabricated deposit chain never advances the root");
        assertEq(s.batchCount(), 0, "no batch settled");
    }

    /// The pin is (count, tip) as a pair: a real tip against the wrong count is refused.
    function test_settle_reverts_on_wrong_prefix_root() public {
        _depositToVault(1000 * USD);
        _depositToVault(500 * USD);

        bytes32 headTip = vault.depositChainTip();
        assertEq(uint256(vault.depositCount()), 2, "two deposits landed on L1");

        bytes32 newRoot = bytes32(uint256(2));
        bytes32 manifest = keccak256("m");
        bytes memory proof =
            abi.encode(s.publicCommitment(GENESIS, manifest, newRoot, bytes32(0), bytes32(0), bytes32(0), headTip));

        vm.expectRevert(_pinError());
        s.settleBatch(GENESIS, manifest, newRoot, bytes32(0), bytes32(0), bytes32(0), headTip, 1, proof);
        assertEq(s.batchCount(), 0, "no batch settled on a mismatched prefix");
        assertEq(s.currentStateRoot(), GENESIS, "root untouched");
    }

    /// A batch proven over prefix N settles even though the vault head has moved past N:
    /// deposits landing in flight simply belong to a later batch.
    function test_settle_accepts_a_proven_prefix_while_head_moved() public {
        _depositToVault(1000 * USD);
        bytes32 prefixTip = vault.depositChainTip();
        uint64 prefixCount = vault.depositCount();

        _depositToVault(500 * USD);
        assertEq(uint256(vault.depositCount()), 2, "head advanced past the proven prefix");
        assertTrue(vault.depositChainTip() != prefixTip, "head tip now differs from the proven prefix");

        bytes32 newRoot = bytes32(uint256(2));
        bytes32 manifest = keccak256("m");
        bytes memory proof =
            abi.encode(s.publicCommitment(GENESIS, manifest, newRoot, bytes32(0), bytes32(0), bytes32(0), prefixTip));

        s.settleBatch(GENESIS, manifest, newRoot, bytes32(0), bytes32(0), bytes32(0), prefixTip, prefixCount, proof);
        assertEq(s.currentStateRoot(), newRoot, "a proven prefix settles even after the head moved");
        assertEq(s.batchCount(), 1, "batch counted");
        assertEq(uint256(s.consumedDepositCount()), 1, "only the proven prefix is consumed");
    }

    function _expectZeroDepositRefused(address from) internal {
        (bytes32 commit, uint64 validUntil, bytes memory sig) = _permit(from, 0);
        vm.prank(from);
        vm.expectRevert(CollateralVault.BadAmount.selector);
        vault.deposit(0, commit, validUntil, sig);
    }

    /// A zero-amount deposit is refused outright, and the smallest accepted deposit
    /// landing between proof build and settle does not stall the in-flight settle.
    function test_zero_value_deposit_cannot_stall_settlement() public {
        _depositToVault(1000 * USD);

        bytes32 prefixTip = vault.depositChainTip();
        uint64 prefixCount = vault.depositCount();
        bytes32 newRoot = bytes32(uint256(2));
        bytes32 manifest = keccak256("m");
        bytes memory proof =
            abi.encode(s.publicCommitment(GENESIS, manifest, newRoot, bytes32(0), bytes32(0), bytes32(0), prefixTip));

        address latecomer = address(0x6217EF);
        _expectZeroDepositRefused(latecomer);
        assertEq(uint256(vault.depositCount()), uint256(prefixCount), "a zero deposit never moves the head");

        _depositFrom(latecomer, 1);
        assertEq(uint256(vault.depositCount()), uint256(prefixCount) + 1, "the in-flight deposit advanced the head");

        s.settleBatch(GENESIS, manifest, newRoot, bytes32(0), bytes32(0), bytes32(0), prefixTip, prefixCount, proof);
        assertEq(s.currentStateRoot(), newRoot, "settlement is immune to head-advancing deposits");
        assertEq(s.batchCount(), 1, "batch counted despite the in-flight deposit");
    }

    /// Settling exactly at the L1 head (the longest prefix) lands end-to-end.
    function test_settle_at_l1_deposit_head_succeeds() public {
        _depositToVault(1000 * USD);
        _depositToVault(500 * USD);

        bytes32 tip = vault.depositChainTip();
        uint64 count = vault.depositCount();
        assertTrue(tip != bytes32(0), "chain tip is non-genesis, so the pin is meaningful");
        assertEq(vault.depositTipAt(count), tip, "the head prefix is the chain tip");

        bytes32 newRoot = bytes32(uint256(2));
        bytes32 manifest = keccak256("m");
        bytes memory proof =
            abi.encode(s.publicCommitment(GENESIS, manifest, newRoot, bytes32(0), bytes32(0), bytes32(0), tip));

        s.settleBatch(GENESIS, manifest, newRoot, bytes32(0), bytes32(0), bytes32(0), tip, count, proof);
        assertEq(s.currentStateRoot(), newRoot, "settled at the L1 deposit head");
        assertEq(s.batchCount(), 1, "batch counted");
        assertEq(uint256(s.consumedDepositCount()), 2, "every deposit consumed");
    }

    function test_settle_stores_a_monotonic_consumed_count() public {
        _depositToVault(1_000 * USD);
        _depositToVault(2_000 * USD);
        _depositToVault(3_000 * USD);
        _settleEmptyAt(1);
        assertEq(uint256(s.consumedDepositCount()), 1, "first deposit consumed");
        _settleEmptyAt(1);
        assertEq(uint256(s.consumedDepositCount()), 1, "a batch may credit nothing new");
        _settleEmptyAt(3);
        assertEq(uint256(s.consumedDepositCount()), 3, "the rest consumed");

        bytes32 prev = s.currentStateRoot();
        bytes32 next = keccak256("regress");
        bytes32 tip2 = vault.depositTipAt(2);
        bytes memory proof =
            abi.encode(s.publicCommitment(prev, bytes32("e"), next, bytes32(0), bytes32(0), bytes32(0), tip2));
        vm.expectRevert(DarkPerpSettlement.BadDepositCount.selector);
        s.settleBatch(prev, bytes32("e"), next, bytes32(0), bytes32(0), bytes32(0), tip2, 2, proof);
        assertEq(uint256(s.consumedDepositCount()), 3, "the consumed count never goes back");
    }

    /// `depositTipAt` is zero past the head, which equals the genesis tip, so the count
    /// is bounded by the head independently of the root.
    function test_settle_refuses_a_count_beyond_the_vault_head() public {
        bytes32 next = bytes32(uint256(2));
        bytes memory zeroProof =
            abi.encode(s.publicCommitment(GENESIS, bytes32(0), next, bytes32(0), bytes32(0), bytes32(0), bytes32(0)));
        vm.expectRevert(DarkPerpSettlement.BadDepositCount.selector);
        s.settleBatch(GENESIS, bytes32(0), next, bytes32(0), bytes32(0), bytes32(0), bytes32(0), 1, zeroProof);

        _depositToVault(1_000 * USD);
        _depositToVault(2_000 * USD);
        (bytes32 headTip,) = _head();
        bytes memory headProof =
            abi.encode(s.publicCommitment(GENESIS, bytes32(0), next, bytes32(0), bytes32(0), bytes32(0), headTip));
        vm.expectRevert(DarkPerpSettlement.BadDepositCount.selector);
        s.settleBatch(GENESIS, bytes32(0), next, bytes32(0), bytes32(0), bytes32(0), bytes32(0), 3, zeroProof);
        vm.expectRevert(DarkPerpSettlement.BadDepositCount.selector);
        s.settleBatch(GENESIS, bytes32(0), next, bytes32(0), bytes32(0), bytes32(0), headTip, 3, headProof);
        assertEq(s.batchCount(), 0, "nothing settled past the head");
    }

    function test_settle_without_a_vault_credits_no_deposit() public {
        DarkPerpSettlement d = new DarkPerpSettlement(_cfg());
        bytes32 next = bytes32(uint256(2));
        bytes32 fakeTip = keccak256("deposit-that-never-happened");
        bytes memory zeroProof =
            abi.encode(d.publicCommitment(GENESIS, bytes32(0), next, bytes32(0), bytes32(0), bytes32(0), bytes32(0)));
        bytes memory fakeProof =
            abi.encode(d.publicCommitment(GENESIS, bytes32(0), next, bytes32(0), bytes32(0), bytes32(0), fakeTip));
        vm.expectRevert(DarkPerpSettlement.BadDepositCount.selector);
        d.settleBatch(GENESIS, bytes32(0), next, bytes32(0), bytes32(0), bytes32(0), bytes32(0), 1, zeroProof);
        vm.expectRevert(_pinError());
        d.settleBatch(GENESIS, bytes32(0), next, bytes32(0), bytes32(0), bytes32(0), fakeTip, 0, fakeProof);
        d.settleBatch(GENESIS, bytes32(0), next, bytes32(0), bytes32(0), bytes32(0), bytes32(0), 0, zeroProof);
        assertEq(d.batchCount(), 1, "the zero prefix settles without a vault");
        assertEq(d.currentStateRoot(), next, "root advanced");
        assertEq(uint256(d.consumedDepositCount()), 0, "nothing consumed");
    }

    // --- every settle path records its batch -----------------------------------------

    function test_settleBatch_records_the_batch() public {
        _depositToVault(1_000 * USD);
        bytes32 manifest = keccak256("m-record");
        bytes32 next = keccak256("next-record");
        vm.roll(block.number + 7);
        vmLogs.recordLogs();
        _settle(GENESIS, manifest, next, keccak256("ord"), keccak256("wd"), keccak256("rej"));
        _assertSettleEvent(BATCH_SETTLED_TOPIC, FINAL_SETTLE_TOPIC, 0, GENESIS, next, manifest);
        _assertBatch(0, manifest, keccak256("ord"), keccak256("rej"));
        assertEq(s.currentStateRoot(), next, "root");
        assertEq(s.lastProgressBlock(), block.number, "progress block");
        assertEq(s.batchCount(), 1, "batch count");
        assertEq(uint256(s.consumedDepositCount()), 1, "consumed count");
        assertEq(vault.withdrawalsRoot(), keccak256("wd"), "withdrawals published");
        assertEq(vault.withdrawalsEpoch(), 0, "withdrawals epoch is the batch id");
        assertFalse(s.windDownSettled(), "an ordinary batch is not a wind-down");
    }

    function test_finalSettle_records_the_batch_as_phase_one() public {
        _depositToVault(1_000 * USD);
        _settleEmptyAt(1);
        s.enterCloseOnly();
        vm.roll(block.number + GRACE);
        bytes32 prev = s.currentStateRoot();
        bytes32 next = keccak256("phase-one-root");
        bytes32 tip = vault.depositTipAt(1);
        bytes32 commitment = s.windDownCommitment(
            prev, bytes32("p1"), next, keccak256("ord"), keccak256("wd"), keccak256("rej"), tip, 1
        );
        vmLogs.recordLogs();
        s.finalSettle(
            prev,
            bytes32("p1"),
            next,
            keccak256("ord"),
            keccak256("wd"),
            keccak256("rej"),
            tip,
            1,
            abi.encode(commitment)
        );
        _assertSettleEvent(FINAL_SETTLE_TOPIC, BATCH_SETTLED_TOPIC, 1, prev, next, bytes32("p1"));
        _assertBatch(1, bytes32("p1"), keccak256("ord"), keccak256("rej"));
        assertEq(s.currentStateRoot(), next, "root");
        assertEq(s.lastProgressBlock(), block.number, "progress block");
        assertEq(s.batchCount(), 2, "batch count");
        assertEq(uint256(s.consumedDepositCount()), 1, "consumed count stored unchanged");
        assertEq(vault.withdrawalsRoot(), keccak256("wd"), "withdrawals published");
        assertEq(vault.withdrawalsEpoch(), 1, "withdrawals epoch is the batch id");
        assertTrue(s.windDownSettled(), "phase one latched");
    }

    function test_finalExit_records_the_batch_as_phase_two() public {
        _depositToVault(1_000 * USD);
        _settleEmptyAt(1);
        s.enterCloseOnly();
        vm.roll(block.number + GRACE);
        _windDown(1, 1);
        bytes32 prev = s.currentStateRoot();
        bytes32 next = keccak256("phase-two-root");
        bytes32 tip = vault.depositTipAt(1);
        bytes32 commitment = s.windDownCommitment(
            prev, bytes32("p2"), next, keccak256("ord"), keccak256("wd"), keccak256("rej"), tip, 2
        );
        vm.roll(block.number + 3);
        vmLogs.recordLogs();
        s.finalExit(
            prev,
            bytes32("p2"),
            next,
            keccak256("ord"),
            keccak256("wd"),
            keccak256("rej"),
            tip,
            1,
            abi.encode(commitment)
        );
        _assertSettleEvent(FINAL_SETTLE_TOPIC, BATCH_SETTLED_TOPIC, 2, prev, next, bytes32("p2"));
        _assertBatch(2, bytes32("p2"), keccak256("ord"), keccak256("rej"));
        assertEq(s.currentStateRoot(), next, "root");
        assertEq(s.lastProgressBlock(), block.number, "progress block");
        assertEq(s.batchCount(), 3, "batch count");
        assertEq(uint256(s.consumedDepositCount()), 1, "consumed count stored unchanged");
        assertEq(vault.withdrawalsRoot(), keccak256("wd"), "withdrawals published");
        assertEq(vault.withdrawalsEpoch(), 2, "withdrawals epoch is the batch id");
        assertTrue(s.windDownSettled(), "phase one stays latched");
    }

    // --- the consumed count is frozen in wind-down -------------------------------------

    function test_wind_down_cannot_move_the_consumed_count() public {
        address alice = address(0xA11CE5);
        address bob = address(0xB0B5);
        (uint64 idA, bytes32 commitA) = _depositFrom(alice, 1_000 * USD);
        _settleEmptyAt(1); // credits alice's deposit
        (uint64 idB, bytes32 commitB) = _depositFrom(bob, 2_000 * USD);
        s.enterCloseOnly();
        vm.roll(block.number + GRACE);

        // phase one may neither credit bob's deposit nor un-credit alice's
        _expectWindDownRevert(1, 2, DarkPerpSettlement.DepositsFrozen.selector);
        _expectWindDownRevert(1, 0, DarkPerpSettlement.DepositsFrozen.selector);
        _windDown(1, 1);
        assertEq(uint256(s.consumedDepositCount()), 1, "phase one keeps the count");

        _expectWindDownRevert(2, 2, DarkPerpSettlement.DepositsFrozen.selector);
        _expectWindDownRevert(2, 0, DarkPerpSettlement.DepositsFrozen.selector);
        _windDown(2, 1);
        assertEq(uint256(s.consumedDepositCount()), 1, "phase two keeps the count");

        // the refund boundary never moved: alice was credited, bob is refundable
        vm.expectRevert(CollateralVault.NotRefundable.selector);
        vault.refundDeposit(idA, alice, commitA, 1_000 * USD, alice);
        vm.prank(OUTSIDER);
        vault.refundDeposit(idB, bob, commitB, 2_000 * USD, bob);
        assertEq(usdc.balanceOf(bob), 2_000 * USD, "uncredited principal refunded");
    }

    function test_finalSettle_check_order() public {
        _depositToVault(1_000 * USD);
        _settleEmptyAt(1);
        _depositToVault(1_000 * USD);
        bytes32 bad = bytes32(uint256(9));
        bytes32 junk = keccak256("junk");
        (bytes32 prev, bytes32 next, bytes32 tip, bytes memory proof) = _windDownArgs(1, 1);
        vm.prank(OUTSIDER);
        vm.expectRevert(DarkPerpSettlement.NotGovernance.selector);
        s.finalSettle(prev, bytes32("w"), next, bytes32(0), bytes32(0), bytes32(0), tip, 1, proof);
        vm.expectRevert(DarkPerpSettlement.NotCloseOnly.selector);
        s.finalSettle(prev, bytes32("w"), next, bytes32(0), bytes32(0), bytes32(0), tip, 1, proof);
        s.enterCloseOnly();
        // the grace before any root
        vm.expectRevert(DarkPerpSettlement.GraceNotExpired.selector);
        s.finalSettle(bad, bytes32("w"), next, bytes32(0), bytes32(0), bytes32(0), junk, 2, hex"");
        vm.roll(block.number + GRACE);
        // prev root before the frozen count
        vm.expectRevert(DarkPerpSettlement.BadPrevRoot.selector);
        s.finalSettle(bad, bytes32("w"), next, bytes32(0), bytes32(0), bytes32(0), junk, 2, hex"");
        // the frozen count before the pin
        vm.expectRevert(DarkPerpSettlement.DepositsFrozen.selector);
        s.finalSettle(prev, bytes32("w"), next, bytes32(0), bytes32(0), bytes32(0), junk, 2, hex"");
        // the pin before the proof
        vm.expectRevert(_pinError());
        s.finalSettle(prev, bytes32("w"), next, bytes32(0), bytes32(0), bytes32(0), junk, 1, hex"");
        vm.expectRevert(DarkPerpSettlement.BadProof.selector);
        s.finalSettle(prev, bytes32("w"), next, bytes32(0), bytes32(0), bytes32(0), tip, 1, hex"");
        s.finalSettle(prev, bytes32("w"), next, bytes32(0), bytes32(0), bytes32(0), tip, 1, proof);
        // one-shot, checked before the grace and the roots
        vm.expectRevert(bytes("wind-down already settled"));
        s.finalSettle(bad, bytes32("w"), next, bytes32(0), bytes32(0), bytes32(0), junk, 2, hex"");
    }

    function test_finalExit_check_order() public {
        _depositToVault(1_000 * USD);
        _settleEmptyAt(1);
        _depositToVault(1_000 * USD);
        bytes32 bad = bytes32(uint256(9));
        bytes32 junk = keccak256("junk");
        vm.prank(OUTSIDER);
        vm.expectRevert(DarkPerpSettlement.NotGovernance.selector);
        s.finalExit(bad, bytes32("w"), bad, bytes32(0), bytes32(0), bytes32(0), junk, 2, hex"");
        vm.expectRevert(DarkPerpSettlement.NotCloseOnly.selector);
        s.finalExit(bad, bytes32("w"), bad, bytes32(0), bytes32(0), bytes32(0), junk, 2, hex"");
        s.enterCloseOnly();
        vm.expectRevert(bytes("wind-down not settled"));
        s.finalExit(bad, bytes32("w"), bad, bytes32(0), bytes32(0), bytes32(0), junk, 2, hex"");
        vm.roll(block.number + GRACE);
        _windDown(1, 1);

        (bytes32 prev, bytes32 next, bytes32 tip, bytes memory proof) = _windDownArgs(2, 1);
        vm.expectRevert(DarkPerpSettlement.BadPrevRoot.selector);
        s.finalExit(bad, bytes32("w"), next, bytes32(0), bytes32(0), bytes32(0), junk, 2, hex"");
        vm.expectRevert(DarkPerpSettlement.DepositsFrozen.selector);
        s.finalExit(prev, bytes32("w"), next, bytes32(0), bytes32(0), bytes32(0), junk, 2, hex"");
        vm.expectRevert(_pinError());
        s.finalExit(prev, bytes32("w"), next, bytes32(0), bytes32(0), bytes32(0), junk, 1, hex"");
        vm.expectRevert(DarkPerpSettlement.BadProof.selector);
        s.finalExit(prev, bytes32("w"), next, bytes32(0), bytes32(0), bytes32(0), tip, 1, hex"");
        s.finalExit(prev, bytes32("w"), next, bytes32(0), bytes32(0), bytes32(0), tip, 1, proof);
        assertEq(s.currentStateRoot(), next, "phase two advanced the root");
    }

    // --- close-only: liveness, forced inclusion and governance -------------------------

    function test_liveness_triggers_close_only() public {
        _keepalive();
        uint256 last = s.lastProgressBlock();
        vm.expectRevert(DarkPerpSettlement.LivenessNotExpired.selector);
        s.triggerCloseOnly();
        vm.roll(last + LIVENESS);
        vm.expectRevert(DarkPerpSettlement.LivenessNotExpired.selector);
        s.triggerCloseOnly();
        vm.roll(last + LIVENESS + 1);
        vmLogs.recordLogs();
        vm.prank(OUTSIDER);
        s.triggerCloseOnly();
        _assertCloseOnlyReason(address(s), "liveness timeout");
        assertTrue(s.closeOnly(), "close-only after liveness timeout");
        assertEq(s.closeOnlyBlock(), block.number, "entry block latched");
        assertEq(s.closeOnlyBatchCount(), 1, "entry batch count latched");
    }

    /// A deployment that has settled nothing and holds no deposit and no open challenge
    /// cannot be closed by waiting out the window. The window still runs from the deploy
    /// block, so the first deposit or challenge makes an expired clock triggerable.
    function test_fresh_stack_is_not_closed_before_it_holds_anything() public {
        uint256 deployed = s.lastProgressBlock();
        vm.roll(deployed + 10 * LIVENESS);
        vm.prank(OUTSIDER);
        vm.expectRevert(DarkPerpSettlement.LivenessNotExpired.selector);
        s.triggerCloseOnly();
        assertFalse(s.closeOnly(), "nothing to protect yet");

        _depositToVault(1_000 * USD);
        vmLogs.recordLogs();
        vm.prank(OUTSIDER);
        s.triggerCloseOnly();
        _assertCloseOnlyReason(address(s), "liveness timeout");
        assertEq(s.closeOnlyBatchCount(), 0, "no phase-0 batch");
    }

    function test_open_challenge_alone_lets_an_expired_fresh_stack_close() public {
        bytes32 h = keccak256("order-before-any-batch");
        _openRipeChallenge(h, BENEFICIARY);
        vm.roll(s.lastProgressBlock() + LIVENESS);
        vm.expectRevert(DarkPerpSettlement.LivenessNotExpired.selector);
        s.triggerCloseOnly();
        vm.roll(s.lastProgressBlock() + LIVENESS + 1);
        vmLogs.recordLogs();
        vm.prank(OUTSIDER);
        s.triggerCloseOnly();
        _assertCloseOnlyReason(address(s), "liveness timeout");
        s.releaseStaleChallenge(h);
        assertEq(s.openChallengeCount(), 0, "the stake is released");
    }

    function test_settle_restarts_the_liveness_clock() public {
        vm.roll(block.number + LIVENESS);
        _keepalive();
        uint256 last = block.number;
        assertEq(s.lastProgressBlock(), last, "progress recorded");
        vm.roll(last + LIVENESS);
        vm.expectRevert(DarkPerpSettlement.LivenessNotExpired.selector);
        s.triggerCloseOnly();
        vm.roll(last + LIVENESS + 1);
        s.triggerCloseOnly();
        assertTrue(s.closeOnly(), "close-only once the restarted clock expires");
        assertEq(s.closeOnlyBatchCount(), 1, "entry batch count latched");
    }

    /// An expired liveness clock alone gates nothing: until someone triggers close-only,
    /// a deposit and a settle still land, and the settle restarts the clock.
    function test_expired_liveness_alone_does_not_gate_deposits_or_settles() public {
        vm.roll(block.number + LIVENESS + 1);
        _depositToVault(1_000 * USD);
        _settleEmptyAt(1);
        assertEq(uint256(s.consumedDepositCount()), 1, "late deposit credited");
        vm.expectRevert(DarkPerpSettlement.LivenessNotExpired.selector);
        s.triggerCloseOnly();
    }

    /// A sequencer that keeps settling without consuming the oldest pending deposit
    /// lets anyone enter close-only once that deposit is older than the liveness window,
    /// and the held deposit is then refundable.
    function test_unconsumed_deposit_forces_close_only_after_the_timeout() public {
        address alice = address(0xA11CE5);
        uint256 amount = 10_000 * USD;
        (uint64 id, bytes32 commit) = _depositFrom(alice, amount);
        uint256 landed = block.number;
        assertEq(vault.depositBlock(id), landed, "landing block recorded");

        vm.roll(landed + LIVENESS / 2);
        _keepalive();
        vm.roll(landed + LIVENESS);
        _keepalive();
        assertEq(uint256(s.consumedDepositCount()), 0, "deposit still unconsumed");
        vm.expectRevert(DarkPerpSettlement.LivenessNotExpired.selector);
        s.triggerCloseOnly();

        vm.roll(landed + LIVENESS + 1);
        vmLogs.recordLogs();
        vm.prank(OUTSIDER);
        s.triggerCloseOnly();
        _assertCloseOnlyReason(address(s), "deposit inclusion timeout");
        assertTrue(s.closeOnly(), "close-only");
        assertEq(s.closeOnlyBlock(), block.number, "entry block latched");
        assertEq(s.closeOnlyBatchCount(), 2, "entry batch count latched");

        vm.prank(OUTSIDER);
        vault.refundDeposit(id, alice, commit, amount, alice);
        assertEq(usdc.balanceOf(alice), amount, "held deposit refunded at principal");
    }

    function test_consuming_the_oldest_deposit_restarts_the_inclusion_clock() public {
        uint256 start = block.number;
        _depositToVault(1_000 * USD); // id 0
        vm.roll(start + 30);
        _depositToVault(2_000 * USD); // id 1
        vm.roll(start + 60);
        _settleEmptyAt(1); // credits id 0 only
        assertEq(vault.depositBlock(1), start + 30, "id 1 landing block");

        vm.roll(start + LIVENESS + 1); // id 0 would be overdue, but it was consumed
        vm.expectRevert(DarkPerpSettlement.LivenessNotExpired.selector);
        s.triggerCloseOnly();
        vm.roll(start + 30 + LIVENESS);
        vm.expectRevert(DarkPerpSettlement.LivenessNotExpired.selector);
        s.triggerCloseOnly();
        vm.roll(start + 30 + LIVENESS + 1);
        vmLogs.recordLogs();
        s.triggerCloseOnly();
        _assertCloseOnlyReason(address(s), "deposit inclusion timeout");
    }

    function test_without_unconsumed_deposits_only_liveness_closes() public {
        _depositToVault(1_000 * USD);
        _settleEmptyAt(1);
        for (uint256 i = 0; i < 4; i++) {
            vm.roll(block.number + LIVENESS / 2);
            vm.expectRevert(DarkPerpSettlement.LivenessNotExpired.selector);
            s.triggerCloseOnly();
            _keepalive();
        }
        uint256 last = s.lastProgressBlock();
        vm.roll(last + LIVENESS);
        vm.expectRevert(DarkPerpSettlement.LivenessNotExpired.selector);
        s.triggerCloseOnly();
        vm.roll(last + LIVENESS + 1);
        vmLogs.recordLogs();
        s.triggerCloseOnly();
        _assertCloseOnlyReason(address(s), "liveness timeout");
    }

    function test_liveness_reason_wins_when_both_timeouts_hold() public {
        _depositToVault(1_000 * USD);
        vm.roll(block.number + LIVENESS + 1);
        vmLogs.recordLogs();
        s.triggerCloseOnly();
        _assertCloseOnlyReason(address(s), "liveness timeout");
    }

    function test_governance_enters_close_only_immediately() public {
        address gov = address(0x6007);
        DarkPerpSettlement.Config memory c = _cfg();
        c.governance = gov;
        DarkPerpSettlement d = new DarkPerpSettlement(c);
        vm.expectRevert(DarkPerpSettlement.NotGovernance.selector);
        d.enterCloseOnly(); // the sequencer is not governance here
        vm.prank(OUTSIDER);
        vm.expectRevert(DarkPerpSettlement.NotGovernance.selector);
        d.enterCloseOnly();
        assertFalse(d.closeOnly(), "still live");

        vm.roll(block.number + 5);
        vmLogs.recordLogs();
        vm.prank(gov);
        d.enterCloseOnly();
        _assertCloseOnlyReason(address(d), "governance");
        assertTrue(d.closeOnly(), "close-only with no timeout");
        assertEq(d.closeOnlyBlock(), block.number, "entry block latched");
        assertEq(d.closeOnlyBatchCount(), 0, "entry batch count latched");

        // irreversible and idempotent
        vm.roll(block.number + 5);
        vmLogs.recordLogs();
        vm.prank(gov);
        d.enterCloseOnly();
        d.triggerCloseOnly(); // a no-op once close-only, though liveness has not expired
        _assertNoCloseOnlyEvent(address(d));
        assertEq(d.closeOnlyBlock(), block.number - 5, "entry block unchanged");

        bytes memory proof = abi.encode(
            d.publicCommitment(GENESIS, bytes32(0), GENESIS, bytes32(0), bytes32(0), bytes32(0), bytes32(0))
        );
        vm.expectRevert(DarkPerpSettlement.InCloseOnly.selector);
        d.settleBatch(GENESIS, bytes32(0), GENESIS, bytes32(0), bytes32(0), bytes32(0), bytes32(0), 0, proof);
    }

    function test_governance_close_only_opens_refunds_at_once() public {
        address alice = address(0xA11CE5);
        (uint64 id, bytes32 commit) = _depositFrom(alice, 500 * USD);
        vm.expectRevert(CollateralVault.NotCloseOnly.selector);
        vault.refundDeposit(id, alice, commit, 500 * USD, alice);
        s.enterCloseOnly();
        vault.refundDeposit(id, alice, commit, 500 * USD, alice);
        assertEq(usdc.balanceOf(alice), 500 * USD, "refunded without waiting for any grace");
        assertEq(vault.tvl(), 0, "refund leaves the TVL");
    }

    function test_close_only_entry_latches_once() public {
        _keepalive();
        _enterCloseOnlyViaLiveness();
        uint256 entryBlock = s.closeOnlyBlock();
        assertEq(s.closeOnlyBatchCount(), 1, "one phase-0 batch at entry");

        vm.roll(block.number + GRACE + 1);
        vmLogs.recordLogs();
        s.enterCloseOnly();
        s.triggerCloseOnly();
        _governanceFinalSettle();
        _windDown(2, s.consumedDepositCount());
        _assertNoCloseOnlyEvent(address(s));
        assertEq(s.batchCount(), 3, "wind-down batches counted");
        assertTrue(s.closeOnly(), "close-only never cleared");
        assertEq(s.closeOnlyBlock(), entryBlock, "entry block unchanged");
        assertEq(s.closeOnlyBatchCount(), 1, "wind-down batches are not phase-0 batches");
    }

    /// Once in close-only the vault refuses new deposits, and the deposit the settled
    /// state never consumed is refundable at principal.
    function test_deposit_blocked_in_close_only() public {
        address alice = address(0xA11CE5);
        (uint64 id, bytes32 commit) = _depositFrom(alice, 100 * USD);
        _enterCloseOnlyViaLiveness();

        _bond(100 * USD); // spare capacity: close-only is what refuses the deposit
        (bytes32 commit2, uint64 validUntil, bytes memory sig) = _permit(alice, 100 * USD);
        vm.prank(alice);
        vm.expectRevert(CollateralVault.InCloseOnly.selector);
        vault.deposit(100 * USD, commit2, validUntil, sig);

        uint256 before = usdc.balanceOf(alice);
        vm.prank(OUTSIDER);
        vault.refundDeposit(id, alice, commit, 100 * USD, alice);
        assertEq(usdc.balanceOf(alice) - before, 100 * USD, "stranded deposit refunded to its payer");
        assertEq(vault.tvl(), 0, "nothing left in the vault's accounting");
    }

    // --- bond -------------------------------------------------------------------------

    function test_withdraw_excess_bond() public {
        // no TVL and nothing open: the whole bond is excess
        _bond(5000 * USD);
        uint256 before = usdc.balanceOf(address(this));
        s.withdrawBond(2000 * USD);
        assertEq(s.sequencerBond(), 3000 * USD, "bond reduced");
        assertEq(usdc.balanceOf(address(this)) - before, 2000 * USD, "USDC returned to sequencer");
    }

    function test_cannot_withdraw_bond_below_required_floor() public {
        _depositToVault(100_000 * USD); // TVL 100k: the deposit needed a 5k bond
        _bond(1000 * USD); // 1k of excess over the 5k floor
        assertEq(s.requiredBond(), 5000 * USD, "floor from TVL");
        vm.expectRevert(DarkPerpSettlement.WithdrawExceedsExcess.selector);
        s.withdrawBond(2000 * USD);
        s.withdrawBond(1000 * USD);
        assertEq(s.sequencerBond(), 5000 * USD, "bond can't drop below the floor");
    }

    function test_withdrawBond_reserves_the_cap_for_each_open_challenge() public {
        _bond(5_000 * USD);
        _openChallenge(keccak256("reserve-0"), BENEFICIARY, SUBMITTER);
        _openChallenge(keccak256("reserve-1"), BENEFICIARY, SUBMITTER);
        // no TVL, so the reserve for two open challenges is the whole floor
        vm.expectRevert(DarkPerpSettlement.WithdrawExceedsExcess.selector);
        s.withdrawBond(3_000 * USD + 1);
        s.withdrawBond(3_000 * USD);
        assertEq(s.sequencerBond(), 2 * CAP, "two caps reserved");
        vm.expectRevert(DarkPerpSettlement.WithdrawExceedsExcess.selector);
        s.withdrawBond(1);

        (uint256 batchId, bytes32[] memory proof) = _settleBatchWithOrder(keccak256("reserve-0"));
        s.answerChallenge(keccak256("reserve-0"), batchId, proof);
        s.withdrawBond(CAP);
        assertEq(s.sequencerBond(), CAP, "an answered challenge releases its reserve");
    }

    function test_withdrawBond_floor_is_the_larger_of_tvl_and_reserve() public {
        _depositToVault(10_000 * USD); // floor 500
        _bond(4_500 * USD); // bond 5_000
        _openChallenge(keccak256("reserved"), BENEFICIARY, SUBMITTER); // reserve 1_000
        vm.expectRevert(DarkPerpSettlement.WithdrawExceedsExcess.selector);
        s.withdrawBond(4_000 * USD + 1);
        s.withdrawBond(4_000 * USD);
        assertEq(s.sequencerBond(), CAP, "the reserve binds above the TVL floor");

        _depositToVault(90_000 * USD); // floor 5_000, topped up by the helper
        assertEq(s.requiredBond(), 5_000 * USD, "TVL floor");
        assertEq(s.sequencerBond(), 5_000 * USD, "bond at the TVL floor");
        vm.expectRevert(DarkPerpSettlement.WithdrawExceedsExcess.selector);
        s.withdrawBond(1);
    }

    function test_withdrawBond_is_allowed_in_close_only() public {
        _depositToVault(10_000 * USD); // floor 500
        _bond(1_500 * USD);
        s.enterCloseOnly();
        s.withdrawBond(1_500 * USD);
        assertEq(s.sequencerBond(), 500 * USD, "excess withdrawn in close-only");
        vm.expectRevert(DarkPerpSettlement.WithdrawExceedsExcess.selector);
        s.withdrawBond(1);
    }

    function test_withdrawBond_still_works_after_a_slash() public {
        _bond(5_000 * USD);
        bytes32 h = keccak256("withheld");
        _openRipeChallenge(h, BENEFICIARY);
        _ripenSlash();
        s.slashUnanswered(h);
        uint256 before = usdc.balanceOf(address(this));
        s.withdrawBond(4_000 * USD);
        assertEq(s.sequencerBond(), 0, "the rest of the bond is excess");
        assertEq(usdc.balanceOf(address(this)) - before, 4_000 * USD, "USDC returned to sequencer");
        assertEq(usdc.balanceOf(address(s)), s.pendingUsdc(BENEFICIARY), "the fine stays held for its beneficiary");
    }

    // --- inclusion challenges: opening ------------------------------------------------

    function test_challenge_requires_bond() public {
        bytes32 h = keccak256("x");
        bytes memory sig = _authSig(h, BENEFICIARY);
        _ripen();
        vm.expectRevert(DarkPerpSettlement.WrongChallengeBond.selector);
        s.challengeInclusion(h, 1, RECV_MS, 0, BENEFICIARY, sig); // no value
        vm.expectRevert(DarkPerpSettlement.WrongChallengeBond.selector);
        s.challengeInclusion{value: CHALLENGE_BOND + 1}(h, 1, RECV_MS, 0, BENEFICIARY, sig);
    }

    function _expectChallengeRevert(bytes32 h, address beneficiary, bytes memory sig, bytes4 err) internal {
        vm.prank(SUBMITTER);
        vm.expectRevert(err);
        s.challengeInclusion{value: CHALLENGE_BOND}(h, 1, RECV_MS, 0, beneficiary, sig);
    }

    function test_non_canonical_signature_rejected() public {
        bytes32 h = keccak256("x");
        bytes32 digest = SettlementTestConfig.challengeAuthDigest(address(s), h, 1, RECV_MS, 0, BENEFICIARY);
        (uint8 v, bytes32 r, bytes32 sg) = vm.sign(ENCLAVE_PK, digest);
        vm.deal(SUBMITTER, CHALLENGE_BOND);
        _ripen();
        bytes4 err = DarkPerpSettlement.NonCanonicalSignature.selector;
        // the high-s twin of a valid signature
        _expectChallengeRevert(
            h,
            BENEFICIARY,
            abi.encodePacked(r, bytes32(SECP256K1_N - uint256(sg)), v == 27 ? uint8(28) : uint8(27)),
            err
        );
        _expectChallengeRevert(h, BENEFICIARY, abi.encodePacked(r, sg), err); // 64 bytes
        _expectChallengeRevert(h, BENEFICIARY, abi.encodePacked(r, sg, v, uint8(0)), err); // 66 bytes
        _expectChallengeRevert(h, BENEFICIARY, abi.encodePacked(r, sg, v - 27), err); // v in {0, 1}
        _expectChallengeRevert(h, BENEFICIARY, abi.encodePacked(r, sg, uint8(29)), err);
        vm.prank(SUBMITTER);
        s.challengeInclusion{value: CHALLENGE_BOND}(h, 1, RECV_MS, 0, BENEFICIARY, abi.encodePacked(r, sg, v));
        assertEq(s.openChallengeCount(), 1, "the canonical form opens");
    }

    function test_bad_receipt_signature_rejected() public {
        bytes32 h = keccak256("x");
        vm.deal(SUBMITTER, CHALLENGE_BOND);
        _ripen();
        _expectChallengeRevert(
            h, BENEFICIARY, _sigBy(0xBADBAD, h, BENEFICIARY), DarkPerpSettlement.BadReceiptSignature.selector
        );
        // well formed, but recovers no address
        _expectChallengeRevert(
            h,
            BENEFICIARY,
            abi.encodePacked(bytes32(0), bytes32(uint256(1)), uint8(27)),
            DarkPerpSettlement.BadReceiptSignature.selector
        );
    }

    function test_challenge_authorization_is_bound_to_beneficiary_and_fields() public {
        bytes32 h = keccak256("bound");
        vm.deal(SUBMITTER, CHALLENGE_BOND);
        _ripen();
        bytes memory signedFor = _authSig(h, BENEFICIARY);
        bytes4 err = DarkPerpSettlement.BadReceiptSignature.selector;
        // naming another beneficiary
        _expectChallengeRevert(h, SUBMITTER, signedFor, err);
        // changing another signed field
        vm.prank(SUBMITTER);
        vm.expectRevert(err);
        s.challengeInclusion{value: CHALLENGE_BOND}(h, 2, RECV_MS, 0, BENEFICIARY, signedFor);
        vm.prank(SUBMITTER);
        vm.expectRevert(err);
        s.challengeInclusion{value: CHALLENGE_BOND}(h, 1, RECV_MS - 1, 0, BENEFICIARY, signedFor);
        vm.prank(SUBMITTER);
        vm.expectRevert(err);
        s.challengeInclusion{value: CHALLENGE_BOND}(h, 1, RECV_MS, 1, BENEFICIARY, signedFor);
        vm.prank(SUBMITTER);
        vm.expectRevert(err);
        s.challengeInclusion{value: CHALLENGE_BOND}(keccak256("other-order"), 1, RECV_MS, 0, BENEFICIARY, signedFor);

        // the genuine authorization works whoever submits it, and names the signed beneficiary
        vm.prank(SUBMITTER);
        s.challengeInclusion{value: CHALLENGE_BOND}(h, 1, RECV_MS, 0, BENEFICIARY, signedFor);
        (address beneficiary,,,,, bool open) = s.challenges(h);
        assertEq(beneficiary, BENEFICIARY, "beneficiary is the signed one");
        assertTrue(open, "open");
    }

    function test_challenge_authorization_is_bound_to_chain_and_settlement() public {
        bytes32 h = keccak256("domain-bound");
        vm.deal(SUBMITTER, CHALLENGE_BOND);
        _ripen();
        bytes4 err = DarkPerpSettlement.BadReceiptSignature.selector;
        bytes memory otherSettlement = SettlementTestConfig.challengeSig(
            vm, ENCLAVE_PK, DarkPerpSettlement(address(0x5E77)), h, 1, RECV_MS, 0, BENEFICIARY
        );
        _expectChallengeRevert(h, BENEFICIARY, otherSettlement, err);

        uint256 chain = block.chainid;
        vm.chainId(chain + 1);
        bytes memory otherChain = _authSig(h, BENEFICIARY);
        vm.chainId(chain);
        _expectChallengeRevert(h, BENEFICIARY, otherChain, err);

        // signed on the fork's chain id, refused on this one
        vm.chainId(chain + 1);
        vm.prank(SUBMITTER);
        s.challengeInclusion{value: CHALLENGE_BOND}(h, 1, RECV_MS, 0, BENEFICIARY, otherChain);
        assertEq(s.openChallengeCount(), 1, "valid where it was signed");
        vm.chainId(chain);
    }

    function test_raw_receipt_signature_no_longer_opens_a_challenge() public {
        bytes32 h = keccak256("raw-receipt");
        (uint8 v, bytes32 r, bytes32 sg) = vm.sign(ENCLAVE_PK, s.receiptDigest(h, 1, RECV_MS, 0));
        vm.deal(SUBMITTER, CHALLENGE_BOND);
        _ripen();
        _expectChallengeRevert(
            h, BENEFICIARY, abi.encodePacked(r, sg, v), DarkPerpSettlement.BadReceiptSignature.selector
        );
        assertTrue(
            s.challengeAuthDigest(h, 1, RECV_MS, 0, BENEFICIARY) != s.receiptDigest(h, 1, RECV_MS, 0),
            "authorization and receipt digests differ"
        );
        assertEq(
            s.challengeAuthDigest(h, 1, RECV_MS, 0, BENEFICIARY),
            SettlementTestConfig.challengeAuthDigest(address(s), h, 1, RECV_MS, 0, BENEFICIARY),
            "on-chain digest matches the helper"
        );
    }

    function test_challenge_reverts_before_ripe() public {
        bytes32 h = keccak256("ripe-order");
        bytes memory sig = _authSig(h, BENEFICIARY);
        vm.deal(SUBMITTER, CHALLENGE_BOND);
        vm.warp(RECV_MS / 1000 + INCLUSION_DEADLINE - 1);
        _expectChallengeRevert(h, BENEFICIARY, sig, DarkPerpSettlement.NotRipe.selector);
    }

    function test_challenge_allowed_after_ripe() public {
        bytes32 h = keccak256("ripe-order");
        bytes memory sig = _authSig(h, BENEFICIARY);
        vm.deal(SUBMITTER, CHALLENGE_BOND);
        vm.warp(RECV_MS / 1000 + INCLUSION_DEADLINE); // exactly ripe
        vm.prank(SUBMITTER);
        s.challengeInclusion{value: CHALLENGE_BOND}(h, 1, RECV_MS, 0, BENEFICIARY, sig);
        (,,,,, bool open) = s.challenges(h);
        assertTrue(open, "challenge opened once ripe");
        assertEq(s.openChallengeCount(), 1, "in the open set");
    }

    function test_challenge_checks_run_in_order() public {
        bytes32 h = keccak256("ordered-checks");
        bytes memory good = _authSig(h, BENEFICIARY);
        bytes memory wrongSigner = _sigBy(0xBADBAD, h, BENEFICIARY);
        vm.deal(SUBMITTER, 10 * CHALLENGE_BOND);
        // at t = 1 the receipt is not ripe: ripeness is the last check
        _expectChallengeRevert(h, BENEFICIARY, good, DarkPerpSettlement.NotRipe.selector);
        _expectChallengeRevert(h, BENEFICIARY, wrongSigner, DarkPerpSettlement.BadReceiptSignature.selector);
        _expectChallengeRevert(h, BENEFICIARY, hex"01", DarkPerpSettlement.NonCanonicalSignature.selector);
        _expectChallengeRevert(h, address(0), hex"01", DarkPerpSettlement.BadBeneficiary.selector);
        vm.prank(SUBMITTER);
        vm.expectRevert(DarkPerpSettlement.WrongChallengeBond.selector);
        s.challengeInclusion(h, 1, RECV_MS, 0, address(0), hex"01");

        _ripen();
        vm.prank(SUBMITTER);
        s.challengeInclusion{value: CHALLENGE_BOND}(h, 1, RECV_MS, 0, BENEFICIARY, good);
        vm.prank(SUBMITTER);
        vm.expectRevert(DarkPerpSettlement.ChallengeExists.selector);
        s.challengeInclusion(h, 1, RECV_MS, 0, address(0), hex"01");

        (uint256 batchId, bytes32[] memory proof) = _settleBatchWithOrder(h);
        s.answerChallenge(h, batchId, proof);
        vm.prank(SUBMITTER);
        vm.expectRevert(DarkPerpSettlement.AlreadyResolved.selector);
        s.challengeInclusion(h, 1, RECV_MS, 0, address(0), hex"01");

        s.enterCloseOnly();
        vm.prank(SUBMITTER);
        vm.expectRevert(DarkPerpSettlement.InCloseOnly.selector);
        s.challengeInclusion(keccak256("fresh"), 1, RECV_MS, 0, address(0), hex"01");
    }

    function _expectReopenResolved(bytes32 h) internal {
        bytes memory sig = _authSig(h, BENEFICIARY);
        vm.deal(BENEFICIARY, CHALLENGE_BOND);
        vm.prank(BENEFICIARY);
        vm.expectRevert(DarkPerpSettlement.AlreadyResolved.selector);
        s.challengeInclusion{value: CHALLENGE_BOND}(h, 1, RECV_MS, 0, BENEFICIARY, sig);
    }

    /// An order hash is challengeable once: after an answer or a slash it stays resolved.
    function test_resolved_order_cannot_be_challenged_again() public {
        bytes32 answered = keccak256("answered");
        _openRipeChallenge(answered, BENEFICIARY);
        uint256 batchId = _settleRejectionBatch(answered);
        s.answerByRejection(answered, batchId, new bytes32[](0));
        assertEq(s.pendingEth(BENEFICIARY), CHALLENGE_BOND, "first challenge forced publication");
        _expectReopenResolved(answered);

        _bond(5_000 * USD);
        bytes32 slashedHash = keccak256("slashed");
        _openRipeChallenge(slashedHash, BENEFICIARY);
        _ripenSlash();
        s.slashUnanswered(slashedHash);
        _expectReopenResolved(slashedHash);
        assertEq(s.slashCount(), 1, "one fine for one order");
    }

    // --- inclusion challenges: answers ------------------------------------------------

    function test_inclusion_answered_clears_challenge() public {
        bytes32 orderHash = keccak256("order-1");
        bytes32 orderedRoot = s.inclusionLeaf(0, orderHash);
        _settle(GENESIS, keccak256("m"), bytes32(uint256(2)), orderedRoot, bytes32(0), bytes32(0));
        _openRipeChallenge(orderHash, address(0xBEEF));

        s.answerChallenge(orderHash, 0, new bytes32[](0));
        (,,,,, bool open) = s.challenges(orderHash);
        assertFalse(open, "challenge cleared");
        assertTrue(s.challengeResolved(orderHash), "order resolved");
        assertEq(s.openChallengeCount(), 0, "open set emptied");
    }

    /// Settlement is async, so an order routinely settles after its challenge opened.
    /// Proving inclusion in that later batch answers the challenge.
    function test_answer_with_batch_settled_after_challenge_succeeds() public {
        bytes32 orderHash = keccak256("settles-late");
        _openRipeChallenge(orderHash, address(0xBEEF));
        vm.roll(block.number + 1);
        bytes32 orderedRoot = s.inclusionLeaf(0, orderHash);
        _settle(GENESIS, keccak256("late"), bytes32(uint256(2)), orderedRoot, bytes32(0), bytes32(0));

        s.answerChallenge(orderHash, 0, new bytes32[](0));
        (,,,,, bool open) = s.challenges(orderHash);
        assertFalse(open, "challenge answered by genuine late inclusion");
    }

    /// The leaf is bound to (batchId, orderHash) over the batch's immutable orderedRoot,
    /// so a settled batch that does not contain the order cannot answer.
    function test_answer_rejected_when_batch_lacks_order() public {
        bytes32 orderHash = keccak256("withheld");
        _openRipeChallenge(orderHash, address(0xBEEF));
        bytes32 orderedRoot = s.inclusionLeaf(0, keccak256("some-other-order"));
        _settle(GENESIS, keccak256("unrelated"), bytes32(uint256(2)), orderedRoot, bytes32(0), bytes32(0));

        bytes32[] memory proof = new bytes32[](0);
        vm.expectRevert(DarkPerpSettlement.NotIncluded.selector);
        s.answerChallenge(orderHash, 0, proof);
    }

    /// Membership in a settled batch's rejectedRoot clears the challenge. This checks
    /// membership only, not the reason the order was rejected.
    function test_declared_rejection_membership_answers_challenge() public {
        bytes32 orderHash = keccak256("validly-rejected");
        _openRipeChallenge(orderHash, address(0xBEEF));
        bytes32 rejectedRoot = s.rejectionLeaf(0, orderHash);
        bytes32 orderedRoot = s.inclusionLeaf(0, keccak256("some-ordered-order"));
        _settle(GENESIS, keccak256("rej"), bytes32(uint256(2)), orderedRoot, bytes32(0), rejectedRoot);

        s.answerByRejection(orderHash, 0, new bytes32[](0));
        (,,,,, bool open) = s.challenges(orderHash);
        assertFalse(open, "challenge answered by declared rejection membership");
    }

    function test_answer_by_rejection_requires_membership() public {
        bytes32 orderHash = keccak256("actually-withheld");
        _openRipeChallenge(orderHash, address(0xBEEF));
        bytes32 rejectedRoot = s.rejectionLeaf(0, keccak256("some-other-rejected"));
        _settle(GENESIS, keccak256("unrelated-rej"), bytes32(uint256(2)), bytes32(0), bytes32(0), rejectedRoot);

        bytes32[] memory proof = new bytes32[](0);
        vm.expectRevert(DarkPerpSettlement.NotRejected.selector);
        s.answerByRejection(orderHash, 0, proof);
        // an inclusion leaf is not a rejection leaf, and vice versa
        vm.expectRevert(DarkPerpSettlement.NotIncluded.selector);
        s.answerChallenge(orderHash, 0, proof);
    }

    /// The stake is credited for pull, never pushed, so a non-payable recipient cannot
    /// block an answer.
    function test_answer_refund_is_pull_not_push() public {
        bytes32 orderHash = keccak256("pull-order");
        bytes32 orderedRoot = s.inclusionLeaf(0, orderHash);
        _settle(GENESIS, keccak256("m"), bytes32(uint256(2)), orderedRoot, bytes32(0), bytes32(0));
        _openRipeChallenge(orderHash, address(0xBEEF));

        s.answerChallenge(orderHash, 0, new bytes32[](0));
        assertEq(s.pendingEth(address(this)), CHALLENGE_BOND, "stake credited to the sequencer");

        uint256 balBefore = address(this).balance;
        s.claimEth();
        assertEq(address(this).balance, balBefore + CHALLENGE_BOND, "sequencer pulls the refund");
        assertEq(s.pendingEth(address(this)), 0, "pending cleared after claim");
    }

    function test_answer_forced_inclusion_refunds_challenger() public {
        bytes32 orderHash = keccak256("withheld");
        address challenger = address(0xC0FFEE);
        _openRipeChallenge(orderHash, challenger);

        vm.roll(block.number + 1);
        (uint256 batchId, bytes32[] memory proof) = _settleBatchWithOrder(orderHash);
        s.answerChallenge(orderHash, batchId, proof);

        assertEq(s.pendingEth(challenger), CHALLENGE_BOND, "challenger refunded");
        assertEq(s.pendingEth(address(this)), 0, "sequencer not paid");
        assertEq(s.slashCount(), 0, "an answer never fines");
        assertFalse(s.closeOnly(), "an answer never trips close-only");
    }

    function test_answer_presettled_forfeits_to_sequencer() public {
        bytes32 orderHash = keccak256("already-in");
        (uint256 batchId, bytes32[] memory proof) = _settleBatchWithOrder(orderHash);
        address challenger = address(0xBEEF);
        _openRipeChallenge(orderHash, challenger);

        s.answerChallenge(orderHash, batchId, proof);
        assertEq(s.pendingEth(address(this)), CHALLENGE_BOND, "stake forfeits to the sequencer");
        assertEq(s.pendingEth(challenger), 0, "challenger not refunded");
    }

    function test_answer_is_permissionless_and_routes_by_batch() public {
        bytes32 h = keccak256("permissionless");
        (uint256 early, bytes32[] memory proof) = _settleBatchWithOrder(h);
        _openChallenge(h, BENEFICIARY, SUBMITTER);
        vm.expectRevert(DarkPerpSettlement.NoSuchChallenge.selector);
        s.answerChallenge(keccak256("unknown"), 99, proof);
        uint256 unsettled = s.batchCount();
        vm.expectRevert(DarkPerpSettlement.BatchNotSettled.selector);
        s.answerChallenge(h, unsettled, proof);

        vm.prank(OUTSIDER);
        s.answerChallenge(h, early, proof);
        assertEq(s.pendingEth(address(this)), CHALLENGE_BOND, "a pre-settled order forfeits to the sequencer");
        assertEq(s.pendingEth(SUBMITTER), 0, "staker not refunded");
        assertEq(s.pendingEth(OUTSIDER), 0, "the answerer earns nothing");
        vm.expectRevert(DarkPerpSettlement.NoSuchChallenge.selector);
        s.answerChallenge(h, early, proof);
    }

    function test_same_block_forced_inclusion_refunds_challenger() public {
        bytes32 orderHash = keccak256("same-block-withheld");
        address challenger = address(0xC0FFEE);
        _openRipeChallenge(orderHash, challenger);
        uint256 challengeBlock = block.number;

        // transaction order matters even when the block number is identical
        (uint256 batchId, bytes32[] memory proof) = _settleBatchWithOrder(orderHash);
        s.answerChallenge(orderHash, batchId, proof);

        assertEq(block.number, challengeBlock, "no block advance");
        assertEq(s.pendingEth(challenger), CHALLENGE_BOND, "same-block forced inclusion refunds challenger");
        assertEq(s.pendingEth(address(this)), 0, "sequencer cannot confiscate same-block forced inclusion stake");
        vm.expectRevert(DarkPerpSettlement.NoSuchChallenge.selector);
        s.answerChallenge(orderHash, batchId, proof);
    }

    /// If the rejecting batch settles only after the challenge opened, the challenge is
    /// what forced the disposition to be published, so the stake refunds.
    function test_rejection_answer_postdating_challenge_refunds() public {
        bytes32 orderHash = keccak256("rejected-order");
        address challenger = address(0xD00D);
        _openRipeChallenge(orderHash, challenger);

        vm.roll(block.number + 1);
        uint256 batchId = _settleRejectionBatch(orderHash);
        s.answerByRejection(orderHash, batchId, new bytes32[](0));
        assertEq(s.pendingEth(challenger), CHALLENGE_BOND, "post-challenge rejection refunds the challenger");
        assertEq(s.pendingEth(address(this)), 0, "sequencer not paid for a late-published rejection");
    }

    /// The rejecting batch settled before the challenge opened: the disposition was
    /// already public, so the stake forfeits to the sequencer.
    function test_rejection_answer_presettled_forfeits_to_sequencer() public {
        bytes32 orderHash = keccak256("rejected-order");
        uint256 batchId = _settleRejectionBatch(orderHash);
        address challenger = address(0xBEEF);
        vm.roll(block.number + 1);
        _openRipeChallenge(orderHash, challenger);

        s.answerByRejection(orderHash, batchId, new bytes32[](0));
        assertEq(s.pendingEth(address(this)), CHALLENGE_BOND, "pre-settled rejection forfeits to sequencer");
        assertEq(s.pendingEth(challenger), 0, "challenger not refunded");
    }

    function test_same_block_late_rejection_refunds_challenger() public {
        bytes32 orderHash = keccak256("same-block-late-rejection");
        address challenger = address(0xD00D);
        _openRipeChallenge(orderHash, challenger);
        uint256 challengeBlock = block.number;

        uint256 batchId = _settleRejectionBatch(orderHash);
        s.answerByRejection(orderHash, batchId, new bytes32[](0));

        assertEq(block.number, challengeBlock, "no block advance");
        assertEq(s.pendingEth(challenger), CHALLENGE_BOND, "same-block late rejection refunds challenger");
        assertEq(s.pendingEth(address(this)), 0, "sequencer cannot confiscate same-block late rejection stake");
        vm.expectRevert(DarkPerpSettlement.NoSuchChallenge.selector);
        s.answerByRejection(orderHash, batchId, new bytes32[](0));
    }

    function test_same_block_presettled_rejection_forfeits_to_sequencer() public {
        bytes32 orderHash = keccak256("same-block-presettled-rejection");
        address challenger = address(0xD00D);
        uint256 batchId = _settleRejectionBatch(orderHash);
        uint256 settledBlock = block.number;
        _openRipeChallenge(orderHash, challenger);

        s.answerByRejection(orderHash, batchId, new bytes32[](0));

        assertEq(block.number, settledBlock, "no block advance");
        assertEq(s.pendingEth(address(this)), CHALLENGE_BOND, "same-block prior settlement forfeits stake");
        assertEq(s.pendingEth(challenger), 0, "preexisting rejection does not refund challenger");
    }

    function testFuzz_same_block_refund_follows_transaction_order(uint8 priorBatches, bool rejection, bool settleFirst)
        public
    {
        // a nonzero boundary as well as genesis; every operation stays in one block, so
        // only the batch count at opening can distinguish the cases
        for (uint256 i; i < priorBatches % 4; ++i) {
            _settleBatchWithOrder(keccak256(abi.encodePacked("prior", i)));
        }
        bytes32 orderHash = keccak256("fuzz-challenged-order");
        address challenger = address(0xD00D);
        uint256 batchId = s.batchCount();
        if (!settleFirst) _openRipeChallenge(orderHash, challenger);
        if (rejection) _settleRejectionBatch(orderHash);
        else _settleBatchWithOrder(orderHash);
        if (settleFirst) _openRipeChallenge(orderHash, challenger);
        (,,, uint256 openBatchCount,,) = s.challenges(orderHash);
        assertEq(openBatchCount, settleFirst ? batchId + 1 : batchId, "open batch count is the batch count at opening");

        if (rejection) s.answerByRejection(orderHash, batchId, new bytes32[](0));
        else s.answerChallenge(orderHash, batchId, new bytes32[](0));

        assertEq(s.pendingEth(challenger), settleFirst ? 0 : CHALLENGE_BOND, "refund follows transaction order");
        assertEq(s.pendingEth(address(this)), settleFirst ? CHALLENGE_BOND : 0, "forfeit follows transaction order");
    }

    function test_answerChallenges_resolves_a_batch_and_skips_closed_entries() public {
        bytes32 h0 = keccak256("batch-a");
        bytes32 h1 = keccak256("batch-b");
        bytes32 h2 = keccak256("batch-c");
        _openChallenge(h0, BENEFICIARY, SUBMITTER);
        _openChallenge(h1, BENEFICIARY, SUBMITTER);
        _openChallenge(h2, BENEFICIARY, SUBMITTER);
        bytes32 l0 = s.inclusionLeaf(0, h0);
        bytes32 l1 = s.inclusionLeaf(0, h1);
        bytes32 ordered = l0 <= l1 ? keccak256(abi.encodePacked(l0, l1)) : keccak256(abi.encodePacked(l1, l0));
        _settle(GENESIS, keccak256("m"), bytes32(uint256(2)), ordered, bytes32(0), s.rejectionLeaf(0, h2));

        bytes32[] memory hashes = _list(h0, h1, h2, h0);
        bool[] memory byRejection = new bool[](4);
        byRejection[2] = true;
        bytes32[][] memory proofs = new bytes32[][](4);
        proofs[0] = _one(l1);
        proofs[1] = _one(keccak256("junk"));
        proofs[2] = new bytes32[](0);
        proofs[3] = _one(l1);

        vm.expectRevert(DarkPerpSettlement.LengthMismatch.selector);
        s.answerChallenges(0, hashes, new bool[](3), proofs);
        vm.expectRevert(DarkPerpSettlement.BatchNotSettled.selector);
        s.answerChallenges(1, hashes, byRejection, proofs);
        vm.expectRevert(DarkPerpSettlement.NotIncluded.selector);
        s.answerChallenges(0, hashes, byRejection, proofs);
        assertEq(s.openChallengeCount(), 3, "a reverted batch resolves nothing");

        proofs[1] = _one(l0);
        vm.prank(OUTSIDER);
        uint256 answered = s.answerChallenges(0, hashes, byRejection, proofs);
        assertEq(answered, 3, "the duplicate entry is skipped");
        assertEq(s.openChallengeCount(), 0, "all resolved");
        assertEq(s.pendingEth(SUBMITTER), 3 * CHALLENGE_BOND, "the batch post-dates every challenge");
        vm.prank(OUTSIDER);
        assertEq(s.answerChallenges(0, hashes, byRejection, proofs), 0, "closed entries are skipped, not reverted");
    }

    // --- inclusion challenges: fines and releases --------------------------------------

    function test_unanswered_challenge_fines_the_bond_by_the_cap() public {
        uint256 bond = 5_000 * USD;
        _bond(bond);
        bytes32 h = keccak256("withheld");
        _openRipeChallenge(h, BENEFICIARY);
        _ripenSlash();

        vmLogs.recordLogs();
        vm.prank(OUTSIDER);
        s.slashUnanswered(h);
        VmLogs.Log[] memory logs = vmLogs.getRecordedLogs();
        (uint256 n, uint256 at) = _find(logs, address(s), SLASHED_TOPIC);
        assertEq(n, 1, "one fine event");
        assertEq(logs[at].topics[1], h, "indexed order hash");
        assertEq(logs[at].topics[2], bytes32(uint256(uint160(BENEFICIARY))), "indexed beneficiary");
        assertEq(keccak256(logs[at].data), keccak256(abi.encode(CAP)), "fine amount");

        assertEq(s.sequencerBond(), bond - CAP, "the fine is capped");
        assertEq(s.slashCount(), 1, "fine counted");
        assertFalse(s.closeOnly(), "a fine does not stop the exchange");
        assertTrue(s.challengeResolved(h), "order resolved");
        assertEq(s.openChallengeCount(), 0, "open set emptied");
        // both the fine and the stake are credited for pull, never pushed
        assertEq(usdc.balanceOf(BENEFICIARY), 0, "fine not pushed directly");
        assertEq(s.pendingUsdc(BENEFICIARY), CAP, "fine credited to the beneficiary");
        assertEq(s.pendingEth(BENEFICIARY), CHALLENGE_BOND, "stake credited to its submitter");
        vm.prank(BENEFICIARY);
        s.claimUsdc();
        assertEq(usdc.balanceOf(BENEFICIARY), CAP, "beneficiary pulls the fine");
        vm.prank(BENEFICIARY);
        s.claimEth();
        assertEq(BENEFICIARY.balance, CHALLENGE_BOND, "submitter pulls the stake");

        vm.expectRevert(DarkPerpSettlement.NoSuchChallenge.selector);
        s.slashUnanswered(h);
        vm.expectRevert(DarkPerpSettlement.NoSuchChallenge.selector);
        s.answerChallenge(h, 0, new bytes32[](0));
        _keepalive();
        assertEq(s.batchCount(), PROGRESS + 1, "settlement continues after a fine");
    }

    function test_slash_waits_for_progress_batches_then_the_grace() public {
        _bond(5_000 * USD);
        bytes32 h = keccak256("progress-gated");
        _openRipeChallenge(h, BENEFICIARY);
        (,,, uint256 openBatchCount,,) = s.challenges(h);
        assertEq(openBatchCount, 0, "opened before any batch");
        vm.expectRevert(DarkPerpSettlement.NoProgress.selector);
        s.slashUnanswered(h);
        _keepalive();
        vm.expectRevert(DarkPerpSettlement.NoProgress.selector);
        s.slashUnanswered(h);
        // blocks alone never ripen a slash
        vm.roll(block.number + 20 * CHALLENGE_GRACE);
        vm.expectRevert(DarkPerpSettlement.NoProgress.selector);
        s.slashUnanswered(h);

        _keepalive();
        uint256 settled = block.number;
        vm.expectRevert(DarkPerpSettlement.ChallengeNotExpired.selector);
        s.slashUnanswered(h);
        vm.roll(settled + CHALLENGE_GRACE);
        vm.expectRevert(DarkPerpSettlement.ChallengeNotExpired.selector);
        s.slashUnanswered(h);
        vm.roll(settled + CHALLENGE_GRACE + 1);
        s.slashUnanswered(h);
        assertEq(s.slashCount(), 1, "fined after progress and grace");
    }

    function test_slash_grace_runs_from_the_progress_batch() public {
        _bond(5_000 * USD);
        bytes32 h = keccak256("grace-anchor");
        _openRipeChallenge(h, BENEFICIARY);
        _keepalive();
        _keepalive();
        uint256 progressBlock = block.number;
        vm.roll(progressBlock + CHALLENGE_GRACE - 5);
        _keepalive(); // a later batch does not restart the grace
        vm.roll(progressBlock + CHALLENGE_GRACE + 1);
        s.slashUnanswered(h);
        assertEq(s.slashCount(), 1, "grace measured from the progress batch");
    }

    function test_slow_settlement_is_answered_not_fined() public {
        _bond(5_000 * USD);
        bytes32 h = keccak256("slow-order");
        _openRipeChallenge(h, BENEFICIARY);
        vm.roll(block.number + 50 * CHALLENGE_GRACE);
        vm.expectRevert(DarkPerpSettlement.NoProgress.selector);
        s.slashUnanswered(h);
        (uint256 batchId, bytes32[] memory proof) = _settleBatchWithOrder(h);
        s.answerChallenge(h, batchId, proof);
        assertEq(s.pendingEth(BENEFICIARY), CHALLENGE_BOND, "a late inclusion refunds the staker");
        assertEq(s.sequencerBond(), 5_000 * USD, "bond untouched");
        assertEq(s.slashCount(), 0, "no fine");
    }

    function test_third_party_submission_pays_the_signed_beneficiary() public {
        _bond(5_000 * USD);
        bytes32 h = keccak256("third-party-submission");
        _openChallenge(h, BENEFICIARY, SUBMITTER);
        _ripenSlash();
        s.slashUnanswered(h);
        assertEq(s.pendingUsdc(BENEFICIARY), CAP, "fine to the beneficiary");
        assertEq(s.pendingUsdc(SUBMITTER), 0, "nothing to the submitter");
        assertEq(s.pendingEth(SUBMITTER), CHALLENGE_BOND, "stake back to the submitter");
        assertEq(s.pendingEth(BENEFICIARY), 0, "the beneficiary posted no stake");
    }

    /// With the bond below the cap the beneficiary picks the moment; a separate submitter
    /// may close the challenge only `LIVENESS` blocks after the slash became possible.
    function test_short_bond_slash_is_left_to_the_parties() public {
        _bond(400 * USD);
        bytes32 h = keccak256("short-bond");
        _openChallenge(h, BENEFICIARY, SUBMITTER);
        _ripenSlash();
        vm.prank(OUTSIDER);
        vm.expectRevert(DarkPerpSettlement.ShortBondSlashRestricted.selector);
        s.slashUnanswered(h);
        vm.prank(SUBMITTER);
        vm.expectRevert(DarkPerpSettlement.ShortBondSlashRestricted.selector);
        s.slashUnanswered(h);
        vm.prank(BENEFICIARY);
        s.slashUnanswered(h);
        assertEq(s.pendingUsdc(BENEFICIARY), 400 * USD, "the whole short bond goes to the beneficiary");
        assertEq(s.sequencerBond(), 0, "bond emptied");

        bytes32 h2 = keccak256("short-bond-2");
        _openChallenge(h2, BENEFICIARY, SUBMITTER);
        _ripenSlash();
        uint256 firstSlashBlock = block.number;
        vm.prank(OUTSIDER);
        vm.expectRevert(DarkPerpSettlement.ShortBondSlashRestricted.selector);
        s.slashUnanswered(h2);
        vm.roll(firstSlashBlock - 1 + LIVENESS);
        vm.prank(SUBMITTER);
        vm.expectRevert(DarkPerpSettlement.ShortBondSlashRestricted.selector);
        s.slashUnanswered(h2);
        vm.roll(firstSlashBlock + LIVENESS);
        vm.prank(OUTSIDER);
        vm.expectRevert(DarkPerpSettlement.ShortBondSlashRestricted.selector);
        s.slashUnanswered(h2);
        vm.prank(SUBMITTER);
        s.slashUnanswered(h2);
        assertEq(s.pendingUsdc(BENEFICIARY), 400 * USD, "an empty bond pays nothing more");
        assertEq(s.slashCount(), 2, "both counted");
        assertEq(s.pendingEth(SUBMITTER), 2 * CHALLENGE_BOND, "both stakes back to the submitter");
    }

    function test_full_cap_slash_is_permissionless() public {
        _bond(CAP);
        bytes32 h = keccak256("exact-cap");
        _openChallenge(h, BENEFICIARY, SUBMITTER);
        _ripenSlash();
        vm.prank(OUTSIDER);
        s.slashUnanswered(h);
        assertEq(s.pendingUsdc(BENEFICIARY), CAP, "full cap paid");
        assertEq(s.sequencerBond(), 0, "bond spent");
    }

    /// A fine leaves settlement running even below the bond floor; the deposit gate stays
    /// closed until the bond is topped up.
    function test_settlement_continues_below_the_floor_after_a_fine() public {
        _depositToVault(100_000 * USD);
        assertEq(s.sequencerBond(), s.requiredBond(), "bond exactly at the floor");
        bytes32 h = keccak256("fined");
        _openRipeChallenge(h, BENEFICIARY);
        _ripenSlash();
        s.slashUnanswered(h);
        assertEq(s.sequencerBond(), 4_000 * USD, "fined by the cap");
        assertTrue(s.sequencerBond() < s.requiredBond(), "bond now below the floor");

        _settleEmptyAt(1);
        assertEq(uint256(s.consumedDepositCount()), 1, "a batch settles below the floor");
        assertFalse(s.closeOnly(), "still live");

        assertEq(s.depositCapacity(), 0, "no capacity below the floor");
        (bytes32 commit, uint64 validUntil, bytes memory sig) = _permit(address(this), 1);
        vm.expectRevert(CollateralVault.BondCapacityExceeded.selector);
        vault.deposit(1, commit, validUntil, sig);
        _bond(CAP);
        vault.deposit(1, commit, validUntil, sig);
        assertEq(uint256(vault.depositCount()), 2, "deposits reopen after a top-up");
    }

    function test_close_only_before_progress_releases_the_challenge() public {
        _bond(5_000 * USD);
        bytes32 h = keccak256("stale");
        _openChallenge(h, BENEFICIARY, SUBMITTER);
        vm.expectRevert(DarkPerpSettlement.NotStale.selector);
        s.releaseStaleChallenge(h); // live
        _keepalive();
        s.enterCloseOnly();
        vm.roll(block.number + GRACE + 1);
        _governanceFinalSettle();
        assertEq(s.batchCount(), 2, "two batches settled since the challenge");
        vm.roll(block.number + CHALLENGE_GRACE + 1);
        vm.expectRevert(DarkPerpSettlement.NoProgress.selector);
        s.slashUnanswered(h); // the wind-down batch is not a phase-0 batch

        vmLogs.recordLogs();
        vm.prank(OUTSIDER);
        s.releaseStaleChallenge(h);
        VmLogs.Log[] memory logs = vmLogs.getRecordedLogs();
        (uint256 n, uint256 at) = _find(logs, address(s), RELEASED_TOPIC);
        assertEq(n, 1, "one release event");
        assertEq(logs[at].topics[1], h, "indexed order hash");
        assertEq(s.pendingEth(SUBMITTER), CHALLENGE_BOND, "stake back to its submitter");
        assertTrue(s.challengeResolved(h), "order resolved");
        assertEq(s.openChallengeCount(), 0, "open set emptied");
        assertEq(s.sequencerBond(), 5_000 * USD, "a release fines nothing");
        assertEq(s.slashCount(), 0, "no fine");
        vm.expectRevert(DarkPerpSettlement.NoSuchChallenge.selector);
        s.slashUnanswered(h);
        vm.expectRevert(DarkPerpSettlement.NotStale.selector);
        s.releaseStaleChallenge(h);
    }

    function test_liveness_close_only_releases_a_fresh_challenge() public {
        bytes32 h = keccak256("fresh-at-close");
        _openChallenge(h, BENEFICIARY, SUBMITTER);
        _enterCloseOnlyViaLiveness();
        s.releaseStaleChallenge(h);
        assertEq(s.pendingEth(SUBMITTER), CHALLENGE_BOND, "stake refunded");
        assertTrue(s.challengeResolved(h), "order resolved");
    }

    /// A slash that lands in close-only, for a challenge whose progress was reached
    /// before close-only, does not move the close-only entry block.
    function test_slash_after_closeOnly_does_not_reset_grace() public {
        _bond(5_000 * USD);
        bytes32 h = keccak256("withheld-order");
        _openRipeChallenge(h, BENEFICIARY);
        _keepalive();
        _keepalive();
        _enterCloseOnlyViaLiveness();
        uint256 entry = s.closeOnlyBlock();
        assertEq(s.closeOnlyBatchCount(), PROGRESS, "progress reached before close-only");
        vm.expectRevert(DarkPerpSettlement.NotStale.selector);
        s.releaseStaleChallenge(h);

        // close-only admits no new challenge
        bytes32 h2 = keccak256("late-challenge");
        bytes memory sig = _authSig(h2, BENEFICIARY);
        vm.deal(BENEFICIARY, CHALLENGE_BOND);
        vm.prank(BENEFICIARY);
        vm.expectRevert(DarkPerpSettlement.InCloseOnly.selector);
        s.challengeInclusion{value: CHALLENGE_BOND}(h2, 1, RECV_MS, 0, BENEFICIARY, sig);

        vm.roll(block.number + CHALLENGE_GRACE + 1);
        s.slashUnanswered(h);
        assertEq(s.slashCount(), 1, "fined in close-only");
        assertTrue(s.closeOnly(), "still close-only");
        assertEq(s.closeOnlyBlock(), entry, "closeOnlyBlock latched to the first entry");

        uint256 before = s.batchCount();
        _governanceFinalSettle();
        assertEq(s.batchCount(), before + 1, "wind-down lands per the original grace deadline");
    }

    function test_open_set_pages_stay_consistent_across_closes() public {
        _bond(5_000 * USD);
        bytes32 h0 = keccak256("open-0");
        bytes32 h1 = keccak256("open-1");
        bytes32 h2 = keccak256("open-2");
        bytes32 h3 = keccak256("open-3");
        _openChallenge(h0, BENEFICIARY, SUBMITTER);
        _openChallenge(h1, BENEFICIARY, SUBMITTER);
        _openChallenge(h2, BENEFICIARY, SUBMITTER);
        _openChallenge(h3, BENEFICIARY, SUBMITTER);
        assertEq(s.openChallengeCount(), 4, "four open");
        _assertPage(0, 10, _list(h0, h1, h2, h3));
        _assertPage(1, 2, _list(h1, h2));
        _assertPage(3, 5, _one(h3));
        _assertPage(4, 1, new bytes32[](0));
        _assertPage(0, 0, new bytes32[](0));
        _assertPage(type(uint256).max, type(uint256).max, new bytes32[](0));

        // answer: the last entry moves into the hole
        (uint256 batchId, bytes32[] memory proof) = _settleBatchWithOrder(h1);
        s.answerChallenge(h1, batchId, proof);
        _assertPage(0, 10, _list(h0, h3, h2));
        // slash
        _ripenSlash();
        s.slashUnanswered(h0);
        _assertPage(0, 10, _list(h2, h3));
        // release a challenge opened after the progress batches
        bytes32 h4 = keccak256("open-4");
        _openChallenge(h4, BENEFICIARY, SUBMITTER);
        _assertPage(0, 10, _list(h2, h3, h4));
        s.enterCloseOnly();
        vm.expectRevert(DarkPerpSettlement.NotStale.selector);
        s.releaseStaleChallenge(h3);
        s.releaseStaleChallenge(h4);
        _assertPage(0, type(uint256).max, _list(h2, h3));
        // a slash reachable before close-only still lands in it
        s.slashUnanswered(h2);
        _assertPage(0, 10, _one(h3));

        _assertStakeAccounting(SUBMITTER, BENEFICIARY);
        assertEq(
            usdc.balanceOf(address(s)),
            s.sequencerBond() + s.pendingUsdc(BENEFICIARY),
            "USDC held equals bond plus fines"
        );
    }

    // --- governance wind-down -----------------------------------------------------------

    function test_finalSettle_reverts_when_not_closeOnly() public {
        (bytes32 p, bytes32 mh, bytes32 nr, bytes32 wr, bytes32 dTip, uint64 dCount, bytes memory pf) =
            _finalSettleArgs();
        vm.expectRevert(DarkPerpSettlement.NotCloseOnly.selector);
        s.finalSettle(p, mh, nr, bytes32(0), wr, bytes32(0), dTip, dCount, pf);
    }

    function test_finalSettle_reverts_before_grace() public {
        _enterCloseOnlyViaLiveness();
        vm.roll(s.closeOnlyBlock() + GRACE - 1);
        (bytes32 p, bytes32 mh, bytes32 nr, bytes32 wr, bytes32 dTip, uint64 dCount, bytes memory pf) =
            _finalSettleArgs();
        vm.expectRevert(DarkPerpSettlement.GraceNotExpired.selector);
        s.finalSettle(p, mh, nr, bytes32(0), wr, bytes32(0), dTip, dCount, pf);
        vm.roll(s.closeOnlyBlock() + GRACE);
        s.finalSettle(p, mh, nr, bytes32(0), wr, bytes32(0), dTip, dCount, pf);
        assertTrue(s.windDownSettled(), "lands once the grace has elapsed");
    }

    function test_finalSettle_reverts_non_governance() public {
        _enterCloseOnlyViaLiveness();
        vm.roll(block.number + GRACE + 1);
        (bytes32 p, bytes32 mh, bytes32 nr, bytes32 wr, bytes32 dTip, uint64 dCount, bytes memory pf) =
            _finalSettleArgs();
        vm.prank(OUTSIDER);
        vm.expectRevert(DarkPerpSettlement.NotGovernance.selector);
        s.finalSettle(p, mh, nr, bytes32(0), wr, bytes32(0), dTip, dCount, pf);
    }

    function test_finalSettle_publish_then_claim() public {
        address to = address(0xFEED);
        uint256 amount = 100 * USD;
        _depositToVault(amount);
        // credited by an ordinary batch before close-only
        _settle(GENESIS, keccak256("m0"), bytes32(uint256(2)), bytes32(0), bytes32(0), bytes32(0));
        assertEq(uint256(s.consumedDepositCount()), 1, "deposit consumed");

        _enterCloseOnlyViaLiveness();
        vm.roll(block.number + GRACE + 1);
        uint256 before = s.batchCount();

        // a withdrawals root that is a real single-leaf claim, so the escape is verified
        // end-to-end through the vault
        uint256 nonce = 1;
        bytes32 leaf = keccak256(abi.encodePacked(to, amount, nonce));
        bytes32 prev = s.currentStateRoot();
        bytes32 newRoot = keccak256("wind-down");
        bytes32 dTip = vault.depositTipAt(1);
        assertTrue(dTip != bytes32(0), "wind-down pins a non-genesis deposit prefix");
        bytes32 commitment = s.windDownCommitment(prev, bytes32("m"), newRoot, bytes32(0), leaf, bytes32(0), dTip, 1);
        s.finalSettle(prev, bytes32("m"), newRoot, bytes32(0), leaf, bytes32(0), dTip, 1, abi.encodePacked(commitment));
        assertEq(s.batchCount(), before + 1, "final settle advanced batchCount");

        bytes32[] memory proof = new bytes32[](0);
        vault.claim(to, amount, nonce, leaf, proof);
        assertEq(usdc.balanceOf(to), amount, "withdrawal claimable via the vault after finalSettle");
    }

    function _finalSettleWithWithdrawals(bytes32 wroot) internal {
        bytes32 prev = s.currentStateRoot();
        uint64 n = s.consumedDepositCount();
        bytes32 tip = vault.depositTipAt(n);
        bytes32 next = keccak256("wind-down");
        bytes32 commitment = s.windDownCommitment(prev, bytes32("m"), next, bytes32(0), wroot, bytes32(0), tip, 1);
        s.finalSettle(prev, bytes32("m"), next, bytes32(0), wroot, bytes32(0), tip, n, abi.encode(commitment));
    }

    /// The frozen consumed count is what the vault reserves: proven claims cannot draw
    /// on principal of deposits the settled state never credited.
    function test_wind_down_claims_leave_uncredited_principal_refundable() public {
        address to = address(0xFEED);
        address late = address(0x1A7E);
        _depositToVault(100 * USD);
        _settleEmptyAt(1);
        (uint64 lateId, bytes32 lateCommit) = _depositFrom(late, 50 * USD);
        s.enterCloseOnly();
        vm.roll(block.number + GRACE);

        bytes32 over = keccak256(abi.encodePacked(to, 120 * USD, uint256(1)));
        bytes32 fair = keccak256(abi.encodePacked(to, 100 * USD, uint256(2)));
        bytes32 root = fair <= over ? keccak256(abi.encodePacked(fair, over)) : keccak256(abi.encodePacked(over, fair));
        _finalSettleWithWithdrawals(root);
        assertEq(vault.refundableOutstanding(), 50 * USD, "the late deposit is reserved");

        vm.expectRevert(CollateralVault.ReservedForUncredited.selector);
        vault.claim(to, 120 * USD, 1, root, _one(fair));
        vault.claim(to, 100 * USD, 2, root, _one(over));
        assertEq(usdc.balanceOf(to), 100 * USD, "a claim within credited principal pays");
        vault.refundDeposit(lateId, late, lateCommit, 50 * USD, late);
        assertEq(usdc.balanceOf(late), 50 * USD, "uncredited principal refunded in full");
    }

    function test_finalSettle_works_after_a_slash() public {
        _bond(5_000 * USD);
        bytes32 h = keccak256("withheld-order");
        _openRipeChallenge(h, BENEFICIARY);
        _ripenSlash();
        s.slashUnanswered(h);
        assertEq(s.slashCount(), 1, "fined");
        assertFalse(s.closeOnly(), "a fine does not enter close-only");
        _enterCloseOnlyViaLiveness();
        vm.roll(block.number + GRACE + 1);
        uint256 before = s.batchCount();
        _governanceFinalSettle();
        assertEq(s.batchCount(), before + 1, "wind-down lands after a fine");
    }

    function test_a06_finalSettle_rejects_ordinary_phase_zero_proof() public {
        _enterCloseOnlyViaLiveness();
        vm.roll(block.number + GRACE + 1);
        (bytes32 p, bytes32 mh, bytes32 nr, bytes32 wr, bytes32 dTip, uint64 dCount,) = _finalSettleArgs();
        bytes32 ordinary = s.publicCommitment(p, mh, nr, bytes32(0), wr, bytes32(0), dTip);
        vm.expectRevert(DarkPerpSettlement.BadProof.selector);
        s.finalSettle(p, mh, nr, bytes32(0), wr, bytes32(0), dTip, dCount, abi.encodePacked(ordinary));
    }

    function test_a06_settleBatch_rejects_phase_one_proof() public {
        bytes32 prev = s.currentStateRoot();
        bytes32 mh = bytes32("phase1");
        bytes32 nr = keccak256("phase1-root");
        (bytes32 dTip, uint64 dCount) = _head();
        bytes32 phase1 = s.windDownCommitment(prev, mh, nr, bytes32(0), bytes32(0), bytes32(0), dTip, 1);
        vm.expectRevert(DarkPerpSettlement.BadProof.selector);
        s.settleBatch(prev, mh, nr, bytes32(0), bytes32(0), bytes32(0), dTip, dCount, abi.encodePacked(phase1));
    }

    function test_a06_final_settle_is_one_shot_and_phase_two_exit_is_repeatable() public {
        _depositToVault(1_000 * USD);
        _settleEmptyAt(1);
        _enterCloseOnlyViaLiveness();
        vm.roll(block.number + GRACE + 1);
        _governanceFinalSettle();
        assertTrue(s.windDownSettled(), "phase 1 latched");

        (bytes32 p, bytes32 mh, bytes32 nr, bytes32 wr, bytes32 dTip, uint64 dCount,) = _finalSettleArgs();
        bytes32 again = s.windDownCommitment(p, mh, nr, bytes32(0), wr, bytes32(0), dTip, 1);
        vm.expectRevert(bytes("wind-down already settled"));
        s.finalSettle(p, mh, nr, bytes32(0), wr, bytes32(0), dTip, dCount, abi.encodePacked(again));

        for (uint256 i = 0; i < 2; i++) {
            bytes32 prev = s.currentStateRoot();
            bytes32 manifest = keccak256(abi.encodePacked("exit", i));
            bytes32 next = keccak256(abi.encodePacked("exit-root", i));
            uint64 count = s.consumedDepositCount();
            bytes32 tip = vault.depositTipAt(count);
            bytes32 phase2 = s.windDownCommitment(prev, manifest, next, bytes32(0), bytes32(0), bytes32(0), tip, 2);
            s.finalExit(prev, manifest, next, bytes32(0), bytes32(0), bytes32(0), tip, count, abi.encodePacked(phase2));
            assertEq(s.currentStateRoot(), next, "phase 2 advanced root");
        }
        assertEq(uint256(s.consumedDepositCount()), 1, "exits never move the consumed count");
    }

    function test_a06_finalExit_rejects_before_phase_one() public {
        _enterCloseOnlyViaLiveness();
        bytes32 prev = s.currentStateRoot();
        uint64 count = s.consumedDepositCount();
        bytes32 tip = vault.depositTipAt(count);
        bytes32 c = s.windDownCommitment(prev, bytes32("x"), bytes32("y"), bytes32(0), bytes32(0), bytes32(0), tip, 2);
        vm.expectRevert(bytes("wind-down not settled"));
        s.finalExit(
            prev, bytes32("x"), bytes32("y"), bytes32(0), bytes32(0), bytes32(0), tip, count, abi.encodePacked(c)
        );
    }

    function test_a06_finalExit_reverts_non_governance() public {
        _enterCloseOnlyViaLiveness();
        vm.roll(block.number + GRACE + 1);
        _governanceFinalSettle();
        bytes32 prev = s.currentStateRoot();
        uint64 count = s.consumedDepositCount();
        bytes32 tip = vault.depositTipAt(count);
        bytes32 commitment =
            s.windDownCommitment(prev, bytes32("x"), bytes32("y"), bytes32(0), bytes32(0), bytes32(0), tip, 2);

        vm.prank(OUTSIDER);
        vm.expectRevert(DarkPerpSettlement.NotGovernance.selector);
        s.finalExit(
            prev,
            bytes32("x"),
            bytes32("y"),
            bytes32(0),
            bytes32(0),
            bytes32(0),
            tip,
            count,
            abi.encodePacked(commitment)
        );
        assertEq(s.currentStateRoot(), prev, "unauthorized exit cannot advance state");
    }

    receive() external payable {}
}

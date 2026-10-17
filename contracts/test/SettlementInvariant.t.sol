// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MiniTest, Vm} from "./utils/MiniTest.sol";
import {SettlementTestConfig} from "./utils/SettlementTestConfig.sol";
import {DarkPerpSettlement} from "../src/DarkPerpSettlement.sol";
import {CollateralVault} from "../src/CollateralVault.sol";
import {MockUSDC} from "../src/mocks/MockUSDC.sol";
import {MockClockVerifier} from "./mocks/MockClockVerifier.sol";

/// Stateful invariants for the settlement: the inclusion-challenge game, the deposit
/// prefix pin, close-only and the custody accounting.
///
/// The handler is the honest sequencer (and governance) of a settlement paired with a
/// real vault. It settles batches asynchronously at random deposit prefixes, accepts
/// gateway-permitted deposits, posts and withdraws bond, and answers challenges late
/// (`actAnswer`, `actAnswerBatch`), but always before a challenge's slash gate opens
/// (`_honestWatcher`, run before time advances). Third parties open challenges with
/// genuine enclave authorizations, answer, slash, release and claim.
///
/// Orders come in two kinds:
/// - 16 HONEST orders. Order j lives in batch j/2 (even j in `orderedRoot`, odd j in
///   `rejectedRoot`). An order is challenged only once it is settled or lands in the
///   next batch, which is the honest sequencer's guarantee for a ripe order. Such a
///   challenge must always be answerable and never slashable.
/// - 8 CENSORED orders that no batch ever contains. They may be slashed once the
///   progress and grace gates open, or released after close-only.
contract Handler {
    Vm internal constant vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);
    uint256 internal constant ENCLAVE_PK = 0xA11CE;
    uint256 internal constant GATEWAY_PK = 0x6A7E;
    uint256 public constant HONEST = 16;
    uint256 public constant CENSORED = 8;
    uint256 public constant ACTORS = 4;
    uint256 public constant BENEFICIARIES = 3;
    bytes32 internal constant M = keccak256("m");

    DarkPerpSettlement public s;
    CollateralVault public vault;
    MockUSDC public usdc;
    uint256 public challengeBond;
    uint256 public progressBatches;
    uint256 public graceBlocks;
    uint256 public slashCap;

    bytes32 internal root;
    address[] internal actors;
    address[] internal beneficiaries;
    address internal constant STRANGER = address(0x5742A6E7);

    // Deposit preimages by vault id, for refunds.
    mapping(uint64 => address) internal depFrom;
    mapping(uint64 => bytes32) internal depCommit;
    mapping(uint64 => uint256) internal depAmount;
    uint256 internal commitNonce;

    // Challenge ghosts.
    mapping(bytes32 => bool) public ghostOpen;
    mapping(bytes32 => bool) public ghostResolved;
    mapping(bytes32 => address) internal ghostStaker;
    mapping(bytes32 => uint256) internal ghostOpenBatch;
    uint256 public ghostOpenCount;
    uint256 public ghostOpenStake;
    uint256 public slashes;
    uint256 public honestSlashes;
    uint256 public answers;
    uint256 public releases;

    // Violation flags; every one MUST stay false.
    bool public griefed; // an honest answer was rejected
    bool public gateBeforeSettle; // a slash gate opened before the order's batch settled
    bool public misrouted; // a stake was credited to the wrong party
    bool public slashGateBypassed; // a slash landed outside its gates or misaccounted
    bool public releaseGateBypassed; // a release landed while a slash was reachable
    bool public resolvedReopened; // a closed order hash was challenged again
    bool public pinBypassed; // a settle with a count outside [consumed, head] landed
    bool public frozenBypassed; // the consumed count moved in close-only
    bool public consumedRegressed; // the consumed count decreased
    bool public closeOnlyCleared; // close-only was left
    bool public coverageLost; // the bond fell below requiredBond without a slash
    bool public triggerMisjudged; // triggerCloseOnly disagreed with its conditions
    bool public withdrawBelowFloor; // withdrawBond went below its floor
    bool public refundBelowBoundary; // a consumed deposit, or one while live, was refunded
    bool public depositInCloseOnly; // a deposit landed in close-only
    bool public claimMismatch; // a pull payment paid a different amount than owed
    bool public ghostDesync; // the contract closed a challenge the handler saw as closed
    bool public settleRefused; // an in-range settle or a due wind-down batch was refused

    uint64 public lastConsumed;
    bool public sawCloseOnly;
    uint64 internal consumedAtCloseOnly;
    uint256 internal lastCoveredSlashCount;

    struct SlashPre {
        bool open;
        bool honest;
        uint256 target;
        uint256 phase0;
        uint256 settledAt;
        uint256 bond;
        address ben;
        address staker;
        uint256 benPending;
        uint256 stakerPending;
    }

    modifier sampled() {
        _;
        _sample();
    }

    function init(DarkPerpSettlement _s, CollateralVault _vault, MockUSDC _usdc, bytes32 genesis) external {
        require(address(s) == address(0), "init once");
        s = _s;
        vault = _vault;
        usdc = _usdc;
        root = genesis;
        challengeBond = _s.challengeBond();
        progressBatches = _s.progressBatches();
        graceBlocks = _s.challengeGraceBlocks();
        slashCap = _s.slashPayoutCap();
        _s.setVault(address(_vault));
        uint256 bond = 20_000e6;
        _usdc.mint(address(this), bond);
        _usdc.approve(address(_s), type(uint256).max);
        _s.postBond(bond);
        for (uint256 i = 0; i < ACTORS; i++) {
            actors.push(vm.addr(0xA0 + i));
            vm.deal(actors[i], 1_000 ether);
        }
        for (uint256 i = 0; i < BENEFICIARIES; i++) {
            beneficiaries.push(vm.addr(0xB0 + i));
        }
    }

    // --- universe ---------------------------------------------------------------------

    function honest(uint256 j) public pure returns (bytes32) {
        return keccak256(abi.encodePacked("order", j));
    }

    function censored(uint256 k) public pure returns (bytes32) {
        return keccak256(abi.encodePacked("censored", k));
    }

    function universe(uint256 i) public pure returns (bytes32) {
        return i < HONEST ? honest(i) : censored(i - HONEST);
    }

    function universeSize() external pure returns (uint256) {
        return HONEST + CENSORED;
    }

    function pendingEthTotal() external view returns (uint256 t) {
        t = s.pendingEth(address(this));
        for (uint256 i = 0; i < ACTORS; i++) {
            t += s.pendingEth(actors[i]);
        }
    }

    function pendingUsdcTotal() external view returns (uint256 t) {
        for (uint256 i = 0; i < BENEFICIARIES; i++) {
            t += s.pendingUsdc(beneficiaries[i]);
        }
    }

    /// Batches that count for the progress gate.
    function _phase0() internal view returns (uint256) {
        return s.closeOnly() ? s.closeOnlyBatchCount() : s.batchCount();
    }

    function _caller(uint256 seed) internal view returns (address) {
        uint256 i = seed % (ACTORS + BENEFICIARIES + 1);
        if (i < ACTORS) return actors[i];
        if (i < ACTORS + BENEFICIARIES) return beneficiaries[i - ACTORS];
        return STRANGER;
    }

    // --- settlement ---------------------------------------------------------------------

    /// Settle the next batch. While live it credits a random prefix between the consumed
    /// count and the vault head, and sometimes first probes counts outside that range,
    /// which must be refused. In close-only it lands the wind-down batches with the
    /// frozen count, and probes a moved count.
    function actSettle(uint256 seed) external sampled {
        if (s.closeOnly()) {
            _windDown(seed);
            return;
        }
        uint64 c = s.consumedDepositCount();
        uint64 head = vault.depositCount();
        if (seed % 5 == 0) {
            if (_trySettle(head + 1)) pinBypassed = true;
            if (c > 0 && _trySettle(c - 1)) pinBypassed = true;
        }
        // Half the batches credit no new deposit, so the oldest pending one can age into
        // the deposit-inclusion trigger.
        uint64 n = (seed >> 16) % 2 == 0 ? c : c + uint64((seed >> 8) % (uint256(head - c) + 1));
        // Any prefix in range lands, whatever deposits arrived since or the bond's state.
        if (!_trySettle(n)) settleRefused = true;
    }

    function _trySettle(uint64 n) internal returns (bool ok) {
        bytes32 newRoot = keccak256(abi.encodePacked(root, s.batchCount()));
        (ok,) = address(s).call(_settleCall(n, newRoot));
        if (ok) root = newRoot;
    }

    struct Roots {
        bytes32 ordered;
        bytes32 rejected;
        bytes32 deposits;
    }

    /// Batch b < 8 carries honest order 2b as included and 2b+1 as declared rejected.
    function _settleCall(uint64 n, bytes32 newRoot) internal view returns (bytes memory) {
        uint256 b = s.batchCount();
        Roots memory r;
        if (b < HONEST / 2) {
            r.ordered = s.inclusionLeaf(b, honest(2 * b));
            r.rejected = s.rejectionLeaf(b, honest(2 * b + 1));
        }
        r.deposits = vault.depositTipAt(n);
        bytes memory proof =
            abi.encode(s.publicCommitment(root, M, newRoot, r.ordered, bytes32(0), r.rejected, r.deposits));
        return
            abi.encodeCall(s.settleBatch, (root, M, newRoot, r.ordered, bytes32(0), r.rejected, r.deposits, n, proof));
    }

    function _windDown(uint256 seed) internal {
        bool settled = s.windDownSettled();
        if (!settled && block.number < s.closeOnlyBlock() + s.finalSettleGraceBlocks()) return;
        uint64 phase = settled ? 2 : 1;
        uint64 c = s.consumedDepositCount();
        if (seed % 3 == 0 && _tryWindDown(phase, c + 1)) frozenBypassed = true;
        if (!_tryWindDown(phase, c)) settleRefused = true;
    }

    function _tryWindDown(uint64 phase, uint64 n) internal returns (bool ok) {
        bytes32 newRoot = keccak256(abi.encodePacked(root, s.batchCount()));
        bytes32 dr = vault.depositTipAt(n);
        bytes memory proof =
            abi.encode(s.windDownCommitment(root, M, newRoot, bytes32(0), bytes32(0), bytes32(0), dr, phase));
        if (phase == 1) {
            try s.finalSettle(root, M, newRoot, bytes32(0), bytes32(0), bytes32(0), dr, n, proof) {
                ok = true;
            } catch {}
        } else {
            try s.finalExit(root, M, newRoot, bytes32(0), bytes32(0), bytes32(0), dr, n, proof) {
                ok = true;
            } catch {}
        }
        if (ok) root = newRoot;
    }

    // --- deposits, refunds and bond ---------------------------------------------------

    function actDeposit(uint256 actorSeed, uint256 amountRaw) external sampled {
        address from = actors[actorSeed % ACTORS];
        uint256 amount = (amountRaw % 1_000e6) + 1;
        bytes32 commit = keccak256(abi.encodePacked("commit", commitNonce++));
        uint64 id = vault.depositCount();
        bool co = s.closeOnly();
        uint64 until = uint64(block.timestamp + 1 hours);
        bytes memory sig = SettlementTestConfig.permitSig(vm, GATEWAY_PK, vault, from, commit, amount, until);
        usdc.mint(from, amount);
        vm.prank(from);
        usdc.approve(address(vault), amount);
        vm.prank(from);
        try vault.deposit(amount, commit, until, sig) {
            if (co) depositInCloseOnly = true;
            depFrom[id] = from;
            depCommit[id] = commit;
            depAmount[id] = amount;
        } catch {}
    }

    function actRefund(uint256 seed, uint256 callerSeed) external sampled {
        uint64 n = vault.depositCount();
        if (n == 0) return;
        uint64 id = uint64(seed % n);
        uint64 c = s.consumedDepositCount();
        bool co = s.closeOnly();
        address from = depFrom[id];
        bytes32 commit = depCommit[id];
        uint256 amount = depAmount[id];
        vm.prank(_caller(callerSeed));
        try vault.refundDeposit(id, from, commit, amount, from) {
            if (!co || id < c) refundBelowBoundary = true;
        } catch {}
    }

    function actPostBond(uint256 amountRaw) external sampled {
        uint256 amount = amountRaw % 5_000e6;
        usdc.mint(address(this), amount);
        s.postBond(amount);
    }

    function actWithdrawBond(uint256 amountRaw) external sampled {
        uint256 bond = s.sequencerBond();
        uint256 amount = amountRaw % (bond + 1);
        // The floor keeps both the TVL coverage and a full fine per open challenge.
        uint256 floor = s.requiredBond();
        uint256 reserve = s.openChallengeCount() * slashCap;
        if (reserve > floor) floor = reserve;
        uint256 excess = bond > floor ? bond - floor : 0;
        try s.withdrawBond(amount) {
            if (amount > excess || s.sequencerBond() != bond - amount) withdrawBelowFloor = true;
        } catch {}
    }

    // --- challenges ---------------------------------------------------------------------

    function actChallengeHonest(uint256 seed, uint256 actorSeed) external sampled {
        uint256 j = seed % HONEST;
        // The honest guarantee: a ripe accepted order is settled or lands in the next batch.
        if (j / 2 > s.batchCount()) return;
        _challenge(honest(j), uint64(j), actorSeed);
    }

    function actChallengeCensored(uint256 seed, uint256 actorSeed) external sampled {
        uint256 k = seed % CENSORED;
        _challenge(censored(k), uint64(HONEST + k), actorSeed);
    }

    function _challenge(bytes32 h, uint64 seqNo, uint256 actorSeed) internal {
        address staker = actors[actorSeed % ACTORS];
        address ben = beneficiaries[(actorSeed / ACTORS) % BENEFICIARIES];
        bytes memory sig = SettlementTestConfig.challengeSig(vm, ENCLAVE_PK, s, h, seqNo, 0, 0, ben);
        uint256 stake = challengeBond;
        vm.prank(staker);
        try s.challengeInclusion{value: stake}(h, seqNo, 0, 0, ben, sig) {
            if (ghostResolved[h] || ghostOpen[h]) resolvedReopened = true;
            ghostOpen[h] = true;
            ghostOpenCount++;
            ghostOpenStake += stake;
            ghostStaker[h] = staker;
            (,,, uint256 ob,,) = s.challenges(h);
            ghostOpenBatch[h] = ob;
        } catch {}
    }

    function _ghostClose(bytes32 h) internal {
        if (!ghostOpen[h]) {
            ghostDesync = true;
            return;
        }
        ghostOpen[h] = false;
        ghostResolved[h] = true;
        ghostOpenCount--;
        ghostOpenStake -= challengeBond;
    }

    /// A late, permissionless answer for a settled honest order.
    function actAnswer(uint256 seed, uint256 actorSeed) external sampled {
        uint256 j = seed % HONEST;
        if (!ghostOpen[honest(j)] || j / 2 >= _phase0()) return;
        _answerOne(j, actors[actorSeed % ACTORS]);
    }

    function _answerOne(uint256 j, address answerer) internal {
        bytes32 h = honest(j);
        uint256 b = j / 2;
        address expectTo = b >= ghostOpenBatch[h] ? ghostStaker[h] : address(this);
        uint256 before = s.pendingEth(expectTo);
        bytes32[] memory empty = new bytes32[](0);
        bool ok;
        vm.prank(answerer);
        if (j % 2 == 0) {
            try s.answerChallenge(h, b, empty) {
                ok = true;
            } catch {}
        } else {
            try s.answerByRejection(h, b, empty) {
                ok = true;
            } catch {}
        }
        if (!ok) {
            griefed = true;
            return;
        }
        if (s.pendingEth(expectTo) != before + challengeBond) misrouted = true;
        _ghostClose(h);
        answers++;
    }

    /// One batched answer over both orders of a settled batch, with a duplicate entry.
    function actAnswerBatch(uint256 seed, uint256 actorSeed) external sampled {
        uint256 p0 = _phase0();
        if (p0 == 0) return;
        uint256 b = seed % p0;
        if (b >= HONEST / 2) return;
        bytes32 even = honest(2 * b);
        bytes32 odd = honest(2 * b + 1);
        bool evenOpen = ghostOpen[even];
        bool oddOpen = ghostOpen[odd];
        bytes32[] memory hs = new bytes32[](3);
        hs[0] = even;
        hs[1] = odd;
        hs[2] = even;
        bool[] memory rej = new bool[](3);
        rej[1] = true;
        bytes32[][] memory proofs = new bytes32[][](3);
        vm.prank(actors[actorSeed % ACTORS]);
        try s.answerChallenges(b, hs, rej, proofs) returns (uint256 n) {
            if (n != (evenOpen ? 1 : 0) + (oddOpen ? 1 : 0)) griefed = true;
            if (evenOpen) {
                _ghostClose(even);
                answers++;
            }
            if (oddOpen) {
                _ghostClose(odd);
                answers++;
            }
        } catch {
            griefed = true;
        }
    }

    function actSlash(uint256 seed, uint256 callerSeed) external sampled {
        bytes32 h = universe(seed % (HONEST + CENSORED));
        SlashPre memory p = _slashPre(h, seed % (HONEST + CENSORED) < HONEST);
        address caller = _caller(callerSeed);
        vm.prank(caller);
        try s.slashUnanswered(h) {
            _afterSlash(h, p, caller);
        } catch {}
    }

    function _slashPre(bytes32 h, bool isHonest) internal view returns (SlashPre memory p) {
        p.open = ghostOpen[h];
        p.honest = isHonest;
        p.target = ghostOpenBatch[h] + progressBatches;
        p.phase0 = _phase0();
        if (p.phase0 >= p.target) (,,, p.settledAt) = s.batches(p.target - 1);
        p.bond = s.sequencerBond();
        p.staker = ghostStaker[h];
        (p.ben,,,,,) = s.challenges(h);
        p.benPending = s.pendingUsdc(p.ben);
        p.stakerPending = s.pendingEth(p.staker);
    }

    function _afterSlash(bytes32 h, SlashPre memory p, address caller) internal {
        if (!p.open || p.phase0 < p.target || block.number <= p.settledAt + graceBlocks) slashGateBypassed = true;
        uint256 payout = p.bond < slashCap ? p.bond : slashCap;
        // A reduced fine is the beneficiary's call; the submitter may only take it after
        // a further liveness window.
        if (
            payout < slashCap && caller != p.ben
                && (caller != p.staker || block.number <= p.settledAt + graceBlocks + s.livenessTimeoutBlocks())
        ) slashGateBypassed = true;
        if (
            s.sequencerBond() != p.bond - payout || s.pendingUsdc(p.ben) != p.benPending + payout
                || s.pendingEth(p.staker) != p.stakerPending + challengeBond
        ) slashGateBypassed = true;
        if (p.honest) honestSlashes++;
        slashes++;
        _ghostClose(h);
    }

    function actRelease(uint256 seed, uint256 callerSeed) external sampled {
        bytes32 h = universe(seed % (HONEST + CENSORED));
        bool open = ghostOpen[h];
        bool co = s.closeOnly();
        uint256 cobc = s.closeOnlyBatchCount();
        uint256 ob = ghostOpenBatch[h];
        address staker = ghostStaker[h];
        uint256 before = s.pendingEth(staker);
        vm.prank(_caller(callerSeed));
        try s.releaseStaleChallenge(h) {
            if (!open || !co || ob + progressBatches <= cobc) releaseGateBypassed = true;
            if (s.pendingEth(staker) != before + challengeBond) misrouted = true;
            _ghostClose(h);
            releases++;
        } catch {}
    }

    // --- close-only, time and pull payments ---------------------------------------------

    /// Governance enters close-only, rarely.
    function actEnterCloseOnly(uint256 seed) external sampled {
        if (seed % 64 != 0) return;
        s.enterCloseOnly();
    }

    function actTrigger() external sampled {
        bool wasCo = s.closeOnly();
        uint256 liveness = s.livenessTimeoutBlocks();
        // A stalled root only counts once there is a batch, deposit or open challenge.
        bool holds = s.batchCount() != 0 || vault.depositCount() != 0 || s.openChallengeCount() != 0;
        bool stalled = holds && block.number - s.lastProgressBlock() > liveness;
        bool starved;
        uint64 c = s.consumedDepositCount();
        if (vault.depositCount() > c) starved = block.number - vault.depositBlock(c) > liveness;
        try s.triggerCloseOnly() {
            if (!wasCo && !stalled && !starved) triggerMisjudged = true;
        } catch {
            if (wasCo || stalled || starved) triggerMisjudged = true;
        }
    }

    /// Advance time. The honest sequencer first answers every challenge whose slash gate
    /// this step would open; until then its answers may lag arbitrarily.
    function actRoll(uint256 n) external sampled {
        uint256 step = (n % 100) + 1;
        _honestWatcher(step);
        vm.roll(block.number + step);
        vm.warp(block.timestamp + 2 * step);
    }

    function _honestWatcher(uint256 step) internal {
        uint256 p0 = _phase0();
        for (uint256 j = 0; j < HONEST; j++) {
            bytes32 h = honest(j);
            if (!ghostOpen[h]) continue;
            uint256 target = ghostOpenBatch[h] + progressBatches;
            if (p0 < target) continue;
            (,,, uint256 settledAt) = s.batches(target - 1);
            if (block.number + step <= settledAt + graceBlocks) continue;
            if (j / 2 >= p0) {
                gateBeforeSettle = true;
                continue;
            }
            _answerOne(j, address(this));
        }
    }

    function actClaimEth(uint256 seed) external sampled {
        uint256 i = seed % (ACTORS + 1);
        address who = i == ACTORS ? address(this) : actors[i];
        uint256 owed = s.pendingEth(who);
        uint256 bal = who.balance;
        vm.prank(who);
        try s.claimEth() {
            if (who.balance != bal + owed || s.pendingEth(who) != 0) claimMismatch = true;
        } catch {
            claimMismatch = true;
        }
    }

    function actClaimUsdc(uint256 seed) external sampled {
        address who = beneficiaries[seed % BENEFICIARIES];
        uint256 owed = s.pendingUsdc(who);
        uint256 bal = usdc.balanceOf(who);
        vm.prank(who);
        try s.claimUsdc() {
            if (usdc.balanceOf(who) != bal + owed || s.pendingUsdc(who) != 0) claimMismatch = true;
        } catch {
            claimMismatch = true;
        }
    }

    /// Records the monotone quantities after every action.
    function _sample() internal {
        uint64 c = s.consumedDepositCount();
        if (c < lastConsumed) consumedRegressed = true;
        lastConsumed = c;
        bool co = s.closeOnly();
        if (sawCloseOnly && !co) closeOnlyCleared = true;
        if (co && !sawCloseOnly) {
            sawCloseOnly = true;
            consumedAtCloseOnly = c;
        }
        if (sawCloseOnly && c != consumedAtCloseOnly) frozenBypassed = true;
        uint256 sc = s.slashCount();
        if (s.sequencerBond() >= s.requiredBond()) lastCoveredSlashCount = sc;
        else if (sc == lastCoveredSlashCount) coverageLost = true;
    }

    receive() external payable {}
}

contract SettlementInvariantTest is MiniTest {
    struct FuzzSelector {
        address addr;
        bytes4[] selectors;
    }

    DarkPerpSettlement internal s;
    CollateralVault internal vault;
    MockUSDC internal usdc;
    MockClockVerifier internal verifier;
    Handler internal handler;

    uint256 internal constant ENCLAVE_PK = 0xA11CE;
    uint256 internal constant GATEWAY_PK = 0x6A7E;
    bytes32 internal constant GENESIS = bytes32(uint256(1));

    function setUp() public {
        verifier = new MockClockVerifier();
        usdc = new MockUSDC();
        handler = new Handler();
        // Liveness 1,000 blocks, slash grace 200 blocks, 0.01 ether stake, no inclusion
        // SLA (every order is ripe at once), wind-down grace 10 blocks, P = 2, cap 1,000e6.
        DarkPerpSettlement.Config memory cfg = SettlementTestConfig.legacy(
            address(handler), vm.addr(ENCLAVE_PK), verifier, GENESIS, 1_000, 200, 0.01 ether, 0, address(handler), 10
        );
        s = new DarkPerpSettlement(cfg);
        vault = new CollateralVault(address(s), address(usdc), vm.addr(GATEWAY_PK));
        handler.init(s, vault, usdc, GENESIS);
    }

    function targetContracts() public view returns (address[] memory t) {
        t = new address[](1);
        t[0] = address(handler);
    }

    function targetSelectors() public view returns (FuzzSelector[] memory t) {
        bytes4[] memory sel = new bytes4[](16);
        sel[0] = Handler.actSettle.selector;
        sel[1] = Handler.actDeposit.selector;
        sel[2] = Handler.actRefund.selector;
        sel[3] = Handler.actPostBond.selector;
        sel[4] = Handler.actWithdrawBond.selector;
        sel[5] = Handler.actChallengeHonest.selector;
        sel[6] = Handler.actChallengeCensored.selector;
        sel[7] = Handler.actAnswer.selector;
        sel[8] = Handler.actAnswerBatch.selector;
        sel[9] = Handler.actSlash.selector;
        sel[10] = Handler.actRelease.selector;
        sel[11] = Handler.actEnterCloseOnly.selector;
        sel[12] = Handler.actTrigger.selector;
        sel[13] = Handler.actRoll.selector;
        sel[14] = Handler.actClaimEth.selector;
        sel[15] = Handler.actClaimUsdc.selector;
        t = new FuzzSelector[](1);
        t[0] = FuzzSelector(address(handler), sel);
    }

    /// The honest sequencer is never griefed: every answer for a settled, included or
    /// declared-rejected order succeeds, late or batched, and its stake goes where the
    /// batch ordering says.
    function invariant_honest_sequencer_is_never_griefed() public view {
        assertTrue(!handler.griefed(), "honest answer rejected");
        assertTrue(!handler.gateBeforeSettle(), "slash gate opened before the order could be answered");
        assertTrue(!handler.misrouted(), "stake credited to the wrong party");
    }

    /// And it is never slashed; every slash that does land is for a censored order and
    /// respects the progress and grace gates. Releases only happen when no slash can.
    function invariant_honest_sequencer_not_slashed() public view {
        assertEq(handler.honestSlashes(), 0, "honest sequencer slashed");
        assertEq(s.slashCount(), handler.slashes(), "every slash observed");
        assertTrue(!handler.slashGateBypassed(), "slash outside its gates");
        assertTrue(!handler.releaseGateBypassed(), "release while a slash was reachable");
    }

    /// The consumed deposit count only grows, never exceeds the vault head, freezes in
    /// close-only, and bounds the refundable ids.
    function invariant_consumed_deposit_count_is_monotonic_and_bounded() public view {
        assertTrue(!handler.consumedRegressed(), "consumed count decreased");
        assertTrue(s.consumedDepositCount() <= vault.depositCount(), "consumed count above the vault head");
        assertTrue(s.consumedDepositCount() == handler.lastConsumed(), "sampled count");
        assertTrue(!handler.pinBypassed(), "count outside the vault prefix settled");
        assertTrue(!handler.settleRefused(), "in-range settle refused");
        assertTrue(!handler.frozenBypassed(), "consumed count moved in close-only");
        assertTrue(!handler.refundBelowBoundary(), "consumed deposit refunded");
    }

    /// The enumerable open set is exactly the set of open challenges, and closed hashes
    /// stay resolved.
    function invariant_open_set_matches_open_challenges() public view {
        uint256 n = s.openChallengeCount();
        assertEq(n, handler.ghostOpenCount(), "open count");
        bytes32[] memory page = s.openChallenges(0, 512);
        assertEq(page.length, n, "page covers the set");
        for (uint256 i = 0; i < page.length; i++) {
            (,,,,, bool open) = s.challenges(page[i]);
            assertTrue(open && handler.ghostOpen(page[i]), "listed hash is open");
            assertTrue(!s.challengeResolved(page[i]), "listed hash unresolved");
        }
        uint256 size = handler.universeSize();
        for (uint256 u = 0; u < size; u++) {
            bytes32 h = handler.universe(u);
            (,,,,, bool open) = s.challenges(h);
            assertTrue(open == handler.ghostOpen(h), "open flag");
            assertTrue(s.challengeResolved(h) == handler.ghostResolved(h), "resolved flag");
            if (!open) continue;
            bool listed;
            for (uint256 i = 0; i < page.length; i++) {
                if (page[i] == h) listed = true;
            }
            assertTrue(listed, "open hash listed");
        }
        assertTrue(!handler.resolvedReopened(), "resolved hash reopened");
        assertTrue(!handler.ghostDesync(), "closed a challenge that was not open");
    }

    /// Custody: the settlement's ETH is exactly the credited refunds plus the open
    /// stakes, and its USDC exactly the bond plus the credited fines.
    function invariant_custody_accounting() public view {
        assertEq(address(s).balance, handler.pendingEthTotal() + handler.ghostOpenStake(), "eth custody");
        assertEq(usdc.balanceOf(address(s)), s.sequencerBond() + handler.pendingUsdcTotal(), "usdc custody");
        assertTrue(!handler.withdrawBelowFloor(), "bond withdrawn below its floor");
        assertTrue(!handler.claimMismatch(), "pull payment mismatch");
    }

    /// Close-only is irreversible and correctly triggered; between slashes the deposit
    /// gate keeps the bond at or above `requiredBond()`.
    function invariant_close_only_and_bond_coverage() public view {
        assertTrue(!handler.closeOnlyCleared(), "close-only cleared");
        if (handler.sawCloseOnly()) assertTrue(s.closeOnly(), "close-only cleared");
        assertTrue(!handler.triggerMisjudged(), "trigger disagreed with its conditions");
        assertTrue(!handler.depositInCloseOnly(), "deposit in close-only");
        assertTrue(!handler.coverageLost(), "bond coverage lost without a slash");
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MiniTest} from "./utils/MiniTest.sol";
import {SettlementTestConfig} from "./utils/SettlementTestConfig.sol";
import {CollateralVault} from "../src/CollateralVault.sol";
import {MockUSDC} from "../src/mocks/MockUSDC.sol";
import {DarkPerpSettlement} from "../src/DarkPerpSettlement.sol";
import {MockClockVerifier} from "./mocks/MockClockVerifier.sol";
import {MockSettlementGate} from "./mocks/MockSettlementGate.sol";

/// Property/fuzz tests (Foundry fuzzes any parameterized test). These hammer the
/// security-critical guarantees with randomized inputs: a withdrawal claim only ever
/// releases the EXACT authorized leaf, settlement binds the ordered/withdrawals roots
/// (audit F2) and pins the credited deposit count to the vault's prefix, refunds cover
/// exactly the deposits the settled state never consumed, and both off-chain
/// authorizations (enclave challenge authorization, gateway deposit permit) bind every
/// field they sign.
contract FuzzTest is MiniTest {
    CollateralVault internal vault;
    MockSettlementGate internal gate;
    MockUSDC internal usdc;
    DarkPerpSettlement internal s;
    MockClockVerifier internal verifier;
    bytes32 internal constant GENESIS = bytes32(uint256(1));
    bytes32 internal constant M = keccak256("m");
    uint256 internal constant ENCLAVE_PK = 0xE7C1A7E;
    uint256 internal constant GATEWAY_PK = 0x6A7E;
    uint256 internal constant SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    uint256 internal constant CAP = SettlementTestConfig.SLASH_PAYOUT_CAP;
    uint256 internal constant STAKE = SettlementTestConfig.CHALLENGE_BOND;
    address internal constant BOB = address(0xB0B);

    // this contract is the sequencer and governance of every settlement here
    function setUp() public {
        usdc = new MockUSDC();
        // The claim vault answers to a settlement stand-in, so withdrawals roots can be
        // published directly. It is funded directly; no deposits enter it.
        gate = new MockSettlementGate();
        vault = new CollateralVault(address(gate), address(usdc), vm.addr(GATEWAY_PK));
        gate.setVault(address(vault));
        usdc.mint(address(vault), 1_000_000_000_000); // 1,000,000 USDC
        verifier = new MockClockVerifier();
        s = new DarkPerpSettlement(SettlementTestConfig.defaults(address(this), vm.addr(ENCLAVE_PK), verifier, GENESIS));
        vm.deal(address(this), 1_000 ether);
    }

    // --- helpers ------------------------------------------------------------------------

    function _bound(uint256 x, uint256 lo, uint256 hi) internal pure returns (uint256) {
        return lo + (x % (hi - lo + 1));
    }

    /// A settlement paired with a fresh vault, with `bond` USDC posted.
    function _liveStack(uint256 bond) internal returns (DarkPerpSettlement st, CollateralVault v) {
        st = new DarkPerpSettlement(
            SettlementTestConfig.defaults(address(this), vm.addr(ENCLAVE_PK), verifier, GENESIS)
        );
        v = new CollateralVault(address(st), address(usdc), vm.addr(GATEWAY_PK));
        st.setVault(address(v));
        if (bond > 0) {
            usdc.mint(address(this), bond);
            usdc.approve(address(st), bond);
            st.postBond(bond);
        }
    }

    function _payer(uint256 i) internal pure returns (address) {
        return address(uint160(0x9000 + i));
    }

    function _commit(uint256 i) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("commit", i));
    }

    /// Funds `from` and submits a gateway-permitted deposit as `from`; returns the call
    /// result instead of reverting.
    function _tryDeposit(CollateralVault v, address from, bytes32 commit, uint256 amount)
        internal
        returns (bool ok, bytes memory ret)
    {
        usdc.mint(from, amount);
        vm.prank(from);
        usdc.approve(address(v), amount);
        uint64 until = uint64(block.timestamp + 1 days);
        bytes memory sig = SettlementTestConfig.permitSig(vm, GATEWAY_PK, v, from, commit, amount, until);
        bytes memory data = abi.encodeCall(v.deposit, (amount, commit, until, sig));
        vm.prank(from);
        (ok, ret) = address(v).call(data);
    }

    function _deposit(CollateralVault v, address from, bytes32 commit, uint256 amount) internal {
        (bool ok,) = _tryDeposit(v, from, commit, amount);
        assertTrue(ok, "deposit");
    }

    /// Calldata settling the next batch at deposit count `n` with `depositsRoot`.
    function _settleData(DarkPerpSettlement st, bytes32 depositsRoot, uint64 n, bytes32 newRoot)
        internal
        view
        returns (bytes memory)
    {
        bytes32 prev = st.currentStateRoot();
        bytes memory proof =
            abi.encode(st.publicCommitment(prev, M, newRoot, bytes32(0), bytes32(0), bytes32(0), depositsRoot));
        return
            abi.encodeCall(
                st.settleBatch, (prev, M, newRoot, bytes32(0), bytes32(0), bytes32(0), depositsRoot, n, proof)
            );
    }

    function _settleAt(DarkPerpSettlement st, CollateralVault v, uint64 n, bytes32 newRoot) internal {
        (bool ok,) = address(st).call(_settleData(st, v.depositTipAt(n), n, newRoot));
        assertTrue(ok, "settle");
    }

    function _selector(bytes memory ret) internal pure returns (bytes4) {
        require(ret.length >= 4, "no selector");
        return bytes4(ret);
    }

    // --- withdrawals and settlement roots ---------------------------------------------

    /// A claim succeeds only for the exact authorized (to, amount, nonce); any
    /// deviation fails. Releases never exceed what was authorized.
    function testFuzz_claim_only_exact_leaf(address to, uint96 amountRaw, uint96 nonce) public {
        vm.assume(uint160(to) > 20 && to != address(vault) && to != address(this));
        vm.assume(to.code.length == 0);
        uint256 amount = (uint256(amountRaw) % 100_000_000) + 1; // up to 100 USDC
        bytes32 leaf = keccak256(abi.encodePacked(to, amount, uint256(nonce)));
        gate.publishTo(address(vault), leaf, 0);

        bytes32[] memory empty = new bytes32[](0);
        // a different amount must not claim
        vm.expectRevert(CollateralVault.BadWithdrawalProof.selector);
        vault.claim(to, amount + 1, nonce, leaf, empty);
        // a different nonce must not claim
        vm.expectRevert(CollateralVault.BadWithdrawalProof.selector);
        vault.claim(to, amount, uint256(nonce) + 1, leaf, empty);

        // the exact leaf claims exactly the authorized amount, once
        uint256 before = usdc.balanceOf(to);
        vault.claim(to, amount, nonce, vault.withdrawalsRoot(), empty);
        assertEq(usdc.balanceOf(to) - before, amount, "claimed exactly authorized");
        vm.expectRevert(CollateralVault.AlreadyClaimed.selector);
        vault.claim(to, amount, nonce, leaf, empty);
    }

    /// A proof valid for one (orderedRoot, withdrawalsRoot) must not settle a batch
    /// with any different roots — they're bound into the proven commitment (F2).
    function testFuzz_settle_binds_roots(bytes32 ordered, bytes32 withdrawals, bytes32 ordered2, bytes32 wd2) public {
        vm.assume(ordered != ordered2 || withdrawals != wd2);
        bytes32 newRoot = keccak256(abi.encodePacked(ordered, withdrawals));
        // `s` has no vault wired here, so the SEC-019 deposit head is genesis
        // (bytes32(0), 0) — the only value that settles.
        bytes memory proof =
            abi.encode(s.publicCommitment(GENESIS, M, newRoot, ordered, withdrawals, bytes32(0), bytes32(0)));

        // swapping in any different roots breaks the proof
        vm.expectRevert(DarkPerpSettlement.BadProof.selector);
        s.settleBatch(GENESIS, M, newRoot, ordered2, wd2, bytes32(0), bytes32(0), 0, proof);

        // the exact roots settle
        s.settleBatch(GENESIS, M, newRoot, ordered, withdrawals, bytes32(0), bytes32(0), 0, proof);
        assertEq(s.currentStateRoot(), newRoot, "settled with the bound roots");
    }

    /// The inclusion leaf is injective in (batchId, orderHash) for distinct inputs
    /// (no cross-batch leaf reuse that would let one proof answer another batch).
    function testFuzz_inclusion_leaf_distinct(uint256 b1, bytes32 h1, uint256 b2, bytes32 h2) public {
        vm.assume(b1 != b2 || h1 != h2);
        assertTrue(s.inclusionLeaf(b1, h1) != s.inclusionLeaf(b2, h2), "leaves distinct");
    }

    /// AUDIT (inclusionLeaf domain separation): the leaf preimage must be domain-tagged
    /// so it can NEVER collide with a MerkleLib internal node, which is a bare
    /// keccak256(abi.encodePacked(bytes32, bytes32)). Otherwise a censoring sequencer
    /// could present a crafted internal node of the ordered tree as an "inclusion leaf"
    /// for an order it never processed and evade the §2 slash. `rejectionLeaf` was
    /// already tagged; `inclusionLeaf` must be too.
    function testFuzz_inclusion_leaf_is_not_an_internal_node(uint256 batchId, bytes32 orderHash) public view {
        // the untagged 2x32-byte node shape the leaf must be distinct from
        bytes32 nodeShape = keccak256(abi.encodePacked(bytes32(batchId), orderHash));
        assertTrue(
            s.inclusionLeaf(batchId, orderHash) != nodeShape, "inclusion leaf must not equal a bare internal-node hash"
        );
    }

    // --- deposit prefix pin and refunds ------------------------------------------------

    /// A settle lands only with a count between the consumed count and the vault head
    /// and the vault's tip at exactly that count; the zero tip past the head never
    /// passes as a prefix. The consumed count only moves forward.
    function testFuzz_settle_pins_deposit_count_to_vault_prefix(uint8 dRaw, uint8 n1Raw, uint8 n2Raw, bool corruptRoot)
        public
    {
        (DarkPerpSettlement st, CollateralVault v) = _liveStack(1_000_000e6);
        uint64 d = uint64(dRaw % 6);
        for (uint256 i = 0; i < d; i++) {
            _deposit(v, _payer(i), _commit(i), 1e6 + i);
        }
        uint64 n1 = uint64(n1Raw % (d + 3));
        if (n1 > d) {
            assertEq(v.depositTipAt(n1), bytes32(0), "no tip past the head");
            (bool okPast, bytes memory ret) = address(st).call(_settleData(st, bytes32(0), n1, keccak256("past")));
            assertTrue(!okPast && _selector(ret) == DarkPerpSettlement.BadDepositCount.selector, "past the head");
            n1 = n1 % (d + 1);
        }
        _settleAt(st, v, n1, keccak256("first"));
        assertEq(uint256(st.consumedDepositCount()), n1, "first count stored");

        uint64 n2 = uint64(n2Raw % (d + 3));
        bytes32 dr = v.depositTipAt(n2);
        bool inRange = n2 >= n1 && n2 <= d;
        if (inRange && corruptRoot) dr = bytes32(uint256(dr) ^ 1);
        (bool ok, bytes memory ret2) = address(st).call(_settleData(st, dr, n2, keccak256("second")));
        if (!inRange) {
            assertTrue(!ok && _selector(ret2) == DarkPerpSettlement.BadDepositCount.selector, "count out of range");
            assertEq(uint256(st.consumedDepositCount()), n1, "count unchanged");
        } else if (corruptRoot) {
            assertTrue(!ok, "root must match the prefix");
            assertEq(
                keccak256(ret2),
                keccak256(abi.encodeWithSignature("Error(string)", "deposits: root != L1 chain prefix")),
                "prefix mismatch reason"
            );
            assertEq(uint256(st.consumedDepositCount()), n1, "count unchanged");
        } else {
            assertTrue(ok, "in-range prefix settles");
            assertEq(uint256(st.consumedDepositCount()), n2, "count advanced");
            assertTrue(st.consumedDepositCount() >= n1, "monotonic");
        }
        assertTrue(st.consumedDepositCount() <= v.depositCount(), "never above the head");
    }

    /// After close-only, exactly the deposits at or above the consumed count are
    /// refundable, each once, at principal to its payer; the credited prefix is not.
    function testFuzz_refunds_cover_exactly_the_unconsumed_suffix(uint8 dRaw, uint8 cRaw, uint256 seed) public {
        (DarkPerpSettlement st, CollateralVault v) = _liveStack(1_000_000e6);
        uint64 d = uint64(dRaw % 6) + 1;
        uint64 cons = uint64(cRaw % (d + 1));
        uint256[] memory amt = new uint256[](d);
        uint256 credited;
        uint256 suffix;
        for (uint256 i = 0; i < d; i++) {
            amt[i] = (uint256(keccak256(abi.encode(seed, i))) % 1_000e6) + 1;
            _deposit(v, _payer(i), _commit(i), amt[i]);
            if (i < cons) credited += amt[i];
            else suffix += amt[i];
        }
        _settleAt(st, v, cons, keccak256("credited"));
        assertEq(v.refundableOutstanding(), suffix, "outstanding = unconsumed principal");
        if (cons < d) {
            vm.expectRevert(CollateralVault.NotCloseOnly.selector);
            v.refundDeposit(cons, _payer(cons), _commit(cons), amt[cons], _payer(cons));
        }

        st.enterCloseOnly();
        for (uint64 i = 0; i < cons; i++) {
            vm.expectRevert(CollateralVault.NotRefundable.selector);
            v.refundDeposit(i, _payer(i), _commit(i), amt[i], _payer(i));
        }
        uint256 refunded;
        for (uint64 i = cons; i < d; i++) {
            uint256 before = usdc.balanceOf(_payer(i));
            v.refundDeposit(i, _payer(i), _commit(i), amt[i], _payer(i));
            assertEq(usdc.balanceOf(_payer(i)) - before, amt[i], "principal to its payer");
            refunded += amt[i];
        }
        assertEq(refunded, suffix, "refunds = unconsumed principal");
        assertEq(v.totalRefunded(), suffix, "accounted");
        assertEq(v.refundableOutstanding(), 0, "nothing outstanding");
        assertEq(v.tvl(), credited, "credited principal stays");
        for (uint64 i = cons; i < d; i++) {
            vm.expectRevert(CollateralVault.AlreadyRefunded.selector);
            v.refundDeposit(i, _payer(i), _commit(i), amt[i], _payer(i));
        }
        vm.expectRevert(CollateralVault.NotRefundable.selector);
        v.refundDeposit(d, _payer(0), _commit(0), amt[0], _payer(0));
    }

    // --- bond capacity -------------------------------------------------------------------

    /// The vault admits deposits up to exactly `depositCapacity()` and not one unit more.
    function testFuzz_capacity_admits_exactly_deposit_capacity(uint64 bondRaw) public {
        uint256 bond = (uint256(bondRaw) % 1e12) + 1;
        (DarkPerpSettlement st, CollateralVault v) = _liveStack(bond);
        uint256 cap = st.depositCapacity();
        assertEq(cap, ((bond + 1) * 10_000 - 1) / st.BOND_BPS(), "capacity formula");
        (bool ok, bytes memory ret) = _tryDeposit(v, _payer(0), _commit(0), cap + 1);
        assertTrue(!ok && _selector(ret) == CollateralVault.BondCapacityExceeded.selector, "one unit over");
        _deposit(v, _payer(1), _commit(1), cap);
        assertEq(st.depositCapacity(), 0, "capacity used up");
        assertTrue(st.requiredBond() <= st.sequencerBond(), "bond covers the floor");
        (ok, ret) = _tryDeposit(v, _payer(2), _commit(2), 1);
        assertTrue(!ok && _selector(ret) == CollateralVault.BondCapacityExceeded.selector, "full");
    }

    // --- challenge authorization -------------------------------------------------------

    /// An enclave authorization opens a challenge only for the exact tuple it signs:
    /// changing any field (order hash, seq, receive time, batch hint, beneficiary)
    /// makes the signature fail.
    function testFuzz_challenge_authorization_binds_every_field(
        bytes32 h,
        uint64 seq,
        uint64 recvRaw,
        uint64 hint,
        address ben,
        uint8 which
    ) public {
        vm.assume(uint160(ben) > 1);
        uint64 recv = recvRaw % 1e12;
        vm.warp(2e9);
        bytes memory sig = SettlementTestConfig.challengeSig(vm, ENCLAVE_PK, s, h, seq, recv, hint, ben);
        _expectPerturbedAuthorizationRefused(h, seq, recv, hint, ben, which, sig);

        s.challengeInclusion{value: STAKE}(h, seq, recv, hint, ben, sig);
        _assertOpened(h, ben, hint);
        vm.expectRevert(DarkPerpSettlement.ChallengeExists.selector);
        s.challengeInclusion{value: STAKE}(h, seq, recv, hint, ben, sig);
    }

    /// Submits `sig` with one field of the signed tuple changed (chosen by `which`).
    function _expectPerturbedAuthorizationRefused(
        bytes32 h,
        uint64 seq,
        uint64 recv,
        uint64 hint,
        address ben,
        uint8 which,
        bytes memory sig
    ) internal {
        which %= 5;
        if (which == 0) h = bytes32(uint256(h) ^ 1);
        else if (which == 1) seq ^= 1;
        else if (which == 2) recv ^= 1;
        else if (which == 3) hint ^= 1;
        else ben = address(uint160(ben) ^ 1);
        vm.expectRevert(DarkPerpSettlement.BadReceiptSignature.selector);
        s.challengeInclusion{value: STAKE}(h, seq, recv, hint, ben, sig);
    }

    function _assertOpened(bytes32 h, address ben, uint64 hint) internal view {
        (address storedBen, uint64 storedHint,, uint256 openBatchCount, uint256 stake, bool open) = s.challenges(h);
        assertEq(storedBen, ben, "signed beneficiary stored");
        assertEq(uint256(storedHint), uint256(hint), "hint");
        assertEq(openBatchCount, 0, "opened at batch 0");
        assertEq(stake, STAKE, "stake");
        assertTrue(open, "open");
        assertEq(s.openChallengeCount(), 1, "one open");
    }

    /// Malleable (high-s), wrong-v and wrong-length signatures are refused even though
    /// the high-s twin is a valid ECDSA signature by the enclave.
    function testFuzz_malleable_or_malformed_challenge_signature_refused(bytes32 h, uint8 badV, uint8 lenRaw) public {
        vm.warp(2e9);
        bytes32 digest = SettlementTestConfig.challengeAuthDigest(address(s), h, 1, 1000, 0, BOB);
        (uint8 v, bytes32 r, bytes32 sg) = vm.sign(ENCLAVE_PK, digest);
        uint8 flippedV = v == 27 ? 28 : 27;
        bytes32 highS = bytes32(SECP256K1_N - uint256(sg));
        assertEq(ecrecover(digest, flippedV, r, highS), vm.addr(ENCLAVE_PK), "the twin is a valid signature");
        _expectNonCanonical(h, abi.encodePacked(r, highS, flippedV));
        _expectNonCanonical(h, abi.encodePacked(r, sg, (badV == 27 || badV == 28) ? uint8(0) : badV));
        bytes memory good = abi.encodePacked(r, sg, v);
        _expectNonCanonical(h, _resized(good, lenRaw % 130));

        s.challengeInclusion{value: STAKE}(h, 1, 1000, 0, BOB, good);
        (,,,,, bool open) = s.challenges(h);
        assertTrue(open, "the canonical signature opens");
    }

    function _expectNonCanonical(bytes32 h, bytes memory sig) internal {
        vm.expectRevert(DarkPerpSettlement.NonCanonicalSignature.selector);
        s.challengeInclusion{value: STAKE}(h, 1, 1000, 0, BOB, sig);
    }

    /// `sig` truncated or zero-extended to `len` bytes (never 65).
    function _resized(bytes memory sig, uint256 len) internal pure returns (bytes memory out) {
        if (len == 65) len = 64;
        out = new bytes(len);
        for (uint256 i = 0; i < len && i < sig.length; i++) {
            out[i] = sig[i];
        }
    }

    /// A slash pays `min(bond, cap)` to the signed beneficiary and refunds the stake to
    /// the submitter; settlement continues. Below the cap only the beneficiary may trigger
    /// it at once, and the submitter after a further liveness window.
    function testFuzz_slash_pays_capped_fine_and_settlement_continues(uint256 bondRaw, bool byStaker) public {
        uint256 bond = bondRaw % (3 * CAP);
        (DarkPerpSettlement st, CollateralVault v) = _liveStack(bond);
        vm.warp(1_000_000);
        address ben = address(0xBE4E);
        address staker = address(0x57A4);
        vm.deal(staker, 10 ether);
        bytes32 h = keccak256("never-settled");
        bytes memory sig = SettlementTestConfig.challengeSig(vm, ENCLAVE_PK, st, h, 1, 1000, 0, ben);
        vm.prank(staker);
        st.challengeInclusion{value: STAKE}(h, 1, 1000, 0, ben, sig);

        vm.expectRevert(DarkPerpSettlement.NoProgress.selector);
        st.slashUnanswered(h);
        _settleAt(st, v, 0, keccak256("b1"));
        vm.expectRevert(DarkPerpSettlement.NoProgress.selector);
        st.slashUnanswered(h);
        _settleAt(st, v, 0, keccak256("b2"));
        vm.roll(block.number + SettlementTestConfig.CHALLENGE_GRACE_BLOCKS);
        vm.expectRevert(DarkPerpSettlement.ChallengeNotExpired.selector);
        st.slashUnanswered(h);
        vm.roll(block.number + 1);

        uint256 payout = bond < CAP ? bond : CAP;
        address caller = address(0xCA11E7);
        if (payout < CAP) {
            vm.prank(caller);
            vm.expectRevert(DarkPerpSettlement.ShortBondSlashRestricted.selector);
            st.slashUnanswered(h);
            caller = byStaker ? staker : ben;
            if (byStaker) {
                vm.prank(staker);
                vm.expectRevert(DarkPerpSettlement.ShortBondSlashRestricted.selector);
                st.slashUnanswered(h);
                vm.roll(block.number + st.livenessTimeoutBlocks());
            }
        }
        vm.prank(caller);
        st.slashUnanswered(h);
        assertEq(st.sequencerBond(), bond - payout, "bond fined");
        assertEq(st.pendingUsdc(ben), payout, "fine to the beneficiary");
        assertEq(st.pendingEth(staker), STAKE, "stake to the submitter");
        assertEq(st.slashCount(), 1, "counted");
        assertTrue(!st.closeOnly(), "settlement continues");
        assertTrue(st.challengeResolved(h), "resolved");
        assertEq(st.openChallengeCount(), 0, "closed");

        _settleAt(st, v, 0, keccak256("b3"));
        assertEq(st.batchCount(), 3, "still settling");
        vm.prank(ben);
        st.claimUsdc();
        assertEq(usdc.balanceOf(ben), payout, "fine claimed");
    }

    // --- deposit permit ------------------------------------------------------------------

    /// A gateway permit admits a deposit only for the exact (sender, commit, amount,
    /// deadline) it signs; each commit enters the chain once.
    function testFuzz_permit_binds_every_field(
        address from,
        bytes32 commit,
        uint96 amountRaw,
        uint32 lifetime,
        uint8 which
    ) public {
        vm.assume(from != address(0) && uint160(from) > 0x10000 && from.code.length == 0);
        vm.assume(from != address(vm));
        (, CollateralVault v) = _liveStack(1_000_000e6);
        uint256 amount = (uint256(amountRaw) % 1_000e6) + 1;
        uint64 until = uint64(block.timestamp) + uint64(lifetime);
        bytes memory sig = SettlementTestConfig.permitSig(vm, GATEWAY_PK, v, from, commit, amount, until);
        usdc.mint(from, amount + 1);
        vm.prank(from);
        usdc.approve(address(v), type(uint256).max);
        _expectPerturbedPermitRefused(v, from, commit, amount, until, which, sig);

        vm.prank(from);
        v.deposit(amount, commit, until, sig);
        bytes32 leaf = keccak256(abi.encodePacked(from, commit, amount, uint256(0)));
        assertEq(v.depositChainTip(), keccak256(abi.encodePacked(bytes32(0), leaf)), "leaf folded");
        assertTrue(v.usedOwnerCommit(commit), "commit used");

        // A re-signed permit for the same commit with a later deadline is refused.
        bytes memory again = SettlementTestConfig.permitSig(vm, GATEWAY_PK, v, from, commit, 1, until + 1);
        vm.prank(from);
        vm.expectRevert(CollateralVault.OwnerCommitUsed.selector);
        v.deposit(1, commit, until + 1, again);
    }

    /// Submits the permit `sig` with one field changed (chosen by `which`); the sender
    /// change submits from a different address.
    function _expectPerturbedPermitRefused(
        CollateralVault v,
        address from,
        bytes32 commit,
        uint256 amount,
        uint64 until,
        uint8 which,
        bytes memory sig
    ) internal {
        which %= 4;
        if (which == 0) from = address(uint160(from) ^ 1);
        else if (which == 1) commit = bytes32(uint256(commit) ^ 1);
        else if (which == 2) amount += 1;
        else until += 1;
        vm.prank(from);
        vm.expectRevert(CollateralVault.BadGatewaySig.selector);
        v.deposit(amount, commit, until, sig);
    }

    receive() external payable {}
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MiniTest} from "./utils/MiniTest.sol";
import {SettlementTestConfig} from "./utils/SettlementTestConfig.sol";
import {MockSettlementGate} from "./mocks/MockSettlementGate.sol";
import {MockClockVerifier} from "./mocks/MockClockVerifier.sol";
import {CollateralVault} from "../src/CollateralVault.sol";
import {DarkPerpSettlement} from "../src/DarkPerpSettlement.sol";
import {MockUSDC} from "../src/mocks/MockUSDC.sol";

/// Cheatcodes these suites need beyond MiniTest's subset (same cheatcode address).
interface VaultTestVm {
    struct Log {
        bytes32[] topics;
        bytes data;
        address emitter;
    }

    function recordLogs() external;
    function getRecordedLogs() external returns (Log[] memory);
    function etch(address target, bytes calldata code) external;
}

/// The token surface the deposit helpers drive; MockUSDC and ScriptedToken both have it.
interface ITestToken {
    function mint(address to, uint256 amount) external;
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

interface ITokenObserver {
    function onTokenMove(bool pull, address from, address to, uint256 amount) external;
}

/// Test-only ERC20 that can report failure by returning false, and that calls an
/// observer before it moves balances, so a test can inspect the vault mid-transfer and
/// re-enter it.
contract ScriptedToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    bool public failTransfer;
    bool public failTransferFrom;
    ITokenObserver public observer;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function setFailures(bool onTransfer, bool onTransferFrom) external {
        failTransfer = onTransfer;
        failTransferFrom = onTransferFrom;
    }

    function setObserver(ITokenObserver o) external {
        observer = o;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        if (failTransfer) return false;
        if (address(observer) != address(0)) observer.onTokenMove(false, msg.sender, to, amount);
        _move(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        if (failTransferFrom) return false;
        uint256 a = allowance[from][msg.sender];
        require(a >= amount, "allowance");
        allowance[from][msg.sender] = a - amount;
        if (address(observer) != address(0)) observer.onTokenMove(true, from, to, amount);
        _move(from, to, amount);
        return true;
    }

    function _move(address from, address to, uint256 amount) internal {
        require(balanceOf[from] >= amount, "balance");
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
    }
}

/// Settlement stand-in whose every read refuses to run outside a static context: each
/// getter first tries a storage write through a self-call, which only fails under
/// STATICCALL. A vault flow that completes against it read its settlement only through
/// STATICCALLs.
contract StaticOnlyGate {
    address internal paired;
    bool internal closed;
    uint64 internal consumed;
    uint256 public probeWrites;

    function setPaired(address v) external {
        paired = v;
    }

    function setClosed(bool v) external {
        closed = v;
    }

    function setConsumed(uint64 c) external {
        consumed = c;
    }

    function probe() external {
        probeWrites += 1;
    }

    function _requireStatic() internal {
        (bool wrote,) = address(this).call{gas: 50_000}(abi.encodeWithSelector(this.probe.selector));
        require(!wrote, "settlement read outside a static context");
    }

    function depositGate(uint256) external returns (uint8) {
        _requireStatic();
        if (msg.sender != paired) return 3;
        return closed ? 1 : 0;
    }

    function closeOnly() external returns (bool) {
        _requireStatic();
        return closed;
    }

    function consumedDepositCount() external returns (uint64) {
        _requireStatic();
        return consumed;
    }

    function vault() external returns (address) {
        _requireStatic();
        return paired;
    }

    function publishTo(address v, bytes32 root, uint256 epoch) external {
        CollateralVault(v).publishWithdrawals(root, epoch);
    }
}

/// Shared fixtures for the vault suites.
contract VaultTestBase is MiniTest {
    VaultTestVm internal constant vmx = VaultTestVm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

    uint256 internal constant USD = 1e6;
    /// Gateway permit signing key (test only).
    uint256 internal constant GW_PK = 0x6A7E;
    /// A key that is not the gateway's.
    uint256 internal constant OTHER_PK = 0xBEEF;
    uint256 internal constant VALID_FOR = 30 minutes;
    uint256 internal constant T0 = 1_760_000_000;
    uint256 internal constant INT128_MAX = uint256(uint128(type(int128).max));

    address internal alice = address(0xA11CE);
    address internal bob = address(0xB0B);
    address internal carol = address(0xCA201);

    function _commit(uint256 i) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("vault-test/owner-commit", i));
    }

    function _deadline() internal view returns (uint64) {
        return uint64(block.timestamp + VALID_FOR);
    }

    function _permit(CollateralVault v, uint256 pk, address from, bytes32 commit, uint256 amount, uint64 validUntil)
        internal
        view
        returns (bytes memory)
    {
        return SettlementTestConfig.permitSig(vm, pk, v, from, commit, amount, validUntil);
    }

    /// Mints `amount` to `who`, approves `v`, and deposits under a fresh gateway permit.
    function _depositInto(CollateralVault v, ITestToken t, address who, uint256 amount, bytes32 commit)
        internal
        returns (uint64 id)
    {
        t.mint(who, amount);
        uint64 until = _deadline();
        bytes memory sig = _permit(v, GW_PK, who, commit, amount, until);
        vm.startPrank(who);
        t.approve(address(v), amount);
        v.deposit(amount, commit, until, sig);
        vm.stopPrank();
        id = v.depositCount() - 1;
    }

    function _wleaf(address to, uint256 amount, uint256 nonce) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(to, amount, nonce));
    }

    function _pair(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return a <= b ? keccak256(abi.encodePacked(a, b)) : keccak256(abi.encodePacked(b, a));
    }

    function _proof1(bytes32 sibling) internal pure returns (bytes32[] memory p) {
        p = new bytes32[](1);
        p[0] = sibling;
    }

    function _noProof() internal pure returns (bytes32[] memory p) {
        p = new bytes32[](0);
    }

    function _depositLeaf(address from, bytes32 commit, uint256 amount, uint64 id) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(from, commit, amount, uint256(id)));
    }

    /// The single log `emitter` produced in `logs`.
    function _onlyLogOf(VaultTestVm.Log[] memory logs, address emitter)
        internal
        pure
        returns (VaultTestVm.Log memory l)
    {
        uint256 found;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].emitter == emitter) {
                l = logs[i];
                found++;
            }
        }
        require(found == 1, "expected exactly one log from the emitter");
    }
}

contract CollateralVaultTest is VaultTestBase, ITokenObserver {
    uint256 internal constant SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    // Deposit-chain known-answer vectors, shared with crates/perp-core/src/merkle.rs
    // (KAT_DEPOSIT_LEAF / KAT_DEPOSIT_TIP2). The leaf and fold encodings did not change.
    // Leaf: keccak256(abi.encodePacked(address from, bytes32 ownerCommit, uint256 amount, uint256 id))
    // Fold: keccak256(abi.encodePacked(bytes32 tip, bytes32 leaf)), genesis tip = bytes32(0)
    address internal constant KAT_FROM_0 = address(0x1111111111111111111111111111111111111111);
    bytes32 internal constant KAT_OWNER_COMMIT_0 =
        bytes32(uint256(0x2222222222222222222222222222222222222222222222222222222222222222));
    uint256 internal constant KAT_AMOUNT_0 = 1000;
    address internal constant KAT_FROM_1 = address(0x3333333333333333333333333333333333333333);
    bytes32 internal constant KAT_OWNER_COMMIT_1 =
        bytes32(uint256(0x4444444444444444444444444444444444444444444444444444444444444444));
    uint256 internal constant KAT_AMOUNT_1 = 500;
    bytes32 internal constant KAT_LEAF = 0xc73050f50b59f4f5e979a977daca61b851dde0b8783079f19612eaa372eea829;
    bytes32 internal constant KAT_TIP2 = 0x5b73a880215f57b806542be075aff06956e28269482bf9b0db854b480e7ee5ca;

    // Deposit-permit known-answer vector (v2 digest, 200-byte preimage). The gateway's
    // permit signer pins the same inputs and digest. Computed independently with
    // `cast keccak` over the hand-concatenated preimage.
    address internal constant PERMIT_KAT_VAULT = 0x1111111111111111111111111111111111111111;
    address internal constant PERMIT_KAT_FROM = 0x2222222222222222222222222222222222222222;
    bytes32 internal constant PERMIT_KAT_COMMIT = 0x3333333333333333333333333333333333333333333333333333333333333333;
    uint256 internal constant PERMIT_KAT_AMOUNT = 1000;
    uint64 internal constant PERMIT_KAT_VALID_UNTIL = 1_800_000_000;
    uint256 internal constant PERMIT_KAT_CHAIN = 84532;
    bytes32 internal constant PERMIT_KAT_DIGEST = 0xb487c678ab8b02ccbd35a03ea1d01c38f0183258f2c23b56f3fb5096096c07cc;

    bytes32 internal constant DEPOSIT_TOPIC0 = 0xdf3f00354434921901d8a49f26c4b0e4a907d497e57f2e9478e9ba4ea43eb0f9;
    bytes32 internal constant DEPOSIT_REFUNDED_TOPIC0 =
        0xa80355a5c92c1a6019875d4ebea85e10c6d0b2412eee86bab0b577c1c78fcf72;

    uint256 internal constant A0 = 1_000 * USD;
    uint256 internal constant A1 = 250 * USD;
    uint256 internal constant A2 = 75 * USD;

    CollateralVault internal vault;
    MockUSDC internal usdc;
    MockSettlementGate internal gate;
    uint256 internal epoch;

    // Scripted-token stack (failure and mid-transfer observation tests).
    ScriptedToken internal stok;
    MockSettlementGate internal sgate;
    CollateralVault internal svault;

    // Observer state.
    uint8 internal constant HOOK_DEPOSIT = 1;
    uint8 internal constant HOOK_REFUND = 2;
    uint8 internal constant HOOK_CLAIM = 3;
    uint8 internal hookMode;
    bool internal hookFired;
    bool internal hookSawMark;
    uint256 internal hookSawTotal;
    uint256 internal hookSawTvl;
    uint256 internal hookSawCount;
    bool internal hookReentrySucceeded;
    bytes4 internal hookReentryError;
    uint64 internal hookId;
    address internal hookFrom;
    bytes32 internal hookCommit;
    uint256 internal hookAmount;
    uint256 internal hookNonce;
    bytes32 internal hookRoot;
    uint64 internal hookUntil;
    bytes internal hookSig;

    function setUp() public {
        vm.warp(T0);
        vm.roll(1_000);
        usdc = new MockUSDC();
        gate = new MockSettlementGate();
        vault = new CollateralVault(address(gate), address(usdc), vm.addr(GW_PK));
        gate.setVault(address(vault));
    }

    // ------------------------------------------------------------------
    // helpers
    // ------------------------------------------------------------------

    function _sig(address from, bytes32 commit, uint256 amount, uint64 validUntil)
        internal
        view
        returns (bytes memory)
    {
        return _permit(vault, GW_PK, from, commit, amount, validUntil);
    }

    function _deposit(address who, uint256 amount, bytes32 commit) internal returns (uint64) {
        return _depositInto(vault, ITestToken(address(usdc)), who, amount, commit);
    }

    /// Funds `who` and approves the vault without depositing.
    function _fund(address who, uint256 amount) internal {
        usdc.mint(who, amount);
        vm.prank(who);
        usdc.approve(address(vault), type(uint256).max);
    }

    /// Calls `deposit` as `who` under a valid permit and expects `err`.
    function _expectDepositRevert(address who, uint256 amount, bytes32 commit, bytes4 err) internal {
        uint64 until = _deadline();
        bytes memory sig = _sig(who, commit, amount, until);
        vm.prank(who);
        vm.expectRevert(err);
        vault.deposit(amount, commit, until, sig);
    }

    function _publish(bytes32 root) internal {
        gate.publishTo(address(vault), root, epoch++);
    }

    function _enterCloseOnly(uint64 consumed) internal {
        gate.setConsumedDepositCount(consumed);
        gate.setCloseOnly(true);
    }

    /// ids 0 (alice, A0), 1 (bob, A1) and 2 (alice, A2), each in its own block.
    function _threeDeposits() internal {
        _deposit(alice, A0, _commit(10));
        vm.roll(block.number + 1);
        _deposit(bob, A1, _commit(11));
        vm.roll(block.number + 1);
        _deposit(alice, A2, _commit(12));
    }

    function _useScriptedStack() internal {
        stok = new ScriptedToken();
        sgate = new MockSettlementGate();
        svault = new CollateralVault(address(sgate), address(stok), vm.addr(GW_PK));
        sgate.setVault(address(svault));
    }

    function _scriptedDeposit(address who, uint256 amount, bytes32 commit) internal returns (uint64) {
        return _depositInto(svault, ITestToken(address(stok)), who, amount, commit);
    }

    /// Token observer: records what the vault looks like mid-transfer, then re-enters it once.
    function onTokenMove(bool, address, address, uint256) external {
        if (msg.sender != address(stok) || hookFired) return;
        hookFired = true;
        if (hookMode == HOOK_DEPOSIT) {
            hookSawMark = svault.usedOwnerCommit(hookCommit);
            hookSawCount = svault.depositCount();
            try svault.deposit(hookAmount, hookCommit, hookUntil, hookSig) {
                hookReentrySucceeded = true;
            } catch (bytes memory err) {
                hookReentryError = bytes4(err);
            }
        } else if (hookMode == HOOK_REFUND) {
            hookSawMark = svault.depositRefunded(hookId);
            hookSawTotal = svault.totalRefunded();
            hookSawTvl = svault.tvl();
            try svault.refundDeposit(hookId, hookFrom, hookCommit, hookAmount, hookFrom) {
                hookReentrySucceeded = true;
            } catch (bytes memory err) {
                hookReentryError = bytes4(err);
            }
        } else if (hookMode == HOOK_CLAIM) {
            hookSawMark = svault.claimed(_wleaf(hookFrom, hookAmount, hookNonce));
            hookSawTotal = svault.totalWithdrawn();
            hookSawTvl = svault.tvl();
            try svault.claim(hookFrom, hookAmount, hookNonce, hookRoot, _noProof()) {
                hookReentrySucceeded = true;
            } catch (bytes memory err) {
                hookReentryError = bytes4(err);
            }
        }
    }

    // ------------------------------------------------------------------
    // construction, constants, ABI
    // ------------------------------------------------------------------

    function test_constructor_rejects_zero_gateway_signer() public {
        vm.expectRevert(CollateralVault.ZeroGatewaySigner.selector);
        new CollateralVault(address(gate), address(usdc), address(0));
    }

    function test_constructor_records_settlement_token_and_signer() public view {
        assertEq(vault.settlement(), address(gate), "settlement");
        assertEq(address(vault.token()), address(usdc), "token");
        assertEq(vault.gatewaySigner(), vm.addr(GW_PK), "gateway signer");
        assertEq(vault.depositCount(), 0, "no deposits");
        assertEq(vault.depositChainTip(), bytes32(0), "genesis tip");
        assertEq(vault.tvl(), 0, "no tvl");
        assertEq(vault.totalRefunded(), 0, "no refunds");
        assertEq(vault.refundableOutstanding(), 0, "nothing outstanding");
    }

    function test_permit_tag_is_the_versioned_domain_constant() public view {
        assertEq(vault.DEPOSIT_PERMIT_TAG(), keccak256("arcora:deposit-permit:v2"), "tag preimage");
        assertEq(
            vault.DEPOSIT_PERMIT_TAG(), 0x64f75800264cb4053b5b671aa4a797e49b39732e10c2ad3768fceffb4b2c0bb4, "tag value"
        );
        assertEq(vault.DEPOSIT_PERMIT_TAG(), SettlementTestConfig.DEPOSIT_PERMIT_TAG, "helper tag");
    }

    function test_selectors_and_event_topics_are_pinned() public view {
        assertTrue(CollateralVault.deposit.selector == bytes4(0xa1059e34), "deposit(uint256,bytes32,uint64,bytes)");
        assertTrue(
            CollateralVault.refundDeposit.selector == bytes4(0xb07e8ad3),
            "refundDeposit(uint64,address,bytes32,uint256,address)"
        );
        assertTrue(CollateralVault.permitDigest.selector == bytes4(0x912733da), "permitDigest");
        assertTrue(CollateralVault.depositBlock.selector == bytes4(0x24680e53), "depositBlock");
        assertTrue(CollateralVault.cumulativeDepositedAt.selector == bytes4(0xaf8f1957), "cumulativeDepositedAt");
        assertTrue(CollateralVault.refundableOutstanding.selector == bytes4(0x92fc1d19), "refundableOutstanding");
        assertTrue(vault.depositMeta.selector == bytes4(0xa496b413), "depositMeta");
        assertTrue(vault.usedOwnerCommit.selector == bytes4(0xb9108d80), "usedOwnerCommit");
        assertTrue(vault.depositRefunded.selector == bytes4(0xb9e279f1), "depositRefunded");
        assertTrue(vault.totalRefunded.selector == bytes4(0xd9082962), "totalRefunded");
        assertEq(CollateralVault.Deposit.selector, DEPOSIT_TOPIC0, "Deposit topic is unchanged");
        assertEq(CollateralVault.DepositRefunded.selector, DEPOSIT_REFUNDED_TOPIC0, "DepositRefunded topic");
    }

    // ------------------------------------------------------------------
    // permit digest
    // ------------------------------------------------------------------

    function test_permit_digest_known_answer() public {
        // Run the vault's own code at the vector's address on the vector's chain.
        vmx.etch(PERMIT_KAT_VAULT, address(vault).code);
        uint256 chainBefore = block.chainid;
        vm.chainId(PERMIT_KAT_CHAIN);

        bytes memory preimage = abi.encodePacked(
            keccak256("arcora:deposit-permit:v2"),
            bytes32(PERMIT_KAT_CHAIN),
            bytes20(PERMIT_KAT_VAULT),
            bytes20(PERMIT_KAT_FROM),
            PERMIT_KAT_COMMIT,
            bytes32(PERMIT_KAT_AMOUNT),
            bytes32(uint256(PERMIT_KAT_VALID_UNTIL))
        );
        assertEq(
            preimage.length,
            200,
            "preimage is tag 32 + chainid 32 + vault 20 + from 20 + commit 32 + amount 32 + validUntil 32"
        );
        assertEq(keccak256(preimage), PERMIT_KAT_DIGEST, "hand-packed preimage matches the vector");
        assertEq(
            CollateralVault(PERMIT_KAT_VAULT)
                .permitDigest(PERMIT_KAT_FROM, PERMIT_KAT_COMMIT, PERMIT_KAT_AMOUNT, PERMIT_KAT_VALID_UNTIL),
            PERMIT_KAT_DIGEST,
            "vault digest matches the vector"
        );
        assertEq(
            SettlementTestConfig.permitDigest(
                PERMIT_KAT_VAULT, PERMIT_KAT_FROM, PERMIT_KAT_COMMIT, PERMIT_KAT_AMOUNT, PERMIT_KAT_VALID_UNTIL
            ),
            PERMIT_KAT_DIGEST,
            "test helper digest matches the vector"
        );
        vm.chainId(chainBefore);
    }

    function test_permit_digest_binds_every_field() public {
        address from = alice;
        bytes32 commit = _commit(1);
        uint256 amount = 5 * USD;
        uint64 until = _deadline();
        bytes32 base = vault.permitDigest(from, commit, amount, until);
        assertEq(base, SettlementTestConfig.permitDigest(address(vault), from, commit, amount, until), "local helper");
        assertTrue(base != vault.permitDigest(bob, commit, amount, until), "payer is bound");
        assertTrue(base != vault.permitDigest(from, _commit(2), amount, until), "owner commit is bound");
        assertTrue(base != vault.permitDigest(from, commit, amount + 1, until), "amount is bound");
        assertTrue(base != vault.permitDigest(from, commit, amount, until + 1), "deadline is bound");
        CollateralVault other = new CollateralVault(address(gate), address(usdc), vm.addr(GW_PK));
        assertTrue(base != other.permitDigest(from, commit, amount, until), "vault is bound");
        uint256 chainBefore = block.chainid;
        vm.chainId(chainBefore + 1);
        assertTrue(base != vault.permitDigest(from, commit, amount, until), "chain is bound");
        vm.chainId(chainBefore);
    }

    function test_permit_over_the_untagged_digest_is_refused() public {
        // The earlier permit shape (no domain tag, no deadline) must not authorize anything.
        uint256 amount = 1_000;
        bytes32 commit = _commit(7);
        _fund(alice, amount);
        bytes32 untagged = keccak256(abi.encodePacked(block.chainid, address(vault), alice, commit, amount));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(GW_PK, untagged);
        bytes memory sig = abi.encodePacked(r, s, v);
        uint64 until = _deadline();
        vm.prank(alice);
        vm.expectRevert(CollateralVault.BadGatewaySig.selector);
        vault.deposit(amount, commit, until, sig);
        assertEq(vault.depositCount(), 0, "nothing entered the chain");
    }

    // ------------------------------------------------------------------
    // deposit: bookkeeping
    // ------------------------------------------------------------------

    function test_deposit_accrues_totals_and_tvl() public {
        _deposit(alice, 3_000 * USD, _commit(1));
        assertEq(vault.totalDeposited(), 3_000 * USD, "deposit tracked");
        assertEq(usdc.balanceOf(address(vault)), 3_000 * USD, "vault holds USDC");
        assertEq(vault.tvl(), 3_000 * USD, "tvl reflects the deposit");
        assertTrue(vault.usedOwnerCommit(_commit(1)), "commit marked");
        assertFalse(vault.usedOwnerCommit(_commit(2)), "other commits untouched");
    }

    function test_deposit_meta_records_landing_block_and_prefix_sums() public {
        uint256 b0 = block.number;
        _threeDeposits();
        (uint64 blk0, uint192 cum0) = vault.depositMeta(0);
        (uint64 blk1, uint192 cum1) = vault.depositMeta(1);
        (uint64 blk2, uint192 cum2) = vault.depositMeta(2);
        assertEq(blk0, b0, "id 0 block");
        assertEq(blk1, b0 + 1, "id 1 block");
        assertEq(blk2, b0 + 2, "id 2 block");
        assertEq(cum0, A0, "id 0 cumulative");
        assertEq(cum1, A0 + A1, "id 1 cumulative");
        assertEq(cum2, A0 + A1 + A2, "id 2 cumulative");
        assertEq(vault.depositBlock(0), b0, "depositBlock(0)");
        assertEq(vault.depositBlock(2), b0 + 2, "depositBlock(2)");
        assertEq(vault.cumulativeDepositedAt(0), 0, "empty prefix");
        assertEq(vault.cumulativeDepositedAt(1), A0, "prefix 1");
        assertEq(vault.cumulativeDepositedAt(2), A0 + A1, "prefix 2");
        assertEq(vault.cumulativeDepositedAt(3), vault.totalDeposited(), "full prefix equals the total");
    }

    function test_views_for_missing_ids_read_zero() public {
        assertEq(vault.depositBlock(0), 0, "no deposit 0 yet");
        assertEq(vault.cumulativeDepositedAt(0), 0, "empty prefix");
        assertEq(vault.cumulativeDepositedAt(1), 0, "prefix past the head");
        _deposit(alice, 10 * USD, _commit(1));
        assertEq(vault.depositBlock(1), 0, "id past the head");
        assertEq(vault.depositBlock(type(uint64).max), 0, "largest id");
        assertEq(vault.cumulativeDepositedAt(2), 0, "prefix past the head reads zero, like depositTipAt");
        assertEq(vault.cumulativeDepositedAt(type(uint64).max), 0, "largest prefix");
    }

    function test_deposit_event_layout_is_unchanged() public {
        uint256 amount = 250 * USD;
        bytes32 commit = _commit(1);
        usdc.mint(alice, amount);
        uint64 until = _deadline();
        bytes memory sig = _sig(alice, commit, amount, until);
        vm.prank(alice);
        usdc.approve(address(vault), amount);
        vmx.recordLogs();
        vm.prank(alice);
        vault.deposit(amount, commit, until, sig);
        VaultTestVm.Log memory l = _onlyLogOf(vmx.getRecordedLogs(), address(vault));
        assertEq(l.topics.length, 3, "two indexed fields");
        assertEq(l.topics[0], DEPOSIT_TOPIC0, "topic0");
        assertEq(l.topics[1], bytes32(uint256(uint160(alice))), "payer");
        assertEq(l.topics[2], commit, "owner commit");
        assertEq(keccak256(l.data), keccak256(abi.encode(amount, uint64(0), vault.depositChainTip())), "data");
    }

    /// The leaf preimage is 20 + 32 + 32 + 32 bytes, the address not left-padded.
    function test_deposit_leaf_encoding() public pure {
        bytes memory preimage =
            abi.encodePacked(bytes20(KAT_FROM_0), KAT_OWNER_COMMIT_0, bytes32(KAT_AMOUNT_0), bytes32(uint256(0)));
        assertEq(preimage.length, 116, "packed leaf preimage is 20+32+32+32 bytes");
        assertEq(keccak256(preimage), KAT_LEAF, "hand-packed leaf matches the shared vector");
        assertEq(
            keccak256(abi.encodePacked(KAT_FROM_0, KAT_OWNER_COMMIT_0, KAT_AMOUNT_0, uint256(0))),
            KAT_LEAF,
            "vault leaf expression matches the shared vector"
        );
    }

    function test_deposit_advances_chain_matching_shared_vector() public {
        assertEq(vault.depositChainTip(), bytes32(0), "genesis tip is zero");
        _deposit(KAT_FROM_0, KAT_AMOUNT_0, KAT_OWNER_COMMIT_0);
        assertEq(vault.depositCount(), 1, "one deposit folded");
        assertEq(
            vault.depositChainTip(),
            keccak256(abi.encodePacked(bytes32(0), KAT_LEAF)),
            "first deposit folds id 0 (pre-increment count); the permit is not part of the leaf"
        );
        _deposit(KAT_FROM_1, KAT_AMOUNT_1, KAT_OWNER_COMMIT_1);
        assertEq(vault.depositCount(), 2, "two deposits folded");
        assertEq(vault.depositChainTip(), KAT_TIP2, "tip matches the shared two-deposit vector");
    }

    function test_deposit_chain_is_order_sensitive() public {
        _deposit(KAT_FROM_1, KAT_AMOUNT_1, KAT_OWNER_COMMIT_1);
        _deposit(KAT_FROM_0, KAT_AMOUNT_0, KAT_OWNER_COMMIT_0);
        assertEq(vault.depositCount(), 2, "two deposits folded");
        assertTrue(vault.depositChainTip() != KAT_TIP2, "reordered deposits give a different tip");
    }

    function test_depositTipAt_records_every_prefix() public {
        assertEq(vault.depositTipAt(0), bytes32(0), "prefix 0 is the genesis tip");
        _deposit(KAT_FROM_0, KAT_AMOUNT_0, KAT_OWNER_COMMIT_0);
        bytes32 t1 = vault.depositChainTip();
        assertEq(vault.depositTipAt(1), t1, "prefix 1");
        _deposit(KAT_FROM_1, KAT_AMOUNT_1, KAT_OWNER_COMMIT_1);
        assertEq(vault.depositTipAt(2), vault.depositChainTip(), "prefix 2 is the live head");
        assertEq(vault.depositTipAt(2), KAT_TIP2, "prefix 2 matches the shared vector");
        assertEq(vault.depositTipAt(1), t1, "earlier prefix preserved");
        assertEq(vault.depositTipAt(0), bytes32(0), "genesis prefix never written");
        assertEq(vault.depositTipAt(3), bytes32(0), "prefix past the head reads zero");
    }

    function test_deadline_is_inclusive() public {
        uint256 amount = 10 * USD;
        bytes32 commit = _commit(1);
        uint64 until = uint64(block.timestamp);
        bytes memory sig = _sig(alice, commit, amount, until);
        _fund(alice, amount);
        vm.prank(alice);
        vault.deposit(amount, commit, until, sig);
        assertEq(vault.depositCount(), 1, "a permit is valid through its deadline second");
    }

    function test_amount_at_int128_max_is_accepted() public {
        _deposit(alice, INT128_MAX, _commit(1));
        assertEq(vault.totalDeposited(), INT128_MAX, "largest amount accepted");
        (, uint192 cum) = vault.depositMeta(0);
        assertEq(cum, INT128_MAX, "prefix sum holds the largest amount");
        _deposit(bob, INT128_MAX, _commit(2));
        assertEq(vault.cumulativeDepositedAt(2), 2 * INT128_MAX, "prefix sums accumulate past 128 bits");
    }

    // ------------------------------------------------------------------
    // deposit: refusals, in check order
    // ------------------------------------------------------------------

    function test_zero_amount_is_refused() public {
        _fund(alice, 1);
        _expectDepositRevert(alice, 0, _commit(1), CollateralVault.BadAmount.selector);
    }

    function test_amount_above_int128_max_is_refused() public {
        _expectDepositRevert(alice, INT128_MAX + 1, _commit(1), CollateralVault.BadAmount.selector);
        _expectDepositRevert(alice, type(uint256).max, _commit(2), CollateralVault.BadAmount.selector);
        assertEq(vault.depositCount(), 0, "nothing entered the chain");
    }

    function test_amount_bound_is_checked_first() public {
        uint64 expired = uint64(block.timestamp - 1);
        gate.setForcedGate(1);
        vm.prank(alice);
        vm.expectRevert(CollateralVault.BadAmount.selector);
        vault.deposit(0, _commit(1), expired, "");
        vm.prank(alice);
        vm.expectRevert(CollateralVault.BadAmount.selector);
        vault.deposit(INT128_MAX + 1, _commit(1), expired, "");
    }

    function test_close_only_gate_maps_to_InCloseOnly() public {
        gate.setCloseOnly(true);
        _expectDepositRevert(alice, 10 * USD, _commit(1), CollateralVault.InCloseOnly.selector);
        gate.setCloseOnly(false);
        gate.setForcedGate(1);
        _expectDepositRevert(alice, 10 * USD, _commit(1), CollateralVault.InCloseOnly.selector);
    }

    function test_capacity_gate_maps_to_BondCapacityExceeded() public {
        gate.setMaxTvl(100 * USD);
        _expectDepositRevert(alice, 100 * USD + 1, _commit(1), CollateralVault.BondCapacityExceeded.selector);
        gate.setMaxTvl(type(uint256).max);
        gate.setForcedGate(2);
        _expectDepositRevert(alice, 1, _commit(1), CollateralVault.BondCapacityExceeded.selector);
    }

    function test_unpaired_or_unknown_gate_codes_map_to_DepositsPaused() public {
        gate.setVault(address(0));
        _expectDepositRevert(alice, 10 * USD, _commit(1), CollateralVault.DepositsPaused.selector);
        gate.setVault(address(0xDEAD));
        _expectDepositRevert(alice, 10 * USD, _commit(1), CollateralVault.DepositsPaused.selector);
        gate.setVault(address(vault));
        uint8[4] memory codes = [uint8(3), 4, 128, 255];
        for (uint256 i = 0; i < codes.length; i++) {
            gate.setForcedGate(codes[i]);
            _expectDepositRevert(alice, 10 * USD, _commit(1), CollateralVault.DepositsPaused.selector);
        }
        gate.setForcedGate(0);
        _deposit(alice, 10 * USD, _commit(1));
        assertEq(vault.depositCount(), 1, "an open gate admits the deposit");
    }

    function test_a_vault_the_settlement_is_not_paired_with_cannot_take_deposits() public {
        CollateralVault foreign = new CollateralVault(address(gate), address(usdc), vm.addr(GW_PK));
        uint64 until = _deadline();
        bytes memory sig = _permit(foreign, GW_PK, alice, _commit(1), 10 * USD, until);
        usdc.mint(alice, 10 * USD);
        vm.startPrank(alice);
        usdc.approve(address(foreign), 10 * USD);
        vm.expectRevert(CollateralVault.DepositsPaused.selector);
        foreign.deposit(10 * USD, _commit(1), until, sig);
        vm.stopPrank();
        assertEq(foreign.depositCount(), 0, "the foreign vault stays empty");
    }

    function test_gate_is_asked_about_accounted_tvl_plus_amount() public {
        gate.setMaxTvl(1_000 * USD);
        _deposit(alice, 600 * USD, _commit(1));
        // A bare transfer into the vault is not accounted TVL and does not consume capacity.
        usdc.mint(address(vault), 1_000_000 * USD);
        _expectDepositRevert(bob, 400 * USD + 1, _commit(2), CollateralVault.BondCapacityExceeded.selector);
        _deposit(bob, 400 * USD, _commit(3));
        assertEq(vault.tvl(), 1_000 * USD, "tvl is exactly the cap");
        _expectDepositRevert(carol, 1, _commit(4), CollateralVault.BondCapacityExceeded.selector);
    }

    function test_claims_free_gate_capacity() public {
        gate.setMaxTvl(1_000 * USD);
        _deposit(alice, 1_000 * USD, _commit(1));
        gate.setConsumedDepositCount(1);
        bytes32 leaf = _wleaf(bob, 300 * USD, 1);
        _publish(leaf);
        vault.claim(bob, 300 * USD, 1, leaf, _noProof());
        assertEq(vault.tvl(), 700 * USD, "claims net out of tvl");
        _expectDepositRevert(carol, 300 * USD + 1, _commit(2), CollateralVault.BondCapacityExceeded.selector);
        _deposit(carol, 300 * USD, _commit(3));
        assertEq(vault.tvl(), 1_000 * USD, "freed capacity is usable again");
    }

    function test_gate_is_checked_before_deadline_and_signature() public {
        uint64 expired = uint64(block.timestamp - 1);
        gate.setForcedGate(1);
        vm.prank(alice);
        vm.expectRevert(CollateralVault.InCloseOnly.selector);
        vault.deposit(10, _commit(1), expired, "");
        gate.setForcedGate(2);
        vm.prank(alice);
        vm.expectRevert(CollateralVault.BondCapacityExceeded.selector);
        vault.deposit(10, _commit(1), expired, "");
        gate.setForcedGate(3);
        vm.prank(alice);
        vm.expectRevert(CollateralVault.DepositsPaused.selector);
        vault.deposit(10, _commit(1), expired, "");
    }

    function test_expired_permit_is_refused() public {
        uint256 amount = 10 * USD;
        bytes32 commit = _commit(1);
        _fund(alice, amount);
        uint64 past = uint64(block.timestamp - 1);
        bytes memory pastSig = _sig(alice, commit, amount, past);
        vm.prank(alice);
        vm.expectRevert(CollateralVault.PermitExpired.selector);
        vault.deposit(amount, commit, past, pastSig);

        // A permit that was valid when issued expires one second after its deadline.
        uint64 until = _deadline();
        bytes memory sig = _sig(alice, commit, amount, until);
        vm.warp(uint256(until) + 1);
        vm.prank(alice);
        vm.expectRevert(CollateralVault.PermitExpired.selector);
        vault.deposit(amount, commit, until, sig);
        assertFalse(vault.usedOwnerCommit(commit), "an expired permit consumes nothing");
        assertEq(vault.depositCount(), 0, "nothing entered the chain");
    }

    function test_deadline_is_checked_before_signature() public {
        vm.prank(alice);
        vm.expectRevert(CollateralVault.PermitExpired.selector);
        vault.deposit(10, _commit(1), uint64(block.timestamp - 1), "");
    }

    function test_permit_binds_payer_commit_amount_and_deadline() public {
        uint256 amount = 1_000 * USD;
        bytes32 commit = _commit(1);
        uint64 until = _deadline();
        bytes memory sig = _sig(alice, commit, amount, until);
        _fund(alice, amount * 2);
        _fund(bob, amount);

        vm.prank(bob);
        vm.expectRevert(CollateralVault.BadGatewaySig.selector);
        vault.deposit(amount, commit, until, sig);
        vm.prank(alice);
        vm.expectRevert(CollateralVault.BadGatewaySig.selector);
        vault.deposit(amount, _commit(2), until, sig);
        vm.prank(alice);
        vm.expectRevert(CollateralVault.BadGatewaySig.selector);
        vault.deposit(amount + 1, commit, until, sig);
        vm.prank(alice);
        vm.expectRevert(CollateralVault.BadGatewaySig.selector);
        vault.deposit(amount, commit, until + 1, sig);
        vm.prank(alice);
        vm.expectRevert(CollateralVault.BadGatewaySig.selector);
        vault.deposit(amount, commit, until - 1, sig);

        vm.prank(alice);
        vault.deposit(amount, commit, until, sig);
        assertEq(vault.depositCount(), 1, "only the exact permitted tuple is admitted");
    }

    function test_permit_cannot_cross_vault_or_chain() public {
        CollateralVault other = new CollateralVault(address(gate), address(usdc), vm.addr(GW_PK));
        gate.setForcedGate(0);
        uint64 until = _deadline();
        bytes memory sig = _sig(alice, _commit(1), USD, until);
        usdc.mint(alice, USD);
        vm.startPrank(alice);
        usdc.approve(address(vault), USD);
        usdc.approve(address(other), USD);
        // `other` is unpaired, so its gate refuses first; pair the gate to it to reach the signature.
        vm.stopPrank();
        gate.setVault(address(other));
        vm.prank(alice);
        vm.expectRevert(CollateralVault.BadGatewaySig.selector);
        other.deposit(USD, _commit(1), until, sig);
        gate.setVault(address(vault));

        uint256 originalChain = block.chainid;
        vm.chainId(originalChain + 1);
        vm.prank(alice);
        vm.expectRevert(CollateralVault.BadGatewaySig.selector);
        vault.deposit(USD, _commit(1), until, sig);
        vm.chainId(originalChain);

        assertEq(usdc.balanceOf(alice), USD, "refused permits move no tokens");
        vm.prank(alice);
        vault.deposit(USD, _commit(1), until, sig);
        assertEq(vault.depositCount(), 1, "the permit works on its own vault and chain");
    }

    function test_malformed_or_malleable_permit_signatures_are_refused() public {
        uint256 amount = 10 * USD;
        bytes32 commit = _commit(3);
        uint64 until = _deadline();
        _fund(alice, amount);
        bytes32 digest = SettlementTestConfig.permitDigest(address(vault), alice, commit, amount, until);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(GW_PK, digest);
        assertTrue(uint256(s) <= SECP256K1_N / 2, "the signer emits low-s signatures");
        uint8 vFlip = v == 27 ? 28 : 27;
        bytes32 sHigh = bytes32(SECP256K1_N - uint256(s));
        // The high-s twin recovers the gateway too; only the canonical-form rule refuses it.
        assertEq(ecrecover(digest, vFlip, r, sHigh), vm.addr(GW_PK), "high-s twin recovers the gateway");

        bytes[] memory bad = new bytes[](8);
        bad[0] = "";
        bad[1] = abi.encodePacked(r, s);
        bad[2] = abi.encodePacked(r, s, v, uint8(0));
        bad[3] = abi.encodePacked(r, s, uint8(v - 27));
        bad[4] = abi.encodePacked(r, s, uint8(29));
        bad[5] = abi.encodePacked(r, sHigh, vFlip);
        bad[6] = abi.encodePacked(bytes32(0), bytes32(0), uint8(27));
        bad[7] = _permit(vault, OTHER_PK, alice, commit, amount, until);
        for (uint256 i = 0; i < bad.length; i++) {
            vm.prank(alice);
            vm.expectRevert(CollateralVault.BadGatewaySig.selector);
            vault.deposit(amount, commit, until, bad[i]);
        }
        assertFalse(vault.usedOwnerCommit(commit), "refused signatures consume nothing");

        vm.prank(alice);
        vault.deposit(amount, commit, until, abi.encodePacked(r, s, v));
        assertEq(vault.depositCount(), 1, "the canonical signature is accepted");
    }

    function test_signature_is_checked_before_commit_reuse() public {
        _deposit(alice, 10 * USD, _commit(1));
        uint64 until = _deadline();
        bytes memory wrongKey = _permit(vault, OTHER_PK, alice, _commit(1), 10 * USD, until);
        _fund(alice, 10 * USD);
        vm.prank(alice);
        vm.expectRevert(CollateralVault.BadGatewaySig.selector);
        vault.deposit(10 * USD, _commit(1), until, wrongKey);
    }

    function test_owner_commit_enters_the_chain_once() public {
        bytes32 commit = _commit(1);
        _deposit(alice, 100 * USD, commit);
        uint64 countBefore = vault.depositCount();
        bytes32 tipBefore = vault.depositChainTip();
        uint256 totalBefore = vault.totalDeposited();
        _fund(alice, 1_000 * USD);
        _fund(bob, 1_000 * USD);

        // Re-signed with a later deadline: a new digest, the same commitment.
        uint64 later = _deadline() + 1 hours;
        bytes memory s1 = _sig(alice, commit, 100 * USD, later);
        vm.prank(alice);
        vm.expectRevert(CollateralVault.OwnerCommitUsed.selector);
        vault.deposit(100 * USD, commit, later, s1);

        _expectDepositRevert(alice, 200 * USD, commit, CollateralVault.OwnerCommitUsed.selector);
        _expectDepositRevert(bob, 100 * USD, commit, CollateralVault.OwnerCommitUsed.selector);

        assertEq(vault.depositCount(), countBefore, "no second leaf");
        assertEq(vault.depositChainTip(), tipBefore, "tip unchanged");
        assertEq(vault.totalDeposited(), totalBefore, "nothing pulled");
    }

    function test_commit_reuse_is_checked_before_the_transfer() public {
        _deposit(alice, 10 * USD, _commit(1));
        // bob holds no tokens and approved nothing, yet the commit refusal comes first.
        _expectDepositRevert(bob, 10 * USD, _commit(1), CollateralVault.OwnerCommitUsed.selector);
    }

    function test_failed_pull_leaves_the_commit_unused() public {
        uint256 amount = 1_000 * USD;
        bytes32 commit = _commit(1);
        uint64 until = _deadline();
        bytes memory sig = _sig(alice, commit, amount, until);
        usdc.mint(alice, amount);
        vm.prank(alice);
        vm.expectRevert(MockUSDC.InsufficientAllowance.selector);
        vault.deposit(amount, commit, until, sig);
        assertFalse(vault.usedOwnerCommit(commit), "the mark rolls back with the call");
        assertEq(vault.depositCount(), 0, "no leaf");
        assertEq(vault.depositChainTip(), bytes32(0), "tip unchanged");
        assertEq(vault.depositBlock(0), 0, "no meta");

        vm.startPrank(alice);
        usdc.approve(address(vault), amount);
        vault.deposit(amount, commit, until, sig);
        vm.stopPrank();
        assertEq(vault.depositCount(), 1, "the same permit works once the approval is there");
    }

    function test_false_returning_pull_reverts_TransferFailed() public {
        _useScriptedStack();
        stok.setFailures(false, true);
        stok.mint(alice, 100);
        vm.prank(alice);
        stok.approve(address(svault), 100);
        uint64 until = _deadline();
        bytes memory sig = _permit(svault, GW_PK, alice, _commit(1), 100, until);
        vm.prank(alice);
        vm.expectRevert(CollateralVault.TransferFailed.selector);
        svault.deposit(100, _commit(1), until, sig);
        assertFalse(svault.usedOwnerCommit(_commit(1)), "commit not consumed");
        assertEq(svault.depositCount(), 0, "no leaf");
        assertEq(svault.totalDeposited(), 0, "nothing accounted");
    }

    function test_commit_is_marked_before_the_pull_and_folded_after() public {
        _useScriptedStack();
        bytes32 commit = _commit(1);
        uint256 amount = 100;
        stok.mint(alice, amount);
        vm.prank(alice);
        stok.approve(address(svault), amount);
        uint64 until = _deadline();
        bytes memory sig = _permit(svault, GW_PK, alice, commit, amount, until);
        // The observer re-enters with its own valid permit for the same commitment.
        hookMode = HOOK_DEPOSIT;
        hookCommit = commit;
        hookAmount = amount;
        hookUntil = until;
        hookSig = _permit(svault, GW_PK, address(this), commit, amount, until);
        stok.setObserver(this);

        vm.prank(alice);
        svault.deposit(amount, commit, until, sig);

        assertTrue(hookFired, "observer ran during the pull");
        assertTrue(hookSawMark, "commit already marked during the pull");
        assertEq(hookSawCount, 0, "the leaf is folded only after the pull");
        assertFalse(hookReentrySucceeded, "re-entry with the same commit fails");
        assertTrue(hookReentryError == CollateralVault.OwnerCommitUsed.selector, "re-entry reverts OwnerCommitUsed");
        assertEq(svault.depositCount(), 1, "exactly one leaf");
    }

    function testFuzz_amount_bounds(uint256 amount) public {
        bytes32 commit = _commit(1);
        if (amount == 0 || amount > INT128_MAX) {
            _expectDepositRevert(alice, amount, commit, CollateralVault.BadAmount.selector);
            assertEq(vault.depositCount(), 0, "refused");
        } else {
            _deposit(alice, amount, commit);
            assertEq(vault.totalDeposited(), amount, "accepted");
        }
    }

    function testFuzz_deadline(uint64 validUntil) public {
        uint256 amount = 10 * USD;
        bytes32 commit = _commit(1);
        bytes memory sig = _sig(alice, commit, amount, validUntil);
        _fund(alice, amount);
        vm.prank(alice);
        if (block.timestamp > validUntil) {
            vm.expectRevert(CollateralVault.PermitExpired.selector);
            vault.deposit(amount, commit, validUntil, sig);
            assertEq(vault.depositCount(), 0, "refused");
        } else {
            vault.deposit(amount, commit, validUntil, sig);
            assertEq(vault.depositCount(), 1, "accepted");
        }
    }

    // ------------------------------------------------------------------
    // refundDeposit
    // ------------------------------------------------------------------

    function test_refund_pays_the_payer_and_nets_accounting() public {
        _threeDeposits();
        _enterCloseOnly(0);
        uint256 vaultBefore = usdc.balanceOf(address(vault));
        uint256 tvlBefore = vault.tvl();
        uint256 outBefore = vault.refundableOutstanding();
        bytes32 tipBefore = vault.depositChainTip();
        assertEq(outBefore, A0 + A1 + A2, "everything is uncredited");

        vmx.recordLogs();
        vm.prank(carol);
        vault.refundDeposit(0, alice, _commit(10), A0, alice);
        VaultTestVm.Log memory l = _onlyLogOf(vmx.getRecordedLogs(), address(vault));

        assertEq(l.topics.length, 3, "two indexed fields");
        assertEq(l.topics[0], DEPOSIT_REFUNDED_TOPIC0, "topic0");
        assertEq(l.topics[1], bytes32(uint256(0)), "id");
        assertEq(l.topics[2], bytes32(uint256(uint160(alice))), "payer");
        assertEq(keccak256(l.data), keccak256(abi.encode(alice, A0)), "recipient and amount");

        assertEq(usdc.balanceOf(alice), A0, "payer received the principal");
        assertEq(usdc.balanceOf(carol), 0, "the trigger receives nothing");
        assertEq(usdc.balanceOf(address(vault)), vaultBefore - A0, "balance dropped by the amount");
        assertEq(vault.tvl(), tvlBefore - A0, "tvl dropped by the amount");
        assertEq(vault.totalRefunded(), A0, "refund accounted");
        assertEq(vault.refundableOutstanding(), outBefore - A0, "outstanding dropped by the amount");
        assertTrue(vault.depositRefunded(0), "id marked");
        assertFalse(vault.depositRefunded(1), "other ids untouched");
        assertEq(vault.depositCount(), 3, "the chain is not rewritten");
        assertEq(vault.depositChainTip(), tipBefore, "tip unchanged");
        assertTrue(vault.usedOwnerCommit(_commit(10)), "the commit stays spent");
    }

    function test_refund_requires_the_paired_settlement() public {
        _threeDeposits();
        _enterCloseOnly(0);
        gate.setVault(address(0));
        vm.expectRevert(CollateralVault.NotPaired.selector);
        vault.refundDeposit(0, alice, _commit(10), A0, alice);
        gate.setVault(address(0xDEAD));
        vm.expectRevert(CollateralVault.NotPaired.selector);
        vault.refundDeposit(0, alice, _commit(10), A0, alice);
        gate.setVault(address(vault));
        vault.refundDeposit(0, alice, _commit(10), A0, alice);
        assertEq(usdc.balanceOf(alice), A0, "paired again, the refund goes through");
    }

    function test_pairing_is_checked_before_close_only() public {
        _deposit(alice, A0, _commit(10));
        gate.setVault(address(0));
        vm.expectRevert(CollateralVault.NotPaired.selector);
        vault.refundDeposit(0, alice, _commit(10), A0, alice);
    }

    function test_refund_requires_close_only() public {
        _threeDeposits();
        vm.expectRevert(CollateralVault.NotCloseOnly.selector);
        vault.refundDeposit(0, alice, _commit(10), A0, alice);
        // The mode check comes before the range check.
        vm.expectRevert(CollateralVault.NotCloseOnly.selector);
        vault.refundDeposit(99, alice, _commit(10), A0, alice);
    }

    function test_refund_boundary_excludes_consumed_ids() public {
        _threeDeposits();
        _enterCloseOnly(2);
        assertEq(vault.refundableOutstanding(), A2, "only the unconsumed suffix is outstanding");
        vm.expectRevert(CollateralVault.NotRefundable.selector);
        vault.refundDeposit(0, alice, _commit(10), A0, alice);
        vm.expectRevert(CollateralVault.NotRefundable.selector);
        vault.refundDeposit(1, bob, _commit(11), A1, bob);
        vault.refundDeposit(2, alice, _commit(12), A2, alice);
        assertEq(usdc.balanceOf(alice), A2, "the unconsumed deposit is refunded");
        assertEq(vault.refundableOutstanding(), 0, "nothing left outstanding");
        assertEq(usdc.balanceOf(address(vault)), A0 + A1, "credited principal stays for withdrawals");
    }

    function test_refund_refuses_any_id_before_the_first_deposit() public {
        _enterCloseOnly(0);
        vm.expectRevert(CollateralVault.NotRefundable.selector);
        vault.refundDeposit(0, alice, _commit(10), A0, alice);
    }

    function test_refund_refuses_ids_at_or_past_the_deposit_count() public {
        _threeDeposits();
        _enterCloseOnly(0);
        vm.expectRevert(CollateralVault.NotRefundable.selector);
        vault.refundDeposit(3, alice, _commit(10), A0, alice);
        vm.expectRevert(CollateralVault.NotRefundable.selector);
        vault.refundDeposit(type(uint64).max, alice, _commit(10), A0, alice);
    }

    function test_each_deposit_refunds_once() public {
        _threeDeposits();
        _enterCloseOnly(0);
        vm.prank(carol);
        vault.refundDeposit(1, bob, _commit(11), A1, bob);

        vm.prank(carol);
        vm.expectRevert(CollateralVault.AlreadyRefunded.selector);
        vault.refundDeposit(1, bob, _commit(11), A1, bob);
        vm.prank(bob);
        vm.expectRevert(CollateralVault.AlreadyRefunded.selector);
        vault.refundDeposit(1, bob, _commit(11), A1, carol);
        // The once check comes before the recipient and preimage checks.
        vm.prank(carol);
        vm.expectRevert(CollateralVault.AlreadyRefunded.selector);
        vault.refundDeposit(1, bob, _commit(11), A1, carol);
        vm.prank(carol);
        vm.expectRevert(CollateralVault.AlreadyRefunded.selector);
        vault.refundDeposit(1, carol, bytes32(0), 1, carol);

        assertEq(vault.totalRefunded(), A1, "paid once");
        assertEq(usdc.balanceOf(bob), A1, "payer paid once");
        assertEq(usdc.balanceOf(carol), 0, "nobody else paid");
    }

    function test_range_check_runs_before_the_once_check() public {
        _threeDeposits();
        _enterCloseOnly(0);
        vault.refundDeposit(0, alice, _commit(10), A0, alice);
        gate.setConsumedDepositCount(1);
        vm.expectRevert(CollateralVault.NotRefundable.selector);
        vault.refundDeposit(0, alice, _commit(10), A0, alice);
    }

    function test_refund_recipient_rules() public {
        _threeDeposits();
        _enterCloseOnly(0);
        vm.prank(alice);
        vm.expectRevert(CollateralVault.BadRefundRecipient.selector);
        vault.refundDeposit(0, alice, _commit(10), A0, address(0));
        vm.prank(carol);
        vm.expectRevert(CollateralVault.BadRefundRecipient.selector);
        vault.refundDeposit(0, alice, _commit(10), A0, address(0));
        vm.prank(carol);
        vm.expectRevert(CollateralVault.BadRefundRecipient.selector);
        vault.refundDeposit(0, alice, _commit(10), A0, carol);
        vm.prank(carol);
        vm.expectRevert(CollateralVault.BadRefundRecipient.selector);
        vault.refundDeposit(0, alice, _commit(10), A0, bob);
        assertEq(vault.totalRefunded(), 0, "nothing paid");

        // Anyone may trigger the refund to the payer.
        vm.prank(carol);
        vault.refundDeposit(0, alice, _commit(10), A0, alice);
        assertEq(usdc.balanceOf(alice), A0, "paid to the payer");
    }

    function test_payer_may_redirect_its_refund() public {
        _threeDeposits();
        _enterCloseOnly(0);
        vmx.recordLogs();
        vm.prank(bob);
        vault.refundDeposit(1, bob, _commit(11), A1, carol);
        VaultTestVm.Log memory l = _onlyLogOf(vmx.getRecordedLogs(), address(vault));
        assertEq(l.topics[2], bytes32(uint256(uint160(bob))), "the event names the payer");
        assertEq(keccak256(l.data), keccak256(abi.encode(carol, A1)), "and the chosen recipient");
        assertEq(usdc.balanceOf(carol), A1, "redirected recipient paid");
        assertEq(usdc.balanceOf(bob), 0, "payer not paid twice");
    }

    function test_recipient_check_runs_before_the_preimage_check() public {
        _threeDeposits();
        _enterCloseOnly(0);
        vm.prank(carol);
        vm.expectRevert(CollateralVault.BadRefundRecipient.selector);
        vault.refundDeposit(0, alice, _commit(99), A0 + 1, carol);
    }

    function test_refund_preimage_must_reproduce_the_chain_link() public {
        _threeDeposits();
        _enterCloseOnly(0);
        // Each attempt keeps `to == from`, so only the preimage can fail.
        vm.prank(carol);
        vm.expectRevert(CollateralVault.BadDepositPreimage.selector);
        vault.refundDeposit(0, bob, _commit(10), A0, bob);
        vm.prank(carol);
        vm.expectRevert(CollateralVault.BadDepositPreimage.selector);
        vault.refundDeposit(0, alice, _commit(11), A0, alice);
        vm.prank(carol);
        vm.expectRevert(CollateralVault.BadDepositPreimage.selector);
        vault.refundDeposit(0, alice, _commit(10), A0 + 1, alice);
        vm.prank(carol);
        vm.expectRevert(CollateralVault.BadDepositPreimage.selector);
        vault.refundDeposit(0, alice, _commit(10), A0 - 1, alice);
        // A real leaf presented at the wrong id.
        vm.prank(carol);
        vm.expectRevert(CollateralVault.BadDepositPreimage.selector);
        vault.refundDeposit(0, bob, _commit(11), A1, bob);
        vm.prank(carol);
        vm.expectRevert(CollateralVault.BadDepositPreimage.selector);
        vault.refundDeposit(1, alice, _commit(10), A0, alice);
        assertEq(vault.totalRefunded(), 0, "nothing paid");
        assertFalse(vault.depositRefunded(0), "id 0 still refundable");
        assertFalse(vault.depositRefunded(1), "id 1 still refundable");
    }

    function test_caller_posing_as_payer_cannot_take_a_refund() public {
        _threeDeposits();
        _enterCloseOnly(0);
        // carol names herself as `from`: the recipient rule passes, the chain link does not.
        vm.prank(carol);
        vm.expectRevert(CollateralVault.BadDepositPreimage.selector);
        vault.refundDeposit(0, carol, _commit(10), A0, carol);
        assertEq(usdc.balanceOf(carol), 0, "nothing diverted");
    }

    function test_refunding_one_id_leaves_its_neighbours_refundable() public {
        _threeDeposits();
        _enterCloseOnly(0);
        vault.refundDeposit(1, bob, _commit(11), A1, bob);
        assertEq(vault.refundableOutstanding(), A0 + A2, "neighbours still outstanding");
        vault.refundDeposit(2, alice, _commit(12), A2, alice);
        vault.refundDeposit(0, alice, _commit(10), A0, alice);
        assertEq(vault.totalRefunded(), A0 + A1 + A2, "all refunded");
        assertEq(vault.tvl(), 0, "tvl nets to zero");
        assertEq(vault.refundableOutstanding(), 0, "nothing outstanding");
        assertEq(usdc.balanceOf(address(vault)), 0, "vault emptied exactly");
        assertEq(usdc.balanceOf(alice), A0 + A2, "alice whole");
        assertEq(usdc.balanceOf(bob), A1, "bob whole");
    }

    function test_false_returning_payout_reverts_and_rolls_back() public {
        _useScriptedStack();
        _scriptedDeposit(alice, 500, _commit(1));
        sgate.setCloseOnly(true);
        stok.setFailures(true, false);
        vm.expectRevert(CollateralVault.TransferFailed.selector);
        svault.refundDeposit(0, alice, _commit(1), 500, alice);
        assertFalse(svault.depositRefunded(0), "mark rolled back");
        assertEq(svault.totalRefunded(), 0, "total rolled back");
        stok.setFailures(false, false);
        svault.refundDeposit(0, alice, _commit(1), 500, alice);
        assertEq(stok.balanceOf(alice), 500, "retry pays");
    }

    function test_refund_is_marked_before_the_payout() public {
        _useScriptedStack();
        _scriptedDeposit(alice, 500, _commit(1));
        sgate.setCloseOnly(true);
        hookMode = HOOK_REFUND;
        hookId = 0;
        hookFrom = alice;
        hookCommit = _commit(1);
        hookAmount = 500;
        stok.setObserver(this);

        vm.prank(carol);
        svault.refundDeposit(0, alice, _commit(1), 500, alice);

        assertTrue(hookFired, "observer ran during the payout");
        assertTrue(hookSawMark, "id already marked during the payout");
        assertEq(hookSawTotal, 500, "total already counted during the payout");
        assertEq(hookSawTvl, 0, "tvl already netted during the payout");
        assertFalse(hookReentrySucceeded, "re-entry cannot refund again");
        assertTrue(hookReentryError == CollateralVault.AlreadyRefunded.selector, "re-entry reverts AlreadyRefunded");
        assertEq(stok.balanceOf(alice), 500, "paid exactly once");
        assertEq(stok.balanceOf(address(svault)), 0, "vault emptied exactly");
    }

    function testFuzz_refund_once_per_id(uint8 n, uint8 c, uint8 pick) public {
        uint64 count = uint64(n % 8) + 1;
        for (uint64 i = 0; i < count; i++) {
            _deposit(i % 2 == 0 ? alice : bob, (uint256(i) + 1) * USD, _commit(100 + i));
        }
        uint64 consumed = uint64(c % (count + 1));
        _enterCloseOnly(consumed);
        uint64 id = uint64(pick % count);
        address from = id % 2 == 0 ? alice : bob;
        uint256 amount = (uint256(id) + 1) * USD;
        if (id < consumed) {
            vm.expectRevert(CollateralVault.NotRefundable.selector);
            vault.refundDeposit(id, from, _commit(100 + id), amount, from);
        } else {
            vault.refundDeposit(id, from, _commit(100 + id), amount, from);
            vm.expectRevert(CollateralVault.AlreadyRefunded.selector);
            vault.refundDeposit(id, from, _commit(100 + id), amount, from);
            assertEq(vault.totalRefunded(), amount, "paid once");
        }
    }

    // ------------------------------------------------------------------
    // refundableOutstanding and tvl
    // ------------------------------------------------------------------

    function test_refundable_outstanding_tracks_the_unconsumed_suffix() public {
        _threeDeposits();
        assertEq(vault.refundableOutstanding(), A0 + A1 + A2, "C = 0");
        gate.setConsumedDepositCount(1);
        assertEq(vault.refundableOutstanding(), A1 + A2, "C = 1");
        gate.setConsumedDepositCount(2);
        assertEq(vault.refundableOutstanding(), A2, "C = 2");
        gate.setConsumedDepositCount(3);
        assertEq(vault.refundableOutstanding(), 0, "C = head");
        gate.setConsumedDepositCount(7);
        assertEq(vault.refundableOutstanding(), 0, "C past the head clamps to the head");
        gate.setConsumedDepositCount(1);
        gate.setCloseOnly(true);
        vault.refundDeposit(2, alice, _commit(12), A2, alice);
        assertEq(vault.refundableOutstanding(), A1, "refunds leave the outstanding set");
    }

    function test_refundable_outstanding_saturates_at_zero() public {
        _threeDeposits();
        _enterCloseOnly(1);
        vault.refundDeposit(2, alice, _commit(12), A2, alice);
        // A boundary that moves past refunded ids (never done by the paired settlement in
        // close-only) must not underflow the view.
        gate.setConsumedDepositCount(3);
        assertEq(vault.refundableOutstanding(), 0, "saturates instead of reverting");
    }

    function test_tvl_nets_withdrawals_and_refunds() public {
        _threeDeposits();
        gate.setConsumedDepositCount(1);
        bytes32 leaf = _wleaf(carol, 400 * USD, 1);
        _publish(leaf);
        vault.claim(carol, 400 * USD, 1, leaf, _noProof());
        assertEq(vault.tvl(), A0 + A1 + A2 - 400 * USD, "withdrawals net out");
        gate.setCloseOnly(true);
        vault.refundDeposit(1, bob, _commit(11), A1, bob);
        assertEq(vault.tvl(), A0 + A2 - 400 * USD, "refunds net out");
        assertEq(vault.tvl(), vault.totalDeposited() - vault.totalWithdrawn() - vault.totalRefunded(), "tvl formula");
        usdc.mint(address(vault), 9_999 * USD);
        assertEq(vault.tvl(), A0 + A2 - 400 * USD, "a donation is not accounted");
    }

    function test_tvl_saturates_when_withdrawals_exceed_deposits() public {
        // Only a donation backs this claim; accounted tvl cannot go negative.
        usdc.mint(address(vault), 100 * USD);
        bytes32 leaf = _wleaf(carol, 100 * USD, 1);
        _publish(leaf);
        vault.claim(carol, 100 * USD, 1, leaf, _noProof());
        assertEq(vault.totalWithdrawn(), 100 * USD, "withdrawal accounted");
        assertEq(vault.tvl(), 0, "tvl saturates at zero");
    }

    // ------------------------------------------------------------------
    // withdrawals and the claim reserve
    // ------------------------------------------------------------------

    function test_only_settlement_publishes_root() public {
        vm.prank(alice);
        vm.expectRevert(CollateralVault.NotSettlement.selector);
        vault.publishWithdrawals(keccak256("r"), 1);
    }

    function test_claim_against_settled_root() public {
        _deposit(alice, 10_000 * USD, _commit(1));
        gate.setConsumedDepositCount(1);
        uint256 amount = 2_000 * USD;
        bytes32 leaf = _wleaf(bob, amount, 1);
        _publish(leaf);
        vault.claim(bob, amount, 1, vault.withdrawalsRoot(), _noProof());
        assertEq(usdc.balanceOf(bob), amount, "bob received USDC");
        assertEq(vault.totalWithdrawn(), amount, "withdrawn tracked");
        assertTrue(vault.claimed(leaf), "leaf spent");
        vm.expectRevert(CollateralVault.AlreadyClaimed.selector);
        vault.claim(bob, amount, 1, leaf, _noProof());
    }

    function test_claim_with_bad_proof_rejected() public {
        _deposit(alice, 10_000 * USD, _commit(1));
        gate.setConsumedDepositCount(1);
        _publish(keccak256("some-other-root"));
        vm.expectRevert(CollateralVault.BadWithdrawalProof.selector);
        vault.claim(bob, 1_000 * USD, 1, keccak256("some-other-root"), _noProof());
    }

    function test_two_leaf_merkle_claim() public {
        _deposit(alice, 10_000 * USD, _commit(1));
        gate.setConsumedDepositCount(1);
        bytes32 la = _wleaf(alice, 2_000 * USD, 1);
        bytes32 lb = _wleaf(bob, 1_000 * USD, 2);
        _publish(_pair(la, lb));
        vault.claim(alice, 2_000 * USD, 1, vault.withdrawalsRoot(), _proof1(lb));
        vault.claim(bob, 1_000 * USD, 2, vault.withdrawalsRoot(), _proof1(la));
        assertEq(usdc.balanceOf(alice), 2_000 * USD, "alice claimed");
        assertEq(usdc.balanceOf(bob), 1_000 * USD, "bob claimed");
    }

    function test_older_published_root_is_still_claimable() public {
        _deposit(alice, 10_000 * USD, _commit(1));
        gate.setConsumedDepositCount(1);
        bytes32 leaf = _wleaf(bob, 2_000 * USD, 1);
        _publish(leaf);
        _publish(keccak256("later-root-without-the-leaf"));
        vault.claim(bob, 2_000 * USD, 1, leaf, _noProof());
        assertEq(usdc.balanceOf(bob), 2_000 * USD, "claimed against the older root");
        vm.expectRevert(CollateralVault.AlreadyClaimed.selector);
        vault.claim(bob, 2_000 * USD, 1, leaf, _noProof());
    }

    function test_zero_root_is_never_a_valid_claim_root() public {
        _publish(bytes32(0));
        assertFalse(vault.rootPublished(bytes32(0)), "the zero root is never registered");
        vm.expectRevert(CollateralVault.BadWithdrawalProof.selector);
        vault.claim(alice, 1, 1, bytes32(0), _noProof());
    }

    function test_claim_reserve_shields_uncredited_principal() public {
        _deposit(alice, 1_000 * USD, _commit(1)); // id 0, credited below
        _deposit(bob, 500 * USD, _commit(2)); // id 1, never credited
        gate.setConsumedDepositCount(1);
        assertEq(vault.refundableOutstanding(), 500 * USD, "bob's principal is uncredited");

        // A root that authorizes more than the credited state holds.
        bytes32 over = _wleaf(carol, 1_200 * USD, 1);
        bytes32 fair = _wleaf(carol, 1_000 * USD, 2);
        bytes32 root = _pair(over, fair);
        _publish(root);
        vm.expectRevert(CollateralVault.ReservedForUncredited.selector);
        vault.claim(carol, 1_200 * USD, 1, root, _proof1(fair));
        assertFalse(vault.claimed(over), "a reserved claim stays unspent");

        vault.claim(carol, 1_000 * USD, 2, root, _proof1(over));
        assertEq(usdc.balanceOf(address(vault)), 500 * USD, "exactly the uncredited principal remains");
        vm.expectRevert(CollateralVault.ReservedForUncredited.selector);
        vault.claim(carol, 1_200 * USD, 1, root, _proof1(fair));

        gate.setCloseOnly(true);
        vm.prank(bob);
        vault.refundDeposit(1, bob, _commit(2), 500 * USD, bob);
        assertEq(usdc.balanceOf(bob), 500 * USD, "uncredited principal returned in full");
        assertEq(usdc.balanceOf(address(vault)), 0, "nothing left");
    }

    function test_claim_reserve_boundary_is_exact() public {
        _deposit(alice, 100 * USD, _commit(1)); // uncredited
        usdc.mint(address(vault), 40 * USD); // donation
        // balance 140, outstanding 100: at most 40 may leave against proofs.
        bytes32 big = _wleaf(bob, 40 * USD + 1, 1);
        bytes32 fit = _wleaf(bob, 40 * USD, 2);
        bytes32 root = _pair(big, fit);
        _publish(root);
        vm.expectRevert(CollateralVault.ReservedForUncredited.selector);
        vault.claim(bob, 40 * USD + 1, 1, root, _proof1(fit));
        vault.claim(bob, 40 * USD, 2, root, _proof1(big));
        assertEq(usdc.balanceOf(address(vault)), vault.refundableOutstanding(), "balance equals the reserve");
    }

    function test_claim_reserve_releases_as_deposits_are_credited() public {
        _deposit(alice, 300 * USD, _commit(1));
        _deposit(bob, 200 * USD, _commit(2));
        bytes32 leaf = _wleaf(carol, 300 * USD, 1);
        _publish(leaf);
        vm.expectRevert(CollateralVault.ReservedForUncredited.selector);
        vault.claim(carol, 300 * USD, 1, leaf, _noProof());
        gate.setConsumedDepositCount(1);
        vault.claim(carol, 300 * USD, 1, leaf, _noProof());
        assertEq(usdc.balanceOf(carol), 300 * USD, "claimable once its funds are credited");
        assertEq(usdc.balanceOf(address(vault)), vault.refundableOutstanding(), "the uncredited deposit is intact");
    }

    function test_claim_reserve_applies_in_close_only() public {
        _deposit(alice, 300 * USD, _commit(1));
        _deposit(bob, 200 * USD, _commit(2));
        gate.setConsumedDepositCount(1);
        bytes32 leaf = _wleaf(carol, 400 * USD, 1); // over-credited
        _publish(leaf);
        _enterCloseOnly(1);
        vm.expectRevert(CollateralVault.ReservedForUncredited.selector);
        vault.claim(carol, 400 * USD, 1, leaf, _noProof());
        vault.refundDeposit(1, bob, _commit(2), 200 * USD, bob);
        assertEq(vault.refundableOutstanding(), 0, "refunded principal leaves the reserve");
        // Now the balance itself is short; the claim still refuses cleanly.
        vm.expectRevert(CollateralVault.ReservedForUncredited.selector);
        vault.claim(carol, 400 * USD, 1, leaf, _noProof());
        usdc.mint(address(vault), 100 * USD);
        vault.claim(carol, 400 * USD, 1, leaf, _noProof());
        assertEq(usdc.balanceOf(carol), 400 * USD, "payable once the balance covers it");
    }

    function test_claim_beyond_balance_refuses_without_panic() public {
        bytes32 leaf = _wleaf(bob, 1, 1);
        _publish(leaf);
        vm.expectRevert(CollateralVault.ReservedForUncredited.selector);
        vault.claim(bob, 1, 1, leaf, _noProof());
    }

    function test_claim_checks_run_in_order() public {
        _deposit(alice, 100 * USD, _commit(1)); // uncredited, so the reserve would refuse
        bytes32 leaf = _wleaf(bob, 50 * USD, 1);
        _publish(leaf);
        bytes32[] memory junk = _proof1(keccak256("junk"));
        vm.expectRevert(CollateralVault.BadWithdrawalProof.selector);
        vault.claim(bob, 50 * USD, 1, leaf, junk);
        vm.expectRevert(CollateralVault.BadWithdrawalProof.selector);
        vault.claim(bob, 50 * USD, 1, keccak256("unpublished"), _noProof());
        vm.expectRevert(CollateralVault.ReservedForUncredited.selector);
        vault.claim(bob, 50 * USD, 1, leaf, _noProof());
        gate.setConsumedDepositCount(1);
        vault.claim(bob, 50 * USD, 1, leaf, _noProof());
        vm.expectRevert(CollateralVault.AlreadyClaimed.selector);
        vault.claim(bob, 50 * USD, 1, keccak256("unpublished"), junk);
    }

    function test_sound_flow_is_unaffected_by_the_reserve() public {
        _threeDeposits();
        gate.setConsumedDepositCount(3);
        bytes32 la = _wleaf(carol, A0 + A1, 1);
        bytes32 lb = _wleaf(bob, A2, 2);
        bytes32 root = _pair(la, lb);
        _publish(root);
        vault.claim(carol, A0 + A1, 1, root, _proof1(lb));
        vault.claim(bob, A2, 2, root, _proof1(la));
        assertEq(usdc.balanceOf(address(vault)), 0, "every credited unit is withdrawable");
        assertEq(vault.tvl(), 0, "tvl nets to zero");
    }

    function test_false_returning_claim_payout_reverts() public {
        _useScriptedStack();
        _scriptedDeposit(alice, 500, _commit(1));
        sgate.setConsumedDepositCount(1);
        bytes32 leaf = _wleaf(bob, 200, 1);
        sgate.publishTo(address(svault), leaf, 0);
        stok.setFailures(true, false);
        vm.expectRevert(CollateralVault.TransferFailed.selector);
        svault.claim(bob, 200, 1, leaf, _noProof());
        assertFalse(svault.claimed(leaf), "mark rolled back");
        assertEq(svault.totalWithdrawn(), 0, "total rolled back");
    }

    function test_claim_is_marked_before_the_payout() public {
        _useScriptedStack();
        _scriptedDeposit(alice, 500, _commit(1));
        sgate.setConsumedDepositCount(1);
        bytes32 leaf = _wleaf(bob, 200, 7);
        sgate.publishTo(address(svault), leaf, 0);
        hookMode = HOOK_CLAIM;
        hookFrom = bob;
        hookAmount = 200;
        hookNonce = 7;
        hookRoot = leaf;
        stok.setObserver(this);

        svault.claim(bob, 200, 7, leaf, _noProof());

        assertTrue(hookFired, "observer ran during the payout");
        assertTrue(hookSawMark, "leaf already spent during the payout");
        assertEq(hookSawTotal, 200, "withdrawal already counted during the payout");
        assertEq(hookSawTvl, 300, "tvl already netted during the payout");
        assertFalse(hookReentrySucceeded, "re-entry cannot claim again");
        assertTrue(hookReentryError == CollateralVault.AlreadyClaimed.selector, "re-entry reverts AlreadyClaimed");
        assertEq(stok.balanceOf(bob), 200, "paid exactly once");
    }

    // ------------------------------------------------------------------
    // settlement reads are static
    // ------------------------------------------------------------------

    function test_settlement_reads_are_static_calls() public {
        StaticOnlyGate sg = new StaticOnlyGate();
        CollateralVault v = new CollateralVault(address(sg), address(usdc), vm.addr(GW_PK));
        sg.setPaired(address(v));

        // The probe itself: a plain call is refused, a static call is served.
        (bool plainOk,) = address(sg).call(abi.encodeWithSignature("closeOnly()"));
        assertFalse(plainOk, "a non-static read is refused");
        (bool staticOk,) = address(sg).staticcall(abi.encodeWithSignature("closeOnly()"));
        assertTrue(staticOk, "a static read is served");

        _depositInto(v, ITestToken(address(usdc)), alice, 300 * USD, _commit(1));
        _depositInto(v, ITestToken(address(usdc)), bob, 200 * USD, _commit(2));
        sg.setConsumed(1);
        assertEq(v.refundableOutstanding(), 200 * USD, "outstanding read");
        bytes32 leaf = _wleaf(carol, 300 * USD, 1);
        sg.publishTo(address(v), leaf, 0);
        v.claim(carol, 300 * USD, 1, leaf, _noProof());
        sg.setClosed(true);
        v.refundDeposit(1, bob, _commit(2), 200 * USD, bob);
        assertEq(usdc.balanceOf(carol), 300 * USD, "claim completed");
        assertEq(usdc.balanceOf(bob), 200 * USD, "refund completed");
        assertEq(sg.probeWrites(), 0, "no settlement read ever ran with write access");
    }
}

/// The vault against the real settlement: pairing, the gate codes it maps, and the
/// refund boundary the settlement records.
contract CollateralVaultPairingTest is VaultTestBase {
    uint256 internal constant ENCLAVE_PK = 0xE1C1A7E;
    bytes32 internal constant GENESIS = keccak256("vault-pairing/genesis");

    DarkPerpSettlement internal s;
    CollateralVault internal vault;
    MockUSDC internal usdc;
    MockClockVerifier internal verifier;

    function setUp() public {
        vm.warp(T0);
        vm.roll(1_000);
        usdc = new MockUSDC();
        verifier = new MockClockVerifier();
        s = new DarkPerpSettlement(SettlementTestConfig.defaults(address(this), vm.addr(ENCLAVE_PK), verifier, GENESIS));
        vault = new CollateralVault(address(s), address(usdc), vm.addr(GW_PK));
    }

    function _pairAndBond(uint256 bond) internal {
        s.setVault(address(vault));
        if (bond > 0) {
            usdc.mint(address(this), bond);
            usdc.approve(address(s), bond);
            s.postBond(bond);
        }
    }

    function _deposit(address who, uint256 amount, bytes32 commit) internal returns (uint64) {
        return _depositInto(vault, ITestToken(address(usdc)), who, amount, commit);
    }

    function _tryDeposit(CollateralVault v, address who, uint256 amount, bytes32 commit, bytes4 err) internal {
        uint64 until = _deadline();
        bytes memory sig = _permit(v, GW_PK, who, commit, amount, until);
        usdc.mint(who, amount);
        vm.prank(who);
        usdc.approve(address(v), amount);
        vm.prank(who);
        vm.expectRevert(err);
        v.deposit(amount, commit, until, sig);
    }

    /// Settles one batch consuming the vault's first `n` deposits.
    function _settle(uint64 n, bytes32 withdrawalsRoot) internal {
        bytes32 prev = s.currentStateRoot();
        bytes32 next = keccak256(abi.encodePacked(prev, n));
        bytes32 manifest = keccak256(abi.encodePacked("vault-pairing/manifest", s.batchCount()));
        bytes32 depositsRoot = vault.depositTipAt(n);
        bytes32 c = s.publicCommitment(prev, manifest, next, bytes32(0), withdrawalsRoot, bytes32(0), depositsRoot);
        s.settleBatch(prev, manifest, next, bytes32(0), withdrawalsRoot, bytes32(0), depositsRoot, n, abi.encode(c));
    }

    function test_deposits_wait_for_pairing() public {
        _tryDeposit(vault, alice, 10, _commit(1), CollateralVault.DepositsPaused.selector);
        _pairAndBond(100 * USD);
        _deposit(alice, 10, _commit(1));
        assertEq(vault.depositCount(), 1, "paired and bonded, the deposit lands");
    }

    function test_a_foreign_vault_stays_unpaired() public {
        _pairAndBond(100 * USD);
        CollateralVault foreign = new CollateralVault(address(s), address(usdc), vm.addr(GW_PK));
        _tryDeposit(foreign, alice, 10, _commit(1), CollateralVault.DepositsPaused.selector);
        s.enterCloseOnly();
        vm.expectRevert(CollateralVault.NotPaired.selector);
        foreign.refundDeposit(0, alice, _commit(1), 10, alice);
    }

    function test_paired_vault_admits_up_to_bond_capacity() public {
        _pairAndBond(100 * USD);
        uint256 cap = s.depositCapacity();
        assertEq(cap, 2_000_000_019, "capacity of a 100e6 bond");
        _tryDeposit(vault, alice, cap + 1, _commit(1), CollateralVault.BondCapacityExceeded.selector);
        _tryDeposit(vault, alice, 1e36, _commit(1), CollateralVault.BondCapacityExceeded.selector);
        _deposit(alice, cap, _commit(1));
        assertEq(vault.tvl(), cap, "filled to capacity");
        _tryDeposit(vault, bob, 1, _commit(2), CollateralVault.BondCapacityExceeded.selector);
    }

    function test_close_only_closes_deposits_and_opens_refunds_above_the_settled_prefix() public {
        _pairAndBond(1_000 * USD);
        _deposit(alice, 600 * USD, _commit(1)); // id 0
        _deposit(bob, 400 * USD, _commit(2)); // id 1
        bytes32 leaf = _wleaf(carol, 600 * USD, 1);
        _settle(1, leaf);
        assertEq(s.consumedDepositCount(), 1, "the settle recorded the consumed prefix");
        assertEq(vault.refundableOutstanding(), 400 * USD, "id 1 is uncredited");

        vm.expectRevert(CollateralVault.NotCloseOnly.selector);
        vault.refundDeposit(1, bob, _commit(2), 400 * USD, bob);

        s.enterCloseOnly();
        _tryDeposit(vault, alice, 10, _commit(3), CollateralVault.InCloseOnly.selector);
        vm.expectRevert(CollateralVault.NotRefundable.selector);
        vault.refundDeposit(0, alice, _commit(1), 600 * USD, alice);
        vm.prank(carol);
        vault.refundDeposit(1, bob, _commit(2), 400 * USD, bob);
        assertEq(usdc.balanceOf(bob), 400 * USD, "uncredited deposit refunded");

        vault.claim(carol, 600 * USD, 1, leaf, _noProof());
        assertEq(usdc.balanceOf(carol), 600 * USD, "settled withdrawal still claimable in close-only");
        assertEq(usdc.balanceOf(address(vault)), 0, "vault emptied exactly");
        assertEq(vault.tvl(), 0, "tvl nets to zero");
    }
}

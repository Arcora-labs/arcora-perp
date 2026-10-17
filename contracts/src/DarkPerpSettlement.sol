// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IZkVerifier} from "./interfaces/IZkVerifier.sol";
import {MerkleLib} from "./libraries/MerkleLib.sol";

interface ICollateralVault {
    function publishWithdrawals(bytes32 root, uint256 epoch) external;
    function tvl() external view returns (uint256);
    function token() external view returns (address);
    /// SEC-019: the vault's authoritative deposit hash chain. `depositTipAt(n)` is the
    /// tip after the vault's first `n` deposits — a settling batch pins its proven
    /// `depositsRoot` to the PREFIX it credited. The head getters remain for the
    /// sequencer to see how far the chain has run.
    function depositTipAt(uint64 n) external view returns (bytes32);
    function depositChainTip() external view returns (bytes32);
    function depositCount() external view returns (uint64);
    /// The settlement this vault answers to; `setVault` requires it to be this contract.
    function settlement() external view returns (address);
    /// The L1 block deposit `id` landed in (0 for an id that does not exist yet).
    function depositBlock(uint64 id) external view returns (uint256);
}

/// The ERC20 subset the settlement uses to custody the sequencer's USDC bond.
interface IERC20Min {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @title DarkPerpSettlement
/// @notice The L1 anchor for dark-perp. It (1) advances the canonical state root only
/// via a verified ZK validity proof, (2) records how many vault deposits the settled
/// state has consumed, so deposits above that boundary stay refundable from the vault
/// once close-only begins, (3) enters irreversible close-only on a liveness timeout, a
/// deposit-inclusion timeout or a governance call, (4) gates vault deposits on the
/// sequencer bond's capacity, and (5) runs the inclusion-challenge game, which fines
/// the bond by a capped amount for an order the sequencer accepted but never settled or
/// rejected. It holds no USER collateral — that lives in CollateralVault; it custodies
/// only its own sequencer bond and challenge stakes.
contract DarkPerpSettlement {
    using MerkleLib for bytes32;

    /// Constructor parameters. A static tuple, so its ABI encoding is exactly twelve
    /// flat words in this order; the first ten keep the previous constructor's order.
    struct Config {
        address sequencer;
        address enclaveSigner;
        IZkVerifier verifier;
        bytes32 genesisRoot;
        uint256 livenessTimeoutBlocks;
        uint256 challengeGraceBlocks;
        uint256 challengeBond;
        uint256 inclusionDeadlineSecs;
        address governance;
        uint256 finalSettleGraceBlocks;
        uint256 progressBatches;
        uint256 slashPayoutCap;
    }

    /// perp-core `Domain::StateRoot` tag, binding the public commitment to the
    /// off-chain prover (`crates/prover::PublicInputs::commitment`).
    uint8 internal constant DOMAIN_STATE_ROOT = 7;
    /// perp-core `Domain::OrderHash` tag, used for the receipt signing digest.
    uint8 internal constant DOMAIN_ORDER_HASH = 5;

    struct Batch {
        bytes32 manifestHash;
        bytes32 orderedRoot; // Merkle root of the manifest's ordered order hashes
        bytes32 rejectedRoot; // Merkle root of declared rejections; legitimacy is not proven by Proof-v1.
        uint256 settledAtBlock;
    }

    /// Six ABI words, as before. `beneficiary` is the address the enclave authorization
    /// names (it receives a fine); the stake belongs to whoever submitted the challenge.
    struct Challenge {
        address beneficiary;
        uint64 batchIdHint;
        uint256 openedBlock;
        /// `batchCount` when the challenge opened: the first batch that settled after it.
        uint256 openBatchCount;
        uint256 bond; // challenger stake, anti-griefing (audit F3)
        bool open;
    }

    /// Read by the gateway at boot; bumped whenever an off-chain caller's view of this
    /// ABI would otherwise be silently wrong.
    uint256 public constant ABI_VERSION = 3;

    /// Domain tag of the enclave-signed challenge authorization (`challengeAuthDigest`).
    bytes32 public constant CHALLENGE_AUTH_TAG = keccak256("arcora:l1-inclusion-challenge:v1");

    /// secp256k1 group order ÷ 2; signatures with higher `s` are non-canonical
    /// (malleable) and rejected (audit F3 hygiene).
    uint256 internal constant SECP256K1_N_HALF = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    /// Bond sizing, in basis points of the vault's accounted TVL. The vault refuses a
    /// deposit that would lift `BOND_BPS` of its TVL above the posted bond
    /// (`depositGate`), so the bond covers the custodied value by construction and
    /// settlement never depends on it.
    uint256 public constant BOND_BPS = 500;

    /// `depositGate` results.
    uint8 internal constant GATE_OPEN = 0;
    uint8 internal constant GATE_CLOSE_ONLY = 1;
    uint8 internal constant GATE_CAPACITY = 2;
    uint8 internal constant GATE_UNPAIRED = 3;

    /// Largest page `openChallenges` returns.
    uint256 internal constant MAX_OPEN_PAGE = 512;

    address public immutable sequencer;
    /// secp256k1 address whose key the enclave signs receipts and challenge
    /// authorizations with. See ADR-0009.
    address public immutable enclaveSigner;
    IZkVerifier public immutable verifier;

    bytes32 public currentStateRoot;
    uint256 public lastProgressBlock;
    uint256 public batchCount;
    /// The sequencer bond, denominated in the vault's collateral asset (USDC), so it
    /// is dimensionally coherent with `requiredBond()`.
    uint256 public sequencerBond;
    bool public closeOnly;
    /// Collateral vault that releases funds against settled withdrawals. Set once by
    /// the sequencer after deploy, and only to a vault that names this settlement.
    address public vault;

    uint256 public immutable livenessTimeoutBlocks;
    /// Blocks a slash must additionally wait after the progress gate is reached (the
    /// settle block of the `progressBatches`-th batch after the challenge opened).
    uint256 public immutable challengeGraceBlocks;
    /// Stake a challenger must post. Refunded to the submitter when the challenge
    /// forced the order's settlement or ends in a slash or release; forfeited to the
    /// sequencer when the order was already settled when the challenge opened.
    uint256 public immutable challengeBond;
    /// Seconds after a receipt's signed `recvTimeMs` before its order becomes
    /// challengeable — the inclusion SLA. A fresh order cannot be challenged, so an
    /// honest sequencer's normal async settlement latency can never be free-griefed by
    /// a spam challenge.
    uint256 public immutable inclusionDeadlineSecs;
    /// Phase-0 batches that must settle after a challenge opens before it can be
    /// slashed (1..16).
    uint256 public immutable progressBatches;
    /// Maximum USDC a single slash moves from the bond to the beneficiary.
    uint256 public immutable slashPayoutCap;

    /// The block close-only was entered (0 while live), so `finalSettle`'s grace
    /// window can be measured.
    uint256 public closeOnlyBlock;
    /// A06: phase-1 SettleAll has landed. Once true, only proof-bound phase-2
    /// price-free exits may use the wind-down entrypoint.
    bool public windDownSettled;
    /// The address allowed to push wind-down batches while close-only, and to enter
    /// close-only directly. Escape stays proof-gated — governance can only land
    /// proof-valid transitions, never fabricate balances.
    address public immutable governance;
    /// Blocks after `closeOnlyBlock` before `finalSettle` is allowed — a grace
    /// window so users/watchers can react before a governance wind-down.
    uint256 public immutable finalSettleGraceBlocks;

    /// Vault deposits the settled state has consumed (`consumed_deposit_count`, bound
    /// inside the state root). Monotonic, never above `vault.depositCount()`, and frozen
    /// once close-only begins: ids at or above it are refundable from the vault then.
    uint64 public consumedDepositCount;
    /// `batchCount` when close-only began. Only batches below it are phase-0 batches.
    uint256 public closeOnlyBatchCount;
    /// Number of slashes executed. The bond-capacity invariant holds between slashes.
    uint256 public slashCount;

    mapping(uint256 => Batch) public batches;
    mapping(bytes32 => Challenge) public challenges; // orderHash => challenge
    /// Order hashes whose challenge ended (answered, slashed or released). They can
    /// never be challenged again.
    mapping(bytes32 => bool) public challengeResolved;
    /// Who posted each open challenge's stake.
    mapping(bytes32 => address) internal _challengeStaker;
    /// Enumerable set of open challenges, so watchers need no log scanning.
    bytes32[] internal _open;
    /// 1-based position of an open hash in `_open` (0 = not open).
    mapping(bytes32 => uint256) internal _openPos;
    /// Pull-payment ledger for native-token refunds (challenge stakes). Credited rather
    /// than pushed, so a non-payable recipient can never brick the challenge-answer or
    /// the slash transition — the recipient pulls it via `claimEth` or `claimEthTo`
    /// (audit DP-011).
    mapping(address => uint256) public pendingEth;
    /// Pull-payment ledger for slashed USDC. Credited to the beneficiary rather than
    /// pushed, so a pausable/blacklisting USDC can never brick `slashUnanswered`.
    /// Pulled via `claimUsdc` or `claimUsdcTo`.
    mapping(address => uint256) public pendingUsdc;

    event BatchSettled(uint256 indexed batchId, bytes32 prevRoot, bytes32 newRoot, bytes32 manifestHash);
    event FinalSettle(uint256 indexed batchId, bytes32 prevRoot, bytes32 newRoot, bytes32 manifestHash);
    event CloseOnlyEntered(string reason);
    event BondPosted(uint256 amount, uint256 total);
    event BondWithdrawn(uint256 amount, uint256 total);
    event InclusionChallenged(
        bytes32 indexed orderHash, address indexed beneficiary, address staker, uint256 openBatchCount
    );
    event InclusionAnswered(bytes32 indexed orderHash, uint256 batchId);
    event RejectionAnswered(bytes32 indexed orderHash, uint256 batchId);
    event SequencerSlashed(bytes32 indexed orderHash, address indexed beneficiary, uint256 amount);
    event ChallengeReleased(bytes32 indexed orderHash);
    /// `account` is the credited balance that was withdrawn, `to` the address paid.
    event EthClaimed(address indexed account, address indexed to, uint256 amount);
    event UsdcClaimed(address indexed account, address indexed to, uint256 amount);

    error InvalidConfig();
    error NotSequencer();
    error InCloseOnly();
    error BadPrevRoot();
    error BadProof();
    error BadDepositCount();
    error DepositsFrozen();
    error LivenessNotExpired();
    error BadReceiptSignature();
    error ChallengeExists();
    error AlreadyResolved();
    error BadBeneficiary();
    error NoSuchChallenge();
    error NoProgress();
    error ChallengeNotExpired();
    error ShortBondSlashRestricted();
    error NotStale();
    error NotIncluded();
    error NotRejected();
    error LengthMismatch();
    error NonCanonicalSignature();
    error WrongChallengeBond();
    error NotRipe();
    error BatchNotSettled();
    error TransferFailed();
    error BadRecipient();
    error VaultNotSet();
    error VaultMismatch();
    error WithdrawExceedsExcess();
    error NotGovernance();
    error NotCloseOnly();
    error GraceNotExpired();

    modifier onlySequencer() {
        if (msg.sender != sequencer) revert NotSequencer();
        _;
    }

    constructor(Config memory c) {
        if (
            c.sequencer == address(0) || c.enclaveSigner == address(0) || c.governance == address(0)
                || address(c.verifier).code.length == 0 || c.livenessTimeoutBlocks == 0 || c.challengeGraceBlocks == 0
                || c.progressBatches == 0 || c.progressBatches > 16 || c.slashPayoutCap == 0
                || c.slashPayoutCap > type(uint128).max
        ) revert InvalidConfig();
        // Verifier shape: only an unbound clock-bound verifier (proof version 2, no
        // settlement yet) may be wired. A bare proof verifier lacks the clock binding.
        // This checks shape, not soundness.
        (bool okVersion, uint256 version) = _staticWord(address(c.verifier), bytes4(keccak256("proofVersion()")));
        (bool okBound, uint256 bound) = _staticWord(address(c.verifier), bytes4(keccak256("settlement()")));
        if (!okVersion || version != 2 || !okBound || bound != 0) revert InvalidConfig();

        sequencer = c.sequencer;
        enclaveSigner = c.enclaveSigner;
        verifier = c.verifier;
        currentStateRoot = c.genesisRoot;
        lastProgressBlock = block.number;
        livenessTimeoutBlocks = c.livenessTimeoutBlocks;
        challengeGraceBlocks = c.challengeGraceBlocks;
        challengeBond = c.challengeBond;
        inclusionDeadlineSecs = c.inclusionDeadlineSecs;
        governance = c.governance;
        finalSettleGraceBlocks = c.finalSettleGraceBlocks;
        progressBatches = c.progressBatches;
        slashPayoutCap = c.slashPayoutCap;
    }

    /// @dev One-word static read that never reverts: false on a failed call or on
    /// returndata that is not exactly one word.
    function _staticWord(address target, bytes4 selector) internal view returns (bool ok, uint256 word) {
        bytes memory ret;
        (ok, ret) = target.staticcall(abi.encodeWithSelector(selector));
        if (!ok || ret.length != 32) return (false, 0);
        word = abi.decode(ret, (uint256));
    }

    /// @notice Bind the collateral vault (once). It must be a contract whose
    /// `settlement()` is this contract, so the deposit gate and the refund path agree
    /// on the pairing. Withdrawals published on every settlement flow through it.
    function setVault(address _vault) external onlySequencer {
        require(vault == address(0), "vault set");
        (bool ok, uint256 paired) = _staticWord(_vault, ICollateralVault.settlement.selector);
        if (_vault.code.length == 0 || !ok || paired != uint256(uint160(address(this)))) revert VaultMismatch();
        vault = _vault;
    }

    /// @notice Stake / top up the sequencer bond (in USDC). The sequencer must
    /// `approve` the settlement for `amount` first.
    function postBond(uint256 amount) external onlySequencer {
        if (vault == address(0)) revert VaultNotSet();
        IERC20Min tok = IERC20Min(ICollateralVault(vault).token());
        if (!tok.transferFrom(msg.sender, address(this), amount)) revert TransferFailed();
        sequencerBond += amount;
        emit BondPosted(amount, sequencerBond);
    }

    /// @notice Reclaim sequencer bond above the floor `max(requiredBond(),
    /// openChallengeCount() * slashPayoutCap)`, so every open challenge stays fully
    /// payable. Allowed in close-only too: refunds are paid by the vault, not the bond.
    function withdrawBond(uint256 amount) external onlySequencer {
        uint256 floor = requiredBond();
        uint256 reserve = _open.length * slashPayoutCap;
        if (reserve > floor) floor = reserve;
        uint256 excess = sequencerBond > floor ? sequencerBond - floor : 0;
        if (amount > excess) revert WithdrawExceedsExcess();
        sequencerBond -= amount;
        IERC20Min tok = IERC20Min(ICollateralVault(vault).token());
        if (!tok.transfer(sequencer, amount)) revert TransferFailed();
        emit BondWithdrawn(amount, sequencerBond);
    }

    /// @notice `BOND_BPS` of the vault's accounted TVL. Zero until the vault is wired.
    function requiredBond() public view returns (uint256) {
        if (vault == address(0)) return 0;
        return (ICollateralVault(vault).tvl() * BOND_BPS) / 10_000;
    }

    /// @notice The vault's admission check for a deposit that would bring its TVL to
    /// `newTvl`: 3 when the caller is not the paired vault, 1 in close-only, 2 when
    /// `BOND_BPS` of `newTvl` would exceed the bond (same rounding as `requiredBond`),
    /// 0 otherwise.
    function depositGate(uint256 newTvl) external view returns (uint8) {
        if (msg.sender != vault) return GATE_UNPAIRED;
        if (closeOnly) return GATE_CLOSE_ONLY;
        if ((newTvl * BOND_BPS) / 10_000 > sequencerBond) return GATE_CAPACITY;
        return GATE_OPEN;
    }

    /// @notice Additional TVL the current bond admits: the largest TVL whose
    /// `requiredBond` the bond still covers, minus the vault's TVL (saturating at 0).
    /// Zero without a vault.
    function depositCapacity() external view returns (uint256) {
        if (vault == address(0)) return 0;
        uint256 maxTvl = ((sequencerBond + 1) * 10_000 - 1) / BOND_BPS;
        uint256 current = ICollateralVault(vault).tvl();
        return maxTvl > current ? maxTvl - current : 0;
    }

    /// @notice True while the paired vault can accept deposits (capacity aside).
    function acceptingDeposits() external view returns (bool) {
        return !closeOnly && vault != address(0);
    }

    /// @notice The public-input commitment the proof must satisfy. Mirrors
    /// `crates/prover::PublicInputs::commitment`. `orderedRoot`, `withdrawalsRoot`, and
    /// `rejectedRoot` are DERIVED by the guest circuit (P1: `perp_core::commitment::
    /// derive_roots`) — `withdrawalsRoot` from the batch's burned notes (audit F2),
    /// `orderedRoot`/`rejectedRoot` by merklizing the manifest's committed order-hash
    /// lists. CAVEAT (Proof-v2): the ordered-vs-rejected SPLIT is not itself proven —
    /// receipts + inclusion slashing do not prevent a dishonest rejection from
    /// dismissing a challenge. Rejection legitimacy still trusts the matcher.
    /// Enforcement of the derived values requires the real verifier
    /// (P2); under MockZkVerifier the check is a stand-in.
    /// `depositsRoot` (SEC-019) is likewise DERIVED by the guest circuit, by folding
    /// the same keccak hash chain over exactly the deposits the batch credits. It is
    /// appended LAST, matching the Rust word order in `PublicInputs::commitment`; the
    /// 225-byte preimage is pinned on both sides by a shared known-answer vector
    /// (`crates/prover/tests/vectors.rs` ↔ `CrossLayer.t.sol`). Unlike the other
    /// derived roots this one is ALSO checkable on L1 — every settle path pins it to the
    /// vault's own deposit chain at the credited prefix — so it holds even under the
    /// mock verifier.
    function publicCommitment(
        bytes32 prevRoot,
        bytes32 manifestHash,
        bytes32 newRoot,
        bytes32 orderedRoot,
        bytes32 withdrawalsRoot,
        bytes32 rejectedRoot,
        bytes32 depositsRoot
    ) public pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                DOMAIN_STATE_ROOT,
                prevRoot,
                manifestHash,
                newRoot,
                orderedRoot,
                withdrawalsRoot,
                rejectedRoot,
                depositsRoot
            )
        );
    }

    /// @dev A06 wind-down commitments append one little-endian phase word to the
    /// legacy seven-root preimage. Ordinary `publicCommitment` is intentionally
    /// unchanged, so existing batches/vectors do not move.
    function windDownCommitment(
        bytes32 prevRoot,
        bytes32 manifestHash,
        bytes32 newRoot,
        bytes32 orderedRoot,
        bytes32 withdrawalsRoot,
        bytes32 rejectedRoot,
        bytes32 depositsRoot,
        uint64 phase
    ) public pure returns (bytes32) {
        require(phase == 1 || phase == 2, "bad wind-down phase");
        return keccak256(
            abi.encodePacked(
                DOMAIN_STATE_ROOT,
                prevRoot,
                manifestHash,
                newRoot,
                orderedRoot,
                withdrawalsRoot,
                rejectedRoot,
                depositsRoot,
                _leWord(phase)
            )
        );
    }

    /// @dev Deposit pin shared by every settle path. The batch claims to have consumed
    /// the vault's first `n` deposits; `depositsRoot` must be the vault's tip at exactly
    /// that prefix, `n` may not exceed the vault's head, and it may not go below the
    /// count already settled. The head bound matters: `depositTipAt(n)` is zero beyond
    /// the head, which equals the genesis tip, so without it a zero root would accept any
    /// count. For a non-zero tip the count is exact by collision resistance, and it
    /// equals the proven `consumed_deposit_count` committed in the state root.
    ///
    /// A PREFIX, deliberately, not the live head: deposits landing after the proof was
    /// built simply belong to a later batch, so a deposit can never race a settle.
    ///
    /// With no vault wired, no deposit may be credited: only `n == 0` with the genesis
    /// root passes.
    function _pinDeposits(bytes32 depositsRoot, uint64 n) internal view {
        uint64 head;
        bytes32 tip;
        if (vault != address(0)) {
            head = ICollateralVault(vault).depositCount();
            if (n <= head) tip = ICollateralVault(vault).depositTipAt(n);
        }
        if (n > head || n < consumedDepositCount) revert BadDepositCount();
        require(depositsRoot == tip, "deposits: root != L1 chain prefix");
    }

    /// @dev Records a verified batch. `kind` 0 = ordinary settle, 1 = wind-down
    /// SettleAll, 2 = wind-down exit.
    function _recordBatch(
        bytes32 prevRoot,
        bytes32 manifestHash,
        bytes32 newRoot,
        bytes32 orderedRoot,
        bytes32 withdrawalsRoot,
        bytes32 rejectedRoot,
        uint64 newDepositCount,
        uint8 kind
    ) internal {
        uint256 batchId = batchCount;
        batches[batchId] = Batch({
            manifestHash: manifestHash,
            orderedRoot: orderedRoot,
            rejectedRoot: rejectedRoot,
            settledAtBlock: block.number
        });
        currentStateRoot = newRoot;
        lastProgressBlock = block.number;
        batchCount = batchId + 1;
        consumedDepositCount = newDepositCount;
        if (kind == 0) {
            emit BatchSettled(batchId, prevRoot, newRoot, manifestHash);
        } else {
            if (kind == 1) windDownSettled = true;
            emit FinalSettle(batchId, prevRoot, newRoot, manifestHash);
        }
        // publish this batch's authorized withdrawals to the vault: only a verified
        // batch reaches here, so withdrawals are gated on hard finality.
        if (vault != address(0)) {
            ICollateralVault(vault).publishWithdrawals(withdrawalsRoot, batchId);
        }
    }

    /// @notice Settle a batch: verify its validity proof and advance the root.
    /// This is the only path to SETTLED finality while live. The bond is not checked
    /// here; the deposit gate keeps it above the floor instead.
    function settleBatch(
        bytes32 prevRoot,
        bytes32 manifestHash,
        bytes32 newRoot,
        bytes32 orderedRoot,
        bytes32 withdrawalsRoot,
        bytes32 rejectedRoot,
        bytes32 depositsRoot,
        uint64 newDepositCount,
        bytes calldata proof
    ) external onlySequencer {
        if (closeOnly) revert InCloseOnly();
        if (prevRoot != currentStateRoot) revert BadPrevRoot();
        // Pin the credited deposits to the L1 deposit chain BEFORE verifying the
        // proof: the circuit only proves it folded SOME chain consistently.
        _pinDeposits(depositsRoot, newDepositCount);
        bytes32 commitment =
            publicCommitment(prevRoot, manifestHash, newRoot, orderedRoot, withdrawalsRoot, rejectedRoot, depositsRoot);
        if (!verifier.verify(commitment, proof)) revert BadProof();
        _recordBatch(prevRoot, manifestHash, newRoot, orderedRoot, withdrawalsRoot, rejectedRoot, newDepositCount, 0);
    }

    /// @notice Governance wind-down settlement that lands only in close-only. It keeps
    /// the ZK proof and prev-root continuity, so governance can only advance
    /// proof-valid state, never fabricate balances. Gated on close-only, a grace window
    /// and `governance`. One-shot. The consumed deposit count is frozen in close-only:
    /// `newDepositCount` must equal `consumedDepositCount`, so the refund boundary the
    /// vault uses never moves.
    function finalSettle(
        bytes32 prevRoot,
        bytes32 manifestHash,
        bytes32 newRoot,
        bytes32 orderedRoot,
        bytes32 withdrawalsRoot,
        bytes32 rejectedRoot,
        bytes32 depositsRoot,
        uint64 newDepositCount,
        bytes calldata proof
    ) external {
        if (msg.sender != governance) revert NotGovernance();
        if (!closeOnly) revert NotCloseOnly();
        require(!windDownSettled, "wind-down already settled");
        if (block.number < closeOnlyBlock + finalSettleGraceBlocks) revert GraceNotExpired();
        if (prevRoot != currentStateRoot) revert BadPrevRoot();
        if (newDepositCount != consumedDepositCount) revert DepositsFrozen();
        _pinDeposits(depositsRoot, newDepositCount);
        bytes32 commitment = windDownCommitment(
            prevRoot, manifestHash, newRoot, orderedRoot, withdrawalsRoot, rejectedRoot, depositsRoot, 1
        );
        if (!verifier.verify(commitment, proof)) revert BadProof();
        _recordBatch(prevRoot, manifestHash, newRoot, orderedRoot, withdrawalsRoot, rejectedRoot, newDepositCount, 1);
    }

    /// @notice A06 post-wind-down exit batches. The proof commitment is phase 2,
    /// whose circuit grammar permits only price-free WindDownUnbind/Withdraw ops.
    /// This is repeatable so users can exit independently after the one-shot close.
    /// The consumed deposit count stays frozen, as in `finalSettle`.
    function finalExit(
        bytes32 prevRoot,
        bytes32 manifestHash,
        bytes32 newRoot,
        bytes32 orderedRoot,
        bytes32 withdrawalsRoot,
        bytes32 rejectedRoot,
        bytes32 depositsRoot,
        uint64 newDepositCount,
        bytes calldata proof
    ) external {
        if (msg.sender != governance) revert NotGovernance();
        if (!closeOnly) revert NotCloseOnly();
        require(windDownSettled, "wind-down not settled");
        if (prevRoot != currentStateRoot) revert BadPrevRoot();
        if (newDepositCount != consumedDepositCount) revert DepositsFrozen();
        _pinDeposits(depositsRoot, newDepositCount);
        bytes32 commitment = windDownCommitment(
            prevRoot, manifestHash, newRoot, orderedRoot, withdrawalsRoot, rejectedRoot, depositsRoot, 2
        );
        if (!verifier.verify(commitment, proof)) revert BadProof();
        _recordBatch(prevRoot, manifestHash, newRoot, orderedRoot, withdrawalsRoot, rejectedRoot, newDepositCount, 2);
    }

    /// @dev Irreversible. Latches the block and the phase-0 batch count on first entry.
    function _enterCloseOnly(string memory reason) internal {
        if (closeOnly) return;
        closeOnly = true;
        closeOnlyBlock = block.number;
        closeOnlyBatchCount = batchCount;
        emit CloseOnlyEntered(reason);
    }

    /// @notice Anyone can force close-only when the root has not progressed within
    /// `livenessTimeoutBlocks`, or when the oldest deposit the settled state has not
    /// consumed landed more than `livenessTimeoutBlocks` ago. A no-op once close-only.
    /// The stalled-root path applies once the stack holds something a wind-down would
    /// protect: a settled batch, a vault deposit or an open challenge. Until then a
    /// fresh deployment cannot be closed by waiting out the window; the window itself
    /// is still measured from `lastProgressBlock`.
    function triggerCloseOnly() external {
        if (closeOnly) return;
        uint64 deposits = vault == address(0) ? 0 : ICollateralVault(vault).depositCount();
        bool stalled = (batchCount != 0 || deposits != 0 || _open.length != 0)
            && block.number - lastProgressBlock > livenessTimeoutBlocks;
        bool starved;
        if (!stalled) {
            uint64 c = consumedDepositCount;
            if (deposits > c) {
                starved = block.number - ICollateralVault(vault).depositBlock(c) > livenessTimeoutBlocks;
            }
        }
        if (!stalled && !starved) revert LivenessNotExpired();
        _enterCloseOnly(stalled ? "liveness timeout" : "deposit inclusion timeout");
    }

    /// @notice Governance enters close-only immediately (emergency brake and orderly
    /// migration path). Irreversible; refunds and wind-down follow the same rules.
    function enterCloseOnly() external {
        if (msg.sender != governance) revert NotGovernance();
        _enterCloseOnly("governance");
    }

    // --- inclusion challenge game ---------------------------------------------

    /// @notice The receipt signing digest, reconstructed to match
    /// `perp-core::Receipt::signing_digest` exactly (Keccak over the
    /// domain-tagged, little-endian-packed words). Kept as a cross-layer helper; it is
    /// not accepted as a challenge authorization.
    function receiptDigest(bytes32 orderHash, uint64 seqNo, uint64 recvTimeMs, uint64 batchIdHint)
        public
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encodePacked(DOMAIN_ORDER_HASH, orderHash, _leWord(seqNo), _leWord(recvTimeMs), _leWord(batchIdHint))
        );
    }

    /// @notice The digest the enclave signs to authorize an L1 inclusion challenge for
    /// `orderHash`, bound to this chain, this settlement and the `beneficiary` a fine
    /// would be paid to. The 256-byte preimage is structurally distinct from the
    /// perp-core receipt digest.
    function challengeAuthDigest(
        bytes32 orderHash,
        uint64 seqNo,
        uint64 recvTimeMs,
        uint64 batchIdHint,
        address beneficiary
    ) public view returns (bytes32) {
        return keccak256(
            abi.encode(
                CHALLENGE_AUTH_TAG, block.chainid, address(this), orderHash, seqNo, recvTimeMs, batchIdHint, beneficiary
            )
        );
    }

    /// @notice The domain-separated, batch-bound Merkle leaf an order occupies in
    /// a batch's `orderedRoot`. Hashing the leaf (rather than using the raw
    /// `orderHash`) closes the second-preimage / node-as-leaf forgery, and binding
    /// `batchId` stops an answer against an unrelated batch (audit F1). The off-chain
    /// tree MUST be built over these same leaves.
    function inclusionLeaf(uint256 batchId, bytes32 orderHash) public pure returns (bytes32) {
        // The `uint8(0x00)` domain tag makes the preimage 65 bytes — structurally
        // distinct from a 64-byte MerkleLib internal node (keccak of two bytes32) — so a
        // crafted internal node can never be presented as an inclusion leaf (audit). A
        // distinct tag from `rejectionLeaf` (0x01) also keeps the two leaf domains apart.
        return keccak256(abi.encodePacked(uint8(0x00), batchId, orderHash));
    }

    /// @notice The batch-bound Merkle leaf an order occupies in a batch's
    /// `rejectedRoot`. A distinct one-byte domain tag from `inclusionLeaf` so a
    /// rejected leaf can never be replayed as an inclusion proof (or vice-versa) at
    /// the same `(batchId, orderHash)` (audit DP-004). The off-chain rejected tree
    /// MUST be built over these leaves.
    function rejectionLeaf(uint256 batchId, bytes32 orderHash) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(uint8(0x01), batchId, orderHash));
    }

    /// @notice Open an inclusion challenge with an enclave-signed authorization
    /// (`challengeAuthDigest`, signature `r‖s‖v`). Anyone may submit it and post the
    /// `challengeBond` stake; a fine always goes to the signed `beneficiary`, the stake
    /// back to the submitter. Each order hash can be challenged at most once.
    function challengeInclusion(
        bytes32 orderHash,
        uint64 seqNo,
        uint64 recvTimeMs,
        uint64 batchIdHint,
        address beneficiary,
        bytes calldata sig
    ) external payable {
        if (closeOnly) revert InCloseOnly();
        if (challengeResolved[orderHash]) revert AlreadyResolved();
        if (challenges[orderHash].open) revert ChallengeExists();
        if (msg.value != challengeBond) revert WrongChallengeBond();
        if (beneficiary == address(0)) revert BadBeneficiary();
        address signer =
            _recoverSigner(challengeAuthDigest(orderHash, seqNo, recvTimeMs, batchIdHint, beneficiary), sig);
        if (signer == address(0) || signer != enclaveSigner) revert BadReceiptSignature();
        // Ripeness SLA: the order must be overdue by `inclusionDeadlineSecs` before it
        // can be challenged (recvTimeMs is milliseconds).
        if (block.timestamp < recvTimeMs / 1000 + inclusionDeadlineSecs) revert NotRipe();

        uint256 openBatchCount = batchCount;
        challenges[orderHash] = Challenge({
            beneficiary: beneficiary,
            batchIdHint: batchIdHint,
            openedBlock: block.number,
            openBatchCount: openBatchCount,
            bond: msg.value,
            open: true
        });
        _challengeStaker[orderHash] = msg.sender;
        _open.push(orderHash);
        _openPos[orderHash] = _open.length;
        emit InclusionChallenged(orderHash, beneficiary, msg.sender, openBatchCount);
    }

    /// @notice Answer an open challenge by proving the order hash is a member of a
    /// settled batch's `orderedRoot` (leaf `inclusionLeaf(batchId, orderHash)`).
    /// Permissionless: the proof is the authority. Valid until a slash or release
    /// lands. The stake goes back to the submitter when `batchId` settled after the
    /// challenge opened (the challenge forced the order in), otherwise to the sequencer.
    function answerChallenge(bytes32 orderHash, uint256 batchId, bytes32[] calldata proof) external {
        if (!challenges[orderHash].open) revert NoSuchChallenge();
        _requireSettled(batchId);
        _answer(orderHash, batchId, false, proof);
    }

    /// @notice Answer an open challenge by proving the order was DECLARED REJECTED in a
    /// settled batch's `rejectedRoot` (leaf `rejectionLeaf(batchId, orderHash)`). This
    /// is membership, not proof that the reason was legitimate. Permissionless; stake
    /// routing as in `answerChallenge`.
    function answerByRejection(bytes32 orderHash, uint256 batchId, bytes32[] calldata proof) external {
        if (!challenges[orderHash].open) revert NoSuchChallenge();
        _requireSettled(batchId);
        _answer(orderHash, batchId, true, proof);
    }

    /// @notice Batched, permissionless answers against one settled batch. Entries
    /// whose challenge is no longer open are skipped (so concurrent answerers do not
    /// collide); a length mismatch, an unsettled batch or any invalid proof reverts the
    /// whole call.
    /// @return answered the number of challenges this call resolved
    function answerChallenges(
        uint256 batchId,
        bytes32[] calldata orderHashes,
        bool[] calldata byRejection,
        bytes32[][] calldata proofs
    ) external returns (uint256 answered) {
        uint256 n = orderHashes.length;
        if (byRejection.length != n || proofs.length != n) revert LengthMismatch();
        _requireSettled(batchId);
        for (uint256 i = 0; i < n; i++) {
            bytes32 h = orderHashes[i];
            if (!challenges[h].open) continue;
            _answer(h, batchId, byRejection[i], proofs[i]);
            answered++;
        }
    }

    /// @notice Fine the sequencer for an open challenge it never answered. Requires
    /// `progressBatches` phase-0 batches settled since the challenge opened (only
    /// batches before close-only count) and `challengeGraceBlocks` past the settle
    /// block of the last of them. Pays `min(sequencerBond, slashPayoutCap)` to the
    /// beneficiary and refunds the stake to the submitter. Settlement continues; the
    /// smaller bond lowers deposit capacity until it is topped up. When the bond is
    /// below the cap the fine is reduced, so the beneficiary chooses when to take it: a
    /// submitter who is not the beneficiary may trigger it (and so recover its stake)
    /// only `livenessTimeoutBlocks` after the slash first became possible, and nobody
    /// else may trigger it at all.
    function slashUnanswered(bytes32 orderHash) external {
        Challenge memory c = challenges[orderHash];
        if (!c.open) revert NoSuchChallenge();
        uint256 target = c.openBatchCount + progressBatches;
        uint256 phase0 = closeOnly ? closeOnlyBatchCount : batchCount;
        if (phase0 < target) revert NoProgress();
        uint256 expiry = batches[target - 1].settledAtBlock + challengeGraceBlocks;
        if (block.number <= expiry) revert ChallengeNotExpired();
        uint256 payout = sequencerBond < slashPayoutCap ? sequencerBond : slashPayoutCap;
        address staker = _challengeStaker[orderHash];
        if (
            payout < slashPayoutCap && msg.sender != c.beneficiary
                && (msg.sender != staker || block.number <= expiry + livenessTimeoutBlocks)
        ) revert ShortBondSlashRestricted();
        _close(orderHash, staker);
        sequencerBond -= payout;
        slashCount++;
        pendingUsdc[c.beneficiary] += payout;
        emit SequencerSlashed(orderHash, c.beneficiary, payout);
    }

    /// @notice Release an open challenge that can no longer reach the slash condition
    /// because close-only began before `progressBatches` phase-0 batches settled after
    /// it. Refunds the stake to the submitter; the order hash stays resolved. The
    /// condition is the exact complement of `slashUnanswered`'s progress gate.
    function releaseStaleChallenge(bytes32 orderHash) external {
        Challenge storage c = challenges[orderHash];
        if (!c.open || !closeOnly || c.openBatchCount + progressBatches <= closeOnlyBatchCount) revert NotStale();
        _close(orderHash, _challengeStaker[orderHash]);
        emit ChallengeReleased(orderHash);
    }

    /// @notice Number of open challenges.
    function openChallengeCount() external view returns (uint256) {
        return _open.length;
    }

    /// @notice A page of open challenge hashes, `[start, start + max)` of the open set
    /// (order changes as challenges close: swap-and-pop). `max` is capped at 512.
    function openChallenges(uint256 start, uint256 max) external view returns (bytes32[] memory page) {
        uint256 len = _open.length;
        if (max > MAX_OPEN_PAGE) max = MAX_OPEN_PAGE;
        uint256 end = start < len ? (len - start < max ? len : start + max) : start;
        page = new bytes32[](end - start);
        for (uint256 i = start; i < end; i++) {
            page[i - start] = _open[i];
        }
    }

    function _requireSettled(uint256 batchId) internal view {
        if (batchId >= batchCount) revert BatchNotSettled();
    }

    /// @dev Verify one answer against a settled batch, then close the challenge.
    function _answer(bytes32 orderHash, uint256 batchId, bool byRejection, bytes32[] calldata proof) internal {
        Batch storage b = batches[batchId];
        if (byRejection) {
            if (!b.rejectedRoot.verify(rejectionLeaf(batchId, orderHash), proof)) revert NotRejected();
        } else if (!b.orderedRoot.verify(inclusionLeaf(batchId, orderHash), proof)) {
            revert NotIncluded();
        }
        address refundTo = batchId >= challenges[orderHash].openBatchCount ? _challengeStaker[orderHash] : sequencer;
        _close(orderHash, refundTo);
        if (byRejection) emit RejectionAnswered(orderHash, batchId);
        else emit InclusionAnswered(orderHash, batchId);
    }

    /// @dev Ends an open challenge: removes it and its staker, swap-and-pops the open
    /// set, marks the hash resolved and credits the stake to `stakeTo`.
    function _close(bytes32 orderHash, address stakeTo) internal {
        uint256 stake = challenges[orderHash].bond;
        delete challenges[orderHash];
        delete _challengeStaker[orderHash];
        uint256 pos = _openPos[orderHash];
        uint256 last = _open.length;
        if (pos != last) {
            bytes32 moved = _open[last - 1];
            _open[pos - 1] = moved;
            _openPos[moved] = pos;
        }
        _open.pop();
        delete _openPos[orderHash];
        challengeResolved[orderHash] = true;
        pendingEth[stakeTo] += stake;
    }

    /// @dev Recover the signer of `digest` from a 65-byte `r‖s‖v` signature. Malformed
    /// length, upper-half `s` (malleable) or `v` outside {27, 28} revert.
    function _recoverSigner(bytes32 digest, bytes calldata sig) internal pure returns (address) {
        if (sig.length != 65) revert NonCanonicalSignature();
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        if (uint256(s) > SECP256K1_N_HALF || (v != 27 && v != 28)) revert NonCanonicalSignature();
        return ecrecover(digest, v, r, s);
    }

    /// @notice Withdraw a native-token refund credited to `msg.sender` (audit DP-011).
    function claimEth() external {
        _claimEth(msg.sender);
    }

    /// @notice Withdraw the native-token refund credited to `msg.sender`, paid to `to`
    /// (for an account that cannot receive ETH itself).
    function claimEthTo(address to) external {
        _claimEth(to);
    }

    /// @notice Withdraw slashed USDC credited to `msg.sender`. A recipient the token
    /// blocks can only fail their OWN claim; the slash already completed.
    function claimUsdc() external {
        _claimUsdc(msg.sender);
    }

    /// @notice Withdraw the slashed USDC credited to `msg.sender`, paid to `to` (for an
    /// account the token refuses to pay).
    function claimUsdcTo(address to) external {
        _claimUsdc(to);
    }

    /// @dev Checks-effects-interactions: zero the caller's balance (and log) before the
    /// transfer; a failed transfer reverts both.
    function _claimEth(address to) internal {
        if (to == address(0)) revert BadRecipient();
        uint256 amount = pendingEth[msg.sender];
        pendingEth[msg.sender] = 0;
        if (amount > 0) {
            emit EthClaimed(msg.sender, to, amount);
            (bool ok,) = to.call{value: amount}("");
            if (!ok) revert TransferFailed();
        }
    }

    /// @dev Checks-effects-interactions: zero the caller's balance (and log) before the
    /// transfer; a failed transfer reverts both.
    function _claimUsdc(address to) internal {
        if (to == address(0)) revert BadRecipient();
        uint256 amount = pendingUsdc[msg.sender];
        pendingUsdc[msg.sender] = 0;
        if (amount > 0) {
            emit UsdcClaimed(msg.sender, to, amount);
            IERC20Min tok = IERC20Min(ICollateralVault(vault).token());
            if (!tok.transfer(to, amount)) revert TransferFailed();
        }
    }

    /// @dev Encode a uint64 to match perp-core `hash::word_u64`: a 32-byte array
    /// whose bytes 0..8 are `v.to_le_bytes()` and bytes 8..32 are zero. In a
    /// big-endian bytes32 that means LE byte `i` sits at byte index `i` from the
    /// left, i.e. bit offset `8*(31-i)`.
    function _leWord(uint64 v) internal pure returns (bytes32 w) {
        unchecked {
            uint256 acc;
            for (uint256 i = 0; i < 8; i++) {
                acc |= uint256((v >> (8 * i)) & 0xff) << (8 * (31 - i));
            }
            w = bytes32(acc);
        }
    }
}

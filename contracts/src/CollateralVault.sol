// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MerkleLib} from "./libraries/MerkleLib.sol";

/// The ERC20 subset the vault uses (USDC). Kept local so the build needs no
/// OpenZeppelin (unavailable in this repo's vendored toolchain).
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

/// The settlement subset the vault reads to reject deposits into a dead system.
interface ISettlementCloseOnly {
    function closeOnly() external view returns (bool);
}

/// @title CollateralVault
/// @notice Holds pooled collateral (**USDC**, the chosen settlement asset) and
/// releases it only against a withdrawals root published by the settlement contract
/// from a SETTLED batch (§3: only settled state is withdrawable). The same mechanism
/// is the forced-exit path (§6): if the system is in close-only, users still claim
/// against the last settled withdrawals root — funds can be stalled but not stolen,
/// because release authority is the verified state, never the sequencer.
contract CollateralVault {
    using MerkleLib for bytes32;

    address public immutable settlement;
    /// The settlement asset held by the vault (USDC; 6 decimals → 1 base unit =
    /// 1 micro-USD = 1 engine quote unit, so on-chain amounts map 1:1 off-chain).
    IERC20 public immutable token;

    /// Withdrawals root from the most recently settled batch that published one.
    bytes32 public withdrawalsRoot;
    uint256 public withdrawalsEpoch;
    uint256 public totalDeposited;
    uint256 public totalWithdrawn;

    /// Spent withdrawal leaves (double-claim prevention).
    mapping(bytes32 => bool) public claimed;
    /// Every withdrawals root ever published by a settled batch. A claim may prove against
    /// ANY of these, so overwriting `withdrawalsRoot` with a later cumulative root can no
    /// longer strand an older authorized-but-unclaimed leaf (audit DP-012); `claimed[leaf]`
    /// still prevents double-claim.
    mapping(bytes32 => bool) public rootPublished;

    /// SEC-019: running keccak hash-chain over every credited deposit, in L1 order.
    /// Genesis is `bytes32(0)`. This is the AUTHORITATIVE record of what was actually
    /// paid into the vault; the settlement contract pins a proof's `deposits_root`
    /// against it, so the sequencer cannot credit a deposit that never happened,
    /// reorder deposits, replay one, or alter an amount/owner. A chain (not a Merkle
    /// set) is used deliberately: order is part of the commitment.
    bytes32 public depositChainTip;
    /// Number of leaves folded into `depositChainTip`. Doubles as the next deposit's
    /// `id`, which is bound into the leaf so an otherwise-identical repeat deposit
    /// (same sender, owner and amount) still produces a distinct leaf.
    uint64 public depositCount;

    /// @param from L1 payer (bound into the leaf; the funds' provenance).
    /// @param owner shielded-note owner the off-chain protocol must credit.
    /// @param amount USDC base units.
    /// @param id the deposit's index in the chain (pre-increment `depositCount`).
    /// @param newTip `depositChainTip` after folding this deposit — indexers and the
    ///        sequencer replay from these without re-deriving the chain themselves.
    event Deposit(address indexed from, bytes32 indexed owner, uint256 amount, uint64 id, bytes32 newTip);
    event WithdrawalsRootPublished(uint256 indexed epoch, bytes32 root);
    event Withdrawn(address indexed to, uint256 amount, uint256 nonce);

    error NotSettlement();
    error AlreadyClaimed();
    error BadWithdrawalProof();
    error TransferFailed();
    error InCloseOnly();

    modifier onlySettlement() {
        if (msg.sender != settlement) revert NotSettlement();
        _;
    }

    constructor(address _settlement, address _token) {
        settlement = _settlement;
        token = IERC20(_token);
    }

    /// @notice Deposit `amount` (USDC base units) into the pooled vault. The caller
    /// must have `approve`d the vault first. The off-chain protocol mints a shielded
    /// note of `amount` for `owner`; the commitment enters the note tree (§1).
    ///
    /// @dev SEC-019: the deposit is folded into `depositChainTip` BEFORE it can be
    /// credited off-chain. The leaf is
    /// `keccak256(abi.encodePacked(address from, bytes32 owner, uint256 amount, uint256 id))`
    /// and the fold is `keccak256(abi.encodePacked(bytes32 tip, bytes32 leaf))` — both
    /// reproduced byte-for-byte by `crates/perp-core/src/merkle.rs`
    /// (`deposit_leaf` / `deposit_chain_fold`) and in-circuit, and pinned on both sides
    /// by the same known-answer vectors. Do NOT change this encoding (no domain tag, no
    /// padded `from`, `id` as a full uint256 word) without changing the Rust side in the
    /// same commit: any divergence silently breaks the binding this whole mechanism exists
    /// to provide.
    /// @param amount USDC base units to pull from `msg.sender`.
    /// @param owner shielded-note owner to credit off-chain. Bound into the leaf, so the
    ///        sequencer cannot redirect the note to a different owner than the payer chose.
    function deposit(uint256 amount, bytes32 owner) external {
        // audit #11: refuse deposits once the system is in close-only. In close-only no
        // new batch settles, so a deposit made here would never be acknowledged into a
        // settled withdrawals root and the funds would be permanently unclaimable. Users
        // exit via `claim` against the last settled root, not by depositing more.
        if (ISettlementCloseOnly(settlement).closeOnly()) revert InCloseOnly();
        if (!token.transferFrom(msg.sender, address(this), amount)) revert TransferFailed();
        totalDeposited += amount;
        // `id` is the PRE-increment count, so the first deposit is id 0 (matching the
        // Rust vectors). Folded only after the transfer succeeded — a reverted deposit
        // must leave the chain untouched.
        bytes32 leaf = keccak256(abi.encodePacked(msg.sender, owner, amount, uint256(depositCount)));
        depositChainTip = keccak256(abi.encodePacked(depositChainTip, leaf));
        emit Deposit(msg.sender, owner, amount, depositCount, depositChainTip);
        depositCount += 1;
    }

    /// @notice Net ACCOUNTED collateral the bond floor scales off (audit Q1): the sum
    /// of `deposit()`s minus claimed withdrawals — NOT the raw token balance. Using
    /// the accounted figure makes the floor immune to donation/inflation griefing: a
    /// bare `token.transfer` into the vault (bypassing `deposit`) cannot push
    /// `requiredBond` up and stall settlement (review fix). For a pooled-collateral
    /// vault this is also the truer measure of value-at-risk.
    function tvl() external view returns (uint256) {
        return totalDeposited > totalWithdrawn ? totalDeposited - totalWithdrawn : 0;
    }

    /// @notice Called by the settlement contract when a batch settles, publishing
    /// that batch's authorized withdrawals (§3). Only a settled batch can reach
    /// here, so withdrawals are inherently gated on hard finality.
    ///
    /// @dev INVARIANT (prover-side): `root` MUST be the **cumulative** root of all
    /// authorized-but-unclaimed withdrawals as of this batch — NOT just the new
    /// withdrawals of this batch. This call overwrites the previous root, so any leaf
    /// not carried forward becomes unclaimable and the user is stranded. Because
    /// `claimed[leaf]` is on-chain, the proven transition can (and must) drop
    /// already-claimed leaves while retaining every still-unclaimed one. The gateway
    /// honors this: each settle it prunes leaves the vault already marks `claimed`
    /// and rebuilds the root over every still-unclaimed leaf (see
    /// `crates/gateway/src/withdrawals.rs`).
    function publishWithdrawals(bytes32 root, uint256 epoch) external onlySettlement {
        withdrawalsRoot = root;
        withdrawalsEpoch = epoch;
        // audit DP-012: remember every published root so an older one can't strand a claim — but
        // NEVER register the empty-batch root bytes32(0) as claimable (review follow-up).
        if (root != bytes32(0)) {
            rootPublished[root] = true;
        }
        emit WithdrawalsRootPublished(epoch, root);
    }

    /// @notice Claim an authorized withdrawal by proving membership in the current
    /// withdrawals root. Works identically in normal and forced-exit/close-only
    /// modes — the authority is the settled root, not the operator. Pays out in USDC.
    /// @param to recipient (the leaf binds the funds to this address)
    /// @param amount amount to release (USDC base units)
    /// @param nonce per-withdrawal uniqueness
    /// @param root a published withdrawals root the leaf is a member of (any past root, so
    ///        a later cumulative root omitting the leaf can no longer strand it — DP-012)
    /// @param proof Merkle proof of `leaf` against `root`
    function claim(address to, uint256 amount, uint256 nonce, bytes32 root, bytes32[] calldata proof) external {
        bytes32 leaf = keccak256(abi.encodePacked(to, amount, nonce));
        if (claimed[leaf]) revert AlreadyClaimed();
        // audit DP-012: accept ANY published (non-zero) root, not just the latest — so a later
        // cumulative root that omits this (still-unclaimed) leaf cannot strand it.
        if (root == bytes32(0) || !rootPublished[root] || !root.verify(leaf, proof)) {
            revert BadWithdrawalProof();
        }
        claimed[leaf] = true;
        totalWithdrawn += amount;
        if (!token.transfer(to, amount)) revert TransferFailed();
        emit Withdrawn(to, amount, nonce);
    }
}

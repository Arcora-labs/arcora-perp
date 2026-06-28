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

    event Deposit(address indexed from, uint256 amount);
    event WithdrawalsRootPublished(uint256 indexed epoch, bytes32 root);
    event Withdrawn(address indexed to, uint256 amount, uint256 nonce);

    error NotSettlement();
    error AlreadyClaimed();
    error BadWithdrawalProof();
    error TransferFailed();

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
    /// note for `msg.sender` of `amount`; the commitment enters the note tree (§1).
    function deposit(uint256 amount) external {
        if (!token.transferFrom(msg.sender, address(this), amount)) revert TransferFailed();
        totalDeposited += amount;
        emit Deposit(msg.sender, amount);
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
        emit WithdrawalsRootPublished(epoch, root);
    }

    /// @notice Claim an authorized withdrawal by proving membership in the current
    /// withdrawals root. Works identically in normal and forced-exit/close-only
    /// modes — the authority is the settled root, not the operator. Pays out in USDC.
    /// @param to recipient (the leaf binds the funds to this address)
    /// @param amount amount to release (USDC base units)
    /// @param nonce per-withdrawal uniqueness
    /// @param proof Merkle proof against `withdrawalsRoot`
    function claim(address to, uint256 amount, uint256 nonce, bytes32[] calldata proof) external {
        bytes32 leaf = keccak256(abi.encodePacked(to, amount, nonce));
        if (claimed[leaf]) revert AlreadyClaimed();
        if (!withdrawalsRoot.verify(leaf, proof)) revert BadWithdrawalProof();
        claimed[leaf] = true;
        totalWithdrawn += amount;
        if (!token.transfer(to, amount)) revert TransferFailed();
        emit Withdrawn(to, amount, nonce);
    }
}

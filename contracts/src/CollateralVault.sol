// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MerkleLib} from "./libraries/MerkleLib.sol";

/// @title CollateralVault
/// @notice Holds pooled collateral (native ETH in this build) and releases it
/// only against a withdrawals root published by the settlement contract from a
/// SETTLED batch (§3: only settled state is withdrawable). The same mechanism is
/// the forced-exit path (§6): if the system is in close-only, users still claim
/// against the last settled withdrawals root — funds can be stalled but not
/// stolen, because release authority is the verified state, never the sequencer.
contract CollateralVault {
    using MerkleLib for bytes32;

    address public immutable settlement;

    /// Withdrawals root from the most recently settled batch that published one.
    bytes32 public withdrawalsRoot;
    uint256 public withdrawalsEpoch;
    uint256 public totalDeposited;

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

    constructor(address _settlement) {
        settlement = _settlement;
    }

    /// @notice Deposit collateral. The off-chain protocol mints a shielded note
    /// for `msg.sender` of `msg.value`; the commitment enters the note tree (§1).
    function deposit() external payable {
        totalDeposited += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    /// @notice Called by the settlement contract when a batch settles, publishing
    /// that batch's authorized withdrawals (§3). Only a settled batch can reach
    /// here, so withdrawals are inherently gated on hard finality.
    function publishWithdrawals(bytes32 root, uint256 epoch) external onlySettlement {
        withdrawalsRoot = root;
        withdrawalsEpoch = epoch;
        emit WithdrawalsRootPublished(epoch, root);
    }

    /// @notice Claim an authorized withdrawal by proving membership in the current
    /// withdrawals root. Works identically in normal and forced-exit/close-only
    /// modes — the authority is the settled root, not the operator.
    /// @param to recipient (the leaf binds the funds to this address)
    /// @param amount amount to release
    /// @param nonce per-withdrawal uniqueness
    /// @param proof Merkle proof against `withdrawalsRoot`
    function claim(address to, uint256 amount, uint256 nonce, bytes32[] calldata proof) external {
        bytes32 leaf = keccak256(abi.encodePacked(to, amount, nonce));
        if (claimed[leaf]) revert AlreadyClaimed();
        if (!withdrawalsRoot.verify(leaf, proof)) revert BadWithdrawalProof();
        claimed[leaf] = true;
        (bool ok,) = to.call{value: amount}("");
        if (!ok) revert TransferFailed();
        emit Withdrawn(to, amount, nonce);
    }
}

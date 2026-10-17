// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IWithdrawalsPublisherTarget {
    function publishWithdrawals(bytes32 root, uint256 epoch) external;
}

/// @title MockSettlementGate
/// @notice Test-only stand-in for the settlement side of CollateralVault: it answers
/// the vault's `ISettlementGate` reads from plain setters and can publish withdrawals
/// roots as the vault's settlement. Deploy the vault with this contract as its
/// `settlement`, then `setVault(vault)` to pair them.
///
/// `depositGate(newTvl)` mirrors DarkPerpSettlement's precedence: `forcedGate` (when
/// non-zero) wins; otherwise 3 for a caller other than `vault`, 1 in close-only, 2 when
/// `newTvl > maxTvl`, else 0.
contract MockSettlementGate {
    address public vault;
    bool public closeOnly;
    uint64 public consumedDepositCount;
    /// Largest TVL a deposit may reach before the gate reports over-capacity (2).
    uint256 public maxTvl = type(uint256).max;
    /// Non-zero: returned by `depositGate` unconditionally.
    uint8 public forcedGate;

    function setVault(address v) external {
        vault = v;
    }

    function setCloseOnly(bool v) external {
        closeOnly = v;
    }

    function setConsumedDepositCount(uint64 c) external {
        consumedDepositCount = c;
    }

    function setMaxTvl(uint256 m) external {
        maxTvl = m;
    }

    function setForcedGate(uint8 g) external {
        forcedGate = g;
    }

    function depositGate(uint256 newTvl) external view returns (uint8) {
        if (forcedGate != 0) return forcedGate;
        if (msg.sender != vault) return 3;
        if (closeOnly) return 1;
        if (newTvl > maxTvl) return 2;
        return 0;
    }

    /// Publishes `root` to vault `v` with this contract as the caller (the vault's
    /// `onlySettlement` check passes only for the vault deployed with this gate).
    function publishTo(address v, bytes32 root, uint256 epoch) external {
        IWithdrawalsPublisherTarget(v).publishWithdrawals(root, epoch);
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import {IZkVerifier} from "./interfaces/IZkVerifier.sol";

interface IClockSettlement {
    function verifier() external view returns (address);
    function sequencer() external view returns (address);
    function governance() external view returns (address);
    function batchCount() external view returns (uint256);
    function currentStateRoot() external view returns (bytes32);
    function closeOnly() external view returns (bool);
    function windDownSettled() external view returns (bool);
}

/// @notice New-deployment verifier: every settlement path requires a pre-proof
/// clock registration AND a version-2 SP1 commitment. Never deploy with a mock
/// inner verifier for real collateral. Existing settlement/vault checks remain.
contract ClockBoundVerifier is IZkVerifier {
    bytes32 public constant DOMAIN = keccak256("arcora:clock-bound-proof:v2");
    uint64 public constant proofVersion = 2;
    address public immutable configurator;
    IZkVerifier public immutable innerVerifier;
    uint64 public immutable maxWindowMs;
    uint64 public immutable clockSkewMs;
    IClockSettlement public settlement;
    uint64 public lastTimedMs;

    struct Anchor {
        bytes32 previousRoot;
        bytes32 baseCommitment;
        bytes32 receipt;
        uint64 firstMs;
        uint64 lastMs;
        uint64 timedOps;
        uint64 anchoredAtMs;
        bool exists;
    }
    mapping(uint64 => mapping(uint8 => Anchor)) private anchors;
    error InvalidConfiguration();
    error Unauthorized();
    error BadContext();
    error InvalidTime();
    error ReplacementForbidden();
    error MissingAnchor();
    event ClockRegistered(uint64 indexed batchId, uint8 indexed phase, bytes32 receipt);

    constructor(IZkVerifier inner_, uint64 maxWindowMs_, uint64 clockSkewMs_) {
        if (address(inner_).code.length == 0 || maxWindowMs_ == 0) revert InvalidConfiguration();
        innerVerifier = inner_;
        maxWindowMs = maxWindowMs_;
        clockSkewMs = clockSkewMs_;
        configurator = msg.sender;
    }

    /// One-time circular-deployment binding. No setter or bypass after binding.
    function bindSettlement(IClockSettlement target) external {
        if (msg.sender != configurator) revert Unauthorized();
        if (
            address(settlement) != address(0) || address(target).code.length == 0 || target.verifier() != address(this)
                || target.batchCount() != 0 || block.chainid == 0 || block.chainid > type(uint64).max
        ) revert InvalidConfiguration();
        settlement = target;
    }

    function phase() public view returns (uint8) {
        if (!settlement.closeOnly()) return 0;
        return settlement.windDownSettled() ? 2 : 1;
    }

    function anchor(uint64 batchId, uint8 phase_) external view returns (Anchor memory) {
        return anchors[batchId][phase_];
    }

    function register(
        uint64 batchId,
        bytes32 previousRoot,
        bytes32 baseCommitment,
        uint64 firstMs,
        uint64 lastMs,
        uint64 timedOps,
        uint8 phase_
    ) external returns (bytes32) {
        if (address(settlement) == address(0)) revert InvalidConfiguration();
        if (msg.sender != (phase_ == 0 ? settlement.sequencer() : settlement.governance())) revert Unauthorized();
        if (phase_ != phase() || batchId != settlement.batchCount() || previousRoot != settlement.currentStateRoot()) {
            revert BadContext();
        }
        Anchor storage a = anchors[batchId][phase_];
        if (a.exists) {
            if (
                a.previousRoot != previousRoot || a.baseCommitment != baseCommitment || a.firstMs != firstMs
                    || a.lastMs != lastMs || a.timedOps != timedOps
            ) revert ReplacementForbidden();
            return a.receipt; // exact retry never re-stamps time after a proof delay
        }
        if (block.timestamp > type(uint64).max / 1000) revert InvalidTime();
        uint64 at = uint64(block.timestamp * 1000);
        if (firstMs > lastMs || lastMs - firstMs > maxWindowMs) revert InvalidTime();
        if (timedOps == 0) {
            if (firstMs != 0 || lastMs != 0) revert InvalidTime();
        } else {
            if (
                firstMs < lastTimedMs || uint256(lastMs) + clockSkewMs < at
                    || uint256(lastMs) > uint256(at) + clockSkewMs
            ) revert InvalidTime();
            lastTimedMs = lastMs;
        }
        bytes32 receipt = keccak256(
            abi.encode(
                DOMAIN,
                block.chainid,
                address(this),
                address(settlement),
                batchId,
                previousRoot,
                baseCommitment,
                phase_,
                firstMs,
                lastMs,
                timedOps,
                at,
                maxWindowMs,
                clockSkewMs
            )
        );
        anchors[batchId][phase_] = Anchor(previousRoot, baseCommitment, receipt, firstMs, lastMs, timedOps, at, true);
        emit ClockRegistered(batchId, phase_, receipt);
        return receipt;
    }

    /// Recompute against the current chain/domain, not only the stored hash.
    /// A copied pre-fork record must not authorize the same proof after a chain-ID change.
    function _currentReceipt(uint64 batchId, uint8 phase_, Anchor storage a) private view returns (bytes32) {
        return keccak256(
            abi.encode(
                DOMAIN,
                block.chainid,
                address(this),
                address(settlement),
                batchId,
                a.previousRoot,
                a.baseCommitment,
                phase_,
                a.firstMs,
                a.lastMs,
                a.timedOps,
                a.anchoredAtMs,
                maxWindowMs,
                clockSkewMs
            )
        );
    }

    function verify(bytes32 baseCommitment, bytes calldata proof) external view returns (bool) {
        if (
            address(settlement) == address(0) || msg.sender != address(settlement)
                || settlement.batchCount() > type(uint64).max || proof.length == 0
        ) return false;
        uint64 batchId = uint64(settlement.batchCount());
        uint8 phase_ = phase();
        Anchor storage a = anchors[batchId][phase_];
        if (
            !a.exists || a.previousRoot != settlement.currentStateRoot() || a.baseCommitment != baseCommitment
                || a.receipt != _currentReceipt(batchId, phase_, a)
        ) {
            return false;
        }
        // Consumed by the parent's atomic batchCount/root advance. Old anchors can
        // never authenticate the next batch, even if a transaction is resubmitted.
        bytes32 bound = keccak256(abi.encode(DOMAIN, baseCommitment, a.receipt));
        try innerVerifier.verify(bound, proof) returns (bool ok) {
            return ok;
        } catch {
            return false;
        }
    }
}

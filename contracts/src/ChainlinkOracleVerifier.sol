// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import {IZkVerifier} from "./interfaces/IZkVerifier.sol";
import {ClockBoundVerifier, IClockSettlement} from "./ClockBoundVerifier.sol";

interface IChainlinkStreamsVerifier {
    function verify(bytes calldata payload, bytes calldata parameterPayload) external payable returns (bytes memory);
}

/// @notice CANDIDATE, new-deployment-only Chainlink binding. Not the reviewed v2 route.
/// Stack: Settlement -> ClockBoundVerifier -> this -> SP1ZkVerifier(new guest key).
/// Reports are verified/registered after clock anchoring, before proving. The NEW
/// guest derives the evidence hash from every oracle-bearing op and checks its
/// normalized fields. A manifest-only oracle list is not sufficient.
contract ChainlinkOracleVerifier is IZkVerifier {
    bytes32 public constant DOMAIN = keccak256("arcora:chainlink-bound-proof:v1");
    bytes32 public constant EVIDENCE_DOMAIN = keccak256("arcora:chainlink-evidence:v1");
    uint256 public constant MAX_ENTRIES = 128;
    uint256 public constant MAX_FULL_REPORT = 4096;
    IZkVerifier public immutable innerVerifier;
    IChainlinkStreamsVerifier public immutable streamsVerifier;
    bytes32 public immutable policyHash;
    uint256 public immutable deploymentChainId;
    address public immutable configurator;
    ClockBoundVerifier public clockVerifier;
    bool private busy;

    struct Entry {
        uint64 marketId;
        uint64 nowMs;
        bytes baseReport;
        bytes quoteReport;
    }

    struct Record {
        bytes32 evidenceHash;
        bytes32 inputHash;
        bool exists;
    }

    struct ReportV3 {
        bytes32 feedId;
        uint32 validFrom;
        uint32 observed;
        uint192 nativeFee;
        uint192 linkFee;
        uint32 expires;
        int192 price;
        int192 bid;
        int192 ask;
    }
    mapping(bytes32 => Record) public records;
    error Configuration();
    error Unauthorized();
    error Context();
    error Evidence();
    error Replacement();
    event ClockBound(address indexed clock);
    event ReportsRegistered(bytes32 indexed clockCommitment, bytes32 evidenceHash);

    constructor(IZkVerifier inner_, IChainlinkStreamsVerifier streams_, bytes32 policy_) {
        if (
            address(inner_).code.length == 0 || address(streams_).code.length == 0 || policy_ == bytes32(0)
                || (block.chainid != 8453 && block.chainid != 84532)
        ) revert Configuration();
        innerVerifier = inner_;
        streamsVerifier = streams_;
        policyHash = policy_;
        deploymentChainId = block.chainid;
        configurator = msg.sender;
    }

    function bindClock(ClockBoundVerifier clock_) external {
        if (msg.sender != configurator) revert Unauthorized();
        if (
            address(clockVerifier) != address(0) || address(clock_).code.length == 0
                || address(clock_.innerVerifier()) != address(this)
        ) revert Configuration();
        IClockSettlement target = clock_.settlement();
        if (address(target) == address(0) || target.verifier() != address(clock_) || target.batchCount() != 0) {
            revert Configuration();
        }
        clockVerifier = clock_;
        emit ClockBound(address(clock_));
    }
    modifier nonReentrant() {
        if (busy) revert Context();
        busy = true;
        _;
        busy = false;
    }

    function register(uint64 batchId, uint8 phase_, Entry[] calldata entries) external nonReentrant returns (bytes32) {
        if (address(clockVerifier) == address(0) || block.chainid != deploymentChainId) revert Context();
        IClockSettlement target = clockVerifier.settlement();
        if (msg.sender != (phase_ == 0 ? target.sequencer() : target.governance())) revert Unauthorized();
        if (target.batchCount() != batchId || clockVerifier.phase() != phase_) revert Context();
        ClockBoundVerifier.Anchor memory a = clockVerifier.anchor(batchId, phase_);
        if (
            !a.exists || a.previousRoot != target.currentStateRoot() || entries.length != a.timedOps
                || entries.length > MAX_ENTRIES
        ) revert Evidence();
        bytes32 clockCommitment = keccak256(abi.encode(clockVerifier.DOMAIN(), a.baseCommitment, a.receipt));
        bytes32 inputHash = keccak256(abi.encode(entries));
        Record storage previous = records[clockCommitment];
        if (previous.exists) {
            if (previous.inputHash != inputHash) revert Replacement();
            return previous.evidenceHash; // exact retries never re-stamp or re-verify expired evidence
        }
        bytes32 h = keccak256(abi.encode(EVIDENCE_DOMAIN, policyHash, entries.length));
        uint64 last = 0;
        for (uint256 i = 0; i < entries.length; i++) {
            Entry calldata e = entries[i];
            if (
                e.nowMs < a.firstMs || e.nowMs > a.lastMs || (i > 0 && e.nowMs < last)
                    || (i == 0 && e.nowMs != a.firstMs) || (i + 1 == entries.length && e.nowMs != a.lastMs)
            ) revert Evidence();
            last = e.nowMs;
            bytes memory base = _verifyBody(e.baseReport, e.nowMs);
            bytes memory quote = _verifyBody(e.quoteReport, e.nowMs);
            h = keccak256(abi.encode(h, e.marketId, e.nowMs, keccak256(base), keccak256(quote)));
        }
        records[clockCommitment] = Record(h, inputHash, true);
        emit ReportsRegistered(clockCommitment, h);
        return h;
    }

    function _verifyBody(bytes calldata full, uint64 nowMs) private returns (bytes memory body) {
        if (full.length < 224 || full.length > MAX_FULL_REPORT || full.length % 32 != 0) revert Evidence();
        // Current subscription interface: no fee approvals, value, or arbitrary metadata.
        // Signature authenticity is delegated to the configured Chainlink proxy.
        body = streamsVerifier.verify(full, bytes(""));
        if (body.length != 288) revert Evidence();
        ReportV3 memory r = abi.decode(body, (ReportV3));
        if (
            uint16(bytes2(r.feedId)) != 3 || r.validFrom == 0 || r.validFrom > r.observed || r.observed > r.expires
                || uint256(r.observed) * 1000 > nowMs || uint256(r.expires) * 1000 < nowMs
                || block.timestamp > r.expires || r.price <= 0 || r.bid <= 0 || r.ask <= 0 || r.price > type(int128).max
                || r.bid > type(int128).max || r.ask > type(int128).max
        ) revert Evidence();
    }

    function boundCommitment(bytes32 clockCommitment, bytes32 evidenceHash) public view returns (bytes32) {
        return keccak256(
            abi.encode(DOMAIN, clockCommitment, address(this), address(streamsVerifier), policyHash, evidenceHash)
        );
    }

    function verify(bytes32 clockCommitment, bytes calldata proof) external view returns (bool) {
        if (
            msg.sender != address(clockVerifier) || address(clockVerifier) == address(0)
                || block.chainid != deploymentChainId || proof.length == 0
        ) return false;
        Record storage r = records[clockCommitment];
        if (!r.exists) return false;
        try innerVerifier.verify(boundCommitment(clockCommitment, r.evidenceHash), proof) returns (bool ok) {
            return ok;
        } catch {
            return false;
        }
    }
}

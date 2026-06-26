// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IZkVerifier} from "./interfaces/IZkVerifier.sol";
import {MerkleLib} from "./libraries/MerkleLib.sol";

interface ICollateralVault {
    function publishWithdrawals(bytes32 root, uint256 epoch) external;
}

/// @title DarkPerpSettlement
/// @notice The L1 anchor for dark-perp (Faz 2). It (1) advances the canonical
/// state root only via a verified ZK validity proof (§3 SETTLED), (2) falls into
/// close-only on sequencer liveness failure (§6), and (3) runs the inclusion
/// challenge game that slashes the sequencer bond for censorship/withholding
/// (§2). It deliberately holds NO funds — collateral lives in CollateralVault —
/// so a broken sequencer can stall or censor but never steal (§0, §10).
contract DarkPerpSettlement {
    using MerkleLib for bytes32;

    /// perp-core `Domain::StateRoot` tag, binding the public commitment to the
    /// off-chain prover (`crates/prover::PublicInputs::commitment`).
    uint8 internal constant DOMAIN_STATE_ROOT = 7;
    /// perp-core `Domain::OrderHash` tag, used for the receipt signing digest.
    uint8 internal constant DOMAIN_ORDER_HASH = 5;

    struct Batch {
        bytes32 manifestHash;
        bytes32 orderedRoot; // Merkle root of the manifest's ordered order hashes
        uint256 settledAtBlock;
    }

    struct Challenge {
        address challenger;
        uint64 batchIdHint;
        uint256 openedBlock;
        uint256 deadlineBlock;
        uint256 bond; // challenger stake, anti-griefing (audit F3)
        bool open;
    }

    /// secp256k1 group order ÷ 2; signatures with higher `s` are non-canonical
    /// (malleable) and rejected (audit F3 hygiene).
    uint256 internal constant SECP256K1_N_HALF =
        0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    /// Risk-based sequencer bond floor, in basis points of live custodied TVL
    /// (the collateral vault's balance). The bond that backs honest sequencing
    /// must scale with the value it secures, not be an arbitrary constant: a
    /// batch cannot settle while `sequencerBond < requiredBond()` (§2, audit Q1).
    /// 5% here is a governance choice (a constructor param in production).
    uint256 public constant BOND_BPS = 500;

    address public immutable sequencer;
    /// secp256k1 address whose key the enclave signs receipts with, so users can
    /// submit receipts to L1 for slashing (§2). See ADR-0009.
    address public immutable enclaveSigner;
    IZkVerifier public immutable verifier;

    bytes32 public currentStateRoot;
    uint256 public lastProgressBlock;
    uint256 public batchCount;
    uint256 public sequencerBond;
    bool public closeOnly;
    bool public slashed;
    /// Collateral vault that releases funds against settled withdrawals (§3).
    /// Set once by the sequencer after deploy.
    address public vault;

    uint256 public immutable livenessTimeoutBlocks;
    uint256 public immutable challengeWindowBlocks;
    /// Stake a challenger must post; returned if the challenge succeeds (sequencer
    /// slashed), forfeited to the sequencer if it is answered (audit F3).
    uint256 public immutable challengeBond;

    mapping(uint256 => Batch) public batches;
    mapping(bytes32 => Challenge) public challenges; // orderHash => challenge

    event BatchSettled(uint256 indexed batchId, bytes32 prevRoot, bytes32 newRoot, bytes32 manifestHash);
    event CloseOnlyEntered(string reason);
    event BondPosted(uint256 amount, uint256 total);
    event InclusionChallenged(bytes32 indexed orderHash, address indexed challenger, uint256 deadlineBlock);
    event InclusionAnswered(bytes32 indexed orderHash, uint256 batchId);
    event SequencerSlashed(bytes32 indexed orderHash, address indexed challenger, uint256 amount);

    error NotSequencer();
    error InCloseOnly();
    error AlreadySlashed();
    error BadPrevRoot();
    error BadProof();
    error LivenessNotExpired();
    error BadReceiptSignature();
    error ChallengeExists();
    error NoSuchChallenge();
    error ChallengeNotExpired();
    error ChallengeExpired();
    error NotIncluded();
    error NonCanonicalSignature();
    error WrongChallengeBond();
    error BatchNotSettled();
    error TransferFailed();
    error UnderBonded();

    modifier onlySequencer() {
        if (msg.sender != sequencer) revert NotSequencer();
        _;
    }

    constructor(
        address _sequencer,
        address _enclaveSigner,
        IZkVerifier _verifier,
        bytes32 _genesisRoot,
        uint256 _livenessTimeoutBlocks,
        uint256 _challengeWindowBlocks,
        uint256 _challengeBond
    ) {
        sequencer = _sequencer;
        enclaveSigner = _enclaveSigner;
        verifier = _verifier;
        currentStateRoot = _genesisRoot;
        lastProgressBlock = block.number;
        livenessTimeoutBlocks = _livenessTimeoutBlocks;
        challengeWindowBlocks = _challengeWindowBlocks;
        challengeBond = _challengeBond;
    }

    /// @notice Bind the collateral vault (once). Withdrawals published on every
    /// settlement flow through it.
    function setVault(address _vault) external onlySequencer {
        require(vault == address(0), "vault set");
        vault = _vault;
    }

    /// @notice Stake / top up the sequencer bond that backs honest sequencing.
    function postBond() external payable onlySequencer {
        sequencerBond += msg.value;
        emit BondPosted(msg.value, sequencerBond);
    }

    /// @notice The minimum sequencer bond required to settle: `BOND_BPS` of the
    /// live custodied TVL (the vault's balance). Scales the bond with the value it
    /// secures rather than fixing it at an arbitrary constant (audit Q1). Zero
    /// until the vault is wired.
    function requiredBond() public view returns (uint256) {
        if (vault == address(0)) return 0;
        return (vault.balance * BOND_BPS) / 10_000;
    }

    /// @notice The public-input commitment the proof must satisfy. Mirrors
    /// `crates/prover::PublicInputs::commitment`. `orderedRoot` and
    /// `withdrawalsRoot` are bound here (audit F2) so the sequencer cannot supply
    /// an arbitrary withdrawals root and drain the vault — both roots are now
    /// outputs of the proven computation, not free calldata.
    function publicCommitment(
        bytes32 prevRoot,
        bytes32 manifestHash,
        bytes32 newRoot,
        bytes32 orderedRoot,
        bytes32 withdrawalsRoot
    ) public pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(DOMAIN_STATE_ROOT, prevRoot, manifestHash, newRoot, orderedRoot, withdrawalsRoot)
        );
    }

    /// @notice Settle a batch: verify its validity proof and advance the root.
    /// This is the only path to SETTLED finality (§3).
    function settleBatch(
        bytes32 prevRoot,
        bytes32 manifestHash,
        bytes32 newRoot,
        bytes32 orderedRoot,
        bytes32 withdrawalsRoot,
        bytes calldata proof
    ) external onlySequencer {
        if (closeOnly) revert InCloseOnly();
        if (slashed) revert AlreadySlashed();
        // The bond must cover the value at risk before state can advance (audit Q1).
        if (sequencerBond < requiredBond()) revert UnderBonded();
        if (prevRoot != currentStateRoot) revert BadPrevRoot();
        bytes32 commitment = publicCommitment(prevRoot, manifestHash, newRoot, orderedRoot, withdrawalsRoot);
        if (!verifier.verify(commitment, proof)) revert BadProof();

        uint256 batchId = batchCount;
        batches[batchId] = Batch({manifestHash: manifestHash, orderedRoot: orderedRoot, settledAtBlock: block.number});
        currentStateRoot = newRoot;
        lastProgressBlock = block.number;
        batchCount = batchId + 1;
        emit BatchSettled(batchId, prevRoot, newRoot, manifestHash);

        // publish this batch's authorized withdrawals to the vault (§3): only a
        // settled batch can reach here, so withdrawals are gated on hard finality.
        if (vault != address(0)) {
            ICollateralVault(vault).publishWithdrawals(withdrawalsRoot, batchId);
        }
    }

    /// @notice Anyone can force close-only if the sequencer has not progressed
    /// the root within the liveness timeout (§6).
    function triggerCloseOnly() external {
        if (closeOnly) return;
        if (block.number - lastProgressBlock <= livenessTimeoutBlocks) revert LivenessNotExpired();
        closeOnly = true;
        emit CloseOnlyEntered("liveness timeout");
    }

    // --- inclusion challenge game (§2) ---------------------------------------

    /// @notice The receipt signing digest, reconstructed to match
    /// `perp-core::Receipt::signing_digest` exactly (Keccak over the
    /// domain-tagged, little-endian-packed words).
    function receiptDigest(bytes32 orderHash, uint64 seqNo, uint64 recvTimeMs, uint64 batchIdHint)
        public
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encodePacked(
                DOMAIN_ORDER_HASH, orderHash, _leWord(seqNo), _leWord(recvTimeMs), _leWord(batchIdHint)
            )
        );
    }

    /// @notice The domain-separated, batch-bound Merkle leaf an order occupies in
    /// a batch's `orderedRoot`. Hashing the leaf (rather than using the raw
    /// `orderHash`) closes the second-preimage / node-as-leaf forgery, and binding
    /// `batchId` stops the sequencer answering against an unrelated batch (audit
    /// F1). The off-chain tree MUST be built over these same leaves.
    function inclusionLeaf(uint256 batchId, bytes32 orderHash) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(batchId, orderHash));
    }

    /// @notice Open an inclusion challenge by submitting an enclave-signed receipt
    /// for an order the user believes was withheld (§2). Requires a `challengeBond`
    /// stake (anti-griefing, F3); if the sequencer cannot prove inclusion before
    /// the deadline, its bond is slashed and the stake refunded.
    function challengeInclusion(
        bytes32 orderHash,
        uint64 seqNo,
        uint64 recvTimeMs,
        uint64 batchIdHint,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external payable {
        if (challenges[orderHash].open) revert ChallengeExists();
        if (msg.value != challengeBond) revert WrongChallengeBond();
        // reject non-canonical (malleable) signatures (F3 hygiene)
        if (uint256(s) > SECP256K1_N_HALF || (v != 27 && v != 28)) revert NonCanonicalSignature();
        bytes32 digest = receiptDigest(orderHash, seqNo, recvTimeMs, batchIdHint);
        address signer = ecrecover(digest, v, r, s);
        if (signer == address(0) || signer != enclaveSigner) revert BadReceiptSignature();

        challenges[orderHash] = Challenge({
            challenger: msg.sender,
            batchIdHint: batchIdHint,
            openedBlock: block.number,
            deadlineBlock: block.number + challengeWindowBlocks,
            bond: msg.value,
            open: true
        });
        emit InclusionChallenged(orderHash, msg.sender, block.number + challengeWindowBlocks);
    }

    /// @notice Sequencer answers a challenge by proving the order hash is a member
    /// of a **genuinely settled** batch, via a Merkle proof over the
    /// domain-separated `inclusionLeaf`. On success the challenger's stake is
    /// forfeited to the sequencer (F3).
    ///
    /// The batch is NOT required to predate the challenge. Settlement is async
    /// (ACCEPTED → MATCHED → SETTLED spans several blocks, and resting orders settle
    /// in a later batch than the one their receipt was issued in), so requiring the
    /// inclusion batch to be older than the challenge would misclassify normal
    /// settlement latency as censorship: anyone holding a fresh receipt could
    /// challenge before the order settled and free-slash the honest sequencer
    /// (the bond is refunded on slash). Forced inclusion is the cure for
    /// withholding — proving the order landed in a real settled batch (within the
    /// window) is exactly that. Forgery is still impossible: the leaf is
    /// `inclusionLeaf(batchId, orderHash)` over that batch's immutable `orderedRoot`,
    /// so the sequencer cannot fabricate inclusion in a batch that does not contain
    /// the order. A withholding sequencer that never settles the order at all simply
    /// cannot produce a proof, and stalled settlement is independently punished by
    /// the liveness timeout. (audit P2 — supersedes F1's over-strict predates rule.)
    function answerChallenge(bytes32 orderHash, uint256 batchId, bytes32[] calldata proof)
        external
        onlySequencer
    {
        Challenge memory c = challenges[orderHash];
        if (!c.open) revert NoSuchChallenge();
        if (block.number > c.deadlineBlock) revert ChallengeExpired();
        // the answering batch must be genuinely settled (its root is then immutable)
        if (batches[batchId].settledAtBlock == 0) revert BatchNotSettled();
        if (!batches[batchId].orderedRoot.verify(inclusionLeaf(batchId, orderHash), proof)) {
            revert NotIncluded();
        }
        delete challenges[orderHash];
        emit InclusionAnswered(orderHash, batchId);
        // griefing deterrent: the challenger's stake goes to the sequencer
        if (c.bond > 0) {
            (bool ok,) = sequencer.call{value: c.bond}("");
            if (!ok) revert TransferFailed();
        }
    }

    /// @notice After the window expires unanswered, slash the sequencer bond to the
    /// challenger, refund the challenger's stake, and force close-only (§2, §6).
    function slashUnanswered(bytes32 orderHash) external {
        Challenge memory c = challenges[orderHash];
        if (!c.open) revert NoSuchChallenge();
        if (block.number <= c.deadlineBlock) revert ChallengeNotExpired();

        delete challenges[orderHash];
        slashed = true;
        closeOnly = true;
        uint256 amount = sequencerBond + c.bond; // slashed bond + refunded stake
        sequencerBond = 0;
        emit SequencerSlashed(orderHash, c.challenger, amount);
        emit CloseOnlyEntered("inclusion slash");
        if (amount > 0) {
            (bool ok,) = c.challenger.call{value: amount}("");
            if (!ok) revert TransferFailed();
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

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
}

/// The ERC20 subset the settlement uses to custody the sequencer's USDC bond.
interface IERC20Min {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @title DarkPerpSettlement
/// @notice The L1 anchor for dark-perp (Faz 2). It (1) advances the canonical
/// state root only via a verified ZK validity proof (§3 SETTLED), (2) falls into
/// close-only on sequencer liveness failure (§6), and (3) runs the inclusion
/// challenge game that slashes the sequencer bond for censorship/withholding
/// (§2). It holds no USER collateral — that lives in CollateralVault; it custodies
/// only its own sequencer bond + challenge stakes — so a broken sequencer can stall
/// or censor but never steal user funds (§0, §10).
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
        bytes32 rejectedRoot; // Merkle root of the manifest's validly-rejected order hashes (audit DP-004)
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
    uint256 internal constant SECP256K1_N_HALF = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

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
    /// The sequencer bond, denominated in the vault's collateral asset (USDC), so it
    /// is dimensionally coherent with `requiredBond()` (5% of USDC TVL, audit Q1).
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
    /// Seconds after a receipt's signed `recvTimeMs` before its order becomes
    /// challengeable — the §2 inclusion SLA. A fresh order cannot be challenged,
    /// so an honest sequencer's normal async settlement latency can never be
    /// free-griefed by a spam challenge (audit-P2 reconciliation, see
    /// `answerChallenge`). `recvTimeMs` is enclave-self-reported: an honest-accept-
    /// then-withhold sequencer is defended (the timestamp is fixed before the
    /// withhold decision); a fully-compromised enclave is out of scope (SEC-019).
    uint256 public immutable inclusionDeadlineSecs;

    /// The block close-only was entered (0 while live), so `finalSettle`'s grace
    /// window can be measured (§6 wind-down).
    uint256 public closeOnlyBlock;
    /// The address allowed to push a wind-down `finalSettle` while close-only.
    /// Alpha: the deployer. Escape stays proof-gated — governance can only land
    /// proof-valid transitions, never fabricate balances.
    address public immutable governance;
    /// Blocks after `closeOnlyBlock` before `finalSettle` is allowed — a grace
    /// window so users/watchers can react before a governance wind-down.
    uint256 public immutable finalSettleGraceBlocks;

    mapping(uint256 => Batch) public batches;
    mapping(bytes32 => Challenge) public challenges; // orderHash => challenge
    /// Pull-payment ledger for native-token refunds (a challenger's stake returned to the
    /// sequencer on a successful answer, or to the challenger on a slash). Credited rather
    /// than pushed, so a non-payable recipient can never brick the challenge-answer or the
    /// slash transition — the recipient pulls it via `claimEth` (audit DP-011).
    mapping(address => uint256) public pendingEth;
    /// Pull-payment ledger for the slashed USDC bond. Credited to the challenger on a
    /// slash rather than pushed, so a pausable/blacklisting USDC (or a challenger the
    /// token blocks) can never brick `slashUnanswered` — which would otherwise leave the
    /// order permanently unslashable and the sequencer un-punished. Pulled via
    /// `claimUsdc` (audit Tier-3, mirrors the DP-011 ETH pattern).
    mapping(address => uint256) public pendingUsdc;

    event BatchSettled(uint256 indexed batchId, bytes32 prevRoot, bytes32 newRoot, bytes32 manifestHash);
    event FinalSettle(uint256 indexed batchId, bytes32 prevRoot, bytes32 newRoot, bytes32 manifestHash);
    event CloseOnlyEntered(string reason);
    event BondPosted(uint256 amount, uint256 total);
    event BondWithdrawn(uint256 amount, uint256 total);
    event InclusionChallenged(bytes32 indexed orderHash, address indexed challenger, uint256 deadlineBlock);
    event InclusionAnswered(bytes32 indexed orderHash, uint256 batchId);
    event RejectionAnswered(bytes32 indexed orderHash, uint256 batchId);
    event SequencerSlashed(bytes32 indexed orderHash, address indexed challenger, uint256 amount);
    event EthClaimed(address indexed to, uint256 amount);
    event UsdcClaimed(address indexed to, uint256 amount);

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
    error NotRejected();
    error NonCanonicalSignature();
    error WrongChallengeBond();
    error NotRipe();
    error BatchNotSettled();
    error TransferFailed();
    error UnderBonded();
    error VaultNotSet();
    error WithdrawExceedsExcess();
    error NotGovernance();
    error NotCloseOnly();
    error GraceNotExpired();

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
        uint256 _challengeBond,
        uint256 _inclusionDeadlineSecs,
        address _governance,
        uint256 _finalSettleGraceBlocks
    ) {
        sequencer = _sequencer;
        enclaveSigner = _enclaveSigner;
        verifier = _verifier;
        currentStateRoot = _genesisRoot;
        lastProgressBlock = block.number;
        livenessTimeoutBlocks = _livenessTimeoutBlocks;
        challengeWindowBlocks = _challengeWindowBlocks;
        challengeBond = _challengeBond;
        inclusionDeadlineSecs = _inclusionDeadlineSecs;
        governance = _governance;
        finalSettleGraceBlocks = _finalSettleGraceBlocks;
    }

    /// @notice Bind the collateral vault (once). Withdrawals published on every
    /// settlement flow through it.
    function setVault(address _vault) external onlySequencer {
        require(vault == address(0), "vault set");
        vault = _vault;
    }

    /// @notice Stake / top up the sequencer bond (in USDC) that backs honest
    /// sequencing. The sequencer must `approve` the settlement for `amount` first.
    /// USDC-denominated so the posted bond and the TVL-scaled floor share a unit.
    function postBond(uint256 amount) external onlySequencer {
        if (vault == address(0)) revert VaultNotSet();
        IERC20Min tok = IERC20Min(ICollateralVault(vault).token());
        if (!tok.transferFrom(msg.sender, address(this), amount)) revert TransferFailed();
        sequencerBond += amount;
        emit BondPosted(amount, sequencerBond);
    }

    /// @notice Reclaim sequencer bond ABOVE the current required floor (honest exit /
    /// right-sizing as TVL shrinks). Disabled once slashed. Returns USDC to the
    /// sequencer — without this the bonded USDC would be permanently locked for a
    /// never-slashed sequencer (review fix). Only the *excess* over `requiredBond()`
    /// is withdrawable, so the bond can never drop below what an honest settle needs.
    function withdrawBond(uint256 amount) external onlySequencer {
        if (slashed) revert AlreadySlashed();
        uint256 floor = requiredBond();
        uint256 excess = sequencerBond > floor ? sequencerBond - floor : 0;
        if (amount > excess) revert WithdrawExceedsExcess();
        sequencerBond -= amount;
        IERC20Min tok = IERC20Min(ICollateralVault(vault).token());
        if (!tok.transfer(sequencer, amount)) revert TransferFailed();
        emit BondWithdrawn(amount, sequencerBond);
    }

    /// @notice The minimum sequencer bond required to settle: `BOND_BPS` of the
    /// live custodied TVL (the vault's USDC balance). Scales the bond with the value
    /// it secures rather than fixing it at an arbitrary constant (audit Q1). Zero
    /// until the vault is wired. Reads the vault's `tvl()` (its USDC holdings), not
    /// its native balance, since collateral is the ERC20 asset.
    function requiredBond() public view returns (uint256) {
        if (vault == address(0)) return 0;
        return (ICollateralVault(vault).tvl() * BOND_BPS) / 10_000;
    }

    /// @notice The public-input commitment the proof must satisfy. Mirrors
    /// `crates/prover::PublicInputs::commitment`. `orderedRoot`, `withdrawalsRoot`, and
    /// `rejectedRoot` are DERIVED by the guest circuit (P1: `perp_core::commitment::
    /// derive_roots`) — `withdrawalsRoot` from the batch's burned notes (audit F2),
    /// `orderedRoot`/`rejectedRoot` by merklizing the manifest's committed order-hash
    /// lists. CAVEAT (Proof-v2): the ordered-vs-rejected SPLIT is not itself proven —
    /// a dishonest matcher's split is constrained by receipts + inclusion slashing
    /// until Proof-v2. Enforcement of the derived values requires the real verifier
    /// (P2); under MockZkVerifier the check is a stand-in.
    /// `depositsRoot` (SEC-019) is likewise DERIVED by the guest circuit, by folding
    /// the same keccak hash chain over exactly the deposits the batch credits. It is
    /// appended LAST, matching the Rust word order in `PublicInputs::commitment`; the
    /// 225-byte preimage is pinned on both sides by a shared known-answer vector
    /// (`crates/prover/tests/vectors.rs` ↔ `CrossLayer.t.sol`). Unlike the other
    /// derived roots this one is ALSO checkable on L1 — `settleBatch` pins it to the
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

    /// @dev SEC-019 L1 pin, shared by both settle entrypoints (kept in one place so
    /// the two can never drift apart, and to hold the settle functions under the
    /// stack limit). Requires the batch's proven deposit fold to equal the vault's own
    /// chain at the PREFIX the batch claims to have credited: `newDepositCount` selects
    /// the prefix, `depositsRoot` must be that prefix's tip. Both together — a genuine
    /// tip presented against the wrong count fails just as a fabricated tip does.
    ///
    /// A PREFIX, deliberately, not the live head. Pinning to the head made every settle
    /// race every concurrent deposit, and because `deposit(0, junk)` costs nothing but
    /// gas, any address could advance the head once per settle interval and stall
    /// settlement — hence L1 finality and all withdrawal claims — indefinitely. Deposits
    /// landing after the proof was built now simply belong to a later batch.
    ///
    /// Monotonicity/no-skip/no-replay need no check here: `consumed_deposit_tip` and
    /// `consumed_deposit_count` live inside `state_root`, `prevRoot == currentStateRoot`
    /// pins where this batch's fold began, and the circuit's `op_deposit` only increments
    /// contiguously (`deposit_id == consumed_deposit_count`). A settle therefore cannot
    /// go backward, skip a deposit, or double-consume one.
    ///
    /// With no vault wired there is no custodied collateral, so no deposit may be
    /// credited and the chain is the genesis `bytes32(0)` at every prefix — the check
    /// stays fail-CLOSED (only a genesis `depositsRoot` passes) rather than being
    /// skipped when `vault` is unset.
    function _requireDepositPrefix(bytes32 depositsRoot, uint64 newDepositCount) internal view {
        bytes32 prefixTip;
        if (vault != address(0)) {
            prefixTip = ICollateralVault(vault).depositTipAt(newDepositCount);
        }
        require(depositsRoot == prefixTip, "deposits: root != L1 chain prefix");
    }

    /// @notice Settle a batch: verify its validity proof and advance the root.
    /// This is the only path to SETTLED finality (§3).
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
        if (slashed) revert AlreadySlashed();
        // The bond must cover the value at risk before state can advance (audit Q1).
        if (sequencerBond < requiredBond()) revert UnderBonded();
        if (prevRoot != currentStateRoot) revert BadPrevRoot();
        // SEC-019: pin the batch's credited deposits to the L1 deposit hash chain
        // BEFORE verifying the proof. The circuit only proves it folded SOME chain
        // consistently; nothing inside it can know which deposits really landed on
        // L1. Without this pin a sequencer could prove a perfectly valid batch over
        // a chain containing a deposit that never happened and mint collateral from
        // nothing. The pin is to the proven PREFIX, so a deposit landing between
        // proof-build and mine cannot invalidate (or be used to stall) this settle.
        _requireDepositPrefix(depositsRoot, newDepositCount);
        bytes32 commitment =
            publicCommitment(prevRoot, manifestHash, newRoot, orderedRoot, withdrawalsRoot, rejectedRoot, depositsRoot);
        if (!verifier.verify(commitment, proof)) revert BadProof();

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
        emit BatchSettled(batchId, prevRoot, newRoot, manifestHash);

        // publish this batch's authorized withdrawals to the vault (§3): only a
        // settled batch can reach here, so withdrawals are gated on hard finality.
        if (vault != address(0)) {
            ICollateralVault(vault).publishWithdrawals(withdrawalsRoot, batchId);
        }
    }

    /// @notice Governance wind-down settlement that can land EVEN in close-only
    /// (EXIT-001). While `settleBatch` reverts in close-only, open positions closed
    /// by users (reduce-only is allowed off-chain in close-only) would otherwise have
    /// no way to become claimable withdrawals. This provides the landing pad: it skips
    /// the close-only/slashed/bond guards but keeps the ZK proof and prev-root
    /// continuity, so governance can only advance proof-valid state, never fabricate
    /// balances. Gated on close-only + a grace window + `governance`. Repeatable.
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
        if (block.number < closeOnlyBlock + finalSettleGraceBlocks) revert GraceNotExpired();
        if (prevRoot != currentStateRoot) revert BadPrevRoot();
        // SEC-019: the wind-down path skips the close-only/slashed/bond guards but
        // NOT this one. Governance may only land proof-valid state over deposits that
        // genuinely happened — otherwise the escape hatch would become the very hole
        // the pin exists to close. Deposits are refused in close-only, so the chain is
        // frozen here and the prefix being settled can only be one of its own.
        _requireDepositPrefix(depositsRoot, newDepositCount);
        bytes32 commitment =
            publicCommitment(prevRoot, manifestHash, newRoot, orderedRoot, withdrawalsRoot, rejectedRoot, depositsRoot);
        if (!verifier.verify(commitment, proof)) revert BadProof();

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
        emit FinalSettle(batchId, prevRoot, newRoot, manifestHash);
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
        closeOnlyBlock = block.number;
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
            abi.encodePacked(DOMAIN_ORDER_HASH, orderHash, _leWord(seqNo), _leWord(recvTimeMs), _leWord(batchIdHint))
        );
    }

    /// @notice The domain-separated, batch-bound Merkle leaf an order occupies in
    /// a batch's `orderedRoot`. Hashing the leaf (rather than using the raw
    /// `orderHash`) closes the second-preimage / node-as-leaf forgery, and binding
    /// `batchId` stops the sequencer answering against an unrelated batch (audit
    /// F1). The off-chain tree MUST be built over these same leaves.
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

        // §2 ripeness SLA: the order must be overdue by `inclusionDeadlineSecs`
        // before it can be challenged (recvTimeMs is milliseconds).
        if (block.timestamp < recvTimeMs / 1000 + inclusionDeadlineSecs) revert NotRipe();

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
    function answerChallenge(bytes32 orderHash, uint256 batchId, bytes32[] calldata proof) external onlySequencer {
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
        // SEQ-001 (audit-P2 reconciliation): route the challenger's stake by WHEN the
        // order settled. If it settled only AFTER this (ripe) challenge opened, the
        // challenge forced a withheld order in — make the victim whole (refund). If it
        // was already settled when challenged, the challenge was noise/griefing — forfeit
        // to the sequencer. This is a REFUND gate, not a slash gate, so P2's free-slash
        // concern does not apply; the ripeness gate (see `challengeInclusion`) already
        // makes normal-latency orders unchallengeable. No slash on answer — slashing
        // stays exclusively in `slashUnanswered`. Credited for pull, never pushed (DP-011).
        if (batches[batchId].settledAtBlock > c.openedBlock) {
            pendingEth[c.challenger] += c.bond;
        } else {
            pendingEth[sequencer] += c.bond;
        }
    }

    /// @notice Sequencer answers a challenge by proving the order was VALIDLY REJECTED
    /// — a member of a settled batch's committed `rejectedRoot` — rather than withheld.
    /// Without this, an honest sequencer could be slashed for an order it legitimately
    /// rejected (e.g. an unfillable FOK, a post-only that would take): the user still
    /// holds an enclave ACCEPTED receipt, but the order never entered any `orderedRoot`,
    /// so `answerChallenge` cannot answer it (audit DP-004). Slashing now requires that the
    /// sequencer can prove NEITHER inclusion NOR valid rejection.
    ///
    /// SOUNDNESS (P1): `rejectedRoot` is DERIVED by the guest circuit
    /// (`perp_core::commitment::derive_roots`, by merklizing the manifest's committed
    /// rejected order-hash list), so this path removes the WRONGFUL slash of an HONEST
    /// sequencer. CAVEAT (Proof-v2): the ordered-vs-rejected SPLIT is not itself proven —
    /// a dishonest matcher's split is constrained by receipts + inclusion slashing until
    /// Proof-v2. Enforcement of the derived value requires the real verifier (P2); under
    /// MockZkVerifier the check is a stand-in.
    function answerByRejection(bytes32 orderHash, uint256 batchId, bytes32[] calldata proof) external onlySequencer {
        Challenge memory c = challenges[orderHash];
        if (!c.open) revert NoSuchChallenge();
        if (block.number > c.deadlineBlock) revert ChallengeExpired();
        // the answering batch must be genuinely settled (its rejectedRoot is then immutable)
        if (batches[batchId].settledAtBlock == 0) revert BatchNotSettled();
        if (!batches[batchId].rejectedRoot.verify(rejectionLeaf(batchId, orderHash), proof)) {
            revert NotRejected();
        }
        delete challenges[orderHash];
        emit RejectionAnswered(orderHash, batchId);
        // A valid rejection proves the challenger was mistaken (the order was never
        // withheld, just legitimately rejected), so the stake always forfeits to the
        // sequencer here — unlike `answerChallenge`, there is no forced-inclusion refund.
        pendingEth[sequencer] += c.bond;
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
        // Latch on first entry only — `closeOnlyBlock` marks when close-only was FIRST
        // entered, the anchor the `finalSettle` grace deadline counts from. A repeat
        // slash (e.g. a subsequent challenge opened while already in close-only) must
        // NOT push this forward, or an attacker could grief the EXIT-001 escape hatch
        // by perpetually re-arming the grace clock at gas-only cost.
        if (closeOnlyBlock == 0) closeOnlyBlock = block.number;
        uint256 slashedBond = sequencerBond; // USDC bond, slashed to the challenger
        sequencerBond = 0;
        emit SequencerSlashed(orderHash, c.challenger, slashedBond);
        emit CloseOnlyEntered("inclusion slash");
        // Credit BOTH refunds for pull (never push): the slashed USDC bond and the
        // challenger's native ETH stake. A pausable/blacklisting USDC or a non-payable
        // challenger can no longer brick this transition — which would otherwise leave the
        // order permanently unslashable (audit Tier-3 for USDC; DP-011 for ETH).
        pendingUsdc[c.challenger] += slashedBond;
        pendingEth[c.challenger] += c.bond;
    }

    /// @notice Withdraw a native-token refund credited to `msg.sender` (audit DP-011).
    /// Checks-effects-interactions: zero the balance before the transfer.
    function claimEth() external {
        uint256 amount = pendingEth[msg.sender];
        pendingEth[msg.sender] = 0;
        if (amount > 0) {
            (bool ok,) = msg.sender.call{value: amount}("");
            if (!ok) revert TransferFailed();
            emit EthClaimed(msg.sender, amount);
        }
    }

    /// @notice Withdraw a slashed-USDC-bond refund credited to `msg.sender` (audit Tier-3).
    /// Checks-effects-interactions: zero the balance before the transfer. A recipient the
    /// token blocks can only fail their OWN claim; the slash already completed.
    function claimUsdc() external {
        uint256 amount = pendingUsdc[msg.sender];
        pendingUsdc[msg.sender] = 0;
        if (amount > 0) {
            IERC20Min tok = IERC20Min(ICollateralVault(vault).token());
            if (!tok.transfer(msg.sender, amount)) revert TransferFailed();
            emit UsdcClaimed(msg.sender, amount);
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

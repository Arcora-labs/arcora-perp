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

/// The settlement subset the vault reads. Every call is a view (STATICCALL).
interface ISettlementGate {
    /// 0 = accept; 1 = close-only; 2 = over bond capacity; 3 (or any other non-zero
    /// value) = not accepting deposits from this caller.
    function depositGate(uint256 newTvl) external view returns (uint8);
    function closeOnly() external view returns (bool);
    function consumedDepositCount() external view returns (uint64);
    function vault() external view returns (address);
}

/// @title CollateralVault
/// @notice Holds pooled collateral (**USDC**, the chosen settlement asset) and
/// releases it only against a withdrawals root published by the settlement contract
/// from a SETTLED batch (only settled state is withdrawable). The same mechanism is
/// the forced-exit path: in close-only, users still claim against the last settled
/// withdrawals root, and deposits the settled state never consumed are refunded at
/// principal to their payer.
contract CollateralVault {
    using MerkleLib for bytes32;

    /// Prefix sums over the deposit chain, one slot per deposit.
    struct DepositMeta {
        /// L1 block the deposit landed in.
        uint64 blockNumber;
        /// Sum of all deposit amounts with id <= this one.
        uint192 cumulative;
    }

    /// Domain tag of the gateway's deposit permit (`permitDigest`).
    bytes32 public constant DEPOSIT_PERMIT_TAG = keccak256("arcora:deposit-permit:v2");

    address public immutable settlement;
    /// The settlement asset held by the vault (USDC; 6 decimals → 1 base unit =
    /// 1 micro-USD = 1 engine quote unit, so on-chain amounts map 1:1 off-chain).
    IERC20 public immutable token;

    /// Withdrawals root from the most recently settled batch that published one.
    bytes32 public withdrawalsRoot;
    uint256 public withdrawalsEpoch;
    uint256 public totalDeposited;
    uint256 public totalWithdrawn;
    /// Principal returned through `refundDeposit`.
    uint256 public totalRefunded;

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
    /// reorder deposits, replay one, or alter an amount/owner-commit. A chain (not a
    /// Merkle set) is used deliberately: order is part of the commitment.
    bytes32 public depositChainTip;
    /// Number of leaves folded into `depositChainTip`. Doubles as the next deposit's
    /// `id`, which is bound into the leaf so an otherwise-identical repeat deposit
    /// (same sender, owner commit and amount) still produces a distinct leaf.
    uint64 public depositCount;
    /// SEC-019: every PREFIX of that chain, kept forever — `depositTipAt[n]` is the tip
    /// after the vault's first `n` deposits, so `depositTipAt[depositCount] ==
    /// depositChainTip`. `depositTipAt[0]` is never written: the mapping default
    /// `bytes32(0)` IS the genesis tip.
    ///
    /// @dev This exists so settlement can pin a batch to the prefix it actually PROVED
    /// rather than to the live head, so a deposit landing mid-flight simply lands in a
    /// later batch.
    mapping(uint64 => bytes32) public depositTipAt;

    /// SEC-019: the gateway's secp256k1 signer. A deposit is accepted ONLY with this
    /// key's permit (`permitDigest`) over (chainid, this vault, payer, ownerCommit,
    /// amount, validUntil). The gateway signs only after recording the `(owner, blind)`
    /// behind `ownerCommit`, so a leaf whose commit preimage it never knew cannot enter
    /// the chain. It CANNOT inflate collateral: each deposit still performs a real
    /// `transferFrom` and settlement pins `depositsRoot` to the proven prefix.
    address public gatewaySigner;

    /// Owner commitments that already entered the chain. Each commitment enters at most
    /// once, whatever deadline its permit carries: a re-signed permit with a new
    /// `validUntil` is a different digest but the same commitment.
    mapping(bytes32 => bool) public usedOwnerCommit;
    /// Deposit ids already refunded.
    mapping(uint64 => bool) public depositRefunded;
    /// Per-deposit landing block and prefix sum.
    mapping(uint64 => DepositMeta) public depositMeta;

    /// secp256k1 group order ÷ 2; ECDSA signatures with higher `s` are non-canonical
    /// (malleable) and rejected in `_recover` (matches DarkPerpSettlement's hygiene).
    uint256 private constant SECP256K1_N_HALF = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    /// @param from L1 payer (bound into the leaf; the funds' provenance).
    /// @param ownerCommit BLINDED binding to the shielded-note owner the off-chain
    ///        protocol must credit: `keccak256(owner ‖ blind)`. Opaque to this
    ///        contract, and deliberately NOT the raw owner — publishing that here
    ///        (a permanent, indexed topic) would publicly link this L1 payer to the
    ///        internal note owner, which is exactly the linkage this system hides.
    /// @param amount USDC base units.
    /// @param id the deposit's index in the chain (pre-increment `depositCount`).
    /// @param newTip `depositChainTip` after folding this deposit — indexers and the
    ///        sequencer replay from these without re-deriving the chain themselves.
    event Deposit(address indexed from, bytes32 indexed ownerCommit, uint256 amount, uint64 id, bytes32 newTip);
    event DepositRefunded(uint64 indexed id, address indexed from, address to, uint256 amount);
    event WithdrawalsRootPublished(uint256 indexed epoch, bytes32 root);
    event Withdrawn(address indexed to, uint256 amount, uint256 nonce);

    error NotSettlement();
    error AlreadyClaimed();
    error BadWithdrawalProof();
    error TransferFailed();
    error InCloseOnly();
    /// The deposit was not authorized by the gateway (missing, malformed, or
    /// wrong-tuple signature).
    error BadGatewaySig();
    /// A zero `gatewaySigner` would make the deposit gate fail-OPEN — `_recover`
    /// returns `address(0)` for a malformed signature — so it is refused at construction.
    error ZeroGatewaySigner();
    /// `amount` is zero or exceeds `type(int128).max`.
    error BadAmount();
    /// The deposit would raise the vault's TVL beyond what the sequencer bond covers.
    error BondCapacityExceeded();
    /// The settlement does not accept deposits from this vault.
    error DepositsPaused();
    /// The permit's `validUntil` has passed.
    error PermitExpired();
    /// This owner commitment already entered the deposit chain.
    error OwnerCommitUsed();
    /// The settlement is not paired with this vault.
    error NotPaired();
    error NotCloseOnly();
    /// The id is below the consumed boundary or does not exist.
    error NotRefundable();
    error AlreadyRefunded();
    error BadRefundRecipient();
    /// (from, ownerCommit, amount, id) does not reproduce the chain link at `id`.
    error BadDepositPreimage();
    /// The claim would dip into principal of deposits the settled state never credited.
    error ReservedForUncredited();

    modifier onlySettlement() {
        if (msg.sender != settlement) revert NotSettlement();
        _;
    }

    constructor(address _settlement, address _token, address _gatewaySigner) {
        // A zero signer makes the deposit gate fail-open (see `ZeroGatewaySigner`).
        if (_gatewaySigner == address(0)) revert ZeroGatewaySigner();
        settlement = _settlement;
        token = IERC20(_token);
        gatewaySigner = _gatewaySigner;
    }

    /// Recover the signer of `digest` from a 65-byte `r‖s‖v` signature, or
    /// `address(0)` if the signature is malformed, malleable (upper-half `s`), or has a
    /// non-canonical `v`.
    function _recover(bytes32 digest, bytes calldata sig) internal pure returns (address) {
        if (sig.length != 65) return address(0);
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        if (uint256(s) > SECP256K1_N_HALF || (v != 27 && v != 28)) return address(0);
        return ecrecover(digest, v, r, s);
    }

    /// @notice The digest the gateway signs to permit `from` to deposit `amount` for
    /// `ownerCommit` into this vault until `validUntil` (unix seconds, inclusive):
    /// `keccak256(abi.encodePacked(DEPOSIT_PERMIT_TAG, chainid, vault, from,
    /// ownerCommit, amount, uint256(validUntil)))`, a 200-byte preimage.
    function permitDigest(address from, bytes32 ownerCommit, uint256 amount, uint64 validUntil)
        public
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encodePacked(
                DEPOSIT_PERMIT_TAG, block.chainid, address(this), from, ownerCommit, amount, uint256(validUntil)
            )
        );
    }

    /// @notice Deposit `amount` (USDC base units) into the pooled vault. The caller
    /// must have `approve`d the vault first. The off-chain protocol mints a shielded
    /// note of `amount` for the owner committed to by `ownerCommit`.
    ///
    /// @dev SEC-019: the deposit is folded into `depositChainTip` BEFORE it can be
    /// credited off-chain. The leaf is
    /// `keccak256(abi.encodePacked(address from, bytes32 ownerCommit, uint256 amount, uint256 id))`
    /// and the fold is `keccak256(abi.encodePacked(bytes32 tip, bytes32 leaf))` — both
    /// reproduced byte-for-byte by `crates/perp-core/src/merkle.rs`
    /// (`deposit_leaf` / `deposit_chain_fold`) and in-circuit, and pinned on both sides
    /// by the same known-answer vectors. Do NOT change this encoding (no domain tag, no
    /// padded `from`, `id` as a full uint256 word) without changing the Rust side in the
    /// same commit.
    /// @param amount USDC base units to pull from `msg.sender`; 1..=type(int128).max.
    /// @param ownerCommit BLINDED commitment to the shielded-note owner to credit
    ///        off-chain: `keccak256(owner ‖ blind)`. Bound into the leaf, so the
    ///        sequencer cannot redirect the note to a different owner.
    /// @param validUntil the permit deadline (unix seconds, inclusive).
    /// @param sig the gateway permit: `gatewaySigner`'s `r‖s‖v` signature over
    ///        `permitDigest(msg.sender, ownerCommit, amount, validUntil)`. Verified then
    ///        discarded; it never enters the leaf or the chain.
    function deposit(uint256 amount, bytes32 ownerCommit, uint64 validUntil, bytes calldata sig) external {
        // The off-chain engine and ingester accept only positive amounts that fit int128.
        if (amount == 0 || amount > uint256(uint128(type(int128).max))) revert BadAmount();
        uint8 gate = ISettlementGate(settlement).depositGate(_tvl() + amount);
        if (gate != 0) {
            if (gate == 1) revert InCloseOnly();
            if (gate == 2) revert BondCapacityExceeded();
            revert DepositsPaused();
        }
        if (block.timestamp > validUntil) revert PermitExpired();
        if (_recover(permitDigest(msg.sender, ownerCommit, amount, validUntil), sig) != gatewaySigner) {
            revert BadGatewaySig();
        }
        // Marked before the token interaction (checks-effects-interactions).
        if (usedOwnerCommit[ownerCommit]) revert OwnerCommitUsed();
        usedOwnerCommit[ownerCommit] = true;
        if (!token.transferFrom(msg.sender, address(this), amount)) revert TransferFailed();
        uint256 cumulative = totalDeposited + amount;
        totalDeposited = cumulative;
        // `id` is the PRE-increment count, so the first deposit is id 0 (matching the
        // Rust vectors). Folded only after the transfer succeeded.
        uint64 id = depositCount;
        bytes32 leaf = keccak256(abi.encodePacked(msg.sender, ownerCommit, amount, uint256(id)));
        bytes32 tip = keccak256(abi.encodePacked(depositChainTip, leaf));
        depositChainTip = tip;
        emit Deposit(msg.sender, ownerCommit, amount, id, tip);
        // `cumulative` is at most 2^64 deposits of at most 2^127 each, so it fits 192 bits.
        depositMeta[id] = DepositMeta({blockNumber: uint64(block.number), cumulative: uint192(cumulative)});
        depositCount = id + 1;
        // record the new PREFIX tip (after `depositCount` deposits). Index 0 stays
        // unwritten and reads back as the genesis tip via the mapping default.
        depositTipAt[id + 1] = tip;
    }

    /// @notice Refund a deposit the settled state never consumed, once the paired
    /// settlement is in close-only (its consumed count is frozen then). Permissionless;
    /// pays the leaf's payer `from`, or `to` when `from` itself calls. The caller
    /// supplies the leaf preimage, checked against the chain link at `id`.
    function refundDeposit(uint64 id, address from, bytes32 ownerCommit, uint256 amount, address to) external {
        ISettlementGate s = ISettlementGate(settlement);
        if (s.vault() != address(this)) revert NotPaired();
        if (!s.closeOnly()) revert NotCloseOnly();
        if (id < s.consumedDepositCount() || id >= depositCount) revert NotRefundable();
        if (depositRefunded[id]) revert AlreadyRefunded();
        if (to == address(0) || (to != from && msg.sender != from)) revert BadRefundRecipient();
        bytes32 leaf = keccak256(abi.encodePacked(from, ownerCommit, amount, uint256(id)));
        if (keccak256(abi.encodePacked(depositTipAt[id], leaf)) != depositTipAt[id + 1]) revert BadDepositPreimage();
        depositRefunded[id] = true;
        totalRefunded += amount;
        if (!token.transfer(to, amount)) revert TransferFailed();
        emit DepositRefunded(id, from, to, amount);
    }

    /// @notice The L1 block deposit `id` landed in; 0 for an id that does not exist.
    function depositBlock(uint64 id) external view returns (uint256) {
        return depositMeta[id].blockNumber;
    }

    /// @notice Sum of the amounts of the first `n` deposits (0 for n = 0, and for an `n`
    /// beyond `depositCount`, like `depositTipAt`).
    function cumulativeDepositedAt(uint64 n) public view returns (uint256) {
        return n == 0 ? 0 : depositMeta[n - 1].cumulative;
    }

    /// @notice Principal of deposits the settled state has not consumed and that were
    /// not refunded: `cumulativeDepositedAt(depositCount) -
    /// cumulativeDepositedAt(consumedDepositCount) - totalRefunded` (saturating).
    function refundableOutstanding() public view returns (uint256) {
        uint64 n = depositCount;
        uint64 c = ISettlementGate(settlement).consumedDepositCount();
        if (c > n) c = n;
        uint256 outstanding = cumulativeDepositedAt(n) - cumulativeDepositedAt(c);
        return outstanding > totalRefunded ? outstanding - totalRefunded : 0;
    }

    /// @notice Net ACCOUNTED collateral: deposits minus claimed withdrawals minus
    /// refunds (saturating) — NOT the raw token balance, so a bare `token.transfer` into
    /// the vault cannot move the bond floor or the deposit capacity.
    function tvl() external view returns (uint256) {
        return _tvl();
    }

    function _tvl() internal view returns (uint256) {
        uint256 out = totalWithdrawn + totalRefunded;
        return totalDeposited > out ? totalDeposited - out : 0;
    }

    /// @notice Called by the settlement contract when a batch settles, publishing
    /// that batch's authorized withdrawals. Only a settled batch can reach here, so
    /// withdrawals are inherently gated on hard finality.
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

    /// @notice Claim an authorized withdrawal by proving membership in a published
    /// withdrawals root. Works identically in normal and close-only modes — the
    /// authority is the settled root, not the operator. Pays out in USDC. A claim may
    /// never draw on the principal of deposits the settled state has not credited
    /// (`refundableOutstanding`).
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
        uint256 balance = token.balanceOf(address(this));
        if (balance < amount || balance - amount < refundableOutstanding()) revert ReservedForUncredited();
        claimed[leaf] = true;
        totalWithdrawn += amount;
        if (!token.transfer(to, amount)) revert TransferFailed();
        emit Withdrawn(to, amount, nonce);
    }
}

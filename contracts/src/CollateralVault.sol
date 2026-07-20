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
    /// rather than to the live head. Pinning to the head made settlement race every
    /// concurrent deposit, and since `deposit(0, ...)` costs only gas, anyone could
    /// advance the head once per settle interval and halt settlement — and with it L1
    /// finality and all withdrawal claims — indefinitely. With prefixes recorded, a
    /// deposit landing mid-flight simply lands in a later batch.
    mapping(uint64 => bytes32) public depositTipAt;

    /// SEC-019 (Task 6c): the gateway's secp256k1 signer. A deposit is accepted ONLY if
    /// it carries this key's ECDSA signature over `(chainid, this vault, from,
    /// ownerCommit, amount)`. This is a LIVENESS GATE on deposit entry, not a mint
    /// authority: the gateway signs only after recording the `(owner, blind)` behind
    /// `ownerCommit`, so every leaf that can ever enter the chain is creditable off-chain
    /// — an uncreditable leaf (e.g. a free `deposit(0, junkCommit)` whose commit preimage
    /// the gateway doesn't know) can no longer head-of-line-block the circuit's
    /// contiguous deposit consumption and strand every deposit queued behind it (spec
    /// §1b). It CANNOT inflate `external_in`: each deposit still performs a real
    /// `transferFrom` and settlement still pins `depositsRoot` to the proven prefix, so a
    /// compromised signer can permit entry but never conjure collateral.
    address public gatewaySigner;

    /// secp256k1 group order ÷ 2; ECDSA signatures with higher `s` are non-canonical
    /// (malleable) and rejected in `_recover` (matches DarkPerpSettlement's F3 hygiene).
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
    event WithdrawalsRootPublished(uint256 indexed epoch, bytes32 root);
    event Withdrawn(address indexed to, uint256 amount, uint256 nonce);

    error NotSettlement();
    error AlreadyClaimed();
    error BadWithdrawalProof();
    error TransferFailed();
    error InCloseOnly();
    /// SEC-019 (Task 6c): the deposit was not authorized by the gateway (missing,
    /// malformed, or wrong-tuple signature).
    error BadGatewaySig();

    modifier onlySettlement() {
        if (msg.sender != settlement) revert NotSettlement();
        _;
    }

    constructor(address _settlement, address _token, address _gatewaySigner) {
        settlement = _settlement;
        token = IERC20(_token);
        gatewaySigner = _gatewaySigner;
    }

    /// SEC-019 (Task 6c): recover the signer of `digest` from a 65-byte `r‖s‖v`
    /// signature, or `address(0)` if the signature is malformed, malleable (upper-half
    /// `s`), or has a non-canonical `v`. `ecrecover` itself returns `address(0)` on
    /// failure, so the caller's `!= gatewaySigner` check (with a non-zero signer) also
    /// rejects a zero recovery. No import needed — `ecrecover` is a precompile.
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

    /// @notice Deposit `amount` (USDC base units) into the pooled vault. The caller
    /// must have `approve`d the vault first. The off-chain protocol mints a shielded
    /// note of `amount` for the owner committed to by `ownerCommit`; the commitment
    /// enters the note tree (§1).
    ///
    /// @dev SEC-019: the deposit is folded into `depositChainTip` BEFORE it can be
    /// credited off-chain. The leaf is
    /// `keccak256(abi.encodePacked(address from, bytes32 ownerCommit, uint256 amount, uint256 id))`
    /// and the fold is `keccak256(abi.encodePacked(bytes32 tip, bytes32 leaf))` — both
    /// reproduced byte-for-byte by `crates/perp-core/src/merkle.rs`
    /// (`deposit_leaf` / `deposit_chain_fold`) and in-circuit, and pinned on both sides
    /// by the same known-answer vectors. Do NOT change this encoding (no domain tag, no
    /// padded `from`, `id` as a full uint256 word) without changing the Rust side in the
    /// same commit: any divergence silently breaks the binding this whole mechanism exists
    /// to provide.
    /// @param amount USDC base units to pull from `msg.sender`.
    /// @param ownerCommit BLINDED commitment to the shielded-note owner to credit
    ///        off-chain: `keccak256(owner ‖ blind)`, computed by the depositor. This
    ///        contract treats it as an opaque 32-byte word and only folds it. Bound
    ///        into the leaf, so the sequencer cannot redirect the note to a different
    ///        owner than the payer committed to — crediting another owner would need a
    ///        different commit (breaking the chain match against this tip) or a keccak
    ///        second-preimage. Passing the RAW owner here would forfeit the payer↔owner
    ///        unlinkability for no added integrity; see spec §1a.
    /// @param sig SEC-019 (Task 6c) gateway authorization: the `gatewaySigner`'s ECDSA
    ///        signature over `keccak256(abi.encodePacked(chainid, this vault, from,
    ///        ownerCommit, amount))`. Binding all four of chain, vault, payer and
    ///        (ownerCommit, amount) stops a signature issued for one deposit from
    ///        authorizing a different payer, owner-commit, or amount (or a replay on
    ///        another chain/vault). It is verified then DISCARDED — it does NOT enter the
    ///        leaf or the chain, so the leaf/fold encoding and all cross-layer KATs are
    ///        unchanged. `depositCount`/`id` is deliberately NOT bound: the gateway can't
    ///        predict the exact landing index at signing time (ordering is enforced by
    ///        the chain + prefix pin, not by this signature).
    function deposit(uint256 amount, bytes32 ownerCommit, bytes calldata sig) external {
        // audit #11: refuse deposits once the system is in close-only. In close-only no
        // new batch settles, so a deposit made here would never be acknowledged into a
        // settled withdrawals root and the funds would be permanently unclaimable. Users
        // exit via `claim` against the last settled root, not by depositing more.
        if (ISettlementCloseOnly(settlement).closeOnly()) revert InCloseOnly();
        // SEC-019 (Task 6c): the vault accepts a deposit ONLY if the gateway pre-authorized
        // this exact (from, ownerCommit, amount) tuple for THIS vault on THIS chain, so
        // every leaf that can enter the chain is creditable off-chain by construction (no
        // uncreditable leaf can head-of-line-block the contiguous deposit queue — spec §1b).
        // Verified BEFORE the transfer and then dropped; it never touches the leaf/chain.
        bytes32 digest = keccak256(abi.encodePacked(block.chainid, address(this), msg.sender, ownerCommit, amount));
        if (_recover(digest, sig) != gatewaySigner) revert BadGatewaySig();
        if (!token.transferFrom(msg.sender, address(this), amount)) revert TransferFailed();
        totalDeposited += amount;
        // `id` is the PRE-increment count, so the first deposit is id 0 (matching the
        // Rust vectors). Folded only after the transfer succeeded — a reverted deposit
        // must leave the chain untouched.
        bytes32 leaf = keccak256(abi.encodePacked(msg.sender, ownerCommit, amount, uint256(depositCount)));
        depositChainTip = keccak256(abi.encodePacked(depositChainTip, leaf));
        emit Deposit(msg.sender, ownerCommit, amount, depositCount, depositChainTip);
        depositCount += 1;
        // record the new PREFIX tip (after `depositCount` deposits). Written after the
        // increment, so index n always means "n deposits folded"; index 0 stays unwritten
        // and reads back as the genesis tip via the mapping default.
        depositTipAt[depositCount] = depositChainTip;
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

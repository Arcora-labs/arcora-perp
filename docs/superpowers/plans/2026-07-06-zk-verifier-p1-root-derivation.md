# ZK Verifier P1 — Circuit Root-Derivation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the sp1-guest circuit (and the prover/host) **derive** all four proof roots — `manifest_hash`, `ordered_root`, `rejected_root`, `withdrawals_root` — from a single `(state, ops, manifest)` witness, instead of echoing them as trusted inputs.

**Architecture:** One canonical no_std derivation lives in `perp-core`: a shared `merkle` module (moved from the gateway) plus a `derive_roots(state, ops, manifest) -> DerivedRoots` function that executes the batch transition and computes the six committed roots. The guest, the prover's `run_transition`, and the host's native reference all call it — "written once, run in every place." Withdrawals become an incremental per-engine-batch root over engine-emitted `WithdrawalOut` leaves whose amount is bound to the burned note.

**Tech Stack:** Rust (`no_std` + `alloc` for perp-core / sp1-guest), `tiny_keccak` (perp-core keccak256, byte-identical to the gateway's `sha3::Keccak256`), `postcard` (witness encoding), SP1 zkVM (guest/host, excluded from the workspace), Foundry/Solidity (contracts, NatSpec only).

**Spec:** `docs/superpowers/specs/2026-07-06-zk-verifier-p1-root-derivation-design.md`

## Global Constraints

- **BOUNDARY 1 — matching-fairness stays Proof-v2.** The circuit derives `ordered_root`/`rejected_root` by merklizing the manifest's explicit `ordered`/`rejected` lists ONLY. It must NOT re-run the matcher or re-derive the ordered-vs-rejected *split* from the order stream. Keep exactly one honest caveat about this in the prover/contract docs; do not delete the caveat, do not expand the scope.
- **BOUNDARY 2 — `BatchOp::Withdraw` gains `(to: Option<[u8;20]>, nonce: u64)` with full ripple.** `Withdraw` is overloaded: only `account_withdraw` (`gateway/src/main.rs:1294`) is a real vault-claimable L1 withdrawal; the LP-debit (`:2015`) and legacy (`:2346`) sites use it as an internal note-burn (no L1 destination, no vault claim), yet both go through the sequencer. `to = Some(addr)` = real L1 withdrawal → emits a `WithdrawalOut { to: addr, amount, nonce }` (amount = burned note value) → enters `withdrawals_root`. `to = None` = internal burn → emits nothing → NOT in the root. Every construction site in the workspace (gateway ×3, demo, e2e, tests) must be updated in the same task so the workspace compiles; `apply_batch` returns `BatchOutputs` carrying one `WithdrawalOut` per `Some` withdrawal. `nonce` is only meaningful when `to.is_some()` (internal sites pass `nonce: 0`).
- **Pure Rust, no on-chain logic change.** Contracts: NatSpec only (`IZkVerifier.sol`, `DarkPerpSettlement.sol`). `CollateralVault.sol` and `settleBatch`/vault logic are untouched (the gateway's cumulative publish path and the incremental on-chain wiring are P2).
- **No change to the 6-field commitment shape or `Domain::StateRoot` (tag 7).** `commitment = keccak_words(Domain::StateRoot, [prev_state_root, manifest_hash, new_state_root, ordered_root, withdrawals_root, rejected_root])` — byte-identical across guest, prover, and `DarkPerpSettlement.publicCommitment`.
- **Byte-identical merkle.** The moved no_std leaf/`merkle_root` builders MUST produce byte-identical output to the current `crates/gateway/src/withdrawals.rs` versions. `merkle_root(&[]) == [0u8;32]`. Leaf encodings are locked by the existing Solidity-vector tests — they must keep passing.
- **no_std test idiom:** `perp-core` is `#![no_std]` (`extern crate alloc;`, no `#[macro_use]`). Inline `#[cfg(test)]` modules must bring collection macros in explicitly — `use alloc::vec;` for `vec![...]` (and `use alloc::vec::Vec;` where a `Vec` is named). Do not assume the std prelude. Prefer `&[...]` arrays over `vec![]` where a slice suffices.
- **Model policy (subagent dispatch):** NO Haiku. Prefer Opus / Fable; Sonnet acceptable.

## File Structure

- `crates/perp-core/src/merkle.rs` **(new)** — no_std leaf builders (`withdrawal_leaf`, `inclusion_leaf`, `rejection_leaf`), `hash_pair`/`next_level`/`merkle_root`, `WithdrawalLeaf`, and the root-derivation helpers `ordered_root`/`rejected_root`/`withdrawals_root`. Single source of truth for tree shape.
- `crates/perp-core/src/commitment.rs` **(new)** — `DerivedRoots` (the six roots + `commitment::<H>()`) and `derive_roots(&mut DefaultState, &[BatchOp], &BatchManifest) -> Result<DerivedRoots, EngineError>`. The canonical derivation the guest/prover/host share.
- `crates/perp-core/src/engine.rs` — `BatchOp::Withdraw` + `to`/`nonce`; `WithdrawalOut`, `BatchOutputs`; `apply_batch -> Result<BatchOutputs, EngineError>`; `op_withdraw` surfaces the note amount.
- `crates/perp-core/src/error.rs` — `EngineError::ManifestMismatch`.
- `crates/perp-core/src/lib.rs` — `pub mod merkle;` + `pub mod commitment;`.
- `crates/prover/src/lib.rs` — `run_transition` wraps `derive_roots`; caveat rewrite.
- `crates/sp1-guest/src/main.rs` — 3-tuple witness + `derive_roots` + commit.
- `crates/sp1-host/src/main.rs` — 3-tuple witness + native reference via `derive_roots`.
- `crates/gateway/src/withdrawals.rs` — re-export perp-core merkle; keep `merkle_proof`/`verify` + Solidity-vector tests.
- `crates/gateway/src/main.rs`, `crates/demo`, `crates/e2e` — `Withdraw` construction sites + `apply_batch` output consumers.
- `crates/perp-core/tests/serde_witness.rs` — new 3-tuple round-trip test.
- `contracts/src/interfaces/IZkVerifier.sol`, `contracts/src/DarkPerpSettlement.sol` — NatSpec.

---

### Task 1: no_std merkle module in perp-core

**Files:**
- Create: `crates/perp-core/src/merkle.rs`
- Modify: `crates/perp-core/src/lib.rs` (add `pub mod merkle;`)
- Test: inline `#[cfg(test)] mod tests` in `merkle.rs`

**Interfaces:**
- Consumes: `perp_core::hash::Digest`, `tiny_keccak::{Hasher, Keccak}` (already a dep).
- Produces:
  - `pub struct WithdrawalLeaf { pub to: [u8;20], pub amount: u128, pub nonce: u64 }`
  - `pub fn withdrawal_leaf(to: &[u8;20], amount: u128, nonce: u64) -> Digest`
  - `pub fn inclusion_leaf(batch_id: u64, order_hash: &Digest) -> Digest`
  - `pub fn rejection_leaf(batch_id: u64, order_hash: &Digest) -> Digest`
  - `pub fn merkle_root(leaves: &[Digest]) -> Digest` (empty → `[0u8;32]`)
  - `pub fn ordered_root(batch_id: u64, ordered: &[Digest]) -> Digest`
  - `pub fn rejected_root(batch_id: u64, rejected: &[Digest]) -> Digest` (takes the order hashes only, not the `(hash, reason)` tuples)
  - `pub fn withdrawals_root(leaves: &[WithdrawalLeaf]) -> Digest`

- [ ] **Step 1: Write the failing test** (byte-identity to the current gateway output + empty root). Add to `crates/perp-core/src/merkle.rs` (created empty first) a test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> Digest {
        // deterministic 32-byte fixture from an ascii label
        let mut out = [0u8; 32];
        let b = s.as_bytes();
        out[..b.len().min(32)].copy_from_slice(&b[..b.len().min(32)]);
        out
    }

    // Locked against contracts/src/CollateralVault.sol `keccak256(abi.encodePacked(
    // address to, uint256 amount, uint256 nonce))` — the same vector the gateway's
    // `leaf_matches_solidity_abi_encode_packed` test asserts.
    #[test]
    fn withdrawal_leaf_matches_solidity_vector() {
        // to = 0x1111..11 (20 bytes), amount = 2_000_000_000, nonce = 7
        let leaf = withdrawal_leaf(&[0x11u8; 20], 2_000_000_000, 7);
        // The exact expected value is pinned from the existing gateway test; copy it
        // verbatim from crates/gateway/src/withdrawals.rs::leaf_matches_solidity_abi_encode_packed.
        assert_eq!(leaf, EXPECTED_WITHDRAWAL_LEAF);
    }

    #[test]
    fn challenge_leaves_domain_separated() {
        let oh = h("order-1");
        assert_ne!(inclusion_leaf(0, &oh), rejection_leaf(0, &oh));
        assert_ne!(inclusion_leaf(0, &oh), inclusion_leaf(5, &oh)); // batch-bound
    }

    #[test]
    fn empty_merkle_root_is_zero() {
        assert_eq!(merkle_root(&[]), [0u8; 32]);
    }

    #[test]
    fn ordered_root_matches_manual_tree() {
        let a = h("a");
        let b = h("b");
        let manual = merkle_root(&[inclusion_leaf(3, &a), inclusion_leaf(3, &b)]);
        assert_eq!(ordered_root(3, &[a, b]), manual);
    }
}
```

Note: replace `EXPECTED_WITHDRAWAL_LEAF` with the literal from the gateway test (Step 3 copies the exact bytes). If the gateway test uses a computed expected (not a literal), instead assert equality against a temporary `sha3`-based reference in this test file guarded by `#[cfg(test)]` dev-dep, or pin the literal after the first run.

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p perp-core merkle`
Expected: FAIL — `merkle` module/functions not found (won't compile).

- [ ] **Step 3: Implement `merkle.rs`** — port the gateway functions verbatim onto `tiny_keccak`. The byte layout MUST match `crates/gateway/src/withdrawals.rs:34-109`:

```rust
//! no_std Merkle tree + domain-separated leaves — the SINGLE source of truth for the
//! withdrawals, ordered, and rejected trees. Byte-for-byte identical to the shapes the
//! L1 contracts verify (CollateralVault / DarkPerpSettlement / MerkleLib): sorted-pair
//! internal node (`keccak(min||max)`, no tag), 65-byte domain-tagged challenge leaves,
//! `keccak(to||amount||nonce)` withdrawal leaves. `crates/gateway/src/withdrawals.rs`
//! re-exports these so off-chain and in-circuit trees are provably the same code.

use crate::hash::Digest;
use alloc::vec::Vec;
use tiny_keccak::{Hasher as _, Keccak};

fn keccak(parts: &[&[u8]]) -> Digest {
    let mut k = Keccak::v256();
    for p in parts {
        k.update(p);
    }
    let mut out = [0u8; 32];
    k.finalize(&mut out);
    out
}

/// A withdrawal tree leaf: `keccak(to(20) || amount(uint256 BE) || nonce(uint256 BE))`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WithdrawalLeaf {
    pub to: [u8; 20],
    pub amount: u128,
    pub nonce: u64,
}

/// `keccak256(abi.encodePacked(address to, uint256 amount, uint256 nonce))`.
pub fn withdrawal_leaf(to: &[u8; 20], amount: u128, nonce: u64) -> Digest {
    let mut amt = [0u8; 32];
    amt[16..].copy_from_slice(&amount.to_be_bytes()); // u128 → low 16 bytes
    let mut non = [0u8; 32];
    non[24..].copy_from_slice(&nonce.to_be_bytes()); // u64 → low 8 bytes
    keccak(&[to, &amt, &non])
}

/// `keccak256(abi.encodePacked(uint8(0), uint256 batchId, bytes32 orderHash))`.
pub fn inclusion_leaf(batch_id: u64, order_hash: &Digest) -> Digest {
    let mut bid = [0u8; 32];
    bid[24..].copy_from_slice(&batch_id.to_be_bytes());
    keccak(&[&[0x00u8], &bid, order_hash])
}

/// `keccak256(abi.encodePacked(uint8(1), uint256 batchId, bytes32 orderHash))`.
pub fn rejection_leaf(batch_id: u64, order_hash: &Digest) -> Digest {
    let mut bid = [0u8; 32];
    bid[24..].copy_from_slice(&batch_id.to_be_bytes());
    keccak(&[&[0x01u8], &bid, order_hash])
}

fn hash_pair(a: Digest, b: Digest) -> Digest {
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    keccak(&[&lo, &hi])
}

fn next_level(level: &[Digest]) -> Vec<Digest> {
    let mut next = Vec::with_capacity(level.len().div_ceil(2));
    let mut i = 0;
    while i < level.len() {
        if i + 1 < level.len() {
            next.push(hash_pair(level[i], level[i + 1]));
            i += 2;
        } else {
            next.push(level[i]); // odd node promoted unchanged
            i += 1;
        }
    }
    next
}

/// Sorted-pair Merkle root (odd node promoted). Empty → `0x0`, matching the contract's
/// unset `withdrawalsRoot` (nothing claimable).
pub fn merkle_root(leaves: &[Digest]) -> Digest {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        level = next_level(&level);
    }
    level[0]
}

/// Merkle root of a batch's ordered order-hashes (the `orderedRoot` in the commitment).
pub fn ordered_root(batch_id: u64, ordered: &[Digest]) -> Digest {
    let leaves: Vec<Digest> = ordered.iter().map(|oh| inclusion_leaf(batch_id, oh)).collect();
    merkle_root(&leaves)
}

/// Merkle root of a batch's validly-rejected order-hashes (the `rejectedRoot`).
pub fn rejected_root(batch_id: u64, rejected: &[Digest]) -> Digest {
    let leaves: Vec<Digest> = rejected.iter().map(|oh| rejection_leaf(batch_id, oh)).collect();
    merkle_root(&leaves)
}

/// Merkle root of this batch's withdrawal leaves (the incremental `withdrawalsRoot`).
pub fn withdrawals_root(leaves: &[WithdrawalLeaf]) -> Digest {
    let hashed: Vec<Digest> = leaves
        .iter()
        .map(|w| withdrawal_leaf(&w.to, w.amount, w.nonce))
        .collect();
    merkle_root(&hashed)
}
```

Add to `crates/perp-core/src/lib.rs` next to the other `pub mod` lines: `pub mod merkle;`

- [ ] **Step 4: Pin the withdrawal-leaf literal** — copy the exact expected 32-byte value from `crates/gateway/src/withdrawals.rs::leaf_matches_solidity_abi_encode_packed` into `EXPECTED_WITHDRAWAL_LEAF` in the test (a `const EXPECTED_WITHDRAWAL_LEAF: Digest = [...]`). If that gateway test computes rather than pins the value, run `cargo test -p perp-core merkle -- --nocapture` once with a `println!("{:?}", leaf)` and pin the printed bytes.

- [ ] **Step 5: Run to verify it passes**

Run: `cargo test -p perp-core merkle`
Expected: PASS (all four tests).

- [ ] **Step 6: Commit**

```bash
git add crates/perp-core/src/merkle.rs crates/perp-core/src/lib.rs
git commit -m "feat(perp-core): no_std merkle module (moved from gateway, single source of truth)"
```

---

### Task 2: gateway re-exports the moved merkle

**Files:**
- Modify: `crates/gateway/src/withdrawals.rs` (delete moved bodies, re-export perp-core, keep `merkle_proof`/`verify` + tests)
- Modify: `crates/gateway/src/main.rs:46` (import unchanged names from the re-export)

**Interfaces:**
- Consumes: `perp_core::merkle::{withdrawal_leaf, inclusion_leaf, rejection_leaf, merkle_root}`.
- Produces: the same public names from `crates/gateway/src/withdrawals.rs` (`withdrawal_leaf`, `inclusion_leaf`, `rejection_leaf`, `merkle_root`, `merkle_proof`, `verify`, `Withdrawal`) so `main.rs` imports are unchanged.

- [ ] **Step 1: Run the existing gateway tests first (baseline green)**

Run: `cargo test -p gateway withdrawals`
Expected: PASS — record the passing test names (`leaf_matches_solidity_abi_encode_packed`, `challenge_leaves_match_solidity`, and any merkle proof tests).

- [ ] **Step 2: Rewire `withdrawals.rs`** — delete the local bodies of `withdrawal_leaf`, `inclusion_leaf`, `rejection_leaf`, `hash_pair`, `next_level`, `merkle_root` and replace with a re-export at the top of the file:

```rust
// The leaf + merkle-root builders now live in perp-core (no_std) so the zkVM guest and
// the gateway share one implementation — byte-identical trees off-chain and in-circuit.
pub use perp_core::merkle::{inclusion_leaf, merkle_root, rejection_leaf, withdrawal_leaf};
```

Keep `Withdrawal`, `Withdrawal::leaf` (now calling the re-exported `withdrawal_leaf`), `merkle_proof`, `verify`, and the existing `#[cfg(test)]` tests unchanged — they now exercise the re-exported code. Remove the now-unused `use sha3::{Digest, Keccak256};` if nothing else in the file needs it (keep it if `merkle_proof`/`verify` still use `sha3`).

- [ ] **Step 3: Run the gateway tests to verify byte-identity held**

Run: `cargo test -p gateway withdrawals`
Expected: PASS — the SAME tests as Step 1 (the Solidity vectors now prove the moved code is byte-identical). If any fail, the port in Task 1 diverged; fix Task 1.

- [ ] **Step 4: Full gateway build**

Run: `cargo build -p gateway`
Expected: builds clean (no unused-import warnings-as-errors).

- [ ] **Step 5: Commit**

```bash
git add crates/gateway/src/withdrawals.rs crates/gateway/src/main.rs
git commit -m "refactor(gateway): re-export perp-core merkle (locks byte-identity via Solidity vectors)"
```

---

### Task 3: `BatchOp::Withdraw` extension + `apply_batch` outputs + full ripple

**Files:**
- Modify: `crates/perp-core/src/engine.rs` (`BatchOp::Withdraw`, `WithdrawalOut`, `BatchOutputs`, `apply_batch`, `apply_op`, `op_withdraw`)
- Modify: `crates/gateway/src/main.rs` (`Withdraw` sites ~`:1294`, `:2015`, `:2346`; consume `apply_batch`/`apply` outputs)
- Modify: `crates/demo/src/main.rs`, `crates/e2e/tests/full_flow.rs` (any `BatchOp::Withdraw` + `apply_batch` callers)
- Modify: `crates/prover/src/lib.rs`, `crates/sp1-host/src/main.rs`, `crates/sp1-guest/src/main.rs` (their `apply_batch(...)` return — `.unwrap()`/`?` keep working, no code change needed unless they bind the value)
- Test: `crates/perp-core/src/engine.rs` inline test

**Interfaces:**
- Produces:
  - `BatchOp::Withdraw { note_commitment: Digest, spend_key: Digest, to: Option<[u8;20]>, nonce: u64 }`
  - `pub struct WithdrawalOut { pub to: [u8;20], pub amount: i128, pub nonce: u64 }` (amount = burned note value)
  - `pub struct BatchOutputs { pub withdrawals: Vec<WithdrawalOut> }` (derives `Default, Clone, Debug, PartialEq, Eq`)
  - `pub fn apply_batch(&mut self, ops: &[BatchOp]) -> Result<BatchOutputs, EngineError>`
  - `WithdrawalOut → merkle::WithdrawalLeaf` via `From` (guards amount ≥ 0 → `u128`)

- [ ] **Step 1: Write the failing test** — add to `engine.rs` tests: a `Withdraw` with `to = Some(addr)` emits a `WithdrawalOut` (amount bound to the burned note), and a `Withdraw` with `to = None` (internal burn) emits NOTHING.

```rust
#[test]
fn apply_batch_emits_only_real_l1_withdrawal_outputs() {
    use crate::fixed::QUOTE_SCALE;
    use crate::note::owner_from_spend_key;
    let spend_key = [3u8; 32];
    let owner = owner_from_spend_key::<Keccak256>(&spend_key);
    let amount = 4_000 * QUOTE_SCALE;
    let mut s = DefaultState::new(16);

    // real L1 withdrawal → one WithdrawalOut bound to the note
    let blind1 = [7u8; 32];
    let cm1 = Note::new(owner, 0, amount, blind1).commitment::<Keccak256>();
    // internal burn (to: None) → no WithdrawalOut, must not pollute the root
    let blind2 = [8u8; 32];
    let cm2 = Note::new(owner, 0, amount, blind2).commitment::<Keccak256>();

    let to = [0xAB; 20];
    let out = s
        .apply_batch(&[
            BatchOp::Deposit { owner, asset_id: 0, amount, blinding: blind1 },
            BatchOp::Deposit { owner, asset_id: 0, amount, blinding: blind2 },
            BatchOp::Withdraw { note_commitment: cm1, spend_key, to: Some(to), nonce: 42 },
            BatchOp::Withdraw { note_commitment: cm2, spend_key, to: None, nonce: 0 },
        ])
        .unwrap();
    assert_eq!(out.withdrawals.len(), 1, "internal burn (to:None) must not emit");
    assert_eq!(out.withdrawals[0].amount, amount); // bound to the real burned note
    assert_eq!(out.withdrawals[0].to, to);
    assert_eq!(out.withdrawals[0].nonce, 42);
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p perp-core apply_batch_emits_only_real_l1_withdrawal`
Expected: FAIL — `BatchOp::Withdraw` has no `to`/`nonce`; `apply_batch` returns `()`.

- [ ] **Step 3: Extend the engine.** In `crates/perp-core/src/engine.rs`:

Add the new types near `AdlHaircut` (after line ~104):

```rust
/// One withdrawal this batch authorizes: value `amount` (bound to the burned note)
/// released to L1 address `to`, unique by `nonce`. Its leaf enters the batch's
/// `withdrawals_root`. amount is the note's value — the transition, not the prover,
/// determines it (F2 closure).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct WithdrawalOut {
    pub to: [u8; 20],
    pub amount: i128,
    pub nonce: u64,
}

/// The observable outputs of applying a batch that the proof roots are derived from.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BatchOutputs {
    pub withdrawals: alloc::vec::Vec<WithdrawalOut>,
}
```

Extend the `Withdraw` variant (line ~80):

```rust
    /// Burn a note. A REAL L1 withdrawal sets `to = Some(addr)` — the burned value is
    /// bound to its `withdrawals_root` leaf `(addr, note.amount, nonce)` inside the
    /// transition. An INTERNAL burn (LP debit / legacy re-fund) sets `to = None` and
    /// emits no withdrawal (it never becomes a vault claim). `nonce` is only
    /// meaningful when `to.is_some()`.
    Withdraw {
        note_commitment: Digest,
        spend_key: Digest,
        to: Option<[u8; 20]>,
        nonce: u64,
    },
```

Change `apply_batch` (line 109) to collect outputs:

```rust
    pub fn apply_batch(&mut self, ops: &[BatchOp]) -> Result<BatchOutputs, EngineError> {
        let mut outputs = BatchOutputs::default();
        for op in ops {
            if let Some(w) = self.apply_op(op)? {
                outputs.withdrawals.push(w);
            }
            debug_assert!(
                self.conservation_holds(),
                "conservation invariant broken by {op:?}"
            );
            if !self.conservation_holds() {
                return Err(EngineError::ConservationViolated);
            }
        }
        self.next_batch_id += 1;
        Ok(outputs)
    }
```

Change `apply_op` to return `Result<Option<WithdrawalOut>, EngineError>` — every arm returns `Ok(None)` except `Withdraw`, which returns the emitted output. Update the `Withdraw` arm (line 180) and `op_withdraw` (line 675):

```rust
    fn op_withdraw(
        &mut self,
        note_commitment: &Digest,
        spend_key: &Digest,
        to: &Option<[u8; 20]>,
        nonce: u64,
    ) -> Result<Option<WithdrawalOut>, EngineError> {
        let note = self.consume_note(note_commitment, spend_key, None)?;
        self.external_out = self
            .external_out
            .checked_add(note.amount)
            .ok_or(EngineError::Overflow)?;
        // Only a real L1 withdrawal (`to = Some`) produces a withdrawals_root leaf;
        // an internal burn (`to = None`) burns value without an L1 exit.
        Ok(to.map(|addr| WithdrawalOut { to: addr, amount: note.amount, nonce }))
    }
```

Make the other `apply_op` arms return `Ok(None)`: wrap the match so each existing arm's `Ok(())`-producing call maps to `Ok(None)`. The cleanest edit is to have `apply_op` delegate as today but map non-withdraw results:

```rust
    pub fn apply_op(&mut self, op: &BatchOp) -> Result<Option<WithdrawalOut>, EngineError> {
        match op {
            BatchOp::Withdraw { note_commitment, spend_key, to, nonce } => {
                self.op_withdraw(note_commitment, spend_key, to, *nonce)
            }
            other => self.apply_settlement_op(other).map(|()| None),
        }
    }
```

...where `apply_settlement_op(&mut self, op: &BatchOp) -> Result<(), EngineError>` holds the existing non-withdraw match arms (Deposit/FundPosition/Fill/AccrueFunding/Liquidate/Unbind/EnterCloseOnly/SeedInsurance), unchanged. NOTE: `serde_witness.rs` and `lifecycle.rs` call `apply_op` directly and `.unwrap()` it — they now get `Option<WithdrawalOut>` back; `.unwrap()` still works (discards). Confirm no caller binds `apply_op(...).unwrap()` to something used as `()`.

- [ ] **Step 4: Add the `From` conversion** (used by prover/guest to build leaves):

```rust
impl From<&WithdrawalOut> for crate::merkle::WithdrawalLeaf {
    fn from(w: &WithdrawalOut) -> Self {
        // engine note amounts are non-negative; a withdrawal of a real settled note
        // is always ≥ 0. Saturating cast keeps this total (a negative would be a bug
        // upstream, not a silently-huge leaf).
        crate::merkle::WithdrawalLeaf { to: w.to, amount: w.amount.max(0) as u128, nonce: w.nonce }
    }
}
```

- [ ] **Step 5: Update every `BatchOp::Withdraw` construction site** so the workspace compiles, classifying each as a real L1 withdrawal (`to: Some`) or an internal burn (`to: None`):
  - `crates/gateway/src/main.rs:1294` (`account_withdraw`) — **real L1 withdrawal**: pass `to: Some(to)` (the fn arg) and `nonce` (the `nonce` local at `:1276`). It builds a `Withdrawal { to, nonce }` right after — the same `to`/`nonce`.
  - `crates/gateway/src/main.rs:2015` (LP debit) and `:2346` (legacy `withdraw`) — **internal burns**: pass `to: None, nonce: 0`. These re-fund internally / never push to `pending_withdrawals`, so they must NOT enter `withdrawals_root`.
  - `crates/demo/src/main.rs`, `crates/e2e/tests/full_flow.rs`, any `crates/*/tests/*.rs`: grep `BatchOp::Withdraw` workspace-wide. Classify by intent — a test asserting a vault claim uses `to: Some([test_addr;20]), nonce: <n>`; a pure burn uses `to: None, nonce: 0`. When unsure, `to: Some([0xCC;20]), nonce: <i>` for anything that models a user exit.
  - Sites that consume `apply_batch(...)`/`apply(...)` results and pattern-match `Ok(())`: update to `Ok(_)` or bind `Ok(outputs)`.

- [ ] **Step 6: Run the whole workspace to verify it compiles + the new test passes**

Run: `cargo test -p perp-core apply_batch_emits_withdrawal_output && cargo build --workspace`
Expected: the new test PASSES; the workspace builds (every `Withdraw` site updated).

- [ ] **Step 7: Run the full perp-core + gateway suites (no regressions)**

Run: `cargo test -p perp-core && cargo test -p gateway`
Expected: PASS (lifecycle `apply_batch` callers unaffected — all use `.unwrap()`/`.unwrap_err()`).

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "feat(perp-core): BatchOp::Withdraw carries (to,nonce); apply_batch emits WithdrawalOut"
```

---

### Task 4: canonical `derive_roots` in perp-core

**Files:**
- Create: `crates/perp-core/src/commitment.rs`
- Modify: `crates/perp-core/src/lib.rs` (`pub mod commitment;`)
- Modify: `crates/perp-core/src/error.rs` (add `EngineError::ManifestMismatch`)
- Test: inline tests in `commitment.rs`

**Interfaces:**
- Consumes: `merkle::{ordered_root, rejected_root, withdrawals_root, WithdrawalLeaf}`, `engine::{BatchOp, apply_batch}`, `order::BatchManifest`, `hash::{Domain, Hasher, Keccak256, Digest}`, `DefaultState`, `EngineError`.
- Produces:
  - `pub struct DerivedRoots { pub prev_state_root, pub manifest_hash, pub new_state_root, pub ordered_root, pub withdrawals_root, pub rejected_root: Digest }` (Clone, Copy, Debug, PartialEq, Eq)
  - `impl DerivedRoots { pub fn commitment<H: Hasher>(&self) -> Digest }`
  - `pub fn derive_roots(state: &mut DefaultState, ops: &[BatchOp], manifest: &BatchManifest) -> Result<DerivedRoots, EngineError>`

- [ ] **Step 1: Write the failing tests.** In `crates/perp-core/src/commitment.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixed::QUOTE_SCALE;
    use crate::hash::Keccak256;
    use crate::market::Market;
    use crate::note::owner_from_spend_key;
    use crate::order::{BatchManifest, RejectReason};
    use crate::Note;
    use alloc::vec;

    fn manifest_for(state: &DefaultState, ordered: Vec<Digest>) -> BatchManifest {
        BatchManifest {
            previous_state_root: state.state_root(),
            batch_id: state.next_batch_id,
            ordered,
            rejected: vec![],
            oracle_updates: vec![],
            matching_rule_version: 0,
            enclave_measurement: [0u8; 32],
            sequencer_pubkey_epoch: 0,
        }
    }

    #[test]
    fn derives_withdrawals_root_from_burned_note() {
        let spend_key = [3u8; 32];
        let owner = owner_from_spend_key::<Keccak256>(&spend_key);
        let blind = [7u8; 32];
        let amount = 4_000 * QUOTE_SCALE;
        let mut s = DefaultState::new(16);
        s.add_market(Market::conservative(0));
        let cm = Note::new(owner, 0, amount, blind).commitment::<Keccak256>();
        let ops = vec![
            BatchOp::Deposit { owner, asset_id: 0, amount, blinding: blind },
            BatchOp::Withdraw { note_commitment: cm, spend_key, to: Some([0xAB; 20]), nonce: 42 },
        ];
        let manifest = manifest_for(&s, vec![]);
        let d = derive_roots(&mut s.clone(), &ops, &manifest).unwrap();
        // the withdrawals root equals the merkle root over exactly this batch's leaf
        let expected = crate::merkle::withdrawals_root(&[crate::merkle::WithdrawalLeaf {
            to: [0xAB; 20],
            amount: amount as u128,
            nonce: 42,
        }]);
        assert_eq!(d.withdrawals_root, expected);
    }

    #[test]
    fn rejects_manifest_with_wrong_prev_root() {
        let mut s = DefaultState::new(16);
        let mut manifest = manifest_for(&s, vec![]);
        manifest.previous_state_root = [0x99u8; 32]; // wrong
        assert_eq!(
            derive_roots(&mut s, &[], &manifest).unwrap_err(),
            EngineError::ManifestMismatch
        );
    }

    #[test]
    fn commitment_is_six_field_state_root_domain() {
        let d = DerivedRoots {
            prev_state_root: [1u8; 32],
            manifest_hash: [2u8; 32],
            new_state_root: [3u8; 32],
            ordered_root: [4u8; 32],
            withdrawals_root: [5u8; 32],
            rejected_root: [6u8; 32],
        };
        let expected = Keccak256::hash_words(
            crate::hash::Domain::StateRoot,
            &[[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32], [5u8; 32], [6u8; 32]],
        );
        assert_eq!(d.commitment::<Keccak256>(), expected);
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p perp-core commitment`
Expected: FAIL — module/functions absent.

- [ ] **Step 3: Add the error variant.** In `crates/perp-core/src/error.rs`, add a variant to `EngineError` (match the enum's existing style/derives):

```rust
    /// The batch manifest's `previous_state_root` or `batch_id` does not match the
    /// pre-state — the manifest is not the one that produced this transition. Only
    /// reachable via `commitment::derive_roots` (root derivation), not the hot-path
    /// settlement ops.
    ManifestMismatch,
```

- [ ] **Step 4: Implement `commitment.rs`:**

```rust
//! Canonical batch root-derivation — the ONE implementation the zkVM guest, the
//! prover's `run_transition`, and the SP1 host's native reference all share. The
//! guest DERIVES these roots (it does not accept them as trusted witness inputs), so
//! under a real verifier the prover cannot supply an arbitrary withdrawals/ordered/
//! rejected root. Matching-fairness (the ordered-vs-rejected SPLIT) is NOT proven
//! here — that is Proof-v2; this derives the roots structurally from the manifest and
//! constrains withdrawals to the burned notes.

use crate::engine::BatchOp;
use crate::hash::{Digest, Domain, Hasher};
use crate::merkle::{ordered_root, rejected_root, withdrawals_root, WithdrawalLeaf};
use crate::order::BatchManifest;
use crate::{DefaultState, EngineError};
use alloc::vec::Vec;

/// The six roots the batch proof commits to (byte-identical to the L1
/// `DarkPerpSettlement.publicCommitment`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DerivedRoots {
    pub prev_state_root: Digest,
    pub manifest_hash: Digest,
    pub new_state_root: Digest,
    pub ordered_root: Digest,
    pub withdrawals_root: Digest,
    pub rejected_root: Digest,
}

impl DerivedRoots {
    /// The proof's public commitment: `keccak_words(StateRoot, [six roots])`.
    pub fn commitment<H: Hasher>(&self) -> Digest {
        H::hash_words(
            Domain::StateRoot,
            &[
                self.prev_state_root,
                self.manifest_hash,
                self.new_state_root,
                self.ordered_root,
                self.withdrawals_root,
                self.rejected_root,
            ],
        )
    }
}

/// Execute the batch transition and DERIVE all six roots. Mutates `state` to the
/// post-state. Fails `ManifestMismatch` if the manifest is not the one for this
/// pre-state, or propagates any engine rejection.
pub fn derive_roots(
    state: &mut DefaultState,
    ops: &[BatchOp],
    manifest: &BatchManifest,
) -> Result<DerivedRoots, EngineError> {
    let prev_state_root = state.state_root();
    let batch_id = state.next_batch_id;
    // tie the manifest to the state (BOUNDARY 1: structural only — no matcher rerun)
    if manifest.previous_state_root != prev_state_root || manifest.batch_id != batch_id {
        return Err(EngineError::ManifestMismatch);
    }
    let outputs = state.apply_batch(ops)?;
    let new_state_root = state.state_root();

    let manifest_hash = manifest.hash::<crate::hash::Keccak256>();
    let ordered_root = ordered_root(batch_id, &manifest.ordered);
    let rejected_hashes: Vec<Digest> = manifest.rejected.iter().map(|(h, _)| *h).collect();
    let rejected_root = rejected_root(batch_id, &rejected_hashes);
    let wl: Vec<WithdrawalLeaf> = outputs.withdrawals.iter().map(WithdrawalLeaf::from).collect();
    let withdrawals_root = withdrawals_root(&wl);

    Ok(DerivedRoots {
        prev_state_root,
        manifest_hash,
        new_state_root,
        ordered_root,
        withdrawals_root,
        rejected_root,
    })
}
```

NOTE: `manifest.hash` is hardcoded to `Keccak256` because the manifest hash domain is fixed; `commitment::<H>` stays generic to preserve the existing generic-hasher seam. If a later phase swaps the hasher, both move together — acceptable for P1.

Add `pub mod commitment;` to `crates/perp-core/src/lib.rs`.

- [ ] **Step 5: Run to verify it passes**

Run: `cargo test -p perp-core commitment`
Expected: PASS (all three tests).

- [ ] **Step 6: Commit**

```bash
git add crates/perp-core/src/commitment.rs crates/perp-core/src/lib.rs crates/perp-core/src/error.rs
git commit -m "feat(perp-core): derive_roots — canonical six-root derivation for the guest/prover/host"
```

---

### Task 5: prover `run_transition` wraps `derive_roots`

**Files:**
- Modify: `crates/prover/src/lib.rs` (`run_transition`, `PublicInputs` docs, Phase-0 caveats, tests)
- Test: existing `crates/prover/src/lib.rs` tests updated

**Interfaces:**
- Consumes: `perp_core::commitment::{derive_roots, DerivedRoots}`, `perp_core::order::BatchManifest`.
- Produces: `pub fn run_transition(state: &mut DefaultState, ops: &[BatchOp], manifest: &BatchManifest) -> Result<PublicInputs, EngineError>` (signature CHANGED — no longer takes four root args). `PublicInputs` unchanged (6 fields, `commitment()` unchanged).

- [ ] **Step 1: Update the failing tests first.** In `crates/prover/src/lib.rs` tests, the calls `run_transition(&mut s, &ops, mh, [0u8;32], [0u8;32], [0u8;32])` no longer compile. Rewrite `transition_binds_roots` to build a manifest and assert the DERIVED roots:

```rust
    #[test]
    fn transition_derives_roots_from_manifest() {
        use perp_core::order::BatchManifest;
        let (mut s, ops) = state_with_deposit();
        let prev = s.state_root();
        let manifest = BatchManifest {
            previous_state_root: prev,
            batch_id: s.next_batch_id,
            ordered: alloc::vec![],
            rejected: alloc::vec![],
            oracle_updates: alloc::vec![],
            matching_rule_version: 0,
            enclave_measurement: [0u8; 32],
            sequencer_pubkey_epoch: 0,
        };
        let public = run_transition(&mut s, &ops, &manifest).unwrap();
        assert_eq!(public.prev_state_root, prev);
        assert_eq!(public.batch_manifest_hash, manifest.hash::<Keccak256>());
        assert_eq!(public.new_state_root, s.state_root());
        assert_ne!(public.prev_state_root, public.new_state_root);
    }
```

Update the other tests that call `run_transition(...)` with the old signature (`prove_and_verify_roundtrip`, `tampered_public_inputs_break_verification`, `wrong_measurement_*`, `rejected_transition_propagates`) to build a manifest the same way and pass `&manifest`. For `rejected_transition_propagates`, the failing op means `apply_batch` errors inside `derive_roots` — the error still propagates; keep the `UnknownOrSpentNote` assertion (build the manifest with `batch_id: s.next_batch_id`, `previous_state_root: s.state_root()` so it fails at `apply_batch`, not `ManifestMismatch`).

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p prover`
Expected: FAIL — old `run_transition` arity / new assertions unmet.

- [ ] **Step 3: Rewrite `run_transition`** (`crates/prover/src/lib.rs:85`):

```rust
/// Run the batch state transition and DERIVE the public inputs — **this is the zkVM
/// guest program's host-side twin**. Delegates to `perp_core::commitment::derive_roots`
/// so the prover, the guest, and the host compute byte-identical roots.
pub fn run_transition(
    state: &mut DefaultState,
    ops: &[BatchOp],
    manifest: &BatchManifest,
) -> Result<PublicInputs, EngineError> {
    let d = perp_core::commitment::derive_roots(state, ops, manifest)?;
    Ok(PublicInputs {
        prev_state_root: d.prev_state_root,
        batch_manifest_hash: d.manifest_hash,
        new_state_root: d.new_state_root,
        ordered_root: d.ordered_root,
        withdrawals_root: d.withdrawals_root,
        rejected_root: d.rejected_root,
    })
}
```

Add `use perp_core::order::BatchManifest;` to the imports (line ~29).

- [ ] **Step 4: Rewrite the Phase-0 caveats (BOUNDARY 1).** In the `PublicInputs` struct doc and the field comments on `ordered_root`/`withdrawals_root`/`rejected_root` (lines ~33-59), replace the `NOTE (Phase 0): run_transition does NOT yet re-derive these roots ... trusted-sequencer inputs` text. The new text, on the struct doc:

```rust
/// The public inputs a batch proof commits to and the L1 verifier checks.
///
/// All six roots are now DERIVED by `run_transition` (via
/// `perp_core::commitment::derive_roots`): `withdrawals_root` from the batch's burned
/// notes (a prover cannot invent a withdrawal without a real burn — audit F2), and
/// `ordered_root`/`rejected_root` by merklizing the manifest's committed order-hash
/// lists. CAVEAT (Proof-v2): the ordered-vs-rejected SPLIT itself — whether the
/// matcher's inclusion/rejection decisions obey the matching rule — is NOT proven
/// here; that is Proof-v2, backed in the interim by receipts + inclusion slashing.
```

Delete the per-field `NOTE (Phase 0)` blocks, keeping short one-line field descriptions. Keep exactly ONE matching-fairness caveat (the struct-doc one above). Do not touch `CommitmentProver`/`SealedWitness`/`AttestedProver`.

- [ ] **Step 5: Run to verify it passes**

Run: `cargo test -p prover`
Expected: PASS (all prover tests, including the rewritten ones).

- [ ] **Step 6: Commit**

```bash
git add crates/prover/src/lib.rs
git commit -m "feat(prover): run_transition derives roots via perp-core; rewrite Phase-0 caveats"
```

---

### Task 6: sp1-guest derives the roots

**Files:**
- Modify: `crates/sp1-guest/src/main.rs`

**Interfaces:**
- Consumes: `perp_core::commitment::derive_roots`, `perp_core::order::BatchManifest`, `perp_core::hash::Keccak256`.
- Produces: a guest that reads `(DefaultState, Vec<BatchOp>, BatchManifest)` and commits `derive_roots(...).commitment::<Keccak256>()`.

NOTE: sp1-guest is `exclude`d from the workspace and built with `cargo prove build` (needs the SP1 toolchain). Its derivation is the SAME `derive_roots` unit-tested in Task 4; correctness is covered there. This task rewrites the guest to a thin wrapper and, if the SP1 toolchain is present, builds it; the executable equivalence is Task 7.

- [ ] **Step 1: Rewrite `crates/sp1-guest/src/main.rs`:**

```rust
//! SP1 zkVM guest — the Proof-v1 validity program (§4, §10b).
//!
//! Runs perp-core's deterministic transition inside the SP1 RISC-V zkVM and commits
//! the cross-layer public commitment. The four non-state roots are DERIVED here (via
//! `perp_core::commitment::derive_roots`), not accepted as trusted witness inputs, so
//! under a real verifier the prover cannot supply an arbitrary withdrawals/ordered/
//! rejected root (audit F2). Byte-identical to `prover::run_transition` and
//! `DarkPerpSettlement.publicCommitment`.
#![no_main]

extern crate alloc;

sp1_zkvm::entrypoint!(main);

use alloc::vec::Vec;
use perp_core::commitment::derive_roots;
use perp_core::engine::BatchOp;
use perp_core::hash::Keccak256;
use perp_core::order::BatchManifest;
use perp_core::DefaultState;

/// Private witness: pre-state, the batch ops, and the manifest. The four non-state
/// roots are DERIVED from these — they are no longer witness inputs. Encoding locked
/// by `perp-core`'s `serde_witness` round-trip test.
type Witness = (DefaultState, Vec<BatchOp>, BatchManifest);

pub fn main() {
    let bytes = sp1_zkvm::io::read_vec();
    let (mut state, ops, manifest): Witness =
        postcard::from_bytes(&bytes).expect("witness decode");

    let derived = derive_roots(&mut state, &ops, &manifest).expect("valid transition");
    sp1_zkvm::io::commit_slice(&derived.commitment::<Keccak256>());
}
```

- [ ] **Step 2: Build the guest IF the SP1 toolchain is available.**

Run: `which cargo-prove && (cd crates/sp1-guest && cargo prove build) || echo "SP1 toolchain absent — guest verified via shared derive_roots tests (Task 4) + host equivalence (Task 7, when SP1 present)"`
Expected: either a successful `cargo prove build`, or the explicit skip message. Do NOT block the task on SP1 being installed — the derivation logic is the Task-4-tested `derive_roots`.

- [ ] **Step 3: Commit**

```bash
git add crates/sp1-guest/src/main.rs
git commit -m "feat(sp1-guest): derive all six roots from (state, ops, manifest) via derive_roots"
```

---

### Task 7: sp1-host equivalence over the new witness

**Files:**
- Modify: `crates/sp1-host/src/main.rs`

**Interfaces:**
- Consumes: `perp_core::commitment::derive_roots`, `perp_core::order::BatchManifest`, the guest ELF.
- Produces: a host that builds the 3-tuple witness, computes the native reference commitment via `derive_roots`, runs the guest, and asserts equality.

NOTE: like Task 6, requires the SP1 SDK/executor. If absent, the host cannot run; the equivalence guarantee then rests on the shared `derive_roots` (both host reference and guest call the identical function). Keep the host correct so it runs wherever SP1 is installed.

- [ ] **Step 1: Rewrite the witness + native reference in `crates/sp1-host/src/main.rs`** (lines ~26-52). Build a deterministic batch that includes a `Withdraw`, then:

```rust
    use perp_core::commitment::derive_roots;
    use perp_core::note::{owner_from_spend_key, Note};
    use perp_core::order::BatchManifest;

    // Deterministic witness: state + market + a deposit + a withdraw (exercises the
    // derived withdrawals_root).
    let spend_key = [3u8; 32];
    let owner = owner_from_spend_key::<Keccak256>(&spend_key);
    let blind = [9u8; 32];
    let amount = 1_000_000i128;
    let mut state = DefaultState::new(16);
    state.add_market(Market::conservative(0));
    let cm = Note::new(owner, 0, amount, blind).commitment::<Keccak256>();
    let ops = vec![
        BatchOp::Deposit { owner, asset_id: 0, amount, blinding: blind },
        BatchOp::Withdraw { note_commitment: cm, spend_key, to: Some([0xAB; 20]), nonce: 1 },
    ];
    let manifest = BatchManifest {
        previous_state_root: state.state_root(),
        batch_id: state.next_batch_id,
        ordered: vec![],
        rejected: vec![],
        oracle_updates: vec![],
        matching_rule_version: 0,
        enclave_measurement: [0u8; 32],
        sequencer_pubkey_epoch: 0,
    };

    // Native reference commitment (what the sequencer/prover compute).
    let native_commit = derive_roots(&mut state.clone(), &ops, &manifest)
        .unwrap()
        .commitment::<Keccak256>();

    // Serialize the witness exactly as the guest reads it (postcard).
    let witness: (DefaultState, Vec<BatchOp>, BatchManifest) = (state, ops, manifest);
    let bytes = postcard::to_allocvec(&witness).unwrap();
```

Keep the rest of the host (feeding `bytes` into `SP1Stdin`, running the executor, reading the committed public value, and asserting it equals `native_commit`) — update the assertion to compare against `native_commit`.

- [ ] **Step 2: Run IF SP1 is available**

Run: `which cargo-prove && (cd crates/sp1-host && cargo run --release) || echo "SP1 toolchain absent — host equivalence deferred to an SP1-capable environment"`
Expected: the host prints native == guest commitment equality, or the explicit skip.

- [ ] **Step 3: Commit**

```bash
git add crates/sp1-host/src/main.rs
git commit -m "test(sp1-host): equivalence over (state, ops, manifest) via derive_roots"
```

---

### Task 8: serde witness round-trip for the new 3-tuple

**Files:**
- Modify: `crates/perp-core/tests/serde_witness.rs`

**Interfaces:**
- Consumes: `perp_core::order::BatchManifest`, `perp_core::commitment::derive_roots`.
- Produces: a test proving `(DefaultState, Vec<BatchOp>, BatchManifest)` postcard-round-trips and re-derives the same commitment.

- [ ] **Step 1: Add the failing test** to `crates/perp-core/tests/serde_witness.rs`:

```rust
#[test]
fn full_witness_round_trips_and_rederives_commitment() {
    use perp_core::commitment::derive_roots;
    use perp_core::order::BatchManifest;

    let mut s = built_state();
    let ops = vec![BatchOp::AccrueFunding {
        market_id: 0,
        mark: 100_050 * PRICE_SCALE,
        oracle: oracle(100_000, 2_000),
        now_ms: 2_000,
    }];
    let manifest = BatchManifest {
        previous_state_root: s.state_root(),
        batch_id: s.next_batch_id,
        ordered: vec![],
        rejected: vec![],
        oracle_updates: vec![],
        matching_rule_version: 0,
        enclave_measurement: [0u8; 32],
        sequencer_pubkey_epoch: 0,
    };
    let witness: (DefaultState, Vec<BatchOp>, BatchManifest) = (s.clone(), ops.clone(), manifest.clone());
    let bytes = postcard::to_allocvec(&witness).expect("serialize witness");
    let (mut s2, ops2, manifest2): (DefaultState, Vec<BatchOp>, BatchManifest) =
        postcard::from_bytes(&bytes).expect("deserialize witness");

    let a = derive_roots(&mut s, &ops, &manifest).unwrap().commitment::<Keccak256>();
    let b = derive_roots(&mut s2, &ops2, &manifest2).unwrap().commitment::<Keccak256>();
    assert_eq!(a, b, "decoded witness re-derives the identical commitment");
}
```

Add `use perp_core::order::...` / `alloc`/`vec` imports as needed (the file already imports `BatchOp`, `Keccak256`, `PRICE_SCALE`; add `BatchManifest`).

- [ ] **Step 2: Run to verify it passes** (this is a characterization test — it should pass once the code from Tasks 3-4 is in)

Run: `cargo test -p perp-core --features serde full_witness_round_trips`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add crates/perp-core/tests/serde_witness.rs
git commit -m "test(perp-core): lock the (state, ops, manifest) witness round-trip + commitment"
```

---

### Task 9: contracts NatSpec (IZkVerifier + settlement)

**Files:**
- Modify: `contracts/src/interfaces/IZkVerifier.sol`
- Modify: `contracts/src/DarkPerpSettlement.sol`

**Interfaces:** none (documentation only — no ABI or logic change).

- [ ] **Step 1: Fix `IZkVerifier.sol` NatSpec** (lines 5-9) — the stale 3-field commitment. Replace:

```solidity
/// @title IZkVerifier
/// @notice The batch validity-proof verifier (§4). A real implementation is the
/// Solidity verifier generated from the SP1/Risc0 circuit; `publicCommitment` is the
/// binding from `crates/prover::PublicInputs::commitment` / `perp_core::commitment::
/// DerivedRoots::commitment`:
/// `keccak256(abi.encodePacked(uint8(7), prevRoot, manifestHash, newRoot, orderedRoot,
/// withdrawalsRoot, rejectedRoot))`, where `7` is perp-core's `Domain::StateRoot` tag.
```

- [ ] **Step 2: Update `DarkPerpSettlement.sol` caveats.** In the `publicCommitment` NatSpec (lines ~200-208) and the `settleBatch` / `answerByRejection` "PHASE 0 caveat" comments (lines ~205-208, ~384-391), replace "these root VALUES are NOT re-derived from the computation ... trusted-sequencer inputs" with:

```solidity
    /// @notice The public-input commitment the proof must satisfy. Mirrors
    /// `crates/prover::PublicInputs::commitment`. `orderedRoot`, `withdrawalsRoot`, and
    /// `rejectedRoot` are DERIVED by the guest circuit (P1: `perp_core::commitment::
    /// derive_roots`) — `withdrawalsRoot` from the batch's burned notes (audit F2),
    /// `orderedRoot`/`rejectedRoot` by merklizing the manifest's committed order-hash
    /// lists. CAVEAT (Proof-v2): the ordered-vs-rejected SPLIT is not itself proven —
    /// a dishonest matcher's split is constrained by receipts + inclusion slashing
    /// until Proof-v2. Enforcement of the derived values requires the real verifier
    /// (P2); under MockZkVerifier the check is a stand-in.
```

Trim `answerByRejection`'s Phase-0 block to the same one honest matching-fairness caveat (do NOT expand scope; do NOT claim the split is proven). Leave `CollateralVault.sol` untouched (P2).

- [ ] **Step 3: Build the contracts to confirm they still compile**

Run: `cd contracts && forge build`
Expected: compiles clean (comments only). If `forge` is unavailable, `git diff --stat` to confirm only NatSpec lines changed.

- [ ] **Step 4: Commit**

```bash
git add contracts/src/interfaces/IZkVerifier.sol contracts/src/DarkPerpSettlement.sol
git commit -m "docs(contracts): commitment is 6 fields and derived (P1); keep matching-fairness caveat"
```

---

## Final verification (after all tasks)

- [ ] `cargo test --workspace` — all green (perp-core, prover, gateway, sequencer, e2e, demo).
- [ ] `cargo clippy --workspace --all-targets` — clean.
- [ ] `cargo test -p perp-core --features serde` — the witness round-trip passes.
- [ ] `cd contracts && forge build` (and `forge test` if the suite runs here) — green.
- [ ] IF SP1 present: `cd crates/sp1-guest && cargo prove build` then `cd crates/sp1-host && cargo run --release` — native == guest commitment.
- [ ] Grep sanity: `rg "BatchOp::Withdraw" crates` shows every site carries `to`/`nonce`; `rg "run_transition" crates` shows no old 4-root-arg call remains.

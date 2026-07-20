# SEC-019 L1-Bound Deposits Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bind every credited deposit to a real, ordered, correctly-attributed L1 deposit event via an on-chain hash-chain accumulator mirrored by an in-circuit incremental fold — closing deposit inflation ("mint from thin air") and misattribution.

**Architecture:** `CollateralVault` maintains a keccak hash-chain over deposits (`depositChainTip`, `depositCount`). `perp-core` gains a 7th derived root `deposits_root` folded incrementally from two new `State` words; `settleBatch` pins `deposits_root` to the vault's live tip (consume-all-to-head). The SP1 guest re-executes `perp-core` unchanged, so correct+unit-tested `perp-core` is enforced by construction.

**Tech Stack:** Rust (`crates/perp-core`, `crates/gateway`, `crates/sequencer` — `cargo test`, no SP1), Solidity 0.8.24 (`contracts/` — `forge test`, vendored MiniTest, no network). Design doc: `docs/superpowers/specs/2026-07-20-sec019-deposit-l1-binding-design.md`.

## Global Constraints

- **Leaf/chain format is byte-identical Rust ↔ Solidity** (any drift silently breaks settlement): `deposit_leaf = keccak256(from(20 bytes) ‖ owner(32 bytes) ‖ amount(uint256 BE, 32 bytes) ‖ id(uint256 BE, 32 bytes))`; `fold(tip, leaf) = keccak256(tip(32) ‖ leaf(32))`; genesis tip `= bytes32(0)`. No domain tag on leaf or fold. `id` is the pre-increment `depositCount`.
- **`deposits_root` is the 7th commitment word, appended LAST**, in BOTH `perp_core::commitment()` and Solidity `publicCommitment(...)` (`keccak256(abi.encodePacked(DOMAIN_STATE_ROOT, prev, manifestHash, new, ordered, withdrawals, rejected, deposits))`).
- **Fail-closed ordering:** a `Deposit` op with `deposit_id != state.consumed_deposit_count` ⇒ `EngineError::DepositOutOfOrder`; a settle with `newDepositCount != vault.depositCount()` or `depositsRoot != vault.depositChainTip()` ⇒ revert.
- **Conservation identity is UNCHANGED** (`internal_value() == external_in - external_out`); we only constrain what may enter `external_in`. Do not edit `conservation_holds`/`internal_value`.
- **Breaking protocol change is expected** (new commitment arity + new `state_root` words + new `deposit` signature) — testnet redeploy; do not add back-compat shims.
- **Cross-parity constants:** Task 1 pins the canonical Rust known-answer hashes; later Solidity/commitment tasks MUST reproduce the exact same hex (the controller threads Task 1's pinned values into their dispatches).
- **fmt/build discipline:** Rust — `cargo fmt` hunk-scoped (repo not fmt-clean at HEAD), `cargo clippy -p <crate> --all-targets` clean. Solidity — `forge build` + `forge test` clean.

---

### Task 1: `perp-core` deposit leaf + hash-chain fold

**Files:**
- Modify: `crates/perp-core/src/merkle.rs` (add fns + `#[cfg(test)]`)

**Interfaces:**
- Produces:
```rust
pub fn deposit_leaf(from: &[u8; 20], owner: &[u8; 32], amount: u128, id: u64) -> Digest;
pub fn deposit_chain_fold(tip: &Digest, leaf: &Digest) -> Digest;
/// Fold `leaves` (in id order) onto `prev_tip`; returns the new tip.
pub fn deposit_chain_root(prev_tip: &Digest, leaves: &[Digest]) -> Digest;
```
- Consumes: the crate's existing keccak (`use` whatever `withdrawal_leaf` uses — grep `fn withdrawal_leaf` in `merkle.rs` and mirror its keccak/`Keccak256` call + byte-packing style exactly).

- [ ] **Step 1: Write the failing test**

Mirror `withdrawal_leaf`'s test style. Encode `amount` and `id` as 32-byte big-endian (left-padded), `from` as 20 bytes, `owner` as 32 bytes, concatenated in that order, then keccak.
```rust
#[test]
fn deposit_leaf_matches_abi_encodepacked() {
    // keccak256(abi.encodePacked(address, bytes32, uint256, uint256))
    let from = [0x11u8; 20];
    let owner = [0x22u8; 32];
    let leaf = deposit_leaf(&from, &owner, 1000u128, 0u64);
    // pin the actual output once computed (KAT):
    // let expected = hex!("...");  assert_eq!(leaf, expected);
    // For now assert determinism + that a manual re-pack matches:
    let mut buf = Vec::new();
    buf.extend_from_slice(&from);
    buf.extend_from_slice(&owner);
    buf.extend_from_slice(&{ let mut a = [0u8;32]; a[16..].copy_from_slice(&1000u128.to_be_bytes()); a });
    buf.extend_from_slice(&{ let mut a = [0u8;32]; a[24..].copy_from_slice(&0u64.to_be_bytes()); a });
    assert_eq!(leaf, keccak_bytes(&buf)); // use the crate's keccak-over-bytes helper (grep how withdrawal_leaf hashes)
}

#[test]
fn deposit_chain_fold_and_root_are_ordered() {
    let g = [0u8; 32];
    let l0 = deposit_leaf(&[0x11;20], &[0x22;32], 1000, 0);
    let l1 = deposit_leaf(&[0x33;20], &[0x44;32], 500, 1);
    let t1 = deposit_chain_fold(&g, &l0);
    let t2 = deposit_chain_fold(&t1, &l1);
    assert_eq!(deposit_chain_root(&g, &[l0, l1]), t2);
    assert_ne!(deposit_chain_root(&g, &[l1, l0]), t2); // order matters
    assert_eq!(deposit_chain_root(&g, &[]), g);        // empty ⇒ unchanged
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p perp-core deposit_`
Expected: FAIL — fns undefined.

- [ ] **Step 3: Implement**

```rust
/// SEC-019 deposit leaf: keccak256(from ‖ owner ‖ amount_u256_be ‖ id_u256_be),
/// byte-identical to Solidity keccak256(abi.encodePacked(address,bytes32,uint256,uint256)).
pub fn deposit_leaf(from: &[u8; 20], owner: &[u8; 32], amount: u128, id: u64) -> Digest {
    let mut buf = Vec::with_capacity(20 + 32 + 32 + 32);
    buf.extend_from_slice(from);
    buf.extend_from_slice(owner);
    let mut amt = [0u8; 32]; amt[16..].copy_from_slice(&amount.to_be_bytes());
    buf.extend_from_slice(&amt);
    let mut idb = [0u8; 32]; idb[24..].copy_from_slice(&id.to_be_bytes());
    buf.extend_from_slice(&idb);
    keccak_bytes(&buf) // replace with the exact keccak-over-bytes the crate uses for withdrawal_leaf
}
pub fn deposit_chain_fold(tip: &Digest, leaf: &Digest) -> Digest {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(tip);
    buf[32..].copy_from_slice(leaf);
    keccak_bytes(&buf)
}
pub fn deposit_chain_root(prev_tip: &Digest, leaves: &[Digest]) -> Digest {
    leaves.iter().fold(*prev_tip, |tip, leaf| deposit_chain_fold(&tip, leaf))
}
```
Match `withdrawal_leaf`'s ACTUAL keccak call (it may use `Keccak256::hash_bytes` or similar — do not invent `keccak_bytes`; use the real symbol).

- [ ] **Step 4: Run to verify it passes; PIN the known-answer vector**

Run: `cargo test -p perp-core deposit_`
Expected: PASS. Then compute and PIN in the test (uncomment the `expected` KAT) the exact hex of: (a) `deposit_leaf(&[0x11;20],&[0x22;32],1000,0)`, (b) the 2-deposit tip `t2` from the canonical vector [(0x11,0x22,1000,0),(0x33,0x44,500,1)]. Print them (`cargo test -- --nocapture` with an `eprintln!`) and hard-code them as `assert_eq!` KATs. **Report these two hex values verbatim** — the Solidity tasks reuse them.

- [ ] **Step 5: Commit**

```bash
git add crates/perp-core/src/merkle.rs
git commit -m "feat(perp-core): SEC-019 deposit leaf + hash-chain fold (byte-parity w/ Solidity)"
```

---

### Task 2: `perp-core` State — deposit accumulator words

**Files:**
- Modify: `crates/perp-core/src/state.rs` (2 fields + `state_root()` fold + constructors)
- Test: `crates/perp-core/src/state.rs` (`#[cfg(test)]`)

**Interfaces:**
- Produces: `State.consumed_deposit_tip: Digest`, `State.consumed_deposit_count: u64`; both folded into `state_root()`.
- Consumes: nothing from Task 1 (pure state).

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn state_root_binds_deposit_accumulator() {
    let mut a = State::default(); // or the crate's genesis ctor — grep how state.rs tests build a State
    let r0 = a.state_root();
    a.consumed_deposit_count = 1;
    assert_ne!(a.state_root(), r0, "count must be in the root");
    let mut b = State::default();
    b.consumed_deposit_tip = [7u8; 32];
    assert_ne!(b.state_root(), r0, "tip must be in the root");
    assert_eq!(State::default().consumed_deposit_count, 0);
    assert_eq!(State::default().consumed_deposit_tip, [0u8; 32]);
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p perp-core state_root_binds_deposit`
Expected: FAIL — fields don't exist.

- [ ] **Step 3: Implement**

Add to `struct State`: `pub consumed_deposit_tip: Digest,` and `pub consumed_deposit_count: u64,`. Initialize both (`[0u8;32]` / `0`) in EVERY State constructor / `Default` / genesis builder (grep `State {` and any `fn new`/`fn genesis`/`Default` impl — init in all). In `state_root()` (`state.rs:196-220`), extend the hashed word list with these two words, placed immediately AFTER `external_in`/`external_out`, encoding `consumed_deposit_count` as a `u64→Digest` word the same way other `u64`s in `state_root` are encoded (grep how `next_batch_id`/`next_seq` become words) and `consumed_deposit_tip` as its raw `Digest`. Keep the same `Domain::StateRoot` tag and hashing call.

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p perp-core` (new test + all pre-existing state tests). Note: pre-existing `state_root` KATs elsewhere WILL change — update any hard-coded expected `state_root` hashes those tests pin (they are now 16-word). `cargo clippy -p perp-core --all-targets` clean.

- [ ] **Step 5: Commit**

```bash
git add crates/perp-core/src/state.rs
git commit -m "feat(perp-core): SEC-019 bind deposit accumulator (tip+count) into state_root"
```

---

### Task 3: `perp-core` engine — deposit ordering + fold

**Files:**
- Modify: `crates/perp-core/src/engine.rs` (`BatchOp::Deposit` fields, `op_deposit`, `DepositIn` output, `BatchOutputs.deposits`, `EngineError::DepositOutOfOrder`, `apply_op` surfacing)
- Test: `crates/perp-core/src/engine.rs` (`#[cfg(test)]`)

**Interfaces:**
- Consumes: `merkle::{deposit_leaf, deposit_chain_fold}` (Task 1); `State.consumed_deposit_tip/consumed_deposit_count` (Task 2).
- Produces: `BatchOp::Deposit { owner, asset_id, amount, blinding, from: [u8;20], deposit_id: u64 }`; `BatchOutputs.deposits: Vec<DepositIn>` where `DepositIn { from: [u8;20], owner: PubKey, amount: u128, deposit_id: u64 }`.

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn deposit_binds_order_and_folds_chain() {
    let mut st = State::default();
    let owner = [9u8; 32]; let from = [1u8; 20];
    let op0 = BatchOp::Deposit { owner, asset_id: 0, amount: 1000, blinding: [3u8;32], from, deposit_id: 0 };
    let out = st.apply_batch(&[op0.clone()]).expect("apply");
    assert_eq!(st.consumed_deposit_count, 1);
    assert_eq!(st.consumed_deposit_tip,
        deposit_chain_fold(&[0u8;32], &deposit_leaf(&from, &owner, 1000, 0)));
    assert_eq!(st.external_in, 1000);
    assert_eq!(out.deposits.len(), 1);
    assert!(st.conservation_holds());
    // out-of-order id ⇒ error
    let bad = BatchOp::Deposit { owner, asset_id:0, amount:5, blinding:[4u8;32], from, deposit_id: 7 };
    assert!(matches!(st.apply_batch(&[bad]), Err(EngineError::DepositOutOfOrder)));
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p perp-core deposit_binds_order`
Expected: FAIL — new fields / `DepositOutOfOrder` / `out.deposits` undefined.

- [ ] **Step 3: Implement**

- `BatchOp::Deposit` gains `from: [u8; 20]` and `deposit_id: u64` (update the variant + every constructor/match site — grep `BatchOp::Deposit` across `perp-core`/`sequencer`/`gateway` and fix each; the host sites get real values in Task 7, use placeholders ONLY in this crate's own tests).
- `EngineError::DepositOutOfOrder` new variant.
- `DepositIn { from:[u8;20], owner: PubKey, amount:u128, deposit_id:u64 }`; add `deposits: Vec<DepositIn>` to `BatchOutputs` (default empty).
- `op_deposit` (`engine.rs:264-286`): keep `amount>0`; add FIRST `if deposit_id != self.consumed_deposit_count { return Err(EngineError::DepositOutOfOrder); }`. After the existing note append + `external_in += amount`, fold:
```rust
    let leaf = crate::merkle::deposit_leaf(from, &owner.0_or_raw_bytes(), amount as u128, deposit_id);
    self.consumed_deposit_tip = crate::merkle::deposit_chain_fold(&self.consumed_deposit_tip, &leaf);
    self.consumed_deposit_count += 1;
```
  (`owner` is `PubKey = Digest = [u8;32]`; pass its 32 bytes directly — adjust the `.0_or_raw_bytes()` to however `PubKey` exposes its bytes.) Return/emit a `DepositIn` so `apply_op`/`apply_batch` pushes it into `outputs.deposits` (mirror exactly how `WithdrawalOut` is surfaced, `engine.rs:162-172`).
- `op_deposit`'s signature gains `from: &[u8;20], deposit_id: u64` (thread from the `BatchOp::Deposit` match arm).

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p perp-core` (new + all pre-existing; fix any `BatchOp::Deposit {..}` literals in existing perp-core tests to include the 2 new fields). `cargo clippy -p perp-core --all-targets` clean.

- [ ] **Step 5: Commit**

```bash
git add crates/perp-core/src/engine.rs
git commit -m "feat(perp-core): SEC-019 op_deposit L1-ordering check + chain fold + DepositIn output"
```

---

### Task 4: `perp-core` commitment — `deposits_root` (7th word)

**Files:**
- Modify: `crates/perp-core/src/commitment.rs` (`DerivedRoots.deposits_root`, `derive_roots`, `commitment()`)
- Test: `crates/perp-core/src/commitment.rs` (`#[cfg(test)]`)

**Interfaces:**
- Consumes: `State.consumed_deposit_tip` post-`apply_batch` (Task 2/3).
- Produces: `DerivedRoots.deposits_root: Digest` as the 7th `commitment()` word.

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn deposits_root_is_post_batch_tip_and_in_commitment() {
    // build a batch with one deposit; derive_roots must set deposits_root = state.consumed_deposit_tip after apply
    let roots = derive_roots::<Keccak256>(&pre_state, &manifest_with_one_deposit, &ops).expect("derive");
    assert_eq!(roots.deposits_root, expected_post_tip); // == fold(genesis, leaf0)
    // commitment changes if deposits_root changes
    let mut r2 = roots.clone(); r2.deposits_root = [1u8;32];
    assert_ne!(r2.commitment::<Keccak256>(), roots.commitment::<Keccak256>());
}
```
(Model `pre_state`/`manifest`/`ops` on the existing `derive_roots` tests in this file — grep `fn.*derive_roots` tests.)

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p perp-core deposits_root_is_post_batch`
Expected: FAIL — `deposits_root` field undefined.

- [ ] **Step 3: Implement**

- Add `pub deposits_root: Digest` to `DerivedRoots` (last field).
- In `derive_roots` (`commitment.rs:48-77`), after `apply_batch`, set `deposits_root: new_state.consumed_deposit_tip` (grep the exact binding name the fn uses for the post-apply state).
- In `commitment()` (`commitment.rs:30-42`), append `deposits_root` as the 7th word: `H::hash_words(Domain::StateRoot, &[prev_state_root, manifest_hash, new_state_root, ordered_root, withdrawals_root, rejected_root, deposits_root])`.

- [ ] **Step 4: Run to verify it passes; PIN a commitment KAT**

Run: `cargo test -p perp-core` (new + pre-existing; update any pinned `commitment()` KATs — now 7-word). PIN one canonical 7-word `commitment()` known-answer for a fixed `DerivedRoots` and **report the hex** (the Solidity settlement task reuses it). `cargo clippy -p perp-core --all-targets` clean.

- [ ] **Step 5: Commit**

```bash
git add crates/perp-core/src/commitment.rs
git commit -m "feat(perp-core): SEC-019 deposits_root as 7th commitment word"
```

---

### Task 5: Solidity `CollateralVault` — deposit hash-chain accumulator

**Files:**
- Modify: `contracts/src/CollateralVault.sol` (accumulator, `deposit(amount, owner)`, `Deposit` event, getters)
- Test: `contracts/test/CollateralVault.t.sol`

**Interfaces:**
- Produces: `bytes32 depositChainTip`, `uint64 depositCount`, `deposit(uint256 amount, bytes32 owner)`, `event Deposit(address indexed from, bytes32 indexed owner, uint256 amount, uint64 id, bytes32 newTip)`.
- Byte-parity target: the leaf/fold MUST reproduce Task 1's pinned KAT (controller supplies the hex).

- [ ] **Step 1: Write the failing test**

```solidity
function test_deposit_advances_chain_matching_rust_KAT() public {
    // canonical vector [(from=0x11..11, owner=0x22..22, amount=1000, id=0)]
    // fund + approve as the existing deposit test does (grep the current deposit test setup)
    vault.deposit(1000, bytes32(uint256(0x2222...2222)));  // from = the test's msg.sender — use the 0x11..11 actor
    assertEq(vault.depositCount(), 1);
    assertEq(vault.depositChainTip(), <RUST_KAT_1DEPOSIT_TIP>); // hex from Task 1 report (controller supplies)
}
function test_deposit_leaf_encoding() public {
    // independent recompute of the leaf, asserting keccak(abi.encodePacked(from,owner,amount,uint256(id)))
    // equals <RUST_KAT_LEAF> from Task 1
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd contracts && forge test --match-contract CollateralVault`
Expected: FAIL — `deposit(uint256,bytes32)` / getters absent.

- [ ] **Step 3: Implement**

```solidity
bytes32 public depositChainTip;   // genesis 0
uint64  public depositCount;

event Deposit(address indexed from, bytes32 indexed owner, uint256 amount, uint64 id, bytes32 newTip);

function deposit(uint256 amount, bytes32 owner) external {
    if (ISettlementCloseOnly(settlement).closeOnly()) revert InCloseOnly();
    if (!token.transferFrom(msg.sender, address(this), amount)) revert TransferFailed();
    totalDeposited += amount;
    bytes32 leaf = keccak256(abi.encodePacked(msg.sender, owner, amount, uint256(depositCount)));
    depositChainTip = keccak256(abi.encodePacked(depositChainTip, leaf));
    emit Deposit(msg.sender, owner, amount, depositCount, depositChainTip);
    depositCount += 1;
}
```
Update the old `deposit(uint256)` callers/tests to the new signature (breaking; grep `\.deposit(` in `contracts/`).

- [ ] **Step 4: Run to verify it passes**

Run: `cd contracts && forge build && forge test --match-contract CollateralVault`
Expected: PASS — including the KAT assertions matching Task 1's Rust hex.

- [ ] **Step 5: Commit**

```bash
git add contracts/src/CollateralVault.sol contracts/test/CollateralVault.t.sol
git commit -m "feat(contracts): SEC-019 CollateralVault deposit hash-chain accumulator"
```

---

### Task 5b: Blinded owner binding (privacy) — `owner_commit`

**Rationale:** publishing the raw shielded `owner` pubkey on L1 would permanently link the depositing L1 address to the internal owner, destroying the unlinkability this DEX exists for. Bind `keccak(owner ‖ deposit_blind)` instead — both SEC-019 guarantees survive (see spec §1a), and the Solidity encoding + both cross-layer KATs are UNCHANGED (the contract folds an opaque `bytes32`).

**Files:**
- Modify: `crates/perp-core/src/merkle.rs` (add `owner_commit`)
- Modify: `crates/perp-core/src/engine.rs` (`BatchOp::Deposit` gains `deposit_blind`; `op_deposit` folds the commit)
- Modify: `contracts/src/CollateralVault.sol` + `contracts/test/CollateralVault.t.sol` (rename `owner` → `ownerCommit` in the param + event; cosmetic)
- Test: `crates/perp-core/src/merkle.rs`, `crates/perp-core/src/engine.rs` (`#[cfg(test)]`)

**Interfaces:**
- Produces: `pub fn owner_commit(owner: &[u8;32], deposit_blind: &[u8;32]) -> Digest = keccak256(owner ‖ deposit_blind)`; `BatchOp::Deposit { owner, asset_id, amount, blinding, from, deposit_id, deposit_blind }`.
- Consumes: `deposit_leaf`/`deposit_chain_fold` (Task 1), `State.consumed_deposit_*` (Task 2), `op_deposit` (Task 3).

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn owner_commit_is_keccak_owner_blind() {
    let owner = [0xAAu8; 32]; let blind = [0xBBu8; 32];
    let c = owner_commit(&owner, &blind);
    // packed keccak over the two 32-byte words, same primitive as deposit_leaf
    assert_eq!(c, keccak_two_words(&owner, &blind));       // recompute with the module's keccak
    assert_ne!(c, owner_commit(&blind, &owner));            // order-bound
    assert_ne!(c, owner_commit(&owner, &[0xCCu8; 32]));     // blind-bound
}
```
```rust
#[test]
fn deposit_folds_blinded_owner_commit_not_raw_owner() {
    let mut st = DefaultState::new(16);
    let (owner, blind, from) = ([9u8;32], [5u8;32], [1u8;20]);
    let op = BatchOp::Deposit { owner, asset_id: 0, amount: 1000, blinding: [3u8;32],
                                from, deposit_id: 0, deposit_blind: blind };
    st.apply_batch(&[op]).expect("apply");
    let commit = owner_commit(&owner, &blind);
    assert_eq!(st.consumed_deposit_tip,
        deposit_chain_fold(&[0u8;32], &deposit_leaf(&from, &commit, 1000, 0)));
    // and specifically NOT the raw-owner leaf
    assert_ne!(st.consumed_deposit_tip,
        deposit_chain_fold(&[0u8;32], &deposit_leaf(&from, &owner, 1000, 0)));
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p perp-core owner_commit deposit_folds_blinded`
Expected: FAIL — `owner_commit` / the `deposit_blind` field undefined.

- [ ] **Step 3: Implement**

In `merkle.rs`, using the SAME module keccak primitive `deposit_leaf` uses:
```rust
/// SEC-019 blinded owner binding: keccak256(owner ‖ deposit_blind).
/// Published on L1 in place of the raw shielded owner so a deposit does not
/// publicly link the L1 payer to the internal note owner (spec §1a).
pub fn owner_commit(owner: &Digest, deposit_blind: &Digest) -> Digest {
    keccak(&[owner, deposit_blind])   // match deposit_chain_fold's call shape
}
```
In `engine.rs`: add `deposit_blind: Digest` to `BatchOp::Deposit` (fix every in-crate literal — grep `BatchOp::Deposit`), thread it into `op_deposit`, and change the fold to use the commit:
```rust
    let commit = crate::merkle::owner_commit(owner, deposit_blind);
    let leaf = crate::merkle::deposit_leaf(from, &commit, amount as u128, deposit_id);
```
Keep the order-gate, `external_in`, note-append, and `DepositIn` behavior exactly as they are (`DepositIn` keeps carrying the raw `owner` — it is internal, never published).

In `contracts/`: rename the `deposit`'s second parameter and the `Deposit` event's second field `owner` → `ownerCommit` (+ update the NatSpec to say it is `keccak256(owner‖blind)`, opaque to the contract). **No encoding change** — the KATs must still pass untouched.

- [ ] **Step 4: Run to verify they pass**

Run: `cargo test -p perp-core` (all green) and `cd contracts && forge test` (73+ green, KATs unchanged).
Expected: PASS. `cargo clippy -p perp-core --all-targets` clean.

- [ ] **Step 5: Commit**

```bash
git add crates/perp-core/src/merkle.rs crates/perp-core/src/engine.rs contracts/src/CollateralVault.sol contracts/test/CollateralVault.t.sol
git commit -m "feat(sec-019): blind the on-chain owner binding (keccak(owner||blind)) for deposit privacy"
```

---

### Task 6: Solidity `DarkPerpSettlement` — 7-word commitment + deposit check

**Files:**
- Modify: `contracts/src/DarkPerpSettlement.sol` (`publicCommitment`, `settleBatch`, `finalSettle`)
- Test: `contracts/test/DarkPerpSettlement.t.sol`

**Interfaces:**
- Consumes: `CollateralVault.depositChainTip()/depositCount()` (Task 5); Task 4's 7-word commitment KAT.
- Produces: `publicCommitment(prev, manifestHash, new, ordered, withdrawals, rejected, deposits)`; `settleBatch`/`finalSettle` take `bytes32 depositsRoot, uint64 newDepositCount` and enforce consume-all-to-head.

- [ ] **Step 1: Write the failing test**

```solidity
function test_public_commitment_7word_matches_rust() public {
    bytes32 c = settlement.publicCommitment(prev, mh, nw, ord, wdr, rej, dep);
    assertEq(c, <RUST_KAT_7WORD_COMMITMENT>); // hex from Task 4 report
}
function test_settle_reverts_on_deposit_root_mismatch() public {
    // vault has depositCount=N, depositChainTip=T; settling with depositsRoot != T reverts
    vm.expectRevert(); settlement.settleBatch(/*...*/, /*depositsRoot=*/bytes32(uint256(1)), /*newDepositCount=*/vault.depositCount(), proof);
}
function test_settle_reverts_on_incomplete_consumption() public {
    vm.expectRevert(); settlement.settleBatch(/*...*/, vault.depositChainTip(), vault.depositCount() - 1, proof);
}
```
(Reuse the file's existing settle-happy-path harness + mock verifier; grep the current `settleBatch` test.)

- [ ] **Step 2: Run to verify it fails**

Run: `cd contracts && forge test --match-contract DarkPerpSettlement`
Expected: FAIL — arity mismatch / new params absent.

- [ ] **Step 3: Implement**

- `publicCommitment` gains a 7th arg appended last: `keccak256(abi.encodePacked(DOMAIN_STATE_ROOT, prevRoot, manifestHash, newRoot, orderedRoot, withdrawalsRoot, rejectedRoot, depositsRoot))`.
- `settleBatch` / `finalSettle` gain `bytes32 depositsRoot, uint64 newDepositCount`; BEFORE `verifier.verify(...)`:
```solidity
require(newDepositCount == vault.depositCount(), "deposits: must consume all pending");
require(depositsRoot == vault.depositChainTip(),  "deposits: root != L1 chain tip");
```
  and pass `depositsRoot` into the `publicCommitment` recomputation. (`vault` reference already exists — it's called for `publishWithdrawals`.)

- [ ] **Step 4: Run to verify it passes**

Run: `cd contracts && forge build && forge test`
Expected: PASS (whole contracts suite; update any other test constructing a 6-arg commitment or calling the old `settleBatch` signature).

- [ ] **Step 5: Commit**

```bash
git add contracts/src/DarkPerpSettlement.sol contracts/test/DarkPerpSettlement.t.sol
git commit -m "feat(contracts): SEC-019 7-word commitment + settleBatch deposit-root binding"
```

---

### Task 7: Host plumbing — thread L1 `from`+`id`+`owner`

**Files:**
- Modify: `crates/gateway/src/l1.rs` (`verify_deposit_tx` returns `id`+`owner`; `DEPOSIT_TOPIC0` / event ABI)
- Modify: `crates/gateway/src/main.rs` (`account_confirm_deposit`, `fund_amount` thread `from`+`deposit_id`; reject owner mismatch)
- Modify: `crates/sequencer/src/lib.rs` (fix any `BatchOp::Deposit` construction site)
- Test: `crates/gateway/src/l1.rs` / `main.rs` (`#[cfg(test)]`)

**Interfaces:**
- Consumes: `BatchOp::Deposit { .., from, deposit_id }` (Task 3).

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn verify_deposit_tx_extracts_id_and_owner() {
    // feed a canned `cast receipt --json` fixture (grep the existing verify_deposit_tx test for the fixture pattern)
    // assert the parsed (from, owner, amount, id) match the new Deposit(address,bytes32,uint256,uint64,bytes32) event
}
#[test]
fn fund_amount_builds_extended_deposit_op() {
    // fund_amount now takes from + deposit_id + owner; assert the BatchOp::Deposit carries them
    // and that an owner mismatch vs the event is rejected
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p gateway verify_deposit_tx_extracts_id_and_owner fund_amount_builds_extended`
Expected: FAIL.

- [ ] **Step 3: Implement**

- `l1.rs`: update `DEPOSIT_TOPIC0` to the new `Deposit(address,bytes32,uint256,uint64,bytes32)` signature hash (**a stale topic0 silently stops every deposit from crediting** — recompute it, do not hand-edit); parse `ownerCommit` (topic[2], indexed) + `id` (from data) + `amount` (from data) + `from` (topic[1]); `verify_deposit_tx` returns `(from, owner_commit, amount, id)`.
- **Blinded binding (Task 5b):** the gateway must obtain/derive `deposit_blind`, recompute `keccak(owner ‖ deposit_blind)`, and **reject the credit unless it equals the on-chain `owner_commit`**. Choose ONE host-side source for `deposit_blind` and document it: user-supplied at confirm time, or deterministically derived from the account's existing key material (must be reproducible, else the deposit can never be credited).
- **Frontend:** `frontend/src/api/wallet.ts` (stale `deposit(uint256)` selector — tx reverts) and `frontend/src/components/TestnetNotice.tsx` (wrong user-facing `cast` instructions) must be updated to `deposit(uint256,bytes32)` + computing `ownerCommit`.
- **Also compile-broken by earlier tasks, fix here:** `crates/gateway/src/prover_client.rs` (`DerivedRoots` literal + `ProveOutcome` needs a `deposits_root` field — it re-derives the commitment), `crates/gateway/src/main.rs` (`DerivedRoots` literal), `crates/demo/src/main.rs`, plus any `BatchOp::Deposit` literals in `node`/`e2e`/`sequencer`.
- `main.rs`: `account_confirm_deposit` receives `owner`+`id`; assert the account's credited `owner` equals the event `owner` (reject mismatch — on-chain attribution is authoritative). `fund_amount` signature gains `from`+`deposit_id` and builds `BatchOp::Deposit { owner, asset_id:0, amount, blinding, from, deposit_id }`.
- `sequencer/src/lib.rs` + any other `BatchOp::Deposit { .. }` construction: supply the real `from`/`deposit_id` (or, for admin/test-seed paths that have no L1 deposit, either route them through a distinct non-deposit op or feed a documented sentinel — grep every `BatchOp::Deposit` and resolve each; a seed path that fabricates `external_in` without an L1 event is exactly what SEC-019 forbids, so such paths must be gated behind a test/dev flag or removed).

- [ ] **Step 4: Run to verify it passes + full host workspace**

Run: `cargo test -p gateway && cargo test -p sequencer && cargo test --workspace`
Expected: PASS. `cargo clippy --workspace --all-targets` clean.

- [ ] **Step 5: Commit**

```bash
git add crates/gateway/src/l1.rs crates/gateway/src/main.rs crates/sequencer/src/lib.rs
git commit -m "fix(gateway): SEC-019 thread L1 from+id+owner into deposits, reject misattribution"
```

---

## Self-Review

**Spec coverage:** §1 leaf/chain → Task 1; §2 vault accumulator → Task 5; §3 settlement 7-word + check → Task 6; §4 in-circuit (State words → Task 2, op_deposit fold+order → Task 3, deposits_root → Task 4); §5 host → Task 7; behavior matrix (order error, incomplete-consume revert, fabricated/misattributed revert, race) → Tasks 3/6 + the SettleFailed reconcile (unchanged). Cross-parity → Task 1 KAT reused by Tasks 5/6. ✓

**Placeholder scan:** the `keccak_bytes`/`.0_or_raw_bytes()`/`<RUST_KAT_*>` markers are explicit "match the real symbol / controller supplies the pinned hex" instructions, not vague TODOs — every one names exactly what to substitute and where it comes from. KAT hex genuinely cannot be pre-computed in prose; Task 1/4 pin them and the controller threads them (documented in Global Constraints).

**Type consistency:** `deposit_leaf(&[u8;20],&[u8;32],u128,u64)`, `deposit_chain_fold(&Digest,&Digest)`, `State.consumed_deposit_tip/consumed_deposit_count`, `BatchOp::Deposit{..,from:[u8;20],deposit_id:u64}`, `DepositIn`, `BatchOutputs.deposits`, `DerivedRoots.deposits_root`, `publicCommitment(7 args)`, `settleBatch(..,depositsRoot,newDepositCount)` are consistent across tasks. The 7-word order (deposits LAST) is identical in Task 4 (Rust) and Task 6 (Solidity).

**Ordering/dependency:** 1→(2,3,4) perp-core, 1's KAT→(5,6) Solidity, 3→7 host. Task 3 breaks all `BatchOp::Deposit` literals; Task 7 fixes the host ones (Task 3 fixes only perp-core's own tests). Contracts (5,6) are independent of the Rust host tasks and can run in parallel with 2-4 once 1's KAT is pinned.

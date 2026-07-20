# SEC-019 Remediation — L1-Bound Deposits (hash-chain accumulator) — Design

**Finding:** SEC-019 [high] — deposits are **not L1-bound**. `BatchOp::Deposit { owner, asset_id, amount, blinding }` credits an arbitrary `amount` into the proven state (`engine.rs:264-286` `op_deposit`, guarded only by `amount > 0`), and the credited value flows into `external_in`, the sole "value entered from outside" term of the conservation invariant (`state.rs:123-125` `internal_value() == external_in - external_out`). Nothing ties a `Deposit` op to a real L1 deposit: `CollateralVault.deposit()` (`contracts/src/CollateralVault.sol:71-80`) only does `transferFrom` + `totalDeposited +=` + an event — there is **no on-chain per-deposit record**, and `settleBatch` never checks what the proof credited against L1. A compromised sequencer/enclave can mint collateral from thin air (`docs/SECURITY.md:138-140` already tracks this). Symmetrically, even a real deposit could be **misattributed** to the wrong internal owner, since the credited note's owner is chosen off-chain by the gateway.

This design binds every credited deposit to a real, ordered L1 deposit event — closing both **inflation** (can't credit more than was deposited) and **misattribution** (can't credit a real deposit to the wrong owner) — using an on-chain hash-chain accumulator mirrored by an in-circuit incremental fold. Chosen mechanism: **hash-chain + per-deposit ordered binding** (brainstorm Approach A).

## Scope

- **On-chain (Solidity):** `CollateralVault` gains a deposit hash-chain accumulator; `DarkPerpSettlement`'s public commitment gains a 7th word `depositsRoot`, and `settleBatch`/`finalSettle` pin it to the vault's live chain tip.
- **In-circuit (`perp-core`, re-executed verbatim by the SP1 guest):** a 7th derived root `deposits_root`; two new `State` words `consumed_deposit_tip`/`consumed_deposit_count` (so the fold is incremental, not O(all-deposits)); `BatchOp::Deposit` carries the L1 `from` address + `deposit_id`; `op_deposit` verifies ordering and folds the leaf; `derive_roots` produces `deposits_root`.
- **Host (`gateway`/`sequencer`):** thread `from`+`deposit_id` from the L1 event into the op; read the vault's tip/count at seal; pass `deposits_root` to the settle tx.
- **Deposit UX change:** `deposit(amount)` → `deposit(amount, bytes32 owner)` so the depositor commits their internal owner pubkey on L1 (needed to bind attribution in the leaf).

**Non-goals / deferred:**

- **Race-free partial consumption.** This design uses **consume-all-to-head** (a settle must credit every L1 deposit up to the current `depositCount`). A deposit landing between window-seal and settle-mining makes the settle tx **revert** (tip/count moved); this surfaces as the settle loop's existing `SettleFailed` path, whose on-chain reconcile re-reads `batchCount`/`currentStateRoot`, sees the tx did not land, rolls back, and the sequencer re-seals including the new deposit. Sound, but a bounded liveness cost. A checkpointed/watermarked partial-consumption variant (race-free) is a **Phase-2 optimization**, deliberately out of scope.
- No change to the conservation identity itself, to withdrawals, to matching, or to the oracle path (ZK-001 is separate).
- The end-to-end **real proof** (does the SP1 guest enforce the new constraint) is a GB10/SP1 smoke-test — not local. The guest has no logic of its own (it runs `perp_core::derive_roots`/`apply_batch`), so correct + unit-tested `perp-core` logic is enforced by construction; only proof generation + a Base-Sepolia settle need the box.

## Current state (grounding)

- **Commitment (6 words):** `DerivedRoots { prev_state_root, manifest_hash, new_state_root, ordered_root, withdrawals_root, rejected_root }` (`commitment.rs:19-26`); `commitment() = H(Domain::StateRoot, [those 6])` (`commitment.rs:30-42`), mirrored byte-for-byte by `DarkPerpSettlement.publicCommitment(...)` with a leading `DOMAIN_STATE_ROOT` tag (`DarkPerpSettlement.sol:240-253`).
- **`derive_roots`** (`commitment.rs:48-77`) is the single builder: validates the manifest vs pre-state, runs `state.apply_batch(ops)` → `new_state_root` + `BatchOutputs`, then structurally derives `ordered_root`/`rejected_root`/`withdrawals_root` — the prover cannot supply these freely.
- **`state_root()`** (`state.rs:196-220`) folds 14 words incl. `external_in`, `external_out`.
- **Withdrawals template** (the mirror): `WithdrawalLeaf{to,amount,nonce}`, `withdrawal_leaf = keccak(to||amount_u256||nonce_u256)`, sorted-pair `merkle_root` (`merkle.rs:207-324`); `outputs.withdrawals` (from `apply_batch`) → `withdrawals_root` in `derive_roots`; the vault only pays a `claim` against a `rootPublished` root that came from a verified proof (`CollateralVault.sol:105-137`). Deposits are the **input-side mirror** — but L1 is ground truth, so the **contract**, not the circuit, owns the root.
- **`op_deposit`** (`engine.rs:264-286`): `amount>0` check, appends a note, `external_in += amount`. Sole normal-path writer of `external_in` besides `op_seed_insurance`.
- **Host:** `verify_deposit_tx` (`l1.rs:359-397`) shells `cast receipt`, scans for the `Deposit` log; `account_confirm_deposit` (`main.rs:1648-1702`) dedups by tx-hash + checks the account's bound `deposit_address`; `fund_amount` (`main.rs:3511-3544`) emits `BatchOp::Deposit` (dropping all L1 provenance).
- **`PubKey = Digest = [u8;32]`** (`note.rs:12`).

## Design

### 1. Leaf & chain format (byte-identical Rust ↔ Solidity)

New functions in `crates/perp-core/src/merkle.rs` (an ordered hash-CHAIN, distinct from the withdrawals sorted-pair tree):

```
deposit_leaf(from: [u8;20], owner_commit: [u8;32], amount: u128, id: u64) -> Digest
    = keccak256( from(20) || owner_commit(32) || amount(u256 BE, 32) || id(u256 BE, 32) )
        // == Solidity keccak256(abi.encodePacked(address, bytes32, uint256, uint256))

deposit_chain_fold(tip: Digest, leaf: Digest) -> Digest
    = keccak256( tip(32) || leaf(32) )   // == keccak256(abi.encodePacked(bytes32, bytes32))

genesis tip = [0u8; 32]
```

There is no domain tag on the fold (matches the on-chain accumulator). `amount` is the positive deposit value as `u256` big-endian (same encoding as `withdrawal_leaf`'s amount).

**`owner_commit` is a BLINDED owner binding, not the raw owner pubkey** (privacy decision, see §1a):

```
owner_commit(owner: PubKey, deposit_blind: Digest) -> Digest
    = keccak256( owner(32) || deposit_blind(32) )
        // == Solidity keccak256(abi.encodePacked(bytes32, bytes32))
```

### 1a. Why blinded (privacy)

Publishing the raw shielded-note `owner` pubkey as an L1 call argument + indexed event topic would permanently and publicly link the depositing L1 address to the internal shielded owner — destroying, for every deposit, exactly the unlinkability this "dark" DEX exists to provide. Previously that link lived only inside the gateway.

Binding `owner_commit = keccak(owner ‖ deposit_blind)` instead keeps **both** SEC-019 guarantees intact while publishing nothing about the owner:

- **Inflation** — unchanged: the chain still pins the exact `(from, amount, id)` sequence.
- **Misattribution** — still closed: to credit a different owner the circuit would have to produce a leaf containing a different `owner_commit` (breaking the chain match), or find `(owner', blind')` with `keccak(owner'‖blind') == owner_commit` — a second-preimage attack on keccak.

The depositor computes `owner_commit` off-chain and passes it to `deposit(amount, ownerCommit)`. The circuit is given `owner` + `deposit_blind` in the op and recomputes the commit, so it can only credit the owner the depositor committed to. `deposit_blind` is distinct from the note's existing `blinding` field (different purpose; do not conflate).

**Solidity is unaffected by this choice** — the contract folds an opaque `bytes32`; only the parameter/event name changes (`owner` → `ownerCommit`). The leaf/fold encoding and both cross-layer KATs are unchanged.

### 2. On-chain accumulator — `CollateralVault.sol`

- Add `bytes32 public depositChainTip;` (starts `bytes32(0)`), `uint64 public depositCount;` (starts 0).
- `deposit(uint256 amount)` → `deposit(uint256 amount, bytes32 owner)`:
  ```solidity
  bytes32 leaf = keccak256(abi.encodePacked(msg.sender, owner, amount, uint256(depositCount)));
  depositChainTip = keccak256(abi.encodePacked(depositChainTip, leaf));
  emit Deposit(msg.sender, owner, amount, depositCount, depositChainTip);
  depositCount += 1;
  // (transferFrom + totalDeposited += amount unchanged)
  ```
  (`amount` folds as `uint256`, `depositCount` as `uint256` — matching `deposit_leaf`.)

### 3. On-chain settlement check — `DarkPerpSettlement.sol`

- `publicCommitment(...)` gains a 7th argument `depositsRoot` appended LAST:
  `keccak256(abi.encodePacked(DOMAIN_STATE_ROOT, prevRoot, manifestHash, newRoot, orderedRoot, withdrawalsRoot, rejectedRoot, depositsRoot))`.
- `settleBatch` / `finalSettle` gain a `bytes32 depositsRoot` + `uint64 newDepositCount` public input and, before/with proof verification, enforce **consume-all-to-head**:
  ```solidity
  require(newDepositCount == vault.depositCount(), "deposits: must consume all pending");
  require(depositsRoot == vault.depositChainTip(),  "deposits: root != L1 chain tip");
  ```
  The starting point is already bound: `prevRoot == currentStateRoot` and `consumed_deposit_tip`/`consumed_deposit_count` live inside `new/prev_state_root`, so the proof cannot lie about where its fold began. The vault exposes `depositCount()`/`depositChainTip()` (public getters, no new storage in settlement beyond the two public inputs).

### 4. In-circuit constraint — `perp-core`

- **State** (`state.rs`): add `consumed_deposit_tip: Digest` (init `[0;32]`), `consumed_deposit_count: u64` (init 0); fold BOTH into `state_root()` (14 → 16 words), placed immediately after `external_in`/`external_out`. Conservation math unchanged.
- **`BatchOp::Deposit`** (`engine.rs`): add `from: [u8;20]`, `deposit_id: u64`, and `deposit_blind: Digest`. New shape: `Deposit { owner, asset_id, amount, blinding, from, deposit_id, deposit_blind }`.
- **`op_deposit`** (`engine.rs`): before crediting, require `deposit_id == self.consumed_deposit_count` (`EngineError::DepositOutOfOrder`) — contiguous, in-order, no skip/dup. Then: credit the note (as today), `external_in += amount`, and fold the BLINDED binding:
  ```
  let commit = owner_commit(owner, deposit_blind);
  let leaf   = deposit_leaf(from, commit, amount as u128, deposit_id);
  self.consumed_deposit_tip = deposit_chain_fold(self.consumed_deposit_tip, leaf);
  self.consumed_deposit_count += 1;
  ```
  Emit a `DepositIn { from, owner, amount, deposit_id }` output (mirroring `WithdrawalOut`) so `apply_batch` surfaces it into `BatchOutputs.deposits`.
- **`derive_roots`** (`commitment.rs`): after `apply_batch`, set `deposits_root = state.consumed_deposit_tip` (the post-batch tip). Add `deposits_root: Digest` to `DerivedRoots` and append it as the 7th word of `commitment()`. (`deposits_root` is derived from the proven fold, not a free witness — same discipline as `withdrawals_root`.)
- The proof now attests: "I credited exactly the deposits with these `(from, owner, amount, id)` in id-order, extending the chain from my previous `consumed_deposit_tip` to `deposits_root`." The contract pins `deposits_root` to the vault's real chain ⇒ `external_in` can only grow by real, correctly-attributed L1 deposits.

### 5. Host plumbing — `gateway` / `sequencer`

- `verify_deposit_tx` (`l1.rs`) also returns the `deposit_id` (the `depositCount` from the `Deposit` event) and `owner_commit` (the indexed commit from the event); **`DEPOSIT_TOPIC0` must be recomputed for the new event signature** — a stale topic silently stops every deposit from crediting.
- `account_confirm_deposit` / `fund_amount` (`main.rs`) thread `from` + `deposit_id` + `deposit_blind` into the extended `BatchOp::Deposit`; the gateway must recompute `keccak(owner ‖ deposit_blind)` and **reject unless it equals the on-chain `owner_commit`** (the on-chain commitment is authoritative for attribution). How the gateway obtains `deposit_blind` is a host-side key-management choice made in that task, but it is **security-critical, not merely mechanical** — the privacy this buys is only as strong as the blind's entropy and secrecy:

- **MUST be per-deposit.** Reusing one blind across a user's deposits turns `owner_commit` into a stable public pseudonym that links all of them.
- **MUST be high-entropy and secret.** An observer can enumerate candidate `owner` pubkeys and brute-force `keccak(owner ‖ blind)` against the on-chain commit. A zero/constant/public-derived blind therefore recovers exactly the payer↔owner link this design exists to hide — full deanonymization, silently.
- **MUST be reproducible** by the gateway at credit time (else the deposit can never be credited).

A derivation from **secret** account key material (e.g. an HKDF over the account's view key and the deposit id) satisfies all three; a derivation from public data (address, tx hash, deposit id alone) satisfies only the third and is forbidden.
- Frontend call sites of the old `deposit(uint256)` ABI (`frontend/src/api/wallet.ts`, `frontend/src/components/TestnetNotice.tsx`) must be updated to the new signature and to compute `ownerCommit`.
- At window seal, the settle path reads `vault.depositChainTip()`/`depositCount()` and carries `deposits_root`/`newDepositCount` into the `settleBatch` call. `WindowWitness` needs no new field — the extended `Deposit` ops already ride in `ops`.
- **Ordering:** the host must feed deposits in ascending `deposit_id` (the L1 order); `op_deposit`'s `deposit_id == consumed_deposit_count` check enforces it and fails closed on any gap/reorder.

## Behavior / edge cases

| Condition | Result |
|---|---|
| `Deposit` with `deposit_id != consumed_deposit_count` | `EngineError::DepositOutOfOrder` → batch invalid (fail-closed) |
| Proof credits fewer than all L1 deposits (`newDepositCount < vault.depositCount()`) | `settleBatch` reverts ("must consume all pending") |
| Fabricated deposit (no L1 event) | its `(from,owner,amount,id)` isn't in the vault chain ⇒ `deposits_root != vault.depositChainTip()` ⇒ revert |
| Real deposit credited to wrong owner | leaf's `owner` differs ⇒ chain tip differs ⇒ revert |
| Deposit lands between seal and settle | tip/count moved ⇒ settle tx reverts ⇒ existing `SettleFailed` reconcile rolls back ⇒ re-seal including it (bounded liveness cost) |
| First-ever deposit | folds onto genesis `[0;32]`, `id == 0 == consumed_deposit_count` |

## Components & interfaces (files)

- `crates/perp-core/src/merkle.rs` — `deposit_leaf`, `deposit_chain_fold` (+ a `deposit_chain_root(prev_tip, &[leaves])` convenience), unit-tested for Solidity byte-parity.
- `crates/perp-core/src/state.rs` — 2 new fields + `state_root()` fold; init in constructors.
- `crates/perp-core/src/engine.rs` — `BatchOp::Deposit` fields, `op_deposit` ordering+fold, `DepositIn` output, `BatchOutputs.deposits`, `EngineError::DepositOutOfOrder`.
- `crates/perp-core/src/commitment.rs` — `DerivedRoots.deposits_root`, `derive_roots` set it, 7th commitment word.
- `contracts/src/CollateralVault.sol` — accumulator + `deposit(amount, owner)` + `Deposit` event + getters.
- `contracts/src/DarkPerpSettlement.sol` — 7-word `publicCommitment`, `settleBatch`/`finalSettle` deposit check + new public inputs.
- `crates/gateway/src/l1.rs`, `crates/gateway/src/main.rs`, `crates/sequencer/src/lib.rs` — host plumbing.
- `crates/gateway/src/withdrawals.rs` (re-export site) — re-export the new merkle fns if the gateway needs them.

## Testing (TDD)

Local, no SP1:
1. **`perp-core` merkle parity** (`cargo test -p perp-core`): `deposit_leaf`/`deposit_chain_fold` produce known-answer vectors that a Solidity test reproduces (hard-coded expected hashes shared by both suites).
2. **`op_deposit`**: in-order deposit folds tip + bumps count + credits `external_in`; out-of-order `deposit_id` ⇒ `DepositOutOfOrder`; conservation still holds after.
3. **`derive_roots`**: `deposits_root` == the incremental fold over the batch's deposits from the prior `consumed_deposit_tip`; 7-word `commitment()` changes when `deposits_root` changes.
4. **Solidity** (`forge test`, vendored MiniTest): `deposit(amount, owner)` advances `depositChainTip`/`depositCount` with the exact leaf/fold; `settleBatch` reverts on `depositsRoot != depositChainTip()` and on `newDepositCount != depositCount()`, passes on the matching pair; `publicCommitment` known-answer matches the Rust `commitment()` vector.
5. **Cross-parity**: one shared known-answer vector (same `from/owner/amount/id` sequence) asserted identical in a `perp-core` test AND a `forge` test — the Rust chain tip == the Solidity `depositChainTip`.
6. **Host** (`cargo test -p gateway`): `verify_deposit_tx` parses `id`/`owner`; `fund_amount` builds the extended op; owner-mismatch rejected.

Deferred to the GB10/SP1 box (tracked, not local): generate a real proof over a batch with deposits, confirm the guest enforces `deposits_root`, and settle it against a redeployed `DarkPerpSettlement`/`CollateralVault` on Base Sepolia (breaking redeploy — new commitment arity + verifier).

## Deferred to Phase 2 (tracked)

Race-free partial consumption (checkpointed deposit watermarks so a settle need not consume all pending), if deposit volume makes the consume-all re-seal cost material. No interface change to the leaf/chain — only the settlement's consume rule and a vault tip-checkpoint would change.

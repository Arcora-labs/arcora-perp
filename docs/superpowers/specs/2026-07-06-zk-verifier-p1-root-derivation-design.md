# ZK Verifier — P1: Circuit Derivation of the Four Roots (Design)

**Date:** 2026-07-06
**Status:** Approved (brainstorming) → ready for implementation plan
**Workstream:** ZK verifier (the named mainnet gate). This spec is **P1 only** — the
soundness core. P2 (real SP1/Risc0 proving backend + on-chain Groth16 verifier +
vkey binding) and P3 (real-TEE confidential proving) are explicitly out of scope
and get their own spec/plan cycles.

---

## 1. Problem

`crates/sp1-guest/src/main.rs` today deserializes
`(state, ops, manifest_hash, ordered_root, withdrawals_root, rejected_root)` from
the witness and only re-derives `new_state_root = state.state_root()`. The other
four roots are **trusted witness inputs** the guest merely echoes into the public
commitment. Under a real verifier (P2) this is a vault-drain: a malicious prover
supplies an arbitrary `withdrawals_root` (with the attacker's leaf), produces a
genuine proof of the state transition with that root baked into the public input,
and `settleBatch` → `vault.publishWithdrawals(arbitraryRoot)` releases funds to the
attacker (audit F2). The `ordered_root`/`rejected_root`/`manifest_hash` are likewise
three independent prover-chosen values that could disagree with each other.

**Replacing MockZkVerifier without fixing this is worse than useless** — a real
verifier would faithfully attest a drain. The guest must **derive** the roots.

## 2. Goal

The guest derives **all four** roots from a single coherent witness `(state, ops,
manifest)`, so they become *outputs of the proven computation* — mutually
consistent and, for withdrawals, constrained to the actual burned notes. Pure Rust;
fully testable now; **no on-chain logic change**. This makes the whole pipeline
real-verifier-ready so P2 is a backend swap.

## 3. Scope boundary (the honest line)

Two soundness levels exist; P1 delivers the first and explicitly defers the second:

- **Level A — structural derivation + withdrawals constraint (P1, this spec).**
  The guest derives `manifest_hash`/`ordered_root`/`rejected_root` by hashing and
  merklizing the manifest's explicit `ordered`/`rejected` lists, and derives
  `withdrawals_root` from the actual `Withdraw` ops (amount bound to each burned
  note). The four roots are computed in-circuit from one witness, so they cannot
  disagree, and **withdrawals is fully constrained → F2 closed**.

- **Level B — matching fairness (Proof-v2, NOT this spec).**
  Re-deriving the ordered-vs-rejected *split* from the raw order stream (proving the
  matcher obeyed the matching rule). The codebase already defers this
  (`crates/perp-core/src/engine.rs:9-13`) and backs it with receipts + inclusion
  slashing in the interim. P1 does **not** re-run the matcher in-circuit.

**What P1 therefore does and does not prove:**
- ✅ `withdrawals_root` provably equals the withdrawals authorized by the burned
  notes in this batch — a prover cannot invent a withdrawal for funds never burned.
- ✅ `manifest_hash`, `ordered_root`, `rejected_root` are circuit-derived merkle
  roots / hash of **one** manifest, mutually consistent, tied to the state
  (`previous_state_root`, `batch_id`).
- ❌ P1 does NOT prove the ordered/rejected *split* is what the matching rule
  dictates (Proof-v2). A dishonest sequencer that fabricates the split is still only
  constrained by receipts + slashing until Proof-v2.

**No deferred on-chain hook.** An earlier draft of this design used a cumulative
withdrawals accumulator, which needed the *previous* root as a prover-supplied
witness and therefore an on-chain inductive anchor to be safe. The incremental
model in §4.2 removes that entirely — there is no prior-root witness to anchor.

## 4. Design

### 4.1 Shared derivation module (`perp-core`, no_std) — single source of truth

`withdrawal_leaf` / `inclusion_leaf` / `rejection_leaf` / `merkle_root` (+
`hash_pair` / `next_level`) live **only** in `crates/gateway/src/withdrawals.rs`
(std, gateway-only) today. The guest is `no_std` and cannot use them. Move them into
a **no_std** module `crates/perp-core/src/merkle.rs`, byte-for-byte identical
(same `Keccak256`, same sorted-pair internal node with no domain tag, same 65-byte
domain-tagged challenge leaves, same `withdrawal_leaf = keccak(to‖amount‖nonce)`
big-endian packing). `crates/gateway/src/withdrawals.rs` re-exports them
(`pub use perp_core::merkle::*`) so off-chain trees and in-circuit trees are provably
the same code — DRY, not duplicated. `merkle_proof` / `verify` (prover-side,
std-friendly) may stay in the gateway; the leaf + `merkle_root` builders are what the
circuit needs.

Add three derivation helpers (no_std, generic over `Hasher`), each callable from the
guest, prover, host, and sequencer:

- `ordered_root(batch_id, &[Digest ordered]) -> Digest`
  = `merkle_root(ordered.map(|oh| inclusion_leaf(batch_id, oh)))`.
- `rejected_root(batch_id, &[Digest rejected]) -> Digest`
  = `merkle_root(rejected.map(|oh| rejection_leaf(batch_id, oh)))`.
- `withdrawals_root(&[WithdrawalLeaf]) -> Digest`
  = `merkle_root(leaves.map(withdrawal_leaf))`.

`manifest_hash` needs no new helper — `BatchManifest::hash::<H>()` already exists in
`perp-core/src/order.rs`.

**Empty batch:** `merkle_root(&[])` returns `[0u8;32]` today
(`withdrawals.rs:101-103`, documented as matching the contract's unset root), so an
all-empty ordered/rejected/withdrawals set yields a deterministic root identical
between guest and gateway. `withdrawals_root == [0u8;32]` is the empty case the
vault's `publishWithdrawals` already special-cases (it will not register
`bytes32(0)` as claimable). The moved no_std `merkle_root` preserves this exactly.

A minimal no_std leaf type — `WithdrawalLeaf { to:[u8;20], amount:u128, nonce:u64 }`
— lives in `merkle.rs`; the gateway's `Withdrawal { owner, to, amount, nonce }`
(`owner` is off-chain filtering only, never in the leaf) converts into it.

### 4.2 `BatchOp::Withdraw` extension + incremental withdrawals (the F2 fix)

`op_withdraw` (`engine.rs:675`) calls `consume_note(...)` which returns the note, so
**`note.amount` is recoverable in-circuit**. Extend the op so a *real L1* withdrawal
also carries its destination:

```
BatchOp::Withdraw { note_commitment: Digest, spend_key: Digest, to: Option<[u8;20]>, nonce: u64 }
```

**Why `to` is optional — `Withdraw` is overloaded.** Only the v1 `account_withdraw`
path (`gateway/src/main.rs:1294`) creates a vault-claimable L1 withdrawal (the only
site that pushes to `pending_withdrawals`, `:1306`). Two other sites use `Withdraw`
as an **internal note-burn** — LP debit (`:2015`, immediately re-funds another
account) and the legacy withdraw (`:2346`) — with no L1 destination and no vault
claim, yet they still go through the sequencer, so a proven batch can contain both.
`to = Some(addr)` marks a real L1 withdrawal; `to = None` marks an internal burn.
Only `Some` withdrawals enter `withdrawals_root` — internal burns must NOT pollute
it. (`nonce` is only meaningful when `to.is_some()`; internal sites pass `nonce: 0`.)

`apply_batch` collects, per `Withdraw` **with `to = Some(addr)`**, a
`WithdrawalOut { to: addr, amount: note.amount, nonce }` — amount bound to the actual
burned note, so the prover cannot lie about it. A `to = None` burn emits nothing.
Change `apply_batch`'s signature from `Result<(), EngineError>` to
`Result<BatchOutputs, EngineError>` where `BatchOutputs { withdrawals:
Vec<WithdrawalOut> }` (the plan picks the least-invasive concrete shape — return
value vs `&mut` accumulator; most callers just `?;` and ignore it).

**`withdrawals_root` is the merkle root of THIS engine batch's `WithdrawalOut` leaves
only — an incremental, per-batch root, derived entirely from the `Withdraw` ops.**
Because every leaf is engine-emitted from a real burned note, a prover cannot add a
leaf without a corresponding real burn in `ops`. This is the **circuit-side F2
closure mechanism** — no prior-root witness, no accumulator, no anchor. Enforcement
of that derived value on-chain requires the real verifier and the matching on-chain
publish path, which land in **P2** (see below and §7); under P1's MockZkVerifier
nothing on-chain is enforced yet — P1 makes the pipeline real-verifier-ready.

**Why incremental is safe (the vault already supports it):**
`CollateralVault` (`contracts/src/CollateralVault.sol`) records
`rootPublished[root] = true` for **every** published root and `claim` accepts a proof
against **any** past published root (audit DP-012); `claimed[leaf]` prevents
double-claim and `nonce` is globally unique, so each leaf lives in exactly one
batch's root. So an incremental per-batch publish path needs **no vault logic
change**. Wiring the gateway to actually publish per-batch incremental roots is P2.

**Batch-granularity note (why the gateway publish path is P2, not P1):** the
prover/host/guest each prove **one engine batch** (one `BatchManifest`, one `ops`
list — `run_transition` takes a single manifest). The gateway's L1 settle loop
(`crates/gateway/src/main.rs:4526-4638`), however, **aggregates every engine batch
since the last settle** into one `settleBatch` call and builds the withdrawals root
**cumulatively** over `pending_withdrawals`, keyed to the *L1* batch counter. Making
the on-chain published root match a per-engine-batch circuit derivation therefore
requires reconciling L1-vs-engine batch granularity — which is exactly the
on-chain-binding work of P2 (real verifier + settle path). P1 does **not** touch the
gateway's cumulative publish path.

**P1 ripple (all updated in lockstep):**
- `crates/perp-core/src/engine.rs` — `BatchOp::Withdraw` gains `to`/`nonce`;
  `apply_batch` returns `BatchOutputs`; `op_withdraw` emits `WithdrawalOut`.
- `crates/gateway/src/main.rs` `Withdraw` construction sites: `account_withdraw`
  (`:1294`) passes `to: Some(to)` + its `next_withdraw_nonce` (real L1 withdrawal);
  the LP-debit (`:2015`) and legacy (`:2346`) internal burns pass `to: None,
  nonce: 0` (excluded from `withdrawals_root`).
- `crates/gateway/src/withdrawals.rs` re-exports the moved perp-core merkle so its
  existing Solidity-vector tests lock the moved code. **Cumulative publish path
  unchanged** (its `merkle_root` calls now hit the re-exported no_std version).
- `crates/sequencer/src/lib.rs` batch build consumes `apply_batch`'s `BatchOutputs`.
- Any `Withdraw` in `crates/demo`, `crates/e2e`, `crates/sequencer` tests.

### 4.3 Witness reshape

New witness tuple (postcard-encoded, replacing the 4 trusted roots):

```
type Witness = (
    DefaultState,     // pre-state
    Vec<BatchOp>,     // the batch ops (Withdraw now carries to/nonce)
    BatchManifest,    // full manifest → derives manifest_hash/ordered/rejected
);
```

`BatchManifest` is already `no_std` (`perp-core/src/order.rs`) — it carries
`previous_state_root`, `batch_id`, `ordered: Vec<Digest>`,
`rejected: Vec<(Digest, RejectReason)>`, etc. `withdrawals_root` needs **no** witness
input beyond `ops` (it is derived from the engine's `WithdrawalOut`s). Update the
postcard round-trip lock `crates/perp-core/tests/serde_witness.rs` and the
guest/host `postcard::from_bytes`/`to_allocvec` to the new tuple.

### 4.4 Guest derivation + consistency checks

`sp1-guest/src/main.rs::main`:

1. `prev_state_root = state.state_root()`.
2. `let batch_id = state.next_batch_id;` (capture before apply).
3. `let outputs = state.apply_batch(&ops).expect("valid transition");`
4. `new_state_root = state.state_root()`.
5. **Consistency (cheap, ties manifest to state):**
   - `assert(manifest.previous_state_root == prev_state_root)`,
   - `assert(manifest.batch_id == batch_id)`.
   A mismatch panics → the proof fails.
6. `manifest_hash  = manifest.hash::<Keccak256>()`.
7. `ordered_root   = ordered_root(batch_id, &manifest.ordered)`.
8. `rejected_root  = rejected_root(batch_id, order_hashes_of(&manifest.rejected))`.
9. `withdrawals_root = withdrawals_root(&outputs.withdrawals.map(WithdrawalLeaf::from))`.
10. `commitment = Keccak256::hash_words(Domain::StateRoot, &[prev_state_root,
    manifest_hash, new_state_root, ordered_root, withdrawals_root, rejected_root])`
    — **byte-identical to prover & contract** (unchanged 6-field shape).
11. `commit_slice(&commitment)`.

Step 9 is the F2-closing invariant: `withdrawals_root`'s leaves come only from
engine-emitted `WithdrawalOut`s whose `amount` is a real burned note.

### 4.5 `prover` crate

`run_transition` derives the roots internally instead of receiving them as args:

```
pub fn run_transition(
    state: &mut DefaultState,
    ops: &[BatchOp],
    manifest: &BatchManifest,
) -> Result<PublicInputs, EngineError>
```

`PublicInputs` stays the 6-field struct and `commitment()` is unchanged. Rewrite the
struct/field doc-comments and the `NOTE (Phase 0): NOT re-derived / trusted-sequencer
input` caveats on `ordered_root`/`withdrawals_root`/`rejected_root` to state they are
now **derived**, keeping ONE honest caveat: the ordered/rejected *split* honesty
(matching fairness) remains Proof-v2. `CommitmentProver`/`SealedWitness`/
`AttestedProver` are untouched (they're the P2/P3 boundary).

### 4.6 Contracts (NatSpec only — no logic change)

- `contracts/src/interfaces/IZkVerifier.sol` — the doc says
  `keccak256(uint8(7), prevRoot, manifestHash, newRoot)` (3 fields, stale). Fix to
  the real 6 fields.
- `contracts/src/DarkPerpSettlement.sol::publicCommitment` NatSpec + the
  `answerByRejection` / `settleBatch` "PHASE 0 caveat" comments — update "these root
  VALUES are NOT re-derived" to reflect that P1 now derives them (retaining the honest
  matching-fairness caveat on the ordered/rejected split).
- `contracts/src/CollateralVault.sol::publishWithdrawals` NatSpec is **left as-is in
  P1** — the gateway still publishes cumulative roots in P1, so the "cumulative root"
  invariant is still accurate. It is rewritten in **P2**, when the gateway switches
  to incremental publishing.
- **No Solidity logic changes in P1.** `settleBatch` still takes the six roots as
  params and binds them; the guest now proves they are the derived values.

## 5. Testing (the equivalence gate)

- **Cross-check equivalence (the key test):**
  - `manifest_hash`: the guest/prover derivation IS `BatchManifest::hash` — assert it
    equals a real `SealedBatch.manifest_hash` produced by the sequencer.
  - `ordered_root`/`rejected_root`/`withdrawals_root`: the moved no_std leaf +
    `merkle_root` builders must be **byte-identical** to the old gateway ones — a
    golden test hashing the old vs moved output, PLUS the existing Solidity-vector
    tests (`leaf_matches_solidity_abi_encode_packed`, `challenge_leaves_match_solidity`
    in `crates/gateway/src/withdrawals.rs`) now exercising the re-exported moved code.
    The guest/prover call these exact functions, so "the circuit derives exactly what
    the honest sequencer publishes." This is the merge gate.
- **Host equivalence** (`crates/sp1-host/src/main.rs`): update the native-reference
  commitment + witness to the new derivation; native and (executor) guest commit the
  same 6-field digest.
- **Negative tests:**
  - a `Withdraw` op whose leaf is tampered (amount ≠ burned note) → the derived
    `withdrawals_root` cannot be forged to include an unbacked leaf; an extra
    fabricated withdrawal has no `Withdraw` op to emit it.
  - `manifest.previous_state_root` / `batch_id` mismatch → guest panics.
  - mutating any `ordered`/`rejected` entry → different root (extends the existing
    `commitment_binds_the_rejected_root` test).
  - empty batch → `withdrawals_root == [0u8;32]`, guest and gateway agree.
- **`serde_witness` round-trip** for the new 3-tuple (postcard encoding locked).
- Full workspace green: `cargo test --workspace`, `cargo clippy --workspace
  --all-targets`, `forge test` (contracts NatSpec-only, must still compile/pass).

## 6. File map

**Create:**
- `crates/perp-core/src/merkle.rs` — no_std leaf builders (`withdrawal_leaf`,
  `inclusion_leaf`, `rejection_leaf`), `merkle_root`, `WithdrawalLeaf`, and the three
  root-derivation helpers (moved from gateway).

**Modify:**
- `crates/perp-core/src/lib.rs` — `pub mod merkle;`.
- `crates/perp-core/src/engine.rs` — `BatchOp::Withdraw` gains `to`/`nonce`;
  `apply_batch`/`op_withdraw` emit `WithdrawalOut`; new `BatchOutputs` return.
- `crates/perp-core/tests/serde_witness.rs` — new 3-tuple witness lock.
- `crates/prover/src/lib.rs` — `run_transition` derives roots; doc/caveat rewrite.
- `crates/sp1-guest/src/main.rs` — derive all four + consistency checks.
- `crates/sp1-host/src/main.rs` — new witness + native reference.
- `crates/gateway/src/withdrawals.rs` — re-export perp-core merkle (delete the moved
  bodies, keep `merkle_proof`/`verify` + the Solidity-vector tests). Cumulative
  publish path unchanged.
- `crates/gateway/src/main.rs` — `Withdraw` sites pass `to`/`nonce`; consume
  `apply_batch` `BatchOutputs`. (No publish-path change in P1.)
- `crates/sequencer/src/lib.rs` — consume `apply_batch` `BatchOutputs` in the batch
  build.
- `crates/demo`, `crates/e2e` — `Withdraw` construction + any `apply_batch` callers.
- `contracts/src/interfaces/IZkVerifier.sol`,
  `contracts/src/DarkPerpSettlement.sol` — NatSpec only. (`CollateralVault.sol`
  NatSpec is P2.)

## 7. Non-goals (P1)

- No real zkVM backend, no `cargo prove` in CI, no on-chain verifier swap (P2).
- No gateway on-chain **publish-path** change: the cumulative withdrawals publish,
  per-batch claim-proof serving, and the L1-vs-engine batch-granularity
  reconciliation all stay as-is in P1 and land in **P2** (the enforcement boundary).
  P1's gateway change is only the mechanical `Withdraw`-signature fix + re-exporting
  the moved merkle module.
- No matching-fairness / order-stream re-derivation (Proof-v2).
- No real-TEE key release (P3).
- No `settleBatch` / vault logic change.
- No change to the 6-field public-commitment shape or `Domain::StateRoot` tag.

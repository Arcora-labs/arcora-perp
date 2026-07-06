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
**`note.amount` is recoverable in-circuit**. Extend the op so the transition also
knows the destination:

```
BatchOp::Withdraw { note_commitment: Digest, spend_key: Digest, to: [u8;20], nonce: u64 }
```

`apply_batch` collects, per `Withdraw`, a `WithdrawalOut { to, amount: note.amount,
nonce }` — amount bound to the actual burned note, so the prover cannot lie about it.
Change `apply_batch`'s signature from `Result<(), EngineError>` to
`Result<BatchOutputs, EngineError>` where `BatchOutputs { withdrawals:
Vec<WithdrawalOut> }` (the plan picks the least-invasive concrete shape — return
value vs `&mut` accumulator; most callers just `?;` and ignore it).

**`withdrawals_root` is the merkle root of THIS batch's `WithdrawalOut` leaves only —
an incremental, per-batch root, derived entirely from the `Withdraw` ops.** Because
every leaf is engine-emitted from a real burned note, a prover cannot add a leaf
without a corresponding real burn in `ops`. **This is the complete F2 closure** — no
prior-root witness, no accumulator, no anchor.

**Why incremental is safe (the vault already supports it):**
`CollateralVault` (`contracts/src/CollateralVault.sol`) records
`rootPublished[root] = true` for **every** published root and `claim` accepts a proof
against **any** past published root (audit DP-012); `claimed[leaf]` prevents
double-claim and `nonce` is globally unique, so each leaf lives in exactly one
batch's root. A user claims against the root of the batch their withdrawal settled
in. No cumulative carry-forward is needed and nothing strands. **No vault logic
change** — only a NatSpec update (§4.6).

**Ripple (all updated in lockstep):**
- `crates/gateway/src/main.rs` `Withdraw` construction sites (≈`:1294`, `:2015`,
  `:2346`) pass `to`/`nonce` (already available — `account_withdraw` has `to` and
  `next_withdraw_nonce`).
- `crates/gateway/src/withdrawals.rs` / the batch-settle path: build the **per-batch
  incremental** withdrawals root (simpler than today's cumulative prune+rebuild) and
  record which batch each `Withdrawal` settled in, so `v1_withdrawals_json`
  (`main.rs:1314`) serves the claim proof against that batch's root.
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
- `contracts/src/CollateralVault.sol::publishWithdrawals` NatSpec — the current
  "INVARIANT: root MUST be the cumulative root" text describes the old off-chain
  model. Update it to: each batch publishes its **own** withdrawals root; DP-012's
  `rootPublished` mapping makes every batch root permanently claimable, so no
  cumulative carry-forward is required. **No logic change** — the contract already
  behaves correctly for incremental roots.
- **No Solidity logic changes in P1.** `settleBatch` still takes the six roots as
  params and binds them; the guest now proves they are the derived values.

## 5. Testing (the equivalence gate)

- **Cross-check equivalence (the key test):** on a real sealed batch produced by the
  sequencer, assert the guest/prover-derived `manifest_hash`, `ordered_root`,
  `rejected_root`, `withdrawals_root` are **byte-identical** to what the sequencer /
  gateway publish off-chain (`SealedBatch.manifest_hash`, the gateway's ordered tree,
  the gateway's per-batch withdrawals tree). "The circuit derives exactly what the
  honest sequencer publishes." This is the merge gate.
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
- `crates/gateway/src/withdrawals.rs` — re-export perp-core merkle; per-batch
  (incremental) root builder; keep `merkle_proof`/`verify`.
- `crates/gateway/src/main.rs` — `Withdraw` sites pass `to`/`nonce`; consume
  `apply_batch` outputs; track each withdrawal's batch for claim-proof serving.
- `crates/sequencer/src/lib.rs` — consume `apply_batch` `BatchOutputs` in the batch
  build.
- `crates/demo`, `crates/e2e` — `Withdraw` construction + any `apply_batch` callers.
- `contracts/src/interfaces/IZkVerifier.sol`,
  `contracts/src/DarkPerpSettlement.sol`, `contracts/src/CollateralVault.sol` —
  NatSpec only.

## 7. Non-goals (P1)

- No real zkVM backend, no `cargo prove` in CI, no on-chain verifier swap (P2).
- No matching-fairness / order-stream re-derivation (Proof-v2).
- No real-TEE key release (P3).
- No `settleBatch` / vault logic change (incremental roots need none).
- No change to the 6-field public-commitment shape or `Domain::StateRoot` tag.

# ZK Verifier P2 — Slice 3b-2a: Gateway Window-Settle Path + Incremental Withdrawals — Design

**Date:** 2026-07-08
**Status:** Approved (brainstorming) → ready for implementation plan
**Workstream:** ZK verifier P2. Slices 1/2/3a/3b-1 are DONE and merged (main `1b05b94`). The chosen
settlement granularity is **per-L1-window (~30s): one proof + one `settleBatch` per window**. Slice 3b-1
gave the sequencer a `seal_window() -> WindowWitness` that produces a replayable per-window witness — but
it is **dormant** (only `spine.rs` tests call it; the live gateway still drives `seal_batch` per tick and
never assembles a window). This slice, **3b-2a**, wires `seal_window` into the gateway settle path behind a
`ProverClient` abstraction whose first implementation is a **local `MockProverClient`** (derives the six
roots via `perp_core::commitment::derive_roots`, `proof == commitment`), and reworks the gateway's
withdrawals publish from a **cumulative** root to the **incremental** per-window root the circuit derives.
It is fully CI-testable — no prover-service, no network. Next: **3b-2b** adds `HttpProverClient` (seal →
`POST /prove` → real Groth16 proof, GB10 e2e); **3b-3** adds per-window rollback + inclusion/receipt
re-keying. Then the migration slice deploys the real verifier and repoints `perp.arcoralabs.xyz`.

---

## 1. Problem

The proving half and the settling half are built but unconnected. The prover-service (Slice 2) accepts a
sealed `(DefaultState, Vec<BatchOp>, BatchManifest)` witness and derives the six on-chain roots; the
sequencer (Slice 3b-1) produces exactly that witness from `seal_window()`. But the gateway's L1-settle loop
(`crates/gateway/src/main.rs:4529-4668`) never calls `seal_window`. Instead, per settle tick it:

- reads the live engine `state_root_hex()` / `last_manifest_hex()` and three gateway-held accumulators
  (`pending_withdrawals`, `pending_ordered`, `pending_rejected`),
- builds a **cumulative** withdrawals root over *every still-unclaimed leaf across all past windows*
  (`main.rs:4569-4580`) — pruning leaves the vault reports `claimed`,
- builds `ordered_root`/`rejected_root` itself from the accumulators, and
- submits a **mock proof** synthesized inside `L1::settle` as `proof == publicCommitment(...)`
  (`crates/gateway/src/l1.rs:390-414`).

Two consequences make this incompatible with a real per-window proof:

1. **The withdrawals root is cumulative, the circuit's is incremental.** The engine derives
   `withdrawals_root` from *only the `BatchOp::Withdraw{to: Some}` ops in this window's `window_ops`*
   (`perp_core::merkle::withdrawals_root`, from `apply_batch` outputs) — an incremental, this-window-only
   root. A window with no new withdrawals derives `0x0`, while the gateway would publish the carried-forward
   cumulative root. Submitting the prover's root would mismatch what `v1_withdrawals_json` proofs verify
   against and break the vault's per-root carry-forward model.

2. **`seal_window` is never drained.** Because nothing calls it, `window_ops`/`window_ordered`/
   `window_rejected` accumulate from genesis and are never cleared — a latent unbounded-growth item — and
   the sequencer's per-window batch counter `state.next_batch_id` (bumped only inside `seal_window`,
   `lib.rs:908`) stays frozen at 0 while the on-chain `batchCount` climbs once per settle.

## 2. Goal

The gateway, when the new path is selected, settles **one window per L1 tick** by: calling
`seq.seal_window()` to get the `WindowWitness`; handing it to a `ProverClient` that returns the six roots +
a proof; and submitting exactly those roots + that proof to `settleBatch`. Withdrawals become
**incremental**: each window's withdrawal tree is built once from that window's `BatchOp::Withdraw{to:Some}`
records, its root is published once (permanently claimable via the vault's `rootPublished`), and per-note
claim proofs are served against that window's root. The whole path is exercised in CI with a
`MockProverClient` (local `derive_roots`, `proof == commitment`) — including a byte-match test that the
gateway's window withdrawal tree root equals the circuit's derived `withdrawals_root`. The **legacy
cumulative + mock path is preserved byte-for-byte** and stays the default; the new path is opt-in.

## 3. Flag semantics — one flag, three states

Selection is driven by the single env var `PROVER_URL`:

| `PROVER_URL` | Path | Client | Slice |
|---|---|---|---|
| unset | legacy cumulative + mock (today, unchanged) | — | (default) |
| `mock` | new window-settle + incremental | `MockProverClient` (local derive, `proof==commitment`) | **3b-2a** |
| `<http url>` | new window-settle + incremental | `HttpProverClient` (seal → `POST /prove`) | 3b-2b |

The `<http url>` case is stubbed in 3b-2a (constructing it errors "HttpProverClient is 3b-2b" or is simply
not wired) and implemented in 3b-2b. The legacy path is what runs on the live stack until the migration
slice deliberately sets `PROVER_URL`.

## 4. Architecture

### 4.1 `ProverClient` abstraction — new module `crates/gateway/src/prover_client.rs`

```rust
use perp_core::hash::Digest;
use sequencer::WindowWitness;

/// The six on-chain roots + commitment + proof for one window's settleBatch.
pub struct ProveOutcome {
    pub prev_root: Digest,
    pub manifest_hash: Digest,
    pub new_root: Digest,
    pub ordered_root: Digest,
    pub withdrawals_root: Digest,
    pub rejected_root: Digest,
    pub commitment: Digest,
    pub proof: Vec<u8>,
}

#[derive(Debug)]
pub enum ProverClientError {
    Derive(perp_core::EngineError),   // witness failed to replay (should not happen on a live window)
    // 3b-2b adds: Http(...), Decode(...), Seal
}

pub trait ProverClient: Send + Sync {
    fn prove(&self, witness: &WindowWitness) -> Result<ProveOutcome, ProverClientError>;
}

/// In-process, no confidentiality boundary: derive the roots locally and use the
/// commitment as the proof (accepted by the on-chain MockZkVerifier: proof == commitment).
pub struct MockProverClient;

impl ProverClient for MockProverClient {
    fn prove(&self, w: &WindowWitness) -> Result<ProveOutcome, ProverClientError> {
        let mut state = w.pre_state.clone();
        let d = perp_core::commitment::derive_roots(&mut state, &w.ops, &w.manifest)
            .map_err(ProverClientError::Derive)?;
        let commitment = d.commitment::<perp_core::hash::Keccak256>();
        Ok(ProveOutcome {
            prev_root: d.prev_state_root,
            manifest_hash: d.manifest_hash,
            new_root: d.new_state_root,
            ordered_root: d.ordered_root,
            withdrawals_root: d.withdrawals_root,
            rejected_root: d.rejected_root,
            commitment,
            proof: commitment.to_vec(),   // MockZkVerifier accepts proof == commitment
        })
    }
}
```

`derive_roots`'s exact field names / signature are taken from `crates/perp-core/src/commitment.rs`
(`DerivedRoots { prev_state_root, manifest_hash, new_state_root, ordered_root, withdrawals_root,
rejected_root }`, `commitment::<H>()` over the six via `Domain::StateRoot`). **Sealing is deliberately NOT
part of the trait** — it is a transport concern of `HttpProverClient` only (the mock is in-process, so there
is nothing to seal). This keeps the mock pure (no seal key) and confines the seal round-trip to 3b-2b.

### 4.2 Settle-loop rewiring (`crates/gateway/src/main.rs` settle task)

The settle task selects a path from the configured `Arc<dyn ProverClient>` option (built in `main` from
`PROVER_URL`). `None` → the legacy loop body, **byte-unchanged**. `Some(client)` → the new body:

1. **Under the `gw` lock**, decide whether there is a transition to settle using a local, RPC-free signal:
   if `gw.seq.state.state_root() == gw.last_settled_root` (no net state change since the last settle)
   **do not call `seal_window`** (avoid a counter bump with no on-chain settle) and skip this tick.
   `last_settled_root` is a new `Gw` field, initialized to the genesis state root and updated to
   `out.new_root` after each successful settle. (The contract still enforces `prevRoot == currentStateRoot`
   inside `settleBatch`, so any residual mismatch fails safe.)
2. **Under the lock**, `let witness = gw.seq.seal_window();` (drains `window_ops`, bumps
   `state.next_batch_id` once) and take the window's withdrawals: `let ww =
   core::mem::take(&mut gw.window_withdrawals);`.
3. **Alignment guard**: read `let bc = l1.batch_count()?;` and require `witness.batch_id == bc`. On the
   happy path both start at 0 and advance once per settle, so this always holds. If a prior fault desynced
   them, **skip this settle and log** (`[l1] batch_id desync: witness W vs chain B`) rather than submit a
   doomed tx. Full recovery/rollback is 3b-3.
4. **In `spawn_blocking`**: `let out = client.prove(&witness)?;` then `let tx = l1.settle_proved(&out)?;`
   (submits `out`'s six roots + `out.proof` to `settleBatch`).
5. **Build the window withdrawal tree** from `ww` (in op-application order) and **assert its root ==
   `out.withdrawals_root`** (byte-match invariant — both come from the same ops in the same order). Store
   per-note claim proofs `{leaf → (out.withdrawals_root, merkle_proof)}` into `withdraw_proofs`.
6. Update `l1_status`, broadcast the snapshot (as today).

The `WindowWitness` (owned: `DefaultState` + `Vec<BatchOp>` + `BatchManifest`, all `Send`) and `ww` move
into `spawn_blocking` cleanly; `MockProverClient::prove` is pure CPU (`derive_roots`). `ProverClient::prove`
is **synchronous** so both the mock (CPU) and the future HTTP impl (blocking POST) fit the existing
`spawn_blocking` structure.

### 4.3 Withdrawals: cumulative → incremental

- **New `Gw` field** `window_withdrawals: Vec<Withdrawal>` — accumulates each `account_withdraw`'s
  `Withdrawal` in the same order the `BatchOp::Withdraw{to: Some}` is applied. `Gw::account_withdraw`
  (`main.rs:1264-1318`) already applies the op and pushes to `pending_withdrawals` (`:1317`); it gains one
  line to also push to `window_withdrawals`. **Legacy `pending_withdrawals` is untouched** (the legacy path
  still builds its cumulative root from it; the new path ignores it).
- **Per-window tree**: `merkle_root(ww.iter().map(|w| w.leaf()))` where `Withdrawal::leaf()` is
  `withdrawal_leaf(&to, amount, nonce)` — the *same* leaf function `perp_core::merkle::withdrawals_root`
  applies to the circuit's `WithdrawalOut`s (`crates/perp-core/src/merkle.rs:318-324`). Because both derive
  from the same op sequence in application order, the trees are byte-identical → the §4.2.5 assertion holds.
  (`to: None` LP/legacy burns at `main.rs:2026`/`:2361` never enter `window_withdrawals` and never enter the
  circuit's root — the engine gates them at `op_withdraw`.)
- **Unify `withdraw_proofs`** from `BTreeMap<[u8;32], Vec<[u8;32]>>` to
  `BTreeMap<[u8;32], (Digest root, Vec<Digest> proof)>` — each note carries the root of the window it was
  published in. The legacy path populates it with `(cumulative_root, proof)`; the new path with
  `(window_root, proof)`. `v1_withdrawals_json` (`main.rs:1325-1353`) reads `(root, proof)` uniformly and
  emits the **same JSON shape** (`{to, amount, nonce, leaf, root, claimable, proof}`) — a behavior-identical
  change for legacy. `claimable = !l1.claimed(leaf)`.
- Because each window root is published once and `rootPublished[root]` is permanent (vault DP-012,
  `CollateralVault.claim(to, amount, nonce, root, proof)` verifies against any published root and
  `claimed[leaf]` prevents replay), the new path **drops the cumulative re-prune/rebuild** at
  `main.rs:4569-4580`; a window's root is fixed at seal time and never recomputed. `withdraw_proofs` is
  retained across windows (bounded by total unclaimed withdrawals) and entries are pruned when
  `claimed[leaf]`.

### 4.4 `L1` (`crates/gateway/src/l1.rs`)

New method `L1::settle_proved(&self, out: &ProveOutcome) -> Result<String, String>` — submits the prover's
roots + proof directly, no `publicCommitment` synthesis:

```rust
self.send(
    &self.settlement.clone(),
    "settleBatch(bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes)",
    &[ &hex32(&out.prev_root), &hex32(&out.manifest_hash), &hex32(&out.new_root),
       &hex32(&out.ordered_root), &hex32(&out.withdrawals_root), &hex32(&out.rejected_root),
       &format!("0x{}", hex::encode(&out.proof)) ],
)
```

The mock client's `out.proof == commitment` (32 bytes), which the on-chain `MockZkVerifier` accepts. Legacy
`L1::settle` (`l1.rs:381-416`) stays unchanged for the legacy path.

### 4.5 Counter alignment (happy path only)

`seal_window` reads `batch_id = state.next_batch_id` then bumps it once (`lib.rs:895/908`). Called exactly
once per settle, `state.next_batch_id` tracks the on-chain `batchCount` (both genesis-0, both +1 per
settle). The §4.2.3 guard (`witness.batch_id == batch_count`) is the cheap safety net that keeps the
`ordered_root`/`rejected_root` leaves (`inclusion_leaf(batch_id, h)` / `rejection_leaf(batch_id, h)`,
byte-locked in `perp_core::merkle`) answerable by the on-chain challenge path, which keys on `batchCount`.
The fault path (settle reverts after `seal_window` already drained + bumped) desyncs the two; 3b-2a's guard
halts further settles and logs, and 3b-3 adds the rollback that restores the counter + window state.

## 5. The merge gate (CI, gateway crate)

- **`MockProverClient::prove` matches the circuit**: for a non-trivial `WindowWitness`, the returned six
  roots equal `derive_roots(pre_state.clone(), ops, manifest)`'s roots and `proof == commitment`.
- **Withdrawals byte-match** (the slice's core correctness claim): drive a window containing ≥2
  `account_withdraw`s (so `window_withdrawals` is non-empty and ordered), plus a fill and a funding accrual;
  `seal_window()`; `MockProverClient::prove`; assert the gateway's window withdrawal tree root **equals**
  `out.withdrawals_root`, and that each note's `merkle_proof` verifies against that root the same way the
  vault's `MerkleLib.verify` does (reuse the pinned `perp_core::merkle` verify).
- **Full new-path settle** (harness-level or a focused unit over `Gw`): a window with fill + withdrawal +
  funding → the assembled `ProveOutcome` roots equal `derive_roots`, the withdrawal-tree assertion holds,
  and `witness.batch_id` equals the expected window id.
- **Legacy regression**: with `PROVER_URL` unset, existing gateway/settle tests stay green and the legacy
  cumulative behavior + `v1_withdrawals_json` JSON are unchanged.

## 6. File map

**Create:** `crates/gateway/src/prover_client.rs` — `ProveOutcome`, `ProverClientError`, `ProverClient`
trait, `MockProverClient`. Register `mod prover_client;` in `main.rs`.

**Modify:** `crates/gateway/src/main.rs` — `Gw.window_withdrawals` and `Gw.last_settled_root` fields +
`new()` init; `account_withdraw` push to `window_withdrawals`; `withdraw_proofs` type →
`BTreeMap<[u8;32], (Digest, Vec<Digest>)>` + `v1_withdrawals_json` read; the settle task's new-path branch
(local settle-needed check → seal_window → prove → settle_proved → window withdrawal tree + per-note proofs
→ update `last_settled_root`); `main` builds `Option<Arc<dyn ProverClient>>` from `PROVER_URL`.
`crates/gateway/src/l1.rs` — `L1::settle_proved`.
`crates/gateway/tests/` (or an in-crate `#[cfg(test)]` module) — the merge-gate tests.

**No change:** perp-core, the guest, the prover-service, the sequencer, the contracts. (`seal_window`,
`WindowWitness`, `derive_roots`, and the `perp_core::merkle` leaf builders already exist with the exact
shapes this slice consumes.)

## 7. Non-goals (Slice 3b-2a)

- **No `HttpProverClient`, no network, no real proof, no GB10 e2e** — Slice 3b-2b. The `<http url>` state of
  `PROVER_URL` is stubbed here.
- **No per-window rollback and no inclusion/receipt re-keying** — Slice 3b-3. The fault path (settle revert
  after `seal_window`) is handled only by the §4.2.3 guard (halt + log), not by counter/window restore. The
  sequencer's internal per-tick receipts/`InclusionRecord` (`issued_batch`/`seen_in_batch`, keyed on the
  per-tick `Sequencer::next_batch_id`) are left as-is; the on-chain challenge path already keys on
  `batchCount` via the gateway's own `batch_orders`, so settle/challenge correctness does not depend on the
  re-keying.
- **No contract change.** The vault's `claim(..., root, proof)` is already per-root and `rootPublished` is
  permanent (DP-012); the cumulative→incremental NatSpec clarification lands with the migration slice, when
  the incremental model actually goes live.
- No change to `derive_roots`, the six-field commitment, the `(DefaultState, Vec<BatchOp>, BatchManifest)`
  witness format, or matching fairness (Proof-v2).

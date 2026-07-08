# ZK Verifier P2 — Slice 3b-4: Off-Chain Receipt/Inclusion Re-Keying — Design

**Date:** 2026-07-08
**Status:** Approved (brainstorming) → ready for implementation plan
**Approach:** B — keep Counter A on the receipt, ADD a signed `window_id` (Counter B) field + a finality-pruned A→B map + a reconciliation endpoint.
**Workstream:** ZK verifier P2. The last off-chain-consistency slice before the live migration. Gateway + sequencer + perp-core; **no contract change**.

---

## 1. Problem

The sequencer has two batch-id counters that Slice 3b-1 split apart and never reconciled:

- **Counter A** = `Sequencer::next_batch_id` (`crates/sequencer/src/lib.rs:277`) — bumped once per ~700ms tick in `seal_batch` (`lib.rs:838-839`), **not** in `state_root`. Drives every **user-facing** batch number: the enclave-signed `Receipt.batch_id_hint` (`crates/perp-core/src/order.rs:103`, stamped `lib.rs:443`), `WReceipt.batch_id_hint` (`crates/gateway/src/main.rs:400-405`), the `WBatch` grouping (grouped on `receipt.batch_id_hint`, `main.rs:2919-2949`), and `nextBatchId` in `GET /v1/system/status` (`= current_batch_id()`, `main.rs:1936`). Also drives internal per-tick machinery: `snapshots`, soft-finality (`mark_settled`/`mark_failed`), censorship tracking (`InclusionRecord`, `inclusion_violations`), liquidation/ADL tags, `SealedBatch.batch_id`.
- **Counter B** = `DefaultState::next_batch_id` (`crates/perp-core/src/state.rs:60`) — bound in `state_root` (`state.rs:216`), bumped **once per ~30s window** in `seal_window` (`lib.rs:909-910`), restored by `rollback_window` (`lib.rs:933-935`). Drives everything **on-chain**: `WindowWitness.batch_id`, `batchCount` (`l1.rs:273-275`), the settled ordered/rejected roots via `inclusion_leaf(batch_id,·)`/`rejection_leaf(batch_id,·)` (`crates/perp-core/src/merkle.rs:222-234`), `Gw.batch_orders`, `build_challenge_answer` (`main.rs:1971-1988`), and `answer_challenge` (`l1.rs:532-543`).

The user-facing `Receipt` is **enclave-signed** (`batch_id_hint` is bound into `signing_digest`, `order.rs:108-118`) and there is **no A→B mapping anywhere** — no receipt field, no map, no log links a Counter-A tick id to the Counter-B window that settled it. So the enclave's signed promise ("batch 42", Counter A) names an id space with **zero on-chain footprint**: a user holding a receipt cannot determine which on-chain window (`batchCount`) contains their order, nor which challenge leaf (`keccak(0x00 ‖ Counter-B-id ‖ order_hash)`) would prove inclusion. `nextBatchId` (Counter A) and `l1.batchCount` (Counter B) are not comparable numbers.

## 2. Goal

A user can reconcile their receipt against the on-chain window/challenge. Achieve it **additively** (Approach B): the receipt keeps its per-tick `batch_id_hint` (Counter A — unchanged UI grouping, soft-finality, censorship tracking) **and** gains an **unsigned** `window_id` (Counter B) naming the on-chain window it settles into. (**Design correction, 2026-07-08:** `window_id` is a plaintext reconciliation *hint*, NOT enclave-signed — see §3.5. Signing it would force a Solidity contract change for zero on-chain value and would misrepresent it as a guarantee the protocol does not make.) A finality-pruned A→B map lets any bare Counter-A id (a `WBatch`, `nextBatchId`, a log line) that lacks a receipt be reconciled to its window, surfaced via a `WBatch.window_id` annotation, a `GET /v1/batch/{id}` endpoint, and an `openWindowId` in the status JSON that is comparable to `l1.batchCount`. Internal Counter-A machinery is untouched; the note-archive keying is out of scope.

## 3. Why `state.next_batch_id` at issue time is the correct window id

`issue_receipt` runs inside `seal_batch` (a tick). At that moment `self.state.next_batch_id` (Counter B) is the **currently open window** M, and it stays == M across every tick of the window (`seal_window` bumps it to M+1 only when the window closes, `lib.rs:909-910`). Every order sequenced during window M's ticks therefore settles in window M, and `rollback_window` restores Counter B to M on a failed window so a re-sealed window keeps the same id (`lib.rs:933-935`). So `state.next_batch_id` read at issue time is exactly — and rollback-stably — the on-chain window the order settles into. It is the right value to sign and to key the A→B map on.

## 3.5 Why `window_id` is UNSIGNED (design correction, 2026-07-08)

The on-chain inclusion-challenge game already decouples the two counters, so signing `window_id` is both valueless and misleading:

- `challengeInclusion(orderHash, seqNo, recvTimeMs, batchIdHint, v, r, s)` (`DarkPerpSettlement.sol:313-339`) uses the receipt's `batchIdHint` (Counter A) **only** to reconstruct `receiptDigest(...)` and `ecrecover` it against `enclaveSigner` — i.e. purely to authenticate the receipt. It does not use `batchIdHint` for any root lookup.
- `answerChallenge(orderHash, batchId, proof)` proves inclusion via `inclusionLeaf(batchId, orderHash)` with `batchId` = **Counter B** (the window that actually settled the order), and the contract **explicitly allows** the settling batch to be *later* than the receipt's hint (`DarkPerpSettlement.sol:346-348`: "resting orders settle in a later batch than the one their receipt was issued in").

Consequences: (1) signing `window_id` would add **zero** on-chain accountability — the answer never consults it — while **forcing** a Solidity change (`receiptDigest`/`challengeInclusion` to hash 5 words + re-locking `CrossLayer.t.sol`); (2) worse, a signed `window_id` would imply a "settle-in-window-N" **guarantee the protocol intentionally does not make**. So `window_id` is an unsigned lower-bound **hint** (the open window at sequencing time; the order settles in that window or a later one). This keeps 3b-4 truly off-chain: perp-core/sequencer/gateway only, **no contract change**, `signing_digest` unchanged.

## 4. Architecture

### 4.1 Signed `window_id` on the receipt (perp-core + sequencer + gateway)

- **`perp-core Receipt`** (`order.rs:99-104`): add `pub window_id: u64` — an **unsigned** plaintext field.
- **`signing_digest`** (`order.rs:108-118`): **unchanged** (4 words). `window_id` is deliberately NOT in the hashed pre-image (see §3.5).
- **`issue_receipt`** (`lib.rs:422-459`): populate `window_id: self.state.next_batch_id` (Counter B) alongside the existing `batch_id_hint: self.next_batch_id` (Counter A). `InclusionRecord.issued_batch`/`seen_in_batch` stay Counter A (censorship tracking is per-tick — untouched).
- **`SignedReceipt`** (`lib.rs:98-105`) and **`WReceipt`** (`main.rs:400-405`, JSON field `windowId`): carry `window_id` through. Every site that constructs a `WReceipt` — the WS/state path plus the gateway order-accept re-emit paths (`main.rs:1772-1803`, `:2406-2442`) — must source `window_id` from the same signed receipt (never fabricate it). `batch_id_hint` is preserved everywhere it exists today.

### 4.2 The A→B map (sequencer, finality-pruned)

- **Field** on `Sequencer`: `tick_window: BTreeMap<u64, u64>` (Counter-A tick id → Counter-B window id).
- **Populate** in `seal_batch`, where both the tick's local `batch_id` (Counter A, `lib.rs:629`) and `self.state.next_batch_id` (Counter B) are in scope, before the Counter-A bump (`lib.rs:838-839`): `self.tick_window.insert(batch_id, self.state.next_batch_id);`. Exact and per-tick; no range inference.
- **Prune** with the existing Counter-A finality lifecycle: `mark_settled` (`lib.rs:958-978`, which already ranges `..=batch_id` over `batch_orders`/`snapshots`) and `mark_failed` (`lib.rs:986-1017`) also drop the corresponding `tick_window` entries. Bounded (consistent with the recent per-account order-history bounding fix, `c01d9ab`).
- **Rollback**: `rollback_window` restores Counter B to M (`lib.rs:933-935`), so the failed window's ticks (whose `tick_window` entries already point to M) and any re-sealed ticks all still map to M — the map stays correct with no rollback-specific handling.
- **Persistence**: `tick_window` **IS serialized as part of the `Gw` postcard boot snapshot** — `Gw` derives Serialize/Deserialize (`main.rs:615`), its `seq: Sequencer` field (`:617`) is not serde-skipped, and `snapshot_plain` (`:1112`) serializes the whole `Gw`. Under positional (non-self-describing) postcard, `#[serde(default)]` gives no tolerance for a snapshot that lacks the field, so adding `tick_window` is a snapshot wire-format change: old snapshots fail to decode (fail-closed on boot). This is the same kind of change as Slice 3b-1's `window_ops`/`window_ordered`/`window_rejected` additions and is covered by the live migration's already-required snapshot reset. The map is finality-pruned (with `batch_orders` in `mark_settled`/`mark_failed`), so it stays bounded.

### 4.3 Surfacing (gateway)

- **Accessor** on `Sequencer`: `current_window_id(&self) -> u64 { self.state.next_batch_id }` (mirrors `current_batch_id()`), plus `window_for_tick(&self, tick_batch: u64) -> Option<u64> { self.tick_window.get(&tick_batch).copied() }`.
- **`WBatch.window_id`** (`main.rs:417-426`, `:2919-2949`): add `window_id: Option<u64>`; at snapshot build, set it from `seq.window_for_tick(batch_id_hint)` for each per-tick `WBatch` (JSON `windowId`, `null` if pruned/unknown). Per-tick grouping (Counter A, ~700ms live UX) is unchanged; each batch is now annotated with the window it rolls into.
- **`/v1/system/status`** (`v1_status_json`, `main.rs:1931-1938`): keep `nextBatchId` (Counter A) and add `"openWindowId": self.seq.current_window_id()` (Counter B). `openWindowId` is directly comparable to the existing `l1.batchCount` — a user reads "my order's window is 5, batchCount is 4 → not settled yet."
- **`GET /v1/batch/{id}`** (new route in the `main.rs:4218-4268` block): given a Counter-A tick id, return `{ "counterA": id, "windowId": M | null, "settled": bool }`, where `windowId = seq.window_for_tick(id)`, and `settled = windowId.map_or(false, |m| m < l1_batch_count)` (window M has settled on-chain once `batchCount > M`). `null` window → `settled:false` (pruned/unknown/future). Read-only, no auth.

### 4.4 Reconciliation, end to end

A user with a receipt reads its signed `window_id = M` and checks the on-chain `batchCount`: `M < batchCount` ⇒ settled (and `inclusion_leaf(M, order_hash)` is the challenge leaf, matching `build_challenge_answer`); `M == batchCount` ⇒ open/pending; the same holds for a `WBatch` via its `windowId` annotation or the `GET /v1/batch/{id}` endpoint for a bare Counter-A id.

## 5. What stays Counter A / out of scope

- **Internal per-tick machinery untouched**: `snapshots`, `mark_settled`/`mark_failed` soft-finality, `InclusionRecord`/`inclusion_violations` censorship tracking, liquidation/ADL tags, `SealedBatch.batch_id`, the per-tick `Sequencer::batch_orders`. All correct as per-tick Counter A.
- **Note-archive** (`main.rs:3068`, keyed `(batch_id=current_batch_id(), commitment)`, `note-archive/src/lib.rs:152`) — **out of scope**. Internal ciphertext storage retrieved by commitment; not part of the receipt/inclusion reconciliation.
- **No contract change**; on-chain challenge/leaf keying (Counter B) is already correct.

## 6. Testing

- **`window_id` == open window at issue** (sequencer unit): after sequencing across a window, every issued receipt's `window_id == state.next_batch_id` at issue time; after `seal_window`, new receipts carry the incremented window id.
- **`signing_digest` ignores `window_id`** (perp-core unit): two receipts identical but for `window_id` produce the **same** signing digest (window_id is unsigned; the digest stays byte-identical to the pre-slice 4-word digest, so the locked cross-layer vectors are unchanged).
- **`tick_window` exactness** (sequencer unit): N ticks in window M ⇒ every Counter-A id → M; after `seal_window` (M→M+1), subsequent ticks → M+1.
- **Rollback keeps the map correct** (sequencer unit): a failed window's ticks still map to M after re-seal.
- **Prune bounds the map** (sequencer unit): `mark_settled`/`mark_failed` drop the settled Counter-A entries; the map does not grow without bound.
- **Surfacing** (gateway): `WBatch.window_id` annotation from `window_for_tick`; `GET /v1/batch/{id}` returns the right `windowId`/`settled`; `openWindowId` present in status JSON. `batch_id_hint` and per-tick grouping unchanged (regression).
- Full `cargo test --workspace` + `cargo clippy --workspace` green.

## 7. Non-goals

- No collapse of user-facing batches to per-window (that was Approach A — rejected in favor of preserving the per-tick view).
- No separate persistence mechanism for the A→B map (it rides along in the existing `Gw` boot snapshot — see §4.2 Persistence; receipts self-describe their `window_id` in any case).
- No note-archive re-keying; no contract change; no change to the internal Counter-A finality/censorship machinery.

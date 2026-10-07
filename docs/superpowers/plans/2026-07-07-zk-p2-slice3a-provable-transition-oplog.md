# ZK Verifier P2 — Slice 3a: Provable Transition (Sequencer Op-Log) Implementation Plan


**Goal:** `seal_batch` emits and retains, per batch, the ordered `Vec<BatchOp>` it applied (fills + funding + liquidation), so `derive_roots(pre_state, ops, manifest)` reproduces the sealed `new_state_root` — the faithful witness Slice 3b will seal and POST to the prover-service.

**Architecture:** Collect-while-applying (parity-verified MECHANICAL): `run_maintenance` pushes the `AccrueFunding`/`Liquidate` ops it already executes; `seal_batch` accumulates `[applied fills] ++ [maintenance ops]` and stores the `(pre_state, ops, manifest)` triple keyed by batch_id (pre_state = the existing per-batch snapshot), pruned with the existing snapshots. Everything is in `crates/sequencer/src/lib.rs`; no perp-core/guest/gateway/contract change.

**Tech Stack:** Rust (std), `perp-core` (`BatchOp`, `apply_batch`, `commitment::derive_roots`), `serde`.

**Spec:** `docs/superpowers/specs/2026-07-07-zk-p2-slice3a-provable-transition-oplog-design.md`

## Global Constraints

- **Collect while applying — no second code path.** Funding/liquidation keep executing exactly as today (`state.apply_op(AccrueFunding)`, `state.liquidate(...)` which still returns `Vec<AdlHaircut>` for the ADL receipts); the emitted op is ALSO pushed. Push an op ONLY when its application succeeded (a failed/ skipped op must not enter the log).
- **Log order == application order.** Fills first (in fill-loop order), then per-market `AccrueFunding` then that market's `Liquidate`s (the existing `MarketId` BTreeMap iteration order in `run_maintenance`).
- **pre_state = the existing snapshot.** `snapshots[batch_id].0` (taken at `seal_batch` start, `lib.rs:553-554`) is the witness pre-state; its root already equals `manifest.previous_state_root`, so `derive_roots` (which asserts `manifest.previous_state_root == state.state_root()`, `commitment.rs:56-58`) accepts it. Do NOT change snapshot timing, `manifest.previous_state_root`, or rollback semantics.
- **`seal_batch` MUST advance `state.next_batch_id` once (latent-bug fix, Task 2).** `state.next_batch_id` is bound in `state_root` (`state.rs:216`) and `apply_batch` (what the guest / `derive_roots` runs) bumps it once per batch (`engine.rs:156`). But `seal_batch` applies ops via `apply_op` (which does NOT bump it) and today never advances `state.next_batch_id` — only the separate *sequencer* `next_batch_id` field climbs. So `state.next_batch_id` is stuck at 0 while `manifest.batch_id` climbs: for batch ≥1 `derive_roots` fails its `manifest.batch_id == state.next_batch_id` precondition AND the live sealed root diverges from the guest's derived root (the mock verifier hid this; real proofs would break). Task 2 adds `self.state.next_batch_id += 1;` in `seal_batch` immediately before `let new_state_root = self.state.state_root();` (`lib.rs:746`), mirroring `apply_batch`'s final bump — so the pre-state snapshot's `next_batch_id == batch_id == manifest.batch_id` and the live root == the derived root. The merge gate then asserts FULL `new_state_root` equality with no counter workaround.
- **Retention lifetime == snapshot lifetime.** The new `batch_ops` map is pruned in the SAME places, on the SAME key ranges, as `snapshots` (`mark_settled` split_off, `mark_failed` per-dropped remove) — never unbounded.
- **Out of scope (do NOT touch):** deposits are not logged (they live in pre_state — Slice 3b folds them into the window witness); no gateway/network/contract change; matcher `cancel_owner_orders` stays off the op-log; matching-fairness stays Proof-v2.
- `BatchOp` derives `Clone, Debug` (`engine.rs:27`). The `Sequencer` struct derives `serde::Serialize/Deserialize` — any new field MUST carry `#[serde(default)]` so existing persisted sequencers still deserialize.
- Model policy: NO Haiku; Fable exhausted → Opus/Sonnet (this is delicate engine-adjacent logic + intricate tests → Opus).

## File Structure

- `crates/sequencer/src/lib.rs` **(modify)** — the only file. `MaintenanceOutcome.ops`; `run_maintenance` op-emission; `SealedBatch.ops`; `Sequencer.batch_ops` + `batch_witness`; `seal_batch` accumulation + insert; prune in `mark_settled`/`mark_failed`; tests.

---

### Task 1: `run_maintenance` emits its `AccrueFunding`/`Liquidate` ops

**Files:**
- Modify: `crates/sequencer/src/lib.rs` — `MaintenanceOutcome` (`:180-183`), `run_maintenance` (`:488-540`)
- Test: inline `#[cfg(test)] mod tests` in the same file

**Interfaces:**
- Consumes: `perp_core::engine::BatchOp` (`AccrueFunding{market_id,mark,oracle,now_ms}`, `Liquidate{owner,market_id,oracle,now_ms}` — exact fields per `engine.rs:57-77`); `state.apply_op`, `state.liquidate`.
- Produces: `MaintenanceOutcome { liquidated, adl, ops: Vec<BatchOp> }`.

- [ ] **Step 1: Write the failing test** — add to `#[cfg(test)] mod tests`. Build a state with ONE open, underwater position (adapt the setup from the existing liquidation test — grep `is_liquidatable` / `liquidate` / `run_maintenance` in the test module for the account/fund/oracle helper calls), then prove the emitted ops reproduce the maintenance transition:

```rust
    #[test]
    fn run_maintenance_ops_replay_reproduces_state() {
        // ---- setup: a sequencer whose state holds an OPEN position that is
        // underwater at the current oracle (reuse the existing liquidation-test
        // setup helpers: deposit + FundPosition via `apply`, open a position, then
        // `set_oracle` to a price that makes it liquidatable). `now_ms` fixed.
        let mut seq = /* built per existing liquidation test */;
        let now_ms = 10_000;
        // snapshot the pre-maintenance state so we can replay the emitted ops onto it
        let pre = seq.state.clone();

        // ---- act
        let outcome = seq.run_maintenance(now_ms);

        // ---- the ops must cover funding AND liquidation (else the gate proves nothing)
        assert!(
            outcome.ops.iter().any(|o| matches!(o, BatchOp::AccrueFunding { .. })),
            "maintenance must emit AccrueFunding"
        );
        assert!(
            outcome.ops.iter().any(|o| matches!(o, BatchOp::Liquidate { .. })),
            "the scenario must actually liquidate a position"
        );

        // ---- faithfulness: replaying the emitted ops onto the pre-state reproduces
        // exactly what run_maintenance did to the live state.
        let mut replay = pre;
        replay.apply_batch(&outcome.ops).expect("replay applies");
        assert_eq!(
            replay.state_root(),
            seq.state.state_root(),
            "emitted maintenance ops must reproduce the maintenance state transition"
        );
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p sequencer run_maintenance_ops_replay`
Expected: FAIL to compile — `MaintenanceOutcome` has no `ops` field.

- [ ] **Step 3: Add the `ops` field** to `MaintenanceOutcome` (`crates/sequencer/src/lib.rs:180-183`):

```rust
pub struct MaintenanceOutcome {
    pub liquidated: Vec<(PubKey, MarketId)>,
    pub adl: Vec<(PubKey, MarketId, i128)>,
    /// The AccrueFunding + Liquidate ops applied this pass, in application order —
    /// the maintenance half of the batch's replayable op-log (Slice 3a).
    pub ops: Vec<BatchOp>,
}
```

- [ ] **Step 4: Emit the ops in `run_maintenance`.** In `run_maintenance` (`crates/sequencer/src/lib.rs:488`), declare the accumulator, push each op on successful application, and return it. Replace the funding-apply line and the liquidation loop:

```rust
    pub fn run_maintenance(&mut self, now_ms: u64) -> MaintenanceOutcome {
        self.matcher.reap_expired(now_ms);
        let mut liquidated = Vec::new();
        let mut adl: Vec<(PubKey, MarketId, i128)> = Vec::new();
        let mut ops: Vec<BatchOp> = Vec::new();
        let market_ids: Vec<MarketId> = self.state.markets.keys().copied().collect();
        for mid in market_ids {
            let Some(oracle) = self.oracles.get(&mid).copied() else {
                continue;
            };
            let mark = self.mark_price(mid).unwrap_or(oracle.price);
            let funding_op = BatchOp::AccrueFunding { market_id: mid, mark, oracle, now_ms };
            if self.state.apply_op(&funding_op).is_ok() {
                ops.push(funding_op);
            }
            let Some(market) = self.state.markets.get(&mid).copied() else {
                continue;
            };
            let Ok(price) = oracle.validate(&market, now_ms) else {
                continue;
            };
            let funding_index = self
                .state
                .funding
                .get(&mid)
                .map(|f| f.cumulative_index)
                .unwrap_or(0);
            let candidates: Vec<PubKey> = self
                .state
                .positions
                .iter()
                .filter(|((_, m), p)| {
                    *m == mid && p.is_open() && p.is_liquidatable(&market, price, funding_index)
                })
                .map(|((o, _), _)| *o)
                .collect();
            for owner in candidates {
                if let Ok(haircuts) = self.state.liquidate(&owner, mid, &oracle, now_ms) {
                    liquidated.push((owner, mid));
                    ops.push(BatchOp::Liquidate { owner, market_id: mid, oracle, now_ms });
                    for h in haircuts {
                        adl.push((h.owner, mid, h.clawed));
                    }
                }
            }
        }
        MaintenanceOutcome { liquidated, adl, ops }
    }
```

- [ ] **Step 5: Run to verify it passes**

Run: `cargo test -p sequencer run_maintenance_ops_replay`
Expected: PASS.

- [ ] **Step 6: Fix any other `MaintenanceOutcome` construction/destructuring.** `seal_batch` destructures `MaintenanceOutcome { liquidated, adl: adl_haircuts }` (`lib.rs:669-672`) — add `ops: _` there FOR NOW so the crate compiles (Task 2 consumes it):

```rust
        let MaintenanceOutcome {
            liquidated,
            adl: adl_haircuts,
            ops: _,
        } = self.run_maintenance(now_ms);
```

Run: `cargo test -p sequencer` — Expected: whole sequencer suite PASS (grep for any other `MaintenanceOutcome { ` literal and add `ops` if a test builds one).

- [ ] **Step 7: Commit**

```bash
git add crates/sequencer/src/lib.rs
git commit -m "feat(sequencer): run_maintenance emits its AccrueFunding/Liquidate ops (op-log half)"
```

---

### Task 2: `seal_batch` op-log + `SealedBatch.ops` + `batch_ops` retention + merge gate

**Files:**
- Modify: `crates/sequencer/src/lib.rs` — `SealedBatch` (`:140`), `Sequencer` struct (`:255`) + `new` (`:284`), `seal_batch` (`:547`, fill loop `:637`, maintenance `:669`, SealedBatch build `:775`), `mark_settled` (`:797`), `mark_failed` (`:826`)
- Test: inline `#[cfg(test)] mod tests`

**Interfaces:**
- Consumes: Task 1's `MaintenanceOutcome.ops`; the existing `snapshots` map; `perp_core::commitment::derive_roots(&mut DefaultState, &[BatchOp], &BatchManifest) -> Result<DerivedRoots, EngineError>` (`commitment.rs:48`; `DerivedRoots { prev_state_root, manifest_hash, new_state_root, ordered_root, withdrawals_root, rejected_root }`).
- Produces: `SealedBatch.ops: Vec<BatchOp>`; `Sequencer::batch_witness(batch_id) -> Option<(DefaultState, Vec<BatchOp>, BatchManifest)>`.

- [ ] **Step 1: Write the failing merge-gate test.** Seal a batch that contains a **fill AND a funding accrual AND a liquidation**, then prove the retained witness reproduces the sealed roots via `derive_roots`. Build the scenario from the existing seal_batch/liquidation test helpers: fund accounts, open a to-be-liquidated position in an earlier batch, move the oracle so it's underwater, then seal a batch whose fresh orders produce a settled fill while maintenance liquidates the underwater position.

**Fallback if the single-batch fill+funding+liquidation scenario proves impractical to construct:** the faithfulness property — not the literal co-occurrence — is what matters. Task 1's `run_maintenance_ops_replay_reproduces_state` already proves the funding+liquidation half is faithful; so a Task-2 `batch_witness_replays_to_sealed_roots` that exercises a **fill + funding** through `seal_batch` (plus the fills-only round-trip below) is acceptable coverage. Report which form you used and why. Do NOT weaken the assertions (`derive_roots(...).new_state_root == sealed.new_state_root`).

```rust
    #[test]
    fn batch_witness_replays_to_sealed_roots_with_fill_funding_liquidation() {
        // ---- setup (adapt from the existing liquidation seal_batch test):
        //   * two funded accounts whose fresh orders MATCH this batch (the fill)
        //   * a third account holding an OPEN position made underwater by an oracle
        //     move (set_oracle) before this batch, so maintenance liquidates it
        let mut seq = /* built per existing seal_batch liquidation test */;
        let now_ms = 20_000;
        let orders = /* two matching orders that settle a fill this batch */;

        // ---- act
        let sealed = seq.seal_batch(&orders, now_ms);

        // ---- the retained witness
        let (pre_state, ops, manifest) =
            seq.batch_witness(sealed.batch_id).expect("witness retained for a pending batch");

        // the op-log must cover all three op kinds (else the gate is hollow)
        assert!(ops.iter().any(|o| matches!(o, BatchOp::Fill { .. })), "batch had a fill");
        assert!(ops.iter().any(|o| matches!(o, BatchOp::AccrueFunding { .. })), "funding accrued");
        assert!(ops.iter().any(|o| matches!(o, BatchOp::Liquidate { .. })), "a position liquidated");

        // ---- faithfulness: derive_roots over (pre_state, ops, manifest) reproduces
        // exactly what the sealer computed.
        let derived = perp_core::commitment::derive_roots(&mut pre_state.clone(), &ops, &manifest)
            .expect("derive_roots accepts the retained witness");
        assert_eq!(derived.new_state_root, sealed.new_state_root, "op-log must reproduce new_state_root");
        assert_eq!(derived.manifest_hash, sealed.manifest_hash, "manifest hash must match");
        assert_eq!(derived.prev_state_root, sealed.prev_state_root, "pre_state is the batch's prev_state");
    }

    #[test]
    fn batch_witness_round_trips_fills_only() {
        // a batch with matching orders but NO maintenance liquidation still round-trips
        let mut seq = /* funded accounts, matching orders, oracle set, no underwater position */;
        let sealed = seq.seal_batch(&orders, 21_000);
        let (pre_state, ops, manifest) = seq.batch_witness(sealed.batch_id).unwrap();
        let derived = perp_core::commitment::derive_roots(&mut pre_state.clone(), &ops, &manifest).unwrap();
        assert_eq!(derived.new_state_root, sealed.new_state_root);
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p sequencer batch_witness`
Expected: FAIL to compile — `batch_witness` and `SealedBatch.ops` don't exist.

- [ ] **Step 3: Add `SealedBatch.ops`** (`crates/sequencer/src/lib.rs:140`, after `adl_receipts`):

```rust
    /// The batch's replayable op-log: `[applied fills] ++ [maintenance AccrueFunding/
    /// Liquidate]`, in application order. Replaying it against the batch's pre-state
    /// (the retained snapshot) via `apply_batch` reproduces `new_state_root` — the
    /// witness a real ZK proof attests (Slice 3a).
    pub ops: Vec<BatchOp>,
```

- [ ] **Step 4: Add the `batch_ops` map + `batch_witness`.** Add the field to `Sequencer` (`:255`, near `snapshots`) with `#[serde(default)]`, initialize it in `new` (`:284`), and add the accessor:

```rust
    /// Per-pending-batch (ops, manifest), retained alongside `snapshots[batch_id].0`
    /// (the pre-state) so `batch_witness` can hand out the replayable
    /// `(pre_state, ops, manifest)` triple. Pruned in lock-step with `snapshots`.
    #[serde(default)]
    batch_ops: BTreeMap<u64, (Vec<BatchOp>, BatchManifest)>,
```

```rust
    // in `new` (:284), alongside `snapshots: BTreeMap::new(),`
            batch_ops: BTreeMap::new(),
```

```rust
    /// The replayable witness for a still-pending batch: `(pre_state, ops, manifest)`
    /// where `derive_roots(pre_state, ops, manifest).new_state_root` == the sealed
    /// `new_state_root`. `None` once the batch is settled/failed (pruned) or unknown.
    pub fn batch_witness(&self, batch_id: u64) -> Option<(DefaultState, Vec<BatchOp>, BatchManifest)> {
        let (state, _matcher) = self.snapshots.get(&batch_id)?;
        let (ops, manifest) = self.batch_ops.get(&batch_id)?;
        Some((state.clone(), ops.clone(), manifest.clone()))
    }
```

(If `BatchManifest` is not `Clone`, add `Clone` to its derive in `crates/perp-core/src/order.rs` — it is already `serde`-serializable since it is part of the postcard witness; confirm and only extend the derive if needed.)

- [ ] **Step 5: Accumulate the op-log in `seal_batch`.** (a) Before the fill loop (`:601`, near `let mut settled_order_hashes`), add `let mut ops: Vec<BatchOp> = Vec::new();`. (b) In the fill loop's success arm (`:649`, the `Ok(_) =>` branch), push the fill after the finality inserts — `op` is free to move there:

```rust
                Ok(_) => {
                    for oh in [m.taker_order_hash, m.maker_order_hash] {
                        self.finality.insert(oh, Finality::Matched);
                        if !settled_order_hashes.contains(&oh) {
                            settled_order_hashes.push(oh);
                        }
                    }
                    ops.push(op);
                }
```

(c) Change the maintenance destructure (from Task 1's `ops: _`) to capture and append:

```rust
        let MaintenanceOutcome {
            liquidated,
            adl: adl_haircuts,
            ops: maintenance_ops,
        } = self.run_maintenance(now_ms);
        ops.extend(maintenance_ops);
```

(c2) **Advance `state.next_batch_id` once** (the latent-bug fix — see Global Constraints). `apply_batch` bumps this counter once per batch and it is bound in `state_root`; `seal_batch`'s `apply_op`-based application does not, so without this the live sealed root diverges from the guest's derived root and batch ≥1 fails `derive_roots`'s `manifest.batch_id == state.next_batch_id` precondition. Add, **immediately before** `let new_state_root = self.state.state_root();` (`lib.rs:746`):

```rust
        // Mirror apply_batch's single per-batch counter bump (engine.rs:156): the guest
        // proves via apply_batch, which advances state.next_batch_id once; seal_batch
        // applies ops via apply_op (no bump), so advance it here or the live sealed root
        // diverges from derive_roots and batch>=1 fails manifest.batch_id==next_batch_id.
        self.state.next_batch_id += 1;
        let new_state_root = self.state.state_root();
```

(The existing `self.next_batch_id += 1;` at `lib.rs:774` advances the separate *sequencer* field and stays.) Update any existing test that asserts a sealed `new_state_root` or round-trips a `Sequencer` expecting `state.next_batch_id == 0` — the counter now advances per batch.

(d) Retain the triple + add `ops` to the returned `SealedBatch`. Just before the `SealedBatch { ... }` literal (`:775`), insert the retention (clone `manifest`/`ops` since both are moved/used after), and add `ops` to the struct:

```rust
        self.batch_ops
            .insert(batch_id, (ops.clone(), manifest.clone()));

        SealedBatch {
            batch_id,
            prev_state_root,
            new_state_root,
            manifest,
            manifest_hash,
            settled_order_hashes,
            settlement_rejected,
            receipts,
            liquidation_tags,
            adl_receipts,
            ops,
        }
```

- [ ] **Step 6: Prune `batch_ops` with `snapshots`.** In `mark_settled` (`:797`), after the `batch_orders` split_off (`:816`):

```rust
        self.batch_ops = self.batch_ops.split_off(&(batch_id + 1));
```

In `mark_failed` (`:826`), inside the `for b in &dropped` loop where it does `self.snapshots.remove(b);`:

```rust
            self.batch_ops.remove(b);
```

- [ ] **Step 7: Run the merge-gate tests**

Run: `cargo test -p sequencer batch_witness`
Expected: PASS — both `batch_witness_replays_to_sealed_roots_with_fill_funding_liquidation` and `batch_witness_round_trips_fills_only`.

- [ ] **Step 8: Full suite + clippy**

Run: `cargo test --workspace && cargo clippy --workspace --all-targets`
Expected: green (the new field is additive + `#[serde(default)]`; fix any test that builds a `SealedBatch` literal to add `ops`).

- [ ] **Step 9: Commit**

```bash
git add crates/sequencer/src/lib.rs
git commit -m "feat(sequencer): seal_batch retains the replayable op-log witness (batch_witness); merge gate"
```

---

## Final verification (after both tasks)

- [ ] `cargo test -p sequencer` — the merge gate (`batch_witness_replays_to_sealed_roots_with_fill_funding_liquidation`) + `run_maintenance_ops_replay_reproduces_state` + fills-only round-trip all green. This is the slice's whole point: a batch with a fill, funding, and a liquidation replays through `derive_roots` to the sealed `new_state_root`.
- [ ] `cargo test --workspace && cargo clippy --workspace --all-targets` — green; `batch_ops` retention is pruned in both `mark_settled` and `mark_failed` (no unbounded growth), and the new fields are additive/`#[serde(default)]`.
- [ ] `git diff --stat` — only `crates/sequencer/src/lib.rs` changed. No perp-core/guest/gateway/contract change.

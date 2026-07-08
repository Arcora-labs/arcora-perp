# ZK P2 Slice 3b-3 — Per-Window Rollback + Content-Derived Nonce — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A prove/settle failure in the new (PROVER_URL) settle path rolls the sealed window back so the next settle re-seals it under the same batch_id (no wedge, no lost op), and the seal nonce is content-derived so the re-seal can't reuse a keystream.

**Architecture:** Add `Sequencer::rollback_window(&witness)` that restores the per-window counter, re-injects the failed window's ops/orders ahead of anything the tick loop added since, and restores the window baseline. `WindowWitness` gains `Clone` so the gateway keeps a rollback copy across the lock-free settle; the gateway's Section C failure arms call it (plus `Gw::rollback_window_withdrawals`). `seal_witness`'s nonce becomes `keccak256(plaintext)`.

**Tech Stack:** Rust (crates `sequencer`, `gateway`, reading `perp-core`), `postcard`, `sha3::Keccak256`, tokio async.

## Global Constraints

- **`WindowWitness` gains `#[derive(Clone)]`** — all four fields (`u64`, `DefaultState`, `Vec<BatchOp>`, `BatchManifest`, incl. nested `RejectReason`) are already `Clone`, so this needs **NO perp-core change**.
- **`rollback_window(&mut self, w: &WindowWitness)`** performs exactly: `self.state.next_batch_id = w.batch_id`; **prepend** `w.ops` to `window_ops`, `w.manifest.ordered` to `window_ordered`, `w.manifest.rejected` to `window_rejected` (the failed window's entries go BEFORE anything accumulated since); `self.window_start_state = w.pre_state.clone()`. It touches nothing else (Counter A / snapshots / finality / inclusion stay as-is).
- **Nonce = `keccak256(plaintext)`** via `sha3::Keccak256` (aliased `RawKeccak` to avoid the `perp_core::Keccak256` name clash); `plaintext` = `postcard(&(&pre_state, &ops, &manifest))`. The `w.batch_id` is no longer read for the nonce.
- **Rollback on ANY Section C failure** — BOTH the `Ok(Err(e))` (prove/settle error) and `Err(e)` (join) arms roll back. No proof-preserving retry.
- **Per-tick soft-finality untouched** — `mark_settled`/`mark_failed`/`snapshots`/`Sequencer::next_batch_id` unchanged.
- **Sequencer + gateway only. NO perp-core or contract change.**
- Run tests single-filter: sequencer `cargo test -p sequencer <name>`, gateway `cargo test -p gateway <name>`.

---

## Reference: exact current shapes (verbatim)

**`WindowWitness`** (`crates/sequencer/src/lib.rs:176-181`, NO derive today):
```rust
pub struct WindowWitness {
    pub batch_id: u64,
    pub pre_state: DefaultState,
    pub ops: Vec<BatchOp>,
    pub manifest: BatchManifest,
}
```
`seal_window` (`lib.rs:894-922`) bumps `self.state.next_batch_id` once, drains `window_ops` via `mem::take`, clears `window_ordered`/`window_rejected`, re-captures `window_start_state = self.state.clone()`. The window fields (`window_ops`, `window_ordered: Vec<Digest>`, `window_rejected: Vec<(Digest, RejectReason)>`, `window_start_state: DefaultState`) are PRIVATE. `seq.state` is `pub`; `state.next_batch_id` (pub field) and `state.state_root()` (pub method) are observable. `seal_batch` appends to the three window accumulators (`lib.rs:870-872`) and does NOT touch `state.next_batch_id`.

**Sequencer test helpers** (`crates/sequencer/tests/spine.rs`): `setup() -> Sequencer` (new + add_market(0) + set_oracle + fund traders 1,2), `order(owner, Side, size, price, nonce)`, `oracle(px, now)`, `owner_id(u64)`, constants `SIZE_SCALE`/`PRICE_SCALE`/`QUOTE_SCALE`. `seal_batch(&[Order], now_ms) -> SealedBatch`, `apply(&BatchOp) -> Result<(),_>`, `seal_window() -> WindowWitness`. `derive_roots(&mut DefaultState, &[BatchOp], &BatchManifest) -> Result<DerivedRoots,_>` (call as `derive_roots(&mut w.pre_state.clone(), &w.ops, &w.manifest)`).

**`seal_witness`** (`crates/gateway/src/prover_client.rs:124-148`) — nonce lines 135-136:
```rust
    let mut nonce = [0u8; 32];
    nonce[24..].copy_from_slice(&w.batch_id.to_be_bytes());
```
`bytes` = `postcard::to_allocvec(&(&w.pre_state, &w.ops, &w.manifest))` (line 133-134). The module imports `perp_core::{Digest, EngineError, Keccak256}` (so `sha3` must be brought in aliased). Raw-keccak idiom used elsewhere in the crate: `use sha3::{Digest as _, Keccak256 as RawKeccak}; let h: [u8;32] = RawKeccak::digest(&bytes).into();` (e.g. `main.rs:3187-3194`, `enclave_epoch.rs:213`).

**Section C** (`crates/gateway/src/main.rs`): `witness`/`ww` owned at `4713` (`let Some(((witness, ww), prune_candidates)) = begun else { continue };`), `batch_id` at `4718`, the `move` `spawn_blocking` at `4722`. Failure arms:
```rust
4760                        Ok(Err(e)) => eprintln!("[l1] window settle failed: {e}"),
4761                        Err(e) => eprintln!("[l1] window settle join: {e}"),
```
`Gw.window_withdrawals: Vec<Withdrawal>` (private, `main.rs:632-633`); `Withdrawal` derives `Clone` (`withdrawals.rs:29`). The `seal_witness` test `seal_witness_is_well_formed_and_addressed` is at `main.rs:6596-6624` (nonce assertion 6617-6620).

---

## Task 1: `Sequencer::rollback_window` + `WindowWitness: Clone`

**Files:**
- Modify: `crates/sequencer/src/lib.rs` (WindowWitness derive + `rollback_window`), `crates/sequencer/tests/spine.rs` (round-trip test).

**Interfaces:**
- Consumes: `WindowWitness`, `state.next_batch_id`, `window_ops`/`window_ordered`/`window_rejected`/`window_start_state`.
- Produces: `#[derive(Clone)]` on `WindowWitness`; `Sequencer::rollback_window(&mut self, w: &WindowWitness)`.

- [ ] **Step 1: Add `#[derive(Clone)]` to `WindowWitness`**

In `crates/sequencer/src/lib.rs`, immediately above `pub struct WindowWitness {` (line 176), add the derive:
```rust
#[derive(Clone)]
pub struct WindowWitness {
```

- [ ] **Step 2: Write the failing test** (append to `crates/sequencer/tests/spine.rs`)

```rust
#[test]
fn rollback_window_restores_and_reseals_to_live_root() {
    let mut seq = setup();

    // window 1: tick 1 has a matched fill, then the window is sealed (a settle attempt).
    seq.set_oracle(0, oracle(100_000, 20_000));
    let orders = [
        order(1, Side::Sell, SIZE_SCALE, 100_000 * PRICE_SCALE, 1),
        order(2, Side::Buy, SIZE_SCALE, 100_000 * PRICE_SCALE, 2),
    ];
    let _ = seq.seal_batch(&orders, 20_000);
    let w = seq.seal_window();
    let sealed_id = w.batch_id;
    assert_eq!(seq.state.next_batch_id, sealed_id + 1, "seal_window bumped Counter B");

    // the settle "fails" — meanwhile the 700ms tick loop keeps adding ops to the new window.
    seq.apply(&BatchOp::Deposit {
        owner: owner_id(5),
        asset_id: 0,
        amount: 500_000,
        blinding: [7u8; 32],
    })
    .unwrap();
    let _ = seq.seal_batch(&[], 20_700);

    // roll the failed window back.
    seq.rollback_window(&w);
    assert_eq!(seq.state.next_batch_id, sealed_id, "Counter B restored to the pre-seal id");

    // re-seal: same on-chain batch_id, and the witness replays [failed ++ intervening] from
    // the restored baseline to the LIVE window-end root (falsifiable: a dropped/mis-ordered
    // op diverges the root).
    let w2 = seq.seal_window();
    assert_eq!(w2.batch_id, sealed_id, "re-seal uses the same batch_id (== on-chain batchCount)");
    let live_root = seq.state.state_root();
    let derived = perp_core::commitment::derive_roots(&mut w2.pre_state.clone(), &w2.ops, &w2.manifest)
        .expect("derive_roots accepts the rolled-back re-seal");
    assert_eq!(derived.new_state_root, live_root, "rolled-back re-seal reproduces the live root");
    assert!(
        w2.ops.iter().any(|o| matches!(o, BatchOp::Fill { .. })),
        "the failed window's fill is re-included"
    );
    assert!(
        w2.ops.iter().any(|o| matches!(o, BatchOp::Deposit { .. })),
        "the intervening deposit is included, after the failed window's ops"
    );
}
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `cargo test -p sequencer rollback_window_restores_and_reseals_to_live_root`
Expected: FAIL to compile (`rollback_window` method absent) until Step 4.

- [ ] **Step 4: Implement `rollback_window`** (in the `impl Sequencer` block, near `seal_window`)

```rust
    /// Undo an optimistic `seal_window` whose off-chain settle failed: restore the
    /// per-window counter and re-inject the failed window's ops/orders AHEAD of anything the
    /// 700ms tick loop appended since the seal, and restore the window baseline. The next
    /// `seal_window` then re-seals `[failed ops ++ intervening ops]` from the old baseline
    /// under the SAME batch_id (== the unchanged on-chain batchCount) — no op is lost and the
    /// desync guard is satisfied. Leaves the per-tick soft-finality (Counter A / snapshots /
    /// finality / inclusion) untouched.
    pub fn rollback_window(&mut self, w: &WindowWitness) {
        // seal_window bumped Counter B once; ticks never touch it, so restore the pre-seal id.
        self.state.next_batch_id = w.batch_id;
        // prepend the failed window's ops/orders before anything accumulated since the seal.
        let mut ops = w.ops.clone();
        ops.append(&mut self.window_ops);
        self.window_ops = ops;
        let mut ordered = w.manifest.ordered.clone();
        ordered.append(&mut self.window_ordered);
        self.window_ordered = ordered;
        let mut rejected = w.manifest.rejected.clone();
        rejected.append(&mut self.window_rejected);
        self.window_rejected = rejected;
        // restore the window baseline (seal_window re-captured it to the post-bump state).
        self.window_start_state = w.pre_state.clone();
    }
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `cargo test -p sequencer rollback_window_restores_and_reseals_to_live_root` → PASS. Then the full crate to confirm no regression: `cargo test -p sequencer` (expect all pass) + `cargo clippy -p sequencer` (clean).

- [ ] **Step 6: Commit**

```bash
git add crates/sequencer/src/lib.rs crates/sequencer/tests/spine.rs
git commit -m "feat(sequencer): rollback_window (un-seal a window on settle failure) + WindowWitness Clone"
```

---

## Task 2: content-derived seal nonce

**Files:**
- Modify: `crates/gateway/src/prover_client.rs` (`seal_witness` nonce), `crates/gateway/src/main.rs` (the `seal_witness_is_well_formed_and_addressed` test's nonce assertion).

**Interfaces:**
- Consumes: `sha3::Keccak256`, the `bytes` plaintext already built in `seal_witness`.
- Produces: `seal_witness` now derives the nonce as `keccak256(plaintext)`.

- [ ] **Step 1: Update the test's nonce expectation** (in `crates/gateway/src/main.rs`, `seal_witness_is_well_formed_and_addressed`)

Replace the current nonce block (lines ~6617-6620):
```rust
        let mut expect_nonce = [0u8; 32];
        expect_nonce[24..].copy_from_slice(&witness.batch_id.to_be_bytes());
        assert_eq!(sealed.nonce(), expect_nonce);
        let plaintext =
            postcard::to_allocvec(&(&witness.pre_state, &witness.ops, &witness.manifest)).unwrap();
        assert_eq!(sealed.ciphertext_len(), plaintext.len());
```
with (compute `plaintext` first, expect the content nonce):
```rust
        let plaintext =
            postcard::to_allocvec(&(&witness.pre_state, &witness.ops, &witness.manifest)).unwrap();
        // Slice 3b-3: the nonce is keccak256 of the plaintext (content-derived), so a
        // rollback+re-seal under the same batch_id never reuses a keystream.
        use sha3::{Digest as _, Keccak256 as RawKeccak};
        let expect_nonce: [u8; 32] = RawKeccak::digest(&plaintext).into();
        assert_eq!(sealed.nonce(), expect_nonce);
        assert_eq!(sealed.ciphertext_len(), plaintext.len());
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p gateway seal_witness_is_well_formed_and_addressed`
Expected: FAIL — `sealed.nonce()` is still the batch_id nonce (`[0…,0,0,0,0,0,0,0,0]` for batch_id 0), not `keccak256(plaintext)`.

- [ ] **Step 3: Change the nonce in `seal_witness`** (`crates/gateway/src/prover_client.rs`)

Replace lines 135-136:
```rust
    let mut nonce = [0u8; 32];
    nonce[24..].copy_from_slice(&w.batch_id.to_be_bytes());
```
with:
```rust
    // nonce = keccak256(plaintext): different plaintext (any window / any rollback re-seal)
    // yields a different nonce, so a re-seal under the same batch_id can never reuse a
    // keystream; an identical retry yields the same nonce (identical ciphertext, no leak).
    use sha3::{Digest as _, Keccak256 as RawKeccak};
    let nonce: [u8; 32] = RawKeccak::digest(&bytes).into();
```
Also update the fn's doc comment line (`prover_client.rs:126-127`) that says "the nonce is derived from the window batch_id (unique per window)" to "the nonce is `keccak256` of the plaintext (content-derived; reuse-proof across rollback re-seals)".

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test -p gateway seal_witness_is_well_formed_and_addressed` → PASS. Then `cargo test -p gateway` (full) + `cargo clippy -p gateway` (clean).

- [ ] **Step 5: Commit**

```bash
git add crates/gateway/src/prover_client.rs crates/gateway/src/main.rs
git commit -m "feat(gateway): content-derived seal nonce (keccak256 of the plaintext), reuse-proof under rollback"
```

---

## Task 3: `Gw::rollback_window_withdrawals` + Section C rollback wiring

**Files:**
- Modify: `crates/gateway/src/main.rs` (the method + a unit test + the async-branch wiring).

**Interfaces:**
- Consumes: `Sequencer::rollback_window` (Task 1), `WindowWitness: Clone` (Task 1), `Gw.window_withdrawals`, `Withdrawal`.
- Produces: `Gw::rollback_window_withdrawals(&mut self, ww: Vec<Withdrawal>)`.

- [ ] **Step 1: Write the failing test** (in `crates/gateway/src/main.rs` `#[cfg(test)] mod tests`)

```rust
    #[test]
    fn rollback_window_withdrawals_prepends() {
        let mut gw = Gw::boot();
        let (key, _o) = gw.register_account(None);
        gw.account_deposit(&key, 0, 40_000 * QUOTE_SCALE).unwrap();
        // one withdrawal accumulated since the (failed) seal drained the window's set
        let after = gw.account_withdraw(&key, 0, 3_000 * QUOTE_SCALE, [8u8; 20]).unwrap();
        // the failed window's withdrawals, captured before the seal
        let failed = vec![Withdrawal { owner: [1u8; 32], to: [7u8; 20], amount: 5_000, nonce: 1 }];

        gw.rollback_window_withdrawals(failed.clone());

        // the failed window's withdrawals are re-injected AHEAD of the accumulated one
        assert_eq!(gw.window_withdrawals.len(), 2);
        assert_eq!(gw.window_withdrawals[0].nonce, failed[0].nonce);
        assert_eq!(gw.window_withdrawals[0].to, [7u8; 20]);
        assert_eq!(gw.window_withdrawals[1].nonce, after.nonce);
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p gateway rollback_window_withdrawals_prepends`
Expected: FAIL to compile (method absent).

- [ ] **Step 3: Implement `rollback_window_withdrawals`** (in an `impl Gw` block, near `prune_claimed_withdrawals`)

```rust
    /// Slice 3b-3: re-inject a failed window's drained withdrawals AHEAD of any accumulated
    /// since, mirroring `Sequencer::rollback_window`'s op prepend, so the re-seal's withdrawal
    /// set is `[failed ++ intervening]` and no withdrawal is lost on a settle failure.
    fn rollback_window_withdrawals(&mut self, mut ww: Vec<Withdrawal>) {
        ww.append(&mut self.window_withdrawals);
        self.window_withdrawals = ww;
    }
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test -p gateway rollback_window_withdrawals_prepends` → PASS.

- [ ] **Step 5: Keep a rollback copy of the witness + ww before Section C**

In `crates/gateway/src/main.rs`, right after `let batch_id = witness.batch_id;` (line ~4718) and before the `// (C) prove + settle (lock-free)` comment, add:
```rust
                    // keep rollback copies for the failure path (a per-settle DefaultState
                    // clone — far rarer than the per-tick snapshot clone, so negligible).
                    let witness_rb = witness.clone();
                    let ww_rb = ww.clone();
```

- [ ] **Step 6: Roll back on ANY Section C failure**

Replace the two failure arms (`crates/gateway/src/main.rs:4760-4761`):
```rust
                        Ok(Err(e)) => eprintln!("[l1] window settle failed: {e}"),
                        Err(e) => eprintln!("[l1] window settle join: {e}"),
```
with rollback blocks:
```rust
                        Ok(Err(e)) => {
                            eprintln!("[l1] window settle failed: {e} — rolling the window back");
                            let mut gw = app.gw.lock().await;
                            gw.seq.rollback_window(&witness_rb);
                            gw.rollback_window_withdrawals(ww_rb);
                        }
                        Err(e) => {
                            eprintln!("[l1] window settle join: {e} — rolling the window back");
                            let mut gw = app.gw.lock().await;
                            gw.seq.rollback_window(&witness_rb);
                            gw.rollback_window_withdrawals(ww_rb);
                        }
```
(This consumes `witness_rb`/`ww_rb` on the failure paths; the success arm doesn't use them, so they're simply dropped there.)

- [ ] **Step 7: Verify the branch compiles + full regression**

Run: `cargo build -p gateway` (the async branch + the clones compile) + `cargo test -p gateway` (full — the new unit test + all prior tests green) + `cargo clippy -p gateway` (clean). (The async-branch failure→rollback wiring needs a live L1, so it's glue — its correctness is that it calls the Task-1/Step-3 unit-tested `rollback_window`/`rollback_window_withdrawals` on both failure arms; live-validatable but not CI-tested.)

- [ ] **Step 8: Whole-workspace check**

Run: `cargo test` (workspace) and `cargo clippy --workspace` from the repo root. Expected: all pass, no warnings.

- [ ] **Step 9: Commit**

```bash
git add crates/gateway/src/main.rs
git commit -m "feat(gateway): roll the window back on a prove/settle failure (rollback_window_withdrawals + Section C wiring)"
```

---

## Self-Review (author checklist — completed)

**1. Spec coverage** (against `2026-07-08-zk-p2-slice3b3-window-rollback-design.md`):
- §4.1 `Sequencer::rollback_window` + `WindowWitness: Clone` → Task 1. ✅
- §4.2 gateway wiring (`rollback_window_withdrawals` + Section C failure arms + rollback copies) → Task 3. ✅
- §4.3 content-derived nonce → Task 2. ✅
- §5 testing (rollback round-trip merge gate; `rollback_window_withdrawals`; content nonce) → Task 1 spine.rs test, Task 3 unit test, Task 2 test. ✅
- §6 non-goals (no (C) re-keying; per-tick finality untouched; no retry-settle; no perp-core/contract change) → respected; only sequencer + gateway touched, WindowWitness Clone needs no perp-core change. ✅

**2. Placeholder scan:** none; every code step is complete; every test asserts real behavior. ✅

**3. Type consistency:** `rollback_window(&mut self, w: &WindowWitness)`, `WindowWitness: Clone`, `rollback_window_withdrawals(&mut self, ww: Vec<Withdrawal>)`, nonce `RawKeccak::digest(&bytes).into(): [u8;32]` — names/types consistent across tasks and with the merged shapes (`witness_rb`/`ww_rb` are `WindowWitness`/`Vec<Withdrawal>`, both `Clone`). ✅

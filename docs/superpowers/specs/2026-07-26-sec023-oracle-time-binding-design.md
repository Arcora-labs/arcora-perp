# SEC-023 — Oracle time-binding — Design

> **Sequencing: this is the FIRST of three findings** split out of the SEC-022 review.
> SEC-024 (`SeedInsurance` fabricates external collateral) is second; SEC-022 (fill-price band +
> closed-position debt) is third and depends on this one — its band is anchored to an oracle mark
> that, until this lands, a prover partly controls.

**Finding:** SEC-023 [critical, proof-soundness] — the proven transition has **no clock**. Oracle freshness is checked only against a value the prover supplies, so a prover can replay any historical signed transcript and have the circuit accept it as current.

Verified at source:

- `OracleTranscript::validate` (`crates/perp-core/src/oracle.rs:93-98`) checks freshness as `publish_time_ms > now_ms || now_ms - publish_time_ms > market.max_oracle_staleness_ms`. Both operands are prover-supplied: `publish_time_ms` comes from the (genuinely signed) transcript, and `now_ms` is a plain field of the `BatchOp` (`engine.rs:59-68`).
- **`BatchManifest` has no time field at all** (`crates/perp-core/src/order.rs:157-166`): `previous_state_root`, `batch_id`, `ordered`, `rejected`, `oracle_updates`, `matching_rule_version`, `enclave_measurement`, `sequencer_pubkey_epoch`.
- **`derive_roots` constrains neither** (`crates/perp-core/src/commitment.rs:53-90`). It binds `manifest.previous_state_root` and `manifest.batch_id` to the state, then applies the batch. Nothing relates `now_ms` to anything outside the witness.

So a prover picks a historical transcript, sets `now_ms` near its `publish_time_ms`, and the 10-second staleness gate passes. The signature check is untouched — **the prover cannot forge a price, only choose which real past price to use.** That is enough: it decides the mark that every downstream risk check is measured against.

**Blast radius: every op that carries an oracle.** `Fill`, `Liquidate`, `Unbind`, `AccrueFunding`. Concretely — liquidate a healthy position by selecting an old adverse mark; avoid liquidating an unhealthy one by selecting an old favourable mark; steer funding; and (once SEC-022 lands) widen the effective fill band, since its right-hand side is anchored to whichever mark the prover selected.

**Why this outranks SEC-022.** SEC-022's band anchors to `mark` precisely so a prover cannot widen its own band. That argument only holds if `mark` is *current*. Until then the anchor is partly attacker-chosen, and SEC-022 buys less than it appears to.

**Trust-model note.** This is a soundness bug, not a liveness one: it is exploitable by whoever produces the witness — the sequencer/prover — not by an ordinary API user. The zk layer exists specifically so that party need not be trusted, so "the sequencer wouldn't do that" is not a defence.

## Scope

- **`crates/perp-core`** (compiles into the SP1 guest):
  - `BatchManifest` gains `batch_time_ms: u64`, hashed with the rest.
  - `DerivedRoots` gains an 8th word `batch_time_ms`; `commitment()` covers it.
  - `DefaultState` gains `last_batch_time_ms: u64` and `last_oracle_publish_ms: BTreeMap<MarketId, u64>`, both bound into `state_root`.
  - `derive_roots` enforces batch monotonicity and the per-op window.
  - `validate` (or its caller) enforces per-market oracle monotonicity.
  - New `EngineError` variants for each rejection.
- **`contracts/`**: `settleBatch` takes `batchTimeMs`, binds it through `publicCommitment`, and checks it against `block.timestamp`.
- **`crates/sequencer`**: populate `batch_time_ms`; surface the new rejection reasons.

**Non-goals / deferred:**

- **Binding `manifest.oracle_updates` to the transcripts actually used.** The field is currently dead weight — hashed into the manifest, never cross-checked against `ops`. Binding it would add auditability (anyone could see which oracle prices a batch consumed), but the *security* property is delivered by oracle monotonicity below, and every additional in-circuit constraint is another way to make an unprovable batch. **Follow-up.**
- **Sub-second or per-op oracle sequencing.** Monotonicity is per market per batch; ordering *within* a batch is not constrained beyond the window.
- SEC-024 and SEC-022, each its own spec.

## Design

### 1. Where the clock comes from

The contract currently sees only `manifest_hash` — a hash, not fields — so adding `batch_time_ms` to the manifest alone would leave it unverifiable on L1.

Therefore `batch_time_ms` becomes the **8th word of the public commitment**. `settleBatch` receives it as an argument, `publicCommitment` folds it in exactly as Solidity already does for the other seven, and the proof binds it. There is no cheaper way to give the contract a value it can check: any field the contract cannot see is a field the prover can choose freely.

Cost, stated plainly: `KAT_COMMIT7` becomes `KAT_COMMIT8` and the cross-layer Solidity KAT re-pins. That is the price of having a clock at all.

### 2. What the circuit enforces

Three constraints. The third does the real work.

1. **Batch window.** Every op's `now_ms` must lie in `(state.last_batch_time_ms, manifest.batch_time_ms]`. Ops cannot claim a time outside the batch they are in.
2. **Batch monotonicity.** `manifest.batch_time_ms > state.last_batch_time_ms`, stored at the end of the batch. A prover cannot rewind.
3. **Per-market oracle monotonicity.** `state.last_oracle_publish_ms[market]` is stored, and every transcript for that market must satisfy `publish_time_ms > last_oracle_publish_ms[market]`, updating it.

Constraint 3 is what closes the finding: **a historical transcript can never be replayed**, because every transcript must be strictly newer than the last one that market consumed. The attack degrades from "choose any past price" to "only move forward". Constraints 1 and 2 then bound how far behind real time that forward march may fall.

Genesis: `last_oracle_publish_ms` absent for a market means no lower bound yet — the first transcript for a market sets it. `last_batch_time_ms` starts at 0.

### 3. What the contract enforces

`settleBatch` checks:

```
batchTimeMs <= block.timestamp * 1000                       // not from the future
block.timestamp * 1000 - batchTimeMs <= MAX_SETTLE_LAG_MS   // not indefinitely behind
```

**`MAX_SETTLE_LAG_MS` must accommodate proving latency, and getting this wrong bricks settlement.** Proof generation currently measures ~13 minutes, so a batch is legitimately that far behind by the time it settles. Proposed **30 minutes**, roughly 2× measured latency.

Taken alone that would be weak — "any price from the last 30 minutes". It is not alone: oracle monotonicity (§2.3) means the prover cannot go *back* to a price inside that window either. The L1 bound stops indefinite lag; monotonicity stops rewinding. Each is insufficient by itself; together they close the window.

## Migration

| Change | Consequence |
|---|---|
| `DerivedRoots` 8th word → `commitment()` | **vkey re-pin**; Solidity `publicCommitment` must match byte-for-byte; `KAT_COMMIT7` → `KAT_COMMIT8`; cross-layer KAT re-pins |
| `BatchManifest.batch_time_ms` | manifest hash changes |
| `State`: `last_batch_time_ms`, `last_oracle_publish_ms` | `state_root` changes → **`GENESIS_ROOT` moves**; **postcard encoding of `DefaultState` changes** → witness plaintext, sealed-witness ciphertext/nonce, gateway + sequencer snapshots, `window_start_state`, rollback journals |
| `settleBatch` signature | contract redeploy — already planned |

**SEC-022 also adds a `Market` field, which also changes the `DefaultState` encoding. The two must ship in one cutover**; sequencing them as separate migrations would mean two snapshot/witness breaks for no benefit.

Any pending witness or rollback journal must be drained or explicitly invalidated before cutover. `GATE-1` applies: verify the built guest ELF's vkey **before** deploying the verifier.

## Testing

| Case | Expected |
|---|---|
| **Replay regression:** a valid historical transcript, `now_ms` set near its `publish_time_ms` | rejected by oracle monotonicity |
| `batch_time_ms <= last_batch_time_ms` | rejected |
| An op's `now_ms` above `batch_time_ms`, or at/below `last_batch_time_ms` | rejected |
| Two transcripts for one market in a batch, second older than the first | rejected |
| Transcripts for *different* markets, independently ordered | accepted — monotonicity is per market |
| First-ever transcript for a market (no stored bound) | accepted, sets the bound |
| Contract: `batchTimeMs` in the future | revert |
| Contract: `batchTimeMs` older than `MAX_SETTLE_LAG_MS` | revert |
| **Contract: a batch ~13 minutes behind `block.timestamp` still settles** | accepted — pins that the tolerance clears real proving latency |
| Rust `commitment()` and Solidity `publicCommitment` over the same 8 words | byte-identical (cross-layer KAT) |
| Every scenario | `conservation_holds()` |

The 13-minute test matters as much as the attack regression: a `MAX_SETTLE_LAG_MS` set tighter than proving latency would stop the exchange settling at all — a self-inflicted outage dressed as a security control.

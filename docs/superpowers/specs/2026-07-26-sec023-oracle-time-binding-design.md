# SEC-023 — Oracle time-binding — Design

> **Sequencing: FIRST of three findings** split out of the SEC-022 review. SEC-024 (`SeedInsurance`
> fabricates external collateral) is second; SEC-022 (fill-price band + closed-position debt) is third
> and depends on this one — its band is anchored to an oracle mark that, until this lands, a prover
> partly controls.

> **Severity corrected.** This spec originally claimed "critical, proof-soundness … exploitable by the sequencer/prover". That was wrong on both halves — see `2026-07-26-sec02x-threat-model.md`, which is canonical. The prover receives a **sealed** (AEAD) witness and cannot alter `now_ms` or swap a transcript; the gateway can, but it also holds the oracle key, so a compromised gateway forges the price outright and the replay is redundant. **Under Phase 1 this is defence-in-depth. It becomes load-bearing the moment a Phase-2 independent price anchor lands** — a signed price the operator cannot forge is still replayable without an anchored clock. Ship it with, or before, any such anchor.

**Finding:** SEC-023 [defence-in-depth under Phase 1; critical once an independent anchor exists] — the proven transition has **no clock**. Oracle freshness is checked against a value the prover supplies, so a prover can replay any historical signed transcript and have the circuit accept it as current.

Verified at source:

- `OracleTranscript::validate` (`crates/perp-core/src/oracle.rs:93-98`) checks `publish_time_ms > now_ms || now_ms - publish_time_ms > market.max_oracle_staleness_ms`. Both operands are prover-supplied: the transcript is genuinely signed, but `now_ms` is a plain field of the `BatchOp` (`engine.rs:59-68`).
- **`BatchManifest` has no time field** (`crates/perp-core/src/order.rs:157-166`).
- **`derive_roots` constrains neither** (`crates/perp-core/src/commitment.rs:53-90`) — it binds only `previous_state_root` and `batch_id`.

The signature check is untouched: **a prover cannot forge a price, only choose which real past price to use.** That decides the mark every downstream risk check is measured against. Affects `Fill`, `Liquidate`, `Unbind`, `AccrueFunding` (`engine.rs:478, 593, 633, 819`): liquidate a healthy position on an old adverse mark, spare an unhealthy one on an old favourable mark, steer funding, and widen SEC-022's fill band, whose right-hand side is anchored to whichever mark the prover selected.

**Trust model.** See `2026-07-26-sec02x-threat-model.md`. In short: not reachable by an API user, not reachable by the prover (sealed witness), reachable by the gateway — which already holds the oracle key, so under Phase 1 this buys hardening rather than a new guarantee.

## STATUS: this rewrite was also rejected. Do not implement it.

The rewrite below was reviewed and **rejected**. Its findings are recorded here rather than fixed, because the threat-model correction (`2026-07-26-sec02x-threat-model.md`) demoted SEC-023 to Phase-1 defence-in-depth, and the principal fix requires redesigning the window/time model — effort that is not justified at this priority. **Revisit when the Phase-2 independent price anchor is scheduled**, at which point this becomes load-bearing.

Outstanding, all verified at source by the reviewer:

1. **A single seal-time clock makes existing windows unprovable — the fundamental one.** Oracle-sensitive ops execute **live** every 700 ms against their own tick `now_ms` and accumulate until a later `seal_window` (`sequencer/src/lib.rs:878-888`, `:697-760`, `:1040-1088`). The nominal window is ~30 s against a 10 s oracle tolerance, and while a proof runs the next window accumulates ~1,100 ticks over ~13 minutes. Validating every embedded transcript against one eventual `batch_time_ms` therefore rejects nearly every op except the last 10 seconds. There is no viable host/circuit split: validating live against `now_ms` accepts state the circuit later rejects; validating against `batch_time_ms` is impossible because it does not exist until seal; and rollback re-seals the same ops later, making them staler still — a permanent retry wedge. **This needs a window/time model redesign, not another comparison.**
2. **The precommit does not bind a proof candidate.** `manifestHash` does not hash the op stream — `derive_roots` applies witness-supplied ops independently (`commitment.rs:58-64`) — and `manifest.oracle_updates` is filled from the seal-time cache rather than from the transcripts the ops carry (`sequencer/src/lib.rs:1090`). So a prover can precommit once and prove several op streams from the same pre-state, then settle whichever is favourable. The precommit must bind the exact public commitment or a commitment to the full canonical witness.
3. **`batch_time_ms` is not tied to precommit time.** Nothing relates it to the block that accepted the precommit, so with a 30-minute lag the sequencer can choose a time ~17 minutes in the past *at precommit*, already knowing that much subsequent market movement.
4. **`op.now_ms` is still a security input.** `AccrueFunding` passes it to `FundingState::accrue` for elapsed time and advances `last_update_ms` (`engine.rs:618`, `funding.rs:64-91`), so a prover can manipulate elapsed time per funding op and potentially take the hourly cap repeatedly. The claim that it "stops being a security input" is false.
5. **Second-precision flooring is wrong.** Live transcripts carry host milliseconds; flooring a seal time of `12:00:00.900` to `12:00:00.000` makes a valid transcript published at `12:00:00.500` "from the future". Source the batch time from an L1 second, or compare at second granularity with defined rounding.
6. **`finalSettle` with only a future check is not defensible** — it currently accepts any proof-valid transition after the close-only grace and does not restrict the proof to reductions/withdrawals, so a relaxed lag admits an arbitrarily old pre-close proof containing fills during wind-down.
7. **Cross-layer transport is incomplete**: `prover-service::ProveResp`, gateway `ProveOutcome` + parser + commitment cross-check, `L1::settle_proved`, the rollback-journal serialization of `ProveOutcome`, every `BatchManifest`/`PublicInputs` initializer across host tools and fixtures, both Rust KATs, `crates/prover/tests/vectors.rs`, `contracts/test/CrossLayer.t.sol`, and the deployment metadata and runbooks.

## Correction history

The first version of this design was rejected in adversarial review (Codex), and all three findings were verified at source. It is recorded here because two of the mistakes are instructive.

1. **The central mechanism did not bind what it claimed.** The design constrained `op.now_ms` to `(last_batch_time, batch_time]` and assumed the 10-second staleness gate would then keep the oracle near `batch_time`. It does not — nothing required `now_ms` to be *close to* `batch_time`. A prover sets `now_ms = 10:02` with a 10:02 transcript and declares `batch_time = 10:20`: the staleness gate passes (measured against `now_ms`), monotonicity passes, and the L1 lag check passes (measured against `batch_time`). Settlement at 10:33 uses a 31-minute-old price. **The freshness check must be anchored to the externally verifiable time, not to a second prover-supplied clock.**
2. **Strict per-transcript monotonicity would have wedged the exchange.** The sequencer holds one transcript per market (`sequencer/src/lib.rs:453`) and reuses it across every fill in a tick (`:844-899`) and, in maintenance, across funding *and every liquidation candidate* (`:712-760`). Live feeds are deliberately not restamped per tick (`gateway/src/main.rs:3098-3112`). Under strict `>`, the second consumer of any transcript would be rejected — trading, funding, liquidation and unbinding all effectively dead. The first version's own warning that "every additional in-circuit constraint is another way to make an unprovable batch" was written and then walked into.
3. **The 8th commitment word touches three definitions, not one.** `crates/prover/src/lib.rs:49-87` defines and hashes the seven words independently of `perp-core`, and `publicCommitment` is recomputed at **two** Solidity sites — `settleBatch` (`DarkPerpSettlement.sol:336`) **and `finalSettle` (`:387`)`. The first version specified the timestamp policy only for `settleBatch`, leaving a `finalSettle` bypass.

Review also sharpened a fourth point the first version raised only weakly: with a 30-minute permitted lag, a prover can generate **candidate proofs from the same pre-state**, observe subsequent market movement, and settle whichever became favourable. That is a retrospective option, not merely price selection — and it is why this design now precommits.

## Design

### 1. Anchored freshness — the core fix

Replace the prover-clock freshness test with one measured against the externally anchored batch time:

```
batch_time_ms − publish_time_ms  ≤  market.max_oracle_staleness_ms
publish_time_ms                  ≤  batch_time_ms          // not from the future
```

`op.now_ms` is no longer trusted for freshness. (It stays in the op for the other uses it already has; it simply stops being a security input.)

**This single change subsumes what the first version tried to get from monotonicity.** If freshness is measured against an L1-bound `batch_time_ms`, a historical transcript is rejected *because it is stale*, regardless of any monotonic bookkeeping. So:

- Finding 1 is closed at its root.
- **Finding 2's wedge disappears entirely** — reusing one transcript across many ops in a window stays legal, because nothing per-transcript is consumed.

Per-market monotonicity (`publish_time_ms >= last_oracle_publish_ms[market]`, non-decreasing) is retained as cheap defence-in-depth, **not** as the load-bearing constraint. Non-decreasing, never strict, precisely so the legitimate reuse above keeps working.

### 2. Precommit — closing retrospective selection

Anchored freshness bounds *which* price, but a prover who may choose `batch_time_ms` after the fact can still produce several candidate proofs from one pre-state and settle whichever the market later favours. It can also renew a stale batch's L1 deadline by re-sealing under a newer `batch_time_ms`.

So the batch time is committed **before** proving begins:

- The sequencer submits `precommit(prevRoot, manifestHash, batchTimeMs)` — a cheap L1 transaction — then proves.
- `settleBatch` requires a matching, unexpired precommit and binds to it.

The prover commits to the window before it can know the outcome, which removes the option value. Two operational requirements fall out:

- **Expiry.** A precommit that never gets a proof must not block the slot. It expires after a bounded interval, after which the same `(prevRoot, batchId)` may be re-precommitted.
- **Rollback compatibility.** The SEC-021 rollback path re-seals a failed window's ops together with intervening ones under the same `batch_id` but a **different** manifest (`sequencer/src/lib.rs:1121-1143`), so the original precommit no longer matches. Re-sealing must therefore issue a fresh precommit, and expiry must be short enough that this is not blocked in practice. **This interaction is the most likely way to wedge settlement and needs an explicit test.**

### 3. Transport: the 8th commitment word

The contract sees only `manifest_hash` — a hash, not fields — so a manifest field alone would remain prover-chosen. `batch_time_ms` therefore becomes the **8th word of the public commitment**, and the proof binds it.

Three definitions must move in lock-step, and all three must stay byte-identical:

- `perp_core::commitment::DerivedRoots` + `commitment()`;
- `crates::prover::PublicInputs` (`prover/src/lib.rs:49-87`) — defines and hashes the words independently;
- Solidity `publicCommitment` (`DarkPerpSettlement.sol:255`), consumed at **both** `settleBatch` (`:336`) and `finalSettle` (`:387`).

Encoding must use the existing little-endian 32-byte `_leWord` convention (`DarkPerpSettlement.sol:619`, matching `perp-core/src/hash.rs:202`). Packing a Solidity `uint64` naturally would emit eight big-endian bytes and silently diverge from Rust.

`KAT_COMMIT7` becomes `KAT_COMMIT8`; the cross-layer KAT re-pins.

### 4. The L1 time check

At `settleBatch`:

```
batchTimeMs  ≤  chainNowMs                       // check BEFORE subtracting (no underflow)
chainNowMs − batchTimeMs  ≤  MAX_SETTLE_LAG_MS
```

**Granularity.** EVM timestamps are whole seconds. A host time of `12:00:00.500` exceeds `block.timestamp * 1000`, so a perfectly legitimate non-future batch would reject. **Canonicalize `batch_time_ms` to chain-second precision** (the circuit requires `batch_time_ms % 1000 == 0`), which removes the skew class entirely rather than papering over it with a tolerance.

**`MAX_SETTLE_LAG_MS` must clear proving latency, and setting it too tight bricks settlement.** Proof generation measures ~13 minutes; proposed **30 minutes**, roughly 2×.

Note what this constant now does and does not buy. With anchored freshness (§1), the oracle can never be more than `max_oracle_staleness_ms` (10 s) older than `batch_time_ms`, so the lag bound is **not** what keeps prices fresh — it bounds how long a *whole batch* may sit between sealing and settling. It is an operational liveness allowance, not the security argument. The first version treated it as the latter; that was wrong.

**`finalSettle` must carry an explicit policy.** Applying the same check preserves the guarantee but may constrain emergency settlement; exempting it creates a bypass. The policy must be stated in the contract, not left implicit. Recommendation: `finalSettle` enforces the future check and the precommit binding, but relaxes `MAX_SETTLE_LAG_MS`, since its purpose is recovery when normal settlement has already failed.

### 5. Atomicity

`last_oracle_publish_ms` must advance only when the op that consumed the transcript **fully succeeds**. A fill can fail its margin checks after `validate()` returns, and `unbind` likewise; the sequencer logs only successful ops (`sequencer/src/lib.rs:888-906`). Advancing the bound before downstream success would mutate live state without a replayable op and break the next proof.

## Scope

- **`crates/perp-core`** (guest): `BatchManifest.batch_time_ms`; `DerivedRoots` 8th word + `commitment()`; `DefaultState.last_oracle_publish_ms`; anchored freshness in `validate` (or its callers); `derive_roots` enforces the second-precision and monotonicity rules; new `EngineError` variants.
- **`crates/prover`**: `PublicInputs` gains the 8th word.
- **`contracts/`**: precommit storage + expiry; `settleBatch` binding and time checks; `finalSettle` policy; `publicCommitment` 8th word via `_leWord`.
- **`crates/sequencer`** + **gateway**: populate `batch_time_ms` at second precision; issue the precommit before proving; re-precommit on rollback re-seal; surface new rejection reasons.

**Non-goals / deferred:**

- **Publisher sequence numbers / hash-chained updates.** Anchored freshness bounds *staleness*, but it cannot prove *completeness*: within the 10-second window a prover may still prefer one signed update over another, and the circuit cannot detect a withheld update because the publisher signs only `(market, price, publish_time, confidence, twap)` (`oracle.rs:76-82`). Proving "no update was skipped" requires publisher-side sequencing plus an externally anchored head — a change to a component outside this repo. **Own workstream.** The residual after this spec is selection within a 10-second window, which is the intended staleness tolerance.
- **Binding `manifest.oracle_updates` to the transcripts actually used.** The field is dead weight today, and `seal_window` fills it from the seal-time cache (`sequencer/src/lib.rs:1090-1100`) rather than from the transcripts ops carried — so it can list an unused update and omit used ones. Binding it improves auditability but does not add soundness here. **Follow-up.**
- SEC-024 and SEC-022, each its own spec.

## Migration

| Change | Consequence |
|---|---|
| `DerivedRoots` 8th word | **vkey re-pin**; `prover::PublicInputs` and both Solidity call sites must match byte-for-byte; `KAT_COMMIT7` → `KAT_COMMIT8`; cross-layer KAT re-pins |
| `BatchManifest.batch_time_ms` | manifest hash changes |
| `DefaultState.last_oracle_publish_ms` | `state_root` changes → **`GENESIS_ROOT` moves**; **postcard encoding of `DefaultState` changes** → witness plaintext, sealed-witness ciphertext/nonce, gateway + sequencer snapshots, `window_start_state`, rollback journals |
| Precommit + `settleBatch`/`finalSettle` signatures | contract redeploy — already planned |

**SEC-022 also changes the `DefaultState` encoding (a new `Market` field). The two must ship in one cutover** — sequencing them separately means two snapshot/witness breaks for no benefit. Pending witnesses and rollback journals must be drained or explicitly invalidated before cutover. `GATE-1` applies: verify the built guest ELF's vkey **before** deploying the verifier.

## Testing

| Case | Expected |
|---|---|
| **Replay regression:** a valid historical transcript, any `op.now_ms` | rejected — stale against `batch_time_ms` |
| The first version's bypass: `now_ms = 10:02` transcript, `batch_time = 10:20` | rejected (it passed before) |
| Transcript newer than `batch_time_ms` | rejected |
| **One transcript reused across many fills, funding and several liquidations in a window** | **accepted** — pins that finding 2's wedge is gone |
| `publish_time_ms` decreasing for a market | rejected |
| First-ever transcript for a market | accepted, sets the bound |
| Op fails after `validate()` (e.g. margin) | `last_oracle_publish_ms` **not** advanced |
| `batch_time_ms % 1000 != 0` | rejected |
| Contract: `batchTimeMs` in the future | revert |
| Contract: settle without a matching precommit | revert |
| Contract: settle against an expired precommit | revert |
| **Rollback → re-seal under a new manifest → fresh precommit → settle** | **accepted** — the most likely wedge |
| **A batch ~13 minutes behind `block.timestamp` still settles** | accepted — pins that the tolerance clears real proving latency |
| `finalSettle` under its stated policy | matches the contract's documented rule |
| Rust `commitment()`, `prover::PublicInputs`, and Solidity `publicCommitment` over the same 8 words | byte-identical |
| Every scenario | `conservation_holds()` |

Two of these matter as much as the attack regression: the transcript-reuse test pins that this design does not repeat the first version's wedge, and the 13-minute test pins that `MAX_SETTLE_LAG_MS` does not become a self-inflicted outage.

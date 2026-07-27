# SEC-025 025-B — Finish the SEC-019 settlement path — Design

> Decomposition: `2026-07-26-sec025-decomposition.md`. Threat model: `2026-07-26-sec02x-threat-model.md`
> (canonical). **This is a rewrite; the first version was reviewed and rejected.** The decomposition
> calls this *"the narrow, mechanical part, and the only piece that is purely integration"* — that
> framing was optimistic, and the correction history below says why.

**Finding:** the repo does not settle end-to-end. The production settle path is broken in **four** independent places, each of which alone stops a cutover, plus one latent.

## Verified at source

| # | Break | Evidence |
|---|---|---|
| 1 | **The prover-side bins do not compile.** All three construct the pre-SEC-019 four-field `BatchOp::Deposit` against an enum that has had seven fields since SEC-019 added `from`, `deposit_id`, `deposit_blind` | `crates/prover-service/src/bin/seal-client.rs:22`, `crates/sp1-host/src/main.rs:43`, `crates/sp1-host/src/bin/prove.rs:31` vs `crates/perp-core/src/engine.rs:41-49` |
| 2 | **The gateway calls a selector the contract does not have.** Solidity's `settleBatch` takes **nine** parameters — six roots, `depositsRoot`, `uint64 newDepositCount`, `bytes proof`. The gateway sends the **seven**-parameter form, so this is not a call that reverts informatively; it is not a call at all | `crates/gateway/src/l1.rs:409`, `:439` vs `contracts/src/DarkPerpSettlement.sol:311-321` |
| 3 | **The gateway cannot parse a real prover response.** `parse_prove_resp` requires a non-optional `deposits_root`; `prover-service`'s `ProveResp` has eight fields and does not emit it. Every HTTP prove fails at JSON decode, before any proof is examined | `crates/gateway/src/prover_client.rs:230-244` vs `crates/prover-service/src/main.rs:71-80` |
| 4 | **A window carrying manifest content but no state change never settles.** `begin_window_settle` returns "nothing to prove" purely on `state_root() == last_settled_root`, never consulting pending `ordered`/`rejected` | `crates/gateway/src/main.rs:2183-2188` |

**Latent, fifth:** the legacy settle path (`L1::settle`, `l1.rs:385-419`, one caller at `main.rs:7285`) synthesizes its commitment via `publicCommitment(bytes32 ×6)`, which also now takes seven roots — so it is broken on both arities.

### Break 4, stated fully — it is the dangerous one

An order that is accepted and rests without crossing is recorded in `ordered` (`crates/matcher/src/lib.rs:126` pushes every non-rejected order), and the sequencer appends those hashes to the open window independently of its op log (`crates/sequencer/src/lib.rs:1247`). Funding can also apply successfully with a zero delta and leave state unchanged (`crates/perp-core/src/funding.rs:80`).

So `window_ordered` / `window_rejected` can be non-empty while the engine root has not moved — and `begin_window_settle` then returns `None` **forever**.

The gateway only copies those hashes into its challenge-answer store *after* an L1 settlement (`main.rs:2209`), and both contract answer paths require a genuinely settled batch (`DarkPerpSettlement.sol:508`, `:549`). **An honest sequencer therefore holds correct manifest data it can neither settle nor answer a ripe inclusion challenge with — and is slashed for it.**

This is a liveness-to-fund-loss path for the operator, it is reachable by any user submitting a resting order into an otherwise quiet window, and it is **not** created by this piece — it is pre-existing and was missed by the decomposition's inventory.

## Correction history

The first version of this spec was sent to adversarial review (Codex) and **every one of its seven examined claims had a defect.** All verified at source before acceptance. The three that changed the design:

1. **"`PROVER_URL=mock` already provides a prover-free dev path, so the legacy path is redundant" — false.** `production_mode(l1_enabled) = l1_enabled || DARKPERP_PROD == "1"` (`main.rs:5829`), and settlement runs only inside `if let Some(l1)` (`main.rs:6760`). So: no L1 configured → dev mode but **no settlement occurs at all**; L1 configured → **production** mode → the proposed refusal rejects `mock`. There is no configuration satisfying "dev boot, mock prover, settles on-chain." The redundancy argument for deleting the legacy path was therefore unfounded, and §4 below is rewritten.

2. **"One commitment comparison verifies all seven roots, so the prover-service needs no change" — half true, and the missing half is a wedge.** The commitment does bind all seven roots (`commitment.rs:32`, mirrored at `DarkPerpSettlement.sol:255`). But `/prove` returns roots and commitment derived **natively** (`prover/src/lib.rs:471` → `prover-service/src/main.rs:163`), and the only comparison against the value the **guest** actually committed is a `debug_assert_eq!` (`prover-service/src/sp1_prover.rs:63`) — which compiles out in the release builds the prover box uses. A native/guest divergence would therefore produce a response whose commitment matches the gateway's native replay while the proof attests a *different* guest commitment: the gateway's check passes, L1 rejects the proof. Soundness holds (L1 catches it); **liveness does not**, and it fails late — after gas, inside the rollback machinery. The prover-service does need a change.

3. **The proposed headline test could not have established what it claimed.** A recorded `/prove` response is *native* output, so comparing it to the gateway's native replay is self-consistency, not guest parity. `spine.rs:971` likewise only replays natively and asserts two of the seven roots. Neither pins native↔RISC-V equivalence.

Four further defects were internal contradictions in the spec itself — a false test expectation, a `serde(default)` that does not work on a `String`, a magic-bump that contradicted its own regression test, and a wrong explanation for a right conclusion. Each is corrected in place below.

## Design

### 1. Local derivation is the source of truth

The gateway already holds everything needed: `prove_and_prepare` receives the `WindowWitness`, and `MockProverClient::prove` (`prover_client.rs:75-91`) already demonstrates the call — clone `pre_state`, run `derive_roots(&mut state, &w.ops, &w.manifest)`.

So `prove_and_prepare` replays the witness locally and obtains all seven roots independently, plus the post-replay `state.consumed_deposit_count` — which *is* the `newDepositCount` the ABI requires.

The gateway computes the commitment from **its own** seven roots and requires the prover's returned `commitment` to equal it. Because the commitment is a keccak over all seven words, that single comparison covers all seven roots. On mismatch: hard error, no settle attempted, nothing broadcast. The prover is reduced to producing **proof bytes**.

The same replay also exposes the post-state `insurance_fund` that 025-D's trading gate needs. **025-B does not add a field for it** — carrying a value nothing reads would be speculative; the point is only that 025-D will need no new machinery.

**Why this is deterministic.** `derive_roots` is a pure transition over explicit inputs (`commitment.rs:53`): no clocks, no RNG, no I/O, no floating point, and state collections are ordered `BTreeMap`s (`state.rs:32`). `now_ms` is an explicit `BatchOp` field (`engine.rs:57`), read from the stored op rather than sampled during replay.

*Correcting a prior note.* An earlier session recorded that "the witness carries `now_ms`, so roots are non-deterministic per seal — settle with the PROVER's roots." Replaying a **stored** witness is deterministic, so that note does not defeat this design. But the explanation the first draft gave for it — that "a fresh seal captures a new `now_ms`" — is also wrong: `seal_window` reads no clock (`sequencer/src/lib.rs:1290`), and rollback clones stored ops unchanged (`:1328`). A re-seal differs only if intervening ticks added newly-timestamped ops. The original observation's meaning is unrecoverable from the repo; it should be treated as superseded rather than explained.

### 2. Native↔guest parity must be enforced where it is checkable

Local derivation makes the gateway authoritative for the roots **as natively computed**. Only the proof binds the guest. Today nothing enforces in release that those agree, so the failure surfaces as an L1 proof rejection.

Therefore: **promote `sp1_prover.rs:63`'s `debug_assert_eq!` to an unconditional runtime check**, and fail `/prove` if the guest's committed public value differs from the natively derived commitment. This turns a late, expensive, rollback-exercising on-chain failure into an immediate prover-side error naming the divergence.

This *is* a prover-service change and it does require a rebuild — which the vkey re-pin forces anyway.

**Break 3 still needs no `ProveResp` change:** under §1 the gateway needs only `commitment` and `proof`. The fix is on the gateway side (§3).

### 3. Parsing a response that omits `deposits_root`

`#[serde(default)]` on the existing `String` field is **not** sufficient: an absent field defaults to `""`, which `parse_hex32` then rejects (`prover_client.rs:250`). There is also a type-flow problem — `HttpProverClient::prove` must return a complete `ProveOutcome` before `prove_and_prepare` runs the authoritative replay (`prover_client.rs:67`).

So: introduce a distinct **remote-response** type whose root fields are `Option<String>`, parsed leniently. `prove_and_prepare` performs the local replay, builds the authoritative `ProveOutcome` from **its own** derived roots plus the remote `commitment`/`proof`, and compares any roots the response did supply **for diagnostics only** — turning "commitment mismatch" into "the prover's `new_root` differs", which is the difference between a five-minute and a five-hour cutover debug.

### 4. The ABI

- `ProveOutcome` gains `new_deposit_count: u64` from the local replay.
- `L1::settle_proved` moves to `settleBatch(bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,uint64,bytes)`.

`_requireDepositPrefix(depositsRoot, newDepositCount)` runs **before** `verifier.verify` (`DarkPerpSettlement.sol:334-337`), pinning credited deposits to the L1 deposit hash chain — without it a sequencer could prove a valid batch over a chain containing a deposit that never happened and mint collateral from nothing. The count is a **fund-safety input**, so deriving it locally rather than accepting it from the prover is the point; taking it from the prover would reintroduce exactly the unbound external-value assertion SEC-024 exists to remove.

**The count is cumulative, not per-window.** `op_deposit` requires `deposit_id == consumed_deposit_count` and increments it (`engine.rs:353`, `:385`). A window with zero deposits over a pre-state of five must submit **5**, not 0. Zero-deposit windows, rollback/re-seal, and deposits landing between proof-build and mine are all handled correctly by the persistent prefix tip (`DarkPerpSettlement.sol:278`).

### 5. The settle-needed predicate must include manifest content

Fixing break 4: `begin_window_settle` must return `Some` when the engine root has moved **or** the open window carries pending `ordered`/`rejected` hashes. A window that is empty in both senses still returns `None`.

This makes a manifest-only window settle, which is what populates the challenge-answer store and keeps an honest sequencer answerable.

**Two consequences to design for rather than discover:**

- A manifest-only window has `new_root == prev_root`. `settleBatch` does not forbid that (`prevRoot != currentStateRoot` is the only root check, `DarkPerpSettlement.sol:326`), but this must be asserted, not assumed.
- Settling more often costs a proof per manifest-only window (~13 minutes and, per the RAM-fit history, memory scaling with total accounts). The predicate must not turn every idle tick into a proof — it triggers on *pending manifest content*, which is bounded by real user submissions, not on liveness.

### 6. Production start, and the legacy path

The first version proposed deleting `L1::settle` on the grounds that `mock` covered its use case. Correction 1 above refutes that: coupling `production_mode` to `l1_enabled` means every L1-configured deployment is production, so a blanket "production refuses mock" leaves **no** configuration that settles on-chain without a real prover — which is exactly what a testnet or a local anvil run needs.

So:

- **Refuse `PROVER_URL` unset-or-`mock` only when `DARKPERP_PROD=1`**, not whenever L1 is configured. That fail-closes real production while preserving a prover-free on-chain path for testnets and local chains.
- **With that path preserved, `L1::settle` becomes genuinely redundant and is deleted** along with its one caller — it cannot work against the current contract on either arity, and `mock` now covers its role through the new window path with the correct ABI.

Two settle paths where one is known-broken is the ambiguity that makes cutover incidents hard to diagnose. This keeps one.

### 7. Stop the drift recurring

Fix the three bins' `Deposit` construction, and add a CI job running `cargo check` on `crates/sp1-host` and `crates/prover-service` against their real `perp-core` path dependency.

They stay **excluded** from the workspace — they pull `sp1-sdk` (Groth16, Docker, gnark), and `cargo build --workspace` must not drag that in (`Cargo.toml:25`). `cargo check` type-checks without linking or proving, which is precisely the coverage needed to catch a changed `BatchOp` shape.

**This item has the longest half-life.** SEC-024 changes `BatchOp` next, so without it the same break recurs on the very next branch — silently, until someone builds on the prover box mid-cutover.

### 8. Runbook

Correct `docs/FINAL_SETTLE_RUNBOOK.md`'s six-root/old-selector documentation (`:52-80`) to the nine-parameter ABI. It is EXIT-001's wind-down escape, read under duress; being wrong there is expensive. The `finalSettle` **script** and prepared-data export stay deferred to 025-C/D.

## Scope

**In:** `crates/gateway` (`prover_client.rs`, `l1.rs`, `main.rs` boot + settle predicate + wiring), one `prover-service` change (§2), the three prover bins, one CI job, one runbook correction.

**Not in:** `crates/perp-core` — nothing, so **this piece does not itself move the vkey**. The `finalSettle` script (025-C/D), the trading gate (025-D), honest genesis (025-C), the operator insurance bootstrap (025-A).

## Migration

| Change | Consequence |
|---|---|
| `ProveOutcome` gains `new_deposit_count` | `PreparedSettle` is journaled (`rollback_journal.rs:35`), so the **rollback-journal format changes**. SEC-022 already bumped `MAGIC` to `DPRBJL2`; a pre-025-B binary can therefore *already* have written `DPRBJL2`, so reusing it would make an old journal a postcard misparse rather than a versioned rejection. **Bump to `DPRBJL3`.** |
| Legacy `L1::settle` deleted | Prover-free on-chain settling moves to `PROVER_URL=mock`, which now runs through the window path |
| Production refuses unset/`mock` under `DARKPERP_PROD=1` | Operator misconfiguration fails at boot instead of settling through a path the contract rejects |
| Settle predicate includes manifest content | Manifest-only windows now produce proofs; expect more settles on low-activity chains |
| `/prove` gains a release parity check | Prover-service rebuild — already forced by the vkey re-pin |

No `GENESIS_ROOT` move and no vkey move originate here.

## Testing

| Case | Expected |
|---|---|
| **Guest parity:** a serialized `WindowWitness` run through the actual SP1 executor | guest-committed public value **equals** the natively derived commitment. This is the only test that pins §1's foundation; a recorded `/prove` fixture is native output and proves nothing about the guest |
| Native replay vs `MockProverClient` over a multi-op window | all **seven** roots byte-identical (`spine.rs:971` asserts only two) |
| `new_deposit_count` | `post_count == pre_count + number_of_deposit_ops` — **cumulative**. Explicitly: a zero-deposit window over a pre-state of 5 submits **5** |
| Prover returns a commitment disagreeing with local derivation | hard error; assert **no `send` is attempted**, not merely that an `Err` returns |
| Prover roots disagree in exactly one position | error names the differing root (§3 diagnostic) |
| `/prove` response **without** `deposits_root` (today's shape) | parses — break 3 closed. **This test must fail before the change** |
| `/prove` response **with** `deposits_root` | also parses; forward-compatible |
| Encoded `settleBatch` calldata | selector and argument order byte-match the Solidity signature — a **fixed-vector** test, not a round-trip through our own encoder |
| **Break 4:** a window with a resting unfilled order and no state change | settles; its hashes reach the challenge-answer store; a challenge on that order is answerable. **Must fail before the change** |
| A window empty of both state change and manifest content | still returns `None` — no proof burned on idle ticks |
| Manifest-only window where `new_root == prev_root` | `settleBatch` accepts it |
| `DARKPERP_PROD=1` with `PROVER_URL` unset/`mock` | refuses to start, naming the variable |
| L1-configured testnet, `PROVER_URL=mock`, no `DARKPERP_PROD` | settles on-chain through the window path |
| A journal written by the pre-025-B binary | **refused** on the `DPRBJL3` magic — versioned rejection, not a decode accident |
| `cargo check` on both excluded crates | passes — and **fails** at the parent commit, which is the assertion that proves the job has teeth |

Rows marked "must fail before the change" are the ones that establish the tests are testing something. A CI job or regression test that passes both before and after is not evidence.

## Open risks

1. **The guest-parity test needs the SP1 executor**, which is heavy and lives on the excluded crates. If it cannot run in CI, it must at minimum be a documented, runnable-on-demand check gated into the cutover runbook — and §2's release-enforced check is then the only continuous defence.
2. **`cargo check` on `sp1-sdk`'s dependency tree may be slow in CI.** Fallback: a scheduled rather than per-PR job. Some automated compile coverage is required, or §7 is another comment like the two that produced breaks 3 and the un-bumped magics.
3. **Break 4's fix changes settle cadence.** On a quiet chain, resting orders now trigger proofs. If proof cost makes that unacceptable, the alternative is a manifest-only settle that does not require a proof — which the contract does not currently support, and which would be a larger change than this piece.
4. **Break 4 may deserve its own finding number.** It is a pre-existing wrongful-slash path, not SEC-019 debt, and it is bundled here only because it is a settle-path break and cheap to fix alongside. If it is descoped from 025-B it must not be dropped.

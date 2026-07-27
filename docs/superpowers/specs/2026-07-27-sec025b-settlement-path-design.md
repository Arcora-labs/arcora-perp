# SEC-025 025-B — Finish the SEC-019 settlement path — Design

> Decomposition: `2026-07-26-sec025-decomposition.md`. Threat model: `2026-07-26-sec02x-threat-model.md`
> (canonical). This is the piece the decomposition calls *"the narrow, mechanical part, and the only
> piece that is purely integration"* — and it is what stands between three merged findings
> (SEC-021, SEC-022, SEC-026) and a deployable system.

**Finding:** the repo does not settle end-to-end. Not "settles with a gap" — the production settle path is broken in **three independent places**, each of which alone stops a cutover.

## Verified at source

Every claim below was checked against the code, not inherited from the decomposition.

| # | Break | Evidence |
|---|---|---|
| 1 | **The prover-side bins do not compile.** All three construct the pre-SEC-019 four-field `BatchOp::Deposit { owner, asset_id, amount, blinding }` against an enum that has taken seven fields since SEC-019 added `from`, `deposit_id`, `deposit_blind` | `crates/prover-service/src/bin/seal-client.rs:22`, `crates/sp1-host/src/main.rs:43`, `crates/sp1-host/src/bin/prove.rs:31` vs `crates/perp-core/src/engine.rs:41-49` |
| 2 | **The gateway calls a selector the contract does not have.** Solidity's `settleBatch` takes **nine** parameters — six roots, `depositsRoot`, `uint64 newDepositCount`, `bytes proof`. The gateway sends the **seven**-parameter form. The selector does not match, so this cannot revert informatively; it is not a live call at all | `crates/gateway/src/l1.rs:409`, `:439` vs `contracts/src/DarkPerpSettlement.sol:311-321` |
| 3 | **The gateway cannot parse a real prover response.** `parse_prove_resp` requires a non-optional `deposits_root` field; `prover-service`'s `ProveResp` has eight fields and does not emit it. Every HTTP prove fails at JSON decode, before any proof is even examined | `crates/gateway/src/prover_client.rs:230-244` vs `crates/prover-service/src/main.rs:71-80` |

**Break 3 is not in the decomposition.** It was found by reading rather than by reasoning. Its shape is worth naming, because this workstream has now produced it twice: the requirement was written down *as a comment* — *"the prover-service must emit the 7th commitment word"* (`prover_client.rs:239-240`) — and never implemented. The un-bumped `DPSNAP1`/`DPRBJL1` magics that SEC-022's whole-branch review caught were the same pattern: an instruction living in a comment, satisfied by nobody. **A requirement recorded only in prose adjacent to the code it constrains is not a requirement.**

There is also a **fourth**, latent: the legacy settle path (`L1::settle`, `l1.rs:385-419`, called once from `main.rs:7285`) synthesizes its commitment by calling `publicCommitment(bytes32 ×6)` on-chain — which also now takes seven roots. So it is broken on both its arities.

## What the gateway currently verifies, and why it is not enough

`prove_and_prepare` (`prover_client.rs:110-159`) does two checks:

1. It re-derives a commitment from **the seven roots the prover returned** and compares it to **the commitment the prover returned**. This is circular: it establishes that the prover is internally self-consistent, not that any root is correct. A prover that is broken, stale-vkey, running a different `perp-core`, or simply swapped will pass it.
2. It rebuilds the withdrawal tree from the gateway's own `ww` and byte-matches `withdrawals_root`. **This one is a genuine independent check** — and it is the shape the rest of this design generalizes.

## Design

### 1. Local derivation is the source of truth

The gateway already holds everything needed to compute the answer itself: `prove_and_prepare` receives the `WindowWitness`, and `MockProverClient::prove` (`prover_client.rs:75-91`) already demonstrates the exact call — clone `pre_state`, run `derive_roots(&mut state, &w.ops, &w.manifest)`.

So `prove_and_prepare` replays the witness locally and obtains:

- all **seven** roots, independently;
- the post-replay `state.consumed_deposit_count` — which *is* the `newDepositCount` the ABI requires.

The same replay also exposes the post-state `insurance_fund` that 025-D's trading-gate predicate needs. **025-B does not add a field for it.** Carrying a value nothing reads would be speculative, and 025-D can obtain it from the replay this design establishes. The point here is only that 025-D will not need new machinery — not that 025-B should pre-build it.

The gateway computes the commitment from **its own** seven roots and requires the prover's returned `commitment` to equal it. Since the commitment is a keccak over all seven words, **that single comparison verifies all seven roots at once.** On mismatch: hard error, no settle attempted, nothing broadcast.

The prover is thereby reduced to what it is actually needed for — **producing proof bytes**. It is no longer trusted for any value that reaches L1.

**This rests on a property the suite already pins, not on an assumption.** `crates/sequencer/tests/spine.rs:971` (`seal_window_replays_multi_tick_window_to_live_root`) asserts that replaying a window witness through `derive_roots` reproduces the live window-end root, across a window spanning `Deposit`, `Fill`, `AccrueFunding` and `Liquidate`.

*A note on a misleading prior observation:* an earlier session recorded that "the witness carries `now_ms` timestamps, so roots are non-deterministic per seal — settle with the PROVER's roots." That is true of **re-sealing** (a fresh seal captures a new `now_ms` and yields a different witness) and false of **replaying a stored witness**, which is deterministic in its `ops`. The distinction is what makes this design possible, and the earlier note should not be read as forbidding it.

### 2. Therefore the prover-service does not change

Under §1 the gateway needs only `commitment` and `proof` from `/prove`. Adding `deposits_root` to `ProveResp` would force a rebuild and redeploy of the prover-service on the prover box for no safety gain.

Instead: `deposits_root` becomes `#[serde(default)]` in `parse_prove_resp`, and the six roots the service does send are compared against the locally derived ones **for diagnostics only** — to turn "commitment mismatch" into "the prover's `new_root` differs", which is the difference between a five-minute and a five-hour debug during a cutover. The **authoritative** check remains the commitment equality of §1.

This closes break 3 with no prover-side change. *(The vkey re-pin forces a prover rebuild regardless — that is unavoidable and unrelated.)*

### 3. The ABI

- `ProveOutcome` gains `new_deposit_count: u64`, populated from the local replay.
- `L1::settle_proved` moves to `settleBatch(bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,uint64,bytes)`.

`_requireDepositPrefix(depositsRoot, newDepositCount)` runs **before** `verifier.verify` (`DarkPerpSettlement.sol:334-337`), pinning the batch's credited deposits to the L1 deposit hash chain. The count is therefore a **fund-safety input, not a status field** — the contract's own comment explains that without the pin a sequencer could prove a valid batch over a chain containing a deposit that never happened and mint collateral from nothing. Deriving it locally rather than accepting it from the prover is the entire point; accepting it from the prover would reintroduce precisely the unbound external-value assertion SEC-024 exists to remove.

`PreparedSettle` is serialized into the rollback journal, so adding a field to `ProveOutcome` is a **format change** — see Migration.

### 4. Delete the legacy settle path

`L1::settle` cannot work against the current contract (both its `publicCommitment` and `settleBatch` arities are stale), and it has exactly one caller.

The decomposition proposed neutralizing it by refusing production start when `PROVER_URL` is unset or `mock`. That is necessary but not sufficient, because it leaves a broken path reachable in dev — and `PROVER_URL=mock` **already provides a prover-free dev path through the new window code**, with local derivation and the correct ABI. The legacy path is therefore redundant, not merely non-production.

So: **delete `L1::settle` and its caller**, and keep the production-start refusal. Two settle paths where one is known-broken is the ambiguity that makes cutover incidents hard to diagnose; `mock` covers the case the legacy path existed for.

### 5. Fail-closed production start

Refuse to boot in production when `PROVER_URL` is unset or `mock`. This removes the legacy path from production by construction rather than by attempting to detect the deployed contract's ABI version at runtime.

### 6. Stop the drift recurring

Fix the three bins' `Deposit` construction, and add a CI job running `cargo check` against `crates/sp1-host` and `crates/prover-service` with their real `perp-core` path dependency.

They stay **excluded** from the workspace — they pull `sp1-sdk` (Groth16, Docker, gnark) and `cargo build --workspace` must not drag that in (`Cargo.toml:25` and the comment above it explain why). `cargo check` type-checks without linking or proving, which is exactly the coverage needed: it catches a changed `BatchOp` shape.

**This is the item with the longest half-life.** SEC-024 changes `BatchOp` next (`DeprecatedSeedInsurance` + `FundInsurance`), so without this the same class of break recurs on the very next branch — and recurs, as it did this time, silently until someone tries to build on the prover box mid-cutover.

### 7. Runbook

`docs/FINAL_SETTLE_RUNBOOK.md` documents six roots and the old selector (`:52-80`). It is EXIT-001's wind-down escape, so it is read under duress and being wrong there is expensive. Correct it to the nine-parameter ABI.

The `finalSettle` **script** and prepared-data export stay out of scope — deferred to 025-C/D, which are what create the bootstrap close-only scenario it exists to recover from.

## Scope

**In:** `crates/gateway` (`prover_client.rs`, `l1.rs`, `main.rs` boot + settle wiring), the three prover bins, one CI job, one runbook correction.

**Not in:**

- **`crates/perp-core` — nothing.** No guest change, so **this piece does not itself move the vkey.** (The bundle moves it via SEC-022 and SEC-024; 025-B does not add to that.)
- **The prover-service** — see §2.
- **`finalSettle` script / prepared-data export** — 025-C/D.
- **The trading gate** (025-D) consumes the insurance figure §1 produces but is its own piece.
- **Honest genesis** (025-C) and the **operator insurance bootstrap** (025-A).

## Migration

| Change | Consequence |
|---|---|
| `ProveOutcome` gains `new_deposit_count` | `PreparedSettle` is journaled, so the **rollback-journal format changes**. SEC-022 already bumped `MAGIC` (`crates/gateway/src/rollback_journal.rs`) from `DPRBJL1` to `DPRBJL2` and **is merged but not deployed**, so no journal in existence carries `DPRBJL2` and that bump can cover this change too — *provided the bundle deploys together*. **If SEC-022 ever ships ahead of 025-B, this must bump to `DPRBJL3`.** Decide at cutover, and grep the constant name rather than the value |
| Legacy `L1::settle` deleted | Any deployment relying on the unset/`mock` legacy settle must move to `PROVER_URL=mock`, which settles through the new path |
| Production refuses unset/`mock` `PROVER_URL` | An operator misconfiguration now fails at boot instead of silently settling through a path the contract rejects |
| Nine-parameter selector | The gateway can finally reach `settleBatch` at all |

No `GENESIS_ROOT` move and no vkey move originate here.

## Testing

| Case | Expected |
|---|---|
| **The headline property:** a sequencer-sealed window, replayed by the gateway, yields byte-identical roots to the prover's | pinned against `MockProverClient` (shares the code path) **and** against a recorded real `/prove` response fixture, so the check is not merely self-consistent |
| `new_deposit_count` after replay | equals `consumed_deposit_count` of the post-state, and equals the number of `BatchOp::Deposit` ops folded in that window |
| Prover returns a commitment that disagrees with local derivation | **hard error, nothing broadcast** — assert no `send` is attempted, not merely that an `Err` is returned |
| Prover returns roots disagreeing in exactly one position | error message **names the differing root** (the §2 diagnostic) |
| `/prove` response **without** `deposits_root` (today's prover-service shape) | parses successfully — break 3 closed |
| `/prove` response **with** `deposits_root` | also parses; forward-compatible if the service later emits it |
| Encoded `settleBatch` calldata | selector and argument order byte-match the Solidity signature — a **fixed-vector** test, not a round-trip through our own encoder |
| Production boot, `PROVER_URL` unset / `mock` | refuses to start, with a message naming the variable |
| Dev boot, `PROVER_URL=mock` | settles through the window path with local derivation |
| A journal written by the pre-025-B binary | **refused**, not misread (the `ProveOutcome` field addition is why the magic bump matters) |
| `cargo check` on both excluded crates | passes — and would have **failed** before this change, which is the assertion that proves the CI job has teeth |

The last row is the one that matters for recurrence: a CI job that passes both before and after is not testing anything.

## Open risks

1. **`cargo check` on `sp1-sdk`'s dependency tree may be slow or fragile in CI.** If it proves unworkable, the fallback is a `--no-default-features` check or a scheduled (rather than per-PR) job — but *some* automated compile coverage is required, or §6 is a comment like the two that produced breaks 3 and the un-bumped magics.
2. **Deleting `L1::settle` (§4) is a judgement call.** It is dead against the current contract and `mock` covers its use case, but if some operational flow depends on it that is not visible in-repo, this is the item to challenge.
3. **The gateway and prover must run the same `perp-core`.** They do today by path dependency, and §1's commitment check now *detects* divergence rather than silently settling on it — but detection surfaces as a failed settle, so a vkey/`perp-core` mismatch during cutover will present as "prover disagrees", not as a build error. The §6 CI job is the upstream defence.

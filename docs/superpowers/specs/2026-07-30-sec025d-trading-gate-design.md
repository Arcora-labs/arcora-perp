# SEC-025-D — the trading gate

**Status:** design. Last piece of the cutover bundle (SEC-022 + SEC-024 + SEC-026 +
025-A/B/C/D). Depends on 025-A for the capitalization it waits on.

**Do not deploy from this spec.** Merge only.

---

## What this is for

A fresh production deployment boots with `insurance_fund == 0`, no positions, and no
demonstrated settle. Opening order ingress in that state risks a first bad debt with no
backstop, which goes to ADL or trips `Mode::CloseOnly` — terminal, since only
`EnterCloseOnly` exists. The gate keeps ingress closed until the deployment is capitalized
and has demonstrably settled, and it must never be re-opened by a wind-down.

**Read this first: the gate protects something that does not currently work.** In production
today a market order cannot fill at all — see §6. 025-D is still worth building (it stops an
uncapitalized deployment from accepting flow), but it is not what makes the alpha usable.

## What the decomposition got wrong

Recorded because the corrections are most of the design. All three verified at source
(`docs/superpowers/specs/2026-07-26-sec025-decomposition.md:65-82`).

1. **"Predicate from the replayed post-state" — the post-state is not there.**
   `commit_window_settle` (`crates/gateway/src/main.rs:2323-2330`) receives
   `(batch_id, ordered, rejected, prepared, l1_status)`: no witness, no state. The replayed
   post-state *is* built, in `prove_and_prepare` (`crates/gateway/src/prover_client.rs:171-173`),
   and then **discarded** — exactly one scalar survives it (`:268`,
   `new_deposit_count: post.consumed_deposit_count`). Of the five proposed predicate terms,
   only that one is in scope.
   And `self.seq.state` is **not** the window post-state: ticks run every 700 ms
   (`main.rs:347`) independently of the settle loop, while a real Groth16 proof takes minutes.
2. **"A settle that lands before the process dies cannot roll the gate forward" — false.**
   `RecoveryAction::RollForward` calls `commit_window_settle` at boot (`main.rs:273`), and
   `finish_boot_recovery` fsyncs before deleting the journal (`:327-337`). Anything mutated
   inside that function is reconstructed by definition. The real gap is narrower: a failed
   stage-2 journal write plus a landed tx leaves `prepared: None`, which falls through to
   `Hold` (`rollback_journal.rs:186-189`), and boot's continuity check then **exits(1)**
   (`main.rs:6837-6868`). A lost commit cannot leave a stale gate *serving*.
3. **"Both format magics bumped" — conditional.** `DPSNAP3 → DPSNAP4` is forced by any new
   `Gw` field. `DPRBJL4 → DPRBJL5` is forced **only** if `ProveOutcome` / `PreparedSettle` /
   `WindowWitness` change — which is precisely the choice §2 has to make.

The one thing it got exactly right: `commit_window_settle` really is the sole commit point.
Three non-test call sites (`main.rs:7454`, `:7566`, `:273`), one submission path
(`settle_proved`, single caller at `:7418`, emitting only the nine-param `settleBatch`
selector, `l1.rs:556-561`), and `l1_status` written nowhere else outside tests.

## 1. The gate itself

A persisted `TradingGate { Closed, Open }` on `Gw`, defaulting to `Closed` on a production
genesis. `DPSNAP3 → DPSNAP4`.

`Gw` is positional postcard (`snapshot_plain`, `main.rs:1754-1761`), and the tree is explicit
that `#[serde(default)]` does **not** rescue old encodings — with a pinned test recording the
worse case, that a misaligned old encoding can decode *successfully into corrupt state*
(`main.rs:11008-11061`). So the magic bump is the only guard, and it is mandatory.

Demo genesis opens the gate at boot. The gate must not be settable by any HTTP route — the
existing `set_mode` (`main.rs:3641-3647`) is the anti-pattern to avoid: it assigns
`state.mode = Mode::Normal` directly, with **no `BatchOp`**, so a replay would not reproduce
it. Demo-only, but it is exactly the shape a gate must not have.

## 2. Evaluating the predicate — pick one, and pay for it

The decomposition's predicate needs `post.mode` and `post.insurance_fund`, neither of which is
in scope at the commit point. Two options, and this spec picks (b):

- **(a) Re-derive at commit.** A second `derive_roots` replay of the witness, under the
  `app.gw` lock, at all three call sites (`witness_rb` is in scope at `:7351` and `:7566`;
  `j.witness` at `:273`). No format change, but it runs a full replay inside the lock —
  on the boot path too — and duplicates work already done during proving.
- **(b) Carry the terms forward.** Add the two scalars to `ProveOutcome` where `post` already
  exists (`prover_client.rs:171-173`), beside the `new_deposit_count` precedent that already
  does exactly this. **Forces `DPRBJL5`**, because `PreparedSettle` is journaled.

**(b), because the precedent is already there** and because a replay under the lock on the
boot recovery path is a poor place to discover a performance or panic surface. The journal
bump is cheap: this cutover already wipes state, and a fresh boot deletes an orphan journal
(`main.rs:6702-6714`).

## 3. The predicate

```
mode           == Normal
insurance_fund >= MIN_BOOTSTRAP_INSURANCE
deposit_count  >= MIN_BOOTSTRAP_DEPOSITS
landed_via     == SettleBatch          // §4
```

`insurance_fund > 0` is **not** capitalization — one base unit passes, and worse, the per-fill
cut (`engine.rs:690`) and liquidation penalties (`:800`) raise it with no bootstrap at all. So
the floor is a named constant, and **025-A must read the same constant** so the deposit-side
and trading-side notions of "capitalized" cannot drift.

The floor is a deployment risk policy with no source-derivable value. It must be a compile-time
constant, not an env var: an env change must not be able to alter a roll-forward decision made
by a different process invocation.

**The latch is one-way, and that is a deliberate compromise.** Both `insurance_fund` and `mode`
are non-monotonic — insurance is drained by the bad-debt backstop (`engine.rs:828-829`) and
true insolvency flips `mode` in-engine (`:843-845`). So the predicate can become false after
the gate has opened. Re-closing on depletion would hand any adversary who can manufacture one
bad debt a cheap trading halt, and `Mode::CloseOnly` already handles genuine insolvency by
blocking risk increase. The gate is a **launch** gate, not a circuit breaker; say so in the
code, because a reader will otherwise assume it tracks the predicate continuously.

## 4. `finalSettle` must never open the gate — and today it could

Contract side confirmed exact: `finalSettle` (`contracts/src/DarkPerpSettlement.sol:365-404`)
requires `closeOnly`, never assigns it, and `closeOnly` is written at only `:411` and `:575`
and **never cleared anywhere in `contracts/`**. On-chain close-only is terminal.

But `finalSettle` advances `currentStateRoot`, `lastProgressBlock` and `batchCount`
**identically** to `settleBatch` (`:397-399` vs `:346-348`), and both roll-forward arms infer
"the tx landed" from exactly those two values — `settle_failure_action` (`main.rs:136-144`)
and `recovery_action` (`rollback_journal.rs:163-190`). The only on-chain discriminator is the
event (`BatchSettled` vs `FinalSettle`), and the gateway reads no logs except challenges
(`l1.rs:475`).

The ordinary wind-down produces the confusion naturally: close-only trips → the gateway's next
`settleBatch` reverts `InCloseOnly` → governance runs `finalSettle` over the gateway's **own
exported prepared data**, so the roots match → the gateway re-reads, sees `batchCount == id+1`
and a matching root → `RollForward` → `commit_window_settle`. A transition placed there with no
extra evidence **fires on a wind-down**.

**Fix:** the clean path already knows it called `settleBatch` — `settle_proved` is the only
submission. So `landed_via` is carried into `commit_window_settle` by the caller:
`SettleBatch` on the clean path, `Unknown` on both roll-forward arms. Only `SettleBatch` may
open the gate. A roll-forward still commits the settle; it just cannot *launch* the deployment.

That is deliberately conservative: a roll-forward of a genuine `settleBatch` will not open the
gate either. The cost is one extra window before launch; the alternative is either an L1
`closeOnly` read (the gateway has **no** read path today — no `L1` accessor, no boot check) or
event-log parsing, and neither is worth it to save one window at cutover.

## 5. Where the gate is enforced

Two paths reach `Sequencer::accept_order`: `account_place_order` (`main.rs:2499`, production,
route `:6340`) and `place_order` (`:3434`, demo-only route `:6296`). The gate goes in both —
in `account_place_order` because that is the production surface, and in `place_order` so a
future re-mount cannot silently bypass it.

**A gate in `account_place_order` alone is not sufficient.** Two paths enter a window without
going through `accept_order`:

- **The house-MM counter-order injector** (`main.rs:3734-3743`, `:3786-3795`) pushes orders
  straight into the `seal` vector and is **not gated on `prod`**. It is stopped only
  transitively — no taker, no counter-order. Gate it directly rather than relying on that.
- **`simulate_adl`** (`:2994+`) applies `BatchOp::Fill` directly and is prod-refused only
  *incidentally*, via a conditional `fund(...)` reaching `refuse_unbacked_mint`. Give it a
  posture guard at the top of the function; incidental refusal is how a refactor reopens a hole.

WebSocket ingress is clean in both directions and needs nothing (`/v1/ws` handles only auth,
`main.rs:5797-5813`; `/ws` is send-only).

`Mode::CloseOnly` is **not** a substitute: it blocks only *opening* (`main.rs:2592-2596`,
`:3453-3457`, engine backstop `engine.rs:567-572`). Reduce-only, cancels, deposits and
withdrawals all still pass. The two checks stack on the same handler and need distinct refusal
messages, or an operator will read one and diagnose the other.

## 6. The circularity, and the house MM

**The gate's opening condition is unreachable while the gate is closed — unless deposits
count.** `begin_window_settle` returns `None` unless the root moved or the window carries
manifest content (`main.rs:2299-2303`), and `window_has_pending_manifest` is deliberately keyed
on ordered/rejected only, never `window_ops`, so idle ticks burn no proofs
(`crates/sequencer/src/lib.rs:1302-1307`). With ingress closed there is no order flow.

This resolves rather than blocks: deposits move the state root, so the 025-A bootstrap itself
produces the settleable windows that satisfy the predicate. But it means the predicate must
**not** require any demonstration of *trading* health — there can be none before launch. Worth
stating in the spec because the obvious reading of "settling normally" is trade-driven.

**The house MM.** `gw.mm` is funded in exactly one place — `boot_with` under
`if mode == GenesisMode::Demo` (`main.rs:1642-1651`). Production genesis is markets-only,
pinned by `production_genesis_mints_nothing` (`:7747-7760`). Nothing else credits it.

So in production today: a market order is accepted → the tick fabricates an MM counter-order at
the oracle mark (`:3786-3795`) → `pre_trade_check` builds `Position::empty` for the MM and
`check_initial_margin` fails on zero collateral (`crates/perp-core/src/position.rs:185-201`)
⇒ `InsufficientMargin` → the taker meets an empty book ⇒ `CancelledNoFill`, filed under
**`ordered`**, not `rejected` (`crates/matcher/src/lib.rs:132-139`) → no fills, so finality
never advances (`sequencer/src/lib.rs:1115-1117`) → the gateway marks it `sealed = true` anyway
(`main.rs:3829`), so it is never resubmitted. **The order sits at `ACCEPTED` with `filled = 0`
forever.**

And the MM's rejection lands in `manifest.rejected`, making `window_has_pending_manifest()`
true — so a production deployment with trading open **burns a full Groth16 proof per window to
settle nothing but its own fabricated rejections.**

**025-D does not fix this and must not pretend to.** Opening the gate on a deployment in this
state produces silently-dead orders and wasted proofs. Two exits, and the choice is a product
decision, not a code one:

- **Fund a real house MM** — makes the operator a counterparty with real risk and real capital,
  and needs a funding path that does not fabricate value (the same problem 025-A just solved
  for insurance).
- **Go no-house** — remove the injector, require genuine market makers, and ship **025-E** so
  their orders report honest execution status. This is the recorded direction, and it is why
  025-E is the honest blocker for the alpha.

Until one is chosen, the gate should stay closed on any real deployment even if the predicate
is satisfied. **Recommend not merging 025-D's opening path into a deployment before that
decision**, because a gate that can open onto a broken market is worse than no gate: it
signals readiness that does not exist.

## 7. Scope

- **`crates/gateway`**: the `TradingGate` field and persistence; `DPSNAP3 → DPSNAP4`;
  two new `ProveOutcome` scalars and `DPRBJL4 → DPRBJL5`; `landed_via` threaded into
  `commit_window_settle` at all three call sites; enforcement in `account_place_order`,
  `place_order`, the MM injector and `simulate_adl`; `MIN_BOOTSTRAP_INSURANCE` shared with
  025-A.
- **`crates/perp-core`**: none. No vkey movement from this piece.
- **Contracts**: none.

## 8. What must be tested

1. A production-genesis boot has the gate `Closed`; a demo boot has it `Open`.
2. Every ingress path refuses while closed — including the MM injector and `simulate_adl`,
   asserted directly rather than via "no taker exists".
3. The predicate: each term independently insufficient. In particular `insurance_fund` at one
   base unit does **not** open the gate, and neither does a fill's insurance cut.
4. **A roll-forward commit does not open the gate**, on both the settle-loop arm and the boot
   arm. This is the `finalSettle` defence and must fail before the fix.
5. The gate survives a snapshot round-trip, and an old-magic snapshot is refused.
6. The latch does not re-close when `insurance_fund` later falls below the floor — pinning the
   deliberate one-way choice so a later reader does not "fix" it.
7. `MIN_BOOTSTRAP_INSURANCE` is the same constant 025-A gates on — a compile-time assertion or
   a shared `const`, not two literals.

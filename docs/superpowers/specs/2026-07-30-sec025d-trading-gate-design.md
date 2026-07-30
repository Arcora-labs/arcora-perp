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
genesis.

**`DPSNAP4 → DPSNAP5`, not `DPSNAP3 → DPSNAP4`.** 025-A already claims `DPSNAP4` for its own
`Gw` field. If both pieces claimed the same magic, whichever landed second would change the
positional v4 schema *without changing its magic* — which is exactly the silent-misparse hazard
the magic exists to prevent. Two options and this spec takes the first: **D requires `DPSNAP5`
and states its dependency on A explicitly**, or A and D are implemented and cut over as one
atomic change with a single v4. Sequential merges into `main` make the first the only safe
choice.

`Gw` is positional postcard (`snapshot_plain`, `main.rs:1754-1761`), and the tree is explicit
that `#[serde(default)]` does **not** rescue old encodings. *(An earlier draft said a pinned
test demonstrates an old encoding decoding successfully into corrupt state. It does not — the
fixture asserts `decoded.is_err()`; the corrupt-decode case exists only as a comment and a
hypothesis, `main.rs:11039-11060`. The bump is still mandatory; the justification is
"positional postcard", not "we have a test showing corruption".)*

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
not_a_wind_down                        // the block-pinned read of §4
```

`insurance_fund > 0` is **not** capitalization — one base unit passes, and worse, the per-fill
cut (`engine.rs:690`) and liquidation penalties (`:800`) raise it with no bootstrap at all. So
the floor is a named constant, and it is a deployment risk policy with no source-derivable
value. It must be a compile-time constant, not an env var: an env change must not be able to
alter a roll-forward decision made by a different process invocation.

### A hard cross-spec requirement on 025-A

`MIN_BOOTSTRAP_INSURANCE` currently exists **only in this document**. An earlier draft said it
is "the same constant 025-A gates on"; that was aspirational, and left as-is it produces a
deadlock:

025-A accepts *any* positive operator bootstrap, marks its record `Complete` after settlement,
and then **permanently refuses the endpoint** — it is deliberately one-shot. So a bootstrap
below this floor completes 025-A's state machine while 025-D stays closed, **with no retry path
in either piece**. The deployment is then unlaunchable without a code change.

So this is not a shared-constant nicety; it is a requirement on 025-A, and 025-A's spec must be
amended to carry it: **025-A must reject a bootstrap whose amount is below
`MIN_BOOTSTRAP_INSURANCE` before applying either leg**, so the one-shot can never be spent on an
insufficient amount. The constant lives in one module that both read.

**One shared constant closes same-build drift but not temporal drift.** A could complete under
floor F1, and a later 025-D build with a raised F2 would then refuse to open while 025-A's
one-shot refuses to top up — the same deadlock, arrived at through time instead of through
arithmetic. Two things close it, and this spec requires both:

1. **A and D ship as one artifact.** They are already in the same cutover bundle and must cut
   over together; make that a stated constraint rather than an accident of sequencing.
2. **025-A's one-shot is keyed on reaching the floor, not on being called.** `Complete` is set
   only when the settled `insurance_fund` meets `MIN_BOOTSTRAP_INSURANCE`; until then the
   endpoint stays open for a further bootstrap. This is strictly better than counting calls: it
   also absorbs a partial capitalization, and it cannot become a runtime top-up path, because
   the moment the fund is adequate the endpoint closes permanently — which is the hazard the
   one-shot existed to prevent.

### The latch is one-way — and the honest reason is not the one I first gave

An earlier draft justified never re-closing by saying `Mode::CloseOnly` already handles a
depleted fund. **It does not.** `CloseOnly` is not triggered by insurance depletion: the
waterfall is insurance → ADL → `CloseOnly`, and the last step is reached only if debt remains
after *both* (`engine.rs:813-845`). The existing regression ends with `insurance_fund == 0`, a
winner haircut by ADL, and `Mode::Normal` (`crates/perp-core/tests/lifecycle.rs:596-621`).

So an opened gate really can keep accepting exposure-increasing trades with **no backstop**, and
the next bad debt is socialized straight onto winners. `CloseOnly`, when it finally trips, blocks
exposure increases but not risk-reducing fills (`engine.rs:566-572`), and those reductions and
liquidations can realize further bad debt.

The latch stays one-way anyway, for a narrower reason: this gate is a blunt **ingress** gate, so
re-closing it would also block reduce-only exits — trapping users in exactly the state where
they most need to leave. The right response to a depleted fund is a **separate
exposure-increase circuit breaker** plus a recapitalization path, not a re-closing launch gate.
Neither exists; both are recorded here as required follow-ups rather than waved away.

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

The ordinary wind-down produces the confusion: close-only trips → the gateway's next
`settleBatch` reverts `InCloseOnly` → governance runs `finalSettle` for the same window, so the
roots match → the gateway re-reads, sees `batchCount == id+1` and a matching root →
`RollForward` → `commit_window_settle`. A transition placed there with no extra evidence
**fires on a wind-down**.

*(An earlier draft said governance runs `finalSettle` over "the gateway's own exported prepared
data". No such export exists: the runbook requires manually constructing the witness and proof,
or reusing an internal rollback-journal outcome, then a manual `cast send`
(`docs/FINAL_SETTLE_RUNBOOK.md:51-103`, `:122-129`). The root match is still reachable — it is
the same window — but do not describe a tool that is not there.)*

**Fix — a block-pinned three-way read, not a caller-supplied flag.** An earlier version of this
spec threaded a `landed_via` value from the caller (`SettleBatch` on the clean arm, `Unknown` on
both roll-forward arms) and opened only on `SettleBatch`. That is *safe* but **not live**, and
the review showed why the "costs one extra window" justification was false:

after an ambiguous capitalization settle is committed as `Unknown`, there is **no guaranteed
next window**. `begin_window_settle` returns `None` when neither root nor manifest changed
(`main.rs:2299-2303`), manifest presence deliberately ignores idle `window_ops`
(`crates/sequencer/src/lib.rs:1297-1307`), and with an empty book the mark equals the oracle so
idle funding has zero delta (`sequencer/src/lib.rs:855-897`,
`crates/perp-core/src/funding.rs:80-95`). And 025-A's endpoint is one-shot, so it cannot
manufacture a retry once `Complete` is set. **The launch would stay closed indefinitely** until
someone deliberately created a root-changing operation.

So use the discriminator this spec previously dismissed. `finalSettle` *requires*
`closeOnly == true` (`DarkPerpSettlement.sol:377`), and `closeOnly` is terminal — written only
at `:411` and `:575`, never cleared. Therefore a **single block-pinned** observation of

```
batchCount        == J + 1
currentStateRoot  == prepared.new_root
closeOnly         == false
```

proves that `finalSettle` did not produce that transition. It is conservative in the harmless
direction — it can miss a real `settleBatch` followed by a later close-only — but it **cannot
falsely open on a `finalSettle`**, and it lets a genuine roll-forward open the gate, which is
what restores liveness.

The gateway has no `closeOnly` accessor today, but it does have the infrastructure: generic
contract reads (`l1.rs:265-293`), receipt-log parsing (`:411-418`) and `cast logs` handling
(`:475-512`). Adding a boolean read is small. The earlier claim that events were "the only
on-chain discriminator" and that this needed a new subsystem was wrong.

**All three reads must be pinned to one block.** Three independent "latest" calls through a
lagging or load-balanced RPC could observe them at different heights and defeat the argument.
`cast call --block <height|hash>` supports this; `current_root` and `batch_count` need
block-aware variants alongside the new boolean reader.

**A failed or stale read must RETRY, never commit closed.** This is the second way "safe" stops
being "live", and it is sharper than the first. The opening check runs once per commit, and a
commit is not repeatable — so a read that errors, or that lands on a coherent but *lagging*
pre-settle block, would evaluate false, the bookkeeping would commit anyway, and **the only
opening opportunity would be gone permanently**. 025-A's endpoint is one-shot and cannot
manufacture another window.

So the rule is asymmetric, and must be written that way in the code:

> Only a **successfully observed** mismatch — a root or count that does not match, or
> `closeOnly == true` — may commit the gate as closed. A read error, or an observation whose
> `batchCount` is behind `J+1`, is **inconclusive**: retry, and if it stays inconclusive leave
> the gate's decision pending rather than resolving it against opening.

Treat inconclusive exactly as the settle path already treats an ambiguous landing — hold and log
loudly — rather than inventing a second vocabulary for the same situation.

**Finality policy must be explicit.** `send_args` supplies no confirmation depth
(`l1.rs:604-617`) and `cast` defaults to one confirmation. **This spec sets the policy: the
opening read requires the pinned block to be at least `GATE_OPEN_CONFIRMATIONS` deep**, a named
constant beside `MIN_BOOTSTRAP_INSURANCE`. One confirmation is a choice, not a default to
inherit silently — and a reorg that unwound the capitalization settle after the gate opened
would leave trading enabled against a fund that no longer exists on L1.

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
- **`simulate_adl`** (`:2994+`) applies `BatchOp::Fill` directly (`:3042`). *(An earlier draft
  said it is prod-refused only through a **conditional** `fund(...)`. That is wrong: it also
  performs an **unconditional** victim `fund(...)` before the Fill (`:3030-3042`), so production
  always refuses before reaching it today.)* A top-level posture guard is still worth adding as
  defence in depth — refusal that depends on an unrelated call's position is one refactor away
  from disappearing — but it is hardening, not a hole.

Two workspace binaries also seal orders directly — `crates/node/src/lib.rs:63-94` and
`crates/demo/src/main.rs:157-161` — and bypass any gateway gate. They do **not** run the
production gateway or L1 settlement path, so they are out of scope; noted so a future reader
does not mistake them for a gap.

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
⇒ `InsufficientMargin` → **if no other resting liquidity exists**, the taker meets an empty book
⇒ `CancelledNoFill`, filed under **`ordered`**, not `rejected`
(`crates/matcher/src/lib.rs:132-139`) → no fills, so finality never advances
(`sequencer/src/lib.rs:1115-1117`) → the gateway marks it `sealed = true` anyway
(`main.rs:3829`), so it is never resubmitted, and it cannot be cancelled either
(`:2763-2775`). **The order sits at `ACCEPTED` with `filled = 0` forever.**

**Two corrections to an earlier draft of this section**, both from review:

- The trace is **conditional, not unconditional**. The invalid step was "the taker meets an
  empty book". A funded external `Gtc`/`PostOnly` order can rest, and a later market order can
  fill against it (`main.rs:3701-3704`). The house MM being rejected does not imply the book is
  empty. What is unconditional is that **the house MM never provides liquidity** — so the
  deployment depends entirely on external makers, which is the no-house posture arriving by
  accident rather than by design.
- The claim that this **burns a proof per window on nothing was causally wrong**, and I had
  propagated it. The user's IOC is *already* in `manifest.ordered`, so the window required
  settlement with or without the MM. The MM's rejection adds a leaf; it does not cause an extra
  proof, an extra window, or a window that would otherwise not have settled.

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

- **`crates/gateway`**: the `TradingGate` field and persistence; **`DPSNAP4 → DPSNAP5`** (025-A
  takes v4); two new `ProveOutcome` scalars and `DPRBJL4 → DPRBJL5` — which also requires
  updating the positional journal tests and the `ProveOutcome` initializer at `l1.rs:1135-1146`;
  a block-pinned `closeOnly` read on `L1`; the three-way opening check at all three
  `commit_window_settle` call sites; enforcement in `account_place_order`, `place_order`, the MM
  injector and `simulate_adl`; `MIN_BOOTSTRAP_INSURANCE` in one module, **read by 025-A too**.
- **025-A (cross-spec):** must reject a bootstrap below `MIN_BOOTSTRAP_INSURANCE` before
  applying either leg. Without that amendment the two pieces deadlock — see §3.
- **`crates/perp-core`**: none. No vkey movement from this piece.
- **Contracts**: none.

## 8. What must be tested

1. A production-genesis boot has the gate `Closed`; a demo boot has it `Open`.
2. Every ingress path refuses while closed — including the MM injector and `simulate_adl`,
   asserted directly rather than via "no taker exists".
3. The predicate: each term independently insufficient. In particular `insurance_fund` at one
   base unit does **not** open the gate, and neither does a fill's insurance cut.
4. **A `finalSettle`-shaped commit does not open the gate**, on both the settle-loop arm and the
   boot arm: with `closeOnly == true` on-chain the gate stays closed even though `batchCount`
   and `currentStateRoot` match. Must fail before the fix.
5. **A genuine `settleBatch` observed only through a roll-forward DOES open the gate** — the
   liveness half. Without this the deployment can be left permanently unlaunchable, since no
   further window is guaranteed and 025-A's endpoint is one-shot.
6. A bootstrap below `MIN_BOOTSTRAP_INSURANCE` is rejected by 025-A rather than consuming its
   one-shot.
7. The gate survives a snapshot round-trip, and an old-magic snapshot is refused.
8. The latch does not re-close when `insurance_fund` later falls below the floor — pinning the
   deliberate one-way choice so a later reader does not "fix" it, with the comment explaining
   that the reason is reduce-only exits, not that `CloseOnly` covers it.
9. `MIN_BOOTSTRAP_INSURANCE` is one `const` read by both pieces — not two literals.

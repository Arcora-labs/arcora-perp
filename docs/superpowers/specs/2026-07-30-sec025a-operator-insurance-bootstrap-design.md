# SEC-025-A — operator insurance bootstrap

**Status:** design, **rewritten after adversarial review rejected the first version.** Depends
on SEC-024 (merged, `2d6a857`), which added `BatchOp::FundInsurance` and left it with zero
production callers. This piece is that caller. The two must cut over together.

**Do not deploy from this spec.** Merge only.

**Blocked on [SEC-028](2026-07-30-sec028-deposit-authorization-replay.md)** — see §7.

---

## The gap

025-C made the production genesis honest, so `insurance_fund` starts at **0** and grows only
from the per-fill cut — 2 bps of notional (`crates/gateway/src/main.rs:350-352`).

The hazard, stated precisely. An earlier draft of this spec said "zero insurance is terminal".
**That is false**, and it contradicts the very test it cited: with insurance exhausted, ADL
covers the residual and the system stays `Mode::Normal`
(`crates/perp-core/tests/lifecycle.rs:615-620`). The waterfall is insurance → ADL →
`CloseOnly`, and only the *last* step is terminal — `EnterCloseOnly` has no inverse.

So the real exposure of an uncapitalized deployment is: every bad debt is paid by **clawing
real users through ADL** instead of by the backstop, and `CloseOnly` — which is terminal —
trips only when ADL also runs out of winners to claw. That is bad enough to gate a launch on.
It is not the same as "one bad debt ends the deployment", and the spec should not borrow
urgency it does not have.

## What the first version got wrong

Recorded because the corrections *are* the design, and because three of the four are the same
failure this workstream keeps repeating — asserting a property the code cannot perform.

1. **It claimed a protocol invariant that lives only in an HTTP handler.** See §2.
2. **It used `insurance_fund > 0` as a bootstrap marker.** Wrong in both directions: the
   per-fill cut and liquidation penalties raise the fund without any bootstrap
   (`engine.rs:690`, `:800`), and the fund can return to **zero while `Mode` stays `Normal`**
   — there is an existing test showing insurance exhausted, ADL covering the residual, and no
   close-only transition (`crates/perp-core/tests/lifecycle.rs:615-620`). A balance is not a
   marker.
3. **It argued "applied, not settled" was safer.** It is not. See §4.
4. **It claimed the new helper would reach the existing deposit guards.** It would not; those
   guards live inside `account_confirm_deposit`. See §5.

## 1. Shape

The operator is an ordinary registered account. The admin key redirects the destination of
value the operator itself paid in. This reuses the existing deposit path — gateway-signed
entry, the SEC-019 misattribution guard, the in-order id gate, the L1 leaf fold — and adds no
new route into the state.

`POST /v1/admin/insurance/bootstrap`, following `admin_resume_authz` (`main.rs:4963-4996`):
env read per request, header `x-admin-key`, three-state fail-closed (unset/empty ⇒ 503;
absent/wrong ⇒ 401), constant-time compare. Deliberately not `api_key_from`, for the reason
recorded at `main.rs:4960-4962`.

*(Correction to the first version: that spec claimed the compare leaks neither key length nor
matching-prefix length. The prefix half is true — no early exit. The length half is false: the
loop runs `max(a.len(), b.len())` iterations (`main.rs:4986`), so a presentation shorter than
the configured key reveals the configured length through iteration count. Minor, pre-existing,
and not this piece's to fix — but do not repeat the claim.)*

Three bindings, all required: `FIN_ADMIN_KEY`; the operator account's `X-Api-Key`; and
`from == INSURANCE_OPERATOR_ADDRESS` taken from the parsed receipt.

**And a minimum amount.** The endpoint must reject a deposit below `MIN_BOOTSTRAP_INSURANCE`
**before applying either leg**. This is a requirement 025-D imposes, not a nicety: 025-D gates
launch on `insurance_fund >= MIN_BOOTSTRAP_INSURANCE`, while this endpoint is one-shot and
permanently refuses once `Complete`. Without the check, a below-floor bootstrap spends the
one-shot, 025-D stays closed, and **neither piece has a retry path** — the deployment becomes
unlaunchable without a code change. The constant lives in one module that both pieces read; two
literals would let the two notions of "capitalized" drift apart silently.

## 2. What the payer binding actually buys — stated honestly

`FundInsurance` carries only `note_commitment` and `spend_key` (`engine.rs:115`). It carries
no payer, no admin authorization, no account identity. The guest validates with
`expected_owner = None` (`engine.rs:942`). L1 pins the deposit prefix, not who may receive the
resulting internal value (`DarkPerpSettlement.sol:301`).

**Therefore none of the three bindings reaches the guest.** A malicious or compromised
sequencer can construct `FundInsurance { victim_cm, victim_spend_key }` for any custodied user
note and produce a valid proof. The first version of this spec stated the invariant as *"only
value whose L1 payer is the configured operator address can reach `insurance_fund`"*. **That
is false as a protocol property.** It is true only of the shipped handler.

The honest claim, which is what this piece should test:

> Within the shipped endpoint, an admin key cannot route a deposit into `insurance_fund`
> unless that deposit's on-chain payer is the configured operator address. This constrains
> misuse of the endpoint. It does **not** constrain a compromised sequencer, which can spend
> any custodied note directly.

That residual is not new and not this piece's to close: the gateway already custodies every
account's wallet (`main.rs:996`, Phase-0 custody acknowledged at `:1829`). **Phase-0 custody is
by itself the sufficient residual-risk argument.** An earlier draft also called oracle-price
forgery "a strictly larger capability"; that is unsupported — it is a *different* capability,
and the custody argument does not need the comparison. Closing this means removing custody,
which is Phase 1.

Two further limits worth naming, both verified: an ordinary user cannot spoof `from`, because
the vault emits `msg.sender` and pulls tokens from that same address
(`CollateralVault.sol:197-204`) — but that proves which account was *debited*, not beneficial
ownership, so a malicious operator can still deposit customer or borrowed funds. And
`verify_deposit_tx` enforces no confirmation depth (`l1.rs:411-419`), so a reorg can remove
the operator deposit after the bootstrap was applied.

## 3. The bootstrap record — one persisted state machine, four problems

A single persisted field on `Gw` replaces the balance predicate and solves four separate
defects at once:

```
enum Bootstrap {
    NotStarted,
    DepositApplied   { note_commitment: Digest, spend_key: Digest, deposit_id: u64 },
    InsuranceApplied { window_id: u64 },
    Complete,
}
```

**Why there are four states and not three.** A three-state version — transitioning to
`Complete` when the window carrying the *deposit* commits — is wrong in two orderings, both
of which the review found:

- `Deposit` succeeds, `FundInsurance` fails. The deposit alone moved the state root, so that
  window is settleable (`main.rs:2299-2303`), its `settleBatch` lands, and `Complete` would be
  set **although no `FundInsurance` ever settled** — the exact fabrication this whole workstream
  exists to remove.
- The first leg's window is sealed, and the endpoint then applies `FundInsurance` into the
  *next* window while proving runs without the lock (`main.rs:7325`, `:7376`). Committing the
  earlier window must not complete the bootstrap.

So the window that matters is the one carrying the **second** leg. `InsuranceApplied` records
it at the moment `FundInsurance` applies — `state.next_batch_id` is the open window's id — and
`Complete` is set when `commit_window_settle` commits **that** id. `batch_id` is already a
parameter of `commit_window_settle` (`main.rs:2323-2330`), so this needs no post-state and no
new `ProveOutcome` field. That is the whole reason to key on an id rather than on a predicate.

**One false-negative ordering, and the primitive that closes it.** If window `J` — the one
carrying `FundInsurance` — settles on-chain *before* the triggered post-seal snapshot persists,
boot restores Counter B at `J` while the chain reads `J+1`. The recovery table returns **`Hold`**,
not `RollForward` (`crates/gateway/src/rollback_journal.rs:182`), so `commit_window_settle` never
runs and a **genuinely settled bootstrap never reaches `Complete`**. The deployment is then stuck
with an endpoint that is one-shot and already spent.

The fix is an **acknowledged snapshot**: a serialized snapshot operation that returns only after
the write succeeded, and that the caller can await. Today's `snapshot_notify` (`main.rs:7017`) is
internal, asynchronous and best-effort — it cannot serve. This piece must add or specify one, and
it is needed in two places:

1. after `FundInsurance` applies and its window seals, **before the settle is submitted**, so the
   `Hold` ordering above cannot arise;
2. after the operator's deposit authorization, **before the L1 deposit is sent** — see §9.

Both are the same primitive. Specify it once.

- **The marker (defect 2).** `Complete` is set at settle-commit, not at apply. Nothing else
  writes it, so no fill or liquidation can forge it and no depletion can clear it.
- **Second-leg recovery.** If `Deposit` lands and `FundInsurance` fails, the record holds
  `DepositApplied` with the exact `(cm, spend_key)`. The endpoint, called again, resumes the
  **second leg alone**. This matters because retrying the *pair* cannot work: the first
  `Deposit` already advanced `consumed_deposit_count`, so a retry fails `DepositOutOfOrder`
  (`engine.rs:375`) before reaching `FundInsurance`. The first version claimed "a later
  `FundInsurance` with the same `(cm, spend_key)` still works" — true as an engine primitive,
  false as an operational path, because no production caller could invoke the second leg alone.
- **The note-blind boundary (H5).** `deposit_counter` bumps when the **first** leg succeeds,
  and the record carries the commitment forward. Bumping only after both legs would leave the
  next same-owner, same-amount deposit colliding with the live note — commitments bind owner,
  asset, amount and blind, but not `from`, id, or deposit blind (`note.rs:39`), and historical
  uniqueness rejects a repeat (`engine.rs:427-435`).
- **One-shot (defect 8), keyed on reaching the floor rather than on being called.** `Complete`
  is set only when the settled `insurance_fund` meets `MIN_BOOTSTRAP_INSURANCE`; until then the
  endpoint stays open for a further bootstrap, and once `Complete` it refuses permanently.

  Counting calls instead would deadlock across time: 025-A could complete under floor F1 and a
  later 025-D build with a raised F2 would refuse to open while the spent one-shot refused to
  top up. Keying on the floor also absorbs a partial capitalization, and it still forecloses the
  runtime top-up path this condition exists to prevent — the endpoint shuts the moment the fund
  is adequate. (025-D additionally requires that A and D ship as **one artifact**, since they
  cut over together.)

Cost: a new field on `Gw`, so the snapshot format moves. `DPSNAP3 → DPSNAP4`. Acceptable —
this cutover already requires a state wipe. The first version's "no new field, no snapshot
change" property is **abandoned deliberately**; it was bought with a predicate that did not work.

## 4. Where the gate transitions, and why "applied" was wrong

The first version argued that gating on applied state was more correct than gating on settled
state, on the grounds that `rollback_window` does not revert `self.state`. The narrow claim is
true (`crates/sequencer/src/lib.rs:1367-1387`). The conclusion is false:

- `Sequencer::apply` mutates live state **before any proof exists** (`lib.rs:649`). The first
  version called this "already-proven state"; that is simply wrong.
- Snapshots are periodic — every `SNAPSHOT_SECS`, default 30 (`main.rs:357`, `:7043`). A hard
  crash after the bootstrap applies but before a snapshot restores a pre-bootstrap state with
  `insurance_fund == 0`, while the operator's deposit remains on L1.
- Boot deliberately compares L1 against `last_settled_root`, not the applied root
  (`main.rs:6825`), and accepts `gw_count < vault_count` (`main.rs:103`). Losing pending
  applied state is an accepted outcome by design.
- Worse, there is a recovery path that **discards a sealed witness**: if the process dies
  after `seal_window` journalled a witness containing the bootstrap but before the post-seal
  snapshot lands, boot classifies it `SealNeverPersisted` and deletes the journal without
  replaying its ops (`rollback_journal.rs:182`, `main.rs:229`). The comment calling this safe
  (`main.rs:7360-7361`) assumes the restored pre-seal snapshot contains everything applied before
  sealing — which is exactly what a 30-second snapshot window does not guarantee.

So `Complete` transitions in `commit_window_settle`. **Not** "from the replayed post-state" —
an earlier draft said that, and the post-state is not there: `commit_window_settle` receives no
witness and no state, and the replay built in `prove_and_prepare` is discarded with exactly one
scalar surviving it (`prover_client.rs:171-173`, `:268`). The transition is the `window_id`
comparison of §3, which needs neither.

**On `finalSettle`.** Both roll-forward arms (`main.rs:7566`, `:273`) reach
`commit_window_settle`, and neither can tell a `settleBatch` from a `finalSettle`: the two
advance `currentStateRoot` and `batchCount` identically
(`contracts/src/DarkPerpSettlement.sol:346-348` vs `:397-399`), the gateway reads no logs but
challenges, and it has no `closeOnly` read path at all. So a governance `finalSettle` landing
the journal's prepared root could set `Complete`.

025-D must defend against that, because opening *trading* on a wind-down is a real harm.
**025-A should not.** If a `finalSettle` committed the bootstrap window, the capitalization
genuinely landed and was proof-verified on-chain, and the deployment is in terminal close-only
anyway. So the property this piece claims and tests is the weaker, honest one — *a proof-valid
on-chain commit of the window carrying `FundInsurance`* — not "a normal `settleBatch`". Claiming
the strong version while testing the weak one is exactly how a spec acquires a mitigation it
cannot perform.

## 5. The helper must refactor, not duplicate

The first version's table claimed exactly three fields change versus `seed_insurance_unbacked`.
More must change, and all of it already exists inside `account_confirm_deposit`: the
throwaway `owner_seed` becomes the registered account wallet; the note blind must come from
`deposit_counter`; the authorization must be looked up and recomputed (`main.rs:2029-2048`);
`processed_deposit_txs` must be checked and inserted (`:2009`, `:2139`); the authorization must
be removed (`:2135`); `deposit_counter` must bump (`:2134`).

A raw `Deposit → FundInsurance` helper does **not** reach those guards. So the first version's
test — "duplicate-tx bootstraps are refused by the existing guards, reached through the new
endpoint" — was unsupported. Either the shared validation and bookkeeping is factored out of
`account_confirm_deposit` and both callers use it, or the bootstrap path duplicates it and the
duplication is pinned by a test. **Prefer the refactor**; duplicated security bookkeeping is
how one copy drifts.

On atomicity: holding one `app.gw.lock()` across both applies does prevent the snapshot writer
from observing the intermediate state (`main.rs:7028`), which is what the first version
claimed. It does **not** make the result durable, and it does not guarantee the authorization
blind was in the preceding snapshot. Durability is the record's job, not the mutex's.

*(One more imprecision to retire: the first version said conservation is enforced as a hard
check at these call sites. `apply_batch` does enforce it (`engine.rs:195`), but the host's two
calls go through `Sequencer::apply` → `state.apply_op`, which does not. The guest replay
checks it. The property holds; the call-site framing did not.)*

## 6. Scope

- **`crates/gateway`**: the bootstrap record and its persistence; the admin endpoint and
  authz; `INSURANCE_OPERATOR_ADDRESS`; the refactor of `account_confirm_deposit`'s validation
  and bookkeeping into a shared path; the `Complete` transition in `commit_window_settle`;
  `DPSNAP3 → DPSNAP4`; tripwire count updates (`main.rs:8124-8197`, currently 7 / 3 / 5 — all
  three verified still accurate).
- **`crates/perp-core`**: none. `op_fund_insurance` is unchanged, so this piece **moves no
  vkey** of its own. (Verified: a gateway-only change does not alter the guest binary.)
- **Contracts**: none.

## 7. The deposit-ordering restriction is deferred to SEC-028

The first version proposed gating `/v1/accounts/deposit/authorize` to stop a user
head-of-line blocking the bootstrap. Adversarial review showed the gate does not do that:

- Authorizations are persisted with **no expiry and no nonce** (`main.rs:1056`). One issued
  before the gate closes can be landed after.
- A user can deposit while the gateway is offline, or before a restarted gateway serves.
- The vault does not consume the signature, so **one authorization can be replayed into
  several leaves**, and after the first is credited its authorization is deleted — leaving
  every later identical leaf permanently uncreditable.

That last point is not a limitation of the gate; it is a **live, unrecoverable wedge of the
deposit stream on `main` today**, and it is strictly worse than the voluntary blocking this
gate was designed against. It is written up separately as
[SEC-028](2026-07-30-sec028-deposit-authorization-replay.md).

**Decision:** 025-A does not ship a deposit-authorize gate. A gate that stops the voluntary
case while the involuntary permanent case remains open would be security theatre, and would
have to be redesigned the moment SEC-028 is fixed. Pre-bootstrap ordering is handled
operationally at cutover — a fresh vault, the operator's deposit as id 0, before the endpoint
is reachable — and properly once SEC-028 lands.

## 8. What must be tested

1. **The endpoint-scoped payer binding**: a deposit whose on-chain `from` is not
   `INSURANCE_OPERATOR_ADDRESS` is refused with both valid credentials presented. Must fail
   before the fix. The test name must not claim a protocol invariant — it is an endpoint
   property (§2).
2. Each authz state independently: no admin key ⇒ 401; unset config ⇒ 503; admin key but no
   account key ⇒ rejected.
3. `external_in` is unchanged by the `FundInsurance` leg and raised exactly once by the
   `Deposit` leg — the SEC-024 property, re-pinned at this call site.
4. **Resume**: with the record at `DepositApplied`, a second call completes the second leg
   alone and does not attempt another `Deposit`. Pin that a naive pair-retry would fail
   `DepositOutOfOrder`, so the test proves the resume path is load-bearing.
5. **One-shot**: with the record `Complete`, the endpoint refuses.
6. `Complete` is not reachable from a fill's insurance cut or a liquidation penalty — the
   balance can move without the record moving. **Do not test that `finalSettle` cannot set
   `Complete`**: §4 deliberately permits it, and an earlier version of this list contradicted
   §4 by demanding the strong property the spec had just chosen not to claim. Test the property
   §4 actually states — a proof-valid on-chain commit of the window carrying `FundInsurance`.
7. The `Hold` ordering above: a settle that lands before its post-seal snapshot persists must
   still reach `Complete`, or must be made unreachable by the acknowledged-snapshot barrier.
   Assert whichever the implementation chooses, and make it fail without the barrier.
7. Duplicate-tx and out-of-order bootstraps are refused — through whichever path §5 chooses,
   asserted against that path rather than assumed.

## 9. Cutover

Shares SEC-024's cutover (rebuilt guest, fresh `SP1ZkVerifier`). This piece adds no
`perp-core` change, so it moves no root or vkey of its own; it does move the snapshot magic.

Order: deploy → operator registers, binds address, authorizes → **force a durable snapshot
before sending the L1 deposit** → deposits on L1 as id 0 → admin bootstrap → the window carrying
`FundInsurance` settles → record reads `Complete` → **then** order ingress (025-D).

The snapshot barrier is not optional, and **no mechanism for it exists today**.
`account_authorize_deposit` stores the blind in memory only (`main.rs:1977-1983`), snapshots are
periodic (default 30 s, `main.rs:357`), and `snapshot_notify` (`:7017`) is internal, asynchronous
and best-effort — a handler cannot await it or learn whether it succeeded. So "force a durable
snapshot" is an instruction to an operator with no button to press.

This piece must therefore **specify a serialized, success-acknowledged snapshot operation** and
use it here. It is the same primitive §3 needs for the `Hold` ordering; one implementation
serves both. `deposit_authorizations` is serialized inside `Gw` (verified), so a successful
snapshot does durably capture the blind.

Without it, a crash between authorizing and snapshotting leaves the gateway unable to credit its
own bootstrap deposit — stranding the capitalization and wedging the deposit queue on the very
first leaf. This is a general defect, recorded as the second cause in SEC-028; the cutover works
around it until SEC-028 fixes it properly.

## 10. Gaps recorded, not solved

- **SEC-028**, above. Prerequisite for any real deposit-ordering guarantee.
- **Recapitalization after depletion.** `CollateralVault.deposit` reverts only when
  settlement `closeOnly()` is actually true (`CollateralVault.sol:186-191`). The first version
  claimed the path is closed "once the backstop is empty enough to matter" — false: insurance
  can sit at zero with `Mode::Normal` and deposits still work. The real gap is narrower and
  worse-defined: recapitalization works until close-only trips, and is impossible after.
- **Insurance is a one-way valve.** No op removes value from the fund except covering bad debt
  (`engine.rs:828-830`). The operator's USDC becomes permanently protocol-owned, with no
  claim path. The endpoint's documentation must say so plainly.
- **`insurance_fund` is proven but not L1-pinned.** A bootstrap whose `Deposit` lands and
  whose `FundInsurance` is lost looks on-chain like an ordinary user deposit.
- **Public attributability.** `Deposit.from` is an indexed topic; the operator's EOA and the
  capitalization size are public and correlate with the settle in which the fund jumps.

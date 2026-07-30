# SEC-025-A — operator insurance bootstrap

**Status:** design. Depends on SEC-024 (merged, `2d6a857`), which added
`BatchOp::FundInsurance` and left it with **zero production callers**. This piece is that
caller. The two must cut over together.

**Do not deploy from this spec.** Merge only.

---

## The gap

SEC-024 made insurance capitalization a transfer instead of a mint: `op_fund_insurance`
consumes an existing note whose value already entered through the deposit path's L1
hash-chain binding. But nothing in production constructs one. 025-C independently made the
production genesis honest, which means `insurance_fund` starts at **0** and grows only from
the per-fill cut — 2 bps of notional (`TAKER_FEE_BPS(10) − TREASURY_FEE_BPS(8) −
MAKER_REBATE_BPS(0)`, `crates/gateway/src/main.rs:350-352`).

Zero insurance is not merely thin. It is a **terminal** risk: the bad-debt waterfall runs
insurance → ADL → `Mode::CloseOnly`, and only `EnterCloseOnly` exists — there is no proven
transition back. A first bad debt on an uncapitalized deployment can wind it down
permanently.

## Shape

**The operator is an ordinary registered account. The admin key only redirects the
destination of value the operator itself paid in.**

This is deliberate: it reuses the entire existing deposit path — gateway-signed entry, the
SEC-019 misattribution guard, the in-order id gate, the L1 leaf fold — and adds no new
trusted route into the state. What is new is one op-pair and one gate.

### 1. `fund_insurance_backed` — the backed sibling of `seed_insurance_unbacked`

`seed_insurance_unbacked` (`main.rs:4238-4266`) already has the correct *shape*. Exactly
three things in it are fabricated:

| Field | Demo (unbacked) | Backed |
|---|---|---|
| `from` | `[0u8; 20]` sentinel | the L1 `Deposit.from` from the receipt |
| `deposit_blind` | `[0u8; 32]` sentinel | the stored authorization blind for that `ownerCommit` |
| `deposit_id` | self-assigned `consumed_deposit_count` | the chain-assigned id from the receipt |

Everything else is kept unchanged and for the reasons already recorded in the demo funnel:
the `Note::new(owner, 0, amount, blind).commitment::<Keccak256>()` precomputation, the two
sequential `seq.apply` calls so both ops land in `window_ops` in order, the deliberate
absence of `archive.record` (`main.rs:4234-4235` — the note is consumed immediately and no
wallet ever needs to decrypt it), and the error message distinguishing a failure *after* the
note was minted.

It carries **no** `refuse_unbacked_mint` call. That guard exists to stop value being
asserted without backing; this path is backed by construction, and calling it here would be
cargo-culting a check whose premise does not apply.

### 2. `POST /v1/admin/insurance/bootstrap`

Follows `admin_resume_authz` (`main.rs:4963-4996`) exactly — env read per request, header
`x-admin-key`, three-state fail-closed (unset/empty ⇒ `Disabled` ⇒ 503; absent/wrong ⇒
`Unauthorized` ⇒ 401), constant-time compare seeded with the length difference so neither key
length nor matching-prefix length leaks. Deliberately **not** `api_key_from`, for the reason
already recorded at `main.rs:4960-4962`.

Three bindings, all required:

1. **`FIN_ADMIN_KEY`** — authorizes the redirect-to-insurance.
2. **The operator account's `X-Api-Key`** — identifies whose wallet owns the note.
3. **`from == INSURANCE_OPERATOR_ADDRESS`** (new env) — the deposit's on-chain payer, taken
   from the parsed receipt, must equal the configured operator address.

Binding 3 is the load-bearing one, and the rest of this section explains why it is not
optional.

### 3. Why binding 3 exists — the confiscation primitive it closes

`op_fund_insurance` validates the spend with `expected_owner = None`
(`crates/perp-core/src/engine.rs:942`). The engine's own comment justifies this: adding value
to a communal backstop can only help the protocol, and the spend key still prevents donating
someone else's note. **Inside the gateway process that reasoning does not hold** — the
gateway custodies every account's wallet, spend key included (`main.rs:1003`, Phase-0 custody
acknowledged at `:1829-1832`).

So an endpoint shaped the obvious way — *"credit the next-in-line deposit and route it to
insurance"* — would be a **confiscation primitive**: the admin key could move an arbitrary
user's L1 deposit into the fund, and no layer would object. The operator's deposit is
indistinguishable from a user's everywhere it could be distinguished: the on-chain leaf
carries no role field (`contracts/src/CollateralVault.sol:204`), the event's owner topic is
blinded (`:99`), and `account_confirm_deposit` takes no role parameter.

The only discriminator that is not forgeable by the caller is the **on-chain payer**, which
comes from the parsed receipt rather than the request body. Hence the invariant this piece
must hold, and must test:

> **Only value whose L1 payer is the configured `INSURANCE_OPERATOR_ADDRESS` can reach
> `insurance_fund`.** A deposit from any other address is refused regardless of which
> credentials accompany it.

Note what this does *not* claim: it does not stop an operator from capitalizing insurance
with their own money and then being unable to retrieve it (see H3 below). It stops the
operator from capitalizing insurance with **someone else's** money.

### 4. The pre-bootstrap deposit-ordering restriction

Deposit ids are assigned by the chain at mine time (`CollateralVault.sol:204`), and crediting
id *k* requires ids `0..k-1` to be credited first — enforced at three layers, the last of
which is that a wrong fold breaks **every future settle**, `finalSettle` included.

Crediting id *j* requires **account *j*'s API key**: `account_confirm_deposit` is keyed on
the caller's header (`main.rs:5187`, `:5212`), and the gateway has no path to credit a
deposit on a user's behalf. Therefore any registered user can **permanently head-of-line
block the bootstrap** by authorizing ≥ 1 base unit, depositing on L1, and never confirming.
Cost ≈ 1 USDC base unit plus gas.

**Restriction:** in production, refuse `POST /v1/accounts/deposit/authorize` while
`insurance_fund == 0`. At cutover no users exist, the operator's deposit is id 0, and the
route opens the moment the fund is capitalized.

Two properties make this cheap:

- The gate is a **pure read of already-proven state** (`self.seq.state.insurance_fund`,
  already read at `main.rs:2903` and `:4119`). No new field on `Account` or `Gw`, so no
  snapshot format change and no reset beyond the one the cutover already requires.
- It gates `authorize`, not registration. Registration alone cannot produce a creditable
  deposit, and gating it would be broader than the hazard.

**Deliberate divergence from the SEC-024 spec.** That spec said to gate on the bootstrap
batch being **settled**. Gating on `insurance_fund > 0` — *applied*, not settled — is both
simpler and more correct for the stated hazard: the thing that decides whether a bad debt is
covered is the engine, which sees applied state, and `Sequencer::rollback_window`
(`crates/sequencer/src/lib.rs:1371-1387`) does **not** revert `self.state`, so an applied
capitalization survives a failed settle. "Settled" was over-strict. This divergence is
recorded here rather than silently taken.

### 5. Atomicity — what is actually guaranteed

Three distinct boundaries, which must not be conflated in the implementation or its tests:

- **Per op:** genuinely all-or-nothing. Both `op_deposit` and `op_fund_insurance` were
  restructured (SEC-026, SEC-024) so a failure leaves state byte-identical.
- **Between the two ops:** *recoverable, not impossible*. If `Deposit` lands and
  `FundInsurance` fails, the deposit is committed and the value is a live unspent note owned
  by the operator account; a later `FundInsurance` with the same `(cm, spend_key)` still
  works. What cannot be redone is the pair — `deposit_id` is consumed forever. This is the
  same asymmetry `fund_amount` already documents (`main.rs:4278-4282`), and the operator
  contract must say so in the same voice. In practice the second leg is
  infallible-by-construction except `insurance_fund` overflow near `i128::MAX`.
- **Persistence:** atomic provided both applies share one `app.gw.lock()` hold. The snapshot
  writer takes the same mutex (`main.rs:7028`), so a crash mid-handler rewinds to a snapshot
  predating both ops *and* `processed_deposit_txs`/`deposit_counter` — leaving the L1 deposit
  fully creditable after restart. The handler must therefore hold the lock across both
  applies, exactly as `post_v1_deposit_onchain` already does (`:5211-5221`).

### 6. Call-site tripwires

`unbacked_funding_has_exactly_the_known_call_sites` (`main.rs:8124-8197`) asserts exact
occurrence counts across `crates/gateway/src`: `fund_amount_unbacked(` == 7, `fund_amount(`
== 3, `BatchOp::Deposit` == 5. This piece adds a `BatchOp::Deposit` construction, so the
count and its prose breakdown move. That is the tripwire working as designed — update the
count *and* the justification text, never the count alone.

## Scope

- **`crates/gateway`**: `fund_insurance_backed`; the admin endpoint and its authz; the
  `INSURANCE_OPERATOR_ADDRESS` config; the `authorize` gate; tripwire count updates.
- **`crates/perp-core`**: **none.** `op_fund_insurance` already exists and is unchanged.
  This piece therefore **does not move the vkey** — unlike SEC-024, whose cutover it shares.
- **Contracts**: none.

## Non-goals

- **A runtime top-up path** (capitalizing insurance after users exist). H1 makes it
  grief-able by any registered user, and solving that needs either an operator path to credit
  third-party deposits — which is the confiscation primitive above — or a contract change.
  Separate piece.
- **Recapitalization after depletion.** `CollateralVault.deposit` reverts in close-only
  (`CollateralVault.sol:191`), and insurance depletion plus exhausted ADL is precisely what
  trips close-only. **So once the backstop is empty enough to matter, this path is closed by
  the contract.** Recorded as a real gap, not solved here; solving it requires a contract
  change.
- **An insurance withdrawal or "unfund" op.** None exists and none is added — see H3.

## Hazards to carry into the plan

- **H3 — insurance is a one-way valve.** No op removes value from the fund except covering
  bad debt into a position's collateral (`engine.rs:828-830`). The operator's USDC becomes
  permanently protocol-owned. Conservation still holds — it sits in `internal_value`, backed
  by real vault USDC — but there is no operator claim path. The endpoint's documentation must
  say this plainly; an operator should not discover it afterwards.
- **H5 — the note blind is a permanent-failure surface.** The deposit path derives
  `0xB0 ‖ deposit_counter` and bumps the counter only on success (`main.rs:2067-2069`,
  `:2134`). SEC-026 uniqueness is **historical**, so reusing the scheme without bumping
  produces a permanent `DuplicateCommitment` on that account's next same-amount deposit. The
  `BLIND-DERIVATION WARNING` (`main.rs:4305-4312`) additionally forbids leaf-count-derived
  blinds on any `/v1` money path. The bootstrap must reuse the existing derivation and bump,
  not invent one.
- **H8 — boot posture exits(1) on any bookkeeping slip.** `deposit_posture` (`main.rs:84-120`,
  wired `:6869-6950`) terminates the process on `gw_count > vault_count` or a tip mismatch,
  on every L1-configured boot. A bootstrap that credited insurance without a matching real
  leaf would brick the next restart rather than degrade — which is the correct behaviour, and
  the reason the backed path must go through `op_deposit` rather than around it.
- **H9 — the bootstrap is publicly attributable.** `Deposit.from` is an indexed topic and
  `amount` is in the data. The operator's EOA and the size of the capitalization are public
  and correlate with the settle in which `insurance_fund` jumps. The privacy story covers
  payer↔owner linkage, not "the operator capitalized insurance with $X from address Y".
- **H10 — `insurance_fund` is proven but not L1-pinned.** It lives in `state_root` and is
  covered by the proof, but nothing on L1 checks it; `_requireDepositPrefix` pins only the
  deposit leg. A bootstrap whose `Deposit` lands and whose `FundInsurance` is lost looks
  on-chain like an ordinary user deposit — detectable only by reading gateway state.

## What must be tested

1. **The confiscation invariant**: a deposit whose on-chain `from` is not
   `INSURANCE_OPERATOR_ADDRESS` is refused, with both valid credentials presented. This is
   the piece's central security property and must fail before the fix.
2. Each authz state independently: no admin key ⇒ 401; unset config ⇒ 503; admin key but no
   account key ⇒ rejected.
3. `external_in` is unchanged across a successful bootstrap by the `FundInsurance` leg, and
   raised **once** by the `Deposit` leg — the SEC-024 property, re-pinned at this call site.
4. The `authorize` gate: refused at `insurance_fund == 0` in production, permitted after,
   and **not** gated in demo mode.
5. Out-of-order and duplicate-tx bootstraps are refused by the existing guards, reached
   through the new endpoint.
6. Conservation holds across the pair (`conservation_holds`, already a hard rejection in
   `apply_batch`).

## Cutover

Shares SEC-024's cutover, which already needs a rebuilt guest and a fresh `SP1ZkVerifier`.
This piece adds no `perp-core` change, so it moves no root and no vkey of its own.

Order at cutover: deploy → operator registers, binds address, authorizes, deposits on L1 as
id 0 → admin bootstrap → confirm `insurance_fund > 0` → the `authorize` route opens →
**then** order ingress (025-D).

# SEC-025 — decomposition

**SEC-025 was written three times and rejected three times.** Each rewrite fixed the previous findings and surfaced new ones. That is not a detail problem; the framing was wrong. What began as "honest genesis + finish the SEC-019 ABI" accreted an operator bootstrap path, a no-house posture, an execution-status model, a frontend rework, a durable trading gate, and OpenAPI/docs/litepaper corrections. **That is a program, not a spec.** A fourth rewrite would be rejected for the same reason.

This document replaces it with pieces small enough to be reviewed and implemented independently, in dependency order. The rejected spec stays in the tree as the source material — its findings are all real, they were just bundled.

## Dependency order

```
SEC-026 ──► 025-A ──► 025-B ──► 025-D ──► cutover
                 └──► 025-C ──┘
025-E ─────────────────────────────────► (parallel, no dependency)
```

---

## SEC-026 — historical commitment uniqueness *(must land first)*

Already recorded in `2026-07-26-sec026-sec027-open-findings.md`. It moves to the front because **025-A's failure mode is exactly SEC-026's bug**: a `Deposit` that succeeds followed by a `FundInsurance` that cannot spend the note. Fixing uniqueness first removes one whole class of partial-mutation from the bootstrap.

Small, self-contained, `perp-core` only. Fund-loss severity.

---

## 025-A — atomic operator deposit-to-insurance

**The problem.** `FundInsurance` needs an unspent note, but `fund_amount` runs `Deposit` then immediately `FundPosition` (`main.rs:1962`, `:3987-4013`). And a naive two-step operator path is **not failure-atomic**: `Sequencer::apply` mutates state and appends the op immediately (`sequencer/src/lib.rs:468-486`), so `Deposit` can commit before `FundInsurance` errors — leaving a live note, an advanced `consumed_deposit_count`, and the account counter / authorization removal / tx dedup uncommitted (`main.rs:1973-1979`). A retry then fails the strict-order check.

**Scope.** Either a composite state transition that commits both mutations together, or explicit prevalidation plus rollback of the `Deposit`, the op log and the archive on every `FundInsurance` failure. Behind the existing fail-closed `FIN_ADMIN_KEY` gate (`main.rs:4602-4642`). Must normatively require SEC-026's historical uniqueness.

**Plus: pre-bootstrap deposit ordering.** Vault IDs are one global contiguous sequence (`CollateralVault.sol:201-211`), and `/v1/accounts/deposit/authorize` is mounted unconditionally (`main.rs:5887-5892`). So any registered user can take the next ID and, by never confirming, head-of-line block the operator's insurance deposit. Before bootstrap completes, either restrict authorization to the admin, or add a global ingester that consumes every authorized deposit in ID order.

---

## 025-B — finish the SEC-019 settlement path

The narrow, mechanical part, and the only piece that is purely integration.

**Found during SEC-026's implementation review, and it will bite this cutover:** `crates/prover-service/src/bin/seal-client.rs:22` and `crates/sp1-host/src/{main.rs:43, bin/prove.rs:31}` still construct the **pre-SEC-019 four-field** `BatchOp::Deposit { owner, asset_id, amount, blinding }`. Those crates are `exclude`d from the workspace (`Cargo.toml:25`) so CI never compiles them — but they take a *path* dependency on `perp-core`, so **they do not build today**. Since the bundle forces a vkey re-pin and therefore a prover-service rebuild on the prover box, a plain `cargo build --release` there will fail. Pre-existing SEC-019 debt, not introduced by SEC-026, but it must be fixed as part of this piece or the cutover stops at the prover.

The rest:

- `ProveResp` emits `deposits_root` **and** a host-only post-state deposit count; `ProveOutcome`, the parser and the cross-check carry both.
- The gateway **MUST** derive the count and the insurance balance from replaying its own witness — the current check only re-hashes prover-returned roots (`prover_client.rs:110-159`).
- `settle_proved` uses the seven-root + count selector (`l1.rs:425-449` is obsolete against `DarkPerpSettlement.sol:311-337`).
- Refuse production start when `PROVER_URL` is unset or `mock`, which removes the legacy path from production instead of trying to detect the contract's ABI version.
- **`finalSettle` script + prepared-data export** — promised in the rejected spec but never scoped. It is the only recovery if close-only trips during bootstrap.

---

## 025-C — honest genesis and the alpha posture

- Genesis is markets-only: zero notes, positions, insurance, `external_in`, deposit tip and count. Mode passed **into** `Gw::boot()`, since `gw.prod` is assigned too late to guard boot funding (`main.rs:5921`, `:6143-6168`).
- `fund_amount_unbacked` unreachable in production, enforced at the call sites.
- `/v1/lp/*` not mounted and no house-MM counter-orders in production — which also makes `pool_transfer`'s deposit-tip corruption unreachable.
- Fresh boot compares its local genesis against the deployed contract before accepting any deposit (`main.rs:6355` only checks when `l1_status` already exists, and fresh genesis sets it to `None` at `:1610`).
- Operational: non-zero `GENESIS_ROOT` and explicit `VERIFIER` required and verified on-chain; bond posted against projected TVL; liveness window expressed in blocks; snapshot **and** journal wiped for the format cutover.

---

## 025-D — the trading gate

Architecture from the rejected spec was judged sound: flag inside serialized `Gw`, transition centralized in `commit_window_settle`, predicate from the replayed post-state, check in `account_place_order`, both format magics bumped.

**What it still needs:**

- **A defined predicate.** There is no source-derived "correct" amount; it is a deployment risk policy and must be named and made immutable or serialized with `Gw` so an env change cannot alter a roll-forward decision:
  ```
  post.mode == Normal
    && post.consumed_deposit_count >= configured_bootstrap_prefix_count
    && post.insurance_fund        >= configured_min_bootstrap_insurance
    && settlement_was_normal_settleBatch
    && L1 closeOnly == false
  ```
  `insurance_fund > 0` is not capitalization — one base unit would pass.
- **`finalSettle` must never open the gate.** It requires `closeOnly` and never clears it (`DarkPerpSettlement.sol:365-404`); it supports wind-down, not launch. The witness state does not currently carry the contract's `closeOnly`.
- **Crash-completeness.** Journal writes are best-effort and settlement continues after a failure (`main.rs:6794-6815`, `:6846-6859`), so a settle that lands before the process dies cannot roll the gate forward. Production settlement must abort before broadcast if the stage-two journal cannot be durably written, or there must be a deterministic reconciliation path.

---

## 025-E — execution reporting *(the largest piece, and independent)*

This is why the no-house posture kept expanding: the gateway currently gets away with fabricating execution data **because a house fill is guaranteed**. Remove the house and it is simply wrong.

**Root cause:** `Finality` has only `Accepted`/`Matched`/`Settled` (`order.rs:195-207`) — a protocol-finality axis. The matcher already distinguishes full fill, partial/resting, partial/cancelled, resting, no-fill cancelled and rejected (`matcher/book.rs:38-52`), but `SealedBatch` discards those outcomes (`sequencer/src/lib.rs:144-176`), so the gateway invents them: `o.filled = o.order.size`, `o.avg_fill = o.order.limit_price` (`main.rs:3667-3668`).

**Scope:** a separate **execution status** — `RESTING` / `PARTIALLY_FILLED` / `FILLED` / `CANCELLED` / `REJECTED` — with real fill records, remaining size and weighted-average price, carried through `SealedBatch` to the API. Finality stays `ACCEPTED → MATCHED → SETTLED`. Must cover every terminal case, not just IOC no-fill: FOK-unfillable, post-only-would-take, expiry, pre-trade rejection, all-fills-failed (`sequencer/src/lib.rs:923-980`). Multi-batch resting fills are currently unrepresentable — any successful fill marks the whole order `Matched` (`:888-895`) and the gateway stops observing it after `SETTLED` (`main.rs:3657`).

**Plus the surfaces that consume it:**

- Synthetic depth (`book_around`) reaches `/v1/orderbook`, `/v1/ws`, `/api/state` and legacy `/ws` (`main.rs:2714`, `:2749`, `:3742`, `:3884`). **Decide explicitly:** publish real aggregate depth and accept that it leaks sealed order prices/sizes in aggregate, or report depth as unavailable. Fabricated depth is not an option.
- The production frontend submits to `/v1/orders` but reads state from legacy `/api/state` and `/ws` (`realClient.ts:488-494`, `:602-615`), which expose only the shared demo user (`main.rs:3776-3809`), and cancels via `/api/cancel` (`realClient.ts:888`) which is not mounted in production. It must use authenticated `/v1` surfaces and `DELETE /v1/orders/:id`. Frontend types have no execution-status field (`domain/types.ts:13-18`, `:109-117`).
- OpenAPI still advertises production LP routes (`main.rs:5360-5368`); public state still emits LP/MM fields (`:3895-3924`); the UI claims an LP counterparty and house edge (`LpVault.tsx:17-20`), synthetic MM depth (`OrderBook.tsx:46-49`) and MM hedging (`HealthPanel.tsx:137-168`); `docs/API.md:79-81` promises guaranteed house fills and the litepaper repeats the house-MM model (`arcora-perp-litepaper.md:76`, `:157`).

**025-E is the honest blocker for launching a no-house alpha**, and it is mostly product work rather than protocol work. It is independent of A–D and can proceed in parallel.

---

## What this changes about the cutover

The cutover bundle is **SEC-022 + SEC-024 + SEC-026 + 025-A/B/C/D**. 025-E gates whether the alpha is *usable and honest*, not whether it settles — so it can land after, provided the alpha is not opened to users until it does.

SEC-023 stays parked (`2026-07-26-sec023-oracle-time-binding-design.md`), SEC-027 needs its own design, and the Phase-2 oracle anchor remains ZK-001's deferred epic.

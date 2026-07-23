# Frontend: SEC-019 deposit flow + FIN-001 settlement-health display — design

**Date:** 2026-07-23
**Scope:** `frontend/` only. No Rust, no Solidity, no redeploy. This is the frontend
leg of the SEC-019 merge-gate ("frontend `deposit(uint256,bytes32,bytes)` + client
sig-request") plus the optional FIN-001 operator surface.

## Context

SEC-019 (merged to `main` 2026-07-21) changed `CollateralVault.deposit` from
`deposit(uint256)` to `deposit(uint256 amount, bytes32 ownerCommit, bytes sig)` —
gateway-ECDSA-gated (`CollateralVault.sol:186`). The gateway serves
`POST /v1/accounts/deposit/authorize` (`{from, amount}` → `{ownerCommit, sig}`),
which **requires the account's deposit address to already be bound** and signs
`keccak256(chainid ‖ vault ‖ from ‖ ownerCommit ‖ amount)` with the key whose
address the deployed vault pins as `gatewaySigner`. The sig is 65-byte `r‖s‖v`
(v ∈ {27,28}, low-s), returned hex-encoded; the client passes it through opaquely.

FIN-001 (merged 2026-07-20) added settle-loop health to the `WState` snapshot the
frontend already consumes. `WState` is `#[serde(rename_all = "camelCase")]`, so the
wire names are `settlementHealth` (`"HEALTHY" | "DEGRADED" | "HELD"`),
`settlementConsecutiveFailures` (u32), `settlementLastError` (omitted when none),
`settlementHeldSinceMs` (omitted unless HELD). The frontend parses none of them yet.

The frontend today builds `deposit(uint256)` calldata (`wallet.ts:320`), has no
reference to the authorize endpoint, and runs the wallet steps in the order
`chain → mint → approve → deposit → bind → credit` — bind AFTER deposit, which the
new authorize precondition inverts.

## Decisions (user-approved)

1. **Clean cutover.** The old `deposit(uint256)` path is deleted outright. The
   frontend ships together with the SEC-019/ZK-001 redeploy; until then the deposit
   button does not work against the currently-deployed old stack. No
   feature-detection, no dual path — fail-closed, matching SEC-019's posture.
2. **Addresses stay hardcoded.** `MOCK_USDC` / `COLLATERAL_VAULT` remain consts in
   `wallet.ts`, updated as part of the redeploy commit. No gateway config endpoint.

## Design

### 1. Calldata (`frontend/src/api/wallet.ts`)

- Replace `encodeDeposit(amount)` with
  `encodeDeposit(amount: bigint, ownerCommit: string, sig: string)` producing
  `deposit(uint256,bytes32,bytes)` calldata:
  - selector = first 4 bytes of `keccak256("deposit(uint256,bytes32,bytes)")`
  - head: `amount` (word 0), `ownerCommit` (word 1), offset `0x60` (word 2 — 3 args × 32)
  - tail: length word (`65`), then the 65 sig bytes right-padded with zeros to 96
- Input validation, fail-closed: `ownerCommit` must be 32 bytes hex, `sig` must
  decode to exactly 65 bytes — throw otherwise (same posture as the module's other
  hex guards).
- The old `deposit(uint256)` encoder is **removed** (clean cutover).
- Address consts get a `⚠ redeploy` comment block noting they change with the
  SEC-019/ZK-001 redeploy and where they are pinned.

### 2. Authorize client method (`frontend/src/api/realClient.ts` + `wallet.ts` interface)

- `WalletDepositClient` (interface + runtime guard in `wallet.ts`) gains
  `authorizeDeposit(from: string, amount: bigint): Promise<{ ownerCommit: string; sig: string }>`.
- `RealClient` implements it: `POST /v1/accounts/deposit/authorize` with
  `X-Api-Key` (self-provisioned account, same as the other deposit endpoints),
  body `{ from, amount: amount.toString() }`.
- Defensive parse (file's house style): both fields must be strings of the right
  shape or the method throws with the gateway's error text passed through
  verbatim (e.g. "Bind a deposit address first…", "`from` does not match…").

### 3. Step machine reorder (`frontend/src/components/AccountPanel.tsx`)

Old: `chain → mint → approve → deposit → bind → credit`
New: `chain → mint → approve → bind → authorize → deposit → credit`

- **bind moves before deposit** — the gateway refuses to authorize without a bound
  address (`account_authorize_deposit`: "Bind a deposit address first").
- **authorize** is an API step, not a tx step: it calls `authorizeDeposit(address,
  amount)` and holds `{ownerCommit, sig}` in run-local state, consumed by the
  deposit step's calldata.
- Recoverability rules (existing design, adapted):
  - The chain step still ALWAYS re-runs.
  - A tx step whose hash was recorded still resumes `waitForTx` instead of
    re-sending (deposit included).
  - **authorize re-runs on every attempt unless the deposit tx was already
    sent.** Rationale: the sig binds the amount, so an amount change invalidates
    a stale authorization; re-authorizing is free (fresh CSPRNG blind server-side,
    the gateway keeps old authorizations without harm). This also means the
    `{ownerCommit, sig}` pair never needs to be persisted — it lives only in the
    run's local state, alongside the existing recorded-tx map.
  - bind stays skippable once done (unchanged semantics, just earlier).
- Step labels/copy updated (e.g. "Authorize with the gateway (SEC-019)").

### 4. Settlement-health display (FIN-001)

- `frontend/src/api/realClient.ts`: wire type gains the four optional camelCase
  fields; the `WState → ClientState` mapping folds them into
  `settlement: { health: "HEALTHY"|"DEGRADED"|"HELD"; consecutiveFailures: number;
  lastError: string | null; heldSinceMs: number | null } | null` — `null` when
  `settlementHealth` is absent (old gateway / mock client), parsed defensively
  (malformed → `null`, never a throw).
- `frontend/src/api/client.ts`: `ClientState` gains the same optional
  `settlement` field (mock client supplies `null`).
- `frontend/src/components/HealthPanel.tsx`: one new `StatusRow`
  "L1 settle loop (FIN-001)":
  - HEALTHY → ok, detail "settling"
  - DEGRADED → warn, detail "N consecutive failures"
  - HELD → danger, detail "held Xm — <lastError snippet>" (held-duration from
    `heldSinceMs` vs `Date.now()`, error truncated to keep the row one line)
  - `settlement === null` → row not rendered (old gateway stays clean).

### 5. Tests (vitest, existing suites extended)

- `wallet.ts` calldata: golden-vector test for the new `encodeDeposit` — selector
  and full ABI layout asserted against hand-derived hex constants; rejection cases
  (bad commit length, sig ≠ 65 bytes).
- `AccountPanel.wallet.test.tsx`: step order asserted; authorize mocked; the
  "amount changed between attempts → fresh authorize before deposit" case; the
  "deposit hash recorded → authorize NOT re-run, waitForTx resumed" case.
- `HealthPanel.test.tsx`: three health states render with the right tone/detail;
  absent `settlement` hides the row.

## Out of scope

The redeploy itself; entering the new contract addresses; any gateway/Rust change;
`TestnetNotice` copy (a redeploy-time edit); Pyth/attestation phase-2 work.

## Success criteria

`pnpm typecheck` and `pnpm test` green in `frontend/`; the deposit flow compiles
against the SEC-019 contract ABI byte-for-byte (golden vector); the health row
renders all three states; no residue of `deposit(uint256)` anywhere in `frontend/`.

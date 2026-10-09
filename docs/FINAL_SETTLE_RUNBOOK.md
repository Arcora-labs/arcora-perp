# A06 final-settle runbook — terminating CloseOnly wind-down

## Alpha acceptance boundary (2026-10-09)

The selected model remains custodial. The liveness timeout does not make all
balances independently withdrawable. Existing vault withdrawal roots and their
Merkle data support permissionless claims; balances or open positions that have
not become withdrawal leaves still depend on operator/prover service. Both
`finalSettle` and `finalExit` require governance. Loss of governance therefore
blocks new wind-down roots even when existing claims work.

The economic rule below is unchanged: positions close at their own entry price,
so unrealized mark-to-market PnL is not paid out. Committed funding is settled;
positive insurance and treasury absorb deficits before the global proportional
haircut to positive collateral and unspent notes. Users must not infer mark-price
profits or an unconditional redemption right from a displayed account balance.

An infrastructure acceptance drill must retain claim data outside the gateway,
claim an existing root while the gateway/prover are unavailable, then explicitly
record which new exits stop when prover or governance access is removed. Restore
from encrypted backup on another machine, reconcile state/deposit roots and
withdrawal nonces, and measure elapsed recovery and lost acknowledgements. Local
tests cover accounting and contract authorization; they do not complete this drill.

A06 replaces the old counterparty-dependent loop. Once the L1 settlement contract is in
`closeOnly`, governance lands exactly one proof-bound `SettleAll`, then users exit through
price-free phase-2 proofs. Ordinary `settleBatch` cannot accept either phase.

## Phase 1 — SettleAll

Preconditions: `closeOnly() == true`, the original close-only grace has elapsed, and the
sender is `governance()`. `POST /v1/admin/wind-down` is additionally gated by
`FIN_ADMIN_KEY`, durable snapshot persistence, a configured prover, an empty ordinary
window, and a successful block-pinned L1 `closeOnly` read. It queues `BatchOp::SettleAll`
and persists the resulting state before returning 202.

`SettleAll` is a single-op batch. It settles already-committed funding, closes every open
position at that position's own entry price (there is no oracle or governance-selected
settlement price), normalizes negative position/pool balances, consumes positive insurance
and treasury first, then applies one deterministic global pro-rata haircut across remaining
positive position collateral and unspent notes if needed. All arithmetic and note reissues
are staged on a cloned state; any overflow, tree-capacity failure, or unreconcilable deficit
leaves the original state unchanged. Haircut note replacements are archived for registered
owners before the snapshot ACK. If a replacement owner cannot be recovered by this gateway,
the admin request fails closed before mutation.

The proof commitment is the legacy seven-root commitment plus little-endian word `1`.
`settleBatch` still verifies the unchanged legacy seven-root commitment, so a phase-1 proof
cannot be smuggled through normal settlement. `finalSettle` verifies phase 1, is one-shot,
and latches `windDownSettled = true`.

The gateway settlement bridge routes a locally replayed `ProveOutcome.wind_down_phase == 1`
to `finalSettle`. The configured L1 transaction key must therefore be the contract's
`governance` address for this phase; otherwise the on-chain call fails `NotGovernance`.

## Phase 2 — price-free exits

After phase 1, a close-only account withdrawal uses `WindDownUnbind` followed by
`WindDownWithdraw`. `WindDownUnbind` requires a flat position and does not read an oracle.
The phase-2 grammar permits only those two wind-down op types; mixing an ordinary op is
rejected before mutation. Its proof commitment appends little-endian word `2`.

The bridge routes phase 2 to repeatable `finalExit`. `finalExit` requires close-only,
`windDownSettled == true`, governance, previous-root continuity, the same SEC-019 deposit
prefix check, and a valid phase-2 proof. Each landed withdrawals root is published to the
vault normally, so users claim with the existing withdrawal proof path.

## Cross-layer invariant

Normal commitments remain byte-for-byte unchanged. Only nonzero wind-down phases append a
phase word. Rust and Solidity pin phase 1 with the KAT:

`0x10e0f1fecdde1dc0b2aad3f551163ce9ea181ecc40f44d3b935dd11c5c373b88`

for seven roots `[0x01.., 0x02.., ... 0x07..]` and phase `1`.

## Operational checks

Before triggering phase 1, verify `closeOnly`, `closeOnlyBlock`, grace, `governance`,
`currentStateRoot`, `batchCount`, vault `depositCount`, and `depositTipAt(count)` from one
intended deployment. Do not delete snapshots or manually edit the proven state to recover a
failed wind-down. A failed transaction/proof must be reconciled through the existing rollback
journal and root/prefix checks.

A06 changes the zkVM guest program. A production SP1 deployment therefore requires a newly
built guest ELF, a newly derived/pinned program vkey, a compatible verifier deployment, and
an end-to-end real proof before real-value use. Native tests or MockZkVerifier tests are not
a substitute. This is tracked under A11.

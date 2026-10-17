# A06 final-settle runbook — terminating CloseOnly wind-down

## Alpha acceptance boundary (2026-10-09)

The selected model remains custodial. The liveness timeout does not make all
balances independently withdrawable. Existing vault withdrawal roots and their
Merkle data support permissionless claims; balances or open positions that have
not become withdrawal leaves still depend on operator/prover service. Both
`finalSettle` and `finalExit` require governance. Loss of governance therefore
blocks new wind-down roots even when existing claims work.

Deposits that no settled batch consumed are the exception: once close-only begins
they are refunded at principal from the vault, permissionlessly, with no operator,
prover or governance step (§ Deposit boundary).

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

## Entering close-only

Close-only is irreversible. `CloseOnlyEntered(reason)` records which entry was used:

| Entry | Who | Condition | `reason` |
|---|---|---|---|
| `triggerCloseOnly()` | anyone | the root has not progressed for more than `livenessTimeoutBlocks`, and the stack holds a settled batch, a vault deposit or an open challenge | `"liveness timeout"` |
| `triggerCloseOnly()` | anyone | the oldest deposit the settled state has not consumed landed more than `livenessTimeoutBlocks` ago | `"deposit inclusion timeout"` |
| `enterCloseOnly()` | governance | none (immediate) | `"governance"` |

`triggerCloseOnly()` reverts `LivenessNotExpired` while neither timeout has passed
and is a no-op once close-only is set. Entry latches `closeOnlyBlock` (the start of
the `finalSettleGraceBlocks` grace) and `closeOnlyBatchCount` (the last phase-0
batch count).

The gateway keeps the liveness clock fresh while the exchange is idle: when nothing
needs settling and `livenessTimeoutBlocks / 4` blocks have passed since
`lastProgressBlock()`, it seals, proves and settles an empty untimed batch.
Run the gateway and prover from the deploy block onward so the first keepalive lands
in time.

**Governance close-only** is the emergency brake (for example, a sequencer key that
must be considered compromised). It is also the recovery for a dead phase-0 clock
anchor (`docs/PROVING-RUNBOOK.md`) and the orderly way to move users to a new stack:

1. Announce the migration and the date.
2. Let users withdraw normally while ordinary settlement still runs.
3. Call `enterCloseOnly()` from the governance key.
4. Refunds and the wind-down below follow.

## Deposit boundary

Every settle records `consumedDepositCount()`: how many vault deposits the settled
state has consumed. In close-only it is frozen:

- `settleBatch` reverts `InCloseOnly`, and no phase-0 clock anchor can register;
- `finalSettle` and `finalExit` require `newDepositCount == consumedDepositCount()`,
  else `DepositsFrozen`;
- `vault.deposit` reverts `InCloseOnly`.

Deposit ids at or above the frozen count are refunded with
`vault.refundDeposit(id, from, ownerCommit, amount, to)`, as soon as close-only is
set. The refund needs only the `Deposit` event fields; anyone may send it. See
`docs/FUNDS_LIFECYCLE.md` and `scripts/claim/refund_deposit.py`. The wind-down never
credits these deposits; they leave the vault only as refunds. Ids below the count
leave only through withdrawal leaves.

## Gateway rebase to the settled state

`SettleAll` must start from exactly the L1-settled state. When the gateway observes
close-only, it rebases before the wind-down can start:

1. Drop the open window and any sealed window that never settled.
2. Drop the credits of deposits at or above `consumedDepositCount()`, with their blinds
   (they are refundable on L1).
3. Assert that the local root equals `currentStateRoot()` and the local consumed count
   equals `consumedDepositCount()`.
4. Persist the result, then run the wind-down start checks.

Order hashes from the dropped windows enter the `SettleAll` manifest's rejected list
as `MarketCloseOnly`, injected after the start checks pass. Fills, deposits credited
off-chain and withdrawal requests that were only in dropped windows are undone; only
settled state carries into the wind-down. A user whose withdrawal request was dropped
signs a new one with the current `nextWithdrawNonce` from `GET /v1/accounts/me`.

## Inclusion challenges in close-only

- New challenges are refused (`challengeInclusion` reverts `InCloseOnly`).
- Open challenges can still be answered by anyone with a settled batch's
  ordered or rejected proof.
- `slashUnanswered` counts only phase-0 batches, those below `closeOnlyBatchCount`.
  A challenge that already had `progressBatches` phase-0 batches settled after it
  remains slashable after `challengeGraceBlocks`. Close-only itself never slashes.
- A challenge that cannot reach that gate is stale. Anyone may call
  `releaseStaleChallenge(orderHash)`, which returns its stake to the submitter and
  marks the hash resolved. The condition is the exact complement of the slash gate,
  so every open challenge is either slashable later or releasable now.

Check `openChallengeCount()` and page `openChallenges(start, 512)` before the
wind-down. Release every stale entry so stakes do not sit idle, and answer the rest.

## Bond in close-only

Refunds are paid by the vault, not by the bond. `withdrawBond` stays available in
close-only, above `max(requiredBond(), openChallengeCount() * slashPayoutCap())`.
The floor falls as users exit and as open challenges are answered or released.

## Phase 1 — SettleAll

Preconditions: `closeOnly() == true`, the original close-only grace has elapsed, and the
sender is `governance()`. `POST /v1/admin/wind-down` is additionally gated by
`FIN_ADMIN_KEY`, durable snapshot persistence, a configured prover, an empty ordinary
window (the rebase above leaves one), and a successful block-pinned L1 `closeOnly` read.
It queues `BatchOp::SettleAll` and persists the resulting state before returning 202.

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
and latches `windDownSettled = true`. It submits the frozen `consumedDepositCount()` as
`newDepositCount`.

The gateway settlement bridge routes a locally replayed `ProveOutcome.wind_down_phase == 1`
to `finalSettle`. The configured L1 transaction key must therefore be the contract's
`governance` address for this phase; otherwise the on-chain call fails `NotGovernance`.

## Phase 2 — price-free exits

After phase 1, a close-only account withdrawal uses `WindDownUnbind` followed by
`WindDownWithdraw`. `WindDownUnbind` requires a flat position and does not read an oracle.
The phase-2 grammar permits only those two wind-down op types; mixing an ordinary op is
rejected before mutation. Its proof commitment appends little-endian word `2`.

The bridge routes phase 2 to repeatable `finalExit`. `finalExit` requires close-only,
`windDownSettled == true`, governance, previous-root continuity, the frozen deposit count,
the same SEC-019 deposit prefix check, and a valid phase-2 proof. Each landed withdrawals
root is published to the vault normally, so users claim with the existing withdrawal proof
path.

A phase-1 or phase-2 clock anchor that can never be proven can be cancelled by governance
once it is `anchorTimeoutMs` old; see `docs/PROVING-RUNBOOK.md`.

## Cross-layer invariant

Normal commitments remain byte-for-byte unchanged. Only nonzero wind-down phases append a
phase word. Rust and Solidity pin phase 1 with the KAT:

`0x10e0f1fecdde1dc0b2aad3f551163ce9ea181ecc40f44d3b935dd11c5c373b88`

for seven roots `[0x01.., 0x02.., ... 0x07..]` and phase `1`.

## Operational checks

Before triggering phase 1, read from one intended deployment, at one block:

- `closeOnly`, `closeOnlyBlock`, the grace, `closeOnlyBatchCount` and `governance`;
- `currentStateRoot`, `batchCount` and `consumedDepositCount`;
- vault `depositCount`, and `depositTipAt(consumedDepositCount)`, which must equal the
  gateway's settled deposit tip;
- `openChallengeCount`.

Deposits above `consumedDepositCount` are refunds, not wind-down input. Do not delete
snapshots or manually edit the proven state to recover a failed wind-down. A failed
transaction/proof must be reconciled through the existing rollback journal and
root/prefix checks.

A06 changes the zkVM guest program. A production SP1 deployment therefore requires a newly
built guest ELF, a newly derived/pinned program vkey, a compatible verifier deployment, and
an end-to-end real proof before real-value use. Native tests or MockZkVerifier tests are not
a substitute. This is tracked under A11.

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

The economic rule (§ Phase 1 — SettleAll) is:

- Open positions close at their market's **last recorded oracle price**: the newest
  validated price committed in the settled state. A market that never recorded a
  price closes its positions at their own entry price.
- Funding already committed to the market's index is settled. The span since the
  market's last settlement is not charged.
- Deficits are covered by the clearing pool, then insurance, then the treasury.
  Only what is still uncovered is taken by one global proportional haircut on
  positive collateral and unspent notes.
- Whatever the three reserves still hold is paid out as one withdrawal leaf to the
  deployment's **wind-down recipient**, an L1 address fixed at genesis.

This replaces the earlier rule, under which positions closed at their own entry
price and unrealized PnL was not paid. Users must not infer an unconditional
redemption right from a displayed account balance: the settlement price comes from
the operator's oracle key (§ Trust statements), and a haircut can still apply.

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
3. Pick the moment. Price-refresh epochs are 6 hours long and aligned to
   00:00, 06:00, 12:00 and 18:00 UTC. Wait for the first settled window after an
   epoch boundary, and confirm that every market's recorded price
   (`last_price_ms`) falls in the current epoch (§ Settlement price).
4. Call `enterCloseOnly()` from the governance key right after that window.
5. Refunds and the wind-down below follow.

Timed like this, `SettleAll` closes positions at a price only minutes old. Do not
apply the engine's own `EnterCloseOnly` op first. It would refuse every withdrawal
until phase 1, and no production route applies it.

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

**The engine can be close-only before L1 is.** The engine trips to close-only on
its own when a liquidation's shortfall exceeds insurance, the treasury and
auto-deleverage (`docs/ECONOMIC_SECURITY.md`, Q3/Q7). From then on:

- the guest refuses every `Deposit` op, so a later deposit never shares in the
  earlier shortfall;
- the gateway stops issuing deposit permits, stops crediting landed deposits, and
  raises an ops alert to call `enterCloseOnly()`.

Deposits that land in this state stay unconsumed. After L1 close-only they are
refunded at principal like any other unconsumed deposit. If governance does not act,
anyone can force close-only through the deposit-inclusion timeout.

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

`SettleAll` is a single-op batch. It carries no time and no oracle transcript. In order:

1. **Close.** Every open position is closed against the clearing pool at its market's
   recorded price (§ Settlement price), or at its own entry price when the market never
   recorded one. Funding already committed to the market's index is settled first; the
   span since the market's last settlement is not charged.
2. **Deficit.** Every negative balance left (a position's collateral, the clearing pool)
   is set to zero. Their sum is the deficit.
3. **Reserves.** The deficit is covered, in order, by the clearing pool's positive
   balance, the insurance fund and the treasury.
4. **Haircut.** Any remainder is taken by one deterministic pro-rata haircut over all
   positive position collateral and unspent notes. A haircut note is reissued at its
   reduced amount.
5. **Payout.** Whatever the three reserves still hold is paid out as one withdrawal to
   the wind-down recipient (§ Reserve recipient), with the next withdrawal nonce. With
   no recipient set, which only tests and demos do, the reserves stay in place.

Afterwards the engine is close-only, every remaining position is flat with positive
collateral, and no value was created: the claims and reserves after the op, plus the
payout, equal the claims and reserves before it. The op is staged on copies of the
positions, notes and balances. Tree capacity for the reissued notes is checked before
anything is appended. Any overflow, capacity failure or unreconcilable deficit leaves
the state unchanged. Haircut note replacements are archived for registered owners
before the snapshot ACK. If this gateway cannot recover a replacement's owner, the admin
request fails closed before mutation.

The phase-1 withdrawals root therefore holds at most one leaf: the reserve payout.
`finalSettle` publishes it like any other root. Anyone can claim it through
`vault.claim(to, amount, nonce, root, proof)` with an empty proof, because the root of a
one-leaf tree is the leaf itself. The claim still cannot draw on refundable deposit
principal (`ReservedForUncredited`). The `POST /v1/admin/wind-down` response returns that
leaf's claim data as `reserveSink`, and `GET /v1/system/status` keeps showing it under
`windDown.reserveSink` (with `claimable` once `finalSettle` has published the root); no
account lists it.

The proof commitment is the legacy seven-root commitment plus little-endian word `1`.
`settleBatch` still verifies the unchanged legacy seven-root commitment, so a phase-1 proof
cannot be smuggled through normal settlement. `finalSettle` verifies phase 1, is one-shot,
and latches `windDownSettled = true`. It submits the frozen `consumedDepositCount()` as
`newDepositCount`.

The gateway settlement bridge routes a locally replayed `ProveOutcome.wind_down_phase == 1`
to `finalSettle`. The configured L1 transaction key must therefore be the contract's
`governance` address for this phase; otherwise the on-chain call fails `NotGovernance`.

## Settlement price

Each market's funding state records a price and its publish time
(`FundingState.last_price`, `last_price_ms`, both bound into the state root). Only a
positive price published strictly later than the recorded one replaces it, so the
recorded price never moves back in time. These ops record their validated oracle price
when they are accepted:

- `Fill`, `Liquidate` and `Unbind`;
- `AccrueFunding`, when at least one of these holds:
  - the tick changed the market's funding state;
  - the recorded price lies in an earlier 6-hour price epoch than the tick's price
    (epochs are aligned to multiples of 6 h from the Unix epoch);
  - the engine is close-only.

A market that has recorded a price therefore refreshes it at least once per epoch while
the gateway runs and settles. While the engine is close-only, every committed tick keeps
it current. A market that never recorded a price keeps idle ticks root-neutral and
settles at entry price.

`SettleAll` uses the price recorded in the last settled state, so its age is measured
from the last window settled before close-only:

- **Orderly migration**, timed as in § Entering close-only: minutes.
- **Any other close-only**, for a market whose funding rate is zero and that saw no
  trading: up to one epoch (6 h) older than that window. After a liveness timeout, that
  window is itself at least `livenessTimeoutBlocks` old.

## Reserve recipient

The wind-down recipient is a 20-byte L1 address stored in the engine state and bound
into the state root. It is set once at setup, before the genesis root is taken. No op
changes it, so the genesis root a deployment pins on L1 also pins its recipient.

- Choose a cold address that is independent of governance, the sequencer, the enclave
  signer and the gateway signer. In the shipped flow governance is the hot sequencer
  key, so governance is not a suitable recipient.
- The gateway reads it from `WIND_DOWN_RECIPIENT`. Unless mock proofs are explicitly
  allowed (`L1_ALLOW_MOCK_PROOF=1`, tests only), the gateway refuses to boot without a
  non-zero recipient that differs from those four addresses. It applies the recipient
  before it seals the genesis baseline.
- `darkperp-gateway --print-genesis-root` refuses a missing or zero recipient and prints
  `GENESIS_ROOT`, `WIND_DOWN_RECIPIENT` and `ORACLE_SIGNER_ADDRESS`. With
  `--oracle-address <address>` it needs only the oracle signer's address, so the oracle
  key never has to be on the machine that computes the root.
- The deploy config, the release manifest and `observe-target` carry the root, the
  recipient and the oracle signer together. While `batchCount() == 0`,
  `observe-target` checks `currentStateRoot()` against the genesis root.

What the recipient receives: the insurance fund, the treasury and the clearing pool's
positive balance, after every deficit is covered. At that point every user claim has
been settled at the settlement price. The clearing pool is the counterparty to open
interest left behind by liquidations, so the payout also includes that interest's gain
at the settlement price; a loss on it falls first on the reserves and only then on
users through the haircut. The payout is protocol reserves, fee revenue and rounding
residue; no user claim is part of it. If the recipient's key is lost, the payout is
lost with it.

## Trust statements

- **Settlement price.** The operator's own oracle key signs it, and the operator
  chooses which signed transcript, within the staleness window, each op carries.
  Governance chooses when close-only starts; in the shipped flow governance is the hot
  sequencer key.
- **Funding.** The guest proves the rate bound, the 1-hour cap on each gap and the
  exact carry (`docs/ECONOMIC_SECURITY.md`, Q8). The sequencer chooses the funding mark
  and the op timing.
- **Recipient.** It is fixed at genesis and immutable.

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

From the gateway's settled state, also record:

- each market's recorded price and its publish time (`last_price`, `last_price_ms`);
- the wind-down recipient, which must equal the one recorded with the genesis root;
- the last withdrawal nonce. The reserve payout carries the next one.

Deposits above `consumedDepositCount` are refunds, not wind-down input. Do not delete
snapshots or manually edit the proven state to recover a failed wind-down. A failed
transaction/proof must be reconciled through the existing rollback journal and
root/prefix checks.

These wind-down rules are part of the zkVM guest program: the settlement price, the reserve
payout and the recipient word in the state root all change what the guest proves. A
production SP1 deployment therefore requires a newly built guest ELF, a newly derived and
pinned program vkey, a compatible verifier deployment, and an end-to-end real proof before
real-value use. Native tests or MockZkVerifier tests are not a substitute. This is tracked
under A11.

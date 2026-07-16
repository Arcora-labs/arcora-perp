# Final-settle runbook — governance wind-down escape (EXIT-001)

`DarkPerpSettlement.finalSettle` is the manual landing pad for open positions
while the system is in close-only (§6 of `docs/ARCHITECTURE.md`). `settleBatch`
reverts with `InCloseOnly` once close-only trips, so normal automatic settlement
stops — but users can still submit reduce-only closes off-chain, and those closes
need a way to become claimable withdrawals. `finalSettle` is that way: it skips
the close-only / slashed / bond guards `settleBatch` enforces, but keeps the same
ZK-proof-gated, prev-root-continuity check, so governance can only advance
**proof-valid** state — it can never fabricate a balance. It is repeatable (call
it again for the next wind-down window).

This is an **operator-run, manual** procedure today. There is no code path that
calls `finalSettle` automatically — see "Out of scope" below.

## 1. Preconditions

All three must hold, or the call reverts:

| Guard | Check | Revert if false |
|---|---|---|
| System is actually in close-only | `closeOnly() == true` | `NotCloseOnly` |
| Grace window has elapsed | `block.number >= closeOnlyBlock() + finalSettleGraceBlocks()` | `GraceNotExpired` |
| Caller is governance | `msg.sender == governance()` | `NotGovernance` |

Verify with `cast call` before doing anything else:

```bash
SETTLEMENT=0x...   # DarkPerpSettlement address

cast call $SETTLEMENT "closeOnly()(bool)" --rpc-url $RPC
cast call $SETTLEMENT "closeOnlyBlock()(uint256)" --rpc-url $RPC
cast call $SETTLEMENT "finalSettleGraceBlocks()(uint256)" --rpc-url $RPC
cast call $SETTLEMENT "governance()(address)" --rpc-url $RPC
cast block-number --rpc-url $RPC
```

`finalSettle` works even if the sequencer has separately been `slashed` (the
guard set is close-only + grace + governance only — slashing is orthogonal).

Note `governance` is set once at deploy (`Deploy.s.sol`'s `GOVERNANCE` env var,
default: the sequencer address if unset). If `governance == sequencer` and the
gateway process is still running and still attempting `settleBatch` on its own
loop (it has no close-only awareness today — see "Out of scope"), a manual
`finalSettle` from the same key racing the gateway's own transactions can hit a
nonce collision. Stop the gateway (or otherwise ensure it's not submitting
transactions) before sending `finalSettle` from a shared key, or deploy with a
distinct `GOVERNANCE` EOA to avoid this entirely.

## 2. Compute the wind-down roots + proof

`finalSettle` takes exactly the same six roots + proof as `settleBatch` — there
is no separate "wind-down" proof format. Compute them the identical way a normal
settle does (see `docs/PROVING-RUNBOOK.md`):

1. Build the pending window's witness — the `(pre_state, ops, manifest)` covering
   whatever reduce-only closes landed off-chain since the last settled root
   (`sequencer::WindowWitness`, the same structure `seal_window` produces during
   normal operation).
2. Seal it to the prover's measurement + seal root (`crates/prover::SealedWitness::seal`,
   the `0xAB…` stand-in measurement / `PROVER_SEAL_ROOT` (`0x5E…` default) in the
   current dev deployment — see §10b's honesty note in `ARCHITECTURE.md`).
3. `POST /prove` to the attested prover-service and take its response:
   `{prev_root, manifest_hash, new_root, ordered_root, withdrawals_root, rejected_root, proof}`
   — this is the gateway's `ProveOutcome` (`crates/gateway/src/prover_client.rs`),
   the exact same struct a normal `settleBatch` call would submit.

`prev_root` MUST equal the settlement's `currentStateRoot()` at call time
(`BadPrevRoot` otherwise — `finalSettle` keeps prev-root continuity, it does not
relax it). If the gateway already computed and cached a `ProveOutcome` for this
window before `settleBatch` started reverting (e.g. from the rollback journal),
that same outcome is valid to resubmit here — reuse it rather than re-proving.

## 3. Submit

```bash
cast send $SETTLEMENT \
  "finalSettle(bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes)" \
  <prev_root> <manifest_hash> <new_root> <ordered_root> <withdrawals_root> <rejected_root> <proof> \
  --rpc-url $RPC --private-key $GOVERNANCE_KEY
```

`$GOVERNANCE_KEY` must control the address returned by `governance()` above.
On success:
- `currentStateRoot` advances to `new_root`, `batchCount` increments, and a
  `FinalSettle` event is emitted (mirrors `BatchSettled`'s fields).
- if a vault is wired, `withdrawalsRoot` is published to it
  (`CollateralVault.publishWithdrawals`), making the wound-down balances
  claimable via `CollateralVault.claim()` — which stays open in close-only for
  any settled balance (§6).

Repeat steps 2–3 for each subsequent wind-down window until all open positions
have been reduced to zero and their balances are claimable.

## 4. Out of scope (tracked follow-up)

The gateway does not currently detect close-only or automatically route a
computed settle through `finalSettle` instead of `settleBatch` — this entire
procedure is manual. Automatic gateway routing (detect `closeOnly()`, switch the
L1 call target, and stop retrying the now-permanently-reverting `settleBatch`
path) is a tracked follow-up, not delivered in this pass.

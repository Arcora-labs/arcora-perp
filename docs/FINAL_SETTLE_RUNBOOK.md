# Final-settle runbook — governance wind-down escape (EXIT-001)

`DarkPerpSettlement.finalSettle` is the manual landing pad for open positions
while the system is in close-only (§6 of `docs/ARCHITECTURE.md`). `settleBatch`
reverts with `InCloseOnly` once close-only trips, so normal automatic settlement
stops — but users can still submit reduce-only closes off-chain, and those closes
need a way to become claimable withdrawals. `finalSettle` is that way: it skips
the close-only / slashed / bond guards `settleBatch` enforces, but keeps the same
ZK-proof gate, prev-root continuity, and SEC-019 deposit-prefix pin, so governance
can only advance **proof-valid** state over deposits that genuinely landed — it
can never fabricate a balance. It is repeatable (call
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

`finalSettle` takes exactly the same nine parameters as `settleBatch` — seven
roots (`prevRoot`, `manifestHash`, `newRoot`, `orderedRoot`, `withdrawalsRoot`,
`rejectedRoot`, `depositsRoot`), the `uint64 newDepositCount`, and the `bytes`
proof. There is no separate "wind-down" proof format. Compute them the identical
way a normal settle does (see `docs/PROVING-RUNBOOK.md`):

1. Build the pending window's witness — the `(pre_state, ops, manifest)` covering
   whatever reduce-only closes landed off-chain since the last settled root
   (`sequencer::WindowWitness`, the same structure `seal_window` produces during
   normal operation).
2. Derive the roots LOCALLY by replaying that witness with
   `perp_core::commitment::derive_roots` — exactly what the gateway's
   `prove_and_prepare` (`crates/gateway/src/prover_client.rs`) does. This yields
   all seven roots, including `depositsRoot` (the post-batch deposit hash-chain
   tip), and the post-replay state whose `consumed_deposit_count` is
   `newDepositCount`. Under SEC-025-B the prover is trusted for NOTHING but the
   proof bytes — every submitted root is derived here, never taken from the
   service.
3. Seal the witness to the prover's measurement + seal root
   (`crates/prover::SealedWitness::seal`, the `0xAB…` stand-in measurement /
   `PROVER_SEAL_ROOT` (`0x5E…` default) in the current dev deployment — see
   §10b's honesty note in `ARCHITECTURE.md`).
4. `POST /prove` to the attested prover-service. Its response is
   `{prev_root, manifest_hash, new_root, ordered_root, withdrawals_root,
   rejected_root, commitment, proof}` — note it does NOT include `depositsRoot`
   or `newDepositCount`, and its itemised roots are diagnostic only
   (`RemoteProveResp` in `crates/gateway/src/prover_client.rs`). Check its
   `commitment` equals the keccak commitment over YOUR seven locally derived
   roots, then take ONLY the `proof` bytes from it.

`newDepositCount` is the **cumulative** post-state `consumed_deposit_count`, not
a per-window count: a zero-deposit wind-down window over a pre-state that has
already consumed five deposits submits **5**. `finalSettle` runs the same
`_requireDepositPrefix` pin as `settleBatch`: `depositsRoot` must equal the
vault's deposit-chain tip at that count. Deposits are refused in close-only, so
the chain is frozen — for a depositless wind-down window both values carry
forward unchanged from the last settled state. Pre-check before submitting:

```bash
VAULT=0x...   # CollateralVault address (settlement's `vault()`)

cast call $VAULT "depositTipAt(uint64)(bytes32)" <new_deposit_count> --rpc-url $RPC
# must equal your locally derived depositsRoot
```

`prev_root` MUST equal the settlement's `currentStateRoot()` at call time
(`BadPrevRoot` otherwise — `finalSettle` keeps prev-root continuity, it does not
relax it). If the gateway already computed and cached a `ProveOutcome` for this
window before `settleBatch` started reverting (e.g. from the rollback journal),
that same outcome is valid to resubmit here — it carries `deposits_root` and
`new_deposit_count` too; reuse it rather than re-proving.

### Before a cutover: verify guest/native parity

`prover-service` now fails `/prove` if the guest's committed public value differs
from the natively derived commitment (SEC-025-B §2). That check is the continuous
defence, but it only fires once a proof has been produced. Before a cutover,
confirm the guest ELF and the host `perp-core` are the same code by building both
from the same commit and running the `sp1-host` comparison binary
(`crates/sp1-host`, `cargo run --release` — executes the guest and asserts the
native and zkVM commitments are byte-identical). A mismatch here presents as "the
prover disagrees" during settlement, not as a build error.

## 3. Submit

```bash
cast send $SETTLEMENT \
  "finalSettle(bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,uint64,bytes)" \
  <prev_root> <manifest_hash> <new_root> <ordered_root> <withdrawals_root> <rejected_root> <deposits_root> <new_deposit_count> <proof> \
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

## Ops note: settle cadence — proofs on a quiet chain are expected

Since SEC-025-B, `begin_window_settle` no longer skips a window just because the
engine root did not move: a window whose **manifest** carries content settles
anyway. Settling is what populates the challenge-answer store, and both on-chain
answer paths require a settled batch — so a root-only predicate left an honest
sequencer unable to answer a ripe inclusion challenge (a wrongful-slash vector).

Operationally: a **rejected or resting user order now forces a real proof and a
`settleBatch` for an otherwise quiet window**, even though no balance moved. This
is bounded at one settle per window — the design maximum — and it is the correct
trade against the wrongful-slash vector; do not treat proofs on a quiet chain as
an anomaly. Genuinely idle windows still burn no proofs: the house MM emits a
counter-order only when a user order crosses the mark (it does not rest quotes
every tick), so a window with no user activity carries an empty manifest and
settles nothing.

## 4. Out of scope (tracked follow-up)

The gateway does not currently detect close-only or automatically route a
computed settle through `finalSettle` instead of `settleBatch` — this entire
procedure is manual. Automatic gateway routing (detect `closeOnly()`, switch the
L1 call target, and stop retrying the now-permanently-reverting `settleBatch`
path) is a tracked follow-up, not delivered in this pass.

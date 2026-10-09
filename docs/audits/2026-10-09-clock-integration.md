# Clock-bound proving integration candidate — 2026-10-09

Status: **source integration candidate, release BLOCKED**. This work extends
the prototype from PR #30 at `f91fbd81841785f7bae88cb50c898653114a72c5`.
PR #30 was merged independently while this work was in progress; this candidate
was moved to a separate branch from `45f6a1c`, whose tree is identical to that
tested base. No existing source file changed during that branch transition.
No existing live contract, vault, deployment record, or production service was
changed. The deployment procedure below is a required review, not an executed
migration. This is clock-envelope version 2, NOT matching/fairness Proof-v2.

## Implemented connection

`gateway immutable WindowWitness -> encrypted durable registration intent ->
ClockBoundVerifier.register -> canonical finalized receipt -> sealed version-2
witness -> prover-service/AttestedProver -> SP1 guest -> bound public digest ->
existing settlement entrypoint -> ClockBoundVerifier -> inner SP1 verifier`.

The gateway and guest derive time bounds and the number of timed operations from
the original execution log. They do not replace historical oracle transcripts,
change funding timestamps, or read the current wall clock during replay.
Every timed operation retains the existing publisher-signature and oracle-freshness
checks. Backward operation times are rejected. Price-free batches have canonical
zero bounds and count, but still register a context.

The manifest hash alone does not authenticate time. A new-deployment
`ClockBoundVerifier` wraps the existing `IZkVerifier` interface so that all three
settlement paths (`settleBatch`, `finalSettle`, `finalExit`) require a registered
context without adding an alternate unguarded settlement entrypoint. It forwards
only the clock-bound public digest to its immutable inner verifier. On-chain
batch/root advancement makes a consumed record unusable for a later batch.

The settlement binding is one-time and verifies the circular deployment relation.
Registration requires the current batch, previous root and phase and the existing
sequencer/governance role. Replacements are refused; an identical retry retains
the original registration time. The receipt binds chain ID, adapter and settlement
addresses, batch, previous root, the full base transition commitment, phase,
derived bounds/count, registration time and both timing-policy parameters.

## Encoding and compatibility

- `DPCLK2\0\0` prefixes the sealed plaintext's new postcard four-tuple:
  `(state, operations, manifest, ClockContext)`.
- Native prover and guest both use strict decoding with no trailing bytes.
  Invalid version-2 payloads never fall back to legacy decoding.
- The receipt and outer digest use standard 32-byte ABI big-endian words and
  left-padded addresses, not the core's legacy little-endian word helpers.
- The public digest is `keccak256(abi.encode(domain, baseCommitment, receipt))`.
  Rust and Solidity share an independently generated fixed encoding vector.
- `PublicInputs.clock_receipt=None` remains an explicit legacy path for existing
  development fixtures. The clock-required client and adapter reject downgrade.
- The gateway WAL retains the base commitment. Its internal proof envelope is
  `DPCLPR2\0 || receipt || proof`; the send path checks a canonical finalized
  receipt again and removes this envelope before the contract call.
- No positional field was added to `RollbackJournal` or its prepared outcome.
  `Some(prepared)` with an empty proof now also represents a durable registration
  intent. Empty proofs are never broadcast. Its unchanged recovery table holds
  this intent instead of treating it as permission to roll back a pending send.

## Actual gateway and prover paths

The configured `HttpProverClient` seals the new witness through the existing
attested/session provider and sends it through the existing authenticated `/prove`
endpoint. Session reauthentication keeps the same immutable clock context.
The service's `AttestedProver.prove_batch` derives the bound public inputs before
passing the original bytes to the SP1 backend. The modified guest performs the
same clock validation; the existing backend checks native/guest public-value
agreement. Building or executing that real guest is a separate validation gate.

`CLOCK_BOUND_VERIFIER` selects the adapter and requires an explicit nonzero
`L1_CHAIN_ID`. Production startup now requires clock mode, a real configured
prover and `DARKPERP_STATE` durability. This is a coordinated upgrade requirement,
not permission to restart an old production deployment with the new binary.
The legacy `sp1-host::native_from_bytes` sample harness remains legacy-only;
version-2 native coverage uses the actual shared prover-service library path.

The live settle loop first persists its post-seal snapshot, then the unproved
intent, before attempting registration. After a potentially broadcast registration,
errors retain the exact WAL and enter a recovery hold rather than merging newer
operations into that batch. Boot recovery can re-prove/resubmit the exact journaled
window only after canonical batch/root checks. A changed or unfinalized receipt
keeps the journal and refuses startup. No chain mutation was executed in this review.

## Clock source and liveness limits

The clock is the **settlement chain's block.timestamp**, which is Base L2 time on
Base. It is not a direct Ethereum L1-origin attestation. Registering before slow
proof generation separates freshness at execution/registration from proof delay.
The earliest admissible observation can be as old as `maxWindowMs + clockSkewMs +
market.max_oracle_staleness_ms` relative to registration. Policy values must be
reviewed with the intended execution cadence; tests do not approve production
parameters. Idempotent retry of an already accepted record does not expire it.

**Unfinished release blockers:**

1. Long-proof queue admission/backpressure is not implemented in this candidate.
   New operations can accumulate while a proof is in flight; the next window may
   exceed the configured timing bounds and enter HOLD. Do not widen timing bounds
   or rewrite operation times just to hide this liveness failure.
2. Registration finality is fail-closed, but its complete wait/retry scheduling and
   an end-to-end reorg/crash/restart/HTTP-prover/chain failure matrix are not yet
   demonstrated. Immediate finalized reads commonly cannot observe a fresh record;
   this candidate then requires an exact-journal restart after finality, not an
   automatic rollback or a switch to `latest`.
3. The updated real SP1 ELF, native/guest execution parity, vkey and real Groth16
   proof have not been generated/verified in this work. Workspace tests are not
   a substitute for the excluded host/service build or for guest execution.
4. New inner SP1 verifier, adapter, settlement and vault funding/migration need
   reviewed deployment evidence. No existing vault balance is migrated by keeping
   a state-root encoding unchanged. A mock inner verifier must never hold real
   collateral. Do not merge/deploy this candidate as a production fix.

Rejection-reason proof, custody/prover privacy and emergency-exit economics remain
separate, open work. No financial loss-distribution policy changed here.

## Validation scope

New tests cover native v2 constraints and encoding (8), gateway context/envelope/
configuration/WAL behavior (8), and real settlement entrypoints with an explicitly
mock proof backend (21). The existing Solidity suite plus those tests is 118 tests.
The earlier isolated prototype is retained as an experiment, not a deployed component.
Full-suite command results and exact source hashes are recorded with this PR's
verification evidence. No real-proof claim is made by any mock-backed test.

# contracts — L1 settlement (Faz 2)

Foundry project for dark-perp's Ethereum settlement layer (§1, §3, §6). The
contracts hold the trust split that makes the protocol safe even if the sequencer
is compromised: **anchor + accountability here, custody in the vault, no operator
fund authority anywhere** (§0, §10, ADR-0010).

| Contract | Role | Arch ref |
|---|---|---|
| `DarkPerpSettlement` | anchors the state root via verified ZK proofs (SETTLED); records the consumed deposit count; irreversible close-only (liveness, deposit-inclusion timeout, governance); bond-capacity deposit gate; inclusion-challenge game with capped fines | §2, §3, §6 |
| `CollateralVault` | holds USDC; deposits need a gateway permit with a deadline; releases funds only against a settled withdrawals root; refunds unconsumed deposits in close-only | §3, §6 |
| `ClockBoundVerifier` | wraps the inner proof verifier; every settle path needs a pre-proof clock registration; a stale anchor can be cancelled after `anchorTimeoutMs` | §4 |
| `IZkVerifier` / `SP1ZkVerifier` / `MockZkVerifier` | proof verifier interface, the SP1 adapter, and the unsound test stand-in | §4 |
| `MerkleLib` | sorted-pair keccak membership (inclusion + withdrawals) | §2 |

`DarkPerpSettlement.ABI_VERSION()` is `3`. The gateway reads it at boot and refuses
to run against any other value.

## Settlement behaviour (ABI version 3)

**Constructor.** `constructor(Config c)` takes one static struct, ABI-identical to
twelve flat words in this order: `sequencer`, `enclaveSigner`, `verifier`,
`genesisRoot`, `livenessTimeoutBlocks`, `challengeGraceBlocks`, `challengeBond`,
`inclusionDeadlineSecs`, `governance`, `finalSettleGraceBlocks`, `progressBatches`,
`slashPayoutCap`. It reverts `InvalidConfig()` for a zero sequencer, enclave signer or
governance, a verifier without code, a zero liveness or grace, `progressBatches`
outside 1..16, or a `slashPayoutCap` of zero or above `uint128` max. The verifier must
also look like a fresh clock verifier: `proofVersion()` returns 2 and `settlement()`
returns zero. A directly wired `MockZkVerifier` or `SP1ZkVerifier`, or a clock verifier
already bound to another settlement, is refused.

**Vault pairing.** `setVault(v)` (sequencer, once) requires `v` to be a contract whose
`settlement()` is this settlement, else `VaultMismatch()`.

**Deposit boundary.** Every settle path (`settleBatch`, `finalSettle`, `finalExit`)
pins `depositsRoot` to `vault.depositTipAt(newDepositCount)`, with
`consumedDepositCount <= newDepositCount <= vault.depositCount()`, and stores
`consumedDepositCount = newDepositCount`. Wind-down paths require
`newDepositCount == consumedDepositCount` (`DepositsFrozen()`), so the boundary never
moves once close-only begins.

**Close-only** is irreversible. It can be entered in three ways:

- `triggerCloseOnly()` (anyone) when the root has not progressed for more than
  `livenessTimeoutBlocks`. This path applies once the stack holds something to protect
  (a settled batch, a vault deposit or an open challenge); the window is still measured
  from `lastProgressBlock`.
- `triggerCloseOnly()` (anyone) when the oldest deposit the settled state has not
  consumed landed more than `livenessTimeoutBlocks` ago.
- `enterCloseOnly()` (governance), immediately.

Entering latches `closeOnlyBlock` and `closeOnlyBatchCount` and emits
`CloseOnlyEntered(reason)` with `"liveness timeout"`, `"deposit inclusion timeout"` or
`"governance"`.

**Bond capacity.** `requiredBond() = vault.tvl() * BOND_BPS / 10_000` with
`BOND_BPS = 500`. Before each deposit the vault asks `depositGate(tvl + amount)`; a
deposit that would raise `requiredBond()` above `sequencerBond` reverts
`BondCapacityExceeded()`. `depositCapacity()` reports the remaining headroom (about
20 times the bond, minus TVL). `settleBatch` does not check the bond, so settlement and
exits never stop on it. `withdrawBond` releases only the excess above
`max(requiredBond(), openChallengeCount() * slashPayoutCap)`, in close-only too.

**Inclusion challenges.**

- `challengeInclusion(orderHash, seqNo, recvTimeMs, batchIdHint, beneficiary, sig)`
  takes an enclave-signed authorization over `challengeAuthDigest(...)`, which binds
  the chain id, this settlement and the beneficiary a fine would be paid to.
- Anyone may submit it with exactly `challengeBond` wei, once
  `recvTimeMs / 1000 + inclusionDeadlineSecs` has passed. Each order hash can be
  challenged at most once (`challengeResolved`).
- Answers are permissionless and stay valid until a slash or release lands:
  `answerChallenge`, `answerByRejection`, or the batched
  `answerChallenges(batchId, orderHashes, byRejection, proofs)`, which skips entries
  that are no longer open. Open challenges are enumerable through
  `openChallengeCount()` and `openChallenges(start, max)` (pages of at most 512).
- `slashUnanswered(orderHash)` needs `progressBatches` phase-0 batches settled since
  the challenge opened, plus `challengeGraceBlocks` after the settle block of the last
  of them.
  - It pays `min(sequencerBond, slashPayoutCap)` to the beneficiary
    (`pendingUsdc`) and returns the stake to the submitter (`pendingEth`).
  - Settlement continues; the smaller bond lowers deposit capacity until it is topped
    up.
  - When the bond is below the cap, only the beneficiary may trigger the reduced fine.
    A submitter who is not the beneficiary may do so only `livenessTimeoutBlocks` after
    the slash first became possible, and nobody else may trigger it at all.
- `releaseStaleChallenge(orderHash)` refunds the stake of a challenge that close-only
  stopped from ever reaching the progress gate.
- Credits are pulled with `claimEth()` / `claimUsdc()`, or `claimEthTo(to)` /
  `claimUsdcTo(to)` to pay another address.

**Vault deposits and refunds.**

- `deposit(amount, ownerCommit, validUntil, sig)` requires a gateway permit over
  `permitDigest(from, ownerCommit, amount, validUntil)`. The digest is
  `keccak256(abi.encodePacked(DEPOSIT_PERMIT_TAG, chainid, vault, from, ownerCommit,
  amount, uint256(validUntil)))`, a 200-byte preimage.
- It refuses, in order: `BadAmount()` (zero or above `int128` max), `InCloseOnly()`,
  `BondCapacityExceeded()`, `DepositsPaused()`, `PermitExpired()`, `BadGatewaySig()`,
  `OwnerCommitUsed()`. Each owner commitment enters the deposit chain at most once.
- In close-only, `refundDeposit(id, from, ownerCommit, amount, to)` (anyone) returns
  the principal of any deposit with `id >= consumedDepositCount`. The arguments are the
  fields of the `Deposit` event and are checked against the deposit chain link at
  `id`. The refund goes to `from`, or to `to` when `from` itself sends the call.
- `claim` refuses to dip into the principal of deposits the settled state has not
  credited (`ReservedForUncredited()`, see `refundableOutstanding()`).

## Clock verifier

`ClockBoundVerifier(inner, maxWindowMs, clockSkewMs, anchorTimeoutMs)` takes four
words; `anchorTimeoutMs` must be at least 1000. `cancel(batchId, phase, receipt)`
removes the current batch's anchor once it is at least `anchorTimeoutMs` old (block
time). Only the role that may register that phase can cancel it: the sequencer for
phase 0, governance for phases 1 and 2. A cancelled receipt is recorded in
`cancelledReceipt` and never verifies again; a re-registration gets a new receipt.
Before the timeout an anchor stays immutable (`ReplacementForbidden`).

## Cross-layer binding (locked by tests)

The contract hashing is byte-identical to the Rust producers, so one receipt /
one proof works on both sides:

- `publicCommitment` ↔ `crates/prover::PublicInputs::commitment`
- `receiptDigest` ↔ `perp-core::Receipt::signing_digest` (kept as a cross-layer
  helper; it is not accepted as a challenge authorization)
- a receipt **signed in Rust** (`crates/sequencer`, secp256k1) recovers on-chain via
  `ecrecover`; see `test/CrossLayer.t.sol`. Vectors come from
  `crates/prover/tests/vectors.rs` and `crates/sequencer/tests/fixture.rs`.
- the challenge-authorization digest (`challengeAuthDigest`) and the deposit-permit
  digest (`permitDigest`) are pinned there too, as known-answer vectors computed with
  `cast` and signed with the same fixture keys the Rust signers use.
- the deposit leaf, deposit-chain fold and `Deposit` event are unchanged, so the
  gateway's ingestion and the guest read the same chain.

## Build & test

Foundry only (no Hardhat). `forge-std` is unavailable in the sandbox (repo-scoped
git proxy), so tests use the vendored `test/utils/MiniTest.sol` harness.

```bash
cd contracts
forge build
forge test
```

## Deploy

**Release deployments use `scripts/local-verification/deploy_clock_stack.py`**, the
only path `release_manifest.py observe-target` checks (see
`docs/REDEPLOY-CC-RUNBOOK.md` and `docs/RELEASE_MANIFEST.md`).

`script/Deploy.s.sol` is a testnet/dev harness only. It wires a clock-bound stack
over the unsound `MockZkVerifier`, in this order: `MockZkVerifier` →
`ClockBoundVerifier` → `DarkPerpSettlement` → `MockUSDC` → `CollateralVault` →
`setVault` → `bindSettlement` → seed mint, plus an optional `INITIAL_BOND`
approve and `postBond`. It returns `(settlement, vault, clock, usdc)` and checks the
wiring afterwards.

```bash
# dry-run simulation (no RPC needed)
forge script script/Deploy.s.sol

# broadcast to a testnet
PRIVATE_KEY=0x... GATEWAY_SIGNER=0x... ENCLAVE_SIGNER=0x... GOVERNANCE=0x... \
GENESIS_ROOT=0x... INITIAL_BOND=50000000000 \
  forge script script/Deploy.s.sol --rpc-url $BASE_SEPOLIA_RPC --broadcast
```

It refuses to run when:

- `VERIFIER` or `INNER_VERIFIER` is set (it never wires a real verifier);
- off the local anvil chain (31337), `PRIVATE_KEY`, `GATEWAY_SIGNER`,
  `ENCLAVE_SIGNER`, `GOVERNANCE` or a non-zero `GENESIS_ROOT` is missing;
- `PRIVATE_KEY` or `GATEWAY_SIGNER` is a default anvil account (a fork dry run that
  really wants them sets `ALLOW_PUBLIC_DEV_KEYS=1`);
- the chain is outside `DeployGuard`'s testnet allowlist (`ALLOW_MOCK_VERIFIER=1`
  overrides, unsafe);
- a clock parameter is below 400 ms.

Defaults assume Base's 2 s blocks:

| Env | Default |
|---|---|
| `LIVENESS_BLOCKS` | 43,200 (24 h) |
| `CHALLENGE_GRACE_BLOCKS` | 3,600 (2 h) |
| `CHALLENGE_BOND` | 0.01 ether |
| `INCLUSION_DEADLINE_SECS` | 3,600 |
| `FINAL_SETTLE_GRACE_BLOCKS` | 300 |
| `PROGRESS_BATCHES` | 2 |
| `SLASH_PAYOUT_CAP` | 1,000e6 (USDC base units) |
| `MAX_WINDOW_MS` / `CLOCK_SKEW_MS` | 30,000 / 30,000 |
| `ANCHOR_TIMEOUT_MS` | 3,600,000 |
| `INITIAL_BOND` | 0 |

With `INITIAL_BOND=0` the capacity is 19 base units, so the vault refuses any real
deposit until a bond is posted (the gateway's bond top-up normally does this).

## Not production

`MockZkVerifier` is **not sound**; it is the testnet stand-in for the real
SP1 verifier (see `../docs/PROVING.md`). `Deploy.s.sol` only ever wires it, so never
use that script for a stack that holds real value.

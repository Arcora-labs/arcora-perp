# Synthetic wallet lifecycle and exact clock guest replay

The opt-in gateway test runs an owned loopback HTTP server and a disposable Anvil
chain. Three fixed public fixture wallets deposit 50,000 test USDC, place four
signed sealed orders to open and close positions, settle four consecutive windows,
then claim 20,000 test USDC. Anvil allocates its port with `--port 0`; the test
reads that port only from its owned child's startup output and drains subsequent
output without printing the fixture-key banner. It uses the real contract
constructors (the settlement's twelve-word `Config`, the four-word clock
constructor), ERC20 allowances, deposit permits and ingestion, clock registration,
the `ClockBoundVerifier`, settlement and vault. The inner verifier is explicitly
`MockZkVerifier`. The gateway reads the settlement's deposit terms through a
read-only L1 bridge; the test sends every transaction itself.

Beyond the wallet windows, the run checks:

- **Bond before deposits.** Without a bond the capacity is 19 base units: the
  gateway refuses the permit (`409` with the capacity) and the vault reverts
  `BondCapacityExceeded`. The bond is then posted before the first deposit.
- **Permits.** Each permit carries `validUntil`; a held permit is re-signed with the
  same deadline and signature; an expired, altered or replayed permit is refused.
- **Capacity, first come first served.** A request above the remaining capacity is
  refused with `409`. Two permits that each fit are issued; the first deposit lands
  and the second reverts `BondCapacityExceeded`.
- **Inclusion challenge.** An order's `l1Challenge` matches the settlement's
  `challengeAuthDigest` and recovers to `enclaveSigner()`. A challenge is opened,
  the gateway's open-set read plans the answer once the batch settles, a third
  party sends it, and the stake returns to the submitter.
- **Keepalive.** After a quarter of `livenessTimeoutBlocks` without progress, an
  idle gateway settles an empty, untimed window.
- **Close-only and refund.** A credited deposit no settled batch consumed is
  `credited_unsettled`. With no further progress, `LivenessLow` fires at half the
  window and a non-operator calls `triggerCloseOnly()` after it. The gateway latches
  close-only at a finalized block: `mode` reads `CloseOnly`, permits are refused,
  and the deposit is `refundable` in the confirm and account views. With the
  gateway stopped, both settled withdrawals are claimed, and a non-depositor
  refunds the deposit to its depositor; consumed, redirected, altered and repeated
  refunds are refused.

Each window writes its unproved encrypted journal before clock registration.
The adapter rejects both malformed proof bytes and a legacy unbound commitment.
The last window reloads its encrypted snapshot and journal after settlement was
mined but before local bookkeeping. This is a same-process recovery test, not an
OS crash or a production service-loop test.

Both users save their published root and Merkle claim data before the HTTP gateway
and its writer are stopped and both tasks are awaited. The test checks that the listener is closed, then each
wallet claims directly from the vault and verifies its token balance increase.
This demonstrates the local previously-published-claim outage path. New withdrawal
publication still requires the operator/prover; missing claim data is not recovered
by this test.

```sh
forge build --root contracts
ARCORA_FUNDS_WITNESS_DIR=/tmp/arcora-funds-witness-NEW \
  cargo test -p gateway funds_lifecycle_tests --locked -- --ignored --nocapture
```

The export directory must not already exist. It contains only generated test data:
four exact v2 witness byte streams, the keepalive's empty window
(`keepalive-batch-4.witness.bin`, listed under `keepalive`) and a final
`lifecycle.json` linking their hashes to each local transaction, commitment and root. This export is available only in
the test harness; it does not add witness export to the production gateway.
The 60-second window/skew is a test policy, not a production recommendation.

`replay-funds` checks the complete four-window sequence, witness hashes, normal
phase, chain and contract identity, empty deposit genesis, state-root continuity,
conservation, deposit prefix, withdrawal roots and clock receipts. It then executes
the unchanged reviewed SP1 guest on each exact input and compares all committed
public values with native replay. It refuses an ELF hash different from the
reviewed clock guest.

Build with Rust 1.99, the installed `succinct` toolchain, SP1 SDK/build 6.1.0,
and `protoc` in PATH (or `PROTOC` pointing to it). Put rustup's cargo/rustc shims
before another system Rust installation. The host build script builds the guest;
do not set `SP1_SKIP_PROGRAM_BUILD` when claiming a fresh source build.

```sh
CARGO_BUILD_JOBS=2 cargo +1.99.0 build --manifest-path crates/sp1-host/Cargo.toml \
  --locked --offline --release --bin replay-funds
crates/sp1-host/target/release/replay-funds \
  /tmp/arcora-funds-witness-NEW /tmp/arcora-funds-replay-NEW \
  --elf contracts/integration/fixtures/clock-v2-verified/guest.elf
python3 scripts/local-verification/verify_funds_replay.py \
  --binary crates/sp1-host/target/release/replay-funds \
  --elf contracts/integration/fixtures/clock-v2-verified/guest.elf \
  --witness-dir /tmp/arcora-funds-witness-NEW \
  --output-dir /tmp/arcora-funds-replay-guards-NEW
```

`--elf` explicitly selects a reviewed artifact, still requiring its exact pinned
hash. The report labels it as an explicit artifact; that is not a source build
claim. Without `--elf`, the host's freshly built embedded guest is used and must
match the same pin. The first new-checkout and path-remapped builds differed from
the reviewed ELF. Investigation found both embedded source paths and Cargo's
path-dependent crate metadata identities. A later clean-target build normalized
only the two reviewed workspace crate identities and paths, reproduced the exact
reviewed ELF, and a fresh CPU setup derived the same pinned program key.
The [reproduction evidence](audits/2026-10-09-followup/clock-lifecycle/reproducible-build/README.md)
preserves both initial mismatches and the successful compiler arguments. This is
a same-machine build using cached dependencies, not an independent cold build or
a fresh proof. The replay tool never changes the ELF/vkey pins.

The separate recipe requires Python 3.11+, Cargo 1.99.0 and the recorded ARM64
macOS SP1 compiler. It verifies all 21 source pins, the exact source layout and
absence of extra build/config inputs before normalization and again after build.
It uses `--locked --offline`, creates an exclusive empty target outside the source
checkout, preserves existing targets, and writes its success manifest only after
the independently pinned ELF hash matches. Select a new output path each time:

```sh
python3.11 scripts/local-verification/rebuild_reviewed_guest.py \
  --cargo "$HOME/.cargo/bin/cargo" \
  --rustc "$HOME/.sp1/toolchains/z4qbuzauUe/bin/rustc" \
  --output-dir /tmp/arcora-reviewed-build-NEW
```

Use the resulting `target/riscv64im-succinct-zkvm-elf/release/perp-core-guest`
as replay's `--elf` argument and retain the build manifest alongside the replay
manifest. Replay itself cannot establish how its supplied ELF was built.

`--native-only` performs the input validation and native continuity stage without
initializing the SP1 CPU executor. Its report explicitly sets `guest_executed` and
`native_guest_equal` to false. Use it for artifact negative controls, not guest
evidence. Output directories are always new and completion manifests are written
last. The executor uses the local CPU client, never a proving-network client.
The guard runner first requires successful native replay, then rejects a missing
or reordered window, a substituted commitment, changed witness bytes, trailing
wire bytes, a legacy witness, and a symlinked witness file. Infrastructure failures
do not count as successful rejection.

Execution cycles/time are useful diagnostics, not proof generation p95, memory
capacity, production admission downtime, or finality measurements. No fresh proof
is produced by this tool and the lifecycle still settles using the mock inner
verifier. R01/R03 require fresh proofs for these same inputs and the target service
and chain path before their release gates can close.

## Operator-free claim from a saved bundle

The test above shows that a user who kept their claim data can claim while the
gateway is gone. The web client now keeps that data for every user:

- When a withdrawal becomes claimable, `WithdrawalsSection` stores its claim
  bundle (`arcora.claim-bundle.v1`: chain id, vault, recipient, amount as a
  decimal string, nonce, leaf, published root and Merkle proof) in this
  browser's storage.
- **Download claim file** saves that bundle. **Export all claim files** saves
  every bundle kept so far as one JSON array, including entries the gateway no
  longer lists.
- The bundle stays with the user. It is never sent anywhere, and leaves are not
  published to anyone else: a public leaf list would reveal recipient and amount
  before the claim does.

`scripts/claim/claim_withdrawal.py` checks a bundle without the gateway:

```sh
python3 scripts/claim/claim_withdrawal.py arcora-claim-84532-3-aaaaaaaa.json \
  --rpc https://sepolia.base.org
```

It recomputes `keccak256(abi.encodePacked(to, amount, nonce))` and folds the
proof with the vault's sorted-pair rule in pure Python. With `--rpc` it then
makes three read-only `cast` calls: `chain-id`, `rootPublished(root)` and
`claimed(leaf)`. Finally it prints the exact
`cast send … "claim(address,uint256,uint256,bytes32,bytes32[])" …` call. The
tool never signs or sends. Anyone may send the claim with their own signer flags,
because the vault always pays `to`.

The Python tree is pinned to the Rust one:
`scripts/claim/fixtures/withdrawal-vectors.json` is regenerated by
`make_vectors.py`, and the gateway test
`withdrawals::tests::claim_tool_vectors_match_rust_tree` checks every leaf,
root and proof in it against perp-core. The keccak and leaf vectors in the
Python tests come from `cast`.

**Limits.**
- A bundle exists only for withdrawals that were claimable while the user had
  the page open. A browser that never saw one, or cleared its storage without a
  download, has nothing to recover.
- Balances and positions that were never withdrawn into a published root still
  need the operator or prover path (`finalSettle` / `finalExit`, see
  FINAL_SETTLE_RUNBOOK.md). Deposits that no settled batch consumed do not: in
  close-only they are refunded from the vault (next section).
- This is not a data-availability archive.

## Challenge kit for an order the sequencer never settles

An accepted order's receipt carries `l1Challenge`, the enclave's authorization to
open `challengeInclusion` for that order (docs/API.md, § L1 inclusion challenges).
If no settled batch ever includes or rejects the order, the user needs this
authorization after the fact, possibly when the gateway no longer answers. The web
client keeps it:

- When `POST /v1/orders` accepts an order, the client stores the order's challenge
  kit (`arcora.challenge-kit.v1`) in this browser's storage. The kit holds the
  receipt fields `challengeInclusion` takes (`orderHash`, `seqNo`, `recvTimeMs`,
  `batchIdHint`), the receipt's `enclaveSigner` and `l1Challenge` (`chainId`,
  `settlement`, `beneficiary`, `signature`). The accept response's copy is kept
  because it names the address bound at acceptance.
- The account panel also keeps the kits of orders the gateway lists with an
  authorization, for example orders placed from another browser. Kits are merged
  by order hash, and the first copy is kept.
- A kit is kept only when its signature recovers to the receipt's enclave signer.
  Receipts without an authorization (`null` when the account has no bound deposit
  address) produce no kit.
- **Download challenge kit** saves one order's kit. **Export all challenge kits**
  saves every kit kept so far, including orders the gateway no longer lists. Kits
  are never sent anywhere. If browser storage is denied, the panel still offers
  the kits of the orders it can see, for that session only.

The kit file has the shape of a receipt, so the gateway-free tool reads it as is,
one kit or the exported array:

```sh
python3 scripts/claim/challenge_inclusion.py arcora-challenge-84532-0-0c164689.json \
  --rpc https://sepolia.base.org
```

The tool recomputes `challengeAuthDigest` and recovers the signer offline. With
`--rpc` it reads the settlement (chain, `enclaveSigner()`, the on-chain digest,
close-only, whether the order's challenge is open or resolved, `challengeBond()`
and the ripeness time). It then prints the `cast send … challengeInclusion(…)
--value <bond>` call, or the slash, release or claim call for a later stage, with a
`<YOUR_SIGNER>` placeholder. It never signs or sends.

`scripts/challenge/fixtures/challenge-kit-vectors.json` pins the browser format to
the tool. `frontend/src/domain/challengeKit.test.ts` builds its `kit` from its
`acceptReceipt`. `scripts/challenge/test_challenge_kit.py` runs that kit, and
tampered copies of it, through `challenge_inclusion.py`. Authorization A in the
fixture is the vector that `crates/gateway/src/challenge_auth.rs` and
`contracts/test/CrossLayer.t.sol` pin.

**Limits.**
- A kit exists only for orders this browser placed, or saw in the account panel
  while the gateway listed them. A browser that cleared its storage without a
  download has nothing to recover.
- Opening a challenge publishes the beneficiary next to the order hash on L1. Keep
  the files private unless you intend to use them.
- A challenge does not execute the order. Anyone may answer it by proving the
  order's inclusion or rejection; if nobody does, the beneficiary is credited the
  fine (docs/API.md, § L1 inclusion challenges, Outcomes).

## Refund of a deposit the settled state never consumed

A deposit enters the vault's deposit chain when it lands on L1, but it becomes part
of the settled state only when a settled batch consumes it. The settlement records
that boundary as `consumedDepositCount()` on every settle. Deposits with an id at or
above it have not been credited by any settled batch.

Once the settlement is in close-only, that boundary is frozen: ordinary settlement
stops, and both wind-down entrypoints require the same count. From then on every
deposit above the boundary is refundable at principal, straight from the vault:

- **Who:** anyone may send `refundDeposit(id, from, ownerCommit, amount, to)`. The
  funds go to the deposit's payer `from`. Only `from` itself may name a different `to`,
  for example when the token refuses to pay `from`.
- **What it needs:** only public L1 data. The arguments are the fields of the
  deposit's `Deposit` event, and the vault checks them against its own chain link at
  `id`. No gateway, prover, governance or saved bundle is involved.
- **When:** as soon as `closeOnly()` is true. Refunds do not wait for the wind-down
  grace or for `finalSettle`.

Close-only can start in three ways, and every one makes refunds available:

1. **Liveness.** The state root has not progressed for `livenessTimeoutBlocks`, and
   the stack holds a settled batch, a deposit or an open challenge. Anyone may then
   call `triggerCloseOnly()`. The gateway settles an empty keepalive batch while the
   exchange is idle, so an idle but healthy operator does not reach this timeout.
2. **Deposit inclusion.** The oldest unconsumed deposit landed more than
   `livenessTimeoutBlocks` ago. Anyone may then call `triggerCloseOnly()`, even while
   other batches keep settling. A settling sequencer therefore cannot hold a landed
   deposit indefinitely.
3. **Governance.** `enterCloseOnly()`, as an emergency brake or to move users to a
   new stack.

A deposit the gateway had already credited off-chain, but that no settled batch
consumed, is also refunded at principal. Trades in windows that never settled are
discarded with it; only settled state is withdrawable.

**Claims cannot consume refundable principal.** `claim` reverts
`ReservedForUncredited` if paying it would leave the vault holding less than
`refundableOutstanding()`, the principal of unconsumed deposits that were not
refunded yet. This holds in live mode and in close-only.

`scripts/claim/refund_deposit.py` performs the same checks without the gateway,
through a read-only RPC. It finds the `Deposit` log by transaction (`--tx`), by
deposit id (`--id`) or for every unconsumed deposit of one payer (`--from`), and
checks it against the vault's deposit chain. It then reports whether the deposit
was credited, refunded or is refundable, whether close-only is set, and whether
(or from which block) anyone may call `triggerCloseOnly()`. Like
`claim_withdrawal.py`, it never signs or sends; it prints the exact calls:

```sh
python3 scripts/claim/refund_deposit.py --rpc https://sepolia.base.org \
  --vault <VAULT> --from <YOUR_DEPOSIT_ADDRESS>
```

`--to` sets another recipient, which only works when the payer itself sends the
refund. The calls the tool prints are:

```sh
cast send <SETTLEMENT> "triggerCloseOnly()" --rpc-url https://sepolia.base.org <signer flags>
cast send <VAULT> "refundDeposit(uint64,address,bytes32,uint256,address)" \
  <id> <from> <ownerCommit> <amount> <from> --rpc-url https://sepolia.base.org <signer flags>
```

`triggerCloseOnly` reverts `LivenessNotExpired` while neither timeout has passed.
The refund errors are listed in `docs/API.md` (§ Refunds after close-only).

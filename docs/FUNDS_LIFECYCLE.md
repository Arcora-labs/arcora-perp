# Synthetic wallet lifecycle and exact clock guest replay

The opt-in gateway test runs an owned loopback HTTP server and a disposable Anvil
chain. Three fixed public fixture wallets deposit 50,000 test USDC, place four
signed sealed orders to open and close positions, settle four consecutive windows,
then claim 20,000 test USDC. Anvil allocates its port with `--port 0`; the test
reads that port only from its owned child's startup output and drains subsequent
output without printing the fixture-key banner. It uses real contract constructors, ERC20 allowances,
deposit authorization and ingestion, clock registration, the `ClockBoundVerifier`,
settlement and vault. The inner verifier is explicitly `MockZkVerifier`.

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
four exact v2 witness byte streams and a final `lifecycle.json` linking their hashes
to each local transaction, commitment and root. This export is available only in
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
  FINAL_SETTLE_RUNBOOK.md).
- This is not a data-availability archive.

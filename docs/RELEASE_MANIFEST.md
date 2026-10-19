# Clock release identity preflight

`release_manifest.py` binds the reviewed PR #31 clock guest (source hashes, ELF,
SP1 6.1.0 and setup key) to **current local** Solidity compiler artifacts and a
strictly public gateway/prover configuration. It rejects an old guest/key mixed
with the new clock stack, stale compiler sources, changed source/artifact files,
and mismatched gateway chain/address settings. Added untracked source files are
included in the source fingerprint; a Git commit alone does not describe a dirty
checkout.

The manifest closes an offline identity check. The optional `observe-target`
command adds finalized chain/runtime/contract-binding verification. Neither closes
R02 as a whole, and both always record `release_gate: HOLD`. They do not assert a
fresh reproducible guest build, a running prover's identity, operator-policy
approval, or a state/withdrawal migration rehearsal. They reuse the established
PR #31 guest identity and do not negate or rerun that release's real proof.
Current contract bytecode is identified separately from that historical proof.
The validator and manifest must come from a trusted release process: checksums
are integrity bindings, not a release signature.

## Build and record

Requires Python 3.11+, Git, Foundry (`forge` and `cast`), Solidity 0.8.24 for the
application and 0.8.20 for the vendored SP1 contracts. SP1 dependency locks and
vendor provenance are checked using the existing release guard. Start from a
clean release checkout for publishing; the script also supports local dirty
worktrees by recording all covered source hashes.

```sh
forge build --root contracts
forge build --root contracts/vendor/sp1-contracts
python3.11 scripts/local-verification/release_manifest.py create \
  --config /path/to/public-release-config.json \
  --output /path/to/release-manifest.json
python3.11 scripts/local-verification/release_manifest.py validate \
  --config /path/to/public-release-config.json \
  --manifest /path/to/release-manifest.json
```

`create` refuses to overwrite an existing manifest. Build metadata is checked
against current source contents with Keccak-256; the artifact file, creation
bytecode and runtime **template** are then SHA-256 pinned. Constructor immutable
placeholders are not represented as an actual deployed runtime hash. Source,
artifact, configuration, or manifest scope changes require a new manifest.
The source commit is also bound: generate the manifest after the intended source
commit is final. Checked-in audit manifests document the checkout at their
creation; they are historical evidence after any covered file or commit changes,
and must not be reused as current release authorization.

The public configuration shape is below. **Every address in this example is
synthetic, and chain 31337 is local only.** Replace them from the actual reviewed
setup before using the preflight for a release. Timing values are illustrative,
not a measured capacity recommendation. No private keys, RPC credentials,
attestation secrets or `.env` files may be supplied; unknown fields are refused.
The `prover` section declares the expected binary identity; it is not a remote
prover observation.

```json
{
  "chain_id": 31337,
  "addresses": {
    "settlement": "0x0000000000000000000000000000000000000001",
    "vault": "0x0000000000000000000000000000000000000002",
    "token": "0x0000000000000000000000000000000000000003",
    "clock_verifier": "0x0000000000000000000000000000000000000004",
    "sp1_adapter": "0x0000000000000000000000000000000000000005",
    "sp1_gateway": "0x0000000000000000000000000000000000000006",
    "sp1_verifier": "0x0000000000000000000000000000000000000007"
  },
  "program_vkey": "0x0017893c7ff3395d60b57d25eaa08cf1542fc7bc3cdfd74468133562994b8353",
  "clock": {"max_window_ms": 30000, "clock_skew_ms": 30000, "anchor_timeout_ms": 3600000},
  "gateway": {
    "L1_CHAIN_ID": "31337",
    "L1_SETTLEMENT": "0x0000000000000000000000000000000000000001",
    "L1_VAULT": "0x0000000000000000000000000000000000000002",
    "L1_USDC": "0x0000000000000000000000000000000000000003",
    "CLOCK_BOUND_VERIFIER": "0x0000000000000000000000000000000000000004",
    "L1_ALLOW_MOCK_PROOF": "0",
    "DEPOSIT_PERMIT_TTL_SECS": "1800",
    "WIND_DOWN_RECIPIENT": "0x0000000000000000000000000000000000000009",
    "PROVER_EXPECTED_ELF_SHA256": "df59a19b310258b4d01d0d5e3cfa31bb7de9ca2f4ea7c2302cf76650c79967c5"
  },
  "prover": {
    "program_vkey": "0x0017893c7ff3395d60b57d25eaa08cf1542fc7bc3cdfd74468133562994b8353",
    "guest_elf_sha256": "df59a19b310258b4d01d0d5e3cfa31bb7de9ca2f4ea7c2302cf76650c79967c5"
  },
  "genesis": {
    "root": "<GENESIS_ROOT printed by --print-genesis-root>",
    "wind_down_recipient": "0x0000000000000000000000000000000000000009",
    "oracle_signer": "0x000000000000000000000000000000000000000a"
  }
}
```

`genesis` is the state the settlement is deployed with, exactly as
`darkperp-gateway --print-genesis-root` prints it: the root, the wind-down
recipient and the oracle signer address, which are bound into that root and
cannot change after deployment. All three must be nonzero; the recipient and the
oracle signer must differ from each other, from every contract address and, when
`operator_policy` is present, from every operator address. The gateway's
`WIND_DOWN_RECIPIENT` must equal `genesis.wind_down_recipient`, and
`PROVER_EXPECTED_ELF_SHA256` (bare lower-case hex) must equal the reviewed guest
ELF. Python does not recompute the root: it is carried from the one
`--print-genesis-root` run and checked against the chain by `observe-target`.

An operator may add `validate --check-process-env` as a service pre-start check.
This compares the nine allowlisted gateway variables against the manifest and
fails before startup on a mismatch. It does not install a startup hook or change
running services; that integration must be configured in the target environment.
No key values are read or emitted by the environment check.

## Real proof status

Two clock identities are pinned separately in
`scripts/local-verification/verify_clock_proof.py`: `REVIEWED_GUEST` (with
`REVIEWED_FIXTURE`), the guest this checkout must build, and `PROOF_FIXTURE`, the
committed real proof the Solidity gate verifies. `proof_status()` reads the
committed proof files from disk and returns `PROVEN` only when they are a proof of
the reviewed fixture under the reviewed guest; otherwise `PENDING_REPROOF`. Editing
a record without committing new proof files does not change the status.

Every manifest records `real_proof` (that status plus both identities). `create`
requires `PROVEN`. While the status is not `PROVEN`, `validate` and
`observe-target` accept only an owned test chain, using the same rule as
`deploy_clock_stack.py`: an Anvil client (asked through `web3_clientVersion`, so
an Anvil fork at chain id 84532 qualifies), or an operator declaration
`--owned-test-chain` for a local chain id (31337 or 1337). Offline `validate`
cannot see the client, so it needs the declaration. The deploy tool likewise
refuses a target that is not an owned test chain until the status is `PROVEN`.
Once it is `PROVEN`, the declaration counts for any chain id that is not a public
Base network.

## Reject a legacy deployment record

```sh
python3.11 scripts/local-verification/release_manifest.py check-deployment \
  --deployment contracts/deployments/base-sepolia.json
```

The checked-in July Base Sepolia record is expected to fail: its program key is
`0x000a2f…bda5ed`, whereas the reviewed clock guest uses `0x001789…4b8353`.
This is an offline record check, not a claim about current chain state. A passing
record check checks only the guest key, clock presence, chain-ID range and address
shape; it does not compare runtime bytecode or prove mutual contract bindings.

## Observe the configured clock deployment

With a manifest for the current checkout and reviewed public target configuration:

```sh
python3.11 scripts/local-verification/release_manifest.py observe-target \
  --config /path/to/public-release-config.json \
  --manifest /path/to/release-manifest.json \
  --rpc https://PUBLIC_TARGET_RPC \
  --output /path/to/target-observation.json
```

The command uses only `eth_chainId`, `eth_getBlockByNumber`, `eth_getCode` and
`eth_call`, plus `web3_clientVersion` while the real proof status is not
`PROVEN`. It does not deploy, transact, import keys, change services or repair a
bad binding. The endpoint must support the `finalized` tag and EIP-1898 block-hash
parameters with `requireCanonical: true`. Unsupported finality/hash pinning is a
failure; there is no `latest` or block-number fallback. The finalized anchor and
chain ID are checked again after the observation. Redirects, malformed envelopes,
RPC errors and oversized responses fail closed. Provider error text and URL paths
are not written to the evidence. Existing output files are never overwritten.

For each of the six compiled contracts, it checks the full runtime, including
metadata. Only the compiler's immutable reference words may differ from the
template. Each repeated occurrence of one immutable must contain the same value;
out-of-bounds, overlapping, non-word and nonzero-placeholder references are
rejected. Every observed immutable word is recorded by its compiler identifier;
this is reconstruction of the actual deployed template, not blanket masking of
all constructor-dependent bytes. An altered opcode or metadata byte fails.

At that same block it checks settlement ↔ vault, settlement ↔ clock verifier,
clock → SP1 adapter → SP1 gateway, vault → token, the settlement's
`ABI_VERSION() == 3`, the reviewed guest key, the clock bounds and
`anchorTimeoutMs()`, proof version 2, the SP1 verifier hash, and the selector's
active, unfrozen route to the configured verifier. While the settlement's
`batchCount()` is 0 it also requires `currentStateRoot()` to equal `genesis.root`
and records `genesis_root_verified`; after the first batch the root is recorded
as not observed. A wind-down recipient or oracle signer equal to an operator
address the target reports fails, with or without `operator_policy`. Zero/unbound or old direct-adapter
configurations fail. The token must have code; its implementation is not among
the six compiled artifacts.

A successful report says `VERIFIED_AT_FINALIZED_BLOCK`, with runtime and target
observation fields set true. It still records `release_gate: HOLD`. RPC responses
are trusted; this is not a light-client check or independent RPC consensus. The
sequencer, enclave signer, governance, gateway signer, SP1 gateway owner and
settlement timing/bond parameters are recorded for review. An optional, complete
`operator_policy` in the public configuration pins all thirteen expected values;
any mismatch fails closed. `operator_and_settlement_policy_matches` is true only
after every runtime, getter, finality and source recheck passes. This is matching
a declaration, not a security/economic review: `operator_and_settlement_policy_approved`
always remains false, even when explicit zero values match. The token's runtime,
proxy/admin/issuance policy, service config/identity, real proof generation,
capacity, custody loss and state migration remain separate acceptance gates.

The opt-in integration test owns a new disposable Anvil, deploys the real six
compiled contracts and a mock token through their actual constructors, binds the
stack, and obtains a successful hash-pinned observation. It then freezes the
actual SP1 route and requires the next finalized observation to fail. No existing
node, supplied RPC, credentials or public network can be selected by this test.

```sh
forge build --root contracts
forge build --root contracts/vendor/sp1-contracts
ARCORA_RUN_MANIFEST_ANVIL=1 \
  python3.11 -m unittest discover -s scripts/local-verification \
  -p test_release_manifest.py -v
```

Optional `ARCORA_MANIFEST_ANVIL_EVIDENCE=/path/to/local-observation.json` captures
both observations. This is local contract/RPC evidence with a mock token; it does
not generate or settle a proof, attest a service, or verify a public deployment.


## Pin operator identities and settlement policy

The optional `operator_policy` is included in the manifest's public configuration
hash. Every field below is required when the section is present. Missing fields,
unknown fields, malformed addresses, booleans/floats/strings in integer positions,
and integers outside the Solidity uint256 range are refused. Values are never
inferred from the queried chain: doing so would turn observation into self-approval.
Duplicate JSON keys and non-finite JSON numbers are rejected in config and RPC data.

**The following values are synthetic examples, not an approved target policy.**
Add this section to a separately reviewed public release configuration:

```json
"operator_policy": {
  "settlement": {
    "sequencer": "0x0000000000000000000000000000000000000011",
    "enclave_signer": "0x0000000000000000000000000000000000000012",
    "governance": "0x0000000000000000000000000000000000000013",
    "liveness_timeout_blocks": 100,
    "challenge_grace_blocks": 50,
    "challenge_bond_wei": 1000,
    "inclusion_deadline_seconds": 600,
    "final_settle_grace_blocks": 10,
    "progress_batches": 2,
    "slash_payout_cap_usdc": 1000000000
  },
  "vault": {"gateway_signer": "0x0000000000000000000000000000000000000014"},
  "clock_verifier": {"configurator": "0x0000000000000000000000000000000000000015"},
  "sp1_gateway": {"owner": "0x0000000000000000000000000000000000000016"}
}
```

Pass `observe-target --require-operator-policy` to reject a missing policy before
any chain reads. Without that flag, old configs still support observation, but
cannot claim a policy match. With a policy supplied, comparisons are mandatory
regardless of the flag. All thirteen getters use the same finalized block hash as
the runtime checks. A late chain/source change prevents the policy match flag
from becoming true. The report also records the canonical policy SHA-256.

Zero addresses and zero numeric values must be explicit. The parser allows them
to describe renounced ownership or other intentional configurations; it does not
endorse them as safe. Review governance availability, signer authority, economic
bounds and recovery separately. This observer does not change deployed settings,
rotate keys, audit token proxies, or promote `release_gate` beyond `HOLD`.

### Keys introduced with settlement ABI version 3

| Section | Key | Getter / meaning |
|---|---|---|
| `operator_policy.settlement` | `challenge_grace_blocks` | `challengeGraceBlocks()`; replaces the removed `challenge_window_blocks` |
| `operator_policy.settlement` | `progress_batches` | `progressBatches()` (1..16 on-chain) |
| `operator_policy.settlement` | `slash_payout_cap_usdc` | `slashPayoutCap()`, compared as the raw integer (USDC base units, 6 decimals) |
| `clock` | `anchor_timeout_ms` | `anchorTimeoutMs()`, the minimum anchor age before `cancel` |
| `gateway` | `DEPOSIT_PERMIT_TTL_SECS` | the gateway's deposit-permit lifetime; public, so it is allowlisted |

A configuration that still carries `challenge_window_blocks`, or a clock section
without `anchor_timeout_ms`, is refused as an unknown or missing field. The open
challenge set is read on-chain, so no deploy-block setting is needed.

### Keys introduced with the genesis binding

| Section | Key | Meaning |
|---|---|---|
| `genesis` | `root` | the settlement's constructor state root, `GENESIS_ROOT` from `--print-genesis-root`; `observe-target` compares it with `currentStateRoot()` while `batchCount()` is 0 |
| `genesis` | `wind_down_recipient` | the address the final wind-down pays the remaining reserves to; a word of the genesis root |
| `genesis` | `oracle_signer` | the oracle publisher every genesis market trusts; part of the genesis root |
| `gateway` | `WIND_DOWN_RECIPIENT` | must equal `genesis.wind_down_recipient` (addresses compare case-insensitively) |
| `gateway` | `PROVER_EXPECTED_ELF_SHA256` | must equal the reviewed guest ELF hash, as 64 lower-case hex digits |

A configuration without the `genesis` section or either gateway key is refused as
missing fields. On a chain id that is not a local test chain (31337 or 1337),
neither genesis address may be one of the published default development accounts
(`PUBLIC_DEV_ADDRESSES`). `deploy_clock_stack.py` reads the recipient and the
oracle signer from its own deploy configuration (`wind_down_recipient`,
`oracle_signer_address`), requires both nonzero, distinct from each other and from
every operator address, and writes the same `genesis` block and gateway keys into
the public configuration it emits.

Without further input, no tool recomputes `genesis.root` from the recipient and
the oracle signer; they rest on the `--print-genesis-root` output that listed them
with the root. With `--gateway-bin <darkperp-gateway>`, `create`, `validate`,
`observe-target` and `deploy_clock_stack.py` rerun `--print-genesis-root
--oracle-address <oracle_signer>` with only `WIND_DOWN_RECIPIENT` in its
environment (no key is needed or passed) and refuse unless the printed root,
recipient and oracle signer equal the configured ones. `observe-target` records
whether it did so as `scope.genesis_bindings_recomputed`.

`deploy_clock_stack.py` deploys to a chain it does not own only when the committed
real proof is PROVEN and the checkout's guest sources are the reviewed ones
(`release_manifest.deployable_status()`).

CPU tests: `python3 -m unittest discover -s scripts/local-verification -p test_operator_policy.py -v`.
The owned-Anvil integration additionally verifies the actual declared policy and
rejects wrong governance, wrong challenge bond and a frozen SP1 verifier route.

## Remaining R02 acceptance gates

Before a target release is accepted, independently reproduce the guest with the
pinned toolchain; verify its setup key; run `observe-target` against the actual
reviewed deployment; approve the observed operator identities and settlement
policy; independently review the token; and verify the actual gateway/prover
runtime configuration. Rehearse preservation of existing state, notes, deposit
accounting and withdrawal rights. A local Anvil observation does not substitute
for target deployment evidence, and this tool never migrates funds or resets state.

```sh
python3.11 -m unittest discover -s scripts/local-verification \
  -p test_release_manifest.py -v
```

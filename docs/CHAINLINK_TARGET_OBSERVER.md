# Chainlink candidate target observer

`scripts/local-verification/candidate_target_observer.py` checks declared
candidate identities against read-only RPC responses at one finalized anchor.
It requires an existing, locally validated
`arcora-chainlink-candidate-offline/v1` manifest, its exact public configuration,
and a separate expected operator policy. A successful observation retains
`release_gate: HOLD`; it does not activate the candidate submission route.

The existing [candidate identity tool](CHAINLINK_CANDIDATE_IDENTITY.md), its
schema and create/validate commands remain unchanged. The reviewed v2 release
script, manifest schema and observer also remain unchanged. The new observer
does not build a guest, derive a setup key, generate or verify a fresh proof,
register reports, discover feeds, or submit transactions.

## Inputs and policy

The public candidate configuration supplies ten addresses and ten expected
runtime hashes: seven compiler roles (`settlement`, `vault`, `sp1_adapter`,
`clock_verifier`, `sp1_gateway`, `sp1_verifier`, `oracle_wrapper`) and three
declaration-only roles (`token`, `verifier_proxy`, `uptime_feed`). Its candidate
key, chain/network, clock bounds, oracle policy hash and uptime grace remain
explicit caller declarations.

The separate policy JSON has exactly four top-level keys:

| Key | Required value |
| --- | --- |
| `schema` | `arcora-chainlink-target-policy/v1` |
| `runtime_hash_algorithm` | `keccak256-evm` |
| `operator_policy` | The exact role object below, using the unchanged v2 operator-policy parser |
| `oracle_configurator` | Expected 20-byte address returned by the candidate wrapper's `configurator()` |

`operator_policy` contains exactly these roles and fields:

| Role | Exact fields |
| --- | --- |
| `settlement` | `sequencer`, `enclave_signer`, `governance`, `liveness_timeout_blocks`, `challenge_window_blocks`, `challenge_bond_wei`, `inclusion_deadline_seconds`, `final_settle_grace_blocks` |
| `vault` | `gateway_signer` |
| `clock_verifier` | `configurator` |
| `sp1_gateway` | `owner` |

Address fields use 20-byte hexadecimal values. The five settlement numeric
fields are integers in `0..2^256-1`; booleans do not count as integers. Explicit
zero values permitted by the inherited parser are retained rather than replaced
by defaults. The inherited name `challenge_bond_wei` compares the raw
`challengeBond()` integer; this observer does not infer its denomination or
approve the economic policy. Unknown, missing or extra fields fail.

The observer records and checks the supplied policy separately from the
candidate manifest. Matching a configurator, owner, signer or economic value
does not mean that the operator or policy has been independently approved.

## Runtime and getter checks

`expected_runtime_code_hashes` means **Keccak-256 of the complete deployed EVM
runtime bytes**, including actual immutable values. It does not mean SHA-256 of
a compiler template. SHA-256 identities are recorded separately for the local
artifacts and observed runtime bytes.

All ten configured roles require nonempty runtime bytes and exact declared
Keccak hashes. For the seven compiler roles, the observer additionally compares
the full runtime to the manifest-bound compiler artifact. Only the declared
immutable words may differ from template placeholders; their ranges and repeated
occurrences must be consistent. Actual getter values must agree with the
configured links, keys and policy. This closes the gap between observing some
immutable bytes and checking the declared identity they represent.

The three declaration-only roles receive exact runtime-hash checks, without a
local compiler-template claim. A proxy's code hash does not authenticate its
current implementation, subscription rights, feed semantics or future upgrades.
The observer performs no implementation or live-feed discovery.

The required candidate stack is settlement → clock verifier → oracle wrapper →
SP1 adapter → SP1 gateway → the configured, unfrozen SP1 verifier route. The
vault/settlement and vault/token links, wrapper/clock link, DON proxy address and
uptime feed address must also match. The wrapper's deployment chain ID, policy
hash and grace must match declarations; the clock's maximum window, skew and
inner proof version `2` must match. The candidate's outer witness domain remains
`DPCLK3`, with its separate historical candidate program key. A reviewed v2
manifest or key cannot authorize the candidate observer.

The one-time binding constructors required `batchCount == 0`. An already bound
target may legitimately have settled batches, so zero batch count is not a
condition for observing its current identity. Neither phase nor a current
uptime-health result is treated as production route authorization.

## RPC and consistency boundary

The CLI accepts one explicitly supplied anonymous HTTP(S) endpoint with a root
path only. Userinfo, authentication, query strings, fragments and non-root paths
are rejected. Redirects are rejected. It reads no process configuration or
credentials; transport diagnostics omit the endpoint, provider payload and
provider error text.

Only `eth_chainId`, `eth_getBlockByNumber`, `eth_getCode` and `eth_call` are
allowed. Calls are limited to the fixed identity getters; no registration,
verification, deployment or mutation method is invoked. The transport uses a
checked 120-second observation deadline and a checked 15-second request deadline,
with socket timeouts capped by the remaining budget. It checks time before
requests, while reading body chunks and before accepting a response. DNS,
connect/header waits and an in-flight socket read are not forcibly preempted;
elapsed time can exceed a deadline before control returns and refusal is
reported. These checks are not a hard wall-clock guarantee.

RPC response bodies are limited to 1 MiB and runtime code to 64 KiB. JSON nesting
is bounded; duplicate keys, malformed envelopes, wrong response IDs,
noncanonical ABI values and provider errors fail. An explicit empty proxy
handler prevents ambient proxy configuration or proxy credentials from being
used.

The initial anchor comes from `finalized`. Every code/getter read uses EIP-1898
`blockHash` plus `requireCanonical: true` for that exact anchor. There is no
fallback to `latest` or unpinned reads. Completion checks the original anchor and
chain again. If finalized height advances, a bounded parent walk of at most 64
blocks must link the new finalized head to the original anchor; regression,
same-height hash replacement, broken ancestry or excess advance fails.

These are consistency checks on one caller-selected RPC endpoint. They are not
consensus verification, a light-client proof, independently verified header
ancestry, or agreement between independent operators. A dishonest endpoint can
present self-consistent false data. Local source/artifact/manifest identities
are revalidated at completion before reporting a match.

## Commands and evidence

The observer requires Python 3.11+, local `cast` and existing compiler artifacts.
Prepare a fresh identity manifest with the unchanged candidate identity tool,
then run:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 scripts/local-verification/candidate_target_observer.py \
  --manifest /absolute/path/fresh-candidate-identity.json \
  --config /absolute/path/public-candidate-config.json \
  --policy /absolute/path/expected-target-policy.json \
  --rpc https://anonymous-public-rpc.example/ \
  --output /absolute/path/new-candidate-observation.json
```

The example endpoint is a placeholder, not a configured or approved target.
Output creation is no-clobber; an existing report is never replaced. A blocked
observation is evidence of refusal, not successful target acceptance.

Adding this observer and its Python tests changes the covered source inventory.
The earlier 353-source CLI demonstration remains preserved historical evidence
and becomes stale against the new inventory. Create a new manifest at a new
pathname; do not overwrite or reinterpret that older demo as current validation.

Self-contained unit tests use injected RPC responses and explicitly synthetic
compiler/runtime fixtures; they do not contact a target:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s scripts/local-verification -p test_candidate_target_observer.py -v
```

The separately owned Anvil test is skipped by default. Explicit local execution
requires `anvil`, `cast` and the seven existing real compiler artifacts:

```sh
PYTHONDONTWRITEBYTECODE=1 ARCORA_RUN_CANDIDATE_TARGET_ANVIL=1 python3 -m unittest discover \
  -s scripts/local-verification -p test_candidate_target_anvil.py -v
```

`ARCORA_CANDIDATE_TARGET_ANVIL_EVIDENCE` may name a fresh, no-clobber JSON output
for that test. Its owned loopback Anvil process deploys seven real production
contract artifacts and three mocks for token, streams verification and uptime.
It checks the observer software against local EVM behavior. It supplies no real
DON signatures, live uptime acceptance, public target acceptance or fresh proof.
An explicitly skipped test is not an executed integration result; actual command
receipts establish which checks ran.

## Remaining gates

The user deferred live feed discovery. An actual approved target configuration
and independent acceptance evidence are still missing. This packet closes a
read-only observer software boundary, with local mock/integration verification
reported separately. Even a target-identity match keeps proof, real DON,
uptime-health acceptance, running-service attestation, custody, operator approval
and candidate submission disabled. Production HOLD and the open gates in
[ACTIVE_WORK.md](ACTIVE_WORK.md) continue.

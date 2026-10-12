# Candidate target observer: GPU-free software verification

Base main: `0b20e6a4ad7223d394cfb0632507f20c9ed0d776` (#53).
Code: `01da176ac3a19d7f8187e0b162a7b28c9aaa91dd`.
**PRODUCTION RELEASE HOLD.** This packet verifies the new read-only software and
an owned local deployment, not a public target or running gateway/prover.
Publication-head CI and normal merge require their own fresh GitHub readback.

The [observer guide](../../CHAINLINK_TARGET_OBSERVER.md) describes its separate
explicit policy envelope, fixed-HOLD output and anonymous root RPC transport.
The existing candidate identity/v2 schemas, scripts, guest sources, ELF/key,
contracts and previous test assertions remain unchanged. The observer validates
the manifest/config/policy before RPC and revalidates source and inputs at return.

At one finalized EIP-1898 anchor, it verifies ten declared EVM Keccak code hashes,
seven exact compiler templates and consistent immutable words, eleven candidate
stack links, guest key/clock version/bounds, wrapper policy/chain/grace and the
exact unfrozen real-SP1 route. Operator addresses, configurators and settlement
policy must match explicit declarations; this does not approve those values.

Code/getters are reread at the same anchor. Completion checks the original block,
chain and fresh finalized tip; a maximum 64-parent walk must reach the anchor.
These are consistency checks on trusted RPC responses, not a light client or
independent consensus. Token/DON proxy/uptime feed have declaration-only code-hash
checks; their implementation, upgrades, economics and health remain unaudited.

## Actual checks

| Check | Result and boundary |
|---|---|
| New observer/transport units | **28 PASS**, current source; synthetic compiler/RPC and explicitly mocked Keccak/selectors. Every observer case first proves a separate complete positive baseline |
| Owned Anvil integration | **1 PASS**, seven real compiled contracts + mock token/streams/uptime, chain84532 and kernel-assigned port; positive match and **12 distinct refusals** |
| Existing candidate/v2/policy/RPC/proof guards | **117 run, OK, one optional legacy Anvil skip**; all original assertions preserved |
| Fresh offline CLI manifest | **356 covered source files**, existing actual artifacts; source/ELF/key unchanged. Configuration describes the stopped owned fixture, not a live target |
| CLI refusal checks | Historical 353-source manifest rejected before RPC; output overwrite refused and original hash retained; unsupported private-key argument rejected without echo |
| Preservation | **2,718 / 2,721** base files byte-exact; only ACTIVE_WORK, raw-log attributes and two added A11 gates differ. Original **13/7/62** dirty checkouts unchanged |

The actual Anvil stack deploys real SP1 verifier/gateway/adapter, oracle wrapper,
clock, settlement and vault. Its gateway route and candidate key are real public
bindings; it generates or submits no proof. The observer itself calls only four
read methods. Only the fixture deploys/binds its own local contracts and freezes
its own route for the final negative. The child and its output drains are cleaned
up without touching user nodes, fixed ports, snapshots, keys or funds.

Actual refusals cover policy hash, grace, runtime hash, clock policy, governance,
bond, oracle configurator, reviewed-v2 key before RPC, unbound proxy/feed, wrong
clock inner route and a genuinely frozen SP1 route. The refined wrong-clock
fixture has its own real settlement/vault and valid earlier links: its first
refusal is exactly `clock_verifier.innerVerifier()`. The initial version instead
refused at `settlement.verifier()`; that earlier log remains historical evidence
and is not attributed to the deeper inner-verifier condition.

## Failures and narrow repairs

Initial unit smoke ran 28 tests with seven failures. The common positive fixture
was refused because the candidate schema accepts compiler object hex with or
without `0x`, while the unchanged legacy runtime helper requires the prefix.
Only the new observer's decoded artifact copy now normalizes that prefix; exact
bytes, immutable checks and old scripts/assertions are preserved. The initial
21 negative statuses do not establish semantic acceptance because their baseline
was also refused. Passed-after units require a positive baseline first.

Pre-test independent design review found ambient proxy configuration and a final
EOF budget edge. Explicit `ProxyHandler({})` prevents proxy lookup/authorization;
consuming `read1` checks bounded body chunks and the final checked call deadline.
Limits are checked budgets and socket timeouts, not forced DNS/connect/header
preemption. The new owned-fixture setup also disables ambient proxies.
[Repair/history record](checks/repair-and-cli-history.json) and
[design QA](checks/design-qa.json) distinguish those iterations from actual tests.

The fresh manifest SHA and no-clobber evidence are in the history record; the
manifest's code commit is an informational ancestor, while current covered hashes
bind the new source. Old #53 manifests/packets are retained unchanged and are
stale against the expanded inventory. The identity schema was not widened.

## Delivery boundary

[Verification ledger](verification.json) binds source/artifact fingerprints and
all raw stdout/stderr/combined logs, payloads, actual Anvil declarations/refusals,
CLI output and before/after evidence. Combined logs concatenate stdout then
stderr; they are not an interleaved timeline. Existing compiler artifacts were
used and validated; no fresh guest build/setup/proof or local full Rust/Foundry
rerun is claimed. The publication's existing CI includes those separate gates.

Two A11 gates were added: 28 self-contained units and the explicit owned Anvil
test. Every old command, assertion and timeout remains unchanged; the new local
fixture output uses the existing `/tmp/arcora-local-drills` artifact directory.

No approved public candidate target/service configuration was found. Live feed
discovery remains user-deferred. The tool does not attest a running service,
observe uptime health, authenticate DON reports, accept custody or enable
submission. Actual target/service identity, fresh wallet/candidate proof,
CC/key release, economics/exit, capacity/finality, operations and independent
review remain open in [ACTIVE_WORK](../../ACTIVE_WORK.md).

# Fixed native witness to local settlement bridge

11 October 2026. **PRODUCTION RELEASE HOLD.** This is a CPU-only, PUBLIC synthetic
integration packet. It does not generate a proof, authenticate DON signatures,
connect a live RPC/service, deploy a public chain stack or establish custody.
PR #49 merged normally after 19/19 successful checks; its tested and merge trees
are equal. The new bridge code commit is
`f11dc13a77b950e20240917c89dd16ab7f34ba5c`; validation code commit
`65bdb5aebcbf0253b54854229e346d5875c48839` adds only CI test scheduling. Both are
based on merged main
`dc00f5ac9a846139d04a82f0689d02a75e5de6d0`.

## What now connects

The preserved #48 FINAL2 witnesses and original synthetic full report containers
supply both actual gateway flows: normal lifecycle and liquidation. A new test-only
Rust module derives all seven public roots from the same mutable pre-state clone
used for post-state count/tip, exports those roots and original Entry[] ABI, then
rebuilds a fresh witness in an actual captured local contract context. The new
witness executes natively. Fresh pinned SP1 CPU execution then produced exactly
the same public32 bytes for both new witnesses: 27,237,960 + 24,293,454 =
51,531,414 guest cycles, both guest exits zero. Setup plus execution took
382.391 seconds; execution itself took approximately 3.615 / 2.878 seconds.

Foundry deploys, in fixed order, the existing exact-tuple `MockSP1Verifier`, real
`SP1ZkVerifier` with the pinned candidate program key, exact-byte mock DON,
mock uptime, real `ChainlinkOracleVerifier`, real `ClockBoundVerifier`, real
`DarkPerpSettlement`, and a new strict mock prefix vault. Two isolated capture
functions record all 32 actual context fields: addresses, runtime hashes,
chain/network, clock anchor/config/receipt, full uint80 uptime epoch/grace,
source witness identity, seven-root base/policy, count/tip and key. Final replay requires
complete equality with that captured context, rather than assuming CREATE order
or compiler metadata stayed stable. Standalone mocks do not import generated
fixtures; generated vector metadata therefore cannot change their runtime code.

The Python fixture generator independently checks full Entry[] ABI/inputHash,
ordered body evidenceHash, seven-root base, clock receipt/commitment and native
outer domains. The ordinary Rust golden guard rederives the actual captured
context into fresh owned storage and compares both complete case DTOs, binary
witness/native/material, every selected canonical archive record, CPU manifest
cases and refusal to replace an existing output. Two exporter tests remain
intentionally ignored unless supplied explicit owned paths.

## Exact source and new provenance

The old corpus is unchanged: manifest SHA256
`3147718b8db6036f0ecb540157dfaea260f010726abdc2895d53baf4d08c6480`.
Original witness hashes are `8f23160f0a0ff9d004c4c78a25877fc84f4e50e8263b46115695f1d212f9e937`
(normal) and `ba6b4cd72a38db1c4b0188b9eff98e41022dffceca7dd5de5ff47b0f5adb0337`
(liquidation). Original pre-state, operations, manifest, evidence, all full report
containers and operation/report milliseconds are retained exactly. Final Rust
module SHA256 is `c320f008daaa495964c924cce517d4aec7e83b110c475f16e78bd1a47c8cfdbc`.

Both actual EVM anchors are **2,001,000 ms**. Normal first/last remain
**2,000,000 / 2,001,100 ms**; liquidation remains **2,000,000 / 2,001,000 ms**.
The 100-ms normal offset fits the original 2,000-ms skew. Nothing retimestamps an
old Pending/Prepared request. Phase zero adds no phase word to the seven-root
base commitment. Both post-states have count **9** and a nonzero deposit tip.
Count is an explicit mock-prefix input, not another public-commitment word or a
stored post-count field in settlement. The mock accepts only the exported
(count=9, tip), and captures authorized withdrawal publication. It represents no
backed deposits, ERC20 balance or actual claim/custody acceptance.

Changed target addresses require a new host policy binding and archive IDs even
though Policy::hash, full-container inputHash and ordered-body evidenceHash are
unchanged. The source JSON does not contain historical archive receipt/admission
metadata or IDs. This packet explicitly reconstructs **NEW synthetic** receipt/
admission times from report observations and new target archive records. It does
not revalidate or relabel old archive IDs. Full signature-container inputHash is
separate from body evidence/native commitment: exact DON allowlisting rejects a
same-body signature sibling before initial report registration; real replacement
refusal establishes full-input immutability only after the original exists.

| Case | New exact witness SHA256 | Native public32 |
|---|---|---|
| normal-lifecycle | `24b4e42a71ea3c595bdb6b33ab5f76eb3bf8e2d1d78ca11b12f26951d46a2e8b` | `0a3467646ab9a432388e8636bcdd3e33123960d1a36e9711723c71ee2cc0607e` |
| liquidation | `3bc9cacd53408bfab5ad7c5efadde48fd7ad357c3189479bb9f4564c31781086` | `c6a41be0a278ffcb101d7c030ee5dc6cbc33651042e2c1b409ab6a3c715d337b` |

Final derived manifest SHA256 is
`bd90b18d505d11be60e5ade812c467cb713b3568ad9636de1720ee3b0df7b49b`.
Captured context SHA256 is
`74b9a15260a927595f8f7d3ef9fd4bd93986a745e9a9baeb063cb30f8c3c4f85`.

## Checks and meaningful refusals

- Final focused Rust: **5 PASS, 0 FAIL, 2 intentional ignored exporters**.
- Workspace Clippy with `-D warnings`: PASS after three narrow lint-only repairs
  (`contains`, `is_multiple_of`, named tuple alias). The failed first log is retained;
  source/guard semantics and all derived payload bytes remain unchanged.
- Full Foundry: **183 PASS, 0 FAIL, 0 SKIP**, 16 suites, final source bytes unchanged.
- New Foundry bridge: **15 PASS**: two captures, two native positives, eleven negative
  functions. New-file Solidity format check passes.
- Fresh SP1 CPU: **2/2 PASS**, exact new witness/native/public32 equality; pinned
  ELF/key/driver/verified reused host binary unchanged. No fresh host build or proof.
- Final full gateway: **602 PASS, 0 FAIL, 20 intentional IGNORE**, including the
  preserved HTTP route and 4,100-admission/restart regression; two test threads.
- Python guards: **47 PASS**. Reviewed/core **21** and candidate **9** pins unchanged;
  release/candidate locks, workspace format and final source diff checks PASS.
- Publication preservation: original dirty counts **13 / 7 / 62**, all primary
  content/staged-diff fingerprints, prior **34 + 22** artifacts and protected
  source/golden identities PASS.

The first unrestricted full gateway run retained **601 PASS / 1 FAIL / 20 IGNORE**.
An old, unchanged HTTP success assertion got 400 at withdrawal after its order
succeeded. Its report age policy is only 2,000 ms, with second-rounded observations
and wall time read for each route. The unchanged test passes alone. A temporary
ignored diagnostic clone returned 200 with no delay and reproduced 400 with exact
`chainlink archive binding Mismatch` after a 2,100-ms delay. The initial full log
omitted its response body, so attribution of that original failure remains inferred.
Final full validation and the CI workspace test job limit unit-test concurrency
to two threads; neither report age nor assertions were changed. The temporary
observer module was removed and original main/golden source hashes restored before
final checks. One early observer assertion wrongly demanded the word `candidate`
in the observed `chainlink` error; its failed log is retained alongside the corrected
exact-JSON observation. These diagnostics are not part of the committed test suite.
Focused/Clippy snapshots use the final Rust module but predate the final self-source
SHA/vector-comment metadata refresh. `final-metadata-check.json` records unchanged
case/witness/material/native/archive payloads; full gateway/Foundry/CPU receipts
bind the final corpus.

Both positive flows assert the seven-root base and complete bound native commitment,
new settlement root/batch counter/batch manifest-ordered-rejected fields, strict
count9/tip and exact mock withdrawal publication. Refusals cover initial full-report
signature siblings and later replacement, valid same-time different-market reorder,
omitted/extra entries, each of seven changed roots, count8/count10, another valid
clock anchor, second deployment, changed chain, wrong vkey/public32/public length/
proof tuple, changed top uint80 epoch byte and changed startedAt. Refusal assertions
protect settlement root, batch counter and mock withdrawal publication. Earlier
clock registration can exist; a valid reordered report registration can persist
before settlement refuses its mismatching proof. This is not whole-protocol atomic
rollback, exactly-once broadcast, RPC finality or power-loss evidence.

The real SP1 adapter forwards the actual key, exactly 32 public bytes and opaque
proof bytes to the explicit exact-tuple mock gateway. It tests adapter projection
and failure mapping, **not SP1 proof authenticity**. Actual clock/oracle/settlement
code does not turn synthetic DON/uptime/prefix data into independent market,
consensus, capacity, custody or production evidence.

## Repeat locally with owned paths

From repository root, use Rust toolchain 1.99.0 and the existing pinned Foundry
Solidity configuration. The generator needs Python `Crypto.Hash.keccak`. Every
export destination must be fresh; no FFI, RPC or Foundry filesystem permission
change is used. Create one owned parent directory and choose fresh child paths.

1. Set `ARCORA_CHAINLINK_BRIDGE_SOURCE_EXPORT` to a fresh child and run
   `rustup run 1.99.0 cargo test -p gateway --locked --bin gateway candidate_bridge::export_native_contract_bridge_source -- --ignored --exact --nocapture`.
2. Run `python3 contracts/test/fixtures/generate_native_contract_bridge.py source SOURCE/source.json contracts/test/fixtures --replace-owned`, then format only
   `contracts/test/fixtures/ChainlinkNativeContractBridgeSource.sol` with `forge fmt`.
3. Run `forge test --root contracts --match-contract ChainlinkNativeContractBridgeTest --match-test 'test_capture_.*_context' -vv --json`, preserving stdout JSON and stderr separately.
   Default `--json` without `-vv` passed the two tests but omitted decoded logs;
   the successful second capture supplies actual observable context.
4. Run generator mode `context CAPTURE_STDOUT contracts/test/fixtures/chainlink-native-contract-bridge-context.json`.
   Use `--replace-owned` only when deliberately replacing an owned prior context
   after inspecting the newly captured values.
5. Set `ARCORA_CHAINLINK_BRIDGE_CONTEXT_JSON` to that exact context and
   `ARCORA_CHAINLINK_BRIDGE_EXPORT` to another fresh child, then run the exact
   ignored test `candidate_bridge::export_native_contract_bridge_derived`.
6. Run generator mode `vector DERIVED/bridge.json contracts/test/fixtures --replace-owned`,
   then format only `contracts/test/fixtures/ChainlinkNativeContractBridgeVector.sol`. Replaying
   Foundry compares the actual context again. Keep generated fixture changes in an
   owned branch and review their diff before publication.
7. Execute the pinned candidate ELF with `replay-chainlink-lifecycle --elf ELF --input-dir DERIVED --manifest-sha256 EXACT_DERIVED_MANIFEST_SHA --output-dir FRESH_CPU_CHILD`,
   with `RAYON_NUM_THREADS=2` and `TOKIO_WORKER_THREADS=2`. The driver uses the CPU
   client and execute API, never a prove route. This run reuses an already verified
   optimized host binary; it does not claim a new host build or guest rebuild.

Full command/source/artifact fingerprints are in [verification.json](verification.json).
Raw stdout/stderr bytes are preserved separately; the combined receipt log is
stdout followed by stderr, not a claim of chronological stream interleaving.
Narrow `.gitattributes` metadata treats only this
packet's `.bin` payloads and raw `.log` outputs as binary, preserving original
nightly-warning spaces and terminal newlines. Git displays those raw logs as binary
in the diff; their complete bytes and separate stream fingerprints remain in the
packet. Source and other text whitespace checks remain active. Original dirty desktop/job
checkouts, four golden builders, old contract fixtures, earlier audit artifacts
and all candidate/core/guest/ELF/key identities are separately rechecked.

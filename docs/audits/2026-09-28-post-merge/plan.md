# Merge and remaining work

The user authorized merging PR #23 and continuing the remaining work with Graph Engineering. PR #23 merged at `f866a94d383d507d0993bc00403f27bbdb25f192`. Work continues on `fix/arcora-runtime-rpc-20260928` in the isolated worktree. The dirty Desktop checkout and its existing runtime are outside the write scope.

Original acceptance remains `../2026-09-27-local/task-status.json` (SHA-256 `87025d856554bd640d21ce05b2174a16565a2518dd2dfbcf05944af42635fcae`). The preceding status is `../2026-09-28-wallet-rpc/task-status.json`: 7 original tasks remain, 2 PARTIAL and 5 BLOCKED. New findings are mapped to those existing criteria; this bounded contract does not redefine their dependencies or increase the original task count.

| Node | Input and responsibility | Output and verification | Owner / side effect | Transition |
|---|---|---|---|---|
| M | PR #23 exact head and CI results; execute authorized merge | Fresh GitHub merged state and merge SHA | Root; GitHub merge | PASS completed; enables continuation |
| R | Known RSA advisory and actual dependency paths | Replace public RSA verification with ring, select DCAP ring backend, remove unused RSA from real/locked graphs; run attestation positives/negatives and unsuppressed audits | rsa_gate; attestation, manifests, locks, manifest-only vendored feature repair with provenance | PASS only with executed meaningful tests, no RSA graph entry, audit clean |
| W | Finalized recovery reader and optional second endpoint | Opt-in two-provider agreement at the same canonical finalized hash, expected chain and three ABI words; failure/mismatch cannot fall back; real cast loopback tests | runtime_rpc_plan; l1.rs and witness_tests.rs only | PASS permits limited recovery-read claim; full S6-03 stays open |
| N | Ordinary Deposit/Withdraw witness, separate from held A06 draft | Persist exact witness, native/guest byte parity and ordinary guest negatives; prepare locally verifying genuine-proof artifact path | remaining_proof_review; host source/manifests/lock, normal evidence | PASS only for executed ordinary evidence; no real proof or A06 claim |
| P | Official GHSA-63x8-x938-vx33 affecting SP1 6.0.0 | Align guest/host/prover SP1 and slop family to patched 6.1.0; rebuild guest and record CLI, ELF and vkey identity; CI version gate | Root guest/CLI/CI, other agents their manifests/locks | Build/execution PASS is not target-verifier or proof evidence |
| V | Final combined source and all evidence | Relevant tests, source hashes before/after, independent review, unchanged original criteria/dependencies, new reviewable PR | Root; local evidence, commit/push/PR | READY_FOR_REVIEW if bounded criteria pass; PARTIAL/BLOCKED if required checks missing |

Source identity includes all tracked/untracked code, config, locks and vendor files; this audit directory is excluded from the code digest and evidence receives separate hashes. Tests made stale by source changes must be repeated or justified by an exact unchanged relevant file set. Logs must not retain credentials.

One initial attempt plus two targeted corrections per distinct failure is the initial retry budget. New evidence-based failure hypotheses may receive an explicitly recorded revised budget; no blind repeats or weakened assertions. RPC fixtures are local synthetic faults, not independent live providers. The existing A06 automatic-review hold is preserved: do not retry/rephrase/redelegate that execution. Ordinary Deposit/Withdraw guest work has distinct inputs and does not touch that draft. No Groth16 proof is executed with affected 6.0.0. This turn does not authorize publishing, paid proof services, live-value transactions, or bypassing approval review. Preparing a new PR does not itself authorize its merge.

Initial status: M PASS; R/W/N/P/V in progress. Final evidence and original-task reconciliation will be recorded in README.md, report.json and task-status.json.

Final update: M/R/W/N/P/V passed their bounded contract. Source candidate31f626529b655a6ee14a400f587fbfa3f78661a0; source digestc2fd3dcf6f0f6afb9d9528a6ca218be34284dba1ba4b2d0b9aaf9dcfc69be6d2. Actual commands, stale/failed intermediates and corrections are reconciled in source-validation.json and review.md. Delivery READY_FOR_REVIEW; seven original tasks and production HOLD remain open.

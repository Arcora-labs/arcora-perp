# Wallet and RPC continuation: execution contract

Status at creation: **PENDING**. This plan defines the bounded work for this turn; it is not a success report.

## Scope and fixed baseline

The user requested continuation of the remaining tasks with Graph Engineering. Work targets the missing real-extension evidence for S2-01 through S2-04 and the read-only RPC agreement portion of S6-03. The original task descriptions, acceptance text and dependency graph remain unchanged. This turn's contract does not replace them or make its new checks prerequisites for previously closed tasks.

The preceding accepted report has 11 remaining original tasks (6 partial, 5 blocked), after 4 original tasks closed. A successful bounded RPC lane alone cannot close S6-03 while its original S6-01 dependency remains incomplete. Root will reconcile final task statuses against the original criteria after inspecting new evidence.

- Original acceptance: `../2026-09-27-local/task-status.json`, SHA-256 `87025d856554bd640d21ce05b2174a16565a2518dd2dfbcf05944af42635fcae`.
- Frozen preceding status: `../2026-09-28-resolution/task-status.json`, SHA-256 `a538aad1d9fcf9561b3f274ce1c05081dfff14a2beed53a42c3e85ff16aa708e`.
- Worktree: `/Users/huseyinarslan/.codex/worktrees/arcora-local-verification/dark-perp`.
- Starting HEAD: `5a3574612669baf153cca4515be95cf71da0ba73`; branch `fix/arcora-deposit-resolution-20260928`.
- Existing delivery: draft PR #23, <https://github.com/Kubudak90/dark-perp/pull/23>.
- Source identity for each new check must be freshly calculated from the combined source, including uncommitted/untracked changes. The starting HEAD is not the tested identity of later changes. This audit directory is excluded from the source digest so evidence creation cannot alter its own subject; evidence files receive separate SHA-256 hashes.

Authorized delivery is local implementation, verification, evidence and an update to the existing draft PR. This contract does not authorize a new merge, deployment, release, messages to third parties, paid prover, live-value transaction, or changes to the user's active Desktop checkout or existing wallet/browser profile. Previously blocked guest/proof work is not part of this lane. Existing original proof, full-funds, incident-owner and external-review requirements remain open on their own evidence.

## Environment and evidence boundaries

Use an unmodified official MetaMask package whose origin and digest are recorded, an isolated persistent Chromium profile, a fresh test wallet, the compiled application/client and a real local Rust gateway. Record browser, extension, gateway, build commands, local ports, effective CSP and public configuration without credentials. Any local chain or test token used must be newly isolated and explicitly labelled; mock verification or demo credits are not real-proof/full-funds evidence. Do not substitute a synthetic EIP-1193 signer for extension evidence.

Controlled storage failures, delayed responses and fixture RPC servers are deliberately injected test conditions and must be labelled as such. The actual extension, native gateway and public read-only endpoint observations are separate evidence classes. A public RPC failure is an explicit blocker for deployment identity, not evidence of matching deployment. Distinct endpoint hosts do not establish independent operators.

Avoid raw request bodies, authorization values, signatures, session material, wallet seed/private keys, and wallet onboarding screenshots in retained logs. Persist only redacted metadata and assertion results. An extension test profile containing test secrets remains an ephemeral runtime resource, not a committed artifact.

## Bounded acceptance

The machine-readable definitions are frozen in `contract.json` for this work. Their IDs are independent of the original task IDs.

| ID | Observable outcome | Verifier and pass condition |
|---|---|---|
| W1 | Official actual extension, disposable profile, real Rust gateway and current source/configuration identities | Inspect package digest, launch/configuration metadata and runtime evidence; synthetic provider evidence does not satisfy this check. |
| W2 | Two same-origin tabs: rejected recovery, successful rotation, stale activity invalidation, adoption and reload | Execute browser assertions against the real extension and native gateway; account/state and credential-generation assertions all hold. |
| W3 | Controlled storage failure, honest session-only reload and preserved legacy/deployment scope | Execute real-browser assertions; no silent persistence claim, record deletion or wrong-deployment credential send. |
| W4 | Applied local CSP works with the actual extension and retained evidence is redacted | Inspect recorded CSP, flow outcomes and sanitized console/network assertions; retain explicit local/production and storage/XSS limits. |
| R1 | Opt-in witness agrees at the primary finalized anchor and on hash-pinned deployment observations | Execute positive regression tests, including unchanged single-endpoint mode; agreement is reported only after all required observations. |
| R2 | Missing, malformed, stale or conflicting witness data fails closed | Execute negative regression tests and inspect required-read/endpoint-redaction assertions. |
| R3 | One fresh public read-only deployment observation | Record success or explicit blocker and the evidence class; do not promote incomplete data to verified deployment. |
| V1 | Combined source validation and evidence reconciliation | Check applicable focused tests/builds and before/after content identity, then map actual results to unchanged original criteria/dependencies. |

## Graph, ownership and transitions

| Node | Input/dependency | Single responsibility and output | Verifier | Side effect and boundary | Transition |
|---|---|---|---|---|---|
| N0 | Starting checkout, frozen criteria and tool availability | Record current source/configuration identity and isolated runtime setup | W1 preparation; inspect fresh state | Local metadata only; preserve active Desktop state | PASS enables wallet lane; setup failure is FAIL or environment BLOCKED |
| N1 | N0; official package; available local ports | Launch disposable extension profile and native gateway; produce runtime metadata | W1 | New isolated local processes/profile only | PASS enables N2; no fallback signer may claim W1 |
| N2 | N1; two real tabs and existing account/recovery paths | Execute rotation/rejection/stale/reload and controlled-storage matrix under CSP | W2, W3, W4 | Test account/credential changes in disposable gateway state | All required assertions PASS enables wallet review; otherwise targeted repair or scoped BLOCKED |
| N3 | Current deployment reader and original S6-03 scope; independent of N1/N2 | Implement opt-in witness agreement and fail-closed regression tests | R1, R2 | Reader/tests only; fixture traffic stays local | PASS enables RPC review; FAIL permits targeted repair |
| N4 | Configured public RPC; independent of N1/N2 | Perform one current read-only deployment observation | R3 | Public read RPC only; no signing or chain writes | Observation complete is PASS for recording; failed identity observation remains BLOCKED as deployment evidence |
| N5 | N2, N3, N4 outputs; final combined source | Run applicable validation, inspect evidence and reconcile original task statuses | V1; machine consistency check plus human/tool review | Local evidence and draft PR update | Required contract checks PASS permits bounded DONE/READY_FOR_REVIEW; unresolved mandatory checks yield PARTIAL/BLOCKED |

Root owns the wallet/runtime lane and final reports/task reconciliation. `rpc_remaining` owns `scripts/local-verification/read_deployment.py` and `test_read_deployment.py`. `graph_records` owns this plan, `contract.json`, and only the exact audit-directory exclusion in `run_check.py`. The harness-planning agent is read-only. No two agents should edit the same source files without an explicit handoff.

## Retry budget and rollback

For each distinct failure: one initial attempt plus at most two targeted correction rounds. Record the failed observation, classification (application, transient tool/environment, authority or requirement), changed hypothesis and next result. A further round requires an explicit evidence-based budget revision; unchanged blind retries do not count as progress. A required check that is SKIPPED or BLOCKED never takes the success edge. A blocked lane does not stop independent authorized work.

Before retrying any state-changing operation, inspect whether the first operation happened. An unknown wallet submission or gateway mutation must not be replayed blindly. Rollback means stopping only processes created by this run, preserving the test state needed to diagnose ambiguity, and deleting disposable profiles only after retaining redacted evidence. Do not kill unrelated listeners, reset a shared chain, restore over user files, weaken security controls, or remove a pending record to create a passing result. Retain patch/diff evidence before undoing a code experiment. No production rollback is in scope because no production write is authorized here.

## Execution ledger at handoff

No checks are claimed complete by this plan. The root execution report will record actual results, attempt counts, commands/tools, source identities and evidence hashes.

| Node | Status | Recorded attempts | Evidence/result |
|---|---|---:|---|
| N0 | PENDING | 0 | Starting references above; fresh runtime identity still required. |
| N1 | PENDING | 0 | Awaiting actual extension/runtime evidence. |
| N2 | PENDING | 0 | Awaiting browser matrix evidence. |
| N3 | PENDING | 0 | Parallel implementation is not a verified result. |
| N4 | PENDING | 0 | Awaiting current public read-only observation. |
| N5 | PENDING | 0 | Awaiting combined validation and final reconciliation. |

The next safe step is to complete the isolated setup and independent RPC tests, then collect current evidence. This plan and contract alone cannot reduce the original remaining count. Final reporting must say exactly which original tasks closed, which remain partial/blocked, and what concrete missing evidence keeps each open.

## Final execution update

The creation ledger above is retained as the initial plan. N0–N5 completed within this turn's bounded contract; Graph consistency result is [PASS](graph-gate.json). Original backlog7items remain open and production remainsHOLD. [Final report](README.md), [criterion evidence](report.json), [remaining tasks](task-status.json).

The harness agent received a later bounded handoff to start/stop isolated services, run frontend checks, and copy redacted runtime identity. The first origin smoke was corrected with exact-origin POST/WS checks; a first disposable CLI session ended during a diagnostic listener, so the complete wallet matrix was rerun and recorded on a second new profile. An overly strict WS test expectation was corrected after observing the native error message; old-key denial remained the criterion. These environment/test-harness retries are retained in wallet/README.md and07–07b evidence. The independent RPC review found a concrete redaction defect; failing regressions preceded its fix and normal/optimized suites then passed. No blocked guest/proof action was rerouted or retried.

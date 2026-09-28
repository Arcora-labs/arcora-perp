# Existing seven-task continuation

The input is PR24 head `81b8c67e9af293c20b3efd7d8f0fadba6eba74c6`, in the isolated `arcora-local-verification` worktree. The Desktop checkout and preexisting runtime/data remain outside the write scope. The original criteria and dependency lists are frozen in `../2026-09-27-local/task-status.json`; preceding status is `../2026-09-28-post-merge/task-status.json`: eight of the original fifteen tasks closed, seven remaining. This turn adds no original task or acceptance condition.

| Node | Input / responsibility | Output / verification | Owner and side effect | Transition |
|---|---|---|---|---|
| L | SP1 6.1.0 depends on lru 0.12.5 with two unsoundness advisories | Manifest-only local SP1-prover patch to a fixed LRU version, original source/license provenance, locked graph, compile/tests and unsuppressed audit | Dependency agent; vendor + host/service manifests and locks | PASS permits ordinary proof on patched stack; failure remains visible |
| P | Same normal synthetic witness and SP1 6.1.0 ELF/vkey | Actual local CPU Groth16 proof with native/public equality and SDK verification; hashed proof artifacts only after success | Root; local CPU/Docker, public upstream downloads, bounded own-process memory/time | PASS only for produced/verified proof; infrastructure/resource failure is BLOCKED |
| E | Official matching v6.1.0 verifier, actual proof artifacts | Vendored unchanged verifier, real EVM positive and wrong-key/input/proof negatives | Contract agent; local Foundry only | Upstream fixture PASS is distinct from Arcora artifact PASS |
| V | Combined final code and evidence | Relevant regressions, exact source identity, unchanged original criteria/dependencies, PR24 update and concise report | Root/reviewer; local git and existing PR | READY_FOR_REVIEW for verified code; original seven remain governed by original dependencies |

The ordinary witness is not an actual vault deposit and has no trade/cancel operation; even an accepted proof does not establish S6-01. S5-03 depends on S5-02, whose A06 execution remains held. No A06 retry, prompt rewrite or alternate-agent execution is part of this plan. The archived tool record is a generic agent content-risk error, not a finding that Arcora is malicious. No production deployment, paid/network prover or merge of PR24 is authorized by this continuation.

Docker was started for local proof prerequisites. Existing containers were automatically resumed by Docker; they will not be stopped, modified or used as this task's proof service. Prover worker/buffer concurrency may be reduced through supported environment settings; verifier checks and recursion arity are unchanged. Resource monitoring may terminate only this task's own process group and records that as incomplete, never PASS. Initial attempt plus at most two evidence-based corrections per distinct failure; no blind retries.

Audit artifacts are excluded from the source digest and hashed separately. Any changed source/lock invalidates overlapping old tests until re-executed or exact relevant-file equality is documented. New proof artifacts go to fresh directories so failures and previous evidence remain intact.

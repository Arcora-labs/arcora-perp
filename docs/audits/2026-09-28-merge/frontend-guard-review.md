# Frontend mutation guards before merge

Only `frontend/src/api/realClient.ts` and its existing `realClient.test.ts` changed in this follow-up. The Desktop checkout was not edited.

`placeOrder` and the legacy gateway `deposit` operation capture the selected account and its existing credential epoch/account intent. Guards run after asynchronous initialization/epoch reads, before submitting a mutation, and after its response. A recovery attempt invalidates a pending operation even when the attempt fails and retains the original API key. A stale response cannot report success, refresh the new account, or trigger an automatic retry.

An explicit authentication refusal on the current account socket latches mutation refusal while retaining the in-memory and stored credential. Reads stay available. Only validated credential installation (including explicit wallet recovery or revalidation after reload) clears the latch. An obsolete socket cannot set it. This avoids creating a replacement account on a stream error.

Twelve deterministic regressions cover order/deposit attempts during pending recovery metadata, delayed epoch reads across successful and failed rotation, delayed mutation responses across rotation or auth refusal, no POST after auth refusal, and successful mutation under the confirmed recovered credential. The pre-fix targeted run produced 10 failed and 2 passed; the two passes are the ordinary successful-recovery cases.

Validation: focused client/recovery tests 156 passed; full frontend unit suite 408 passed with one explicitly skipped live-gateway e2e test; TypeScript/Vite build and diff check passed. `frontend-guard-checks.json` records argv, exits, counts, source manifests and log hashes. The earlier runtime evidence stays unchanged and is explicitly bound to its earlier source. Root owns the final browser run and independent review result.

# Final frontend mutation guard review

The final guard extends the initial narrow order/legacy-deposit change with a synchronous persistent credential check. Captured account key, owner and server recovery generation must still match the saved scoped credential before POST and after its response. Parsing the saved record also validates deployment scope. This rejects stale operations while a cross-tab storage event is undelivered or its validation request is pending. Confirmed session-only recovery remains usable when browser storage still contains the revoked old key.

Five added deterministic cases cover delayed order/deposit responses while newer credential adoption is held, an epoch read completing after a newer saved credential without a storage event, and successful order/deposit under session-only recovered access. The corrected pre-fix run failed the three unsafe cases and passed fourteen; final focused tests161 and full unit tests413 passed, with one explicit live-gateway e2e skip. TypeScript/Vite build and diff check passed. The seventeen cases include the twelve initial mutation/auth-refusal scenarios.

The initial manifests/checks/logs and earlier runtime reconciliation evidence are unchanged. `frontend-guard-final-checks.json` binds current checks to `frontend-guard-final-source.json`; previous408-unit/72-browser evidence is not relabeled. Root owns the final browser run and the independent review disposition.

Only `frontend/src/api/realClient.ts` and `frontend/src/api/realClient.test.ts` changed in this follow-up. No Desktop source, wallet, chain or external account was modified. Stale server outcomes are not automatically retried.

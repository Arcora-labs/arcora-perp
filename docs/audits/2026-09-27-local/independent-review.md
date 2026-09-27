# Local independent code review — 2026-09-27

Scope: working-tree changes relative to `098e4952c189f92e4293ed7d49f81222b626e406`, limited to frontend credential persistence and withdrawal/cancel context guards, snapshot restoration/size bounds, listener configuration and the core batch-counter check. Read-only source review; no production files modified and no broad builds run. This is an additional local review, not an external audit or release approval.

## Finding

**IR-01 · P2 · Session-only credential warning disappears after a failed second recovery attempt.**

- Location: `frontend/src/components/RecoveryPanel.tsx:20` and `:27-29`; the newly retained warning is initialized at `:12-14`.
- Trigger: first recovery succeeds while credential storage throws (quota or denied storage), leaving `client.credentialStorage === "session"`. The user starts recovery again and rejects the wallet signature, or the new attempt otherwise fails before installing a replacement.
- Result: `setResult(null)` removes the only tab-only persistence warning; the catch path sets only the error. The existing in-memory credential remains session-only, but the panel no longer tells the user to keep the tab open or recover after reload. The initializer does not run again until remount.
- Evidence: source-confirmed control flow; the reviewer did not execute an additional browser reproduction. `frontend/tests/browser/local.spec.ts:256-262` verifies remount persistence, and `:120-130` verifies the first failed storage write, but neither performs a failed second attempt. The existing `RecoveryPanel.test.tsx` similarly checks only the first successful session-only result.
- Fix: show the current credential's session-only warning independently of transient attempt result/error state. A failed subsequent attempt must preserve both its error and the warning. Add a browser regression with quota failure, successful first rotation, rejected second signature, unchanged in-memory credential and no extra rotation POST; also check that a later successfully persisted credential clears the warning.

## Other reviewed changes

No additional correctness defect identified in this bounded pass:

- Withdrawal captures the selected market before asynchronous work, signs and posts the same market, checks credential ownership after the auth read/signature/POST; cancellation suppresses a late success event after recovery changes the credential. The withdrawal proof read discards results after a credential epoch change.
- Legacy storage contributes only a syntactically validated public owner hint. The old unscoped API key is neither adopted nor transmitted by the added helper.
- V8 execution framing uses postcard's actual consumed boundary rather than searching arbitrary payload bytes. Row count, duplicate/missing/orphan and execution validity checks precede caller-owned metadata mutation. Full boot owns its temporary decoded state, so subsequent recovery-extension rejection does not publish partial state.
- Snapshot file reads are limited at the descriptor as well as metadata; oversized atomic writes reject before touching the durable target. `boot_restored` and sealed intake enforce the matching payload/envelope limits.
- Listener input becomes an explicit `SocketAddr`, with invalid text rejected; default `0.0.0.0:8080` deliberately remains unchanged. Local loopback therefore depends on the explicit verification environment.
- `apply_batch` checks `next_batch_id` exhaustion before applying operations and commits the increment only after successful completion. The added tests cover last representable success and subsequent non-mutating rejection in both debug/release evidence.

## Evidence and limits

Inspected regression source and existing evidence, without representing those earlier runs as reviewer reruns: frontend `evidence.json`/`browser.log` report 36 browser cases passing and 316 unit tests passing with one skipped; snapshot `parser-after.log` reports the original five focused parser tests passing (it does not establish execution of later-added historical/mutation tests); listener log reports three passing; core debug and release logs include both added exhaustion tests passing.

Remaining validation gaps are separate from IR-01: actual extension wallets and Safari/private-profile behavior, browser-to-real-gateway integration, a newly built SP1 guest/verifying-key workflow, production configuration/deployment, and external independent audit are not established by this review. The reviewer did not inspect the entire financial protocol or validate production keys. Other task evidence must retain its own scope and current source hashes.

## Closure recorded by integrating agent

IR-01 was reproduced as a real Chromium assertion failure, then fixed by deriving the warning from current credential storage independently of attempt result/error. The same case passed Chromium and WebKit; four component tests and the final38-case browser suite passed. See `frontend/reviewer-session-evidence.json` and `frontend/evidence.json`. This is implementer/integrator closure, not a second independent reviewer rerun.

Later journal fail-closed changes are outside this reviewer's original scope. No claim of external audit or independent full-protocol signoff is made.

# Frontend local verification — 27 September 2026

This lane uses Graph Engineering and the Playwright skill. Worktree baseline is `098e4952c189f92e4293ed7d49f81222b626e406`. No original-worktree edits, push, deploy, external wallet signature or chain transaction were performed. `evidence.json` binds the final frontend files and logs by SHA-256; the dirty source fingerprint matters in addition to the unchanged base commit.

## Reproduce

From `frontend/` with Node and pnpm installed:

```sh
pnpm install --frozen-lockfile
pnpm exec playwright install chromium webkit
pnpm typecheck
pnpm test
pnpm build
pnpm test:browser
```

Browser test server binds **127.0.0.1:4173**. It builds a separate test-only entry under `output/playwright/build`; ordinary `dist/` contains neither the client capture wrapper nor test-wallet controls. Playwright output is ignored. Do not serve the harness publicly. No environment keys are needed. Run with port 4173 free; the suite fails rather than reusing another process. Every test has a fresh context; the two-tab tests explicitly use two pages in the same context and origin. Storage partitioning and cross-origin tabs are not simulated as shared storage.

## Confirmed findings and fixes

| Finding | Failed-before assertion | Fix |
|---|---|---|
| Legacy owner hint absent from recovery UI | Expected visible legacy message/input owner; absent | Read only validated public legacy owner, explain wallet authority and preserve legacy bytes |
| Withdrawal payload reread mutable market after signing | Expected market 0, received 1 after selecting ETH | Capture market at method entry and reuse for digest and POST |
| Withdrawal signature pending across rotation | Expected refusal/no POST; returned success | Check selected account credential before/after signing and after submission |
| Cancel response after rotation emitted success | Expected account-change error; returned success | Check credential context before DELETE and before success event |
| Old withdrawal list escaped after rotation | Expected null; received old-context list | Reject response if credential epoch changed |
| Session-only warning disappeared on panel navigation | Expected status after remount; absent | Retain persistence status on client; render it on RecoveryPanel remount |
| Denied localStorage read crashed application shell | Expected Recover navigation; absent | Catch denied reads in TestnetNotice initializer |

Real failing assertions are in `failed-before.log`, `failed-before-context.log` and `failed-before-storage-ui.log`. These are behavior assertions from running Chromium, not compilation failures. The first five run on the unmodified baseline application; the last two were added after the first fixes and independently reproduced before their fixes. `passed-after*.log` verifies targeted closure; the final suite verifies both engines on the final source.

## Evidence boundary

- Browser API and WS responses are deterministic route fixtures; the provider is a controlled EIP-1193 object with synthetic signatures. Browser fetch, native WebSocket objects, native Web Locks and shared localStorage events are real.
- Stalled-body test uses actual loopback HTTP headers plus an unfinished JSON body and real 15-second deadlines, three bounded attempts. It does not fast-forward timers or treat a timeout as recovery success.
- Obsolete-socket test captures old callbacks from native sockets and invokes late callbacks after rotation. Transport delivery is route-controlled; this is not real Rust gateway TCP backpressure evidence.
- The full unit run retains the existing one skipped HTTP integration test when `GATEWAY_URL` is unset. Root owns a separate live-loopback HTTP run; its NullWebSocket boundary must remain explicit.
- No actual Safari, real extension wallet, hardware wallet, OS private browsing profile, external chain or production CSP/telemetry collector was tested. Browser threat model, mutation matrix and manual-wallet-test state the remaining gates. S2 as a whole is **PARTIAL**, with this local fixture matrix and seven fixes ready for independent review.

Source review covered the two edited TSX components using the React best-practices checklist: hooks are unconditional, storage reads use lazy state initialization, new owner/error text is React-escaped, the input remains labelled, and no new global subscriptions were introduced. No frontend redesign was performed.

`dependency-review.md` separates the exact Playwright test dependency from compatible transitive security patches. Production audit is clean; remaining dev-tool advisories require a dedicated major Vite/Vitest migration. See audit JSON for live registry results.

## Independent-review follow-up

The reviewer additionally confirmed that a failed second recovery erased the session-only warning. This was reproduced before its fix and now passes in both browser engines plus four component tests. See `reviewer-session-followup.md` and `reviewer-session-evidence.json`. The final full browser rerun passed all 38 cases (19 per engine) on the current source. The earlier 36-test result remains historical.


## Final aggregate validation

Current fingerprint: `2197bb43294d70e05de671adb2e7807e0b41f19c463987ebda84fa38d5c3a02a` (see `final-source-manifest.json`). Frozen-lock installation, typecheck and production build passed. Unit tests: **317 passed / 1 existing live HTTP test skipped**. Browser tests: **38 passed / 0 skipped / 0 flaky**, with all cases run in both Chromium and WebKit.

Root separately ran the skipped HTTP test against its real ephemeral loopback gateway: **1 passed**, captured by `../runtime/http-smoke.log` and `../checks/live-http-restore-integrated.json`. It uses happy-dom and NullWebSocket; this is real HTTP sealing/decryption evidence, not a browser connected to a real gateway WebSocket. These test selections overlap and are reported separately. No frontend source changed during final aggregate verification.

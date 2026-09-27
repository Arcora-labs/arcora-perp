# Local browser threat model and CSP

The harness builds the real App, RecoveryPanel and RealDarkPerpClient as a test-only production bundle. A capture wrapper exposes the client to the test process; it is excluded from the normal `pnpm build`. The loopback static server applies CSP HTTP headers. API responses and WebSocket messages are deterministic Playwright route fixtures; `/__stall-body` is an actual loopback HTTP response whose body never completes. Native browser Web Locks, localStorage, StorageEvent, fetch, React rendering and WebSocket objects execute in Chromium and WebKit.

## Surfaces reviewed

- React interpolation of gateway errors, market/order labels, recovery messages and addresses; no production `dangerouslySetInnerHTML`, `innerHTML`, `eval`, `new Function` or `document.write` sink found by source search.
- `ApiAccess`: clipboard contains API examples. Withdrawal clipboard builds an intentionally public claim command (recipient, amount, nonce, Merkle proof); do not classify a public proof as a private spend key.
- External links in AccountPanel, WalletButton, HealthPanel, TestnetNotice and ApiAccess use `rel=noreferrer`. Their transaction suffixes and gateway base remain untrusted render inputs; React escaping is required.
- `credentialStore`: schema 2 is scoped by endpoint/chain/vault. The old unscoped key is a migration hint only; only its validated public owner is exposed.
- Real client logging and ErrorBoundary: source currently logs some caught Error objects. Fixture flows assert synthetic API credentials do not appear in console messages or request URLs. This is bounded evidence, not proof that an arbitrary compromised dependency/provider cannot log secrets. There is no telemetry/CSP reporting collector in this local harness.

## Applied policy

See `csp-local-policy.txt`; policy is applied by `frontend/tests/browser/server.mjs`, not by production deployment configuration. Script execution is same-origin only; inline script execution and external fetch are explicitly rejected by tests. Styles require `unsafe-inline` because existing React components set inline style attributes. Inline scripts, eval, object, framing, form submission and base rewrites are prohibited. Same-origin HTTP plus explicit loopback WebSocket are allowed. A real browser wallet extension may have additional requirements; injected fixture wallet signing works under the policy but does not prove extension compatibility.

## Trust boundary

Any JavaScript executing in this origin can read localStorage API credentials. Web Locks provide concurrency ordering, not encryption or XSS isolation. CSP reduces injection paths; an allowed compromised same-origin script retains credential access. API keys belong in authenticated headers/WS auth frames, never URLs. Wallet signatures are necessarily sent to the authorized gateway endpoint; tests deliberately do not export raw network traces or bodies. The harness uses only synthetic fixtures and exports counts/names/outcomes plus public owner screenshots if requested.

Gateway custody/spend-key/oracle trust is unchanged. This work does not make the architecture non-custodial. Production CSP rollout, report redaction, extension wallet testing and independent review require separate verification.

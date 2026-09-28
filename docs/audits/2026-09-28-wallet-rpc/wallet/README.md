# Actual extension wallet and native gateway

The official **MetaMask 13.50.0** extension ran unmodified in a new persistent Playwright Chromium **154.0.8037.0** profile. [Package identity](extension-identity.json) verifies the GitHub release asset SHA-256 and all 676 extracted files. No existing user browser/wallet, private key or seed phrase was read. The account was generated in the disposable extension UI. Usage-data collection was declined.

The served application was the compiled real App/RealDarkPerpClient with only its existing test-only client inspection hook. The gateway was the real Rust binary using a fresh isolated demo snapshot, exact loopback origin allowlist and real HTTP/WebSocket transport. No wallet provider, signature, gateway response or account endpoint was mocked. MetaMask's pending side-panel URL was discovered through Chromium target metadata and opened as an extension page; all Connect/Confirm/Cancel actions used the extension's actual UI. The extension code and protection settings were unchanged.

## Executed checks

| Evidence | Actual assertion |
|---|---|
| [01](01-onboard-result.json), [02](02-connect-result.json), [03](03-bind-result.json) | New extension wallet; connect; actual personal signature bound to the native account. |
| [04](04-rotation-result.json) | Two same-origin tabs; native Web Lock refuses the sibling before second recovery; actual Cancel preserves the key; Confirm rotates generation 0→1; old HTTP credential returns 401; old private socket closes; sibling adopts the same new key; both reload the same owner/generation. |
| [05](05-storage-result.json) | Controlled credential-write QuotaExceededError: actual approved rotation 1→2 remains usable in memory (HTTP200), saved generation remains1, visible session-only warning. Reload shows degraded account placeholders and makes zero replacement registrations. |
| [06](06-legacy-result.json) | Controlled wrong-vault/corrupt records stay byte-preserved, with zero authenticated requests or registrations. Legacy hint is retained; actual wallet recovery restores the same owner at generation3 without erasing the legacy record. |
| [07b](07b-final-checks-result.json) | Old key receives native WebSocket `unknown api key`, never authOk; controlled missing Web Locks prevents any POST; strict applied CSP supports extension signatures and gateway traffic. Four real credential values checked in memory against captured console/network/observation data: zero leaks. |
| [08](08-native-ws-auth-result.json) | Gateway stopped cleanly and restarted from the same durable snapshot. Both reloaded tabs received a real `authOk` frame for their exact owner and retained generation3/HTTP200. This strengthens the earlier readyState-only transport observation. |

The corresponding `.js`, `.log`, and `.json` files retain the exact executed Playwright CLI code, output and exit status. `07-final-checks` is a retained failed harness assertion: it initially expected the server to close an unauthenticated connection. `07a` observed the actual `unknown api key` response; `07b` checks denial, then closes the test socket client-side. This does not claim that the server closes on its first failed authentication.

## Boundaries and retries

- The no-L1 gateway recovery domain was chain84532 / zero vault; the MetaMask UI displayed its default Ethereum network for personal-sign messages. No chain transaction or token/proof lifecycle was executed. Existing S2 mutation fixture tests and this actual extension integration are separate evidence. S6-01 remains open.
- Before the recorded successful run, initial GET-only smoke missed the exact-origin allowlist needed by POST/WS. This was corrected and both allowed101/200 and forbidden403 paths were checked. The gateway snapshot and proxy origin were preserved.
- The first disposable browser run passed recovery/session tests, then its CLI daemon terminated during a diagnostic request listener. Its observations were not substituted for the recorded run: a second fresh profile reran the matrix. No user browser process was touched.
- MetaMask emitted extension listener/intrinsic warnings; deliberate stale credentials generated401 and storage/scope fault warnings. These are retained in the final result. The run does not claim zero console warnings. No CSP violation affecting the flow was observed.
- API keys were kept in browser/test-process memory. Exported network records contain method/path/count and authenticated-present booleans, not header values, response bodies or signatures. No raw HAR/trace is committed. Browser captures under `output/playwright/` are ignored; reviewed evidence is here.
- Same-origin JavaScript can still access localStorage credentials. CSP reduces injection paths but cannot make an already trusted compromised script safe. Web Locks order concurrent actions; they do not encrypt credentials. The original [threat inventory](../../2026-09-27-local/frontend/browser-threat-model.md) remains applicable.
- Actual Safari/hardware wallets, production hosting CSP and all-wallet certification were not executed and are not added to the original S2 acceptance criteria.

Official release: [MetaMask v13.50.0](https://github.com/MetaMask/metamask-extension/releases/tag/v13.50.0). Browser setup follows [Playwright persistent extension guidance](https://playwright.dev/docs/chrome-extensions).

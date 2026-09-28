# Deposit reconciliation UI continuation — 2026-09-28

## Delivered behavior

The wallet deposit card now reads its existing durable journal at mount and on same-tab/cross-tab storage updates. A pending original operation remains visible after reload, wallet disconnection, credential rotation or market selection changes. The recovery card shows the original wallet, chain/network, owner, gateway, vault, market id, exact six-decimal USDC amount, last transaction step and recorded transaction hash.

`Check original transaction` is a separate status action. It uses the original native Web Lock and a fresh existing-account context, validates the saved revision, pins the provider/wallet/network, and checks the receipt for the exact recorded transaction hash. It has no network-switch, wallet-signature, authorization or transaction-send call. Pending and reverted receipts retain the journal. A confirmed deposit proceeds only through the original gateway credit receipt API; the existing gateway API may ingest/finalize the original deposit, but no new chain transfer is created. Journal removal requires the same owner/deployment/market, a durable validated receipt and exactly the original amount.

Same-owner credential rotation can therefore finish the original deposit under the newly captured credential. A credential change while a receipt/credit request is pending invalidates that result. No response can clear a different operation. `existingOnly` reaches the actual registration boundary (`initAccount(false)`), so a missing/deleted saved credential cannot create a replacement account during a check or explicit resume.

For a confirmed mint/approval, the status action can record confirmation and the current same-owner credential generation. A later explicit `Resume original deposit` retains the original amount and exact journal identity/revision. It cannot turn a gateway/deployment/owner/market mismatch into a fresh flow. Completed transaction steps without hashes and malformed transaction containers fail closed.

## Unknown hash and reverted-transaction boundary

When a wallet send did not return a hash, the card identifies the original step and amount, explains the missing result, and directs the user to that wallet's activity on the displayed network. New sends remain blocked. There is no arbitrary hash input, automatic matching, destructive clear or replacement-send action.

The existing v1 journal does not contain an immutable original calldata fingerprint. Therefore this round does not claim to discover and verify an unknown transaction's exact from/to/chain/input/value. Such discovery needs a separate verified RPC/transaction-context design. A reverted known transaction is displayed and retained; automatic replacement or journal clearing after a revert is also outside this change.

## Validation and evidence

- `pnpm --dir frontend test`: 396 passed; one explicitly skipped live-gateway e2e test. `reconciliation-unit-final.log`.
- `pnpm --dir frontend build`: TypeScript + Vite 6.4.3 build passed. `reconciliation-build-final.log`.
- Focused Chromium browser iteration: 17 passed. `reconciliation-browser-iteration.log`.
- Final full Chromium/WebKit suite: 72 passed, exit0. Original list log retained in `reconciliation-browser-final.log`; shared Playwright JSON was later overwritten by the narrow visual run and is not reused as full-suite evidence.
- Exact frontend hashes/runtime versions: `reconciliation-source-pre-layout.json` binds the 396-unit/72-browser runs; `reconciliation-source.json` binds the final source. Actual argv, observed exit codes, counts and log hashes are in `reconciliation-checks.json`.
- Final narrow layout follow-up: the existing bound withdrawal address in `AccountPanel.tsx` received one `overflowWrap: "anywhere"` style after a 320px overflow was observed. No deposit/API logic changed. The actual rebuilt final source passed 24 AccountPanel component tests, the production build, and one temporary Chromium visual test covering both 390×844 and 320×844 with no viewport horizontal overflow. `reconciliation-visual.log`, `reconciliation-layout-components.log`, `reconciliation-narrow-390.png`, and `reconciliation-narrow-320.png`. The temporary harness is archived as `reconciliation-visual.fixture.ts`, outside the persistent browser suite.
- Playwright-owned server exited; no listener remained on port4173 (`reconciliation-server-cleanup.log`).
- `git diff --check -- frontend`: passed.

The additional deterministic cases cover no-send receipt checking; same-owner rotation; original owner/endpoint/chain/vault/market mismatch; pending/reverted/malformed/missing-hash receipts; stale receipt and credit results; altered display metadata; unknown send; stale journal revisions; exact resume identity across gateways; malformed completed steps without hashes; and saved-credential removal between reads without replacement registration. Updated browser flows exercise visible original metadata, reload recovery, native cross-tab locking, credential rotation, market restoration, malformed credit receipts, and pending/reverted statuses while asserting unchanged wallet send counts.

Independent read-only review found and drove fixes for cross-gateway resume, malformed completed journals, missing receipt-hash acceptance, and registration through an existing-only storage race. The reviewer rechecked the fixes and reported no remaining blocking finding in the reviewed code. This is not a claim of a full security audit.

No real wallet, live chain write, external credential, dependency addition or deployment occurred in this lane. Actual extension-wallet/RPC rehearsal remains a separate release gate. S2-03 is still PARTIAL as a release-wide item.

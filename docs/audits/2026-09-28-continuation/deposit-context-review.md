# S2-03 deposit continuation — 2026-09-28

## Outcome and boundary

Local frontend deposit races are guarded through capture → chain → mint → approve → bind → authorize → deposit → credit. Work is uncommitted on `5c71b2d`; exact tested source hashes and runtime versions are in `deposit-source.json`. This is frontend/browser evidence with synthetic HTTP/EIP-1193 fixtures, not a real gateway deposit, extension-wallet rehearsal, on-chain transfer, or proof.

The broader S2-03 release gate remains PARTIAL: an authorized local RPC/test-wallet integration, actual extension-wallet signing delays and independent review are still required. No real wallet, external credential, deployment, A06 work, or chain write was used.

## Changes

- `RealDarkPerpClient.captureDepositContext` captures immutable owner, endpoint/chain/vault, market selection intent, recovery nonce, credential epoch and account intent. Client-owned contexts retain their original credential privately. Bind, authorize and credit validate before POST and after response; a context from another client is refused. Switching market away and back also invalidates the old context. Raw storage changes are checked before cross-tab adoption completes.
- The wallet runner captures the amount and UI identity, checks the account context and pinned provider/current account/current chain after every await, and observes account/chain/disconnect events. Transaction requests explicitly include the captured Base Sepolia chain id. A transaction already accepted by an external wallet cannot be retracted; its returned hash is retained for reconciliation and no later step runs after context changes.
- Origin-native Web Locks serialize wallet deposit attempts by normalized wallet address and deployment. Missing Web Locks or failed durable storage refuses new sends.
- A credential-free localStorage journal records the exact amount, owner/market/generation, completed steps and transaction hashes. A pending-send marker is saved and read back before each wallet transaction prompt. Only explicit wallet rejection clears an unknown send; an RPC failure, malformed hash or closed tab cannot trigger a duplicate transfer. Known hashes resume the original wait/credit, including after reload. The journal never contains API keys, signatures or owner commitments.
- The credit API requires the current gateway durable receipt wire shape (`status=credited`, `durability=confirmed`, positive u128 amount, collateral purpose, captured market, unique nonempty safe-integer deposit ids, and matching owner/chain/vault/recovery nonce). The runner additionally requires exact original amount equality before deleting the journal. Missing, unknown, zero, negative, out-of-range or mismatched receipts remain pending recovery of the original transaction. Sixteen raw-client and four flow regressions cover this gate.
- An empty journal with no hash and no outstanding send can be discarded, permitting a new intent after first-prompt rejection. Existing transactions and unknown outcomes remain fenced. The old unscoped binding cache is no longer trusted; a new deposit asks for a bind signature, while a resumed journal can skip a confirmed bind.

## Verification

- `pnpm --dir frontend test`: 370 passed, 1 explicitly skipped live-gateway e2e; 28 test files passed. `deposit-unit.log`.
- `pnpm --dir frontend build`: TypeScript and Vite production build passed. `deposit-build.log`.
- Full existing + added Playwright suite: 58 passed across Chromium and WebKit. `deposit-browser.log`. This ran before the final address-normalization/empty-journal/chain-id/receipt-validation refinements; final deposit-only browser verification and all unit/build checks were repeated afterward.
- Final `pnpm --dir frontend exec playwright test deposit.spec.ts`: 28 passed across Chromium and WebKit. `deposit-browser-final.log`.
- 53 new unit/component/client cases: 12 credential barriers from account capture through credit; wallet account/chain/disconnect events; current-account RPC checks; deployment mismatch; unknown mint/approve/deposit sends; origin lock; normalized address lock; storage/lock absence; recorded-hash preservation; unknown credit retry; empty-journal rejection recovery; immutable API contexts, market switch away/back, foreign-client context, storage owner/generation change, late credit reply, and amount change during signature.
- 14 new browser scenarios per engine: full exact calldata/HTTP flow; market switches during four wallet stages; two same-origin tabs with native lock plus credential propagation; delayed authorize and credit responses across rotation; unknown-send reload fencing; known-transaction credit resumption after reload; missing/unknown/zero/wrong-amount receipts retain the journal and retry only original credit.

The initial browser fixture run failed on an ambiguous `Connect wallet` locator (header and account card); the fixture was scoped to `.walletflow` using the emitted accessibility snapshot, then all cases passed. One storage-failure unit fixture initially spied on the wrong happy-dom target; it now spies on the actual storage instance. These were test-fixture corrections, not weakened product assertions.

## Remaining reconciliation limitation

Unknown sends without a hash intentionally stay blocked. There is no user-facing journal-clear or transaction-discovery wizard in this change: wallet/RPC activity must first establish whether the original transaction exists and which hash/receipt belongs to it. Credential/owner/market changes after a known send also require original-context reconciliation. Do not erase storage or suggest a new transfer as a substitute. Browser storage clearing, separate origins/profiles/devices, and provider behavior that ignores transaction chain id are outside this origin-local guard; the gateway and on-chain replay/finality checks remain separate requirements.

Production deployment configuration is not upgraded here. The configured wallet token/vault must match the gateway deployment; mismatch refuses all sends before a wallet transaction is requested.

Final root integration: after the dependency migration and truthful environment notice correction, the complete frontend suite passed 371 tests (1 live e2e skipped), all 66 Chromium/WebKit scenarios passed, and production build passed. See `checks/frontend-final.json`, `checks/frontend-browser.json` and `checks/frontend-build.json`; earlier agent counts above retain their original scope.

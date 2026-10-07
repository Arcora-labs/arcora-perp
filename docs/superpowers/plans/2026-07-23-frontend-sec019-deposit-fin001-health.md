# Frontend SEC-019 Deposit Flow + FIN-001 Health Implementation Plan


**Goal:** Cut the frontend deposit flow over to the SEC-019 contract (`deposit(uint256,bytes32,bytes)` via `POST /v1/accounts/deposit/authorize`), and surface the FIN-001 settle-loop breaker state in the HealthPanel.

**Architecture:** Three self-contained layers, one task each: (1) the new `authorizeDeposit` client method + capability gate; (2) the calldata encoder cutover + wallet step-machine reorder (bind now precedes deposit); (3) the FIN-001 `settlement` field threaded wire→state→HealthPanel. Spec: `docs/superpowers/specs/2026-07-23-frontend-sec019-deposit-fin001-health-design.md`.

**Tech Stack:** React 18 + TypeScript + Vite, `@noble/hashes` (keccak), vitest + happy-dom + @testing-library/react. NO wallet library — raw EIP-1193 + hand-encoded ABI (house rule).

## Global Constraints

- **No new dependencies.** Everything is hand-rolled on `@noble/*` like the rest of `frontend/src/api/wallet.ts`.
- **Clean cutover:** the final tree contains NO `deposit(uint256)` encoder/selector residue (`grep -F 'deposit(uint256)' frontend/src` must only hit the 3-arg form, i.e. zero exact matches).
- **Addresses stay hardcoded** (`MOCK_USDC`, `COLLATERAL_VAULT` in `wallet.ts`) — do NOT invent a config endpoint. They change only in the future redeploy commit.
- **Defensive wire parsing** (house style of `realClient.ts`): malformed server data → readable throw (POST paths) or `null` (state-snapshot paths), never a crash.
- All commands run from `<repo>/frontend`.

**Pinned facts (verified against `main` 2026-07-23 — do not re-derive):**
- Gateway endpoint: `POST /v1/accounts/deposit/authorize`, auth `X-Api-Key`, body `{ "from": "0x…20-byte", "amount": "<u128 decimal string>" }` → `{ "ownerCommit": "0x…32-byte", "sig": "0x…65-byte" }`. Errors are `{ "error": "…" }` with 400 (e.g. `"Bind a deposit address first (POST /v1/accounts/deposit/address)."`).
- Contract: `CollateralVault.deposit(uint256 amount, bytes32 ownerCommit, bytes calldata sig)`; sig must be exactly 65 bytes `r‖s‖v`, v ∈ {27,28}.
- Selector `deposit(uint256,bytes32,bytes)` = **`0x2b681307`** (keccak-derived, verified with @noble in-repo).
- FIN-001 wire fields on the state snapshot (`WState` is `rename_all = "camelCase"`): `settlementHealth` (`"HEALTHY"|"DEGRADED"|"HELD"`), `settlementConsecutiveFailures` (number), `settlementLastError` (string, omitted when none), `settlementHeldSinceMs` (number, omitted unless HELD).

---

### Task 1: `authorizeDeposit` client method + capability gate

**Files:**
- Modify: `src/api/wallet.ts` (interface `WalletDepositClient` ~line 372, guard `supportsWalletDeposit` ~line 382)
- Modify: `src/api/realClient.ts` (new method after `bindDepositAddress`, ~line 772)
- Modify: `src/api/wallet.test.ts` (guard tests, `describe("supportsWalletDeposit")` ~line 336)
- Modify: `src/api/realClient.test.ts` (fetch-mock handler + new describe block)
- Modify: `src/components/AccountPanel.wallet.test.tsx` (fake client in `makeClient()` ~line 82 — typecheck only this task; behavior asserted in Task 2)

**Interfaces:**
- Consumes: existing `private post<T>(path, body, headers?)` and `ensureAccount()` on `RealDarkPerpClient`; `s(v: bigint): string` module helper.
- Produces: `authorizeDeposit(from: string, amount: bigint): Promise<{ ownerCommit: string; sig: string }>` on `WalletDepositClient` and `RealDarkPerpClient` — Task 2's step machine calls exactly this signature. Test constants `COMMIT = "0x" + "ab".repeat(32)`, `GWSIG = "0x" + "cd".repeat(65)` and the `authorizeCalls` array in `makeClient()` — Task 2's tests assert against these names.

- [ ] **Step 1: Write the failing guard tests** — in `src/api/wallet.test.ts`, replace the body of `it("true only when all three wallet-deposit methods exist", …)` with:

```ts
  it("true only when all four wallet-deposit methods exist", () => {
    const full = {
      depositAccount: vi.fn(),
      bindDepositAddress: vi.fn(),
      authorizeDeposit: vi.fn(),
      creditOnchainDeposit: vi.fn(),
    };
    expect(supportsWalletDeposit(full)).toBe(true);
    expect(supportsWalletDeposit({})).toBe(false);
    expect(supportsWalletDeposit(null)).toBe(false);
    expect(supportsWalletDeposit({ depositAccount: vi.fn() })).toBe(false);
    // SEC-019: a client without the authorize call must NOT pass the gate —
    // it could only build the pre-SEC-019 deposit the vault now rejects.
    expect(supportsWalletDeposit({ ...full, authorizeDeposit: undefined })).toBe(false);
  });
```

(The `it("the REAL gateway client passes the gate; the mock does not", …)` test stays byte-identical — it will fail until the real client gains the method, which is the point.)

- [ ] **Step 2: Run to verify it fails**

Run: `pnpm vitest run src/api/wallet.test.ts -t "supportsWalletDeposit"`
Expected: FAIL on the `{ ...full, authorizeDeposit: undefined }` → `false` assertion (the guard doesn't check the method yet, so it still returns `true`).

- [ ] **Step 3: Extend the interface + guard** — in `src/api/wallet.ts` replace the `WalletDepositClient` interface and guard with:

```ts
export interface WalletDepositClient {
  /** The self-provisioned /v1 account (apiKey + 32-byte owner pubkey). */
  depositAccount(): Promise<{ apiKey: string; owner: Uint8Array }>;
  /** POST /v1/accounts/deposit/address — bind the EOA (ownership-proven). */
  bindDepositAddress(address: string, signature: string): Promise<void>;
  /** POST /v1/accounts/deposit/authorize — SEC-019: the gateway pre-authorizes
   *  this exact (from, amount), returning the blinded ownerCommit + 65-byte
   *  gateway sig that `deposit(amount, ownerCommit, sig)` requires on-chain.
   *  `from` must be the account's already-bound deposit address. */
  authorizeDeposit(from: string, amount: bigint): Promise<{ ownerCommit: string; sig: string }>;
  /** POST /v1/accounts/deposit/onchain — credit a confirmed deposit tx. Returns
   *  the credited amount in USDC base units. */
  creditOnchainDeposit(txHash: string): Promise<bigint>;
}

export function supportsWalletDeposit(c: unknown): c is WalletDepositClient {
  const x = c as Partial<Record<keyof WalletDepositClient, unknown>> | null;
  return (
    typeof x === "object" &&
    x !== null &&
    typeof x.depositAccount === "function" &&
    typeof x.bindDepositAddress === "function" &&
    typeof x.authorizeDeposit === "function" &&
    typeof x.creditOnchainDeposit === "function"
  );
}
```

- [ ] **Step 4: Add the failing realClient tests** — in `src/api/realClient.test.ts`:

(a) Next to the other per-test override lets (`let v1WithdrawStatus = 200;` ~line 108), add:

```ts
let authorizeStatus = 200; // per-test override: gateway rejection (bind-first etc.)
let authorizeBody: unknown = null; // per-test override of the response body (null ⇒ well-formed default)
```

(b) In `installFetch()`'s handler chain (next to the `/v1/accounts/withdraw` branch), add:

```ts
      if (path === "/v1/accounts/deposit/authorize" && method === "POST") {
        if (authorizeStatus !== 200) {
          return json(
            { error: "Bind a deposit address first (POST /v1/accounts/deposit/address)." },
            authorizeStatus,
          );
        }
        return json(authorizeBody ?? { ownerCommit: "0x" + "ab".repeat(32), sig: "0x" + "cd".repeat(65) });
      }
```

(c) In the `beforeEach`, add the resets:

```ts
  authorizeStatus = 200;
  authorizeBody = null;
```

(d) Add a new describe block (top level, near the other /v1 account flows):

```ts
describe("authorizeDeposit (SEC-019)", () => {
  const FROM = "0x" + "22".repeat(20);

  it("POSTs from+amount under the account key and returns ownerCommit+sig", async () => {
    const client = await bootstrapClient();
    const r = await client.authorizeDeposit(FROM, 1_000_000_000n);
    expect(r).toEqual({ ownerCommit: "0x" + "ab".repeat(32), sig: "0x" + "cd".repeat(65) });
    const call = calls.find((c) => c.path === "/v1/accounts/deposit/authorize");
    expect(call).toBeTruthy();
    expect(call!.method).toBe("POST");
    expect(call!.headers["X-Api-Key"]).toBe(ACCT_KEY);
    expect(call!.body).toEqual({ from: FROM, amount: "1000000000" });
  });

  it("surfaces the gateway's bind-first error text verbatim", async () => {
    authorizeStatus = 400;
    const client = await bootstrapClient();
    await expect(client.authorizeDeposit(FROM, 1n)).rejects.toThrow(/Bind a deposit address first/);
  });

  it("rejects a malformed ownerCommit from the gateway", async () => {
    authorizeBody = { ownerCommit: "0x1234", sig: "0x" + "cd".repeat(65) };
    const client = await bootstrapClient();
    await expect(client.authorizeDeposit(FROM, 1n)).rejects.toThrow(/ownerCommit/);
  });

  it("rejects a malformed signature from the gateway", async () => {
    authorizeBody = { ownerCommit: "0x" + "ab".repeat(32), sig: "0x1234" };
    const client = await bootstrapClient();
    await expect(client.authorizeDeposit(FROM, 1n)).rejects.toThrow(/65-byte/);
  });
});
```

- [ ] **Step 5: Run to verify the new tests fail**

Run: `pnpm vitest run src/api/realClient.test.ts -t "authorizeDeposit"`
Expected: FAIL with `client.authorizeDeposit is not a function`

- [ ] **Step 6: Implement `authorizeDeposit`** — in `src/api/realClient.ts`, directly after the `bindDepositAddress` method, add:

```ts
  /**
   * `POST /v1/accounts/deposit/authorize` — SEC-019: the gateway pre-authorizes
   * this exact (from, amount) for the vault, returning the blinded `ownerCommit`
   * + the 65-byte gateway signature that `deposit(amount, ownerCommit, sig)`
   * requires on-chain. The gateway refuses unless `from` is the account's bound
   * deposit address — its error text ("Bind a deposit address first…") is
   * surfaced verbatim so the pipeline shows the real reason.
   */
  async authorizeDeposit(
    from: string,
    amount: bigint,
  ): Promise<{ ownerCommit: string; sig: string }> {
    const acct = await this.ensureAccount();
    const r = await this.post<{ ownerCommit?: unknown; sig?: unknown }>(
      "/v1/accounts/deposit/authorize",
      { from, amount: s(amount) },
      { "X-Api-Key": acct.apiKey },
    );
    if (typeof r.ownerCommit !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(r.ownerCommit)) {
      throw new Error("authorize: gateway returned a malformed ownerCommit (expected 32-byte 0x hex)");
    }
    if (typeof r.sig !== "string" || !/^0x[0-9a-fA-F]{130}$/.test(r.sig)) {
      throw new Error("authorize: gateway returned a malformed signature (expected 65-byte 0x hex r‖s‖v)");
    }
    return { ownerCommit: r.ownerCommit, sig: r.sig };
  }
```

- [ ] **Step 7: Fix the AccountPanel test fake for typecheck** — in `src/components/AccountPanel.wallet.test.tsx`, next to the `SIG` constant (~line 34) add:

```ts
const COMMIT = "0x" + "ab".repeat(32); // gateway-issued blinded ownerCommit (fake)
const GWSIG = "0x" + "cd".repeat(65); // gateway 65-byte authorization sig (fake)
```

and replace `makeClient()` with:

```ts
/// A fake gateway client implementing only the wallet-deposit surface.
function makeClient() {
  const bindCalls: [string, string][] = [];
  const authorizeCalls: [string, bigint][] = [];
  const creditCalls: string[] = [];
  const client = {
    depositAccount: async () => ({ apiKey: "0x" + "aa".repeat(32), owner: OWNER }),
    bindDepositAddress: async (a: string, s: string) => {
      bindCalls.push([a, s]);
    },
    authorizeDeposit: async (from: string, amount: bigint) => {
      authorizeCalls.push([from, amount]);
      return { ownerCommit: COMMIT, sig: GWSIG };
    },
    creditOnchainDeposit: async (txHash: string) => {
      creditCalls.push(txHash);
      return 1_000_000_000n;
    },
  };
  return { client, bindCalls, authorizeCalls, creditCalls };
}
```

- [ ] **Step 8: Full verify**

Run: `pnpm typecheck && pnpm vitest run src/api/wallet.test.ts src/api/realClient.test.ts src/components/AccountPanel.wallet.test.tsx`
Expected: typecheck clean; all three suites PASS (AccountPanel behavior unchanged — the fake just gained an unused method).

- [ ] **Step 9: Commit**

```bash
git add src/api/wallet.ts src/api/realClient.ts src/api/wallet.test.ts src/api/realClient.test.ts src/components/AccountPanel.wallet.test.tsx
git commit -m "feat(frontend): SEC-019 authorizeDeposit client method + capability gate"
```

---

### Task 2: SEC-019 cutover — new `encodeDeposit` + wallet step-machine reorder

**Files:**
- Modify: `src/api/wallet.ts` (`encodeDeposit` ~line 318; address-const comment ~line 33)
- Modify: `src/api/wallet.test.ts` (selector pins ~line 50, calldata pins ~line 115)
- Modify: `src/components/AccountPanel.tsx` (step machine, ~lines 193–361)
- Modify: `src/components/AccountPanel.wallet.test.tsx` (pipeline tests)

**Interfaces:**
- Consumes: `authorizeDeposit(from, amount) → { ownerCommit, sig }` from Task 1 (fake: `makeClient().authorizeCalls`, `COMMIT`, `GWSIG`).
- Produces: `encodeDeposit(amount: bigint, ownerCommit: string, sig: string): string` — nothing later consumes it beyond AccountPanel; final shape is terminal.

- [ ] **Step 1: Write the failing encoder tests** — in `src/api/wallet.test.ts`:

(a) In `describe("function selectors")`, replace the `deposit(uint256)` pin line with:

```ts
    expect(selectorHex("deposit(uint256,bytes32,bytes)")).toBe("0x2b681307");
```

and in the recompute-independently loop replace `"deposit(uint256)"` with `"deposit(uint256,bytes32,bytes)"`.

(b) In `describe("calldata builders (pinned)")`, replace the `it("deposit(1000000000)", …)` test with:

```ts
  it("deposit(1000000000, commit, sig) — SEC-019, dynamic sig tail at offset 0x60", () => {
    expect(
      encodeDeposit(1_000_000_000n, "0x" + "ab".repeat(32), "0x" + "cd".repeat(65)),
    ).toBe(
      "0x2b681307" +
        "000000000000000000000000000000000000000000000000000000003b9aca00" +
        "ab".repeat(32) +
        "0000000000000000000000000000000000000000000000000000000000000060" +
        "0000000000000000000000000000000000000000000000000000000000000041" +
        "cd".repeat(65) +
        "00".repeat(31),
    );
  });

  it("deposit rejects a malformed ownerCommit or a non-65-byte sig", () => {
    expect(() => encodeDeposit(1n, "0x1234", "0x" + "cd".repeat(65))).toThrow(/32-byte/);
    expect(() => encodeDeposit(1n, "0x" + "ab".repeat(32), "0x" + "cd".repeat(64))).toThrow(/65-byte/);
    expect(() => encodeDeposit(1n, "0x" + "ab".repeat(32), "0xzz")).toThrow(/65-byte/);
  });
```

- [ ] **Step 2: Run to verify they fail**

Run: `pnpm vitest run src/api/wallet.test.ts -t "deposit"`
Expected: FAIL — TS error / arity mismatch (`encodeDeposit` takes 1 argument).

- [ ] **Step 3: Implement the new encoder** — in `src/api/wallet.ts` replace the `encodeDeposit` function with:

```ts
/**
 * `deposit(uint256,bytes32,bytes)` — SEC-019 CollateralVault deposit: amount,
 * the gateway-issued blinded owner commitment, and the gateway's 65-byte
 * authorization signature (r‖s‖v) over keccak256(chainid ‖ vault ‖ from ‖
 * ownerCommit ‖ amount). `sig` is the one dynamic argument: its head word is
 * the tail offset (3 args × 32 = 0x60), the tail is length (65) ‖ the bytes
 * zero-padded to 96.
 */
export function encodeDeposit(amount: bigint, ownerCommit: string, sig: string): string {
  if (!/^0x[0-9a-fA-F]{130}$/.test(sig)) {
    throw new Error("gateway sig must be 65-byte 0x hex (r‖s‖v)");
  }
  const tail = new Uint8Array(96); // 65 sig bytes zero-padded to 3 words
  tail.set(hexToBytes(sig.slice(2).toLowerCase()));
  return calldata("deposit(uint256,bytes32,bytes)", [
    encodeUint256(amount),
    encodeBytes32(ownerCommit), // throws on non-32-byte hex
    encodeUint256(3n * 32n), // offset of the bytes tail
    encodeUint256(65n), // bytes length
    tail,
  ]);
}
```

Also update the address-const comment block (~line 17) to:

```ts
// ── chain + contract facts (Base Sepolia public testnet) ─────────────────────
// Deployed 2026-07-09 (clean pre-alpha stack — PRE-SEC-019 contracts).
// ⚠ REDEPLOY GATE: the SEC-019/ZK-001 redeploy replaces BOTH addresses (new
// CollateralVault arity deposit(uint256,bytes32,bytes) + clean prod genesis).
// Until then the deposit flow below cannot land on-chain (old vault, new
// calldata). Must match TestnetNotice.tsx and deployments/base-sepolia.json —
// update BOTH on any redeploy.
```

- [ ] **Step 4: Run the encoder tests**

Run: `pnpm vitest run src/api/wallet.test.ts`
Expected: PASS (all — selectors, pins, rejections).

- [ ] **Step 5: Update the AccountPanel step machine** — in `src/components/AccountPanel.tsx`:

(a) Replace the step-id type + list + idle map (~lines 193–207) with:

```ts
type StepId = "chain" | "mint" | "approve" | "bind" | "authorize" | "deposit" | "credit";
type StepStatus = "idle" | "pending" | "done" | "error";

const WALLET_STEPS: { id: StepId; label: string }[] = [
  { id: "chain", label: "Switch wallet to Base Sepolia" },
  { id: "mint", label: "Mint test USDC to your wallet" },
  { id: "approve", label: "Approve the vault to pull USDC" },
  { id: "bind", label: "Bind wallet to trading account (one-time signature)" },
  { id: "authorize", label: "Authorize the deposit with the gateway (SEC-019)" },
  { id: "deposit", label: "Deposit USDC into the vault" },
  { id: "credit", label: "Credit the trading account" },
];

const idleSteps = (): Record<StepId, StepStatus> => ({
  chain: "idle", mint: "idle", approve: "idle", bind: "idle", authorize: "idle", deposit: "idle", credit: "idle",
});
```

(b) Replace the `WalletDepositCard` doc comment (~lines 221–237) with:

```ts
/**
 * The full on-chain deposit pipeline driven by an injected wallet (MetaMask-
 * class): [1] ensure Base Sepolia [2] mint test USDC (open mint — testnet
 * convenience) [3] approve the vault [4] bind the EOA to the /v1 account (one
 * `personal_sign`, remembered per account+address — MUST precede authorize:
 * the gateway only authorizes a bound payer) [5] SEC-019 gateway authorization
 * (`ownerCommit` + sig for this exact amount) [6] `vault.deposit(amount,
 * ownerCommit, sig)` [7] credit via `POST /v1/accounts/deposit/onchain`.
 *
 * Recoverability: per-step progress is kept across attempts, so a re-run after
 * an error SKIPS the already-done steps — with three guards: the chain step
 * ALWAYS re-runs (the user may have manually switched networks; a no-op when
 * already on Base Sepolia); the authorize step re-runs whenever the deposit tx
 * was NOT yet sent (the sig binds the amount, and the authorization lives only
 * in the run closure — a fresh run needs a fresh sig; re-authorizing is free
 * server-side); and a tx-sending step whose hash was recorded but not confirmed
 * RESUMES by waiting on that hash instead of sending a duplicate tx. Editing
 * the amount before the deposit landed resets the run — mint/approve simply
 * redo with the new amount (both are idempotent enough).
 */
```

(c) In `onAmountChange`, update only the comment (code unchanged):

```ts
    // A new amount restarts the pipeline — UNLESS the deposit tx already
    // landed (then the remaining credit step doesn't depend on the amount,
    // and resetting would orphan the on-chain deposit).
```

(d) Inside `run()`, replace everything from `const sendAndWait = …` through the end of the `for` loop's error handling with:

```ts
    // SEC-019: the gateway authorization for THIS run — consumed by the deposit
    // step's calldata. Never persisted: a run that must re-send the deposit
    // always re-authorizes first (see the loop's re-run guards).
    let auth: { ownerCommit: string; sig: string } | null = null;
    const sendAndWait = async (id: StepId, to: string, data: () => string) => {
      // Resume, don't resend: a prior attempt may have SENT this step's tx but
      // failed while waiting for it (RPC hiccup / confirmation timeout). The
      // hash is already recorded, so re-await the SAME tx instead of proposing
      // a second one (a duplicate vault.deposit would double-deposit). `data`
      // is lazy so a resumed step never rebuilds calldata it doesn't need.
      const prior = tx[id];
      if (prior) {
        await waitForTx(prior);
        return;
      }
      const h = await sendTx({ from: address, to, data: data() });
      tx[id] = h;
      setTxs({ ...tx });
      await waitForTx(h);
    };
    const executors: [StepId, () => Promise<void>][] = [
      ["chain", () => ensureBaseSepolia()],
      ["mint", () => sendAndWait("mint", MOCK_USDC, () => encodeMint(address, v))],
      ["approve", () => sendAndWait("approve", MOCK_USDC, () => encodeApprove(COLLATERAL_VAULT, v))],
      ["bind", async () => {
        const acct = await client.depositAccount();
        const key = boundStorageKey(bytesToHex(acct.owner), address);
        let bound = false;
        try { bound = localStorage.getItem(key) === "1"; } catch { /* private mode */ }
        if (!bound) {
          const digest = bindDepositDigest(acct.owner, address);
          const sig = await personalSign("0x" + bytesToHex(digest), address);
          await client.bindDepositAddress(address, sig);
          try { localStorage.setItem(key, "1"); } catch { /* private mode — re-bind next time (idempotent) */ }
        }
      }],
      ["authorize", async () => {
        auth = await client.authorizeDeposit(address, v);
      }],
      ["deposit", () => sendAndWait("deposit", COLLATERAL_VAULT, () => {
        if (!auth) throw new Error("internal: missing gateway authorization");
        return encodeDeposit(v, auth.ownerCommit, auth.sig);
      })],
      ["credit", async () => {
        const dep = tx.deposit;
        if (!dep) throw new Error("internal: missing deposit tx hash");
        const credited = await client.creditOnchainDeposit(dep);
        setOk(`Deposited ${formatUsd(credited)} — credited to your trading account.`);
      }],
    ];
    try {
      for (const [id, fn] of executors) {
        // Recovered run — skip what already succeeded, EXCEPT: the chain step
        // ALWAYS re-runs (the user may have switched networks between
        // attempts), and the authorize step re-runs whenever the deposit tx
        // was NOT yet sent (`auth` lives only in this closure and the sig
        // binds the amount — a fresh run must fetch a fresh authorization
        // before it can build the deposit calldata).
        const mustRerun = id === "chain" || (id === "authorize" && !tx.deposit);
        if (st[id] === "done" && !mustRerun) continue;
        mark(id, "pending");
        try {
          await fn();
        } catch (e) {
          mark(id, "error");
          const m = e instanceof Error ? e.message : String(e);
          setErr(
            tx.deposit && id === "credit"
              ? `${m} — your deposit tx ${shortHash(tx.deposit)} IS on-chain; press Deposit again to finish (completed steps are skipped).`
              : m,
          );
          return;
        }
        mark(id, "done");
      }
      // Full success → fresh slate for the next deposit.
      setSteps(idleSteps());
      setTxs({});
    } finally {
      setRunning(false);
    }
```

(The `st`/`tx`/`mark` local-copy lines above `sendAndWait` stay exactly as they are.)

- [ ] **Step 6: Update the pipeline tests** — in `src/components/AccountPanel.wallet.test.tsx`:

(a) Happy path — rename to `"happy path: connect → deposit runs the 7-step pipeline in order"` and replace the deposit-tx + credit assertions (keep the [1]/[2..3] mint+approve assertions unchanged) with:

```ts
    // [2..3] mint → approve, correct targets + calldata
    const txs = p.sent();
    expect(txs.length).toBe(3);
    expect(txField(txs[0], "to")).toBe(MOCK_USDC);
    expect(txField(txs[0], "data").startsWith("0x40c10f19")).toBe(true);
    expect(txField(txs[0], "data")).toContain(addr.slice(2)); // mint to self
    expect(txField(txs[1], "to")).toBe(MOCK_USDC);
    expect(txField(txs[1], "data").startsWith("0x095ea7b3")).toBe(true);
    expect(txField(txs[1], "data")).toContain(COLLATERAL_VAULT.slice(2).toLowerCase());

    // [4] bind BEFORE the deposit: personal_sign over the exact bind digest, POSTed
    const signs = p.signs();
    expect(signs.length).toBe(1);
    expect(signs[0].params).toEqual(["0x" + bytesToHex(bindDepositDigest(OWNER, addr)), addr]);
    expect(bindCalls).toEqual([[addr, SIG]]);
    expect(localStorage.getItem(boundStorageKey(bytesToHex(OWNER), addr))).toBe("1");

    // [5] SEC-019 authorization for the exact (from, amount)
    expect(authorizeCalls).toEqual([[addr, 1_000_000_000n]]);

    // [6] deposit tx carries the NEW calldata: selector + the gateway ownerCommit
    expect(txField(txs[2], "to")).toBe(COLLATERAL_VAULT);
    expect(txField(txs[2], "data").startsWith("0x2b681307")).toBe(true);
    expect(txField(txs[2], "data")).toContain(COMMIT.slice(2));
    for (const t of txs) expect(txField(t, "from")).toBe(addr);

    // [7] credit with the DEPOSIT tx hash (the 3rd fake hash the provider issued)
    expect(creditCalls).toEqual(["0x" + (3).toString(16).padStart(64, "0")]);
```

and destructure `authorizeCalls` at the top of the test: `const { client, bindCalls, authorizeCalls, creditCalls } = makeClient();`

(b) Add a new re-authorize test after the mid-pipeline-rejection test:

```ts
  it("re-authorizes on a re-run when the deposit tx was never sent (sig binds the amount)", async () => {
    let rejectDeposit = true;
    const p = makeProvider({
      eth_sendTransaction: (_call, calls) => {
        const n = calls.filter((c) => c.method === "eth_sendTransaction").length;
        if (n === 3 && rejectDeposit) {
          rejectDeposit = false; // reject only the FIRST deposit attempt
          throw { code: 4001 };
        }
        return "0x" + n.toString(16).padStart(64, "0");
      },
    });
    install(p.provider);
    const { client, authorizeCalls, creditCalls } = makeClient();
    render(<WalletDepositCard client={client} />);

    fireEvent.click(screen.getByRole("button", { name: /connect wallet/i }));
    await screen.findByText(/0xabcd…ef01/);

    // First attempt: mint + approve land, bind + authorize succeed, the DEPOSIT
    // send is rejected — no hash recorded.
    fireEvent.click(screen.getByRole("button", { name: /^deposit$/i }));
    expect(await screen.findByText(/Transaction rejected in the wallet/i)).toBeTruthy();
    expect(authorizeCalls.length).toBe(1);

    // Re-run: mint/approve/bind are skipped (done) but authorize runs AGAIN —
    // a fresh gateway sig for the re-sent deposit.
    fireEvent.click(screen.getByRole("button", { name: /^deposit$/i }));
    expect(await screen.findByText(/credited to your trading account/i)).toBeTruthy();
    expect(authorizeCalls.length).toBe(2);
    expect(p.sent().length).toBe(4); // mint, approve, rejected deposit, re-sent deposit
    expect(creditCalls).toEqual(["0x" + (4).toString(16).padStart(64, "0")]);
  });
```

(c) In the existing `"resumes a timed-out deposit wait on the SAME tx hash instead of re-sending"` test, destructure `authorizeCalls` too and add as the final assertion:

```ts
    // The recorded hash also means authorize is NOT re-run — the on-chain sig
    // was already consumed by the sent tx; only the wait + credit resume.
    expect(authorizeCalls.length).toBe(1);
```

(d) In the `"recovers after a mid-pipeline rejection"` test, no assertion changes are needed (the mint rejection happens before bind/authorize; the re-run completes the 7 steps).

(e) Add the spec's amount-change case after the re-authorize test:

```ts
  it("amount edit before the deposit landed resets the run — authorize uses the NEW amount", async () => {
    let rejectDeposit = true;
    const p = makeProvider({
      eth_sendTransaction: (_call, calls) => {
        const n = calls.filter((c) => c.method === "eth_sendTransaction").length;
        if (n === 3 && rejectDeposit) {
          rejectDeposit = false; // reject only the FIRST deposit attempt
          throw { code: 4001 };
        }
        return "0x" + n.toString(16).padStart(64, "0");
      },
    });
    install(p.provider);
    const { client, authorizeCalls, creditCalls } = makeClient();
    render(<WalletDepositCard client={client} />);

    fireEvent.click(screen.getByRole("button", { name: /connect wallet/i }));
    await screen.findByText(/0xabcd…ef01/);

    // First attempt at 1000 USDC: deposit send rejected, NO hash recorded.
    fireEvent.click(screen.getByRole("button", { name: /^deposit$/i }));
    await screen.findByText(/Transaction rejected in the wallet/i);
    expect(authorizeCalls).toEqual([[addr, 1_000_000_000n]]);

    // No deposit tx recorded → editing the amount resets the whole pipeline.
    fireEvent.change(screen.getByLabelText(/deposit amount/i), { target: { value: "500" } });
    fireEvent.click(screen.getByRole("button", { name: /^deposit$/i }));
    await screen.findByText(/credited to your trading account/i);

    // Fresh run: mint(4) → approve(5) → deposit(6), and the authorization is
    // for the NEW amount — the old sig (bound to 1000) was never reusable.
    expect(authorizeCalls.length).toBe(2);
    expect(authorizeCalls[1]).toEqual([addr, 500_000_000n]);
    expect(p.sent().length).toBe(6);
    expect(creditCalls).toEqual(["0x" + (6).toString(16).padStart(64, "0")]);
  });
```

- [ ] **Step 7: Run the panel tests to verify they fail, then pass**

Run: `pnpm vitest run src/components/AccountPanel.wallet.test.tsx`
Expected first: FAIL on the old 6-step assumptions if Step 5 was skipped; after Step 5: PASS. If any fail, fix the implementation (not the pins).

- [ ] **Step 8: Full verify + residue check**

Run: `pnpm typecheck && pnpm vitest run && grep -rFn 'deposit(uint256)' src/ ; echo "residue-exit:$?"`
Expected: typecheck clean, ALL suites pass, grep finds nothing (`residue-exit:1`).

- [ ] **Step 9: Commit**

```bash
git add src/api/wallet.ts src/api/wallet.test.ts src/components/AccountPanel.tsx src/components/AccountPanel.wallet.test.tsx
git commit -m "feat(frontend): SEC-019 deposit cutover — deposit(uint256,bytes32,bytes) + bind-before-authorize step machine"
```

---

### Task 3: FIN-001 settlement-health surface

**Files:**
- Modify: `src/api/client.ts` (new `SettlementHealth` interface + `ClientState.settlement`, ~line 36)
- Modify: `src/api/realClient.ts` (WireState ~line 50, `parseState` ~line 101)
- Modify: `src/api/mockClient.ts` (state builder, `attestation: null` ~line 263)
- Modify: `src/components/HealthPanel.tsx` (new row + exported pure helper)
- Modify: `src/api/realClient.test.ts` (parse tests)
- Modify: `src/components/HealthPanel.test.tsx` (helper + absence tests)

**Interfaces:**
- Consumes: the WS/state frame shape from `realClient.test.ts` (`pushStateFrame`, `wireState`, `lastWs`).
- Produces: `SettlementHealth { health: "HEALTHY"|"DEGRADED"|"HELD"; consecutiveFailures: number; lastError: string | null; heldSinceMs: number | null }` exported from `src/api/client.ts`; `ClientState.settlement: SettlementHealth | null`; `settlementRowModel(s: SettlementHealth): { status: "ok"|"warn"|"down"; detail: string }` exported from `HealthPanel.tsx`.

- [ ] **Step 1: Write the failing parse tests** — in `src/api/realClient.test.ts` add a top-level describe:

```ts
describe("settlement health (FIN-001)", () => {
  it("parses the camelCase settlement fields from a state frame", async () => {
    const client = await bootstrapClient();
    lastWs!.onmessage!({
      data: JSON.stringify({
        type: "state",
        state: {
          ...wireState,
          settlementHealth: "HELD",
          settlementConsecutiveFailures: 5,
          settlementLastError: "prover 503",
          settlementHeldSinceMs: 1234,
        },
      }),
    });
    expect(client.getState().settlement).toEqual({
      health: "HELD", consecutiveFailures: 5, lastError: "prover 503", heldSinceMs: 1234,
    });
  });

  it("defaults the omitted optionals (serde skip_serializing_if)", async () => {
    const client = await bootstrapClient();
    lastWs!.onmessage!({
      data: JSON.stringify({
        type: "state",
        state: { ...wireState, settlementHealth: "DEGRADED", settlementConsecutiveFailures: 2 },
      }),
    });
    expect(client.getState().settlement).toEqual({
      health: "DEGRADED", consecutiveFailures: 2, lastError: null, heldSinceMs: null,
    });
  });

  it("null for an old gateway (fields absent) and for a malformed health", async () => {
    const client = await bootstrapClient();
    pushStateFrame(); // the base fixture carries no settlement fields
    expect(client.getState().settlement).toBeNull();
    lastWs!.onmessage!({
      data: JSON.stringify({ type: "state", state: { ...wireState, settlementHealth: "BANANA" } }),
    });
    expect(client.getState().settlement).toBeNull();
  });
});
```

- [ ] **Step 2: Run to verify they fail**

Run: `pnpm vitest run src/api/realClient.test.ts -t "settlement health"`
Expected: FAIL — `settlement` is `undefined`, not the parsed object / `null`.

- [ ] **Step 3: Implement the type + parse**

(a) `src/api/client.ts` — above `ClientState`, add:

```ts
/// FIN-001: the gateway settle-loop breaker state, from the status snapshot.
export interface SettlementHealth {
  health: "HEALTHY" | "DEGRADED" | "HELD";
  /// Consecutive settle failures behind `health` (0 when healthy).
  consecutiveFailures: number;
  /// Most recent settle error while unhealthy, or null.
  lastError: string | null;
  /// Wall-clock ms the loop entered HELD, or null unless currently HELD.
  heldSinceMs: number | null;
}
```

and to `ClientState` (after `attestation`):

```ts
  /// FIN-001 settle-loop health, or null when the gateway predates it (or mock).
  settlement: SettlementHealth | null;
```

(b) `src/api/realClient.ts` — add `SettlementHealth` to the existing type import from `"./client"`; extend `WireState` (after `attestation`):

```ts
  /// FIN-001 (absent on an old gateway) — validated field-by-field at parse time.
  settlementHealth?: unknown;
  settlementConsecutiveFailures?: unknown;
  settlementLastError?: unknown;
  settlementHeldSinceMs?: unknown;
```

add next to the other `p*` parsers:

```ts
/// FIN-001, defensively: an old gateway (fields absent) or a malformed frame
/// parses to null — the UI simply hides the row, never crashes.
function pSettlement(w: WireState): SettlementHealth | null {
  const h = w.settlementHealth;
  if (h !== "HEALTHY" && h !== "DEGRADED" && h !== "HELD") return null;
  return {
    health: h,
    consecutiveFailures:
      typeof w.settlementConsecutiveFailures === "number" ? w.settlementConsecutiveFailures : 0,
    lastError: typeof w.settlementLastError === "string" ? w.settlementLastError : null,
    heldSinceMs: typeof w.settlementHeldSinceMs === "number" ? w.settlementHeldSinceMs : null,
  };
}
```

and in `parseState`'s returned object (after `attestation: w.attestation,`):

```ts
    settlement: pSettlement(w),
```

(c) `src/api/mockClient.ts` — in the state builder, directly after `attestation: null,` add:

```ts
      settlement: null,
```

- [ ] **Step 4: Run the parse tests**

Run: `pnpm vitest run src/api/realClient.test.ts && pnpm typecheck`
Expected: PASS + clean typecheck (mock updated in the same step, so `ClientState` stays satisfied everywhere).

- [ ] **Step 5: Write the failing HealthPanel tests** — in `src/components/HealthPanel.test.tsx` replace the whole file with:

```tsx
// @vitest-environment happy-dom
import { describe, it, expect, afterEach } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";
import { StoreProvider } from "../store";
import { HealthPanel, settlementRowModel } from "./HealthPanel";

afterEach(cleanup);

describe("HealthPanel", () => {
  it("renders service statuses incl. the live conservation check", () => {
    render(
      <StoreProvider>
        <HealthPanel />
      </StoreProvider>,
    );
    expect(screen.getByText(/web client/i)).toBeTruthy();
    expect(screen.getByText(/oracle feed/i)).toBeTruthy();
    expect(screen.getByText(/system mode/i)).toBeTruthy();
    expect(screen.getByText(/collateral conservation/i)).toBeTruthy();
    // a healthy default account satisfies the real invariants → the ✓ detail is shown
    expect(screen.getByText(/free ≥ 0 · margin ≥ 0 · solvent ✓/i)).toBeTruthy();
  });

  it("hides the FIN-001 settle-loop row when the client reports none (mock)", () => {
    render(
      <StoreProvider>
        <HealthPanel />
      </StoreProvider>,
    );
    expect(screen.queryByText(/L1 settle loop/i)).toBeNull();
  });
});

describe("settlementRowModel (FIN-001)", () => {
  it("HEALTHY → ok", () => {
    expect(
      settlementRowModel({ health: "HEALTHY", consecutiveFailures: 0, lastError: null, heldSinceMs: null }),
    ).toEqual({ status: "ok", detail: "settling — breaker closed" });
  });

  it("DEGRADED → warn with the failure count", () => {
    const m = settlementRowModel({
      health: "DEGRADED", consecutiveFailures: 2, lastError: "prover 503", heldSinceMs: null,
    });
    expect(m.status).toBe("warn");
    expect(m.detail).toContain("2 consecutive");
  });

  it("HELD → down with held-duration + error snippet + resume hint", () => {
    const m = settlementRowModel({
      health: "HELD", consecutiveFailures: 5, lastError: "prover 503", heldSinceMs: Date.now() - 120_000,
    });
    expect(m.status).toBe("down");
    expect(m.detail).toMatch(/HELD for 2m/);
    expect(m.detail).toContain("prover 503");
    expect(m.detail).toMatch(/operator resume/i);
  });

  it("HELD with no heldSince/lastError still renders sanely", () => {
    const m = settlementRowModel({
      health: "HELD", consecutiveFailures: 3, lastError: null, heldSinceMs: null,
    });
    expect(m.status).toBe("down");
    expect(m.detail).toMatch(/^HELD — operator resume required$/);
  });
});
```

- [ ] **Step 6: Run to verify they fail**

Run: `pnpm vitest run src/components/HealthPanel.test.tsx`
Expected: FAIL — `settlementRowModel` is not exported.

- [ ] **Step 7: Implement the row** — in `src/components/HealthPanel.tsx`:

(a) Add to the imports: `import type { SettlementHealth } from "../api/client";`

(b) Below the `StatusRow` component, add:

```tsx
/// Exported for tests: the status/detail pair the FIN-001 settle-loop row shows.
export function settlementRowModel(s: SettlementHealth): { status: Status; detail: string } {
  if (s.health === "HEALTHY") return { status: "ok", detail: "settling — breaker closed" };
  if (s.health === "DEGRADED") {
    return { status: "warn", detail: `${s.consecutiveFailures} consecutive settle failures — backing off` };
  }
  const mins =
    s.heldSinceMs === null ? null : Math.max(0, Math.round((Date.now() - s.heldSinceMs) / 60_000));
  const err = s.lastError ? ` — ${s.lastError.slice(0, 80)}` : "";
  return {
    status: "down",
    detail: `HELD${mins !== null ? ` for ${mins}m` : ""}${err} — operator resume required`,
  };
}
```

(c) In `HealthPanel`, before the `return`, add:

```tsx
  // FIN-001: the settle-loop breaker (null = old gateway / mock → row hidden)
  const settleRow = state.settlement ? settlementRowModel(state.settlement) : null;
```

and in the "Services" card, directly after the `Matching / settlement (§2/§3)` StatusRow, add:

```tsx
          {settleRow && (
            <StatusRow label="L1 settle loop (FIN-001)" status={settleRow.status} detail={settleRow.detail} />
          )}
```

- [ ] **Step 8: Full verify**

Run: `pnpm typecheck && pnpm vitest run`
Expected: clean typecheck, ALL suites pass.

- [ ] **Step 9: Commit**

```bash
git add src/api/client.ts src/api/realClient.ts src/api/mockClient.ts src/components/HealthPanel.tsx src/api/realClient.test.ts src/components/HealthPanel.test.tsx
git commit -m "feat(frontend): FIN-001 settle-loop breaker row in HealthPanel (settlementHealth wire parse)"
```

---

### Final gate (after all tasks)

- [ ] Run the spec's success criteria in one shot:

```bash
cd <repo>/frontend
pnpm typecheck && pnpm vitest run && { grep -rFn 'deposit(uint256)' src/ && echo "RESIDUE FOUND" || echo "clean cutover ✓"; }
```

Expected: typecheck clean, all tests green, `clean cutover ✓`.

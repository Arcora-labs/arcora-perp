// @vitest-environment happy-dom
import { installTestLocks } from "../testSupport/locks";
//
// S1 account-recovery hardening — the client side of the hardened gateway
// contract: atomic swap only on fully-validated confirmed success, the
// re-GET/re-sign/re-POST retry contract (never replaying a stale signed
// authorization as success), the credential-epoch guard (late results from a
// superseded swap, stale own-state refreshes, and old sockets' /v1/ws frames
// must not overwrite the winner), and cross-tab propagation/stale-overwrite
// protection over the `storage` event. Patterns mirror realClient.test.ts.
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { credentialKey, type StoredCredential } from "./credentialStore";
import { RealDarkPerpClient } from "./realClient";

// ── fixtures ─────────────────────────────────────────────────────────────────
const OWNER_HEX = "0x" + "22".repeat(32);
const OTHER_OWNER_HEX = "0x" + "33".repeat(32);
const AUTHORIZER = "0x" + "44".repeat(20);
const VAULT = "0x" + "3b".repeat(20);
const CHAIN_ID = 4242;
const OLD_KEY = "0x" + "11".repeat(32);
const NEW_KEY = "0x" + "77".repeat(32);
const KEY_B = "0x" + "55".repeat(32);
const SCOPE = { base: "http://gw.test", chainId: CHAIN_ID, vault: VAULT };
const LS_KEY = credentialKey(SCOPE);
const record = (apiKey = OLD_KEY, recoveryNonce = 0, owner = OWNER_HEX): StoredCredential =>
  ({ ...SCOPE, schema: 2, apiKey, owner, recoveryNonce });
let keyGenerations = new Map<string, number>();

const wireMarket = {
  id: 0, symbol: "BTC/USDC", maxLeverage: 20, maintenanceMarginRatio: 0.05,
  initialMarginRatio: 0.1, referencePrice: "6450000000000", live: false,
  takerFeeBps: 8, makerRebateBps: 2,
};
const wireState = {
  markets: [wireMarket], selectedMarketId: 0, market: wireMarket, mode: "Normal",
  oracle: { marketId: 0, price: "6450000000000", confidence: "1", publishTimeMs: 0 },
  book: { marketId: 0, bids: [], asks: [] },
  marks: { "0": "6450000000000" }, account: { settledBalance: "0", positions: [] },
  orders: [], batches: [], insuranceFund: "0", treasury: "0", userAdlClawed: "0",
  lp: { tvl: "0", navPerShare: "1.000000", totalShares: "0", myShares: "0", myValue: "0" },
  mmHedge: [], l1: null, attestation: null,
};
// A distinctive own order the stale-refresh test serves to OLD-key reads only.
const staleOrder = {
  orderId: "o42", marketId: 1, side: "Sell", size: "250000000", limitPrice: "352000000000",
  tif: "Fok", reduceOnly: true, orderHash: "0x" + "a1".repeat(32), finality: "ACCEPTED",
  filledSize: "0", avgFillPrice: "0", createdMs: 5000,
  receipt: { orderHash: "0x" + "a1".repeat(32), seqNo: 5, recvTimeMs: 5001, batchIdHint: 3, windowId: 9 },
};

// ── mock-gateway state ───────────────────────────────────────────────────────
interface Captured { path: string; method: string; headers: Record<string, string>; body: unknown }
let calls: Captured[] = [];
/** GET /v1/accounts/recovery/:owner serves this, then increments — models the server nonce advancing after a dropped 503. */
let nextRecoveryNonce: number;
/** Behavior of POST /v1/accounts/recovery; null ⇒ default confirmed success. */
let recoveryPostHandler: ((body: { nonce?: unknown }) => Promise<{ status: number; body: unknown }>) | null = null;
/** One-shot gate parked in front of the NEXT GET /v1/orders (payload captured at request time). */
let v1OrdersGate: Promise<void> | null = null;
/** When true, GET /v1/orders answered to the OLD key carries the stale order. */
let serveStaleOrderToOldKey = false;
let rejectPersonalSign = false;
/** When true, every POST /v1/accounts/recovery throws at the transport layer. */
let recoveryPostNetworkError = false;
let intercept: ((path: string, method: string, headers: Record<string, string>) => Promise<ReturnType<typeof json> | null>) | null = null;

const json = (v: unknown, status = 200) => ({
  ok: status < 400,
  status,
  json: async () => v,
  text: async () => JSON.stringify(v),
});

function recoveryMeta(nonce: number) {
  return { owner: OWNER_HEX, authorizer: AUTHORIZER, recoveryNonce: nonce, chainId: CHAIN_ID, vault: VAULT };
}

function installFetch() {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: unknown, init?: { method?: string; headers?: Record<string, string>; body?: string }) => {
      const path = new URL(String(input)).pathname;
      const method = init?.method ?? "GET";
      calls.push({ path, method, headers: init?.headers ?? {}, body: init?.body ? JSON.parse(init.body) : null });
      const override = await intercept?.(path, method, init?.headers ?? {});
      if (override) return override;
      if (path === "/api/state") return json(wireState);
      if (path === "/v1/system/status") return json(SCOPE);
      // Bootstrap's prepareSealing tolerates an unreachable epoch endpoint.
      if (path === "/v1/enclave/epoch") throw new Error("epoch unreachable in recovery tests");
      if (path === "/v1/accounts/me") {
        return json({ owner: OWNER_HEX, settledBalance: "1000", callerSigned: false, ...SCOPE, recoveryNonce: keyGenerations.get(init?.headers?.["X-Api-Key"] ?? OLD_KEY) ?? 0 });
      }
      if (path === "/v1/accounts/deposit" && method === "POST") return json({});
      if (path === "/v1/positions" && method === "GET") return json({ positions: [] });
      if (path === "/v1/orders" && method === "GET") {
        if (v1OrdersGate) {
          const gate = v1OrdersGate;
          v1OrdersGate = null; // one-shot
          await gate;
        }
        // Deliberately accepts ANY key: stale-refresh results are well-formed
        // data, so only the epoch guard can drop them.
        if (serveStaleOrderToOldKey && init?.headers?.["X-Api-Key"] === OLD_KEY) {
          return json({ orders: [staleOrder] });
        }
        return json({ orders: [] });
      }
      if (path === `/v1/accounts/recovery/${OWNER_HEX}` && method === "GET") {
        return json(recoveryMeta(nextRecoveryNonce++));
      }
      if (path === "/v1/accounts/recovery" && method === "POST") {
        if (recoveryPostNetworkError) throw new Error("network down");
        const body = calls[calls.length - 1].body as { nonce?: unknown };
        if (recoveryPostHandler) {
          const r = await recoveryPostHandler(body);
          const v = r.body as { apiKey?: string; recoveryNonce?: number } | null;
          if (r.status === 200 && v?.apiKey && typeof v.recoveryNonce === "number") keyGenerations.set(v.apiKey, v.recoveryNonce);
          return json(r.body, r.status);
        }
        const nonce = (body?.nonce as number) ?? 0;
        keyGenerations.set(NEW_KEY, nonce + 1);
        return json({ apiKey: NEW_KEY, owner: OWNER_HEX, recoveryNonce: nonce + 1, durability: "confirmed" });
      }
      throw new Error(`unexpected fetch ${method} ${path}`);
    }),
  );
}

let lastWsV1: FakeWebSocket | null = null;

class FakeWebSocket {
  onopen: (() => void) | null = null;
  onmessage: ((ev: { data: string }) => void) | null = null;
  onclose: (() => void) | null = null;
  onerror: (() => void) | null = null;
  readyState = 0;
  sent: string[] = [];
  readonly url: string;
  constructor(url: string) {
    this.url = url;
    if (url.includes("/v1/ws")) lastWsV1 = this;
  }
  send(data: string) { this.sent.push(data); }
  close() {}
  open() { this.readyState = 1; this.onopen?.(); }
}

let personalSigns: { digestHex: string; address: string }[];
function installWallet() {
  (window as unknown as { ethereum?: unknown }).ethereum = {
    request: async ({ method, params }: { method: string; params?: unknown[] }) => {
      if (method === "personal_sign") {
        if (rejectPersonalSign) throw new Error("user rejected");
        personalSigns.push({ digestHex: params?.[0] as string, address: params?.[1] as string });
        // Distinct 65-byte signature per call so tests can prove re-signing happened.
        return "0x" + personalSigns.length.toString(16).padStart(2, "0") + "ab".repeat(64);
      }
      throw new Error(`unexpected wallet method ${method}`);
    },
  };
}

const macrotask = () => new Promise<void>((r) => setTimeout(r, 0));
const storedRecord = () => JSON.parse(localStorage.getItem(LS_KEY) ?? "null") as Record<string, unknown> | null;
const getCalls = (path: string, method?: string) =>
  calls.filter((c) => c.path === path && (method === undefined || c.method === method));
const lastApiKeyFor = (path: string) => {
  const cs = getCalls(path);
  return cs.length ? cs[cs.length - 1].headers["X-Api-Key"] : undefined;
};

/** Bootstrap a client whose stored (and live) credential is OLD_KEY for OWNER_HEX. */
async function makeClient() {
  localStorage.setItem(LS_KEY, JSON.stringify(record()));
  return RealDarkPerpClient.bootstrap("http://gw.test");
}

beforeEach(() => {
  // Isolate proxy-bound Storage spies between Vitest 4 tests.
  vi.stubGlobal("localStorage", new Storage());
  installTestLocks();
  keyGenerations = new Map([[OLD_KEY, 0]]);
  calls = [];
  intercept = null;
  nextRecoveryNonce = 1;
  recoveryPostHandler = null;
  v1OrdersGate = null;
  serveStaleOrderToOldKey = false;
  rejectPersonalSign = false;
  recoveryPostNetworkError = false;
  personalSigns = [];
  lastWsV1 = null;
  localStorage.clear();
  installFetch();
  installWallet();
  vi.stubGlobal("WebSocket", FakeWebSocket);
});

afterEach(() => {
  vi.useRealTimers();
  delete (window as unknown as { ethereum?: unknown }).ethereum;
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("S1 recovery: confirmed success", () => {
  it("swaps the stored credential + sealing, bumps the epoch, and closes the old socket", async () => {
    const client = await makeClient();
    const wsV1 = lastWsV1!;
    let closed = false;
    wsV1.close = () => { closed = true; };

    const r = await client.recoverAccount(OWNER_HEX);

    expect(r).toEqual({ owner: OWNER_HEX, recoveryNonce: 2, credentialStorage: "persistent" });
    const stored = storedRecord()!;
    expect(stored.apiKey).toBe(NEW_KEY);
    expect(stored.owner).toBe(OWNER_HEX);
    expect(stored.recoveryNonce).toBe(2); // server generation, not a local write counter
    expect(closed).toBe(true); // old /v1/ws socket closed for a re-auth
    // Sealing swapped: the next authenticated read goes out under the NEW key.
    await client.getPositions();
    expect(lastApiKeyFor("/v1/positions")).toBe(NEW_KEY);
    client.dispose();
  });
});

describe("S1 recovery: failure matrix keeps the OLD credential + sealing intact", () => {
  const nonRetryable = [
    { name: "400 bad signature/params", status: 400 },
    { name: "401 unknown authorization", status: 401 },
    { name: "409 superseded by a newer rotation", status: 409 },
  ];
  for (const { name, status } of nonRetryable) {
    it(name, async () => {
      const client = await makeClient();
      recoveryPostHandler = async () => ({ status, body: { error: "nope", durability: status === 409 ? "confirmed" : undefined } });
      await expect(client.recoverAccount(OWNER_HEX)).rejects.toThrow();
      expect(getCalls("/v1/accounts/recovery", "POST").length).toBe(1); // NO retry
      expect(storedRecord()).toEqual(record()); // untouched
      await client.getPositions();
      expect(lastApiKeyFor("/v1/positions")).toBe(OLD_KEY); // sealing intact
      client.dispose();
    });
  }

  it("503 (unconfirmed durability) retries bounded, then gives up — old credential intact", async () => {
    const client = await makeClient();
    recoveryPostHandler = async () => ({ status: 503, body: { error: "snapshot write failed", durability: "unknown" } });
    await expect(client.recoverAccount(OWNER_HEX)).rejects.toThrow(/3 attempts/);
    expect(getCalls("/v1/accounts/recovery", "POST").length).toBe(3);
    expect(getCalls(`/v1/accounts/recovery/${OWNER_HEX}`, "GET").length).toBe(3); // fresh metadata each round
    expect(storedRecord()).toEqual(record());
    await client.getPositions();
    expect(lastApiKeyFor("/v1/positions")).toBe(OLD_KEY);
    client.dispose();
  });

  it("network error on the POST retries bounded, then gives up", async () => {
    const client = await makeClient();
    recoveryPostNetworkError = true;
    await expect(client.recoverAccount(OWNER_HEX)).rejects.toThrow(/3 attempts/);
    expect(getCalls("/v1/accounts/recovery", "POST").length).toBe(3);
    expect(storedRecord()).toEqual(record());
    await client.getPositions();
    expect(lastApiKeyFor("/v1/positions")).toBe(OLD_KEY);
    client.dispose();
  });

  const malformed = [
    { name: "missing apiKey", body: { owner: OWNER_HEX, recoveryNonce: 2, durability: "confirmed" } },
    { name: "wrong owner", body: { apiKey: NEW_KEY, owner: OTHER_OWNER_HEX, recoveryNonce: 2, durability: "confirmed" } },
    { name: "durability missing", body: { apiKey: NEW_KEY, owner: OWNER_HEX, recoveryNonce: 2 } },
    { name: "recoveryNonce not nonce+1", body: { apiKey: NEW_KEY, owner: OWNER_HEX, recoveryNonce: 9, durability: "confirmed" } },
    { name: "unreadable body (missing response)", body: null as unknown },
  ];
  for (const { name, body } of malformed) {
    it(`malformed response: ${name}`, async () => {
      const client = await makeClient();
      recoveryPostHandler = async () => ({
        status: 200,
        body: body ?? (() => { throw new Error("unreadable"); })(),
      });
      await expect(client.recoverAccount(OWNER_HEX)).rejects.toThrow();
      expect(storedRecord()).toEqual(record());
      await client.getPositions();
      expect(lastApiKeyFor("/v1/positions")).toBe(OLD_KEY);
      client.dispose();
    });
  }

  it("wallet rejection does not retry and never reaches the POST", async () => {
    const client = await makeClient();
    rejectPersonalSign = true;
    await expect(client.recoverAccount(OWNER_HEX)).rejects.toThrow(/Wallet refused/);
    expect(getCalls("/v1/accounts/recovery", "POST").length).toBe(0);
    expect(getCalls(`/v1/accounts/recovery/${OWNER_HEX}`, "GET").length).toBe(1);
    expect(storedRecord()).toEqual(record());
    client.dispose();
  });
});

describe("S1 recovery: dropped response re-GETs fresh metadata and re-signs the new nonce", () => {
  it("503 once, then confirmed success on the retry with the FRESH nonce and a NEW signature", async () => {
    const client = await makeClient();
    let posts = 0;
    recoveryPostHandler = async (body) => {
      posts++;
      if (posts === 1) {
        expect(body.nonce).toBe(1);
        return { status: 503, body: { error: "snapshot write failed", durability: "unknown" } };
      }
      expect(body.nonce).toBe(2); // the advanced server nonce — never the replayed 1
      return { status: 200, body: { apiKey: NEW_KEY, owner: OWNER_HEX, recoveryNonce: 3, durability: "confirmed" } };
    };
    const r = await client.recoverAccount(OWNER_HEX);
    expect(r.recoveryNonce).toBe(3);
    expect(getCalls(`/v1/accounts/recovery/${OWNER_HEX}`, "GET").length).toBe(2);
    expect(posts).toBe(2);
    expect(personalSigns.length).toBe(2);
    expect(personalSigns[0].digestHex).not.toBe(personalSigns[1].digestHex); // re-signed, not replayed
    expect(storedRecord()!.apiKey).toBe(NEW_KEY);
    client.dispose();
  });
});

describe("S1 recovery: epoch guard", () => {
  it("concurrent same-account recoveries share one wallet signature and one POST", async () => {
    const client = await makeClient();
    let release!: () => void;
    const gate = new Promise<void>(resolve => { release = resolve; });
    recoveryPostHandler = async body => { await gate; return { status: 200, body: { apiKey: NEW_KEY, owner: OWNER_HEX, recoveryNonce: (body.nonce as number) + 1, durability: "confirmed" } }; };
    const a = client.recoverAccount(OWNER_HEX);
    const b = client.recoverAccount(OWNER_HEX);
    expect(a).toBe(b);
    await macrotask();
    release();
    await Promise.all([a, b]);
    expect(personalSigns).toHaveLength(1);
    expect(getCalls("/v1/accounts/recovery", "POST")).toHaveLength(1);
    client.dispose();
  });

  it("a refresh started before rotation cannot overwrite post-rotation own state", async () => {
    const client = await makeClient();
    serveStaleOrderToOldKey = true;
    let release!: () => void;
    v1OrdersGate = new Promise<void>((r) => { release = r; });
    // Pre-rotation refresh (old key) parks on the gate inside its GET /v1/orders.
    const dep = client.deposit(0n); // POST /v1/accounts/deposit, then refreshOwnState
    await macrotask();
    await macrotask();
    // Rotate while the old-key refresh is parked. Recovery's own end-of-recovery
    // refresh JOINS the parked one, so release the gate before awaiting it.
    const rec = client.recoverAccount(OWNER_HEX);
    await macrotask();
    release(); // the parked pre-rotation read resolves late with the STALE list
    await rec;
    await dep;
    await client.ownStateSettled();
    expect(client.getState().orders).toEqual([]); // stale [o42] dropped, not overlaid
    client.dispose();
  });
});

describe("S1 recovery: /v1/ws old-socket frames cannot clear or replace the new credential", () => {
  it("late authOk and error frames from the pre-rotation socket are ignored", async () => {
    const client = await makeClient();
    const oldSocket = lastWsV1!;
    await client.recoverAccount(OWNER_HEX); // rotates, closes oldSocket (epoch bumps)
    // Late frames from the OLD socket/auth attempt arrive after the rotation.
    oldSocket.onmessage!({ data: JSON.stringify({ type: "error", message: "dead key" }) });
    oldSocket.onmessage!({ data: JSON.stringify({ type: "authOk", owner: OWNER_HEX }) });
    await macrotask();
    await client.getPositions();
    expect(lastApiKeyFor("/v1/positions")).toBe(NEW_KEY); // new sealing untouched
    client.dispose();
  });
});

describe("S1 recovery: multi-tab propagation", () => {
  const storageEvent = (newValue: string) => {
    const rec = JSON.parse(newValue) as StoredCredential;
    localStorage.setItem(LS_KEY, newValue);
    keyGenerations.set(rec.apiKey, rec.recoveryNonce);
    window.dispatchEvent(new StorageEvent("storage", { key: LS_KEY, newValue, storageArea: localStorage }));
  };

  it("adopts a newer-generation record for the SAME owner (sealing + epoch + re-auth)", async () => {
    const client = await makeClient();
    const wsV1 = lastWsV1!;
    let closed = false;
    wsV1.close = () => { closed = true; };
    storageEvent(JSON.stringify(record(KEY_B, 7)));
    await macrotask();
    expect(closed).toBe(true);
    await client.getPositions();
    expect(lastApiKeyFor("/v1/positions")).toBe(KEY_B);
    client.dispose();
  });

  it("ignores a record for a DIFFERENT owner", async () => {
    const client = await makeClient();
    storageEvent(JSON.stringify(record(KEY_B, 7, OTHER_OWNER_HEX)));
    await macrotask();
    await client.getPositions();
    expect(lastApiKeyFor("/v1/positions")).toBe(OLD_KEY);
    client.dispose();
  });

  it("ignores an older-or-equal generation echo", async () => {
    const client = await makeClient();
    storageEvent(JSON.stringify(record(KEY_B, 0)));
    await macrotask();
    await client.getPositions();
    expect(lastApiKeyFor("/v1/positions")).toBe(OLD_KEY);
    client.dispose();
  });

  it("a stale tab refuses to overwrite a newer stored generation", async () => {
    const client = await makeClient(); // adopts storedGen 0
    // Another tab rotated to gen 9 (same-tab setItem fires no storage event,
    // so this tab stays stale at storedGen 0).
    localStorage.setItem(LS_KEY, JSON.stringify(record(KEY_B, 9)));
    recoveryPostHandler = async (body) => ({
      status: 200,
      body: { apiKey: NEW_KEY, owner: OWNER_HEX, recoveryNonce: (body.nonce as number) + 1, durability: "confirmed" },
    });
    await expect(client.recoverAccount(OWNER_HEX)).rejects.toThrow(/newer stored credential/);
    const stored = storedRecord()!;
    expect(stored.apiKey).toBe(KEY_B); // the newer generation survived
    expect(stored.recoveryNonce).toBe(9);
    await client.getPositions();
    expect(lastApiKeyFor("/v1/positions")).toBe(OLD_KEY); // old in-memory credential kept
    client.dispose();
  });
});

// Direct review: initialization, deployment scope, persistence and transport races.
describe("direct review regressions", () => {
  const initAccount = (client: RealDarkPerpClient) =>
    (client as unknown as { initAccount(): Promise<{ apiKey: string }> }).initAccount();
  const deferred = () => {
    let release!: () => void;
    const promise = new Promise<void>(r => { release = r; });
    return { promise, release };
  };

  it.each(["", "not-a-key", "0x01"])("rejects a confirmed malformed string key %j without replacing saved credentials", async apiKey => {
    const client = await makeClient();
    recoveryPostHandler = async body => ({ status: 200, body: { apiKey, owner: OWNER_HEX, recoveryNonce: Number(body.nonce) + 1, durability: "confirmed" } });
    await expect(client.recoverAccount(OWNER_HEX)).rejects.toThrow(/malformed/);
    expect(storedRecord()).toEqual(record());
    client.dispose();
  });

  it("late stored-account validation cannot overwrite a confirmed recovery", async () => {
    const client = await makeClient();
    const gate = deferred(); let parked = false;
    intercept = async path => {
      if (path !== "/v1/accounts/me" || parked) return null;
      parked = true;
      await gate.promise;
      return json({ ...SCOPE, owner: OWNER_HEX, recoveryNonce: 0, settledBalance: "1000" });
    };
    const initialization = initAccount(client);
    await macrotask();
    expect(parked).toBe(true);
    await client.recoverAccount(OWNER_HEX);
    gate.release();
    expect((await initialization).apiKey).toBe(NEW_KEY);
    await client.getPositions();
    expect(lastApiKeyFor("/v1/positions")).toBe(NEW_KEY);
    expect(storedRecord()!.apiKey).toBe(NEW_KEY);
    client.dispose();
  });

  it("late registration cannot overwrite a recovery that starts while it is pending", async () => {
    const client = await makeClient();
    localStorage.removeItem(LS_KEY);
    const gate = deferred(); let parked = false;
    intercept = async (path, method) => {
      if (path !== "/v1/accounts" || method !== "POST") return null;
      parked = true; await gate.promise;
      return json({ ...SCOPE, apiKey: KEY_B, owner: OTHER_OWNER_HEX, recoveryNonce: 0 });
    };
    const initialization = initAccount(client);
    await macrotask(); expect(parked).toBe(true);
    await client.recoverAccount(OWNER_HEX);
    gate.release();
    expect((await initialization).apiKey).toBe(NEW_KEY);
    expect(storedRecord()!.owner).toBe(OWNER_HEX);
    expect(storedRecord()!.apiKey).toBe(NEW_KEY);
    client.dispose();
  });

  it.each([401, 503])("validation HTTP %i must not create a replacement account", async status => {
    const client = await makeClient();
    intercept = async path => path === "/v1/accounts/me" ? json({ error: "unavailable" }, status) : null;
    await expect(initAccount(client)).rejects.toThrow(/validation failed/);
    expect(getCalls("/v1/accounts", "POST")).toHaveLength(0);
    expect(storedRecord()).toEqual(record());
    client.dispose();
  });

  it("legacy unscoped credentials are not transmitted or erased and do not trigger registration", async () => {
    localStorage.setItem("darkperp.v1Account", JSON.stringify({ apiKey: OLD_KEY, owner: OWNER_HEX }));
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const client = await RealDarkPerpClient.bootstrap(SCOPE.base);
    await expect(client.depositAccount()).rejects.toThrow(/Legacy/);
    expect(calls.some(c => c.headers["X-Api-Key"] === OLD_KEY)).toBe(false);
    expect(getCalls("/v1/accounts", "POST")).toHaveLength(0);
    expect(localStorage.getItem("darkperp.v1Account")).toContain(OLD_KEY);
    client.dispose();
  });

  it("a scope-mismatched record stored under our key is never sent to the gateway", async () => {
    localStorage.setItem(LS_KEY, JSON.stringify({ ...record(), base: "https://other.test", chainId: 84532 }));
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const client = await RealDarkPerpClient.bootstrap(SCOPE.base);
    await expect(client.depositAccount()).rejects.toThrow(/deployment/);
    expect(calls.some(c => c.headers["X-Api-Key"] === OLD_KEY)).toBe(false);
    expect(getCalls("/v1/accounts", "POST")).toHaveLength(0);
    client.dispose();
  });

  it("foreign-vault recovery metadata is rejected before wallet approval or POST", async () => {
    const client = await makeClient();
    intercept = async path => path.includes("/recovery/") ? json({ ...recoveryMeta(1), vault: AUTHORIZER }) : null;
    await expect(client.recoverAccount(OWNER_HEX)).rejects.toThrow(/different deployment/);
    expect(personalSigns).toHaveLength(0);
    expect(getCalls("/v1/accounts/recovery", "POST")).toHaveLength(0);
    client.dispose();
  });

  it("a confirmed rotation survives storage failure in memory and reports session-only access", async () => {
    const client = await makeClient();
    const before = localStorage.getItem(LS_KEY);
    const original = localStorage.setItem.bind(localStorage);
    vi.spyOn(localStorage, "setItem").mockImplementation((key, value) => {
      if (key === LS_KEY) throw new DOMException("Quota exceeded", "QuotaExceededError");
      original(key, value);
    });
    const result = await client.recoverAccount(OWNER_HEX);
    expect(result.credentialStorage).toBe("session");
    expect(localStorage.getItem(LS_KEY)).toBe(before);
    await client.getPositions();
    expect(lastApiKeyFor("/v1/positions")).toBe(NEW_KEY);
    client.dispose();
  });

  it("missing cross-tab locking fails before any recovery signature or mutation", async () => {
    const client = await makeClient();
    vi.stubGlobal("navigator", {});
    await expect(client.recoverAccount(OWNER_HEX)).rejects.toThrow(/cross-tab locking/);
    expect(personalSigns).toHaveLength(0);
    expect(getCalls("/v1/accounts/recovery", "POST")).toHaveLength(0);
    client.dispose();
  });

  it("two client instances cannot rotate the same account concurrently", async () => {
    const a = await makeClient();
    const b = await RealDarkPerpClient.bootstrap(SCOPE.base);
    const gate = deferred();
    recoveryPostHandler = async body => {
      await gate.promise;
      return { status: 200, body: { apiKey: NEW_KEY, owner: OWNER_HEX, recoveryNonce: Number(body.nonce) + 1, durability: "confirmed" } };
    };
    const first = a.recoverAccount(OWNER_HEX);
    await macrotask();
    await expect(b.recoverAccount(OWNER_HEX)).rejects.toThrow(/another tab/);
    expect(personalSigns).toHaveLength(1);
    expect(getCalls("/v1/accounts/recovery", "POST")).toHaveLength(1);
    gate.release(); await first;
    a.dispose(); b.dispose();
  });

  it("old socket error and close callbacks cannot close or replace the current connection", async () => {
    const client = await makeClient();
    const old = lastWsV1!;
    await client.recoverAccount(OWNER_HEX);
    const current = lastWsV1!;
    const close = vi.spyOn(current, "close");
    vi.useFakeTimers();
    old.onerror?.(); old.onclose?.();
    await vi.advanceTimersByTimeAsync(2000);
    expect(close).not.toHaveBeenCalled();
    expect(lastWsV1).toBe(current);
    vi.useRealTimers(); client.dispose();
  });

  it("a never-resolving POST reaches its deadline and bounds fresh-challenge retries", async () => {
    const client = await makeClient();
    await client.ownStateSettled();
    intercept = async (path, method) => path === "/v1/accounts/recovery" && method === "POST" ? new Promise(() => {}) : null;
    vi.useFakeTimers();
    const result = client.recoverAccount(OWNER_HEX).then(() => "unexpected-success", e => String(e));
    await vi.advanceTimersByTimeAsync(45_010);
    expect(await result).toMatch(/3 attempts/);
    expect(getCalls("/v1/accounts/recovery", "POST")).toHaveLength(3);
    expect(storedRecord()).toEqual(record());
    vi.useRealTimers(); client.dispose();
  });
});

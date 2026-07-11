// @vitest-environment happy-dom
//
// Task 11 — the browser client fetches + verifies the enclave order-epoch key and
// SEALS every order before POSTing. Two byte-exact cross-language contracts are
// pinned here against vectors extracted from the REAL Rust gateway functions
// (`enclave_epoch::epoch_signing_digest` and `serialize_order_terms`, run via
// `cargo test -p gateway`): if these tests fail, fix the TS mirror, never the pins.
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import { x25519KeypairFromIkm, domainAad, unseal } from "./sealedBox";
import {
  RealDarkPerpClient,
  serializeOrderTerms,
  epochSigningDigest,
  verifyEnclaveEpoch,
} from "./realClient";

// ── Rust-extracted contract vectors (source of truth) ────────────────────────
// epoch_signing_digest(1, &[0x11;32], 1_720_000_000_000)
const RUST_EPOCH_DIGEST = "2970286c16087c4e795e6434004031b19b350f93737d971dcaab10e945032753";
// serialize_order_terms{market_id:1, side:Sell, size:250_000_000, limit_price:6_450_000_000_000, tif:Fok, reduce_only:true, nonce:42}
const RUST_TERMS_1 =
  "01000000000000000280b2e60e0000000000000000000000000074f5c1dd050000000000000000000003012a00000000000000";
// serialize_order_terms{market_id:0, side:Buy, size:-1, limit_price:0, tif:Gtc, reduce_only:false, nonce:u64::MAX}
const RUST_TERMS_2 =
  "000000000000000001ffffffffffffffffffffffffffffffff000000000000000000000000000000000100ffffffffffffffff";

// ── fixtures: enclave signer (secp256k1) + epoch X25519 keypair ──────────────
const ENCLAVE_SK = new Uint8Array(32).fill(7);
const enclavePubUncompressed = secp256k1.getPublicKey(ENCLAVE_SK, false);
const ENCLAVE_ADDR = "0x" + bytesToHex(keccak_256(enclavePubUncompressed.subarray(1)).subarray(12));
const OTHER_SK = new Uint8Array(32).fill(9);

const epochKp = x25519KeypairFromIkm(
  new Uint8Array(32).fill(5),
  new Uint8Array([25, 1, 0, 0, 0, 0, 0, 0, 0]),
);
const MEASUREMENT = "0x" + "ab".repeat(32);

const ACCT_KEY = "0x" + "11".repeat(32);
const OWNER_HEX = "0x" + "22".repeat(32);

interface EpochOverrides {
  epochId?: number;
  notAfterMs?: number;
  pub?: Uint8Array;
  measurement?: string;
  sig?: string;
  signWith?: Uint8Array;
}

/** A gateway-shaped `/v1/enclave/epoch` response, genuinely signed over the digest. */
function signedEpoch(o: EpochOverrides = {}) {
  const epochId = o.epochId ?? 1;
  const notAfterMs = o.notAfterMs ?? Date.now() + 86_400_000;
  const pub = o.pub ?? epochKp.public;
  const digest = epochSigningDigest(BigInt(epochId), pub, BigInt(notAfterMs));
  const sg = secp256k1.sign(digest, o.signWith ?? ENCLAVE_SK);
  const sig65 = new Uint8Array(65);
  sig65.set(sg.toCompactRawBytes(), 0);
  sig65[64] = sg.recovery + 27;
  return {
    epochId,
    x25519Pub: "0x" + bytesToHex(pub),
    notAfterMs,
    measurement: o.measurement ?? MEASUREMENT,
    sig: o.sig ?? "0x" + bytesToHex(sig65),
  };
}

// ── mock gateway ─────────────────────────────────────────────────────────────
const wireMarket = {
  id: 0, symbol: "BTC/USDC", maxLeverage: 20, maintenanceMarginRatio: 0.05,
  initialMarginRatio: 0.1, referencePrice: "6450000000000", live: false,
  takerFeeBps: 8, makerRebateBps: 2,
};
const wireEthMarket = {
  id: 1, symbol: "ETH/USDC", maxLeverage: 20, maintenanceMarginRatio: 0.05,
  initialMarginRatio: 0.1, referencePrice: "350000000000", live: false,
  takerFeeBps: 8, makerRebateBps: 2,
};
// The WS/snapshot frame mirrors the shared prod gateway: book/oracle/selected
// are the SERVER's market (0), while `markets` + `marks` cover every market.
const wireState = {
  markets: [wireMarket, wireEthMarket], selectedMarketId: 0, market: wireMarket, mode: "Normal",
  oracle: { marketId: 0, price: "6450000000000", confidence: "1", publishTimeMs: 0 },
  book: { marketId: 0, bids: [], asks: [] },
  marks: { "0": "6450000000000", "1": "350000000000" }, account: { settledBalance: "0", positions: [] },
  orders: [], batches: [], insuranceFund: "0", treasury: "0", userAdlClawed: "0",
  lp: { tvl: "0", navPerShare: "1.000000", totalShares: "0", myShares: "0", myValue: "0" },
  mmHedge: [], l1: null, attestation: null,
};
// Per-market PUBLIC endpoints (the client-side market switch fetches these).
const ethBook = {
  marketId: 1,
  bids: [{ price: "351000000000", size: "200000000" }],
  asks: [{ price: "352000000000", size: "300000000" }],
};
const ethOracle = { marketId: 1, price: "351500000000", confidence: "5", publishTimeMs: 1234 };

interface Captured { path: string; method: string; headers: Record<string, string>; body: unknown }
let calls: Captured[] = [];
let epochResponse: () => unknown = () => signedEpoch();
let epochHits = 0;
let registrations = 0;
let v1WithdrawStatus = 200; // per-test override: gateway rejection of the REAL path
let demoWithdrawStatus = 200; // per-test override: legacy demo-mirror failure

function installFetch() {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: unknown, init?: { method?: string; headers?: Record<string, string>; body?: string }) => {
      const path = new URL(String(input)).pathname;
      const method = init?.method ?? "GET";
      calls.push({ path, method, headers: init?.headers ?? {}, body: init?.body ? JSON.parse(init.body) : null });
      const json = (v: unknown, status = 200) => ({
        ok: status < 400, status,
        json: async () => v,
        text: async () => JSON.stringify(v),
      });
      if (path === "/api/state") return json(wireState);
      if (path === "/v1/enclave/epoch") { epochHits++; return json(epochResponse()); }
      if (path === "/v1/accounts" && method === "POST") {
        registrations++;
        return json({ apiKey: ACCT_KEY, owner: OWNER_HEX, callerSigned: false });
      }
      if (path === "/v1/accounts/me") return json({ owner: OWNER_HEX });
      if (path === "/v1/orders" && method === "POST") {
        return json({ orderHash: "0x" + "00".repeat(32), seqNo: 1, recvTimeMs: 0, batchIdHint: 1 });
      }
      if (path === "/api/deposit" || path === "/v1/accounts/deposit") return json({});
      if (path === "/v1/accounts/withdraw" && method === "POST") {
        if (v1WithdrawStatus !== 200) {
          return json({ error: "Not withdrawable: amount exceeds the SETTLED balance in this market (§3)." }, v1WithdrawStatus);
        }
        return json({ to: "0x" + "ab".repeat(20), amount: "5000000", nonce: 0, leaf: "0x" + "aa".repeat(32), status: "recorded" });
      }
      if (path === "/api/withdraw" && method === "POST") {
        if (demoWithdrawStatus !== 200) return json({ error: "demo state unavailable" }, demoWithdrawStatus);
        return json({});
      }
      if (path === "/v1/markets/0/orderbook") return json({ marketId: 0, bids: [], asks: [] });
      if (path === "/v1/markets/0/oracle") return json({ marketId: 0, price: "6450000000000", confidence: "1", publishTimeMs: 0 });
      if (path === "/v1/markets/1/orderbook") return json(ethBook);
      if (path === "/v1/markets/1/oracle") return json(ethOracle);
      throw new Error(`unexpected fetch ${method} ${path}`);
    }),
  );
}

let lastWs: FakeWebSocket | null = null;

class FakeWebSocket {
  onmessage: ((ev: { data: string }) => void) | null = null;
  onclose: (() => void) | null = null;
  onerror: (() => void) | null = null;
  constructor(_url: string) { lastWs = this; }
  close() {}
}

/** Push a server state frame (market 0 selected) through the client's WS. */
function pushStateFrame() {
  lastWs!.onmessage!({ data: JSON.stringify({ type: "state", state: wireState }) });
}

const ordersPosted = () => calls.filter((c) => c.path === "/v1/orders" && c.method === "POST");

async function bootstrapClient() {
  return RealDarkPerpClient.bootstrap("http://gw.test");
}

beforeEach(() => {
  calls = [];
  epochHits = 0;
  registrations = 0;
  lastWs = null;
  v1WithdrawStatus = 200;
  demoWithdrawStatus = 200;
  epochResponse = () => signedEpoch();
  localStorage.clear();
  installFetch();
  vi.stubGlobal("WebSocket", FakeWebSocket);
  vi.stubEnv("VITE_ENCLAVE_SIGNER", ENCLAVE_ADDR);
  vi.stubEnv("VITE_ENCLAVE_MEASUREMENT", MEASUREMENT);
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
});

// ── CONTRACT 1: epoch signing digest + verification ──────────────────────────
describe("enclave epoch verification (contract 1)", () => {
  it("epochSigningDigest matches the Rust gateway byte-for-byte", () => {
    const d = epochSigningDigest(1n, hexToBytes("11".repeat(32)), 1_720_000_000_000n);
    expect(bytesToHex(d)).toBe(RUST_EPOCH_DIGEST);
  });

  it("accepts a genuinely signed epoch and returns the key material", () => {
    const ep = signedEpoch();
    const v = verifyEnclaveEpoch(ep, { expectedSigner: ENCLAVE_ADDR, expectedMeasurement: MEASUREMENT });
    expect(v.epochId).toBe(1);
    expect(bytesToHex(v.pub)).toBe(bytesToHex(epochKp.public));
    expect(v.notAfterMs).toBe(ep.notAfterMs);
  });

  it("rejects a tampered signature (recovered address ≠ pinned signer)", () => {
    const ep = signedEpoch();
    const sig = hexToBytes(ep.sig.slice(2));
    sig[10] ^= 0x01; // flip one bit of r
    expect(() =>
      verifyEnclaveEpoch({ ...ep, sig: "0x" + bytesToHex(sig) }, { expectedSigner: ENCLAVE_ADDR }),
    ).toThrow(/signer|recover/i);
  });

  it("rejects an epoch signed by the wrong key", () => {
    const ep = signedEpoch({ signWith: OTHER_SK });
    expect(() => verifyEnclaveEpoch(ep, { expectedSigner: ENCLAVE_ADDR })).toThrow(/signer/i);
  });

  it("rejects v outside {27,28} and malformed field lengths", () => {
    const ep = signedEpoch();
    const badV = hexToBytes(ep.sig.slice(2));
    badV[64] = 29;
    expect(() =>
      verifyEnclaveEpoch({ ...ep, sig: "0x" + bytesToHex(badV) }, { expectedSigner: ENCLAVE_ADDR }),
    ).toThrow(/v/i);
    expect(() =>
      verifyEnclaveEpoch({ ...ep, x25519Pub: "0x1111" }, { expectedSigner: ENCLAVE_ADDR }),
    ).toThrow(/hex|32/i);
    expect(() =>
      verifyEnclaveEpoch({ ...ep, sig: ep.sig.slice(0, 10) }, { expectedSigner: ENCLAVE_ADDR }),
    ).toThrow(/hex|65/i);
  });

  it("rejects a measurement mismatch when a measurement is pinned", () => {
    const ep = signedEpoch();
    expect(() =>
      verifyEnclaveEpoch(ep, { expectedSigner: ENCLAVE_ADDR, expectedMeasurement: "0x" + "cd".repeat(32) }),
    ).toThrow(/measurement/i);
  });

  it("unpinned signer (dev): accepts an internally-valid sig but warns", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const v = verifyEnclaveEpoch(signedEpoch(), {});
    expect(v.epochId).toBe(1);
    expect(warn).toHaveBeenCalled();
  });

  it("rejects an EMPTY/whitespace signer pin (no silent downgrade to unpinned)", () => {
    // present-but-empty VITE_ENCLAVE_SIGNER is a config bug, never dev mode
    expect(() => verifyEnclaveEpoch(signedEpoch(), { expectedSigner: "" })).toThrow(/empty/i);
    expect(() => verifyEnclaveEpoch(signedEpoch(), { expectedSigner: "   " })).toThrow(/empty/i);
  });

  it("rejects a malformed signer pin (must be a 20-byte 0x-hex address)", () => {
    expect(() => verifyEnclaveEpoch(signedEpoch(), { expectedSigner: "0x1234" })).toThrow(/address/i);
    expect(() =>
      verifyEnclaveEpoch(signedEpoch(), { expectedSigner: ENCLAVE_ADDR.slice(2) }), // no 0x
    ).toThrow(/address/i);
  });

  it("production build without a signer pin is a hard error (unpinned is dev-only)", () => {
    expect(() => verifyEnclaveEpoch(signedEpoch(), { prod: true })).toThrow(/production|pinned/i);
    // with the pin set, prod verifies normally
    const v = verifyEnclaveEpoch(signedEpoch(), { prod: true, expectedSigner: ENCLAVE_ADDR });
    expect(v.epochId).toBe(1);
  });
});

// ── CONTRACT 2: canonical 51-byte order-terms layout ─────────────────────────
describe("canonical order terms (contract 2)", () => {
  it("serializes byte-for-byte identically to Rust serialize_order_terms", () => {
    const t1 = serializeOrderTerms({
      marketId: 1n, side: "Sell", size: 250_000_000n, limitPrice: 6_450_000_000_000n,
      tif: "Fok", reduceOnly: true, nonce: 42n,
    });
    expect(t1.length).toBe(51);
    expect(bytesToHex(t1)).toBe(RUST_TERMS_1);

    // negative i128 two's complement + max u64 nonce
    const t2 = serializeOrderTerms({
      marketId: 0n, side: "Buy", size: -1n, limitPrice: 0n,
      tif: "Gtc", reduceOnly: false, nonce: 0xffff_ffff_ffff_ffffn,
    });
    expect(bytesToHex(t2)).toBe(RUST_TERMS_2);
  });

  it("side/tif numeric mapping is exact (Buy=1,Sell=2; Gtc=1,Ioc=2,Fok=3,PostOnly=4)", () => {
    const base = { marketId: 0n, size: 1n, limitPrice: 0n, reduceOnly: false, nonce: 0n } as const;
    expect(serializeOrderTerms({ ...base, side: "Buy", tif: "Gtc" })[8]).toBe(1);
    expect(serializeOrderTerms({ ...base, side: "Sell", tif: "Gtc" })[8]).toBe(2);
    expect(serializeOrderTerms({ ...base, side: "Buy", tif: "Gtc" })[41]).toBe(1);
    expect(serializeOrderTerms({ ...base, side: "Buy", tif: "Ioc" })[41]).toBe(2);
    expect(serializeOrderTerms({ ...base, side: "Buy", tif: "Fok" })[41]).toBe(3);
    expect(serializeOrderTerms({ ...base, side: "Buy", tif: "PostOnly" })[41]).toBe(4);
  });

  it("rejects out-of-range values instead of silently truncating", () => {
    const base = { marketId: 0n, side: "Buy", size: 1n, limitPrice: 0n, tif: "Gtc", reduceOnly: false, nonce: 0n } as const;
    expect(() => serializeOrderTerms({ ...base, nonce: 1n << 64n })).toThrow();
    expect(() => serializeOrderTerms({ ...base, marketId: -1n })).toThrow();
    expect(() => serializeOrderTerms({ ...base, size: 1n << 127n })).toThrow();
    expect(() => serializeOrderTerms({ ...base, side: "buy" as never })).toThrow();
    expect(() => serializeOrderTerms({ ...base, tif: "GTC" as never })).toThrow();
  });
});

// ── the client: seal-before-POST behaviour ───────────────────────────────────
describe("RealDarkPerpClient sealed order flow", () => {
  it("placeOrder POSTs ONLY {epochId, sealed} to /v1/orders — never raw terms — and the payload decrypts to the canonical bytes", async () => {
    const client = await bootstrapClient();
    const receipt = await client.placeOrder({
      marketId: 0, side: "Sell", size: 250_000_000n, limitPrice: 6_450_000_000_000n,
      tif: "Fok", reduceOnly: true,
    });
    expect(receipt.seqNo).toBe(1);

    const posts = ordersPosted();
    expect(posts.length).toBe(1);
    const { headers, body } = posts[0];
    expect(headers["X-Api-Key"]).toBe(ACCT_KEY);

    // Wire shape: exactly {epochId, sealed} — no plaintext order terms.
    const b = body as Record<string, unknown>;
    expect(Object.keys(b).sort()).toEqual(["epochId", "sealed"]);
    expect(b.epochId).toBe(1);
    expect(typeof b.sealed).toBe("string");
    expect((b.sealed as string).startsWith("0x")).toBe(true);

    // The sealed payload decrypts (with the epoch secret + the exact AAD) to the
    // canonical 51-byte terms.
    const wire = hexToBytes((b.sealed as string).slice(2));
    const extra = new Uint8Array(40);
    extra.set(hexToBytes("0100000000000000"), 0); // epochId 1 as u64 LE
    extra.set(hexToBytes(OWNER_HEX.slice(2)), 8); // owner pubkey (32B)
    const aad = domainAad(28, extra);
    const pt = unseal(epochKp.secret, wire, aad);
    expect(pt).not.toBeNull();
    expect(pt!.length).toBe(51);

    // Reconstruct expected terms with the client-chosen nonce (last 8 bytes LE).
    let nonce = 0n;
    for (let i = 7; i >= 0; i--) nonce = (nonce << 8n) | BigInt(pt![43 + i]);
    const expected = serializeOrderTerms({
      marketId: 0n, side: "Sell", size: 250_000_000n, limitPrice: 6_450_000_000_000n,
      tif: "Fok", reduceOnly: true, nonce,
    });
    expect(bytesToHex(pt!)).toBe(bytesToHex(expected));

    // AAD binds epoch + owner: a different owner or epoch id fails to open.
    const wrongOwner = new Uint8Array(extra); wrongOwner[8] ^= 0xff;
    expect(unseal(epochKp.secret, wire, domainAad(28, wrongOwner))).toBeNull();
    const wrongEpoch = new Uint8Array(extra); wrongEpoch[0] = 2;
    expect(unseal(epochKp.secret, wire, domainAad(28, wrongEpoch))).toBeNull();
  });

  it("fails CLOSED: a tampered/wrong-signer epoch blocks placeOrder entirely (no fallback to plaintext)", async () => {
    epochResponse = () => signedEpoch({ signWith: OTHER_SK });
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const client = await bootstrapClient(); // bootstrap survives (read-only UI)
    expect(warn).toHaveBeenCalled();
    await expect(
      client.placeOrder({ marketId: 0, side: "Buy", size: 1n, limitPrice: 0n, tif: "Ioc", reduceOnly: false }),
    ).rejects.toThrow(/signer/i);
    expect(ordersPosted().length).toBe(0);
  });

  it("re-fetches + re-verifies the epoch once notAfterMs has passed", async () => {
    const stale = signedEpoch({ epochId: 1, notAfterMs: Date.now() - 1000 });
    let served = 0;
    epochResponse = () => (++served === 1 ? stale : signedEpoch({ epochId: 2 }));
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const client = await bootstrapClient(); // caches the (stale) epoch 1, with a warning
    expect(warn).toHaveBeenCalled();
    await client.placeOrder({ marketId: 0, side: "Buy", size: 1n, limitPrice: 1n, tif: "Gtc", reduceOnly: false });
    expect(epochHits).toBe(2); // bootstrap + expiry refetch
    expect((ordersPosted()[0].body as { epochId: number }).epochId).toBe(2);
  });

  it("provisions the /v1 sealing account once and persists it across bootstraps", async () => {
    await bootstrapClient();
    expect(registrations).toBe(1);
    await bootstrapClient(); // second boot: stored key revalidated via /v1/accounts/me
    expect(registrations).toBe(1);
    expect(calls.some((c) => c.path === "/v1/accounts/me")).toBe(true);
  });

  it("mirrors deposits to the /v1 trading account so sealed orders have margin", async () => {
    const client = await bootstrapClient();
    await client.deposit(5_000_000n);
    const demo = calls.find((c) => c.path === "/api/deposit");
    const v1 = calls.find((c) => c.path === "/v1/accounts/deposit");
    expect(demo?.body).toEqual({ amount: "5000000" });
    expect(v1?.body).toEqual({ marketId: 0, amount: "5000000" });
    expect(v1?.headers["X-Api-Key"]).toBe(ACCT_KEY);
  });
});

// ── withdrawals: /v1 PRIMARY (real claimable leaf), demo mirror cosmetic ──────
describe("RealDarkPerpClient.requestWithdrawal", () => {
  const TO = "0x" + "cd".repeat(20);

  it("posts the REAL /v1 withdrawal FIRST (keyed {marketId, amount, to}), then mirrors the legacy demo path", async () => {
    const client = await bootstrapClient();
    await client.requestWithdrawal(5_000_000n, TO);
    const v1Idx = calls.findIndex((c) => c.path === "/v1/accounts/withdraw");
    const demoIdx = calls.findIndex((c) => c.path === "/api/withdraw");
    expect(v1Idx).toBeGreaterThan(-1);
    expect(demoIdx).toBeGreaterThan(-1);
    // Priority inversion vs deposit: the /v1 call is the money path and runs first.
    expect(v1Idx).toBeLessThan(demoIdx);
    expect(calls[v1Idx].body).toEqual({ marketId: 0, amount: "5000000", to: TO });
    expect(calls[v1Idx].headers["X-Api-Key"]).toBe(ACCT_KEY);
    expect(calls[demoIdx].body).toEqual({ amount: "5000000" });
  });

  it("surfaces a /v1 rejection and SKIPS the demo mirror (no silent fallback — demo cannot mint a claimable leaf)", async () => {
    const client = await bootstrapClient();
    v1WithdrawStatus = 400;
    await expect(client.requestWithdrawal(5_000_000n, TO)).rejects.toThrow(/exceeds the SETTLED/i);
    expect(calls.some((c) => c.path === "/api/withdraw")).toBe(false);
  });

  it("swallows a demo-mirror failure with a warning — the real withdrawal already landed", async () => {
    const client = await bootstrapClient();
    demoWithdrawStatus = 500;
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    await expect(client.requestWithdrawal(5_000_000n, TO)).resolves.toBeUndefined();
    expect(calls.some((c) => c.path === "/v1/accounts/withdraw")).toBe(true);
    expect(warn).toHaveBeenCalledWith(expect.stringMatching(/mirror/i), expect.anything());
  });
});

// ── CONTRACT: client-side market selection ───────────────────────────────────
// The legacy POST /api/select-market is 404 in prod AND was a global toggle;
// which market a browser views is client-local. selectMarket switches instantly
// (metadata + marks are already per-market) and fetches the market's live
// book/oracle, which the WS (server's market only) would otherwise never refresh.
describe("client-side market selection (contract)", () => {
  /** Let queued microtasks (the refreshSelected fetch chain) settle. */
  const flush = async () => { await Promise.resolve(); await Promise.resolve(); await Promise.resolve(); };

  it("switches selectedMarketId + market metadata INSTANTLY, before the book fetch resolves", async () => {
    const client = await bootstrapClient();
    expect(client.getState().selectedMarketId).toBe(0);
    client.selectMarket(1);
    // synchronous: no await — the switch is immediate off marks/markets
    const st = client.getState();
    expect(st.selectedMarketId).toBe(1);
    expect(st.market.symbol).toBe("ETH/USDC");
    client.dispose();
  });

  it("fetches the selected market's live book + oracle and applies them once resolved", async () => {
    const client = await bootstrapClient();
    client.selectMarket(1);
    await flush();
    const st = client.getState();
    expect(st.book.bids[0]?.price).toBe(351_000_000_000n);
    expect(st.book.asks[0]?.price).toBe(352_000_000_000n);
    expect(st.oracle.price).toBe(351_500_000_000n);
    // it fetched the per-market public endpoints, never the dead /api route
    expect(calls.some((c) => c.path === "/v1/markets/1/orderbook")).toBe(true);
    expect(calls.some((c) => c.path === "/api/select-market")).toBe(false);
    client.dispose();
  });

  it("a later server WS frame (market 0) does NOT reset the client's selection", async () => {
    const client = await bootstrapClient();
    client.selectMarket(1);
    await flush();
    pushStateFrame(); // server frame carries selectedMarketId 0 + market-0 book
    const st = client.getState();
    expect(st.selectedMarketId).toBe(1);
    expect(st.market.symbol).toBe("ETH/USDC");
    expect(st.book.bids[0]?.price).toBe(351_000_000_000n); // still ETH's book, not the frame's empty market-0 book
    client.dispose();
  });

  it("ignores an unknown market id", async () => {
    const client = await bootstrapClient();
    client.selectMarket(999);
    expect(client.getState().selectedMarketId).toBe(0);
    expect(calls.some((c) => c.path === "/v1/markets/999/orderbook")).toBe(false);
    client.dispose();
  });

  it("targets the selected market for deposits/withdrawals (not the server's)", async () => {
    const client = await bootstrapClient();
    client.selectMarket(1);
    await flush();
    await client.requestWithdrawal(1_000_000n, "0x" + "cd".repeat(20));
    const v1 = calls.find((c) => c.path === "/v1/accounts/withdraw");
    expect((v1!.body as { marketId: number }).marketId).toBe(1);
    client.dispose();
  });
});

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
  withdrawAuthDigest,
} from "./realClient";
import type { OrderEvent } from "./client";

// ── Rust-extracted contract vectors (source of truth) ────────────────────────
// epoch_signing_digest(1, &[0x11;32], 1_720_000_000_000)
const RUST_EPOCH_DIGEST = "2970286c16087c4e795e6434004031b19b350f93737d971dcaab10e945032753";
// serialize_order_terms{market_id:1, side:Sell, size:250_000_000, limit_price:6_450_000_000_000, tif:Fok, reduce_only:true, nonce:42}
const RUST_TERMS_1 =
  "01000000000000000280b2e60e0000000000000000000000000074f5c1dd050000000000000000000003012a00000000000000";
// serialize_order_terms{market_id:0, side:Buy, size:-1, limit_price:0, tif:Gtc, reduce_only:false, nonce:u64::MAX}
const RUST_TERMS_2 =
  "000000000000000001ffffffffffffffffffffffffffffffff000000000000000000000000000000000100ffffffffffffffff";
// SEC-021 — gateway `auth_digests_match_known_answer_vectors` (crates/gateway/src/main.rs):
// withdraw_auth_digest(84532, &[0x22;20], &[0x07;32], 0, 1_000, &[0x11;20], 1)
const RUST_WITHDRAW_DIGEST = "297d6fcc305700b679a59a06cb0d990a70157fcc314f93f69ed36bb1eec6ff97";
// withdraw_auth_digest(84532, &[0x22;20], &[0x07;32], 0, -1, &[0x11;20], 1)
// — pins the i128 two's-complement big-endian amount encoding (16 bytes of 0xFF)
const RUST_WITHDRAW_DIGEST_NEG = "e9285454ef17c530a4a32577d234bbace2d0fc1177f7a9a677a88f63474f695e";

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
/** The key a POST-WIPE re-registration hands out (review F7's recovery test). */
const ACCT_KEY2 = "0x" + "77".repeat(32);
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

// ── SEC-025-E1 fixtures: the caller's /v1 account state ≠ the demo wallet's ──
// The public /api/state feed serves ONLY the shared demo wallet (the gateway's
// LIQ-001 invariant), so a client that keeps reading account state off it shows
// the WRONG account. Every distinguishing field below DIFFERS between the demo
// wallet and the caller's /v1 account — id demo-1 vs o42, market 0 vs 1, Buy vs
// Sell, seqNo 77 vs 5, hash dd… vs a1…, long-BTC vs short-ETH, settledBalance
// 123000000 vs 987654321777 (no combination of the demo fixture's values
// produces the /v1 one) — so an implementation still reading /api/state cannot
// pass any assertion by coincidence (the workstream's most common defect shape).
const demoOrder = {
  id: "demo-1",
  input: { marketId: 0, side: "Buy", size: "100000000", limitPrice: "6400000000000", tif: "Gtc", reduceOnly: false },
  receipt: { orderHash: "0x" + "dd".repeat(32), seqNo: 77, recvTimeMs: 1000, batchIdHint: 2, windowId: 1 },
  finality: "MATCHED", filledSize: "100000000", avgFillPrice: "6400000000000", createdMs: 1000,
};
const demoPosition = {
  marketId: 0, size: "100000000", entryPrice: "6400000000000",
  collateral: "32000000000", unrealizedPnl: "5000000000", liquidationPrice: "6100000000000",
};
const demoState = {
  ...wireState,
  orders: [demoOrder],
  account: { settledBalance: "123000000", positions: [demoPosition] },
};
// The caller's own order in the FLAT `GET /v1/orders` wire shape (no nested
// `input`; `receipt` per SEC-025-E1 decision (c), including the extra windowId).
const v1Order = {
  orderId: "o42", marketId: 1, side: "Sell", size: "250000000", limitPrice: "352000000000",
  tif: "Fok", reduceOnly: true, orderHash: "0x" + "a1".repeat(32), finality: "ACCEPTED",
  filledSize: "0", avgFillPrice: "0", createdMs: 5000,
  receipt: { orderHash: "0x" + "a1".repeat(32), seqNo: 5, recvTimeMs: 5001, batchIdHint: 3, windowId: 9 },
};
const v1Position = {
  marketId: 1, size: "-25000000", entryPrice: "351000000000",
  collateral: "1755000000", unrealizedPnl: "-12500000", liquidationPrice: "368550000000",
};
// The /v1 account's settledBalance (`GET /v1/accounts/me`). Deliberately a value
// the demo wallet's fixtures cannot produce (no sum/echo of 123000000 or any
// demo field): a mixed-account overlay — demo balance beside /v1 positions —
// must fail the balance assertions, never pass by coincidence.
const V1_BALANCE = "987654321777";

interface Captured { path: string; method: string; headers: Record<string, string>; body: unknown }
let calls: Captured[] = [];
let epochResponse: () => unknown = () => signedEpoch();
let epochHits = 0;
let registrations = 0;
let v1WithdrawStatus = 200; // per-test override: gateway rejection of the REAL path
let v1DepositStatus = 200; // per-test override: the production unbacked-mint refusal
let v1CancelStatus = 200; // per-test override: gateway cancel refusal (sealed/finality)
let authorizeStatus = 200; // per-test override: gateway rejection (bind-first etc.)
let authorizeBody: unknown = null; // per-test override of the response body (null ⇒ well-formed default)
let stateResponse: unknown = wireState; // per-test override of the /api/state snapshot
let v1OrdersResponse: unknown = { orders: [] }; // GET /v1/orders (own-account read)
let v1PositionsResponse: unknown = { positions: [] }; // GET /v1/positions (own-account read)
let accountsStatus = 200; // per-test override: /v1 account registration failure
// One-shot gate: parks the NEXT GET /v1/orders (payload captured at REQUEST
// time) until resolved — a slow read delivering a stale list late.
let v1OrdersGate: Promise<void> | null = null;
// The api key the gateway currently accepts (and hands out on registration).
// Tests model a state-wipe cutover (review F7) by flipping it: the old key
// 401s everywhere and a fresh registration returns the new one.
let validKey = ACCT_KEY;
// Review F4 ordering hooks: run when the mutating POST lands, so a test can
// move the served balance AT the mutation — a refresh issued BEFORE the POST
// cannot see the post-mutation value.
let afterWithdrawPost: (() => void) | null = null;
let afterOnchainPost: (() => void) | null = null;

// ── SEC-021 withdrawal-authorization fixtures ────────────────────────────────
// The bound deposit address withdrawals pay to (and whose key signs).
const BOUND = "0x" + "cd".repeat(20);
// Deliberately DISTINCTIVE fixture values: NOT the Rust KAT vault (0x2222…)
// and NOT the real Base Sepolia chain id (84532). If realClient ever hardcodes
// either instead of reading them off /v1/accounts/me, the digest assertions
// below diverge and fail. (With KAT-coincident values, a hardcode passed —
// which is exactly what these fixtures must catch. The KAT tests keep their
// own 84532/0x2222… inputs: those pin the Rust vectors, not this property.)
const VAULT = "0x" + "3b".repeat(20);
const CHAIN_ID = 4242;
// Per-test override of the SEC-021 + SEC-025-E1 fields GET /v1/accounts/me serves.
let meFields: Record<string, unknown> = {};
const defaultMeFields = () => ({
  settledBalance: V1_BALANCE,
  depositAddress: BOUND, callerSigned: false, nextWithdrawNonce: 1,
  rebindCounter: 0, chainId: CHAIN_ID, vault: VAULT,
});

// A fake EIP-1193 wallet answering `personal_sign` — records what it was asked
// to sign (and as which account) so tests can assert the EXACT digest. Injected
// onto `window` directly (the pattern AccountPanel.wallet.test.tsx uses):
// wallet.ts reads `window.ethereum`, which stubGlobal does not reliably reach.
const FAKE_SIG = "0x" + "ef".repeat(65);
let personalSigns: { digestHex: string; address: string }[] = [];
function installWallet() {
  (window as unknown as { ethereum?: unknown }).ethereum = {
    request: async ({ method, params }: { method: string; params?: unknown[] }) => {
      if (method === "personal_sign") {
        personalSigns.push({ digestHex: params?.[0] as string, address: params?.[1] as string });
        return FAKE_SIG;
      }
      throw new Error(`unexpected wallet method ${method}`);
    },
  };
}

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
      if (path === "/api/state") return json(stateResponse);
      if (path === "/v1/enclave/epoch") { epochHits++; return json(epochResponse()); }
      if (path === "/v1/accounts" && method === "POST") {
        registrations++;
        if (accountsStatus !== 200) return json({ error: "registration unavailable" }, accountsStatus);
        return json({ apiKey: validKey, owner: OWNER_HEX, callerSigned: false });
      }
      if (path === "/v1/accounts/me") {
        // Authenticated like the gateway's — the SEC-025-E1 balance read must
        // provably be the CALLER's account, not an open endpoint.
        if (init?.headers?.["X-Api-Key"] !== validKey) return json({ error: "unknown account" }, 401);
        return json({ owner: OWNER_HEX, ...meFields });
      }
      if (path === "/v1/orders" && method === "POST") {
        return json({ orderHash: "0x" + "00".repeat(32), seqNo: 1, recvTimeMs: 0, batchIdHint: 1 });
      }
      // SEC-025-E1 own-account reads — authenticated per account, like the gateway.
      if ((path === "/v1/orders" || path === "/v1/positions") && method === "GET") {
        if (init?.headers?.["X-Api-Key"] !== validKey) return json({ error: "unknown account" }, 401);
        if (path === "/v1/positions") return json(v1PositionsResponse);
        const payload = v1OrdersResponse; // response reflects state AS OF the request
        if (v1OrdersGate) {
          const gate = v1OrdersGate;
          v1OrdersGate = null; // one-shot: later reads answer immediately
          await gate;
        }
        return json(payload);
      }
      if (path === "/v1/accounts/deposit" && method === "POST") {
        if (init?.headers?.["X-Api-Key"] !== validKey) return json({ error: "unknown account" }, 401);
        if (v1DepositStatus !== 200) {
          return json(
            { error: "unbacked demo deposit refused in production — fund the account on-chain (wallet deposit + confirm) instead" },
            v1DepositStatus,
          );
        }
        return json({});
      }
      // Task 3: the CALLER-scoped cancel — resolves the id inside the
      // authenticated account only, like the gateway's `account_cancel`.
      if (path.startsWith("/v1/orders/") && method === "DELETE") {
        if (init?.headers?.["X-Api-Key"] !== validKey) return json({ error: "unknown account" }, 401);
        if (v1CancelStatus !== 200) {
          return json(
            { error: "Only an ACCEPTED order can be cancelled (matched/settled are binding)." },
            v1CancelStatus,
          );
        }
        return json({ orderId: path.slice("/v1/orders/".length), cancelled: true });
      }
      // The LEGACY demo cancel resolver: `POST /api/cancel` matches the id
      // against the SHARED DEMO WALLET's own list (gateway `Gw::cancel` over
      // `self.orders`). It deliberately ANSWERS SUCCESS here — in the
      // cross-account fixture the demo wallet DOES hold the id — so a client
      // that mis-routes a cancel to it does NOT fail by throwing: it can only
      // fail the targeting assertions (that is the hazard under test — a
      // user's cancel silently cancelling a stranger's same-named order).
      if (path === "/api/cancel" && method === "POST") return json({});
      if (path === "/v1/accounts/withdraw" && method === "POST") {
        if (v1WithdrawStatus !== 200) {
          return json({ error: "Not withdrawable: amount exceeds the SETTLED balance in this market (§3)." }, v1WithdrawStatus);
        }
        if (afterWithdrawPost) {
          // Review F4 ordering pin: the server "processes" for one macrotask,
          // so every microtask-queued read issued BEFORE this POST resolves
          // still sees the pre-mutation balance — only a refresh issued AFTER
          // the POST resolves can observe the hook's post-mutation value. A
          // refresh relocated ahead of the POST therefore fails the test.
          await new Promise<void>((r) => setTimeout(r, 0));
          afterWithdrawPost();
        }
        return json({ to: "0x" + "ab".repeat(20), amount: "5000000", nonce: 0, leaf: "0x" + "aa".repeat(32), status: "recorded" });
      }
      // Review F4: the on-chain deposit credit (the wallet pipeline's step 4).
      if (path === "/v1/accounts/deposit/onchain" && method === "POST") {
        if (init?.headers?.["X-Api-Key"] !== validKey) return json({ error: "unknown account" }, 401);
        if (afterOnchainPost) {
          await new Promise<void>((r) => setTimeout(r, 0)); // same ordering pin as withdraw
          afterOnchainPost();
        }
        return json({ credited: "1000000" });
      }
      if (path === "/v1/accounts/deposit/authorize" && method === "POST") {
        if (authorizeStatus !== 200) {
          return json(
            { error: "Bind a deposit address first (POST /v1/accounts/deposit/address)." },
            authorizeStatus,
          );
        }
        return json(authorizeBody ?? { ownerCommit: "0x" + "ab".repeat(32), sig: "0x" + "cd".repeat(65) });
      }
      if (path === "/v1/markets/0/orderbook") return json({ marketId: 0, bids: [], asks: [] });
      if (path === "/v1/markets/0/oracle") return json({ marketId: 0, price: "6450000000000", confidence: "1", publishTimeMs: 0 });
      if (path === "/v1/markets/1/orderbook") return json(ethBook);
      if (path === "/v1/markets/1/oracle") return json(ethOracle);
      throw new Error(`unexpected fetch ${method} ${path}`);
    }),
  );
}

let lastWs: FakeWebSocket | null = null; // legacy /ws (public state stream)
let lastWsV1: FakeWebSocket | null = null; // /v1/ws (authenticated account stream)

class FakeWebSocket {
  onopen: (() => void) | null = null;
  onmessage: ((ev: { data: string }) => void) | null = null;
  onclose: (() => void) | null = null;
  onerror: (() => void) | null = null;
  /** 0 = CONNECTING until the test calls open() — like a real socket. */
  readyState = 0;
  /** Everything the client sent — the /v1/ws auth handshake lands here. */
  sent: string[] = [];
  readonly url: string;
  constructor(url: string) {
    this.url = url;
    // "/v1/ws".endsWith("/ws") too — discriminate on the /v1 segment.
    if (url.includes("/v1/ws")) lastWsV1 = this;
    else lastWs = this;
  }
  send(data: string) { this.sent.push(data); }
  close() {}
  /** Test hook: the server accepted the connection. */
  open() { this.readyState = 1; this.onopen?.(); }
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
  lastWsV1 = null;
  v1WithdrawStatus = 200;
  v1DepositStatus = 200;
  v1CancelStatus = 200;
  authorizeStatus = 200;
  authorizeBody = null;
  stateResponse = wireState;
  v1OrdersResponse = { orders: [] };
  v1PositionsResponse = { positions: [] };
  v1OrdersGate = null;
  accountsStatus = 200;
  validKey = ACCT_KEY;
  afterWithdrawPost = null;
  afterOnchainPost = null;
  meFields = defaultMeFields();
  personalSigns = [];
  epochResponse = () => signedEpoch();
  localStorage.clear();
  installFetch();
  installWallet();
  vi.stubGlobal("WebSocket", FakeWebSocket);
  vi.stubEnv("VITE_ENCLAVE_SIGNER", ENCLAVE_ADDR);
  vi.stubEnv("VITE_ENCLAVE_MEASUREMENT", MEASUREMENT);
});

afterEach(() => {
  delete (window as unknown as { ethereum?: unknown }).ethereum;
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

  // ── Task 3: the legacy `POST /api/deposit` primary is GONE ────────────────
  // It is unmounted in production (build_router), and because it ran FIRST and
  // threw, its 404 also blocked the /v1 leg — in production the old deposit()
  // could never fund anything. The /v1 deposit (mounted in BOTH postures; the
  // production gateway answers it with the SEC-025-C unbacked-mint refusal) is
  // now the only path. The fetch harness no longer answers /api/deposit at
  // all, so a resurrected legacy call fails loudly as an unexpected fetch.

  it("deposit funds ONLY the authenticated /v1 account — no legacy demo call — and refreshes the own-account view", async () => {
    const client = await bootstrapClient();
    const meReadsBefore = calls.filter((c) => c.path === "/v1/accounts/me").length;
    await client.deposit(5_000_000n);
    await client.ownStateSettled();
    expect(calls.some((c) => c.path === "/api/deposit")).toBe(false);
    const v1 = calls.find((c) => c.path === "/v1/accounts/deposit");
    expect(v1?.body).toEqual({ marketId: 0, amount: "5000000" });
    expect(v1?.headers["X-Api-Key"]).toBe(ACCT_KEY);
    // The credit changes the /v1 balance, which only the own-account refresh
    // can surface (deposits emit no /v1/ws event) — one more /me read landed.
    expect(calls.filter((c) => c.path === "/v1/accounts/me").length).toBeGreaterThan(meReadsBefore);
    client.dispose();
  });

  it("a refused /v1 deposit (the production posture) SURFACES the gateway's reason — never resolves as success", async () => {
    const client = await bootstrapClient();
    v1DepositStatus = 400;
    await expect(client.deposit(5_000_000n)).rejects.toThrow(/refused in production/i);
    client.dispose();
  });
});

// ── CONTRACT 3: SEC-021 withdrawal-authorization digest ──────────────────────
// The gateway concatenates fixed-width BIG-endian fields with no separators, so
// a wrong field width silently produces a different digest and the signature is
// rejected with no clue why — hence the hard-coded Rust known-answer pins
// (gateway test `auth_digests_match_known_answer_vectors`). If these fail, fix
// the TS mirror, never the pins.
describe("withdrawAuthDigest (contract 3)", () => {
  const KAT_VAULT = "0x" + "22".repeat(20);
  const KAT_OWNER = new Uint8Array(32).fill(7);
  const KAT_TO = "0x" + "11".repeat(20);

  it("matches the Rust gateway KAT byte-for-byte", () => {
    const d = withdrawAuthDigest(84532n, KAT_VAULT, KAT_OWNER, 0n, 1_000n, KAT_TO, 1n);
    expect(bytesToHex(d)).toBe(RUST_WITHDRAW_DIGEST);
  });

  it("pins the i128 two's-complement big-endian amount encoding (negative KAT)", () => {
    const d = withdrawAuthDigest(84532n, KAT_VAULT, KAT_OWNER, 0n, -1n, KAT_TO, 1n);
    expect(bytesToHex(d)).toBe(RUST_WITHDRAW_DIGEST_NEG);
  });

  it("rejects malformed inputs instead of hashing garbage", () => {
    expect(() => withdrawAuthDigest(-1n, KAT_VAULT, KAT_OWNER, 0n, 1n, KAT_TO, 1n)).toThrow(/u64/);
    expect(() => withdrawAuthDigest(1n << 64n, KAT_VAULT, KAT_OWNER, 0n, 1n, KAT_TO, 1n)).toThrow(/u64/);
    expect(() => withdrawAuthDigest(84532n, "0x1234", KAT_OWNER, 0n, 1n, KAT_TO, 1n)).toThrow(/20-byte/);
    expect(() => withdrawAuthDigest(84532n, KAT_VAULT, new Uint8Array(31), 0n, 1n, KAT_TO, 1n)).toThrow(/32/);
    expect(() => withdrawAuthDigest(84532n, KAT_VAULT, KAT_OWNER, 0n, 1n << 127n, KAT_TO, 1n)).toThrow(/i128/);
    expect(() => withdrawAuthDigest(84532n, KAT_VAULT, KAT_OWNER, 0n, 1n, "0x1234", 1n)).toThrow(/20-byte/);
    expect(() => withdrawAuthDigest(84532n, KAT_VAULT, KAT_OWNER, 0n, 1n, KAT_TO, 1n << 64n)).toThrow(/u64/);
  });
});

// ── withdrawals: /v1 PRIMARY (real claimable leaf), demo mirror cosmetic ──────
// SEC-021: the destination is ALWAYS the bound deposit address, and the request
// carries that address's personal_sign over the gateway's withdraw digest.
describe("RealDarkPerpClient.requestWithdrawal", () => {
  it("signs the EXACT gateway digest with the bound address and posts {marketId, amount, to, nonce, signature} — /v1 ONLY, no legacy demo mirror (Task 3: /api/withdraw is unmounted in production)", async () => {
    const client = await bootstrapClient();
    await client.requestWithdrawal(5_000_000n);
    const v1Idx = calls.findIndex((c) => c.path === "/v1/accounts/withdraw");
    expect(v1Idx).toBeGreaterThan(-1);
    expect(calls.some((c) => c.path === "/api/withdraw")).toBe(false);
    expect(calls[v1Idx].body).toEqual({
      marketId: 0, amount: "5000000", to: BOUND, nonce: 1, signature: FAKE_SIG,
    });
    expect(calls[v1Idx].headers["X-Api-Key"]).toBe(ACCT_KEY);

    // The wallet was asked to sign EXACTLY withdraw_auth_digest — with the
    // gateway-served chainId/vault/owner/nonce, never hardcoded ones (the
    // fixture's distinctive 4242/0x3b3b… make a hardcoded 84532/KAT-vault
    // fail here) — as the BOUND address (its key is the authorizing key for
    // server-custody accounts).
    expect(personalSigns.length).toBe(1);
    expect(personalSigns[0].address).toBe(BOUND);
    const expected = withdrawAuthDigest(
      BigInt(CHAIN_ID), VAULT, hexToBytes(OWNER_HEX.slice(2)), 0n, 5_000_000n, BOUND, 1n,
    );
    expect(personalSigns[0].digestHex).toBe("0x" + bytesToHex(expected));
  });

  it("uses nextWithdrawNonce VERBATIM — it is already the next acceptable nonce (never +1 again)", async () => {
    meFields = { ...defaultMeFields(), nextWithdrawNonce: 7 };
    const client = await bootstrapClient();
    await client.requestWithdrawal(5_000_000n);
    const v1 = calls.find((c) => c.path === "/v1/accounts/withdraw");
    expect((v1!.body as { nonce: number }).nonce).toBe(7);
    const expected = withdrawAuthDigest(
      BigInt(CHAIN_ID), VAULT, hexToBytes(OWNER_HEX.slice(2)), 0n, 5_000_000n, BOUND, 7n,
    );
    expect(personalSigns[0].digestHex).toBe("0x" + bytesToHex(expected));
  });

  it("refuses to withdraw when no deposit address is bound — nothing signed, nothing submitted", async () => {
    meFields = { ...defaultMeFields(), depositAddress: null };
    const client = await bootstrapClient();
    await expect(client.requestWithdrawal(5_000_000n)).rejects.toThrow(/Bind a deposit address/);
    expect(calls.some((c) => c.path === "/v1/accounts/withdraw")).toBe(false);
    expect(personalSigns.length).toBe(0);
  });

  it("refuses a caller-signed account instead of producing a signature the gateway rejects", async () => {
    meFields = { ...defaultMeFields(), callerSigned: true };
    const client = await bootstrapClient();
    await expect(client.requestWithdrawal(5_000_000n)).rejects.toThrow(/caller-signed/i);
    expect(calls.some((c) => c.path === "/v1/accounts/withdraw")).toBe(false);
    expect(personalSigns.length).toBe(0);
  });

  it("refuses when the gateway does not serve the SEC-021 fields (too old) — never signs a guessed digest", async () => {
    meFields = {}; // an old gateway: only `owner` comes back
    const client = await bootstrapClient();
    await expect(client.requestWithdrawal(5_000_000n)).rejects.toThrow(/SEC-021|gateway too old/i);
    expect(calls.some((c) => c.path === "/v1/accounts/withdraw")).toBe(false);
    expect(personalSigns.length).toBe(0);
  });

  it("surfaces a /v1 rejection — no silent fallback (demo cannot mint a claimable leaf)", async () => {
    const client = await bootstrapClient();
    v1WithdrawStatus = 400;
    await expect(client.requestWithdrawal(5_000_000n)).rejects.toThrow(/exceeds the SETTLED/i);
    expect(calls.some((c) => c.path === "/api/withdraw")).toBe(false);
  });

  it("withdrawAuthInfo exposes the bound address + callerSigned for the UI gate", async () => {
    const client = await bootstrapClient();
    await expect(client.withdrawAuthInfo()).resolves.toEqual({ depositAddress: BOUND, callerSigned: false });
    meFields = { ...defaultMeFields(), depositAddress: null };
    await expect(client.withdrawAuthInfo()).resolves.toEqual({ depositAddress: null, callerSigned: false });
  });
});

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
    await client.requestWithdrawal(1_000_000n);
    const v1 = calls.find((c) => c.path === "/v1/accounts/withdraw");
    expect((v1!.body as { marketId: number }).marketId).toBe(1);
    // the signed digest binds the SELECTED market too
    const expected = withdrawAuthDigest(
      BigInt(CHAIN_ID), VAULT, hexToBytes(OWNER_HEX.slice(2)), 1n, 1_000_000n, BOUND, 1n,
    );
    expect(personalSigns[0].digestHex).toBe("0x" + bytesToHex(expected));
    client.dispose();
  });
});

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

// ── SEC-025-E1: authenticated own-account reads (orders + positions) ─────────
// The browser must show the CALLER's /v1 account, not the shared demo wallet the
// public /api/state feed serves. The fixtures make the two accounts differ in
// every distinguishing field (see their definition above) so nothing passes by
// coincidence.
describe("own-account reads from /v1 (SEC-025-E1)", () => {
  /**
   * A macrotask barrier: setTimeout(0) fires only after the ENTIRE pending
   * microtask queue (including chains each microtask enqueues) has drained, so
   * one await here means every purely-microtask fetch chain — the mock is
   * all-microtask — has fully completed. Quiescence, not a guessed tick count.
   */
  const macrotask = () => new Promise<void>((r) => setTimeout(r, 0));

  beforeEach(() => {
    stateResponse = demoState;
    v1OrdersResponse = { orders: [v1Order] };
    v1PositionsResponse = { positions: [v1Position] };
  });

  it("bootstrap shows the CALLER's /v1 orders, positions AND balance, never the demo wallet's", async () => {
    const client = await bootstrapClient();
    const st = client.getState();
    expect(st.orders.map((o) => o.id)).toEqual(["o42"]);
    expect(st.orders.some((o) => o.id === "demo-1")).toBe(false);
    expect(st.account.positions.length).toBe(1);
    expect(st.account.positions[0].marketId).toBe(1);
    expect(st.account.positions[0].size).toBe(-25_000_000n);
    // demo-wallet position (long BTC on market 0) must NOT leak through
    expect(st.account.positions.some((p) => p.marketId === 0)).toBe(false);
    // The balance beside those positions is the SAME account's — the demo
    // wallet's 123000000 rendered here would hand OrderTicket.maxOrderSize a
    // stranger's collateral. V1_BALANCE is unreachable from the demo fixtures.
    expect(st.account.settledBalance).toBe(987_654_321_777n);
    // all three reads hit AUTHENTICATED /v1 endpoints under the account's key
    const reads = calls.filter(
      (c) => (c.path === "/v1/orders" || c.path === "/v1/positions") && c.method === "GET",
    );
    expect(reads.length).toBe(2);
    for (const r of reads) expect(r.headers["X-Api-Key"]).toBe(ACCT_KEY);
    const meReads = calls.filter((c) => c.path === "/v1/accounts/me" && c.method === "GET");
    expect(meReads.length).toBe(1); // the balance read (fresh registration fetches /me no other way)
    expect(meReads[0].headers["X-Api-Key"]).toBe(ACCT_KEY);
    client.dispose();
  });

  it("maps the flat /v1 order into the nested TrackedOrder (bigints; receipt = exactly the four domain fields)", async () => {
    const client = await bootstrapClient();
    // toEqual is strict on extra keys: this dies if the wire receipt (which
    // carries windowId) is passed through instead of mapped field-by-field.
    expect(client.getState().orders[0]).toEqual({
      id: "o42",
      input: {
        marketId: 1, side: "Sell", size: 250_000_000n, limitPrice: 352_000_000_000n,
        tif: "Fok", reduceOnly: true,
      },
      receipt: { orderHash: "0x" + "a1".repeat(32), seqNo: 5, recvTimeMs: 5001, batchIdHint: 3 },
      finality: "ACCEPTED",
      filledSize: 0n,
      avgFillPrice: 0n,
      createdMs: 5000,
    });
    client.dispose();
  });

  it("a later demo-wallet WS frame does NOT clobber the caller's own orders/positions/balance", async () => {
    const client = await bootstrapClient();
    lastWs!.onmessage!({ data: JSON.stringify({ type: "state", state: demoState }) });
    const st = client.getState();
    expect(st.orders.map((o) => o.id)).toEqual(["o42"]);
    expect(st.account.positions[0].marketId).toBe(1);
    expect(st.account.settledBalance).toBe(987_654_321_777n); // not the frame's 123000000
    client.dispose();
  });

  it("degrades to the legacy feed when no /v1 account can be provisioned — never throws", async () => {
    accountsStatus = 500;
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const client = await bootstrapClient(); // must resolve, not reject
    // Discriminate on the MESSAGE: prepareSealing also fails and warns here
    // ("sealed-order setup failed…"), so a bare toHaveBeenCalled() would pass
    // even if refreshOwnState's own catch never ran.
    expect(warn).toHaveBeenCalledWith(
      expect.stringContaining("own-account read failed"),
      expect.anything(),
    );
    const st = client.getState();
    // no key ⇒ the /v1 reads are impossible; the legacy feed falls through.
    // This is the ONE case the public feed may stand in (review F1): no /v1
    // account exists, so there is no "right account" to show instead — and
    // accordingly the view is NOT flagged unavailable.
    expect(st.orders.map((o) => o.id)).toEqual(["demo-1"]);
    expect(st.accountUnavailable).toBe(false);
    expect(calls.some((c) => c.path === "/v1/orders" && c.method === "GET")).toBe(false);
    client.dispose();
  });

  it("a failed balance read shows the EMPTY unavailable placeholder — never the demo wallet, never a mixed account", async () => {
    // /v1/accounts/me stops serving settledBalance while orders + positions
    // still read fine. The /v1 account EXISTS here, so the demo feed must NOT
    // stand in for it (review F1): a demo balance would hand
    // OrderTicket.maxOrderSize a stranger's collateral, and demo ORDER ROWS
    // would render actionable — ids collide across accounts (`o{nonce}`), so
    // clicking Cancel on the demo row's "o42" would cancel the caller's own
    // unseen "o42". The WHOLE view degrades to the empty placeholder plus
    // `accountUnavailable`, so the UI can say "unreadable", never "zero".
    const { settledBalance: _dropped, ...noBalance } = defaultMeFields();
    meFields = noBalance;
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const client = await bootstrapClient();
    const st = client.getState();
    expect(st.account.settledBalance).toBe(0n); // not the demo 123000000
    expect(st.account.positions).toEqual([]); // not the demo long-BTC position
    expect(st.orders).toEqual([]); // no actionable demo rows
    expect(st.accountUnavailable).toBe(true); // "unreadable", not "no position"
    expect(warn).toHaveBeenCalledWith(
      expect.stringContaining("own-account read failed"),
      expect.anything(),
    );
    client.dispose();
  });

  it("the unavailable placeholder recovers to the own view once a later read succeeds", async () => {
    const { settledBalance: _dropped, ...noBalance } = defaultMeFields();
    meFields = noBalance;
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const client = await bootstrapClient();
    expect(client.getState().accountUnavailable).toBe(true);
    meFields = defaultMeFields(); // the gateway recovers
    await client.placeOrder({
      marketId: 1, side: "Sell", size: 250_000_000n, limitPrice: 352_000_000_000n,
      tif: "Fok", reduceOnly: true,
    });
    await client.ownStateSettled();
    const st = client.getState();
    expect(st.accountUnavailable).toBe(false);
    expect(st.account.settledBalance).toBe(987_654_321_777n);
    expect(st.orders.map((o) => o.id)).toEqual(["o42"]);
    client.dispose();
  });

  it("the F7 error-branch reset does NOT reopen the demo-feed fallback: /v1 reads down + an `error` auth reply keeps the placeholder + accountUnavailable (fix-wave-2 G1)", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    // The own reads fail from the start (no settledBalance served) while
    // registration itself succeeds — so NO own read has ever landed when the
    // socket refuses the key. This is the F1∩F7 interaction: F7's error
    // branch nulls `sealing`, and a fallback gated on `sealing` alone would
    // then paint the shared demo wallet as the caller's account, unflagged —
    // in exactly the state-wipe cutover F7 was written for.
    const { settledBalance: _dropped, ...noBalance } = defaultMeFields();
    meFields = noBalance;
    stateResponse = demoState; // the public feed is the DEMO wallet — distinguishable
    const client = await bootstrapClient();
    lastWsV1!.open();
    expect(client.getState().accountUnavailable).toBe(true); // the F1 baseline holds pre-error
    lastWsV1!.onmessage!({ data: JSON.stringify({ type: "error", message: "unknown api key" }) });
    // The next public frame re-emits. `sealing` is gone (F7's reset), but an
    // account EXISTS — localStorage still holds it — so the demo wallet must
    // not come back and the view must stay flagged unreadable.
    lastWs!.onmessage!({ data: JSON.stringify({ type: "state", state: demoState }) });
    const st = client.getState();
    expect(st.orders).toEqual([]); // not the demo wallet's actionable rows
    expect(st.account.settledBalance).toBe(0n); // not the demo 123000000
    expect(st.account.positions).toEqual([]); // not the demo long-BTC position
    expect(st.accountUnavailable).toBe(true);
    client.dispose();
  });

  it("a returning browser whose stored key fails revalidation AND whose re-registration fails renders the placeholder — never the demo wallet (fix-wave-2 G1)", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    // A previous session's account sits in localStorage (LS_ACCOUNT_KEY)…
    localStorage.setItem(
      "darkperp.v1Account",
      JSON.stringify({ apiKey: ACCT_KEY, owner: OWNER_HEX }),
    );
    // …but the gateway was wiped AND registration is down: the stored key
    // 401s on revalidation and the re-register POST 500s, so `sealing` never
    // gets set at all this session.
    validKey = ACCT_KEY2;
    accountsStatus = 500;
    stateResponse = demoState;
    const client = await bootstrapClient();
    const st = client.getState();
    // The fresh-browser fallback ("degrades to the legacy feed…" above)
    // applies only when NOTHING is stored — here an account exists, so the
    // public demo feed must not stand in for it.
    expect(st.orders).toEqual([]);
    expect(st.account.settledBalance).toBe(0n);
    expect(st.account.positions).toEqual([]);
    expect(st.accountUnavailable).toBe(true);
    client.dispose();
  });

  it("private mode (localStorage write fails): a provisioned-but-unreadable account still renders the placeholder (G1 — the gate's `sealing` side)", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    // Storage rejects writes (private browsing): registration succeeds and
    // `sealing` is set, but nothing lands in localStorage — the gate's OTHER
    // disjunct. A gate narrowed to the STORED account alone would fall back
    // to the demo feed here.
    vi.spyOn(localStorage, "setItem").mockImplementation(() => {
      throw new Error("private mode");
    });
    const { settledBalance: _dropped, ...noBalance } = defaultMeFields();
    meFields = noBalance; // the own reads fail, the account itself exists
    stateResponse = demoState;
    const client = await bootstrapClient();
    const st = client.getState();
    expect(st.orders).toEqual([]);
    expect(st.account.settledBalance).toBe(0n);
    expect(st.account.positions).toEqual([]);
    expect(st.accountUnavailable).toBe(true);
    client.dispose();
  });

  it("private mode + the F7 error reset: the placeholder still survives — the provisioning latch outlives both erasable gate sources (fix-wave-3 H3)", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    // Storage rejects writes (private browsing): registration succeeds and
    // `sealing` is set, but NOTHING ever lands in localStorage…
    vi.spyOn(localStorage, "setItem").mockImplementation(() => {
      throw new Error("private mode");
    });
    const { settledBalance: _dropped, ...noBalance } = defaultMeFields();
    meFields = noBalance; // no own read ever succeeds
    stateResponse = demoState;
    const client = await bootstrapClient();
    lastWsV1!.open();
    expect(client.getState().accountUnavailable).toBe(true); // the G1 baseline holds pre-error
    // …then the socket refuses the key (the state-wipe cutover F7 was written
    // for) and its error branch nulls `sealing`: BOTH of hasAccount()'s
    // erasable sources are now gone. Only the in-memory `everProvisioned`
    // latch still knows an account was provisioned this session — without it
    // the next public frame repaints the shared demo wallet, unflagged (the
    // exact defect F1 removed).
    lastWsV1!.onmessage!({ data: JSON.stringify({ type: "error", message: "unknown api key" }) });
    lastWs!.onmessage!({ data: JSON.stringify({ type: "state", state: demoState }) });
    const st = client.getState();
    expect(st.orders).toEqual([]); // not the demo wallet's actionable rows
    expect(st.account.settledBalance).toBe(0n); // not the demo 123000000
    expect(st.account.positions).toEqual([]); // not the demo long-BTC position
    expect(st.accountUnavailable).toBe(true);
    client.dispose();
  });

  it("a stored account revalidated OK, then storage cleared mid-session + the F7 reset: the latch still holds the placeholder (fix-wave-3 H3, the initAccount stored path)", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    // A previous session's account revalidates fine (the STORED provisioning
    // path — no fresh registration)…
    localStorage.setItem(
      "darkperp.v1Account",
      JSON.stringify({ apiKey: ACCT_KEY, owner: OWNER_HEX }),
    );
    const { settledBalance: _dropped, ...noBalance } = defaultMeFields();
    meFields = noBalance; // revalidation 200s, the own reads still fail
    stateResponse = demoState;
    const client = await bootstrapClient();
    expect(registrations).toBe(0); // provisioned via the stored path, not POST /v1/accounts
    lastWsV1!.open();
    // …then another tab (or a site-data clear) erases the stored copy AND the
    // auth-error reset nulls `sealing`. A latch set only at the fresh-
    // registration site would miss this session entirely.
    localStorage.clear();
    lastWsV1!.onmessage!({ data: JSON.stringify({ type: "error", message: "unknown api key" }) });
    lastWs!.onmessage!({ data: JSON.stringify({ type: "state", state: demoState }) });
    const st = client.getState();
    expect(st.orders).toEqual([]);
    expect(st.account.settledBalance).toBe(0n);
    expect(st.account.positions).toEqual([]);
    expect(st.accountUnavailable).toBe(true);
    client.dispose();
  });

  it("an order served without a receipt (older gateway) degrades to a synthesized stub receipt", async () => {
    const { receipt: _dropped, ...noReceipt } = v1Order;
    v1OrdersResponse = { orders: [noReceipt] };
    const client = await bootstrapClient();
    expect(client.getState().orders[0].receipt).toEqual({
      orderHash: "0x" + "a1".repeat(32), // from the flat orderHash field
      seqNo: 0,
      recvTimeMs: 5000, // createdMs — the closest honest stand-in
      batchIdHint: 0,
    });
    client.dispose();
  });

  it("placeOrder refreshes the own-account view (the legacy stream can't carry it)", async () => {
    const client = await bootstrapClient();
    expect(client.getState().orders.map((o) => o.id)).toEqual(["o42"]);
    const newOrder = {
      ...v1Order, orderId: "o43", orderHash: "0x" + "b2".repeat(32),
      receipt: { ...v1Order.receipt, orderHash: "0x" + "b2".repeat(32), seqNo: 6 },
    };
    v1OrdersResponse = { orders: [newOrder, v1Order] };
    await client.placeOrder({
      marketId: 1, side: "Sell", size: 250_000_000n, limitPrice: 352_000_000_000n,
      tif: "Fok", reduceOnly: true,
    });
    // placeOrder kicked the refresh off fire-and-forget BEFORE resolving, so its
    // in-flight promise is already exposed — await it, don't count ticks.
    await client.ownStateSettled();
    expect(client.getState().orders.map((o) => o.id)).toEqual(["o43", "o42"]);
    client.dispose();
  });

  it("requestWithdrawal refreshes the own view — the post-debit balance lands (review F4)", async () => {
    const client = await bootstrapClient();
    expect(client.getState().account.settledBalance).toBe(987_654_321_777n);
    // The gateway's balance moves exactly WHEN the withdraw POST lands (the
    // harness hook), so a refresh issued before the mutation cannot see it.
    // 444333222111 is producible by NO pre-mutation fixture (not the demo
    // 123000000, not V1_BALANCE): only a re-read AFTER the POST can show it.
    afterWithdrawPost = () => {
      meFields = { ...defaultMeFields(), settledBalance: "444333222111" };
    };
    await client.requestWithdrawal(5_000_000n);
    await client.ownStateSettled();
    await macrotask();
    // No /v1/ws event announces a withdrawal (the gateway's events_tx carries
    // exactly fill/order/adl) — without requestWithdrawal's own refresh this
    // stays 987654321777 until an unrelated fill.
    expect(client.getState().account.settledBalance).toBe(444_333_222_111n);
    client.dispose();
  });

  it("creditOnchainDeposit refreshes the own view — the credited balance lands (review F4)", async () => {
    const client = await bootstrapClient();
    expect(client.getState().account.settledBalance).toBe(987_654_321_777n);
    afterOnchainPost = () => {
      meFields = { ...defaultMeFields(), settledBalance: "555666777888" };
    };
    const credited = await client.creditOnchainDeposit("0x" + "ff".repeat(32));
    expect(credited).toBe(1_000_000n);
    await client.ownStateSettled();
    await macrotask();
    // Same reasoning as the withdrawal test: no event announces a deposit.
    expect(client.getState().account.settledBalance).toBe(555_666_777_888n);
    client.dispose();
  });

  it("no emitted frame EVER mixes accounts — balance and positions land atomically", async () => {
    // Settled-state asserts can't catch a two-phase write (positions emitted,
    // balance patched in later): every frame between them is a mixed account on
    // screen. Record every emission and require each one to be entirely the /v1
    // account or entirely the demo wallet.
    const client = await bootstrapClient();
    const frames: string[] = [];
    client.subscribe((s) =>
      frames.push(`${s.account.settledBalance}|${s.account.positions.map((p) => p.marketId).join(",")}`),
    );
    lastWs!.onmessage!({ data: JSON.stringify({ type: "state", state: demoState }) }); // interleaved demo push
    await client.placeOrder({
      marketId: 1, side: "Sell", size: 250_000_000n, limitPrice: 352_000_000_000n,
      tif: "Fok", reduceOnly: true,
    });
    await client.ownStateSettled();
    await macrotask();
    expect(frames.length).toBeGreaterThan(0);
    for (const f of frames) {
      // Every frame is the OWN account whole (V1_BALANCE with the /v1
      // short-ETH position) — never a hybrid, and (review F1) never the demo
      // wallet: the /v1 account exists for this whole test, so the demo
      // "123000000|0" the pre-fix assertion tolerated must not appear either
      // — an interleaved demo push may only re-emit the own overlay.
      expect(f).toBe("987654321777|1");
    }
    client.dispose();
  });

  it("a slow earlier refresh can never overwrite a fresher one (in-flight guard + trailing re-run)", async () => {
    const client = await bootstrapClient(); // own view settled: ["o42"]
    const mk = (id: string, hex: string, seqNo: number) => ({
      ...v1Order, orderId: id, orderHash: "0x" + hex.repeat(32),
      receipt: { ...v1Order.receipt, orderHash: "0x" + hex.repeat(32), seqNo },
    });
    const o43 = mk("o43", "b2", 6);
    const o44 = mk("o44", "c3", 7);
    // Refresh R1 (first placeOrder) reads the list AS OF its request — [o43,
    // o42] — but delivers it LATE: its GET parks on the one-shot gate.
    let release!: () => void;
    v1OrdersGate = new Promise<void>((r) => { release = r; });
    v1OrdersResponse = { orders: [o43, v1Order] };
    await client.placeOrder({
      marketId: 1, side: "Sell", size: 250_000_000n, limitPrice: 352_000_000_000n,
      tif: "Fok", reduceOnly: true,
    });
    await macrotask(); // R1's GET is now issued and parked on the gate
    // The account moves on: a second order lands and prompts another refresh
    // while R1 is still in flight.
    v1OrdersResponse = { orders: [o44, o43, v1Order] };
    await client.placeOrder({
      marketId: 1, side: "Sell", size: 250_000_000n, limitPrice: 352_000_000_000n,
      tif: "Fok", reduceOnly: true,
    });
    release();
    await client.ownStateSettled(); // guard path: waits for the trailing re-run too
    await macrotask(); // full quiescence — an UN-guarded stale write chain has also run by now
    // The fresher list must win. Without the guard, the second refresh's fast
    // read landed first and R1's stale [o43, o42] then overwrote it, losing o44.
    expect(client.getState().orders.map((o) => o.id)).toEqual(["o44", "o43", "o42"]);
    client.dispose();
  });
});

// ── SEC-025-E1 Task 2: the live stream (/v1/ws) ──────────────────────────────
// The legacy /ws is a public broadcast: every client receives every account's
// event frames (the shared demo wallet's lifecycle) unfiltered. The client now
// treats the legacy stream as PUBLIC STATE ONLY — its event frames are another
// account's and must never reach this client — and takes its own account events
// from the authenticated /v1/ws, whose server filters by owner (and which the
// client re-verifies).
describe("live stream: /v1/ws own-account events (SEC-025-E1 Task 2)", () => {
  /** Macrotask barrier (see the SEC-025-E1 describe above): full microtask quiescence. */
  const macrotask = () => new Promise<void>((r) => setTimeout(r, 0));
  const ownReads = () =>
    calls.filter((c) => (c.path === "/v1/orders" || c.path === "/v1/positions") && c.method === "GET").length;
  /** Open the /v1/ws socket and complete the auth handshake as the gateway would. */
  const openAndAuth = () => {
    lastWsV1!.open();
    lastWsV1!.onmessage!({ data: JSON.stringify({ type: "authOk", owner: OWNER_HEX }) });
  };

  beforeEach(() => {
    stateResponse = demoState;
    v1OrdersResponse = { orders: [v1Order] };
    v1PositionsResponse = { positions: [v1Position] };
  });

  it("a legacy /ws event frame — another account's lifecycle — does NOT reach onOrderEvent", async () => {
    const client = await bootstrapClient();
    const events: OrderEvent[] = [];
    client.onOrderEvent((e) => events.push(e));
    // This event WOULD visibly land if forwarded: a MATCHED transition pops a
    // toast + an Activity row for order demo-1. It is the shared demo wallet's
    // (the legacy stream carries no owner at all — it cannot be attributed to
    // this client), so it must be dropped.
    lastWs!.onmessage!({
      data: JSON.stringify({
        type: "event",
        event: { orderId: "demo-1", kind: "MATCHED", message: "Matched (soft preconfirmation) — not yet withdrawable" },
      }),
    });
    expect(events).toEqual([]);
    client.dispose();
  });

  it("connects to /v1/ws and authenticates with the account's api key once the socket opens — never before", async () => {
    const client = await bootstrapClient();
    expect(lastWsV1).toBeTruthy();
    expect(lastWsV1!.sent).toEqual([]); // nothing until the socket is OPEN
    lastWsV1!.open();
    expect(lastWsV1!.sent.map((s) => JSON.parse(s))).toEqual([{ type: "auth", apiKey: ACCT_KEY }]);
    client.dispose();
  });

  it("an own-account order event refreshes the /v1 view AND surfaces the toast", async () => {
    const client = await bootstrapClient();
    const events: OrderEvent[] = [];
    client.onOrderEvent((e) => events.push(e));
    openAndAuth();
    await client.ownStateSettled();
    await macrotask();
    expect(client.getState().orders[0].finality).toBe("ACCEPTED");
    // The account moves server-side: o42 matches. The stream announces it and
    // the refresh must pick up the new finality + fill values.
    v1OrdersResponse = {
      orders: [{ ...v1Order, finality: "MATCHED", filledSize: "250000000", avgFillPrice: "352000000000" }],
    };
    lastWsV1!.onmessage!({
      data: JSON.stringify({ owner: OWNER_HEX, type: "order", orderId: "o42", finality: "MATCHED", marketId: 1 }),
    });
    await client.ownStateSettled();
    await macrotask();
    const st = client.getState();
    expect(st.orders[0].finality).toBe("MATCHED");
    expect(st.orders[0].filledSize).toBe(250_000_000n);
    expect(events).toEqual([
      { orderId: "o42", kind: "MATCHED", message: expect.stringMatching(/matched/i) },
    ]);
    client.dispose();
  });

  it("authOk triggers a refresh, so activity missed while unauthenticated is recovered", async () => {
    const client = await bootstrapClient(); // own view settled: o42 ACCEPTED
    // The order matched while the stream was still unauthenticated — no event
    // was ever delivered for it. The auth handshake must start the view current
    // rather than waiting for the NEXT transition.
    v1OrdersResponse = { orders: [{ ...v1Order, finality: "MATCHED" }] };
    openAndAuth();
    await client.ownStateSettled();
    await macrotask();
    expect(client.getState().orders[0].finality).toBe("MATCHED");
    client.dispose();
  });

  it("an event for ANOTHER owner is dropped: no toast, no refresh, no state change", async () => {
    const client = await bootstrapClient();
    const events: OrderEvent[] = [];
    client.onOrderEvent((e) => events.push(e));
    openAndAuth();
    await client.ownStateSettled();
    await macrotask();
    const readsBefore = ownReads();
    // Discriminating fixture: if this event LANDED, all three assertions below
    // would flip — the refresh would read the new MATCHED list, and the toast
    // would fire. (The server already filters by owner; this pins the client's
    // own re-verification so a confused/hostile stream still can't cross accounts.)
    v1OrdersResponse = { orders: [{ ...v1Order, finality: "MATCHED" }] };
    lastWsV1!.onmessage!({
      data: JSON.stringify({ owner: "0x" + "99".repeat(32), type: "order", orderId: "o42", finality: "MATCHED", marketId: 1 }),
    });
    await client.ownStateSettled();
    await macrotask();
    expect(events).toEqual([]);
    expect(client.getState().orders[0].finality).toBe("ACCEPTED"); // NOT refreshed to MATCHED
    expect(ownReads()).toBe(readsBefore);
    client.dispose();
  });

  it("pre-key window: with no /v1 account the stream degrades to public-only — no auth, no throw", async () => {
    accountsStatus = 500; // registration fails ⇒ no api key exists
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const client = await bootstrapClient(); // must resolve, not reject
    lastWsV1!.open(); // opening with nothing to authenticate with is fine
    expect(lastWsV1!.sent).toEqual([]);
    // The public markets frame /v1/ws sends unauthenticated connections is
    // handled without touching state (the legacy /ws stays the base-state
    // source — it alone carries mode/batches/l1/settlement/lp/…).
    const before = client.getState();
    lastWsV1!.onmessage!({
      data: JSON.stringify({
        type: "markets",
        markets: [{ id: 0, symbol: "BTC/USDC", price: "1", book: { marketId: 0, bids: [], asks: [] } }],
        tsMs: 1,
      }),
    });
    expect(client.getState()).toBe(before); // same reference — nothing emitted
    // An account event pushed anyway (an unauthenticated server never would) is
    // dropped safely: no /v1 reads are even possible without a key.
    lastWsV1!.onmessage!({
      data: JSON.stringify({ owner: OWNER_HEX, type: "order", orderId: "o42", finality: "MATCHED", marketId: 1 }),
    });
    await macrotask();
    expect(ownReads()).toBe(0);
    client.dispose();
  });

  it("authenticates LATE: an account provisioned after the socket opened still auths the stream", async () => {
    accountsStatus = 500;
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const client = await bootstrapClient();
    lastWsV1!.open();
    expect(lastWsV1!.sent).toEqual([]); // pre-key: nothing to send yet
    accountsStatus = 200; // the gateway recovers; the next order provisions the account
    await client.placeOrder({ marketId: 0, side: "Buy", size: 1n, limitPrice: 1n, tif: "Gtc", reduceOnly: false });
    expect(lastWsV1!.sent.map((s) => JSON.parse(s))).toEqual([{ type: "auth", apiKey: ACCT_KEY }]);
    client.dispose();
  });

  it("an own adl event surfaces an ADL toast and refreshes the /v1 view", async () => {
    const client = await bootstrapClient();
    const events: OrderEvent[] = [];
    client.onOrderEvent((e) => events.push(e));
    openAndAuth();
    await client.ownStateSettled();
    await macrotask();
    const readsBefore = ownReads();
    lastWsV1!.onmessage!({ data: JSON.stringify({ owner: OWNER_HEX, type: "adl", clawed: "12" }) });
    await client.ownStateSettled();
    await macrotask();
    expect(events.length).toBe(1);
    expect(events[0].kind).toBe("ADL");
    expect(events[0].message).toContain("12");
    expect(ownReads()).toBeGreaterThan(readsBefore); // the haircut moved the balance — re-read
    client.dispose();
  });

  it("a fill event refreshes but does NOT toast (its paired order event carries the toast)", async () => {
    const client = await bootstrapClient();
    const events: OrderEvent[] = [];
    client.onOrderEvent((e) => events.push(e));
    openAndAuth();
    await client.ownStateSettled();
    await macrotask();
    const readsBefore = ownReads();
    // The gateway pushes a fill AND an order event for the same transition —
    // toasting both would double-notify every fill.
    lastWsV1!.onmessage!({
      data: JSON.stringify({
        owner: OWNER_HEX, type: "fill", orderId: "o42", marketId: 1, side: "Sell",
        size: "250000000", price: "352000000000",
      }),
    });
    await client.ownStateSettled();
    await macrotask();
    expect(events).toEqual([]);
    expect(ownReads()).toBeGreaterThan(readsBefore);
    client.dispose();
  });

  it("reconnects /v1/ws after a drop and re-authenticates on the NEW socket", async () => {
    const client = await bootstrapClient();
    lastWsV1!.open();
    expect(lastWsV1!.sent.length).toBe(1);
    const first = lastWsV1!;
    vi.useFakeTimers();
    first.onclose!(); // the server dropped us
    vi.advanceTimersByTime(1600);
    vi.useRealTimers();
    expect(lastWsV1).not.toBe(first); // a fresh socket, not the dead one
    lastWsV1!.open();
    // auth is per-connection: the new socket must be authenticated again
    expect(lastWsV1!.sent.map((s) => JSON.parse(s))).toEqual([{ type: "auth", apiKey: ACCT_KEY }]);
    client.dispose();
  });

  it("an `error` auth reply un-wedges: the dead account is dropped, the next use re-registers and re-auths the SAME socket (review F7)", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const client = await bootstrapClient();
    lastWsV1!.open();
    expect(lastWsV1!.sent.length).toBe(1); // auth with the (about-to-die) key
    // The deployment wiped state.snap (the runbook does, on every cutover):
    // the old key is now unknown everywhere and a fresh registration hands
    // out a NEW key.
    validKey = ACCT_KEY2;
    lastWsV1!.onmessage!({ data: JSON.stringify({ type: "error", message: "unknown api key" }) });
    // Next use must NOT serve the dead cached account: ensureAccount
    // revalidates the stored key (401 now), re-registers, and the fresh
    // account re-auths THIS socket — without the fix `v1AuthSent` stays true
    // (no second auth frame, ever) and `sealing` keeps the dead key (no
    // second registration, every /v1 read 401s for the tab's lifetime).
    await client.placeOrder({ marketId: 0, side: "Buy", size: 1n, limitPrice: 1n, tif: "Gtc", reduceOnly: false });
    expect(registrations).toBe(2);
    expect(lastWsV1!.sent.map((s) => JSON.parse(s))).toEqual([
      { type: "auth", apiKey: ACCT_KEY },
      { type: "auth", apiKey: ACCT_KEY2 },
    ]);
    // the order itself went out under the NEW key
    expect(ordersPosted()[0].headers["X-Api-Key"]).toBe(ACCT_KEY2);
    client.dispose();
  });

  it("an authOk naming a DIFFERENT owner is refused — the stream stays unauthenticated (review F8)", async () => {
    const client = await bootstrapClient();
    const events: OrderEvent[] = [];
    client.onOrderEvent((e) => events.push(e));
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    lastWsV1!.open();
    const readsBefore = ownReads();
    // A confused/hostile server confirms auth but names a stranger's owner.
    // Storing that echo and then "verifying" events against it would compare
    // the server to itself — the client must instead check the claim against
    // the owner IT holds from registration, and refuse the mismatch.
    const stranger = "0x" + "99".repeat(32);
    lastWsV1!.onmessage!({ data: JSON.stringify({ type: "authOk", owner: stranger }) });
    await client.ownStateSettled();
    await macrotask();
    expect(ownReads()).toBe(readsBefore); // no authOk refresh for a mismatch
    expect(warn).toHaveBeenCalledWith(
      expect.stringContaining("authOk owner mismatch"),
      expect.anything(),
    );
    // …and the stranger's events do NOT land: had the echo been trusted,
    // this frame would refresh the view to MATCHED and pop a toast.
    v1OrdersResponse = { orders: [{ ...v1Order, finality: "MATCHED" }] };
    lastWsV1!.onmessage!({
      data: JSON.stringify({ owner: stranger, type: "order", orderId: "o42", finality: "MATCHED", marketId: 1 }),
    });
    await client.ownStateSettled();
    await macrotask();
    expect(events).toEqual([]);
    expect(client.getState().orders[0].finality).toBe("ACCEPTED");
    client.dispose();
  });
});

// ── SEC-025-E1 Task 3: cancel is caller-scoped; the demo mutation surface is gone ──
//
// The hazard the cancel re-route closes is CROSS-ACCOUNT, not just a 404:
// order ids are `format!("o{nonce}")` in BOTH the /v1 account path and the
// demo wallet (gateway main.rs) — per-account, NOT globally unique — and the
// legacy `POST /api/cancel` resolves the id against the DEMO WALLET's own
// list. After Task 1 the UI renders the CALLER's /v1 ids, so on a demo
// gateway a user cancelling their "o42" would silently cancel the demo
// wallet's "o42" (if one existed, ACCEPTED) and be told it succeeded.
describe("cancelOrder is caller-scoped: DELETE /v1/orders/:id (SEC-025-E1 Task 3)", () => {
  beforeEach(() => {
    // THE DISCRIMINATING FIXTURE: both lists hold an order with the SAME id.
    // Without this collision the test proves nothing about targeting — a
    // demo-list resolver would just 404 and fail for the wrong reason. Here
    // the harness's /api/cancel ANSWERS SUCCESS (the demo wallet has "o42"),
    // so a mis-routed cancel completes "successfully" and only the targeting
    // assertions can catch it.
    stateResponse = {
      ...demoState,
      orders: [{ ...demoOrder, id: "o42" }], // the DEMO wallet's own "o42"
    };
    v1OrdersResponse = { orders: [v1Order] }; // the CALLER's "o42"
    v1PositionsResponse = { positions: [v1Position] };
  });

  it("cancels the CALLER's order via the authenticated per-account route — never the demo wallet's same-named order", async () => {
    const client = await bootstrapClient();
    const events: OrderEvent[] = [];
    client.onOrderEvent((e) => events.push(e));
    v1OrdersResponse = { orders: [] }; // the post-cancel read: the order is gone
    await client.cancelOrder("o42");
    // the one cancel request is the caller-scoped DELETE, under the api key
    const dels = calls.filter((c) => c.method === "DELETE");
    expect(dels.map((c) => c.path)).toEqual(["/v1/orders/o42"]);
    expect(dels[0].headers["X-Api-Key"]).toBe(ACCT_KEY);
    // and the demo-wallet resolver was never touched (it would have answered
    // success for ITS "o42" — the silent cross-account mutation)
    expect(calls.some((c) => c.path === "/api/cancel")).toBe(false);
    // cancel's real producer: the CANCELLED lifecycle event (Toaster/Activity)
    expect(events).toEqual([
      { orderId: "o42", kind: "CANCELLED", message: expect.stringMatching(/cancelled/i) },
    ]);
    // the own-account view refreshed — the cancelled order left the list
    await client.ownStateSettled();
    expect(client.getState().orders.some((o) => o.id === "o42")).toBe(false);
    client.dispose();
  });

  it("SURFACES the gateway's refusal — including the `sealed` refusal every resting order hits until E2 — instead of reporting success", async () => {
    const client = await bootstrapClient();
    const events: OrderEvent[] = [];
    client.onOrderEvent((e) => events.push(e));
    v1CancelStatus = 400;
    // The gateway's exact wording must reach the caller: `account_cancel`
    // refuses any sealed order, and every order seals within one ~700ms tick,
    // so this refusal is the EXPECTED production answer for resting orders
    // until E2 lands cancel-inside-the-window. Unsatisfying, but honest —
    // swallowing it is the defect this task removes.
    await expect(client.cancelOrder("o42")).rejects.toThrow(
      /Only an ACCEPTED order can be cancelled/,
    );
    expect(events).toEqual([]); // no CANCELLED event for a refused cancel
    client.dispose();
  });

  it("exposes NO demo mutation surface — the production router does not mount those routes", async () => {
    // closePosition/simulateAdl/triggerCloseOnly/resumeNormal/recover had no
    // production transport (their /api/* routes 404 there) and three of them
    // reported that failure as success. They are DELETED from the real client
    // — not stubbed — so the UI presence-gates honestly (the wallet-methods
    // idiom). A resurrected no-op stub would resolve silently — the exact
    // report-failure-as-success defect — and fails these absence pins.
    const client = await bootstrapClient();
    for (const m of ["closePosition", "simulateAdl", "triggerCloseOnly", "resumeNormal", "recover"]) {
      expect((client as unknown as Record<string, unknown>)[m], m).toBeUndefined();
    }
    client.dispose();
  });
});

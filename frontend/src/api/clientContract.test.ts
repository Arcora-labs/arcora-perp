// @vitest-environment happy-dom
//
// SEC-025-E1 Task 4 — ONE shared contract fixture BOTH clients must satisfy.
//
// Why one fixture: mock and gateway used to fabricate the same wrong numbers,
// so mock-pinned UI tests could never catch the real client drifting (that is
// how the E1 finding survived — the two sides were "consistently wrong
// together"). This suite drives the SAME scenario through MockDarkPerpClient
// and RealDarkPerpClient (each behind a thin transport adapter), collects the
// OBSERVED surface with the SAME collector code, and compares both
// observations against the SINGLE `EXPECTED` literal below. Two hand-written
// expectation sets is exactly how the clients drifted apart; there is one.
//
// What is deliberately PINNED AS FABRICATED (do not "fix" it here): at MATCHED
// both clients report a full fill at the limit price — the mock at its
// advance-to-matched step, the gateway at its account-order finality pass
// (crates/gateway/src/main.rs:4347-4367 — the only account-event emitter;
// `o.filled = o.order.size; o.avg_fill = o.order.limit_price` inside it).
// Honest execution reporting is SEC-025-E3's task, IN
// BOTH PLACES AT ONCE — when E3 lands, the `matched` leg of EXPECTED changes
// once and both clients must move together. A mock that reported honestly
// while the gateway still fabricates would be a new divergence, not a fix.
//
// What is deliberately PINNED AS REFUSED: cancelling a SEALED order — every
// order seals into the next batch within one gateway tick (TICK_MS = 700), and
// `account_cancel` refuses sealed orders even while their finality is still
// ACCEPTED (main.rs:3195-3198 — the `sealed || last_finality != "ACCEPTED"`
// predicate and the verbatim refusal string EXPECTED pins below).
// Cancel-inside-the-window is SEC-025-E2; until then the refusal IS
// the production answer for resting orders, and the mock must give the same
// answer instead of pinning an always-succeeds contract the gateway does not
// honor. (Pre-seal cancel succeeds — the gateway honors that window too.)
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { secp256k1 } from "@noble/curves/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";
import { bytesToHex } from "@noble/hashes/utils";
import { x25519KeypairFromIkm } from "./sealedBox";
import { RealDarkPerpClient, epochSigningDigest } from "./realClient";
import { MockDarkPerpClient } from "./mockClient";
import type { DarkPerpClient, OrderEvent } from "./client";
import type { OrderInput, Receipt, TrackedOrder } from "../domain/types";
import { PRICE_SCALE, SIZE_SCALE } from "../domain/types";

// ── the ONE shared scenario ──────────────────────────────────────────────────
const LIMIT = 100_000n * PRICE_SCALE;
const SCENARIO = {
  /** The order both clients place, match, and settle. */
  order: {
    marketId: 0, side: "Buy", size: SIZE_SCALE, limitPrice: LIMIT,
    tif: "Gtc", reduceOnly: false,
  } as OrderInput,
  /** Smaller orders for the two cancel legs (so the mock's buying-power guard
   *  never gates the scenario — margin is not what this suite pins). */
  cancelOrder: {
    marketId: 0, side: "Buy", size: SIZE_SCALE / 10n, limitPrice: LIMIT,
    tif: "Gtc", reduceOnly: false,
  } as OrderInput,
  /** ADL haircut in WHOLE dollars — the gateway's adl event sends
   *  `clawed/QUOTE_SCALE` as a string; the mock's demo cascade claws the same. */
  adlClawedWhole: "1975",
};

// ── the ONE shared fixture ───────────────────────────────────────────────────
// Key sets are SORTED; `orderReceiptKeys` is EXACTLY the domain Receipt — the
// live gateway's WReceipt carries an extra `windowId` on the wire, and the real
// client must STRIP it when mapping /v1/orders into TrackedOrder (pV1Order maps
// field-by-field; a spread pass-through fails this pin). `forPlacedOrder`
// asserts the event's orderId is the order the scenario placed.
const EXPECTED = {
  receiptFieldTypes: {
    orderHash: "string", seqNo: "number", recvTimeMs: "number", batchIdHint: "number",
  },
  accepted: {
    orderKeys: ["avgFillPrice", "createdMs", "filledSize", "finality", "id", "input", "receipt"],
    inputKeys: ["limitPrice", "marketId", "reduceOnly", "side", "size", "tif"],
    receiptKeys: ["batchIdHint", "orderHash", "recvTimeMs", "seqNo"],
    orderFieldTypes: {
      id: "string", finality: "string", filledSize: "bigint",
      avgFillPrice: "bigint", createdMs: "number",
    },
    inputEcho: {
      marketId: 0, side: "Buy", size: SIZE_SCALE.toString(),
      limitPrice: LIMIT.toString(), tif: "Gtc", reduceOnly: false,
    },
    finality: "ACCEPTED", filledSize: "0", avgFillPrice: "0",
  },
  acceptedEvent: { kind: "ACCEPTED", message: "Order accepted", forPlacedOrder: true },
  // The SHARED FABRICATION (SEC-025-E3 changes this leg, in both clients at once).
  matched: {
    finality: "MATCHED",
    filledSize: SIZE_SCALE.toString(),
    avgFillPrice: LIMIT.toString(),
  },
  matchedEvent: {
    kind: "MATCHED",
    message: "Matched (soft preconfirmation) — not yet withdrawable",
    forPlacedOrder: true,
  },
  settled: { finality: "SETTLED" },
  settledEvent: { kind: "SETTLED", message: "Settled on L1 — withdrawable", forPlacedOrder: true },
  // Sealed-but-still-ACCEPTED cancel: REFUSED, verbatim gateway wording, order
  // untouched, no CANCELLED event. (The E2 gap, pinned honestly.)
  sealedCancel: {
    outcome: "refused",
    message: "Only an ACCEPTED order can be cancelled (matched/settled are binding).",
    stillListed: true,
    stillFinality: "ACCEPTED",
    sawCancelledEvent: false,
  },
  // Pre-seal cancel: the window the gateway DOES honor.
  freshCancel: {
    outcome: "resolved",
    gone: true,
    cancelledEvent: { kind: "CANCELLED", message: "Order cancelled before matching", forPlacedOrder: true },
  },
  adlEvent: {
    orderId: "adl",
    kind: "ADL",
    message: `Auto-deleveraged: $${SCENARIO.adlClawedWhole} of your winning position was clawed to cover a counterparty's bad debt.`,
  },
  // Review F3: `settledBalancePositive` is the discrimination the shape alone
  // lacks — the branch's headline regression (reading account state off the
  // PUBLIC feed) still satisfies keys/types, because the demo-wallet fixture
  // has the same shape. Both harnesses serve "0" publicly while the caller's
  // own account is funded in both worlds (mock: 25_000 USDC at construction,
  // mockClient.ts; real: /v1/accounts/me serves "50000000000" below), so a
  // client that regressed to the public feed observes `false` here and dies.
  accountShape: {
    keys: ["positions", "settledBalance"],
    settledBalanceType: "bigint",
    positionsIsArray: true,
    settledBalancePositive: true,
  },
};

type Observation = typeof EXPECTED;

// ── the shared collector (identical code observes both clients) ──────────────

const typeOf = (v: unknown) => typeof v;
const pick = <T extends object>(o: T, keys: (keyof T)[]) =>
  Object.fromEntries(keys.map((k) => [k, typeOf(o[k])]));

function observeAccepted(o: TrackedOrder): Observation["accepted"] {
  return {
    orderKeys: Object.keys(o).sort(),
    inputKeys: Object.keys(o.input).sort(),
    receiptKeys: Object.keys(o.receipt).sort(),
    orderFieldTypes: pick(o, ["id", "finality", "filledSize", "avgFillPrice", "createdMs"]) as Observation["accepted"]["orderFieldTypes"],
    inputEcho: {
      marketId: o.input.marketId, side: o.input.side, size: o.input.size.toString(),
      limitPrice: o.input.limitPrice.toString(), tif: o.input.tif, reduceOnly: o.input.reduceOnly,
    },
    finality: o.finality, filledSize: o.filledSize.toString(), avgFillPrice: o.avgFillPrice.toString(),
  };
}

function observeEvent(e: OrderEvent | undefined, placedId: string) {
  if (!e) return { kind: "<none>", message: "<none>", forPlacedOrder: false };
  return { kind: e.kind, message: e.message, forPlacedOrder: e.orderId === placedId };
}

/**
 * Transport adapter — ONLY the mechanics of driving each client (timers for the
 * mock, harness responses + stream frames for the real client). Everything
 * observed and asserted lives in `runScenario`, which is shared.
 */
interface Driver {
  client: DarkPerpClient;
  /** Place an order; resolve with the receipt and the client-visible order id. */
  place(input: OrderInput): Promise<{ receipt: Receipt; id: string }>;
  /** The gateway announces the order ACCEPTED (mock: emitted at place). */
  announceAccepted(id: string): Promise<void>;
  /** The order matches server-side (with the CURRENT fabricated fill values). */
  driveMatched(id: string): Promise<void>;
  /** The order settles server-side. */
  driveSettled(id: string): Promise<void>;
  /** One tick passes: the RESTING order seals into a batch (finality unchanged). */
  sealResting(id: string): Promise<void>;
  /** The account takes an ADL haircut of SCENARIO.adlClawedWhole dollars. */
  driveAdl(): Promise<void>;
  /** Quiesce: all in-flight view refreshes applied. */
  settle(): Promise<void>;
}

async function runScenario(d: Driver): Promise<Observation> {
  const events: OrderEvent[] = [];
  d.client.onOrderEvent((e) => events.push(e));
  let mark = 0;
  const newEvents = () => { const s = events.slice(mark); mark = events.length; return s; };
  const orderById = (id: string) => d.client.getState().orders.find((o) => o.id === id);

  // 1) place → ACCEPTED
  const { receipt, id } = await d.place(SCENARIO.order);
  await d.announceAccepted(id);
  await d.settle();
  const acceptedOrder = orderById(id);
  if (!acceptedOrder) throw new Error("scenario: placed order not in getState().orders");
  const accepted = observeAccepted(acceptedOrder);
  const acceptedEvent = observeEvent(newEvents().find((e) => e.kind === "ACCEPTED"), id);
  const account = d.client.getState().account;
  const accountShape = {
    keys: Object.keys(account).sort(),
    settledBalanceType: typeOf(account.settledBalance),
    positionsIsArray: Array.isArray(account.positions),
    // F3: discriminates own-account (funded, > 0) from the public feed's "0".
    settledBalancePositive: account.settledBalance > 0n,
  };

  // 2) MATCHED — the shared fabrication (see header; E3 changes this in both).
  await d.driveMatched(id);
  await d.settle();
  const m = orderById(id)!;
  const matched = { finality: m.finality, filledSize: m.filledSize.toString(), avgFillPrice: m.avgFillPrice.toString() };
  const matchedEvent = observeEvent(newEvents().find((e) => e.kind === "MATCHED"), id);

  // 3) SETTLED
  await d.driveSettled(id);
  await d.settle();
  const settled = { finality: orderById(id)!.finality };
  const settledEvent = observeEvent(newEvents().find((e) => e.kind === "SETTLED"), id);

  // 4) cancel a SEALED (still-ACCEPTED) resting order → the E2-gap refusal
  const { id: restingId } = await d.place(SCENARIO.cancelOrder);
  await d.settle();
  await d.sealResting(restingId);
  newEvents(); // discard this leg's placement events; only CANCELLED is pinned
  let sealedOutcome: { outcome: string; message: string | null };
  try {
    await d.client.cancelOrder(restingId);
    sealedOutcome = { outcome: "resolved", message: null };
  } catch (e) {
    sealedOutcome = { outcome: "refused", message: e instanceof Error ? e.message : String(e) };
  }
  await d.settle();
  const sealedCancel = {
    ...sealedOutcome,
    stillListed: orderById(restingId) !== undefined,
    stillFinality: orderById(restingId)?.finality ?? "<gone>",
    sawCancelledEvent: newEvents().some((e) => e.kind === "CANCELLED"),
  };

  // 5) cancel a FRESH (pre-seal) order → the honored window
  const { id: freshId } = await d.place(SCENARIO.cancelOrder);
  await d.settle();
  newEvents();
  let freshOutcome = "resolved";
  try {
    await d.client.cancelOrder(freshId);
  } catch {
    freshOutcome = "refused";
  }
  await d.settle();
  const freshCancel = {
    outcome: freshOutcome,
    gone: orderById(freshId) === undefined,
    cancelledEvent: observeEvent(newEvents().find((e) => e.kind === "CANCELLED"), freshId),
  };

  // 6) ADL haircut
  await d.driveAdl();
  await d.settle();
  const adlRaw = newEvents().find((e) => e.kind === "ADL");
  const adlEvent = adlRaw
    ? { orderId: adlRaw.orderId, kind: adlRaw.kind, message: adlRaw.message }
    : { orderId: "<none>", kind: "<none>", message: "<none>" };

  return {
    receiptFieldTypes: pick(receipt, ["orderHash", "seqNo", "recvTimeMs", "batchIdHint"]) as Observation["receiptFieldTypes"],
    accepted, acceptedEvent, matched, matchedEvent, settled, settledEvent,
    sealedCancel: sealedCancel as Observation["sealedCancel"],
    freshCancel: freshCancel as Observation["freshCancel"],
    adlEvent, accountShape,
  };
}

// ── mock driver: fake timers stand in for the gateway's tick ─────────────────
// The mock's seal moment mirrors the gateway's TICK_MS=700 (< the 900ms match
// step, so the sealed-but-still-ACCEPTED state exists in both worlds).
const MOCK_SEAL_MS = 700;
const MOCK_MATCH_MS = 900;
const MOCK_SETTLE_MS = 4500;

function mockDriver(): Driver {
  const client = new MockDarkPerpClient();
  return {
    client,
    async place(input) {
      const receipt = await client.placeOrder(input);
      return { receipt, id: client.getState().orders[0].id };
    },
    async announceAccepted() { /* the mock emits ACCEPTED at place */ },
    async driveMatched() { await vi.advanceTimersByTimeAsync(MOCK_MATCH_MS); },
    async driveSettled() { await vi.advanceTimersByTimeAsync(MOCK_SETTLE_MS - MOCK_MATCH_MS); },
    async sealResting() { await vi.advanceTimersByTimeAsync(MOCK_SEAL_MS); },
    async driveAdl() { await client.simulateAdl!(); },
    async settle() { /* the mock is synchronous */ },
  };
}

// ── real driver: a gateway-model harness (fetch + WS stubs) ──────────────────
// The stubs model the REAL gateway's documented behavior at each step —
// including its fabricated fills and its sealed-cancel refusal — so the client
// code under test is the production RealDarkPerpClient end to end.

const ENCLAVE_SK = new Uint8Array(32).fill(7);
const ENCLAVE_ADDR =
  "0x" + bytesToHex(keccak_256(secp256k1.getPublicKey(ENCLAVE_SK, false).subarray(1)).subarray(12));
const epochKp = x25519KeypairFromIkm(
  new Uint8Array(32).fill(5),
  new Uint8Array([25, 1, 0, 0, 0, 0, 0, 0, 0]),
);
const MEASUREMENT = "0x" + "ab".repeat(32);
const ACCT_KEY = "0x" + "11".repeat(32);
const OWNER_HEX = "0x" + "22".repeat(32);

function signedEpoch() {
  const epochId = 1;
  const notAfterMs = Date.now() + 86_400_000;
  const digest = epochSigningDigest(BigInt(epochId), epochKp.public, BigInt(notAfterMs));
  const sg = secp256k1.sign(digest, ENCLAVE_SK);
  const sig65 = new Uint8Array(65);
  sig65.set(sg.toCompactRawBytes(), 0);
  sig65[64] = sg.recovery + 27;
  return {
    epochId, x25519Pub: "0x" + bytesToHex(epochKp.public), notAfterMs,
    measurement: MEASUREMENT, sig: "0x" + bytesToHex(sig65),
  };
}

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

/** One flat /v1 order as `v1_orders_json` serves it (receipt = WReceipt, i.e.
 *  WITH the extra `windowId` the domain Receipt does not carry). */
interface SrvOrder {
  orderId: string; marketId: number; side: string; size: string; limitPrice: string;
  tif: string; reduceOnly: boolean; orderHash: string; finality: string;
  filledSize: string; avgFillPrice: string; createdMs: number;
  receipt: { orderHash: string; seqNo: number; recvTimeMs: number; batchIdHint: number; windowId: number };
}

interface GatewayModel {
  orders: SrvOrder[];
  sealed: Set<string>;
  pendingInput: OrderInput | null;
  n: number;
}

function installRealHarness(gw: GatewayModel) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: unknown, init?: { method?: string; headers?: Record<string, string>; body?: string }) => {
      const path = new URL(String(input)).pathname;
      const method = init?.method ?? "GET";
      const json = (v: unknown, status = 200) => ({
        ok: status < 400, status,
        json: async () => v,
        text: async () => JSON.stringify(v),
      });
      if (path === "/api/state") return json(wireState);
      if (path === "/v1/enclave/epoch") return json(signedEpoch());
      if (path === "/v1/accounts" && method === "POST") {
        return json({ apiKey: ACCT_KEY, owner: OWNER_HEX, callerSigned: false });
      }
      if (path === "/v1/accounts/me") {
        if (init?.headers?.["X-Api-Key"] !== ACCT_KEY) return json({ error: "unknown account" }, 401);
        return json({
          owner: OWNER_HEX, settledBalance: "50000000000", depositAddress: null,
          callerSigned: false, nextWithdrawNonce: 1, rebindCounter: 0, chainId: 4242,
          vault: "0x" + "3b".repeat(20),
        });
      }
      if (path === "/v1/orders" && method === "POST") {
        // The sealed body is opaque to the harness; the driver parked the input.
        const inp = gw.pendingInput;
        if (!inp) throw new Error("harness: POST /v1/orders with no pending input");
        gw.pendingInput = null;
        const n = ++gw.n;
        const receipt = {
          orderHash: "0x" + n.toString(16).padStart(64, "0"),
          seqNo: n, recvTimeMs: 1000 + n, batchIdHint: 1,
          windowId: 3, // WReceipt's extra wire field — the domain Receipt has no windowId
        };
        gw.orders.unshift({
          orderId: `o${n}`, marketId: inp.marketId, side: inp.side,
          size: inp.size.toString(), limitPrice: inp.limitPrice.toString(),
          tif: inp.tif, reduceOnly: inp.reduceOnly, orderHash: receipt.orderHash,
          finality: "ACCEPTED", filledSize: "0", avgFillPrice: "0", createdMs: 1000 + n,
          receipt,
        });
        return json(receipt);
      }
      if (path === "/v1/orders" && method === "GET") {
        if (init?.headers?.["X-Api-Key"] !== ACCT_KEY) return json({ error: "unknown account" }, 401);
        return json({ orders: gw.orders });
      }
      if (path === "/v1/positions" && method === "GET") {
        if (init?.headers?.["X-Api-Key"] !== ACCT_KEY) return json({ error: "unknown account" }, 401);
        return json({ positions: [] });
      }
      if (path.startsWith("/v1/orders/") && method === "DELETE") {
        if (init?.headers?.["X-Api-Key"] !== ACCT_KEY) return json({ error: "unknown account" }, 401);
        const id = decodeURIComponent(path.slice("/v1/orders/".length));
        const idx = gw.orders.findIndex((o) => o.orderId === id);
        if (idx === -1) return json({ error: "Order not found." }, 400);
        // `account_cancel` (main.rs:3195-3198): sealed OR non-ACCEPTED ⇒ the
        // verbatim refusal string pinned in EXPECTED.sealedCancel.
        if (gw.sealed.has(id) || gw.orders[idx].finality !== "ACCEPTED") {
          return json(
            { error: "Only an ACCEPTED order can be cancelled (matched/settled are binding)." },
            400,
          );
        }
        gw.orders.splice(idx, 1);
        return json({ orderId: id, cancelled: true });
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
  constructor(readonly url: string) {
    if (url.includes("/v1/ws")) lastWsV1 = this;
  }
  send(data: string) { this.sent.push(data); }
  close() {}
  open() { this.readyState = 1; this.onopen?.(); }
}

const macrotask = () => new Promise<void>((r) => setTimeout(r, 0));

async function realDriver(): Promise<Driver & { dispose(): void }> {
  const gw: GatewayModel = { orders: [], sealed: new Set(), pendingInput: null, n: 0 };
  installRealHarness(gw);
  vi.stubGlobal("WebSocket", FakeWebSocket);
  vi.stubEnv("VITE_ENCLAVE_SIGNER", ENCLAVE_ADDR);
  vi.stubEnv("VITE_ENCLAVE_MEASUREMENT", MEASUREMENT);
  const client = await RealDarkPerpClient.bootstrap("http://gw.test");
  // Authenticate the account stream, as the gateway would.
  lastWsV1!.open();
  lastWsV1!.onmessage!({ data: JSON.stringify({ type: "authOk", owner: OWNER_HEX }) });
  await client.ownStateSettled();
  await macrotask();
  const srv = (id: string) => {
    const o = gw.orders.find((x) => x.orderId === id);
    if (!o) throw new Error(`harness: no server order ${id}`);
    return o;
  };
  const push = (frame: Record<string, unknown>) =>
    lastWsV1!.onmessage!({ data: JSON.stringify({ owner: OWNER_HEX, ...frame }) });
  const settle = async () => { await client.ownStateSettled(); await macrotask(); };
  return {
    client,
    async place(input) {
      gw.pendingInput = input;
      const receipt = await client.placeOrder(input);
      await settle();
      return { receipt, id: `o${gw.n}` };
    },
    async announceAccepted(id) {
      // Review F2: this frame models a MATCHED→ACCEPTED DOWNGRADE (a
      // rollback/replay), NOT the accept path. The gateway never pushes
      // finality:"ACCEPTED" for a newly accepted order — orders are created
      // ACCEPTED (main.rs:3181) and the only emitter fires on a transition
      // (main.rs:4347-4367, `if f != o.last_finality`), so the first
      // evaluation pushes nothing. On the real client the placement-time
      // acceptance signal is placeOrder's resolved receipt; only the MOCK
      // produces an ACCEPTED event at placement.
      push({ type: "order", orderId: id, finality: "ACCEPTED", marketId: srv(id).marketId });
      await settle();
    },
    async driveMatched(id) {
      // The gateway's account-order finality pass (main.rs:4347-4367): full
      // fill AT THE LIMIT — the SEC-025-E3 fabrication, modeled where the
      // gateway performs it.
      const o = srv(id);
      o.finality = "MATCHED";
      o.filledSize = o.size;
      o.avgFillPrice = o.limitPrice;
      push({ type: "fill", orderId: id, marketId: o.marketId, side: o.side, size: o.size, price: o.limitPrice });
      push({ type: "order", orderId: id, finality: "MATCHED", marketId: o.marketId });
      await settle();
    },
    async driveSettled(id) {
      const o = srv(id);
      o.finality = "SETTLED";
      push({ type: "order", orderId: id, finality: "SETTLED", marketId: o.marketId });
      await settle();
    },
    async sealResting(id) {
      // One TICK_MS elapses: the seal loop marks every resting order sealed
      // (finality still ACCEPTED — matching is a separate step).
      gw.sealed.add(id);
    },
    async driveAdl() {
      push({ type: "adl", clawed: SCENARIO.adlClawedWhole });
      await settle();
    },
    settle,
    dispose() { client.dispose(); },
  };
}

// ── the suite ────────────────────────────────────────────────────────────────

describe("shared client contract (SEC-025-E1 Task 4): one fixture, both clients", () => {
  beforeEach(() => {
    lastWsV1 = null;
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.unstubAllEnvs();
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  it("MockDarkPerpClient satisfies the shared fixture", async () => {
    vi.useFakeTimers();
    const d = mockDriver();
    const observed = await runScenario(d);
    expect(observed).toEqual(EXPECTED);
  });

  it("RealDarkPerpClient satisfies the shared fixture", async () => {
    const d = await realDriver();
    try {
      const observed = await runScenario(d);
      expect(observed).toEqual(EXPECTED);
    } finally {
      d.dispose();
    }
  });
});

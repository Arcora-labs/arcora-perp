// Real client — talks to the `gateway` crate (axum HTTP + WebSocket) which holds the
// live Rust protocol engine. It implements the SAME `DarkPerpClient` interface the
// mock does, so swapping it in (see store.tsx, gated on VITE_API_URL) changes nothing
// else in the UI.
//
// Wire format: every fixed-point amount (i128 in Rust) is carried as a DECIMAL STRING
// in JSON — JSON numbers can't hold i128 precisely — and parsed back to bigint here, so
// the UI keeps doing exact bigint money math. State arrives both as a GET /api/state
// snapshot (initial) and as live pushes over the WebSocket.

import type { DarkPerpClient, ClientState, OrderEvent } from "./client";
import type {
  AccountState, BatchSummary, BookLevel, Market, OracleQuote, OrderBookSnapshot,
  OrderInput, Position, RecoveredNote, Receipt, TrackedOrder,
} from "../domain/types";
import { QUOTE_SCALE } from "../domain/types";

// ── wire types (bigints as strings) ──────────────────────────────────────────
interface WireBookLevel { price: string; size: string }
interface WireOracle { marketId: number; price: string; confidence: string; publishTimeMs: number }
interface WireMarket {
  id: number; symbol: string; maxLeverage: number; maintenanceMarginRatio: number;
  initialMarginRatio: number; referencePrice: string; live: boolean;
  takerFeeBps: number; makerRebateBps: number;
}
interface WirePosition {
  marketId: number; size: string; entryPrice: string; collateral: string;
  unrealizedPnl: string; liquidationPrice: string;
}
interface WireOrderInput { marketId: number; side: "Buy" | "Sell"; size: string; limitPrice: string; tif: string; reduceOnly: boolean }
interface WireTrackedOrder {
  id: string; input: WireOrderInput; receipt: Receipt; finality: TrackedOrder["finality"];
  filledSize: string; avgFillPrice: string; createdMs: number;
}
interface WireState {
  markets: WireMarket[]; selectedMarketId: number; market: WireMarket; mode: ClientState["mode"];
  oracle: WireOracle; book: { marketId: number; bids: WireBookLevel[]; asks: WireBookLevel[] };
  marks: Record<string, string>; account: { settledBalance: string; positions: WirePosition[] };
  orders: WireTrackedOrder[]; batches: BatchSummary[]; insuranceFund: string; treasury: string; userAdlClawed: string;
  mmHedge: WireHedge[];
  l1: WireL1 | null;
  attestation: { measurement: string; tcb: string; quoteVersion: number } | null;
}
interface WireHedge {
  marketId: number; symbol: string; inventory: string; hedgeTarget: string; notional: string;
}
interface WireL1 {
  settledRoot: string; batchCount: number; lastTx: string; bondUsdc: string; withdrawalsRoot: string;
}

const B = (s: string): bigint => BigInt(s);

function pMarket(m: WireMarket): Market {
  return { ...m, referencePrice: B(m.referencePrice) };
}
function pOracle(o: WireOracle): OracleQuote {
  return { marketId: o.marketId, price: B(o.price), confidence: B(o.confidence), publishTimeMs: o.publishTimeMs };
}
function pLevel(l: WireBookLevel): BookLevel {
  return { price: B(l.price), size: B(l.size) };
}
function pBook(b: WireState["book"]): OrderBookSnapshot {
  return { marketId: b.marketId, bids: b.bids.map(pLevel), asks: b.asks.map(pLevel) };
}
function pPosition(p: WirePosition): Position {
  return {
    marketId: p.marketId, size: B(p.size), entryPrice: B(p.entryPrice), collateral: B(p.collateral),
    unrealizedPnl: B(p.unrealizedPnl), liquidationPrice: B(p.liquidationPrice),
  };
}
function pOrder(o: WireTrackedOrder): TrackedOrder {
  return {
    id: o.id,
    input: { ...o.input, side: o.input.side, size: B(o.input.size), limitPrice: B(o.input.limitPrice), tif: o.input.tif as OrderInput["tif"] },
    receipt: o.receipt, finality: o.finality, filledSize: B(o.filledSize), avgFillPrice: B(o.avgFillPrice), createdMs: o.createdMs,
  };
}
function pAccount(a: WireState["account"]): AccountState {
  return { settledBalance: B(a.settledBalance), positions: a.positions.map(pPosition) };
}
function parseState(w: WireState): ClientState {
  const marks: Record<number, bigint> = {};
  for (const [k, v] of Object.entries(w.marks)) marks[Number(k)] = B(v);
  return {
    markets: w.markets.map(pMarket),
    selectedMarketId: w.selectedMarketId,
    market: pMarket(w.market),
    mode: w.mode,
    oracle: pOracle(w.oracle),
    book: pBook(w.book),
    marks,
    account: pAccount(w.account),
    orders: w.orders.map(pOrder),
    batches: w.batches,
    insuranceFund: B(w.insuranceFund),
    treasury: B(w.treasury),
    userAdlClawed: B(w.userAdlClawed),
    mmHedge: w.mmHedge.map((h) => ({
      marketId: h.marketId,
      symbol: h.symbol,
      inventory: B(h.inventory),
      hedgeTarget: B(h.hedgeTarget),
      notional: B(h.notional),
    })),
    l1: w.l1
      ? {
          settledRoot: w.l1.settledRoot,
          batchCount: w.l1.batchCount,
          lastTx: w.l1.lastTx,
          bondUsdc: B(w.l1.bondUsdc),
          withdrawalsRoot: w.l1.withdrawalsRoot,
        }
      : null,
    attestation: w.attestation,
  };
}

const s = (v: bigint) => v.toString();

export class RealDarkPerpClient implements DarkPerpClient {
  private base: string;
  private wsUrl: string;
  private state: ClientState | null = null;
  private subs = new Set<(s: ClientState) => void>();
  private eventSubs = new Set<(e: OrderEvent) => void>();
  private ws: WebSocket | null = null;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;

  constructor(baseUrl: string, initial: ClientState) {
    this.base = baseUrl.replace(/\/$/, "");
    this.wsUrl = this.base.replace(/^http/, "ws") + "/ws";
    this.state = initial;
    this.connect();
  }

  /** One blocking fetch of the initial snapshot so the store has a non-null first state. */
  static async bootstrap(baseUrl: string): Promise<RealDarkPerpClient> {
    const base = baseUrl.replace(/\/$/, "");
    const res = await fetch(base + "/api/state");
    if (!res.ok) throw new Error(`gateway /api/state ${res.status}`);
    const initial = parseState((await res.json()) as WireState);
    return new RealDarkPerpClient(base, initial);
  }

  private connect() {
    try {
      if (this.ws) { try { this.ws.close(); } catch { /* noop */ } }
      this.ws = new WebSocket(this.wsUrl);
      this.ws.onmessage = (ev) => {
        try {
          const msg = JSON.parse(ev.data as string) as
            | { type: "state"; state: WireState }
            | { type: "event"; event: OrderEvent };
          if (msg.type === "state") {
            this.state = parseState(msg.state);
            for (const cb of this.subs) cb(this.state);
          } else if (msg.type === "event") {
            for (const cb of this.eventSubs) cb(msg.event);
          }
        } catch { /* ignore malformed frame */ }
      };
      this.ws.onclose = () => { this.scheduleReconnect(); };
      this.ws.onerror = () => { try { this.ws?.close(); } catch { /* noop */ } };
    } catch {
      this.scheduleReconnect();
    }
  }

  private scheduleReconnect() {
    if (this.reconnectTimer) return;
    this.reconnectTimer = setTimeout(() => { this.reconnectTimer = null; this.connect(); }, 1500);
  }

  private async post<T>(path: string, body: unknown): Promise<T> {
    const res = await fetch(this.base + path, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body ?? {}),
    });
    const text = await res.text();
    const json = text ? JSON.parse(text) : null;
    if (!res.ok) throw new Error(json?.error ?? `${path} failed (${res.status})`);
    return json as T;
  }

  getState(): ClientState {
    if (!this.state) throw new Error("RealDarkPerpClient used before bootstrap");
    return this.state;
  }
  subscribe(cb: (s: ClientState) => void): () => void { this.subs.add(cb); return () => this.subs.delete(cb); }
  onOrderEvent(cb: (e: OrderEvent) => void): () => void { this.eventSubs.add(cb); return () => this.eventSubs.delete(cb); }

  async placeOrder(input: OrderInput): Promise<Receipt> {
    return this.post<Receipt>("/api/order", {
      marketId: input.marketId, side: input.side, size: s(input.size),
      limitPrice: s(input.limitPrice), tif: input.tif, reduceOnly: input.reduceOnly,
    });
  }
  async deposit(amountQuote: bigint): Promise<void> { await this.post("/api/deposit", { amount: s(amountQuote) }); }
  async requestWithdrawal(amountQuote: bigint): Promise<void> { await this.post("/api/withdraw", { amount: s(amountQuote) }); }
  triggerCloseOnly(): void { void this.post("/api/mode", { mode: "CloseOnly" }); }
  resumeNormal(): void { void this.post("/api/mode", { mode: "Normal" }); }
  async simulateAdl(): Promise<bigint> {
    const r = await this.post<{ clawed: string }>("/api/simulate-adl", {});
    return B(r.clawed) * QUOTE_SCALE; // gateway returns whole USD; scale to quote
  }
  async closePosition(marketId: number): Promise<void> { await this.post("/api/close", { marketId }); }
  async cancelOrder(orderId: string): Promise<void> { await this.post("/api/cancel", { orderId }); }
  selectMarket(marketId: number): void { void this.post("/api/select-market", { marketId }); }
  async recover(seedHex: string): Promise<RecoveredNote[]> {
    const notes = await this.post<{ batchId: number; amount: string; spent: boolean }[]>("/api/recover", { seed: seedHex });
    return notes.map((n) => ({ batchId: n.batchId, amount: B(n.amount), spent: n.spent }));
  }
}

export type { WireState };

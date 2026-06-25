// In-memory mock that encodes the protocol's observable semantics so the UI is
// faithful before any backend exists. Now multi-market (BTC-PERP, ETH-PERP),
// matching the protocol's per-MarketId state. Fidelity points unchanged:
//   • every order returns a signed-style receipt immediately (ACCEPTED, §2)
//   • finality advances ACCEPTED → MATCHED → SETTLED, only SETTLED is withdrawable
//   • close-only blocks opening/increasing (§6)
//   • the book is seeded by an internal market-maker (§15)

import type { DarkPerpClient, ClientState, OrderEvent } from "./client";
import {
  PRICE_SCALE,
  QUOTE_SCALE,
  SIZE_SCALE,
  type Market,
  type OracleQuote,
  type OrderBookSnapshot,
  type OrderInput,
  type RecoveredNote,
  type Receipt,
  type TrackedOrder,
} from "../domain/types";

const MATCH_DELAY_MS = 900;
const SETTLE_DELAY_MS = 4500;

interface MarketData {
  market: Market;
  oracle: OracleQuote;
  book: OrderBookSnapshot;
}

let counter = 0;
function pseudoHash(seed: string): string {
  let h = 0xcbf29ce484222325n;
  for (const ch of seed) {
    h ^= BigInt(ch.charCodeAt(0));
    h = (h * 0x100000001b3n) & ((1n << 256n) - 1n);
  }
  return "0x" + h.toString(16).padStart(64, "0");
}

function bookAround(marketId: number, mid: bigint): OrderBookSnapshot {
  const mk = (off: bigint) => mid + off;
  const step = mid / 5000n; // ~0.02% ticks
  return {
    marketId,
    bids: [
      { price: mk(-2n * step), size: SIZE_SCALE / 2n },
      { price: mk(-4n * step), size: SIZE_SCALE },
      { price: mk(-10n * step), size: 2n * SIZE_SCALE },
      { price: mk(-18n * step), size: 3n * SIZE_SCALE },
    ],
    asks: [
      { price: mk(2n * step), size: SIZE_SCALE / 2n },
      { price: mk(4n * step), size: SIZE_SCALE },
      { price: mk(10n * step), size: 2n * SIZE_SCALE },
      { price: mk(18n * step), size: 3n * SIZE_SCALE },
    ],
  };
}

function makeMarket(id: number, symbol: string, priceUsd: bigint): MarketData {
  const market: Market = {
    id,
    symbol,
    maxLeverage: 10,
    maintenanceMarginRatio: 0.05,
    initialMarginRatio: 0.1,
  };
  const price = priceUsd * PRICE_SCALE;
  const oracle: OracleQuote = { marketId: id, price, confidence: price / 10000n, publishTimeMs: Date.now() };
  return { market, oracle, book: bookAround(id, price) };
}

export class MockDarkPerpClient implements DarkPerpClient {
  private data = new Map<number, MarketData>();
  private selectedMarketId = 0;
  private state: ClientState;
  private subs = new Set<(s: ClientState) => void>();
  private eventSubs = new Set<(e: OrderEvent) => void>();

  constructor() {
    this.data.set(0, makeMarket(0, "BTC-PERP", 100_000n));
    this.data.set(1, makeMarket(1, "ETH-PERP", 3_000n));
    this.state = this.snapshot([]);
    if (typeof globalThis.setInterval === "function") {
      globalThis.setInterval(() => this.priceTick(), 1500);
    }
  }

  private priceOf(marketId: number): bigint {
    return this.data.get(marketId)!.oracle.price;
  }

  private snapshot(orders: TrackedOrder[]): ClientState {
    const md = this.data.get(this.selectedMarketId)!;
    return {
      markets: [...this.data.values()].map((d) => d.market),
      selectedMarketId: this.selectedMarketId,
      market: md.market,
      mode: this.state?.mode ?? "Normal",
      oracle: md.oracle,
      book: md.book,
      account: this.state?.account ?? { settledBalance: 25_000n * QUOTE_SCALE, positions: [] },
      orders,
    };
  }

  getState(): ClientState {
    return this.state;
  }

  subscribe(cb: (s: ClientState) => void): () => void {
    this.subs.add(cb);
    return () => this.subs.delete(cb);
  }

  private emit() {
    this.state = this.snapshot(this.state.orders);
    for (const cb of this.subs) cb(this.state);
  }

  onOrderEvent(cb: (e: OrderEvent) => void): () => void {
    this.eventSubs.add(cb);
    return () => this.eventSubs.delete(cb);
  }

  private emitEvent(e: OrderEvent) {
    for (const cb of this.eventSubs) cb(e);
  }

  selectMarket(marketId: number): void {
    if (this.data.has(marketId)) {
      this.selectedMarketId = marketId;
      this.emit();
    }
  }

  private priceTick() {
    for (const md of this.data.values()) {
      const p = md.oracle.price;
      const baseline = md.market.symbol === "BTC-PERP" ? 100_000n * PRICE_SCALE : 3_000n * PRICE_SCALE;
      const drift = (baseline - p) / 400n;
      const noise = BigInt(Math.floor((Math.random() - 0.5) * 160)) * (p / 100000n);
      const next = p + drift + noise;
      md.oracle = { ...md.oracle, price: next, publishTimeMs: Date.now() };
      md.book = bookAround(md.market.id, next);
    }
    // re-mark every position against ITS market's price
    this.state.account = {
      ...this.state.account,
      positions: this.state.account.positions.map((pos) => ({
        ...pos,
        unrealizedPnl: this.pnl(pos.size, pos.entryPrice, this.priceOf(pos.marketId)),
      })),
    };
    this.emit();
  }

  async placeOrder(input: OrderInput): Promise<Receipt> {
    const opening = this.isOpening(input);
    if (this.state.mode === "CloseOnly" && opening) {
      throw new Error("System is in close-only mode — opening/increasing is blocked (§6).");
    }
    const id = `o${++counter}`;
    const orderHash = pseudoHash(id + JSON.stringify(input, (_k, v) => (typeof v === "bigint" ? v.toString() : v)));
    const receipt: Receipt = { orderHash, seqNo: counter, recvTimeMs: Date.now(), batchIdHint: Math.floor(counter / 4) };
    const order: TrackedOrder = {
      id,
      input,
      receipt,
      finality: "ACCEPTED",
      filledSize: 0n,
      avgFillPrice: 0n,
      createdMs: Date.now(),
    };
    this.state = this.snapshot([order, ...this.state.orders]);
    this.emit();
    this.emitEvent({ orderId: id, kind: "ACCEPTED", message: `Order accepted — receipt #${receipt.seqNo}` });
    setTimeout(() => this.advanceToMatched(id), MATCH_DELAY_MS);
    setTimeout(() => this.advanceToSettled(id), SETTLE_DELAY_MS);
    return receipt;
  }

  private advanceToMatched(id: string) {
    const o = this.state.orders.find((x) => x.id === id);
    if (!o || o.finality !== "ACCEPTED") return;
    const fillPrice = o.input.limitPrice === 0n ? this.priceOf(o.input.marketId) : o.input.limitPrice;
    o.finality = "MATCHED";
    o.filledSize = o.input.size;
    o.avgFillPrice = fillPrice;
    this.applyFillToPosition(o);
    this.state = this.snapshot([...this.state.orders]);
    this.emit();
    this.emitEvent({ orderId: id, kind: "MATCHED", message: "Matched (soft preconfirmation) — not yet withdrawable" });
  }

  private advanceToSettled(id: string) {
    const o = this.state.orders.find((x) => x.id === id);
    if (!o || o.finality !== "MATCHED") return;
    o.finality = "SETTLED";
    this.state = this.snapshot([...this.state.orders]);
    this.emit();
    this.emitEvent({ orderId: id, kind: "SETTLED", message: "Settled on L1 — withdrawable" });
  }

  private isOpening(input: OrderInput): boolean {
    const pos = this.state.account.positions.find((p) => p.marketId === input.marketId);
    if (!pos || pos.size === 0n) return true;
    const signed = input.side === "Buy" ? input.size : -input.size;
    return (pos.size > 0n) === (signed > 0n);
  }

  private applyFillToPosition(o: TrackedOrder) {
    const signed = o.input.side === "Buy" ? o.filledSize : -o.filledSize;
    const positions = [...this.state.account.positions];
    const idx = positions.findIndex((p) => p.marketId === o.input.marketId);
    if (idx === -1) {
      positions.push({
        marketId: o.input.marketId,
        size: signed,
        entryPrice: o.avgFillPrice,
        collateral: this.requiredMargin(o.filledSize, o.avgFillPrice),
        unrealizedPnl: 0n,
        liquidationPrice: this.liqPrice(signed, o.avgFillPrice),
      });
    } else {
      const p = positions[idx];
      const newSize = p.size + signed;
      if (newSize === 0n) {
        positions.splice(idx, 1);
      } else {
        const increasing = (p.size > 0n) === (signed > 0n);
        const entry = increasing
          ? (p.entryPrice * abs(p.size) + o.avgFillPrice * abs(signed)) / (abs(p.size) + abs(signed))
          : p.entryPrice;
        positions[idx] = { ...p, size: newSize, entryPrice: entry, liquidationPrice: this.liqPrice(newSize, entry) };
      }
    }
    this.state.account = {
      ...this.state.account,
      positions: positions.map((p) => ({ ...p, unrealizedPnl: this.pnl(p.size, p.entryPrice, this.priceOf(p.marketId)) })),
    };
  }

  private requiredMargin(size: bigint, price: bigint): bigint {
    const notional = (size * price) / ((SIZE_SCALE * PRICE_SCALE) / QUOTE_SCALE);
    return notional / 10n;
  }
  private pnl(size: bigint, entry: bigint, mark: bigint): bigint {
    return (size * (mark - entry)) / ((SIZE_SCALE * PRICE_SCALE) / QUOTE_SCALE);
  }
  private liqPrice(size: bigint, entry: bigint): bigint {
    const delta = (entry * 9n) / 100n;
    return size > 0n ? entry - delta : entry + delta;
  }

  async deposit(amountQuote: bigint): Promise<void> {
    if (amountQuote <= 0n) throw new Error("Amount must be positive.");
    this.state.account = { ...this.state.account, settledBalance: this.state.account.settledBalance + amountQuote };
    this.emit();
  }

  async requestWithdrawal(amountQuote: bigint): Promise<void> {
    if (amountQuote <= 0n) throw new Error("Amount must be positive.");
    if (amountQuote > this.state.account.settledBalance) {
      throw new Error("Not withdrawable: amount exceeds SETTLED balance (§3).");
    }
    this.state.account = { ...this.state.account, settledBalance: this.state.account.settledBalance - amountQuote };
    this.emit();
  }

  triggerCloseOnly(): void {
    this.state.mode = "CloseOnly";
    this.emit();
  }

  async closePosition(marketId: number): Promise<void> {
    const pos = this.state.account.positions.find((p) => p.marketId === marketId);
    if (!pos || pos.size === 0n) throw new Error("No open position to close.");
    await this.placeOrder({
      marketId,
      side: pos.size > 0n ? "Sell" : "Buy",
      size: pos.size < 0n ? -pos.size : pos.size,
      limitPrice: 0n,
      tif: "Ioc",
      reduceOnly: true,
    });
  }

  async cancelOrder(orderId: string): Promise<void> {
    const o = this.state.orders.find((x) => x.id === orderId);
    if (!o) throw new Error("Order not found.");
    if (o.finality !== "ACCEPTED") {
      throw new Error("Only an ACCEPTED order can be cancelled (matched/settled are binding).");
    }
    this.state = this.snapshot(this.state.orders.filter((x) => x.id !== orderId));
    this.emit();
    this.emitEvent({ orderId, kind: "CANCELLED", message: "Order cancelled before matching" });
  }

  async recover(seedHex: string): Promise<RecoveredNote[]> {
    const base = pseudoHash("view:" + seedHex);
    const n = (parseInt(base.slice(2, 4), 16) % 3) + 1;
    const notes: RecoveredNote[] = [];
    for (let i = 0; i < n; i++) {
      const amt = BigInt((parseInt(base.slice(4 + i * 2, 6 + i * 2), 16) + 1) * 1000) * QUOTE_SCALE;
      notes.push({ batchId: i, amount: amt, spent: i === n - 1 && n > 1 });
    }
    return notes;
  }
}

function abs(v: bigint): bigint {
  return v < 0n ? -v : v;
}

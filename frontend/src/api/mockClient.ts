// In-memory mock that encodes the protocol's observable semantics so the UI is
// faithful before any backend exists. The important fidelity points:
//   • every order returns a signed-style receipt immediately (ACCEPTED, §2)
//   • finality advances ACCEPTED → MATCHED → SETTLED over time, and only SETTLED
//     is withdrawable (§3)
//   • close-only blocks opening/increasing (§6)
//   • the book is seeded by an internal market-maker (§15)

import type { DarkPerpClient, ClientState, OrderEvent } from "./client";
import {
  PRICE_SCALE,
  QUOTE_SCALE,
  SIZE_SCALE,
  type OrderInput,
  type RecoveredNote,
  type Receipt,
  type TrackedOrder,
} from "../domain/types";

const MATCH_DELAY_MS = 900;
const SETTLE_DELAY_MS = 4500;

let counter = 0;
function pseudoHash(seed: string): string {
  // deterministic non-crypto hash for display only
  let h = 0xcbf29ce484222325n;
  for (const ch of seed) {
    h ^= BigInt(ch.charCodeAt(0));
    h = (h * 0x100000001b3n) & ((1n << 256n) - 1n);
  }
  return "0x" + h.toString(16).padStart(64, "0");
}

function initialState(): ClientState {
  return {
    market: {
      id: 0,
      symbol: "BTC-PERP",
      maxLeverage: 10,
      maintenanceMarginRatio: 0.05,
      initialMarginRatio: 0.1,
    },
    mode: "Normal",
    oracle: {
      marketId: 0,
      price: 100_000n * PRICE_SCALE,
      confidence: 10n * PRICE_SCALE,
      publishTimeMs: Date.now(),
    },
    book: {
      marketId: 0,
      bids: [
        { price: 99_990n * PRICE_SCALE, size: SIZE_SCALE / 2n },
        { price: 99_980n * PRICE_SCALE, size: SIZE_SCALE },
        { price: 99_950n * PRICE_SCALE, size: 2n * SIZE_SCALE },
      ],
      asks: [
        { price: 100_010n * PRICE_SCALE, size: SIZE_SCALE / 2n },
        { price: 100_020n * PRICE_SCALE, size: SIZE_SCALE },
        { price: 100_050n * PRICE_SCALE, size: 2n * SIZE_SCALE },
      ],
    },
    account: { settledBalance: 25_000n * QUOTE_SCALE, positions: [] },
    orders: [],
  };
}

export class MockDarkPerpClient implements DarkPerpClient {
  private state: ClientState = initialState();
  private subs = new Set<(s: ClientState) => void>();
  private eventSubs = new Set<(e: OrderEvent) => void>();
  private tick = 0;

  constructor() {
    // make the market feel alive: random-walk the index price and refresh the
    // book + position marks on a timer.
    if (typeof globalThis.setInterval === "function") {
      globalThis.setInterval(() => this.priceTick(), 1500);
    }
  }

  getState(): ClientState {
    return this.state;
  }

  private priceTick() {
    this.tick++;
    // ±0.08% random walk, with a gentle mean-reversion toward $100k
    const p = this.state.oracle.price;
    const drift = (100_000n * PRICE_SCALE - p) / 400n;
    const noise = BigInt(Math.floor((Math.random() - 0.5) * 160)) * (PRICE_SCALE / 1000n);
    const next = p + drift + noise;
    this.state.oracle = { ...this.state.oracle, price: next, publishTimeMs: Date.now() };
    // re-mark positions
    this.state.account = {
      ...this.state.account,
      positions: this.state.account.positions.map((pos) => ({
        ...pos,
        unrealizedPnl: this.pnl(pos.size, pos.entryPrice, next),
      })),
    };
    // drift the book around the new mid
    const mk = (off: bigint) => next + off;
    this.state.book = {
      marketId: 0,
      bids: [
        { price: mk(-10n * PRICE_SCALE), size: SIZE_SCALE / 2n },
        { price: mk(-20n * PRICE_SCALE), size: SIZE_SCALE },
        { price: mk(-50n * PRICE_SCALE), size: 2n * SIZE_SCALE },
        { price: mk(-90n * PRICE_SCALE), size: 3n * SIZE_SCALE },
      ],
      asks: [
        { price: mk(10n * PRICE_SCALE), size: SIZE_SCALE / 2n },
        { price: mk(20n * PRICE_SCALE), size: SIZE_SCALE },
        { price: mk(50n * PRICE_SCALE), size: 2n * SIZE_SCALE },
        { price: mk(90n * PRICE_SCALE), size: 3n * SIZE_SCALE },
      ],
    };
    this.emit();
  }

  subscribe(cb: (s: ClientState) => void): () => void {
    this.subs.add(cb);
    return () => this.subs.delete(cb);
  }

  private emit() {
    // shallow clone so React sees a new reference
    this.state = { ...this.state };
    for (const cb of this.subs) cb(this.state);
  }

  onOrderEvent(cb: (e: OrderEvent) => void): () => void {
    this.eventSubs.add(cb);
    return () => this.eventSubs.delete(cb);
  }

  private emitEvent(e: OrderEvent) {
    for (const cb of this.eventSubs) cb(e);
  }

  async placeOrder(input: OrderInput): Promise<Receipt> {
    const opening = this.isOpening(input);
    if (this.state.mode === "CloseOnly" && opening) {
      throw new Error("System is in close-only mode — opening/increasing is blocked (§6).");
    }
    const id = `o${++counter}`;
    const orderHash = pseudoHash(id + JSON.stringify(input, (_k, v) => (typeof v === "bigint" ? v.toString() : v)));
    const receipt: Receipt = {
      orderHash,
      seqNo: counter,
      recvTimeMs: Date.now(),
      batchIdHint: Math.floor(counter / 4),
    };
    const order: TrackedOrder = {
      id,
      input,
      receipt,
      finality: "ACCEPTED",
      filledSize: 0n,
      avgFillPrice: 0n,
      createdMs: Date.now(),
    };
    this.state.orders = [order, ...this.state.orders];
    this.emit();
    this.emitEvent({ orderId: id, kind: "ACCEPTED", message: `Order accepted — receipt #${receipt.seqNo}` });

    // ACCEPTED → MATCHED
    setTimeout(() => this.advanceToMatched(id), MATCH_DELAY_MS);
    // MATCHED → SETTLED
    setTimeout(() => this.advanceToSettled(id), SETTLE_DELAY_MS);

    return receipt;
  }

  private advanceToMatched(id: string) {
    const o = this.state.orders.find((x) => x.id === id);
    if (!o || o.finality !== "ACCEPTED") return; // cancelled orders are removed
    const fillPrice = o.input.limitPrice === 0n ? this.state.oracle.price : o.input.limitPrice;
    o.finality = "MATCHED";
    o.filledSize = o.input.size;
    o.avgFillPrice = fillPrice;
    this.applyFillToPosition(o);
    this.state.orders = [...this.state.orders];
    this.emit();
    this.emitEvent({ orderId: id, kind: "MATCHED", message: "Matched (soft preconfirmation) — not yet withdrawable" });
  }

  private advanceToSettled(id: string) {
    const o = this.state.orders.find((x) => x.id === id);
    if (!o || o.finality !== "MATCHED") return;
    o.finality = "SETTLED";
    this.state.orders = [...this.state.orders];
    this.emit();
    this.emitEvent({ orderId: id, kind: "SETTLED", message: "Settled on L1 — withdrawable" });
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
    this.state.orders = this.state.orders.filter((x) => x.id !== orderId);
    this.emit();
    this.emitEvent({ orderId, kind: "CANCELLED", message: "Order cancelled before matching" });
  }

  private isOpening(input: OrderInput): boolean {
    const pos = this.state.account.positions.find((p) => p.marketId === input.marketId);
    if (!pos || pos.size === 0n) return true;
    const signed = input.side === "Buy" ? input.size : -input.size;
    // same direction ⇒ increasing
    return (pos.size > 0n) === (signed > 0n);
  }

  private applyFillToPosition(o: TrackedOrder) {
    const signed = o.input.side === "Buy" ? o.filledSize : -o.filledSize;
    const positions = [...this.state.account.positions];
    const idx = positions.findIndex((p) => p.marketId === o.input.marketId);
    const mark = this.state.oracle.price;
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
      // naive VWAP on increase; close on opposite (UI-level approximation)
      if (newSize === 0n) {
        positions.splice(idx, 1);
      } else {
        const increasing = (p.size > 0n) === (signed > 0n);
        const entry = increasing
          ? (p.entryPrice * abs(p.size) + o.avgFillPrice * abs(signed)) / (abs(p.size) + abs(signed))
          : p.entryPrice;
        positions[idx] = {
          ...p,
          size: newSize,
          entryPrice: entry,
          liquidationPrice: this.liqPrice(newSize, entry),
        };
      }
    }
    this.state.account = {
      ...this.state.account,
      positions: positions.map((p) => ({ ...p, unrealizedPnl: this.pnl(p.size, p.entryPrice, mark) })),
    };
  }

  private requiredMargin(size: bigint, price: bigint): bigint {
    const notional = (size * price) / (SIZE_SCALE * PRICE_SCALE / QUOTE_SCALE);
    return notional / 10n; // 10% initial margin
  }

  private pnl(size: bigint, entry: bigint, mark: bigint): bigint {
    return (size * (mark - entry)) / (SIZE_SCALE * PRICE_SCALE / QUOTE_SCALE);
  }

  private liqPrice(size: bigint, entry: bigint): bigint {
    // approx: maintenance 5%; long liquidates ~5% below entry at 10x (UI hint)
    const delta = (entry * 9n) / 100n;
    return size > 0n ? entry - delta : entry + delta;
  }

  async deposit(amountQuote: bigint): Promise<void> {
    if (amountQuote <= 0n) throw new Error("Amount must be positive.");
    this.state.account = {
      ...this.state.account,
      settledBalance: this.state.account.settledBalance + amountQuote,
    };
    this.emit();
  }

  async requestWithdrawal(amountQuote: bigint): Promise<void> {
    if (amountQuote <= 0n) throw new Error("Amount must be positive.");
    if (amountQuote > this.state.account.settledBalance) {
      throw new Error("Not withdrawable: amount exceeds SETTLED balance (§3).");
    }
    this.state.account = {
      ...this.state.account,
      settledBalance: this.state.account.settledBalance - amountQuote,
    };
    this.emit();
  }

  triggerCloseOnly(): void {
    this.state.mode = "CloseOnly";
    this.emit();
  }

  async recover(seedHex: string): Promise<RecoveredNote[]> {
    // deterministic mock: derive a few notes from the seed
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

// In-memory mock that encodes the protocol's observable semantics so the UI is
// faithful before any backend exists. Multi-market (5 USDC pairs, see MARKETS),
// matching the protocol's per-MarketId state. Fidelity points:
//   • every order returns a signed-style receipt immediately (ACCEPTED, §2)
//   • finality advances ACCEPTED → MATCHED → SETTLED, only SETTLED is withdrawable
//   • close-only blocks opening/increasing/flipping; reduce-only can only reduce (§6)
//   • opening locks initial margin out of the free balance; close releases it + realizes PnL
//   • liq/margin derive from each market's initial/maintenance ratios (mirrors perp-core)
//   • the book is seeded by an internal market-maker (§15)

import type { DarkPerpClient, ClientState, OrderEvent } from "./client";
import { fetchLiveQuotes } from "./oracleFeed";
import { liquidationPrice } from "../domain/risk";
import {
  PRICE_SCALE,
  QUOTE_SCALE,
  SIZE_SCALE,
  type BatchSummary,
  type Finality,
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

const FINALITY_RANK: Record<Finality, number> = { ACCEPTED: 0, MATCHED: 1, SETTLED: 2 };

/// Derive the sealed-batch view (§2/§3) from the order-commitment log: group orders
/// by their settling batch, and per batch commit a manifest hash (over the ordered
/// order-hash sequence) and an ordered root (over the SORTED leaves — what inclusion
/// challenges prove against). A batch is only SETTLED once every order in it has.
function batchesFromOrders(orders: TrackedOrder[]): BatchSummary[] {
  const byBatch = new Map<number, TrackedOrder[]>();
  for (const o of orders) {
    const b = o.receipt.batchIdHint;
    const arr = byBatch.get(b);
    if (arr) arr.push(o);
    else byBatch.set(b, [o]);
  }
  const out: BatchSummary[] = [];
  for (const [batchId, os] of byBatch) {
    const hashes = os.map((o) => o.receipt.orderHash);
    const finality = os.reduce<Finality>(
      (min, o) => (FINALITY_RANK[o.finality] < FINALITY_RANK[min] ? o.finality : min),
      "SETTLED",
    );
    out.push({
      batchId,
      orderCount: os.length,
      manifestHash: pseudoHash("manifest:" + hashes.join("")),
      orderedRoot: pseudoHash("ordered:" + [...hashes].sort().join("")),
      finality,
      sealedMs: Math.min(...os.map((o) => o.receipt.recvTimeMs)),
    });
  }
  return out.sort((a, b) => b.batchId - a.batchId);
}

function bookAround(marketId: number, mid: bigint, bestBid?: bigint, bestAsk?: bigint): OrderBookSnapshot {
  const step = mid / 5000n; // ~0.02% ticks, for the synthetic depth beyond top-of-book
  // anchor the innermost levels to the REAL best bid/ask when the live oracle has
  // them; the deeper levels are the internal market-maker seed (§15).
  const b0 = bestBid && bestBid > 0n ? bestBid : mid - 2n * step;
  const a0 = bestAsk && bestAsk > 0n ? bestAsk : mid + 2n * step;
  return {
    marketId,
    bids: [
      { price: b0, size: SIZE_SCALE / 2n },
      { price: b0 - 2n * step, size: SIZE_SCALE },
      { price: b0 - 8n * step, size: 2n * SIZE_SCALE },
      { price: b0 - 16n * step, size: 3n * SIZE_SCALE },
    ],
    asks: [
      { price: a0, size: SIZE_SCALE / 2n },
      { price: a0 + 2n * step, size: SIZE_SCALE },
      { price: a0 + 8n * step, size: 2n * SIZE_SCALE },
      { price: a0 + 16n * step, size: 3n * SIZE_SCALE },
    ],
  };
}

/// The listed markets. `instrument` is the Crypto.com perp the live oracle polls
/// (null = no external feed, runs on the internal walk). `seed` is the price the
/// market opens at before the first live tick. All margin/liq math derives from
/// each market's initial/maintenance ratios (domain/risk), so it stays correct
/// per-market rather than assuming a single hard-coded leverage.
interface MarketCfg {
  id: number;
  symbol: string;
  instrument: string | null;
  seed: number;
}
const MARKETS: MarketCfg[] = [
  { id: 0, symbol: "BTC/USDC", instrument: "BTCUSD-PERP", seed: 59_575.14 },
  { id: 1, symbol: "ETH/USDC", instrument: "ETHUSD-PERP", seed: 1_570.61 },
  { id: 2, symbol: "SOL/USDC", instrument: "SOLUSD-PERP", seed: 66.44 },
  { id: 3, symbol: "HYPE/USDC", instrument: "HYPEUSD-PERP", seed: 63.124 },
  { id: 4, symbol: "LIT/USDC", instrument: null, seed: 1.1 },
];

/// Decimal USD → PRICE_SCALE bigint (geometry/seed only; on-wire math stays bigint).
function priceFromUsd(n: number): bigint {
  return BigInt(Math.round(n * Number(PRICE_SCALE)));
}

function makeMarket(cfg: MarketCfg): MarketData {
  const price = priceFromUsd(cfg.seed);
  const market: Market = {
    id: cfg.id,
    symbol: cfg.symbol,
    maxLeverage: 10,
    maintenanceMarginRatio: 0.05,
    initialMarginRatio: 0.1,
    referencePrice: price,
    live: false,
    takerFeeBps: 10,
    makerRebateBps: 4,
  };
  const oracle: OracleQuote = { marketId: cfg.id, price, confidence: price / 10000n, publishTimeMs: Date.now() };
  return { market, oracle, book: bookAround(cfg.id, price) };
}

export class MockDarkPerpClient implements DarkPerpClient {
  private data = new Map<number, MarketData>();
  private selectedMarketId = 0;
  private state: ClientState;
  private adlClawed = 0n;
  private subs = new Set<(s: ClientState) => void>();
  private eventSubs = new Set<(e: OrderEvent) => void>();

  constructor() {
    for (const cfg of MARKETS) this.data.set(cfg.id, makeMarket(cfg));
    this.state = this.snapshot([]);
    if (typeof globalThis.setInterval === "function") {
      globalThis.setInterval(() => this.priceTick(), 1500);
      // connect the real oracle: poll Crypto.com, fall back to the walk on failure.
      // Skipped under the test runner so unit tests never touch the network.
      if (import.meta.env?.MODE !== "test") {
        void this.pollOracle();
        globalThis.setInterval(() => void this.pollOracle(), 5000);
      }
    }
  }

  /// Poll the live Crypto.com oracle and mark every tracked market to its real
  /// index price. Best-effort: any failure (offline / CORS) leaves the internal
  /// random-walk in charge, so the UI never stalls.
  private async pollOracle() {
    const instruments = MARKETS.map((m) => m.instrument).filter((x): x is string => x !== null);
    let quotes;
    try {
      quotes = await fetchLiveQuotes(instruments);
    } catch {
      // total feed outage: hand every live market BACK to the internal walk so the
      // UI keeps moving. Without this, priceTick() skips live markets and they would
      // freeze on their last price for the whole outage — the opposite of the
      // "never stalls" guarantee. A later successful poll re-anchors and re-marks live.
      this.demoteLiveMarkets();
      return;
    }
    for (const cfg of MARKETS) {
      if (!cfg.instrument) continue;
      const md = this.data.get(cfg.id);
      if (!md) continue;
      const q = quotes.get(cfg.instrument);
      if (!q) {
        // this instrument dropped out of the feed — resume the walk for it alone
        if (md.market.live) md.market = { ...md.market, live: false };
        continue;
      }
      // on the first live tick (or after a reconnect), anchor the 24h baseline to
      // the real open. Guard the denominator: a malformed change24h <= -1 would
      // otherwise yield a zero/negative reference price.
      if (!md.market.live) {
        const raw = BigInt(Math.round((1 + q.change24h) * 1_000_000));
        const denom = raw > 0n ? raw : 1_000_000n;
        md.market = { ...md.market, live: true, referencePrice: (q.price * 1_000_000n) / denom };
      }
      md.oracle = { ...md.oracle, price: q.price, publishTimeMs: Date.now() };
      md.book = bookAround(cfg.id, q.price, q.bid, q.ask);
    }
    this.remarkPositions();
    this.emit();
  }

  /// Revert every live-flagged market to the internal walk (used on feed outage),
  /// so priceTick() resumes driving it instead of leaving a frozen "live" price.
  private demoteLiveMarkets() {
    let changed = false;
    for (const md of this.data.values()) {
      if (md.market.live) {
        md.market = { ...md.market, live: false };
        changed = true;
      }
    }
    if (changed) this.emit();
  }

  /// Re-mark every open position against its market's current price.
  private remarkPositions() {
    this.state.account = {
      ...this.state.account,
      positions: this.state.account.positions.map((pos) => ({
        ...pos,
        unrealizedPnl: this.pnl(pos.size, pos.entryPrice, this.priceOf(pos.marketId)),
      })),
    };
  }

  private priceOf(marketId: number): bigint {
    return this.data.get(marketId)!.oracle.price;
  }

  private snapshot(orders: TrackedOrder[]): ClientState {
    const md = this.data.get(this.selectedMarketId)!;
    const marks: Record<number, bigint> = {};
    for (const d of this.data.values()) marks[d.market.id] = d.oracle.price;
    return {
      markets: [...this.data.values()].map((d) => d.market),
      selectedMarketId: this.selectedMarketId,
      market: md.market,
      mode: this.state?.mode ?? "Normal",
      oracle: md.oracle,
      book: md.book,
      marks,
      account: this.state?.account ?? { settledBalance: 25_000n * QUOTE_SCALE, positions: [] },
      orders,
      batches: batchesFromOrders(orders),
      insuranceFund: 25_000n * QUOTE_SCALE,
      treasury: 0n,
      lp: {
        tvl: 30_000_000n * QUOTE_SCALE,
        navPerShare: "1.000000",
        totalShares: 30_000_000n * QUOTE_SCALE,
        myShares: 0n,
        myValue: 0n,
      },
      userAdlClawed: this.adlClawed,
      mmHedge: [],
      l1: null,
      attestation: null,
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
      // markets tracking the live oracle are driven by pollOracle, not the walk
      if (md.market.live) continue;
      const p = md.oracle.price;
      const baseline = md.market.referencePrice;
      const drift = (baseline - p) / 400n;
      const noise = BigInt(Math.floor((Math.random() - 0.5) * 160)) * (p / 100000n);
      const next = p + drift + noise;
      md.oracle = { ...md.oracle, price: next, publishTimeMs: Date.now() };
      md.book = bookAround(md.market.id, next);
    }
    this.remarkPositions();
    this.emit();
  }

  async placeOrder(input: OrderInput): Promise<Receipt> {
    const opening = this.isOpening(input);
    if (this.state.mode === "CloseOnly" && opening) {
      throw new Error("System is in close-only mode — opening/increasing is blocked (§6).");
    }
    // A reduce-only order must never grow or flip the position. `opening` is true
    // exactly when the order increases exposure or crosses zero, so reject those;
    // a pure reduce or exact close (incl. closePosition) passes through.
    if (input.reduceOnly && opening) {
      throw new Error("Reduce-only order would open or increase a position — rejected.");
    }
    // Buying-power guard: a fresh open or a same-direction increase locks new margin
    // out of the free balance, so it must be affordable. (Flips net-release margin —
    // old side closes before the new opens — so they are not gated here.)
    if (this.locksNewMargin(input)) {
      const px = input.limitPrice === 0n ? this.priceOf(input.marketId) : input.limitPrice;
      // Margin only locks at MATCH (a tick later), so the free balance hasn't moved
      // yet for orders still ACCEPTED. Count the margin those in-flight opens WILL
      // lock, or two quick opens each see the whole balance and together overcommit
      // it (free balance goes negative). Cancelled orders leave the log; matched ones
      // are no longer ACCEPTED (their margin is already in settledBalance), so neither
      // is double-counted.
      const reserved = this.state.orders.reduce((sum, o) => {
        if (o.finality !== "ACCEPTED" || !this.locksNewMargin(o.input)) return sum;
        const opx = o.input.limitPrice === 0n ? this.priceOf(o.input.marketId) : o.input.limitPrice;
        return sum + this.requiredMargin(o.input.size, opx, o.input.marketId);
      }, 0n);
      if (this.requiredMargin(input.size, px, input.marketId) + reserved > this.state.account.settledBalance) {
        throw new Error("Insufficient free margin to open this position (§3).");
      }
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

  /// Would this order lock NEW initial margin out of the free balance? True for a
  /// fresh open or a same-direction increase; false for a reduce, exact close, or a
  /// flip (a flip net-releases the old side's margin before opening the new). This is
  /// the exact set the buying-power guard must charge against the balance.
  private locksNewMargin(input: OrderInput): boolean {
    if (!this.isOpening(input)) return false;
    const existing = this.state.account.positions.find((p) => p.marketId === input.marketId);
    const signedReq = input.side === "Buy" ? input.size : -input.size;
    return !existing || existing.size === 0n || (existing.size > 0n) === (signedReq > 0n);
  }

  private isOpening(input: OrderInput): boolean {
    const pos = this.state.account.positions.find((p) => p.marketId === input.marketId);
    if (!pos || pos.size === 0n) return true; // no position → any order opens one
    const signed = input.side === "Buy" ? input.size : -input.size;
    // same direction → adds exposure (opening/increasing)
    if ((pos.size > 0n) === (signed > 0n)) return true;
    // opposite direction: a strict reduce toward zero is allowed, but an order
    // LARGER than the position crosses zero and opens a fresh position on the
    // other side — that is opening, and close-only (§6) must block it. (A pure
    // reduce or exact close leaves newSize on the same side or flat.)
    const newSize = pos.size + signed;
    return newSize !== 0n && (pos.size > 0n) !== (newSize > 0n);
  }

  private applyFillToPosition(o: TrackedOrder) {
    const signed = o.input.side === "Buy" ? o.filledSize : -o.filledSize;
    const fill = o.avgFillPrice;
    const mkt = o.input.marketId;
    const positions = [...this.state.account.positions];
    const idx = positions.findIndex((p) => p.marketId === mkt);
    // Track collateral flowing between the free balance and the position: opening or
    // increasing LOCKS margin out of the settled balance; reducing/closing RELEASES it
    // and REALIZES the closed portion's PnL. Without this the margin was double-counted
    // in equity and the "free" balance backing nothing — funds could be withdrawn from
    // under an open position.
    let balanceDelta = 0n;
    if (idx === -1) {
      const collateral = this.requiredMargin(o.filledSize, fill, mkt);
      balanceDelta = -collateral; // lock initial margin
      positions.push({
        marketId: mkt,
        size: signed,
        entryPrice: fill,
        collateral,
        unrealizedPnl: 0n,
        liquidationPrice: this.liqPrice(signed, fill, mkt),
      });
    } else {
      const p = positions[idx];
      const newSize = p.size + signed;
      const increasing = (p.size > 0n) === (signed > 0n);
      if (newSize === 0n) {
        // exact close: realize full PnL at the fill, release all locked margin
        balanceDelta = p.collateral + this.pnl(p.size, p.entryPrice, fill);
        positions.splice(idx, 1);
      } else if (increasing) {
        // grow: weighted-average entry, lock the additional margin
        const entry = (p.entryPrice * abs(p.size) + fill * abs(signed)) / (abs(p.size) + abs(signed));
        const collateral = this.requiredMargin(abs(newSize), entry, mkt);
        balanceDelta = -(collateral - p.collateral);
        positions[idx] = { ...p, size: newSize, entryPrice: entry, collateral, liquidationPrice: this.liqPrice(newSize, entry, mkt) };
      } else if ((p.size > 0n) !== (newSize > 0n)) {
        // flip: old side fully closed (realize its PnL, release its margin), a fresh
        // position opens at the fill price with newly-locked margin
        const realizedOld = this.pnl(p.size, p.entryPrice, fill);
        const collateral = this.requiredMargin(abs(newSize), fill, mkt);
        balanceDelta = p.collateral + realizedOld - collateral;
        positions[idx] = { ...p, size: newSize, entryPrice: fill, collateral, liquidationPrice: this.liqPrice(newSize, fill, mkt) };
      } else {
        // partial reduce: realize PnL on the closed quantity (in the old direction),
        // release the freed margin, entry unchanged
        const closed = p.size > 0n ? abs(signed) : -abs(signed);
        const realized = this.pnl(closed, p.entryPrice, fill);
        const collateral = this.requiredMargin(abs(newSize), p.entryPrice, mkt);
        balanceDelta = p.collateral - collateral + realized;
        positions[idx] = { ...p, size: newSize, entryPrice: p.entryPrice, collateral, liquidationPrice: this.liqPrice(newSize, p.entryPrice, mkt) };
      }
    }
    this.state.account = {
      ...this.state.account,
      settledBalance: this.state.account.settledBalance + balanceDelta,
      positions: positions.map((p) => ({ ...p, unrealizedPnl: this.pnl(p.size, p.entryPrice, this.priceOf(p.marketId)) })),
    };
  }

  private requiredMargin(size: bigint, price: bigint, marketId: number): bigint {
    // initial margin = notional × the market's initial-margin ratio (same basis as
    // domain/risk.orderRisk), not a hard-coded 10× — so a non-10× market is correct.
    const notional = (size * price) / ((SIZE_SCALE * PRICE_SCALE) / QUOTE_SCALE);
    const imrBp = BigInt(Math.round(this.data.get(marketId)!.market.initialMarginRatio * 10_000));
    return (notional * imrBp) / 10_000n;
  }
  private pnl(size: bigint, entry: bigint, mark: bigint): bigint {
    return (size * (mark - entry)) / ((SIZE_SCALE * PRICE_SCALE) / QUOTE_SCALE);
  }
  private liqPrice(size: bigint, entry: bigint, marketId: number): bigint {
    // single source of truth with the pre-trade preview: the buffer is derived
    // from THIS market's initial/maintenance ratios (domain/risk), so the position's
    // liq line always matches what the ticket showed before the fill.
    const m = this.data.get(marketId)!.market;
    return liquidationPrice(entry, size > 0n, m.initialMarginRatio, m.maintenanceMarginRatio);
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

  resumeNormal(): void {
    this.state.mode = "Normal";
    this.emit();
  }

  async simulateAdl(): Promise<bigint> {
    const clawed = 1_975n * QUOTE_SCALE;
    this.adlClawed += clawed;
    this.emit();
    this.emitEvent({
      orderId: "adl-sim",
      kind: "ADL",
      message:
        "Auto-deleveraged: $1,975 of your winning position was clawed to cover a counterparty's bad debt (audit Q2).",
    });
    return clawed;
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

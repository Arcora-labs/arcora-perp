// Domain model — mirrors the Rust protocol types so the UI speaks the protocol's
// language exactly. Keep these in sync with crates/perp-core.

/// Fixed-point scales (must match crates/perp-core::fixed).
export const QUOTE_SCALE = 1_000_000n; // micro-USD
export const PRICE_SCALE = 100_000_000n; // 1e8
export const SIZE_SCALE = 100_000_000n; // 1e8

export type Side = "Buy" | "Sell";

export type TimeInForce = "Gtc" | "Ioc" | "Fok" | "PostOnly";

/// The three-layer finality (§3). Binding finality is SETTLED; MATCHED is a
/// soft good-faith preconfirmation, NOT financial certainty.
export type Finality = "ACCEPTED" | "MATCHED" | "SETTLED";

export function isWithdrawable(f: Finality): boolean {
  return f === "SETTLED";
}

/// Human copy for each finality state — the UI must make MATCHED ≠ SETTLED
/// unmistakable (§3).
export const FINALITY_COPY: Record<Finality, { label: string; hint: string }> = {
  ACCEPTED: {
    label: "Accepted",
    hint: "The enclave received your order and signed a receipt (your inclusion proof).",
  },
  MATCHED: {
    label: "Matched",
    hint: "Soft preconfirmation. Good-faith, not final — not yet withdrawable.",
  },
  SETTLED: {
    label: "Settled",
    hint: "ZK proof verified on Ethereum. Hard finality — withdrawable.",
  },
};

export interface Market {
  id: number;
  symbol: string;
  maxLeverage: number;
  maintenanceMarginRatio: number; // fraction, e.g. 0.05
  initialMarginRatio: number;
  /// Session reference price (the 24h open once the live oracle reports it),
  /// price-scaled — the baseline the stats strip measures the change against.
  referencePrice: bigint;
  /// `true` when this market is tracking the live Crypto.com oracle feed; `false`
  /// when it has no external feed and runs on the internal random-walk.
  live: boolean;
  /// Taker trading fee in basis points of notional (audit Q4). The taker pays it
  /// on every fill; `makerRebateBps` is credited to the resting maker and the
  /// remainder funds the insurance fund.
  takerFeeBps: number;
  /// Maker rebate in basis points — what the resting maker earns for providing
  /// liquidity (audit Q4). Always `<= takerFeeBps`.
  makerRebateBps: number;
}

/// The market-maker's delta-hedging signal for one market (audit Q5): net
/// inventory (signed, size-scaled), the offsetting `hedgeTarget` to take on an
/// external venue for delta-neutrality, and the quote-scaled notional exposure.
/// Venue-agnostic — the protocol emits this; an external keeper executes the hedge.
export interface HedgeSignal {
  marketId: number;
  symbol: string;
  inventory: bigint;
  hedgeTarget: bigint;
  notional: bigint;
}

/// The last on-chain L1 settlement the gateway's bridge published (§3) — present
/// only when the gateway runs with the L1 bridge configured (Base Sepolia).
export interface L1Settlement {
  settledRoot: string;
  batchCount: number;
  lastTx: string;
  /// Sequencer bond in USDC base units (the bond is USDC-denominated, audit Q1).
  bondUsdc: bigint;
  /// Cumulative withdrawals root last published to the vault (users claim against it).
  withdrawalsRoot: string;
}

/// The verified TEE attestation the enclave identity is bound to — present only
/// when the gateway boots with a real Azure TDX + vTPM attestation (else null/stub).
export interface Attestation {
  measurement: string;
  tcb: string;
  quoteVersion: number;
}

export interface OrderInput {
  marketId: number;
  side: Side;
  /// size in base units, size-scaled (bigint)
  size: bigint;
  /// limit price, price-scaled; 0n = market order
  limitPrice: bigint;
  tif: TimeInForce;
  reduceOnly: boolean;
}

export interface Receipt {
  orderHash: string;
  seqNo: number;
  recvTimeMs: number;
  batchIdHint: number;
}

/// An order as tracked in the UI, with its evolving finality.
export interface TrackedOrder {
  id: string;
  input: OrderInput;
  receipt: Receipt;
  finality: Finality;
  filledSize: bigint;
  avgFillPrice: bigint;
  createdMs: number;
}

export interface Position {
  marketId: number;
  /// signed size, size-scaled (>0 long, <0 short)
  size: bigint;
  entryPrice: bigint; // price-scaled
  collateral: bigint; // quote-scaled
  unrealizedPnl: bigint; // quote-scaled, at current mark
  liquidationPrice: bigint; // price-scaled
}

export interface OracleQuote {
  marketId: number;
  price: bigint; // price-scaled
  confidence: bigint;
  publishTimeMs: number;
}

export interface BookLevel {
  price: bigint; // price-scaled
  size: bigint; // size-scaled
}

export interface OrderBookSnapshot {
  marketId: number;
  bids: BookLevel[]; // high → low
  asks: BookLevel[]; // low → high
}

/// System-wide mode (§6). Close-only blocks opening/increasing.
export type SystemMode = "Normal" | "CloseOnly";

export interface AccountState {
  /// free, settled shielded balance (quote-scaled) — withdrawable
  settledBalance: bigint;
  positions: Position[];
}

/// A note recovered by scanning the archive with a view-key (§7).
export interface RecoveredNote {
  batchId: number;
  amount: bigint; // quote-scaled
  spent: boolean;
}

/// A sealed batch as published to the order-commitment log (§2/§3). `manifestHash`
/// binds the batch's contents; `orderedRoot` is the Merkle root of its ordered
/// order-hash leaves (what inclusion challenges prove against). `finality` is the
/// batch's overall state — SETTLED once every order in it has settled.
export interface BatchSummary {
  batchId: number;
  orderCount: number;
  manifestHash: string;
  orderedRoot: string;
  finality: Finality;
  sealedMs: number;
}

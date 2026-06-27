// The client interface the UI talks to. The mock implements it now; a real
// implementation later talks to the sequencer (orders, receipts) and reads L1 /
// the note archive (settlement, recovery). Keeping the UI behind this interface
// means the design + components never change when the backend lands.

import type {
  AccountState,
  Attestation,
  BatchSummary,
  HedgeSignal,
  L1Settlement,
  Market,
  OracleQuote,
  OrderBookSnapshot,
  OrderInput,
  RecoveredNote,
  Receipt,
  SystemMode,
  TrackedOrder,
} from "../domain/types";

export interface ClientState {
  /// all listed markets
  markets: Market[];
  /// the currently selected market's id
  selectedMarketId: number;
  /// the selected market (convenience; equals markets.find(selectedMarketId))
  market: Market;
  mode: SystemMode;
  /// oracle + book for the SELECTED market
  oracle: OracleQuote;
  book: OrderBookSnapshot;
  /// current index price per market id — so positions/health/notional in OTHER
  /// markets are marked at THEIR own price, not the selected market's (§8).
  marks: Record<number, bigint>;
  account: AccountState;
  orders: TrackedOrder[];
  /// sealed batches published to the order-commitment log (§2/§3), newest first.
  batches: BatchSummary[];
  /// Quote-scaled insurance-fund balance — the bad-debt backstop that absorbs
  /// liquidation shortfalls before they socialize (audit Q3/Q7). Grows from the
  /// per-fill insurance cut of the trading fee (audit Q4).
  insuranceFund: bigint;
  /// Quote-scaled cumulative collateral the user has had auto-deleveraged — the
  /// transparency surface for socialized losses (audit Q2).
  userAdlClawed: bigint;
  /// The market-maker's net inventory + delta-neutral hedge target per market with
  /// open MM exposure — the venue-agnostic hedging signal (audit Q5).
  mmHedge: HedgeSignal[];
  /// The last on-chain L1 settlement (Base Sepolia), or null when the gateway runs
  /// without the L1 bridge (pure in-memory / mock).
  l1: L1Settlement | null;
  /// The verified TEE attestation the enclave is bound to, or null (stub enclave).
  attestation: Attestation | null;
}

export interface DarkPerpClient {
  getState(): ClientState;
  subscribe(cb: (s: ClientState) => void): () => void;

  /// Submit an order; resolves with the ACCEPTED receipt (§2). Finality then
  /// advances ACCEPTED → MATCHED → SETTLED asynchronously (§3).
  placeOrder(input: OrderInput): Promise<Receipt>;

  /// Deposit collateral (mints a shielded note off-chain).
  deposit(amountQuote: bigint): Promise<void>;

  /// Request a withdrawal. Rejects unless the amount is backed by SETTLED balance
  /// (§3 — only settled state is withdrawable).
  requestWithdrawal(amountQuote: bigint): Promise<void>;

  /// Simulate the liveness/forced-exit trigger → close-only (§6).
  triggerCloseOnly(): void;

  /// Clear close-only and return to Normal (the breaker recovers / sequencer is
  /// back). Lets the forced-exit simulation be toggled instead of being a dead-end.
  resumeNormal(): void;

  /// Demo: run a bad-debt cascade that auto-deleverages the user, surfacing the
  /// resulting ADL receipt (audit Q2). Returns the quote-scaled amount clawed.
  simulateAdl(): Promise<bigint>;

  /// Recover notes by scanning the archive with a seed-derived view-key (§7).
  recover(seedHex: string): Promise<RecoveredNote[]>;

  /// Close a position with a reduce-only market order.
  closePosition(marketId: number): Promise<void>;

  /// Cancel an order that is still ACCEPTED (not yet matched).
  cancelOrder(orderId: string): Promise<void>;

  /// Switch the active market.
  selectMarket(marketId: number): void;

  /// Subscribe to order lifecycle events (for toasts). Returns an unsubscribe fn.
  onOrderEvent(cb: (e: OrderEvent) => void): () => void;
}

/// An order lifecycle event surfaced for notifications.
export interface OrderEvent {
  orderId: string;
  kind: "ACCEPTED" | "MATCHED" | "SETTLED" | "CANCELLED" | "REJECTED" | "ADL";
  message: string;
}

// The client interface the UI talks to. The mock implements it now; a real
// implementation later talks to the sequencer (orders, receipts) and reads L1 /
// the note archive (settlement, recovery). Keeping the UI behind this interface
// means the design + components never change when the backend lands.

import type {
  AccountState,
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
  account: AccountState;
  orders: TrackedOrder[];
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
  kind: "ACCEPTED" | "MATCHED" | "SETTLED" | "CANCELLED" | "REJECTED";
  message: string;
}

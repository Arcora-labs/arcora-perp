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
  WithdrawalEntry,
} from "../domain/types";

/// The LP pool (the MM-as-counterparty): LPs deposit USDC → mint shares of the
/// pool's mark-to-market equity, earn the house edge (trader losses), bear pool PnL.
export interface LpPool {
  /// Pool TVL — its mark-to-market equity (quote-scaled).
  tvl: bigint;
  /// NAV per share (a "1.000000"-style string); 1.0 at genesis, drifts with pool PnL.
  navPerShare: string;
  totalShares: bigint;
  /// The current user's LP shares + their value (quote-scaled).
  myShares: bigint;
  myValue: bigint;
}

/// FIN-001: the gateway settle-loop breaker state, from the status snapshot.
export interface SettlementHealth {
  health: "HEALTHY" | "DEGRADED" | "HELD";
  /// Consecutive settle failures behind `health` (0 when healthy).
  consecutiveFailures: number;
  /// Most recent settle error while unhealthy, or null.
  lastError: string | null;
  /// Wall-clock ms the loop entered HELD, or null unless currently HELD.
  heldSinceMs: number | null;
}

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
  /// Protocol-treasury balance — the operator's accrued trading-fee revenue (§9).
  treasury: bigint;
  /// The LP pool (the MM-as-counterparty): TVL, NAV/share, and the user's own stake.
  lp: LpPool;
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
  /// FIN-001 settle-loop health, or null when the gateway predates it (or mock).
  settlement: SettlementHealth | null;
  /// SEC-025-E1 (whole-branch review F1): true when the caller HAS a /v1
  /// account but its state could not be read — `account`/`orders` are then
  /// EMPTY PLACEHOLDERS (zero balance, no positions, no rows), which is a
  /// read failure, NOT a statement of "no balance / no positions", and never
  /// the public demo feed. Absent/false on the mock (its account is always
  /// readable) and while no /v1 account exists yet (there the public feed
  /// legitimately stands in).
  accountUnavailable?: boolean;
}

export interface DarkPerpClient {
  getState(): ClientState;
  subscribe(cb: (s: ClientState) => void): () => void;

  /// Submit an order; resolves with the ACCEPTED receipt (§2). Finality then
  /// advances ACCEPTED → MATCHED → SETTLED asynchronously (§3).
  placeOrder(input: OrderInput): Promise<Receipt>;

  /// Deposit collateral (mints a shielded note off-chain).
  deposit(amountQuote: bigint): Promise<void>;

  /// Request a withdrawal of SETTLED balance (§3 — only settled state is
  /// withdrawable). SEC-021: the destination is NOT a parameter — on the real
  /// gateway funds always pay to the account's bound deposit address, and the
  /// request carries that address's wallet signature over the gateway's
  /// withdraw digest. Rejects when no deposit address is bound (fail closed).
  requestWithdrawal(amountQuote: bigint): Promise<void>;

  /// SEC-021 (optional — the real client implements it, the mock has no binding
  /// concept): the bound withdrawal destination (null = not bound yet, so a
  /// withdrawal would be refused) and whether the account is caller-signed (the
  /// advanced API mode whose registered signer key the web UI does not hold).
  withdrawAuthInfo?(): Promise<{ depositAddress: string | null; callerSigned: boolean }>;

  /// The account's requested withdrawals + the vault they claim against — so the
  /// UI can show settling→claimable status and the on-chain `claim` call instead
  /// of dead-ending after `requestWithdrawal`. `null` = unsupported (mock) or no
  /// account provisioned yet; the UI hides the surface entirely then.
  listWithdrawals(): Promise<{ withdrawals: WithdrawalEntry[]; vault: string } | null>;

  // ── demo-only surfaces (SEC-025-E1 Task 3) ────────────────────────────────
  // OPTIONAL because their legacy /api/* routes exist only in the demo build
  // (audit DP-010: the production router does not mount them). The mock client
  // implements them; the real client DELETES them rather than calling routes
  // that 404 — three of them used to report that failure to the user as
  // success. The UI presence-gates on each (the `withdrawAuthInfo` idiom), so
  // the corresponding buttons are honestly absent in live mode.

  /// Demo: simulate the liveness/forced-exit trigger → close-only (§6).
  triggerCloseOnly?(): void;

  /// Demo: clear close-only and return to Normal (the breaker recovers /
  /// sequencer is back). Lets the forced-exit simulation be toggled.
  resumeNormal?(): void;

  /// Demo: run a bad-debt cascade that auto-deleverages the user, surfacing the
  /// resulting ADL receipt (audit Q2). Returns the quote-scaled amount clawed.
  simulateAdl?(): Promise<bigint>;

  /// Demo: recover notes by scanning the archive with a seed-derived view-key
  /// (§7). The live gateway serves no recovery route yet.
  recover?(seedHex: string): Promise<RecoveredNote[]>;

  /// Demo: close a position with a reduce-only market order. There is NO /v1
  /// equivalent yet — implementing close as a reduce-only /v1 order submission
  /// is a product decision for a later slice, so in live mode the close button
  /// is honestly absent rather than falsely reporting success.
  closePosition?(marketId: number): Promise<void>;

  /// Cancel an order that is still ACCEPTED (not yet matched). On the real
  /// client this is `DELETE /v1/orders/:id` (caller-scoped); gateway refusals
  /// — including the `sealed` refusal every resting order hits until E2 —
  /// reject the promise with the gateway's reason. The mock mirrors the same
  /// one-tick seal window and refusal wording (Task 4, clientContract.test.ts),
  /// so neither client pins an always-cancellable contract E2 hasn't earned.
  cancelOrder(orderId: string): Promise<void>;

  /// Switch the active market.
  selectMarket(marketId: number): void;

  /// Subscribe to order lifecycle events (for toasts). Returns an unsubscribe fn.
  onOrderEvent(cb: (e: OrderEvent) => void): () => void;
}

/// An order lifecycle event surfaced for notifications. Every member has a
/// live producer (SEC-025-E1 Task 3 dropped the producer-less "REJECTED"),
/// but the producers are NOT symmetrical across the clients:
/// - ACCEPTED — produced at PLACEMENT by the MOCK only. The real client's
///   /v1/ws `order` handler accepts the kind, but the gateway emits an order
///   frame only on a finality TRANSITION (crates/gateway/src/main.rs:4347-4367
///   — `if f != o.last_finality`, the only account-event emitter) and creates
///   every order ACCEPTED (main.rs:3181), so the first evaluation compares
///   ACCEPTED to ACCEPTED and pushes nothing. A live `finality:"ACCEPTED"`
///   frame therefore occurs only on a MATCHED→ACCEPTED downgrade (a
///   rollback), never on the accept path — there, placeOrder's resolved
///   receipt is the acceptance signal.
/// - MATCHED/SETTLED — mock lifecycle + the real stream's owner-verified
///   `order` events.
/// - CANCELLED — both clients' cancelOrder on success.
/// - ADL — mock simulateAdl + the real stream's `adl` events.
/// If the gateway ever pushes real rejection events (E3 territory), re-add the
/// kind WITH its producer.
export interface OrderEvent {
  orderId: string;
  kind: "ACCEPTED" | "MATCHED" | "SETTLED" | "CANCELLED" | "ADL";
  message: string;
}

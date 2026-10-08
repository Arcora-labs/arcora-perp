/** Proposed UI adapter boundaries only; not the actual Arcora protocol API.
 * Decimal strings are intentional. Validate against the real protocol at runtime.
 * Demo setTimeouts and local float accounting must never be production adapters.
 */
export type DecimalString = string;
export type MarketId = string;
export interface PriceSample {
  market: MarketId;
  referencePrice: DecimalString;
  indexPrice?: DecimalString;
  observedAt: string;
  source: string;
  isStale: boolean;
  mode: 'live' | 'delayed' | 'demo';
}
export interface OrderIntent {
  market: MarketId;
  side: 'long' | 'short';
  kind: 'market' | 'limit';
  notional: DecimalString;
  settlementAsset: string;
  leverage: DecimalString;
  limitPrice?: DecimalString;
  reduceOnly: boolean;
  clientRequestId: string;
}
export interface Evidence {
  id: string;
  observedAt: string;
  source: string;
  transactionHash?: string;
  chainId?: string;
  blockNumber?: string;
  /** Human-readable description of what was actually checked. */
  verificationDescription: string;
}
export type OrderLifecycle =
  | {state: 'draft'; intent: OrderIntent}
  | {state: 'awaiting-signature'; intent: OrderIntent}
  | {state: 'submitting'; requestId: string}
  | {state: 'accepted'; orderId: string; acceptance: Evidence}
  | {state: 'partially-filled'; orderId: string; filledNotional: DecimalString; execution: Evidence}
  | {state: 'matched'; orderId: string; execution: Evidence}
  | {state: 'settled'; orderId: string; settlement: Evidence}
  | {state: 'cancel-pending'; orderId: string}
  | {state: 'canceled'; orderId: string; cancellation: Evidence}
  | {state: 'rejected'; requestId: string; code: string; message: string}
  | {state: 'unknown'; requestId: string; message: string};
export interface OrderQuote {
  intent: OrderIntent;
  initialMargin: DecimalString;
  estimatedFee: DecimalString;
  estimatedLiquidationPrice?: DecimalString;
  expiresAt: string;
  assumptions: string[];
  warnings: string[];
}
export interface TradingAdapter {
  quote(intent: OrderIntent, signal?: AbortSignal): Promise<OrderQuote>;
  /** Implementation must handle authorization/signing; not a silent financial action. */
  submit(quote: OrderQuote, signal?: AbortSignal): Promise<OrderLifecycle>;
  cancel(orderId: string, signal?: AbortSignal): Promise<OrderLifecycle>;
  subscribeOrder(orderId: string, onUpdate: (state: OrderLifecycle) => void): () => void;
}

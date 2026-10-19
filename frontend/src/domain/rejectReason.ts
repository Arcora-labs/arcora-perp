// Readable text for the reasons a batch manifest records for a rejected order.
//
// The gateway reports a rejected order's `execution.reason` as the name of
// `perp-core::order::RejectReason` (the manifest itself stores the numeric code).
// Keep the codes in sync with crates/perp-core/src/order.rs: they are explicit
// and stable, and new reasons are only ever appended.

export const REJECT_REASONS: Record<string, { code: number; text: string }> = {
  Expired: { code: 1, text: "The order expired." },
  SelfTradePrevented: { code: 2, text: "It would have traded against your own order." },
  PostOnlyWouldTake: { code: 3, text: "A post-only order would have taken liquidity." },
  ReduceOnlyViolation: { code: 4, text: "A reduce-only order would have opened or increased a position." },
  InsufficientMargin: { code: 5, text: "Not enough free margin for the initial-margin requirement." },
  MarketCloseOnly: { code: 6, text: "The system is close-only: only reducing orders are accepted." },
  OracleUnavailable: { code: 7, text: "No fresh validated price was available." },
  FillOrKillUnfillable: { code: 8, text: "A fill-or-kill order could not fill in full." },
  Cancelled: { code: 9, text: "The order expired before it could match." },
  InvalidOrder: { code: 10, text: "The order was malformed or could not be applied." },
  FillPriceOutOfBand: { code: 11, text: "The fill price lay outside the market's band around the oracle price." },
  FillWouldBankrupt: { code: 12, text: "The fill would have left a position with negative collateral or below maintenance margin." },
  BelowMinimumSize: { code: 13, text: "Below the $10 minimum order size for an order that opens or increases a position." },
};

/// Readable text for a reason name, or the name itself when it is not a known
/// manifest reason (execution metadata can also carry non-manifest reasons).
export function describeRejectReason(reason: string): string {
  return Object.prototype.hasOwnProperty.call(REJECT_REASONS, reason) ? REJECT_REASONS[reason].text : reason;
}

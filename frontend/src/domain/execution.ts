import type { OrderExecution } from "./types";

const MAX_I128 = (1n << 127n) - 1n;
const STATUSES: ReadonlySet<string> = new Set([
  "PENDING", "RESTING", "PARTIALLY_FILLED", "FILLED", "CANCELLED", "REJECTED", "UNKNOWN",
]);

/** The protocol transports non-negative i128 values as decimal strings. */
function amount(value: unknown): bigint | null {
  // Bound work before BigInt conversion, including deliberately oversized input.
  if (typeof value !== "string" || value.length > 39 || !/^(0|[1-9]\d*)$/.test(value)) return null;
  const n = BigInt(value);
  return n <= MAX_I128 ? n : null;
}

export interface ExecutionTotals {
  size: unknown;
  filledSize: unknown;
  avgFillPrice: unknown;
}

/** Validate native metadata without treating receipt finality as an execution. */
export function parseExecution(value: unknown, totals: ExecutionTotals): OrderExecution | undefined {
  if (value === undefined) return undefined;
  const v = value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown> : {};
  const validStatus = typeof v.status === "string" && STATUSES.has(v.status);
  const original = amount(totals.size);
  const remaining = amount(v.remainingSize);
  const validRemaining = original !== null && original > 0n && remaining !== null && remaining <= original;
  const status = validStatus ? v.status as OrderExecution["status"] : "UNKNOWN";
  const invalid: OrderExecution = {
    status: "UNKNOWN", available: false, remainingSize: null,
    unsettledSize: null, settledSize: null, reason: "ExecutionMetadataMismatch", proven: false,
  };
  if (!validStatus || !validRemaining || typeof v.available !== "boolean") return invalid;
  if (v.available === false) {
    // A migrated row may have a known current remainder but no trustworthy
    // historical total. Never expose its old fabricated filled/average fields.
    if (["FILLED", "CANCELLED", "REJECTED"].includes(status) && remaining !== 0n) return invalid;
    return {
      status, available: false, remainingSize: remaining,
      unsettledSize: null, settledSize: null,
      reason: typeof v.reason === "string" ? v.reason : "LegacyExecutionUnavailable", proven: false,
    };
  }
  const filled = amount(totals.filledSize);
  const average = amount(totals.avgFillPrice);
  const unsettled = amount(v.unsettledSize);
  const settled = amount(v.settledSize);
  if (filled === null || average === null || unsettled === null || settled === null ||
      filled > original || remaining > original - filled || settled + unsettled !== filled ||
      (filled === 0n ? average !== 0n : average === 0n) ||
      (v.filledSize !== undefined && amount(v.filledSize) !== filled) ||
      (v.avgFillPrice !== undefined && amount(v.avgFillPrice) !== average)) return invalid;
  const coherent = status === "PENDING" ? filled === 0n && remaining === original
    : status === "RESTING" ? filled === 0n && remaining === original
    : status === "PARTIALLY_FILLED" ? filled > 0n && remaining > 0n && filled + remaining === original
    : status === "FILLED" ? filled === original && remaining === 0n
    : status === "CANCELLED" || status === "REJECTED" ? remaining === 0n
    : false;
  if (!coherent) return invalid;
  return {
    status, available: true, remainingSize: remaining, unsettledSize: unsettled, settledSize: settled,
    reason: typeof v.reason === "string" ? v.reason : null, proven: false,
  };
}

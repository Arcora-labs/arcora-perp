import type { TrackedOrder } from "./types";

/** Absent means legacy; a present malformed capability must fail closed. */
export function cancellationCapability(value: unknown): Pick<TrackedOrder, "cancellable"> {
  return value === undefined ? {} : { cancellable: value === true };
}

/** Settled partial fills can retain live depth. Prefer the gateway's capability. */
export function canCancelOrder(order: Pick<TrackedOrder, "cancellable" | "finality" | "execution">): boolean {
  if (order.cancellable !== undefined) return order.cancellable;
  if (order.execution) {
    return (order.execution.remainingSize ?? 0n) > 0n &&
      ["PENDING", "RESTING", "PARTIALLY_FILLED"].includes(order.execution.status);
  }
  return order.finality === "ACCEPTED";
}

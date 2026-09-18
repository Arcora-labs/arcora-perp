import type { TrackedOrder } from "./types";

/** Absent means legacy; a present malformed capability must fail closed. */
export function cancellationCapability(value: unknown): Pick<TrackedOrder, "cancellable"> {
  return value === undefined ? {} : { cancellable: value === true };
}

/** Settled partial fills can retain live depth. Prefer the gateway's capability. */
export function canCancelOrder(order: Pick<TrackedOrder, "cancellable" | "finality">): boolean {
  return order.cancellable ?? (order.finality === "ACCEPTED");
}

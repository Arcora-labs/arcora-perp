// @vitest-environment happy-dom
import { render, screen, cleanup, fireEvent, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { OrdersTable } from "./Tables";
import type { TrackedOrder } from "../domain/types";
const fixture = vi.hoisted(() => ({ orders: [] as unknown[], cancel: vi.fn() }));
vi.mock("../store", () => ({ useStore: () => ({
  state: { orders: fixture.orders, accountUnavailable: false },
  client: { cancelOrder: fixture.cancel },
}) }));
function order(): TrackedOrder {
  return { id: "o1", input: { marketId: 0, side: "Sell", size: 10_000_000n,
    limitPrice: 100_000_000_000n, tif: "Gtc", reduceOnly: false },
    receipt: { orderHash: "0x" + "11".repeat(32), seqNo: 1, recvTimeMs: 1, batchIdHint: 1 },
    finality: "SETTLED", filledSize: 2_500_000n, avgFillPrice: 100_000_000_000n, createdMs: 1,
    execution: { status: "PARTIALLY_FILLED", remainingSize: 7_500_000n, unsettledSize: 1_250_000n,
      settledSize: 1_250_000n, available: true, proven: false, reason: null },
  };
}
beforeEach(() => { fixture.orders = [order()]; fixture.cancel.mockReset().mockResolvedValue(undefined); });
afterEach(cleanup);
describe("order execution is separate from finality", () => {
  it("lets a settled partial maker cancel its remaining quantity", async () => {
    render(<OrdersTable />);
    expect(screen.getByText("PARTIALLY_FILLED")).toBeTruthy();
    expect(screen.getByText(/\+0\.0250 \/ \+0\.0750/)).toBeTruthy();
    expect(screen.getByText(/Unsettled fills/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    await waitFor(() => expect(fixture.cancel).toHaveBeenCalledWith("o1"));
  });
  it("never offers cancellation for a terminal remainder", () => {
    const o = order(); o.execution = { ...o.execution!, status: "CANCELLED", remainingSize: 0n };
    fixture.orders = [o]; render(<OrdersTable />);
    expect(screen.queryByRole("button", { name: "Cancel" })).toBeNull();
  });
  it("does not present legacy fabricated fill values as real history", () => {
    const o = order(); o.filledSize = o.input.size;
    o.execution = { ...o.execution!, available: false, settledSize: null, unsettledSize: null };
    fixture.orders = [o]; render(<OrdersTable />);
    expect(screen.getByText("Historical fills unavailable")).toBeTruthy();
    expect(screen.getByText(/\? \/ \+0\.0750/)).toBeTruthy();
  });
  it("surfaces a durability error instead of announcing a durable cancellation", async () => {
    fixture.cancel.mockRejectedValue(new Error("Cancellation durability unconfirmed"));
    render(<OrdersTable />); fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(await screen.findByText("Cancellation durability unconfirmed")).toBeTruthy();
  });
});

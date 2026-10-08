// @vitest-environment happy-dom
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MockDarkPerpClient } from "../api/mockClient";
import { OrderTicket } from "./OrderTicket";
const store = vi.hoisted(() => ({ value: null as any }));
vi.mock("../store", () => ({ useStore: () => store.value }));
afterEach(cleanup);
function setup() {
  const client = new MockDarkPerpClient();
  const state = client.getState();
  const place = vi.spyOn(client, "placeOrder").mockResolvedValue({ seqNo: 7 } as any);
  store.value = { client, state, prefillPrice: null, setPrefillPrice: vi.fn() };
  render(<OrderTicket />);
  return { client, state, place };
}
const preview = () => fireEvent.click(screen.getByRole("button", { name: /preview buy/i }));
const confirm = () => fireEvent.click(screen.getByRole("button", { name: /confirm demo order/i }));
describe("order review boundary", () => {
  it("does not submit until confirmation and uses the reviewed bigint inputs", async () => {
    const { place } = setup();
    fireEvent.change(screen.getByLabelText(/^size \(/i), { target: { value: "0.125" } });
    preview(); expect(place).not.toHaveBeenCalled(); expect(screen.getByRole("dialog")).toBeTruthy();
    confirm(); await waitFor(() => expect(place).toHaveBeenCalledTimes(1));
    expect(place.mock.calls[0][0]).toMatchObject({ size: 12500000n, limitPrice: 0n, tif: "Ioc" });
    expect(await screen.findByRole("status")).toHaveProperty("textContent", expect.stringContaining("receipt #7"));
  });
  it("closing review never places an order", () => {
    const { place } = setup(); preview(); fireEvent.click(screen.getByRole("button", { name: "Close dialog" }));
    expect(place).not.toHaveBeenCalled(); expect(screen.queryByRole("dialog")).toBeNull();
  });
  it("rejects changed market between review and confirmation", () => {
    const { client, place } = setup(); preview(); client.selectMarket(1); confirm();
    expect(place).not.toHaveBeenCalled(); expect(screen.getByRole("alert").textContent).toContain("Market or account changed");
  });
  it("rejects a close-only transition between review and confirmation", () => {
    const { client, place } = setup(); preview(); client.triggerCloseOnly(); confirm();
    expect(place).not.toHaveBeenCalled(); expect(screen.getByRole("alert").textContent).toContain("Close-only mode");
  });
  it("blocks unreadable accounts before review", () => {
    const { state, place } = setup(); state.accountUnavailable = true; preview();
    expect(place).not.toHaveBeenCalled(); expect(screen.getByRole("alert").textContent).toContain("could not be read");
  });
  it("prevents duplicate confirmation and surfaces rejection without success", async () => {
    const { place } = setup();
    let reject!: (error: Error) => void;
    place.mockImplementation(() => new Promise((_, no) => { reject = no; }));
    preview(); confirm(); fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Submitting…" }));
    expect(place).toHaveBeenCalledTimes(1);
    reject(new Error("Gateway rejected order"));
    expect(await screen.findByRole("alert")).toHaveProperty("textContent", "Gateway rejected order");
    expect(screen.queryByRole("status")).toBeNull();
  });
});

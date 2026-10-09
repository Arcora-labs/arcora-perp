// @vitest-environment happy-dom
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MockDarkPerpClient } from "../api/mockClient";
import { ModeBanner } from "./ModeBanner";
import { OrderTicket } from "./OrderTicket";

const store = vi.hoisted(() => ({ current: {} as ReturnType<typeof import("../store").useStore> }));
vi.mock("../store", () => ({ useStore: () => store.current }));
beforeEach(() => {
  const client = new MockDarkPerpClient();
  const state = { ...client.getState(), clockAdmission: { enabled: true, paused: false } };
  store.current = { client, state, prefillPrice: null, setPrefillPrice: vi.fn() };
  vi.spyOn(client, "getState").mockImplementation(() => store.current.state);
  vi.spyOn(client, "placeOrder");
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

it("shows the financial pause even in close-only mode and disables new previews", () => {
  store.current.state.mode = "CloseOnly";
  store.current.state.clockAdmission = { enabled: true, paused: true };
  render(<><ModeBanner /><OrderTicket /></>);
  expect(screen.getByRole("status").textContent).toContain("Trading temporarily paused");
  expect(screen.getByRole("status").textContent).toContain("including position closes");
  expect(screen.getByRole("button", { name: /preview buy/i }).hasAttribute("disabled")).toBe(true);
  expect(store.current.client.placeOrder).not.toHaveBeenCalled();
});

it("rechecks a pause after review and never replays the order when admission resumes", async () => {
  render(<OrderTicket />);
  fireEvent.click(screen.getByRole("button", { name: /preview buy/i }));
  store.current.state.clockAdmission = { enabled: true, paused: true };
  fireEvent.click(screen.getByRole("button", { name: /confirm demo order/i }));
  expect(screen.getByRole("alert").textContent).toContain("No order was sent");
  expect(store.current.client.placeOrder).not.toHaveBeenCalled();
  store.current.state.clockAdmission = { enabled: true, paused: false };
  await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  expect(store.current.client.placeOrder).not.toHaveBeenCalled();
});

// @vitest-environment happy-dom
import { describe, it, expect, afterEach } from "vitest";
import { render, screen, fireEvent, cleanup } from "@testing-library/react";
import { StoreProvider } from "../store";
import { OrderTicket } from "./OrderTicket";

afterEach(cleanup);

const renderTicket = () =>
  render(
    <StoreProvider>
      <OrderTicket />
    </StoreProvider>,
  );

describe("OrderTicket", () => {
  it("rejects an empty size on submit with an inline error", () => {
    renderTicket();
    const size = screen.getByLabelText(/^size \(/i);
    fireEvent.change(size, { target: { value: "" } });
    // the submit button reads "<Side> <SYMBOL>" — default Buy
    fireEvent.click(screen.getByRole("button", { name: /buy btc\/usdc/i }));
    expect(screen.getByText(/enter a valid size/i)).toBeTruthy();
  });

  it("shows a live risk preview (notional/margin/leverage/liq) for a valid order", () => {
    renderTicket();
    fireEvent.change(screen.getByLabelText(/^size \(/i), { target: { value: "1" } });
    // the preview renders its labelled rows
    expect(screen.getByText(/notional/i)).toBeTruthy();
    expect(screen.getByText(/margin required/i)).toBeTruthy();
    expect(screen.getByText(/est\. liquidation/i)).toBeTruthy();
  });

  it("hides the risk preview when reduce-only is checked", () => {
    renderTicket();
    fireEvent.change(screen.getByLabelText(/^size \(/i), { target: { value: "1" } });
    expect(screen.queryByText(/margin required/i)).toBeTruthy();
    fireEvent.click(screen.getByLabelText(/reduce-only/i));
    // reduce-only has no margin preview
    expect(screen.queryByText(/margin required/i)).toBeNull();
  });
});

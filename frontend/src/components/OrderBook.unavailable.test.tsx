// @vitest-environment happy-dom
import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";
import { OrderBook } from "./OrderBook";

vi.mock("../store", () => ({
  useStore: () => ({
    state: {
      book: { marketId: 0, unavailable: true, bids: [{ price: 6000000000000n, size: 100000000n }], asks: [] },
      oracle: { price: 6000000000000n },
    },
    setPrefillPrice: vi.fn(),
  }),
}));
afterEach(cleanup);

describe("unpublished dark-book depth", () => {
  it("explains non-disclosure and exposes no synthetic price buttons", () => {
    render(<OrderBook />);
    expect(screen.getByText(/Depth is not published/)).toBeTruthy();
    expect(screen.getByText(/not an empty-book signal/)).toBeTruthy();
    expect(screen.queryAllByRole("button")).toHaveLength(0);
    expect(document.querySelectorAll(".orderbook__depth")).toHaveLength(0);
  });
});

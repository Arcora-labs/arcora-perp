// @vitest-environment happy-dom
import { describe, it, expect, afterEach } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";
import { StoreProvider } from "../store";
import { OrderBook } from "./OrderBook";

afterEach(cleanup);

// The book renders depth bars whose width is `cum / max`. These lock the guards:
// max is floored at 1n so an empty book never divides by zero, and every bar
// width must be a finite, sane percentage a reskin can style.

describe("OrderBook robustness", () => {
  it("renders without dividing by zero and produces finite, bounded depth widths", () => {
    render(
      <StoreProvider>
        <OrderBook />
      </StoreProvider>,
    );
    expect(screen.getByText(/Order book/i)).toBeTruthy();

    // every depth bar's inline width must be a finite percentage in [0, 100]
    const bars = Array.from(document.querySelectorAll<HTMLElement>(".orderbook__depth"));
    expect(bars.length).toBeGreaterThan(0);
    for (const bar of bars) {
      const w = bar.style.width;
      expect(w).toMatch(/^\d+(\.\d+)?%$/); // never "NaN%" / "Infinity%"
      const pct = Number(w.replace("%", ""));
      expect(Number.isFinite(pct)).toBe(true);
      expect(pct).toBeGreaterThanOrEqual(0);
      expect(pct).toBeLessThanOrEqual(100);
    }
  });
});

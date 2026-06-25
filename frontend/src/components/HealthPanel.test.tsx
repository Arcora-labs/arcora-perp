// @vitest-environment happy-dom
import { describe, it, expect, afterEach } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";
import { StoreProvider } from "../store";
import { HealthPanel } from "./HealthPanel";

afterEach(cleanup);

describe("HealthPanel", () => {
  it("renders service statuses incl. the live conservation check", () => {
    render(
      <StoreProvider>
        <HealthPanel />
      </StoreProvider>,
    );
    expect(screen.getByText(/web client/i)).toBeTruthy();
    expect(screen.getByText(/oracle feed/i)).toBeTruthy();
    expect(screen.getByText(/system mode/i)).toBeTruthy();
    expect(screen.getByText(/collateral conservation/i)).toBeTruthy();
    // a healthy default account satisfies the real invariants → the ✓ detail is shown
    expect(screen.getByText(/free ≥ 0 · margin ≥ 0 · solvent ✓/i)).toBeTruthy();
  });
});

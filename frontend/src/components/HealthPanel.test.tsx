// @vitest-environment happy-dom
import { describe, it, expect, afterEach } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";
import { StoreProvider } from "../store";
import { HealthPanel, settlementRowModel } from "./HealthPanel";

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

  it("hides the FIN-001 settle-loop row when the client reports none (mock)", () => {
    render(
      <StoreProvider>
        <HealthPanel />
      </StoreProvider>,
    );
    expect(screen.queryByText(/L1 settle loop/i)).toBeNull();
  });
});

describe("settlementRowModel (FIN-001)", () => {
  it("HEALTHY → ok", () => {
    expect(
      settlementRowModel({ health: "HEALTHY", consecutiveFailures: 0, lastError: null, heldSinceMs: null }),
    ).toEqual({ status: "ok", detail: "settling — breaker closed" });
  });

  it("DEGRADED → warn with the failure count", () => {
    const m = settlementRowModel({
      health: "DEGRADED", consecutiveFailures: 2, lastError: "prover 503", heldSinceMs: null,
    });
    expect(m.status).toBe("warn");
    expect(m.detail).toContain("2 consecutive");
  });

  it("HELD → down with held-duration + error snippet + resume hint", () => {
    const m = settlementRowModel({
      health: "HELD", consecutiveFailures: 5, lastError: "prover 503", heldSinceMs: Date.now() - 120_000,
    });
    expect(m.status).toBe("down");
    expect(m.detail).toMatch(/HELD for 2m/);
    expect(m.detail).toContain("prover 503");
    expect(m.detail).toMatch(/operator resume/i);
  });

  it("HELD with no heldSince/lastError still renders sanely", () => {
    const m = settlementRowModel({
      health: "HELD", consecutiveFailures: 3, lastError: null, heldSinceMs: null,
    });
    expect(m.status).toBe("down");
    expect(m.detail).toMatch(/^HELD — operator resume required$/);
  });
});

// @vitest-environment happy-dom
import { describe, it, expect, afterEach, beforeEach } from "vitest";
import { render, screen, cleanup, fireEvent } from "@testing-library/react";
import { TestnetNotice } from "./TestnetNotice";

afterEach(cleanup);
beforeEach(() => localStorage.clear());

describe("TestnetNotice", () => {
  it("discloses that funds are not real and settlement is real zk proofs", () => {
    render(<TestnetNotice />);
    expect(screen.getByText(/funds are not real/i)).toBeTruthy();
    // The 2026-07-09 live migration replaced mocked proofs with real Groth16 —
    // the notice must disclose the real-proof posture and its settle lag.
    expect(screen.getByText(/real zk validity proofs/i)).toBeTruthy();
    expect(screen.getByText(/~10–20 min/)).toBeTruthy();
  });

  it("reveals the test-USDC mint instructions on demand", () => {
    render(<TestnetNotice />);
    expect(screen.queryByText(/mint\(address,uint256\)/)).toBeNull();
    fireEvent.click(screen.getByText(/get test usdc/i));
    expect(screen.getByText(/mint\(address,uint256\)/)).toBeTruthy();
    // SEC-019: the bare-cast deposit command is GONE (the vault would revert
    // it) — the notice must point at the gateway-authorized in-app flow instead.
    expect(screen.queryByText(/deposit\(uint256\)/)).toBeNull();
    expect(screen.getByText(/deposit\/authorize/)).toBeTruthy();
  });

  it("stays dismissed once acknowledged", () => {
    const { unmount } = render(<TestnetNotice />);
    fireEvent.click(screen.getByText(/got it/i));
    expect(screen.queryByText(/funds are not real/i)).toBeNull();
    unmount();
    render(<TestnetNotice />);
    expect(screen.queryByText(/funds are not real/i)).toBeNull();
  });
});

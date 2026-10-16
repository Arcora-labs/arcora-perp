import { describe, expect, it } from "vitest";
import { resolveContractAddress } from "./contractAddresses";
import { COLLATERAL_VAULT, MOCK_USDC } from "./wallet";

const FALLBACK = "0x57e951F6a378E00e4F1b26510380E089D7c07b8B";

describe("deploy-time contract addresses", () => {
  it("falls back to the recorded deployment when the variable is unset or empty", () => {
    expect(resolveContractAddress(undefined, FALLBACK, "VITE_COLLATERAL_VAULT")).toBe(FALLBACK);
    expect(resolveContractAddress("", FALLBACK, "VITE_COLLATERAL_VAULT")).toBe(FALLBACK);
  });

  it("uses a configured 20-byte address verbatim", () => {
    const next = "0x145ea184903401d6f313a0d589fe7624b69505c0";
    expect(resolveContractAddress(next, FALLBACK, "VITE_COLLATERAL_VAULT")).toBe(next);
  });

  it.each(["0x123", "57e951F6a378E00e4F1b26510380E089D7c07b8B", " 0x57e951F6a378E00e4F1b26510380E089D7c07b8B", "0x" + "zz".repeat(20)])(
    "refuses a malformed address instead of silently using it: %s", (value) => {
      expect(() => resolveContractAddress(value, FALLBACK, "VITE_COLLATERAL_VAULT")).toThrow(/VITE_COLLATERAL_VAULT/);
    },
  );

  it("keeps the July 11 Base Sepolia addresses when no override is built in", () => {
    expect(MOCK_USDC).toBe("0x8a52d127b556465F613766b903B717e19b3eaE7B");
    expect(COLLATERAL_VAULT).toBe(FALLBACK);
  });
});

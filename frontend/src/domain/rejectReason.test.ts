import { describe, it, expect } from "vitest";
import { REJECT_REASONS, describeRejectReason } from "./rejectReason";

describe("manifest reject reasons", () => {
  it("cover the stable codes 1..13 exactly once each", () => {
    const codes = Object.values(REJECT_REASONS).map((r) => r.code).sort((a, b) => a - b);
    expect(codes).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]);
  });

  it("names the minimum-size refusal with code 13", () => {
    expect(REJECT_REASONS.BelowMinimumSize.code).toBe(13);
    expect(describeRejectReason("BelowMinimumSize")).toMatch(/\$10 minimum order size/);
  });

  it("passes an unknown or non-manifest reason through unchanged", () => {
    expect(describeRejectReason("UserCancelled")).toBe("UserCancelled");
    expect(describeRejectReason("toString")).toBe("toString");
  });
});

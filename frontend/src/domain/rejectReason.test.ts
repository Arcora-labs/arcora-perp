import { describe, it, expect } from "vitest";
import { EXECUTION_REASONS, REJECT_REASONS, describeRejectReason, isExecutionReason } from "./rejectReason";

describe("manifest reject reasons", () => {
  it("cover the stable codes 1..13 exactly once each", () => {
    const codes = Object.values(REJECT_REASONS).map((r) => r.code).sort((a, b) => a - b);
    expect(codes).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]);
  });

  it("names the minimum-size refusal with code 13", () => {
    expect(REJECT_REASONS.BelowMinimumSize.code).toBe(13);
    expect(describeRejectReason("BelowMinimumSize")).toMatch(/\$10 minimum order size/);
  });

  it("explains an order whose settlement window was voided", () => {
    expect(describeRejectReason("WindowVoided")).toBe(
      "Its settlement window was voided; fills in it were undone.",
    );
    expect(Object.keys(EXECUTION_REASONS).filter((r) => r in REJECT_REASONS)).toEqual([]);
    expect(isExecutionReason("WindowVoided")).toBe(true);
    for (const other of ["Cancelled", "UserCancelled", "toString"]) expect(isExecutionReason(other)).toBe(false);
  });

  it("passes an unknown or non-manifest reason through unchanged", () => {
    expect(describeRejectReason("UserCancelled")).toBe("UserCancelled");
    expect(describeRejectReason("toString")).toBe("toString");
    expect(describeRejectReason("hasOwnProperty")).toBe("hasOwnProperty");
  });
});

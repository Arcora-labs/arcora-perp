import { describe, it, expect } from "vitest";
import { isWithdrawable, FINALITY_COPY, type Finality } from "./types";

// These lock the #1 "non-negotiable UX invariant" from the frontend README:
// MATCHED ≠ SETTLED. They are design-independent — whatever theme/markup the
// incoming design uses, the finality semantics it renders must stay these.

const ALL: Finality[] = ["ACCEPTED", "MATCHED", "SETTLED"];

describe("finality invariants (§3)", () => {
  it("ONLY SETTLED is withdrawable", () => {
    expect(isWithdrawable("SETTLED")).toBe(true);
    expect(isWithdrawable("ACCEPTED")).toBe(false);
    expect(isWithdrawable("MATCHED")).toBe(false);
  });

  it("MATCHED copy must NOT imply finality/withdrawability", () => {
    const hint = FINALITY_COPY.MATCHED.hint.toLowerCase();
    // it must call itself soft/preconfirmation and explicitly not-yet-withdrawable
    expect(hint).toMatch(/soft|preconfirmation|not final|good-faith/);
    expect(hint).toMatch(/not yet withdrawable|not.*withdrawable/);
  });

  it("SETTLED copy is the only one that claims hard finality / withdrawable", () => {
    expect(FINALITY_COPY.SETTLED.hint.toLowerCase()).toMatch(/hard finality|withdrawable/);
    // the non-final states must not claim plain "withdrawable" without negation
    for (const f of ["ACCEPTED", "MATCHED"] as Finality[]) {
      const h = FINALITY_COPY[f].hint.toLowerCase();
      const claimsWithdrawable = /(^|[^t])\bwithdrawable/.test(h) && !/not.*withdrawable/.test(h);
      expect(claimsWithdrawable).toBe(false);
    }
  });

  it("every finality state has copy and the labels are distinct", () => {
    const labels = ALL.map((f) => FINALITY_COPY[f].label);
    expect(new Set(labels).size).toBe(ALL.length);
    for (const f of ALL) {
      expect(FINALITY_COPY[f].label.length).toBeGreaterThan(0);
      expect(FINALITY_COPY[f].hint.length).toBeGreaterThan(0);
    }
  });
});

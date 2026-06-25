import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

// Guard the "reskin = token swap" invariant (see frontend/README.md). Every brand
// and semantic colour must live ONLY in the `:root` token block; everywhere else,
// colours must be referenced as `var(--token)` or derived with `color-mix(... var(--token) ...)`.
// A hard-coded copy outside `:root` would silently NOT follow a token override,
// breaking the design handoff — this test fails the moment one is reintroduced.

const css = readFileSync(
  fileURLToPath(new URL("./styles.css", import.meta.url)),
  "utf8",
);

/** The stylesheet with the single `:root { ... }` token block removed. */
function bodyOutsideRoot(): string {
  const start = css.indexOf(":root");
  const open = css.indexOf("{", start);
  // walk to the matching close brace of the :root block
  let depth = 0;
  let i = open;
  for (; i < css.length; i++) {
    if (css[i] === "{") depth++;
    else if (css[i] === "}" && --depth === 0) break;
  }
  return css.slice(0, start) + css.slice(i + 1);
}

describe("design-token discipline", () => {
  const body = bodyOutsideRoot();

  it("defines the token block exactly once", () => {
    expect(css.match(/:root\s*\{/g)?.length).toBe(1);
  });

  it("has no hex colour literals outside :root", () => {
    // #abc / #aabbcc / #aabbccdd — any hex colour is a brand value that belongs in a token
    const hex = body.match(/#[0-9a-fA-F]{3,8}\b/g) ?? [];
    expect(hex, `hard-coded hex outside :root: ${hex.join(", ")}`).toEqual([]);
  });

  it("has no brand-coloured rgb/rgba literals outside :root (neutral white/black overlays allowed)", () => {
    const rgba = body.match(/rgba?\([^)]*\)/g) ?? [];
    const brand = rgba.filter((c) => {
      const nums = c.match(/\d+(\.\d+)?/g)?.map(Number) ?? [];
      const [r, g, b] = nums;
      // allow only pure-neutral overlays: white (255,255,255) and black (0,0,0),
      // which are theme-independent depth/hover effects, not brand colour.
      const neutral = (r === 255 && g === 255 && b === 255) || (r === 0 && g === 0 && b === 0);
      return !neutral;
    });
    expect(brand, `brand-coloured rgba outside :root (use color-mix(var(--token))): ${brand.join(" | ")}`).toEqual([]);
  });

  it("derives translucent brand tints via color-mix on a token", () => {
    // sanity: the mechanism is actually in use (not that everything got deleted)
    expect(css).toMatch(/color-mix\(in srgb, var\(--\w[\w-]*\) \d+%, transparent\)/);
  });
});

// The production-surface tripwire (SEC-025-E1 Task 3).
//
// The gateway's production router (crates/gateway/src/main.rs `build_router`)
// mounts ONLY: `/api/state`, `/attest`, `/ws`, and the `/v1` surface MINUS the
// three `/v1/lp*` routes (SEC-025-C: the LP pool credits through an unbacked
// mint, so production neither mounts nor documents it). Every other legacy
// `/api/*` mutation route exists only in the demo build (audit DP-010).
//
// This scan asserts that NO production frontend source targets a route outside
// that mounted surface. It is the frontend sibling of the gateway's
// `unbacked_funding_has_exactly_the_known_call_sites` idiom, with two
// deliberate structural differences that close that idiom's known traps:
//
//  1. SELF-COUNTING. A source scan that includes its own file counts the route
//     names in its own prose/fixtures — naming a route in a new comment
//     inflates the very count it describes (that has failed an edit twice in
//     this workstream). This scan excludes `*.test.*` files entirely, which is
//     also the honest production boundary: test files are never imported by
//     `main.tsx`, so they are not in the shipped bundle. The fixture strings
//     in this file therefore cannot inflate anything.
//
//  2. PATTERN-COUNT vs CLASS. Asserting `count(needle) == N` pins the needles
//     you thought of; it does not fail when a NEW dead route appears. This
//     scan instead EXTRACTS every route-shaped token (`/api/...`, `/v1/...`)
//     from comment-stripped production source and requires each to be in the
//     mounted allowlist below — so a brand-new unmounted target fails the
//     build without this file ever having heard of it.
//
// The remaining legitimate `/api/*` occurrences in production source, named as
// the idiom requires (kept accurate by `the scanner sees the legitimate uses`
// below, which fails if they move):
//
//   - realClient.ts `bootstrap()` — `fetch(base + "/api/state")`: the initial
//     public snapshot. `/api/state` is mounted unconditionally in production
//     (`build_router`), and its LIQ-001 invariant keeps it serving ONLY the
//     shared public/demo state (it must never iterate real accounts).
//   - realClient.ts `bootstrap()` — the error string
//     "`gateway /api/state ${res.status}`" names the same mounted route.
//
// Everything else the client touches is `/v1/*` (all mounted in production)
// or `/ws` (mounted; single-segment, below this scan's token shape).

import { describe, it, expect } from "vitest";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const SRC_ROOT = fileURLToPath(new URL("..", import.meta.url));

/** Recursively collect production sources: *.ts / *.tsx, excluding tests. */
function productionSources(dir: string, out: { rel: string; text: string }[] = [], prefix = ""): { rel: string; text: string }[] {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.isDirectory()) {
      productionSources(join(dir, entry.name), out, rel);
      continue;
    }
    if (!/\.tsx?$/.test(entry.name)) continue;
    if (entry.name.includes(".test.")) continue; // never shipped; see header note 1
    out.push({ rel, text: readFileSync(join(dir, entry.name), "utf8") });
  }
  return out;
}

/**
 * Strip `//` and `/* *​/` comments while PRESERVING string/template-literal
 * contents (route targets are string literals — a comment merely mentions a
 * route, and a mention is not a target). Small state machine, biased so any
 * ambiguity KEEPS text: kept-too-much can only produce a loud false positive,
 * never silently hide a target. Template `${…}` interpolation is treated as
 * template content (a comment inside an interpolation survives — see bias).
 */
export function stripComments(src: string): string {
  let out = "";
  type Mode = "code" | "line" | "block" | "str";
  let mode: Mode = "code";
  let quote = "";
  for (let i = 0; i < src.length; i++) {
    const c = src[i];
    const n = src[i + 1];
    if (mode === "code") {
      if (c === "/" && n === "/") { mode = "line"; i++; continue; }
      if (c === "/" && n === "*") { mode = "block"; i++; continue; }
      if (c === '"' || c === "'" || c === "`") { mode = "str"; quote = c; }
      out += c;
    } else if (mode === "line") {
      if (c === "\n") { mode = "code"; out += c; }
    } else if (mode === "block") {
      if (c === "*" && n === "/") { mode = "code"; i++; }
    } else {
      // string/template: escapes never terminate; the matching quote does.
      if (c === "\\") { out += c + (n ?? ""); i++; continue; }
      if (c === quote) mode = "code";
      out += c;
    }
  }
  return out;
}

/**
 * Extract every gateway-route-shaped token from comment-stripped source.
 * Two patterns, unioned:
 *  - GENERAL: `/api/...` or `/v1/...` anywhere in code (including inside a
 *    larger string, e.g. an error message), as long as it is not part of a
 *    longer path (`(?<![.\w])` rejects `../api/client` import specifiers and
 *    external URLs like `…exchange/v1/public/get-tickers`, where the prefix
 *    is preceded by a word character).
 *  - LITERAL-START: a string literal that BEGINS with `/api/` or `/v1/`, with
 *    NO further requirement — this is the choke that catches dynamic assembly
 *    (`"/api/" + name` yields the token `/api/`, which no allowlist contains,
 *    so building routes dynamically fails the scan by construction: dynamic
 *    routes defeat source scanning and are refused outright).
 * Tokens stop at `${…}` interpolation, so `/v1/markets/${id}/oracle` yields
 * `/v1/markets` — the mounted parameterized prefix is what gets verified.
 */
export function extractRouteTokens(stripped: string): string[] {
  const tokens: string[] = [];
  const general = /(?<![.\w])\/(?:api|v1)\/[A-Za-z0-9_-]+(?:\/[A-Za-z0-9_-]+)*/g;
  const literalStart = /["'`](\/(?:api|v1)\/[A-Za-z0-9/_-]*)/g;
  for (const m of stripped.matchAll(general)) tokens.push(m[0]);
  for (const m of stripped.matchAll(literalStart)) {
    // the GENERAL pattern already reported non-empty tokens; keep only the
    // empty-tail form it cannot see (the dynamic-assembly choke)
    if (m[1] === "/api/" || m[1] === "/v1/") tokens.push(m[1]);
  }
  return tokens;
}

/**
 * The mounted production surface, token-shaped — derived from `build_router`
 * (crates/gateway/src/main.rs; the `if !prod` blocks there are the DEMO-only
 * routes and are deliberately NOT in this list: the eleven legacy `/api/*`
 * mutation routes and the three `/v1/lp*` routes). Parameterized mounts are
 * listed as their static prefix (`/v1/orders/:id` → `/v1/orders`), which is
 * exactly the token a template-literal target reduces to.
 */
const MOUNTED = new Set([
  "/api/state",
  "/v1/accounts",
  "/v1/accounts/me",
  "/v1/accounts/recovery",
  "/v1/accounts/deposit",
  "/v1/accounts/deposit/address",
  "/v1/accounts/deposit/authorize",
  "/v1/accounts/deposit/onchain",
  "/v1/accounts/withdraw",
  "/v1/accounts/withdrawals",
  "/v1/orders",
  "/v1/positions",
  "/v1/markets",
  "/v1/system/status",
  "/v1/admin/settlement/resume",
  "/v1/admin/insurance/bootstrap",
  "/v1/batch",
  "/v1/enclave/epoch",
  "/v1/openapi", // `/v1/openapi.json` — the token stops at the dot
  "/v1/ws",
]);
/** Parameterized mounts: a token below one of these prefixes is mounted too. */
const MOUNTED_PREFIXES = ["/v1/orders/", "/v1/markets/", "/v1/batch/", "/v1/accounts/recovery/"];

const isMounted = (t: string) =>
  MOUNTED.has(t) || MOUNTED_PREFIXES.some((p) => t.startsWith(p));

describe("production surface tripwire (SEC-025-E1 Task 3)", () => {
  const sources = productionSources(SRC_ROOT);

  it("the scan actually covers the production sources", () => {
    // A broken walk (wrong root, over-eager exclusion) must fail HERE, not
    // pass the allowlist test vacuously on zero files.
    expect(sources.length).toBeGreaterThanOrEqual(25);
    const names = sources.map((s) => s.rel);
    expect(names).toContain("api/realClient.ts");
    expect(names).toContain("components/LpVault.tsx");
    expect(names.some((n) => n.includes(".test."))).toBe(false);
  });

  it("no production path targets a route the production gateway does not mount", () => {
    const offenders: string[] = [];
    for (const { rel, text } of sources) {
      for (const token of extractRouteTokens(stripComments(text))) {
        if (!isMounted(token)) offenders.push(`${rel}: ${token}`);
      }
    }
    expect(
      offenders,
      `production frontend source targets route(s) the production gateway does not mount ` +
        `(build_router omits the legacy /api/* mutation routes and /v1/lp* — audit DP-010, ` +
        `SEC-025-C). A route that 404s is not a fallback: either the target is mounted in ` +
        `production, or the call site must be deleted/demo-gated with the refusal surfaced ` +
        `to the user. Offenders:\n  ${offenders.join("\n  ")}`,
    ).toEqual([]);
  });

  it("the scanner sees the legitimate uses (positive control)", () => {
    // If stripComments over-stripped (a lexer bug swallowing code) or the
    // extraction regressed, the allowlist test above could pass by seeing
    // NOTHING. Pin the two known-legitimate /api/state occurrences — both in
    // realClient.ts bootstrap(): the fetch target and its error string.
    const real = sources.find((s) => s.rel === "api/realClient.ts")!;
    const apiTokens = extractRouteTokens(stripComments(real.text)).filter((t) =>
      t.startsWith("/api/"),
    );
    expect(apiTokens.filter((t) => t === "/api/state").length).toBe(2);
  });

  // ── scanner self-tests: the discriminators discriminate ────────────────────
  // (Fixture strings here cannot inflate the production scan — test files are
  // excluded from it; see header note 1.)

  it("stripComments removes comments but PRESERVES string and template contents", () => {
    const kept = stripComments(`const a = "/api/kept"; const b = \`\${x}/api/kept2\`;`);
    expect(kept).toContain("/api/kept");
    expect(kept).toContain("/api/kept2");
    expect(stripComments(`// POST /api/dead\nconst x = 1;`)).not.toContain("/api/dead");
    expect(stripComments(`/* the legacy \`/api/dead\` route */ const x = 1;`)).not.toContain("/api/dead");
    // a `//` INSIDE a string is content, not a comment — the rest of the line
    // (including a route target) must survive
    const url = stripComments(`const u = "http://host"; const r = "/api/kept3";`);
    expect(url).toContain("/api/kept3");
  });

  it("extractRouteTokens finds targets, skips import specifiers and external URLs, and refuses dynamic assembly", () => {
    expect(extractRouteTokens(`fetch(base + "/api/close")`)).toEqual(["/api/close"]);
    expect(extractRouteTokens(`post("/v1/lp/deposit", body)`)).toEqual(["/v1/lp/deposit"]);
    // embedded in a larger string (an error message) still counts
    expect(extractRouteTokens("`gateway /api/state ${res.status}`")).toEqual(["/api/state"]);
    // template-literal target reduces to the mounted parameterized prefix
    expect(extractRouteTokens("`${this.base}/v1/markets/${id}/oracle`")).toEqual(["/v1/markets"]);
    // import specifiers and external URLs are NOT gateway route targets
    expect(extractRouteTokens(`import x from "../api/client";`)).toEqual([]);
    expect(extractRouteTokens(`"https://api.crypto.com/exchange/v1/public/get-tickers"`)).toEqual([]);
    // dynamic assembly yields the bare prefix, which no allowlist contains
    expect(extractRouteTokens(`post("/api/" + name)`)).toEqual(["/api/"]);
    expect(isMounted("/api/")).toBe(false);
    expect(isMounted("/v1/")).toBe(false);
    // and the demo-only routes are, of course, unmounted
    for (const dead of ["/api/cancel", "/api/close", "/api/deposit", "/api/withdraw", "/api/mode", "/api/simulate-adl", "/api/recover", "/api/lp/deposit", "/api/lp/withdraw", "/v1/lp", "/v1/lp/deposit", "/v1/lp/withdraw"]) {
      expect(isMounted(dead), dead).toBe(false);
    }
  });
});

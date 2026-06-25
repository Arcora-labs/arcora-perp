// Live oracle feed — connects the UI to a REAL price source (Crypto.com's public
// exchange API). This is the "oracle" the dark-perp design calls for (§8): a
// signed external index the matcher marks against. In production it is a Pyth /
// committee-attested transcript; here we poll Crypto.com's public REST `get-tickers`
// (no key required) and degrade gracefully to the internal random-walk if the
// network or CORS blocks it, so the UI always has a price.

import { PRICE_SCALE } from "../domain/types";

export interface LiveQuote {
  /// Last price, PRICE_SCALE-scaled (1e8).
  price: bigint;
  /// Best bid / ask, PRICE_SCALE-scaled (for a real spread in the book).
  bid: bigint;
  ask: bigint;
  /// 24h change as a fraction (e.g. -0.0123 = −1.23%).
  change24h: number;
}

const BASE = "https://api.crypto.com/exchange/v1/public/get-tickers";

/// Scale a decimal price string (e.g. "59575.14") to a PRICE_SCALE bigint without
/// floats: split on the dot and pad/truncate the fraction to 8 places.
export function scalePrice(decimal: string): bigint {
  const neg = decimal.startsWith("-");
  const s = neg ? decimal.slice(1) : decimal;
  const [whole, frac = ""] = s.trim().split(".");
  const fracPadded = (frac + "0".repeat(8)).slice(0, 8);
  const v = BigInt(whole || "0") * PRICE_SCALE + BigInt(fracPadded || "0");
  return neg ? -v : v;
}

interface TickerRow {
  i: string; // instrument
  a: string; // last
  b: string; // best bid
  k: string; // best ask
  c: string; // 24h change ratio
}

/// Fetch live quotes for the given Crypto.com instruments (e.g. "BTCUSD-PERP").
/// Returns a map instrument → quote. Throws on network/HTTP failure so the caller
/// can fall back. One request fetches every ticker; we filter to what we need.
/// Bounded by `timeoutMs` so a hung connection can never leave a pending poll.
export async function fetchLiveQuotes(
  instruments: string[],
  timeoutMs = 4000,
): Promise<Map<string, LiveQuote>> {
  const want = new Set(instruments);
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  let json: { result?: { data?: TickerRow[] } };
  try {
    const res = await fetch(BASE, { headers: { accept: "application/json" }, signal: ctrl.signal });
    if (!res.ok) throw new Error(`oracle feed HTTP ${res.status}`);
    json = (await res.json()) as { result?: { data?: TickerRow[] } };
  } finally {
    clearTimeout(timer);
  }
  const rows = json.result?.data ?? [];
  const out = new Map<string, LiveQuote>();
  for (const r of rows) {
    if (!want.has(r.i)) continue;
    // a single malformed row must not poison the whole feed
    try {
      const price = scalePrice(r.a);
      if (price <= 0n) continue;
      out.set(r.i, {
        price,
        bid: r.b ? scalePrice(r.b) : price,
        ask: r.k ? scalePrice(r.k) : price,
        change24h: Number(r.c) || 0,
      });
    } catch {
      continue;
    }
  }
  return out;
}

// Fixed-point formatting/parsing helpers. All on-wire amounts are scaled bigints
// (no floats), matching the Rust core; we only convert to/from strings for display
// and input, never carrying floats through logic.

import { PRICE_SCALE, QUOTE_SCALE, SIZE_SCALE } from "./types";

/// Insert thousands separators into an unsigned integer-digit string
/// ("1234567" → "1,234,567") — financial-UI readability, applied to the whole part.
function groupThousands(intDigits: string): string {
  return intDigits.replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

function fmtScaled(v: bigint, scale: bigint, decimals: number): string {
  const neg = v < 0n;
  let x = neg ? -v : v;
  const whole = x / scale;
  const frac = x % scale;
  // frac is in [0, scale); render `decimals` digits
  const fracStr = (frac * 10n ** BigInt(decimals) / scale)
    .toString()
    .padStart(decimals, "0");
  const sign = neg ? "-" : "";
  const wholeStr = groupThousands(whole.toString());
  return decimals > 0 ? `${sign}${wholeStr}.${fracStr}` : `${sign}${wholeStr}`;
}

export function formatUsd(quote: bigint, decimals = 2): string {
  return `$${fmtScaled(quote, QUOTE_SCALE, decimals)}`;
}

export function formatPrice(price: bigint, decimals = 2): string {
  return fmtScaled(price, PRICE_SCALE, decimals);
}

export function formatSize(size: bigint, decimals = 4): string {
  return fmtScaled(size, SIZE_SCALE, decimals);
}

export function formatSignedSize(size: bigint, decimals = 4): string {
  const s = formatSize(size < 0n ? -size : size, decimals);
  return size < 0n ? `-${s}` : size > 0n ? `+${s}` : s;
}

export function formatPct(fraction: number): string {
  return `${(fraction * 100).toFixed(2)}%`;
}

/// Parse a decimal string into a scaled bigint. Returns null on bad input.
export function parseScaled(input: string, scale: bigint): bigint | null {
  // strip thousands separators so display strings (and pasted "1,000") round-trip
  const t = input.trim().replace(/,/g, "");
  if (!/^\d*\.?\d*$/.test(t) || t === "" || t === ".") return null;
  const [whole, frac = ""] = t.split(".");
  const decimals = scale.toString().length - 1;
  const fracPadded = (frac + "0".repeat(decimals)).slice(0, decimals);
  return BigInt(whole || "0") * scale + BigInt(fracPadded || "0");
}

export const parsePrice = (s: string) => parseScaled(s, PRICE_SCALE);
export const parseSize = (s: string) => parseScaled(s, SIZE_SCALE);
export const parseUsd = (s: string) => parseScaled(s, QUOTE_SCALE);

/// Short hex display for hashes/addresses.
export function shortHash(h: string): string {
  if (h.length <= 12) return h;
  return `${h.slice(0, 6)}…${h.slice(-4)}`;
}

/// Base asset of a market symbol ("BTC/USDC" → "BTC"). Used to label size inputs
/// per-market so a multi-market UI never shows the wrong unit (e.g. "Size (BTC)"
/// while ETH is selected). Falls back to the whole symbol if there is no "/".
export function baseAsset(symbol: string): string {
  return symbol.split("/")[0] || symbol;
}

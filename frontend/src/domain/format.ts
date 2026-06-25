// Fixed-point formatting/parsing helpers. All on-wire amounts are scaled bigints
// (no floats), matching the Rust core; we only convert to/from strings for display
// and input, never carrying floats through logic.

import { PRICE_SCALE, QUOTE_SCALE, SIZE_SCALE } from "./types";

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
  return decimals > 0 ? `${sign}${whole}.${fracStr}` : `${sign}${whole}`;
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
  const t = input.trim();
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

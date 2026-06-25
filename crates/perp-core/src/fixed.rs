//! Fixed-point conventions.
//!
//! Determinism is non-negotiable: the same arithmetic must produce bit-identical
//! results when executed natively in the sequencer (§1) and inside a zkVM guest
//! (§4, §10b). Floating point is therefore forbidden everywhere in this crate.
//! All monetary, price, and size quantities are scaled integers.
//!
//! Scales (chosen to match common oracle / perp-DEX conventions):
//!
//! | quantity            | type   | scale  | 1 unit means        |
//! |---------------------|--------|--------|---------------------|
//! | quote (USD, PnL)    | `i128` | `1e6`  | 1 micro-USD         |
//! | price               | `i128` | `1e8`  | $1e-8 per base unit |
//! | size (base asset)   | `i128` | `1e8`  | 1e-8 base units     |
//! | funding index       | `i128` | `1e6`  | 1 micro-USD / base  |
//! | rate (bps-like)     | `i128` | `1e6`  | 1e-6 fraction       |
//!
//! Headroom: `i128` max ≈ 1.7e38. A $1M position at BTC=$1e5 is
//! `size≈1e9 · price≈1e13 = 1e22`, far inside range; intermediate products stay
//! below ~1e30 in practice. We still saturate-check the hot multiplications.

/// Scale for quote / collateral / PnL amounts (micro-USD).
pub const QUOTE_SCALE: i128 = 1_000_000;
/// Scale for prices.
pub const PRICE_SCALE: i128 = 100_000_000;
/// Scale for position sizes (base asset units).
pub const SIZE_SCALE: i128 = 100_000_000;
/// Scale for the cumulative funding index (micro-USD per base unit).
pub const FUNDING_SCALE: i128 = 1_000_000;
/// Scale for fractional rates (margin ratios, funding rates).
pub const RATE_SCALE: i128 = 1_000_000;

/// Convert a notional given as `size * price` into quote (micro-USD).
///
/// `size` is scaled by [`SIZE_SCALE`] and `price` by [`PRICE_SCALE`]; the raw
/// product therefore carries `SIZE_SCALE * PRICE_SCALE` of scale, and we want a
/// result carrying only `QUOTE_SCALE`.
///
/// Returns `None` on overflow rather than wrapping — a wrap would silently
/// violate collateral conservation, which is the one thing this whole system
/// exists to prevent.
#[inline]
pub fn notional_quote(size: i128, price: i128) -> Option<i128> {
    // divisor = SIZE_SCALE * PRICE_SCALE / QUOTE_SCALE = 1e8 * 1e8 / 1e6 = 1e10
    const DIVISOR: i128 = SIZE_SCALE * (PRICE_SCALE / QUOTE_SCALE);
    let raw = size.checked_mul(price)?;
    Some(raw / DIVISOR)
}

/// Multiply a quote amount by a [`RATE_SCALE`]-scaled fraction.
#[inline]
pub fn apply_rate(quote: i128, rate: i128) -> Option<i128> {
    quote.checked_mul(rate).map(|v| v / RATE_SCALE)
}

/// Absolute value that never panics (i128::MIN maps to i128::MAX).
#[inline]
pub fn abs(v: i128) -> i128 {
    if v == i128::MIN {
        i128::MAX
    } else {
        v.abs()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notional_of_one_btc_at_100k() {
        // 1.0 BTC, price $100,000.00
        let size = SIZE_SCALE; // 1.0
        let price = 100_000 * PRICE_SCALE; // $100k
                                           // expect $100,000 = 100_000 * QUOTE_SCALE micro-USD
        assert_eq!(notional_quote(size, price), Some(100_000 * QUOTE_SCALE));
    }

    #[test]
    fn notional_handles_fractional_size() {
        // 0.5 BTC at $80,000 = $40,000
        let size = SIZE_SCALE / 2;
        let price = 80_000 * PRICE_SCALE;
        assert_eq!(notional_quote(size, price), Some(40_000 * QUOTE_SCALE));
    }

    #[test]
    fn apply_rate_basic() {
        // 5% maintenance margin of $40,000 = $2,000
        let quote = 40_000 * QUOTE_SCALE;
        let rate = 50_000; // 0.05 * RATE_SCALE
        assert_eq!(apply_rate(quote, rate), Some(2_000 * QUOTE_SCALE));
    }
}

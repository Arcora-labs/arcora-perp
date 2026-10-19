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
    let raw = size.checked_mul(price)?;
    Some(raw / NOTIONAL_DIVISOR)
}

/// `SIZE_SCALE * PRICE_SCALE / QUOTE_SCALE = 1e8 * 1e8 / 1e6 = 1e10`: the scale a raw
/// `size * price` product carries beyond [`QUOTE_SCALE`].
const NOTIONAL_DIVISOR: i128 = SIZE_SCALE * (PRICE_SCALE / QUOTE_SCALE);

/// Multiply a quote amount by a [`RATE_SCALE`]-scaled fraction.
#[inline]
pub fn apply_rate(quote: i128, rate: i128) -> Option<i128> {
    quote.checked_mul(rate).map(|v| v / RATE_SCALE)
}

/// `a / d` rounded up, for `a >= 0` and `d > 0` (callers guarantee both). The `+ 1`
/// cannot overflow: `a / d <= i128::MAX / 2` for every divisor used here.
#[inline]
fn div_ceil_non_negative(a: i128, d: i128) -> i128 {
    a / d + i128::from(a % d != 0)
}

/// [`notional_quote`] rounded UP: the smallest quote amount that is at least the
/// exact notional. Margin requirements use it, so a non-zero size at a positive
/// price never needs zero margin.
///
/// Defined for non-negative inputs only: returns `None` when either input is
/// negative, or when the product overflows.
#[inline]
pub fn notional_quote_ceil(size: i128, price: i128) -> Option<i128> {
    if size < 0 || price < 0 {
        return None;
    }
    let raw = size.checked_mul(price)?;
    Some(div_ceil_non_negative(raw, NOTIONAL_DIVISOR))
}

/// [`apply_rate`] rounded UP: the smallest quote amount that is at least
/// `quote * rate / RATE_SCALE`.
///
/// Defined for non-negative inputs only: returns `None` when either input is
/// negative, or when the product overflows.
#[inline]
pub fn apply_rate_ceil(quote: i128, rate: i128) -> Option<i128> {
    if quote < 0 || rate < 0 {
        return None;
    }
    let raw = quote.checked_mul(rate)?;
    Some(div_ceil_non_negative(raw, RATE_SCALE))
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
    fn notional_ceil_rounds_a_fractional_notional_up() {
        // 1e-8 base at $50: the exact notional is 0.5 micro-USD.
        assert_eq!(notional_quote(1, 50 * PRICE_SCALE), Some(0));
        assert_eq!(notional_quote_ceil(1, 50 * PRICE_SCALE), Some(1));
        // 1e-8 base at $150: 1.5 micro-USD.
        assert_eq!(notional_quote(1, 150 * PRICE_SCALE), Some(1));
        assert_eq!(notional_quote_ceil(1, 150 * PRICE_SCALE), Some(2));
        // 1.5e-6 base at $1 is 1.5 micro-USD → 2; an exact multiple is unchanged.
        assert_eq!(notional_quote_ceil(150, PRICE_SCALE), Some(2));
        assert_eq!(notional_quote_ceil(200, PRICE_SCALE), Some(2));
        assert_eq!(
            notional_quote_ceil(SIZE_SCALE, 100_000 * PRICE_SCALE),
            Some(100_000 * QUOTE_SCALE)
        );
        // zero stays zero
        assert_eq!(notional_quote_ceil(0, 100_000 * PRICE_SCALE), Some(0));
        assert_eq!(notional_quote_ceil(SIZE_SCALE, 0), Some(0));
    }

    #[test]
    fn rate_ceil_rounds_a_fractional_product_up() {
        // 5% of 1 micro-USD is 0.05 micro-USD → 1; floor gives 0.
        assert_eq!(apply_rate(1, RATE_SCALE / 20), Some(0));
        assert_eq!(apply_rate_ceil(1, RATE_SCALE / 20), Some(1));
        // exact products are unchanged
        assert_eq!(
            apply_rate_ceil(40_000 * QUOTE_SCALE, 50_000),
            Some(2_000 * QUOTE_SCALE)
        );
        assert_eq!(apply_rate_ceil(0, RATE_SCALE), Some(0));
        assert_eq!(apply_rate_ceil(7, 0), Some(0));
    }

    #[test]
    fn ceil_helpers_refuse_negative_inputs_and_overflow() {
        assert_eq!(notional_quote_ceil(-1, PRICE_SCALE), None);
        assert_eq!(notional_quote_ceil(1, -PRICE_SCALE), None);
        assert_eq!(notional_quote_ceil(i128::MAX, 2), None);
        assert_eq!(apply_rate_ceil(-1, RATE_SCALE), None);
        assert_eq!(apply_rate_ceil(1, -1), None);
        assert_eq!(apply_rate_ceil(i128::MAX, 2), None);
        // the largest non-overflowing products still round without wrapping
        assert_eq!(
            notional_quote_ceil(i128::MAX, 1),
            Some(i128::MAX / NOTIONAL_DIVISOR + 1)
        );
        assert_eq!(
            apply_rate_ceil(i128::MAX, 1),
            Some(i128::MAX / RATE_SCALE + 1)
        );
    }

    /// Against the exact rational value: the ceil result is the smallest integer
    /// at or above it, and differs from the floor result by at most one.
    #[test]
    fn ceil_helpers_match_the_exact_quotient() {
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for _ in 0..20_000 {
            let size = (next() % (1 << 40)) as i128;
            let price = (next() % (1 << 50)) as i128;
            let raw = size * price;
            let c = notional_quote_ceil(size, price).unwrap();
            assert!(c * NOTIONAL_DIVISOR >= raw);
            assert!(c == 0 || (c - 1) * NOTIONAL_DIVISOR < raw);
            let f = notional_quote(size, price).unwrap();
            assert!(c - f <= 1 && c >= f);

            let quote = (next() % (1 << 60)) as i128;
            let rate = (next() % (2 * RATE_SCALE as u64)) as i128;
            let raw = quote * rate;
            let c = apply_rate_ceil(quote, rate).unwrap();
            assert!(c * RATE_SCALE >= raw);
            assert!(c == 0 || (c - 1) * RATE_SCALE < raw);
            let f = apply_rate(quote, rate).unwrap();
            assert!(c - f <= 1 && c >= f);
        }
    }

    #[test]
    fn apply_rate_basic() {
        // 5% maintenance margin of $40,000 = $2,000
        let quote = 40_000 * QUOTE_SCALE;
        let rate = 50_000; // 0.05 * RATE_SCALE
        assert_eq!(apply_rate(quote, rate), Some(2_000 * QUOTE_SCALE));
    }
}

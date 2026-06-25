//! Live oracle adapter (§8): turns a real exchange ticker into the protocol's
//! [`OracleTranscript`] — the signed price the engine marks, liquidates, and funds
//! against. The conversion (decimal price strings → fixed-point, spread → confidence
//! band, mid → backup TWAP) is a pure, offline-testable function; the optional
//! `http` feature adds a live fetch from Crypto.com's public REST API.
//!
//! This is the backend counterpart to the frontend's `oracleFeed.ts`: both feed the
//! SAME `OracleTranscript` shape, so swapping the source (Crypto.com now, Pyth /
//! committee-attested later) is a parser change, not an architecture change.

use perp_core::fixed::PRICE_SCALE;
use perp_core::oracle::OracleTranscript;

/// Parse a decimal price string (e.g. "59585.60") into a [`PRICE_SCALE`] i128,
/// without floats. Returns `None` on malformed input or overflow.
pub fn parse_price(s: &str) -> Option<i128> {
    let s = s.trim();
    let neg = s.starts_with('-');
    let body = s.strip_prefix('-').unwrap_or(s);
    let (whole, frac) = body.split_once('.').unwrap_or((body, ""));
    let whole: i128 = if whole.is_empty() {
        0
    } else {
        whole.parse().ok()?
    };
    if !frac.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let mut fp = frac.to_string();
    fp.truncate(8);
    while fp.len() < 8 {
        fp.push('0');
    }
    let frac_val: i128 = if fp.is_empty() { 0 } else { fp.parse().ok()? };
    let v = whole.checked_mul(PRICE_SCALE)?.checked_add(frac_val)?;
    Some(if neg { -v } else { v })
}

/// Build an [`OracleTranscript`] from a ticker's last/bid/ask decimal strings at
/// `now_ms`. Confidence is the bid/ask spread (the live uncertainty band); the
/// backup TWAP is the mid. Returns `None` if the last price is unparseable / ≤ 0.
pub fn transcript_from_ticker(
    last: &str,
    bid: &str,
    ask: &str,
    now_ms: u64,
) -> Option<OracleTranscript> {
    let price = parse_price(last)?;
    if price <= 0 {
        return None;
    }
    let b = parse_price(bid).unwrap_or(price);
    let a = parse_price(ask).unwrap_or(price);
    let spread = (a - b).abs();
    let mid = if a > 0 && b > 0 { (a + b) / 2 } else { price };
    Some(OracleTranscript {
        price,
        publish_time_ms: now_ms,
        // a tiny floor so a zero-spread snapshot still has a non-zero band
        confidence: spread.max(price / 1_000_000),
        backup_twap: mid,
    })
}

/// Live fetch (opt-in `http`): pull a single instrument's ticker from Crypto.com's
/// public REST API and convert it to an [`OracleTranscript`]. `now_ms` stamps it.
#[cfg(feature = "http")]
pub fn fetch_transcript(instrument: &str, now_ms: u64) -> Result<OracleTranscript, String> {
    let url = format!(
        "https://api.crypto.com/exchange/v1/public/get-tickers?instrument_name={instrument}"
    );
    let body: serde_json::Value = ureq::get(&url)
        .call()
        .map_err(|e| e.to_string())?
        .into_json()
        .map_err(|e| e.to_string())?;
    let row = body["result"]["data"]
        .get(0)
        .ok_or_else(|| "no ticker data".to_string())?;
    let get = |k: &str| row[k].as_str().unwrap_or("").to_string();
    transcript_from_ticker(&get("a"), &get("b"), &get("k"), now_ms)
        .ok_or_else(|| "unparseable ticker".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use perp_core::market::Market;

    #[test]
    fn parses_decimal_prices_exactly() {
        assert_eq!(parse_price("59585.60"), Some(5_958_560_000_000));
        assert_eq!(parse_price("66.44"), Some(66 * PRICE_SCALE + 44_000_000));
        assert_eq!(parse_price("1"), Some(PRICE_SCALE));
        assert_eq!(parse_price("0.00000001"), Some(1));
        assert_eq!(parse_price("1.123456789"), Some(PRICE_SCALE + 12_345_678)); // 9th dropped
        assert_eq!(parse_price("bogus"), None);
        assert_eq!(parse_price("1.2x"), None);
    }

    #[test]
    fn builds_a_valid_transcript_that_passes_the_oracle_gate() {
        // real BTCUSD-PERP snapshot: last 59585.6, bid 59586.7, ask 59586.8
        let t = transcript_from_ticker("59585.6", "59586.7", "59586.8", 1_000).unwrap();
        assert_eq!(t.price, 5_958_560_000_000);
        assert_eq!(
            t.backup_twap,
            (parse_price("59586.7").unwrap() + parse_price("59586.8").unwrap()) / 2
        );
        assert!(t.confidence > 0);
        // it must clear the engine's §8 sanity gate at its own publish time
        assert_eq!(t.validate(&Market::conservative(0), 1_000), Ok(t.price));
    }

    #[test]
    fn rejects_nonpositive_or_unparseable_last() {
        assert!(transcript_from_ticker("0", "1", "1", 1).is_none());
        assert!(transcript_from_ticker("-5", "1", "1", 1).is_none());
        assert!(transcript_from_ticker("bad", "1", "1", 1).is_none());
    }

    // --- adversarial: a malformed/manipulated external feed must NEVER become a
    // silently-trusted mark. The adapter does not "fix" the feed; it builds the
    // transcript faithfully and lets the §8 gate reject it. These lock that the
    // fail-safe actually triggers for adapter-produced transcripts, not just for
    // hand-built ones in oracle.rs.

    #[test]
    fn fat_finger_last_outside_the_book_is_rejected_by_the_gate() {
        use perp_core::oracle::OracleError;
        // `last` is a stale / fat-finger print ~17% above a tight, current book.
        // backup_twap = book mid, so the deviation gate refuses to mark against it.
        let m = Market::conservative(0);
        let t = transcript_from_ticker("70000", "59586.7", "59586.8", 1_000).unwrap();
        assert_eq!(
            t.validate(&m, 1_000),
            Err(OracleError::DeviatesFromBackup),
            "a last-trade far outside the current book must not become a mark"
        );
    }

    #[test]
    fn absurd_spread_book_is_rejected_by_the_gate() {
        // a glitched / manipulated book with a giant spread → giant confidence
        // band → the §8 confidence gate rejects it (garbage book never marks).
        let m = Market::conservative(0);
        let t = transcript_from_ticker("59585.6", "30000", "90000", 1_000).unwrap();
        assert!(
            t.validate(&m, 1_000).is_err(),
            "a book with an absurd spread must be rejected, not marked"
        );
    }

    #[test]
    fn a_book_outage_falls_back_to_last_and_still_marks() {
        // bid/ask unparseable (a book outage): the adapter falls back to `last`
        // for both the band floor and the TWAP, so a healthy last still produces
        // a transcript that clears the gate (graceful degradation, not a stall).
        let m = Market::conservative(0);
        let t = transcript_from_ticker("59585.6", "", "", 1_000).unwrap();
        assert_eq!(t.backup_twap, t.price);
        assert_eq!(t.validate(&m, 1_000), Ok(t.price));
    }
}

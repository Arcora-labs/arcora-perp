//! Live oracle adapter (§8): turns a real exchange ticker into the protocol's
//! [`OracleTranscript`] — the signed price the engine marks, liquidates, and funds
//! against. The conversion (decimal price strings → fixed-point, spread → confidence
//! band, mid → backup TWAP) is a pure, offline-testable function; the optional
//! `http` feature adds a live fetch from Crypto.com's public REST API.
//!
//! This is the backend counterpart to the frontend's `oracleFeed.ts`: both feed the
//! SAME `OracleTranscript` shape, so swapping the source (Crypto.com now, Pyth /
//! committee-attested later) is a parser change, not an architecture change.

use k256::ecdsa::SigningKey;
use perp_core::fixed::PRICE_SCALE;
use perp_core::oracle::{oracle_digest, OracleSig, OracleTranscript};

/// ZK-001 (Task 5) dev/test default for the oracle-publisher signing key. NEVER use
/// it on a real deployment — the operator must set `ORACLE_SIGNER_KEY` to a SECRET
/// scalar and pin its address as each `Market.oracle_pubkey`. This fixed scalar
/// (well-known Anvil account #1) only exists so the demo probe + unit tests have a
/// working publisher signer without provisioning secrets.
const DEV_ORACLE_SIGNER_KEY: [u8; 32] = [
    0x59, 0xc6, 0x99, 0x5e, 0x99, 0x8f, 0x97, 0xa5, 0xa0, 0x04, 0x49, 0x66, 0xf0, 0x94, 0x53, 0x89,
    0xdc, 0x9e, 0x86, 0xda, 0xe8, 0x8c, 0x7a, 0x84, 0x12, 0xf4, 0x60, 0x3b, 0x6b, 0x78, 0x69, 0x0d,
];

/// The 20-byte Ethereum address a publisher `signer`'s signatures recover to — the
/// value the operator must set as `Market.oracle_pubkey` for the §8 gate to admit
/// this feed's prices. Derived through the REAL perp-core path (sign a fixed probe
/// digest, then [`OracleSig::recover`]) so it is byte-identical to the address
/// `OracleTranscript::validate` compares against — no separate keccak re-derivation.
pub fn signer_address(signer: &SigningKey) -> [u8; 20] {
    let probe = oracle_digest(0, 0, 0, 0, 0);
    OracleSig::sign(signer, &probe)
        .recover(&probe)
        .expect("a freshly-produced signature always recovers")
}

/// Resolve the oracle-publisher signing key AND whether the public dev default was
/// taken — the fail-closed, boot-time provenance check (mirrors the gateway's
/// `enclave_seed_from_env`). `is_default == true` iff `ORACLE_SIGNER_KEY` was UNSET and
/// the [`DEV_ORACLE_SIGNER_KEY`] fallback (well-known Anvil account #1, a PUBLISHED
/// scalar) was used. A SET-but-malformed / invalid key STILL fails closed with an `Err`
/// (the caller exits) — it is NOT reported as `is_default` — so a mistyped secret is
/// refused, never silently swapped for the dev key. This lets a caller refuse an UNSET
/// key in production BEFORE it pins every `Market.oracle_pubkey` to a public address.
/// Silent by design (no boot log): the address is logged by [`signer_from_env`] at the
/// actual load, so this up-front check does not double-print it.
pub fn signer_from_env_checked() -> Result<(SigningKey, bool), String> {
    let (key, is_default) = match std::env::var("ORACLE_SIGNER_KEY") {
        Ok(s) => (
            parse_hex32(&s).ok_or("ORACLE_SIGNER_KEY is set but is not a 32-byte hex value")?,
            false,
        ),
        Err(_) => (DEV_ORACLE_SIGNER_KEY, true),
    };
    let signer = SigningKey::from_slice(&key)
        .map_err(|e| format!("ORACLE_SIGNER_KEY is not a valid secp256k1 scalar: {e}"))?;
    Ok((signer, is_default))
}

/// Load the oracle-publisher signing key from the environment (mirrors SEC-019's
/// `GatewaySigner::from_env`): `ORACLE_SIGNER_KEY` is a `0x`-optional 32-byte hex
/// secp256k1 scalar. Unset ⇒ the documented [`DEV_ORACLE_SIGNER_KEY`] (fine for the
/// demo build / tests); SET-but-malformed fails closed with an `Err` (the caller
/// exits) rather than silently signing with the dev key. Prints the derived address
/// at construction so the operator can pin it as `Market.oracle_pubkey`.
///
/// Whether the dev default was taken is dropped here — a caller that must REFUSE the
/// public dev key in production (the gateway) uses [`signer_from_env_checked`] instead.
pub fn signer_from_env() -> Result<SigningKey, String> {
    let (signer, _is_default) = signer_from_env_checked()?;
    println!(
        "[oracle-feed] publisher signer address 0x{} — set each Market.oracle_pubkey to this",
        hex20(&signer_address(&signer))
    );
    Ok(signer)
}

/// Byte-safe `0x`-optional 64-hex → 32-byte parse (same posture as the gateway's
/// `parse_hex32`): a non-ASCII / wrong-length string yields a clean `None`.
fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    let h = s.strip_prefix("0x").unwrap_or(s).as_bytes();
    if h.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = hex_nibble(h[i * 2])? << 4 | hex_nibble(h[i * 2 + 1])?;
    }
    Some(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Lowercase hex of a 20-byte address, for the boot-log line.
fn hex20(a: &[u8; 20]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(40);
    for b in a {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Overall per-request timeout for a live fetch. ureq's default agent has NO read
/// timeout, so a black-hole connection (TCP up, no response bytes) would block the
/// poll thread forever; bounding it keeps a hung feed from stalling the poll loop
/// (and, since freshness now advances only on a successful fetch, lets the market go
/// cleanly stale instead of freezing the gateway) (audit review).
#[cfg(feature = "http")]
const FETCH_TIMEOUT_SECS: u64 = 5;

/// Parse a decimal price string (e.g. "59585.60") into a [`PRICE_SCALE`] i128,
/// without floats. Returns `None` on malformed input or overflow.
pub fn parse_price(s: &str) -> Option<i128> {
    let s = s.trim();
    let neg = s.starts_with('-');
    let body = s.strip_prefix('-').unwrap_or(s);
    let (whole, frac) = body.split_once('.').unwrap_or((body, ""));
    // A string with no digits at all ("", "-", ".", "-.") is ABSENT, not zero —
    // returning None lets callers (transcript_from_ticker) fall a missing bid/ask
    // back to `last` via unwrap_or, instead of reading an empty side as a literal 0
    // and computing a giant spurious spread that the §8 gate would reject.
    if whole.is_empty() && frac.is_empty() {
        return None;
    }
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
///
/// ZK-001 (Task 5): the produced transcript carries the publisher's signature over
/// `oracle_digest(market_id, price, publish_time_ms, confidence, backup_twap)` —
/// signed LAST, over the FINAL field values, with the operator-held `signer` — so
/// the price handed to the prover already recovers to the market's `oracle_pubkey`
/// and clears [`OracleTranscript::validate`]'s fail-closed signature gate. The
/// digest is produced by CALLING [`perp_core::oracle::oracle_digest`] (never
/// re-implemented) so the guest's in-circuit re-hash is byte-identical.
pub fn transcript_from_ticker(
    last: &str,
    bid: &str,
    ask: &str,
    now_ms: u64,
    market_id: u64,
    signer: &SigningKey,
) -> Option<OracleTranscript> {
    let price = parse_price(last)?;
    if price <= 0 {
        return None;
    }
    let b = parse_price(bid).unwrap_or(price);
    let a = parse_price(ask).unwrap_or(price);
    let spread = (a - b).abs();
    let mid = if a > 0 && b > 0 { (a + b) / 2 } else { price };
    let publish_time_ms = now_ms;
    // a tiny floor so a zero-spread snapshot still has a non-zero band
    let confidence = spread.max(price / 1_000_000);
    let backup_twap = mid;
    // Sign LAST, over the digest of the FINAL field values (signing stale/pre-mutation
    // values would make `validate` reject). The digest comes from perp-core's own
    // word-encoding — a hand-rolled keccak here would recover to the wrong address.
    let digest = oracle_digest(market_id, price, publish_time_ms, confidence, backup_twap);
    Some(OracleTranscript {
        price,
        publish_time_ms,
        confidence,
        backup_twap,
        signature: OracleSig::sign(signer, &digest),
    })
}

/// Choose a transcript's publish time. Prefer the exchange's OWN ticker timestamp
/// (`t`) so a frozen-but-responsive feed (HTTP 200, stale price) trips the §8
/// staleness gate instead of being re-stamped fresh forever. Never let a
/// clock-skewed future timestamp exceed local `now_ms` (the gate rejects a
/// publish time in the future); fall back to `now_ms` when the exchange omits `t`.
pub fn publish_ms(exchange_t: Option<u64>, now_ms: u64) -> u64 {
    match exchange_t {
        Some(t) => t.min(now_ms),
        None => now_ms,
    }
}

/// Live fetch (opt-in `http`): pull a single instrument's ticker from Crypto.com's
/// public REST API and convert it to an [`OracleTranscript`]. The transcript is
/// stamped with the exchange's own ticker timestamp (falling back to `now_ms`), so
/// a frozen feed goes stale rather than reading as perpetually fresh.
#[cfg(feature = "http")]
pub fn fetch_transcript(
    instrument: &str,
    now_ms: u64,
    market_id: u64,
    signer: &SigningKey,
) -> Result<OracleTranscript, String> {
    let url = format!(
        "https://api.crypto.com/exchange/v1/public/get-tickers?instrument_name={instrument}"
    );
    let body: serde_json::Value = ureq::get(&url)
        .timeout(std::time::Duration::from_secs(FETCH_TIMEOUT_SECS))
        .call()
        .map_err(|e| e.to_string())?
        .into_json()
        .map_err(|e| e.to_string())?;
    let row = body["result"]["data"]
        .get(0)
        .ok_or_else(|| "no ticker data".to_string())?;
    let get = |k: &str| row[k].as_str().unwrap_or("").to_string();
    let publish = publish_ms(row["t"].as_u64(), now_ms);
    transcript_from_ticker(&get("a"), &get("b"), &get("k"), publish, market_id, signer)
        .ok_or_else(|| "unparseable ticker".to_string())
}

/// One historical OHLC bar from the exchange, [`PRICE_SCALE`]-scaled — the raw
/// material for backfilling a market's REAL price history (the chart's past bars).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeedCandle {
    /// Bar start, unix ms.
    pub start_ms: u64,
    pub open: i128,
    pub high: i128,
    pub low: i128,
    pub close: i128,
}

/// Parse a Crypto.com `public/get-candlestick` response body into candles
/// (ascending by time). Pure — hermetically testable without the network.
#[cfg(feature = "http")]
pub fn parse_candles(body: &serde_json::Value) -> Result<Vec<FeedCandle>, String> {
    let rows = body["result"]["data"]
        .as_array()
        .ok_or_else(|| "no candlestick data".to_string())?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let s = |k: &str| row[k].as_str().unwrap_or("");
        let (Some(open), Some(high), Some(low), Some(close)) = (
            parse_price(s("o")),
            parse_price(s("h")),
            parse_price(s("l")),
            parse_price(s("c")),
        ) else {
            continue; // skip a malformed row rather than poisoning the whole backfill
        };
        let Some(start_ms) = row["t"].as_u64() else {
            continue;
        };
        out.push(FeedCandle {
            start_ms,
            open,
            high,
            low,
            close,
        });
    }
    out.sort_by_key(|c| c.start_ms);
    Ok(out)
}

/// Live fetch (opt-in `http`): historical candles for `instrument` at a Crypto.com
/// `timeframe` (`M1`/`M5`/`M15`/`H1`/`H4`/`D1`), ascending, at most `count` bars.
#[cfg(feature = "http")]
pub fn fetch_candles(
    instrument: &str,
    timeframe: &str,
    count: usize,
) -> Result<Vec<FeedCandle>, String> {
    let url = format!(
        "https://api.crypto.com/exchange/v1/public/get-candlestick?instrument_name={instrument}&timeframe={timeframe}&count={count}"
    );
    let body: serde_json::Value = ureq::get(&url)
        .timeout(std::time::Duration::from_secs(FETCH_TIMEOUT_SECS))
        .call()
        .map_err(|e| e.to_string())?
        .into_json()
        .map_err(|e| e.to_string())?;
    parse_candles(&body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use perp_core::market::Market;

    // A fixed dev/test signing key + market id every transcript-building test signs
    // with, so the produced signature is deterministic and the assertions stay DRY.
    const TEST_MARKET_ID: u64 = 0;

    fn test_signer() -> SigningKey {
        SigningKey::from_slice(&DEV_ORACLE_SIGNER_KEY).expect("valid dev scalar")
    }

    /// Build a transcript signed by the shared test key for `TEST_MARKET_ID`.
    fn signed_transcript(
        last: &str,
        bid: &str,
        ask: &str,
        now_ms: u64,
    ) -> Option<OracleTranscript> {
        transcript_from_ticker(last, bid, ask, now_ms, TEST_MARKET_ID, &test_signer())
    }

    /// A conservative market whose `oracle_pubkey` is the shared test signer's address,
    /// so the ZK-001 signature gate PASSES and the price-sanity gates (which these tests
    /// actually exercise) are what decides the outcome.
    fn test_market() -> Market {
        let mut m = Market::conservative(TEST_MARKET_ID);
        m.oracle_pubkey = signer_address(&test_signer());
        m
    }

    // ZK-001 (Task 5): the adapter must attach a publisher signature the §8 gate
    // accepts — the price fed to the prover already carries the publisher's
    // attestation. Round-trips through the REAL perp-core path: the produced
    // signature recovers to the signer's address AND the transcript validates under
    // a market whose `oracle_pubkey` is that address.
    #[test]
    fn produced_transcript_signature_recovers_to_signer() {
        let key = test_signer();
        let addr = signer_address(&key);
        let t =
            transcript_from_ticker("59585.6", "59586.7", "59586.8", 1_000, TEST_MARKET_ID, &key)
                .unwrap();
        // recompute the digest exactly as the guest would, from the FINAL field values
        let d = perp_core::oracle::oracle_digest(
            TEST_MARKET_ID,
            t.price,
            t.publish_time_ms,
            t.confidence,
            t.backup_twap,
        );
        assert_eq!(
            t.signature.recover(&d),
            Some(addr),
            "the produced signature must recover to the signer's address"
        );
        // and it validates under a market whose oracle_pubkey == addr
        let mut m = Market::conservative(TEST_MARKET_ID);
        m.oracle_pubkey = addr;
        assert_eq!(
            t.validate(&m, t.publish_time_ms),
            Ok(t.price),
            "a matching oracle_pubkey admits the price through the §8 gate"
        );
    }

    #[test]
    fn parses_decimal_prices_exactly() {
        assert_eq!(parse_price("59585.60"), Some(5_958_560_000_000));
        assert_eq!(parse_price("66.44"), Some(66 * PRICE_SCALE + 44_000_000));
        assert_eq!(parse_price("1"), Some(PRICE_SCALE));
        assert_eq!(parse_price("0.00000001"), Some(1));
        assert_eq!(parse_price("1.123456789"), Some(PRICE_SCALE + 12_345_678)); // 9th dropped
        assert_eq!(parse_price("bogus"), None);
        assert_eq!(parse_price("1.2x"), None);
        // a digit-less string is ABSENT (None), not a silent zero — so a missing
        // bid/ask falls back to `last` rather than reading as 0.
        assert_eq!(parse_price(""), None);
        assert_eq!(parse_price("   "), None);
        assert_eq!(parse_price("."), None);
        assert_eq!(parse_price("-"), None);
        // but a real zero (with a digit) is still a valid 0
        assert_eq!(parse_price("0"), Some(0));
        assert_eq!(parse_price("0.0"), Some(0));
        assert_eq!(parse_price(".5"), Some(PRICE_SCALE / 2));
    }

    #[test]
    fn builds_a_valid_transcript_that_passes_the_oracle_gate() {
        // real BTCUSD-PERP snapshot: last 59585.6, bid 59586.7, ask 59586.8
        let t = signed_transcript("59585.6", "59586.7", "59586.8", 1_000).unwrap();
        assert_eq!(t.price, 5_958_560_000_000);
        assert_eq!(
            t.backup_twap,
            (parse_price("59586.7").unwrap() + parse_price("59586.8").unwrap()) / 2
        );
        assert!(t.confidence > 0);
        // it must clear the engine's §8 sanity gate at its own publish time
        assert_eq!(t.validate(&test_market(), 1_000), Ok(t.price));
    }

    // AUDIT (oracle staleness): the transcript must be stamped with the exchange's
    // own timestamp so a frozen-but-responsive feed goes stale, not re-stamped fresh.
    #[test]
    fn publish_time_prefers_exchange_timestamp_but_never_future() {
        // a PAST exchange timestamp is used verbatim → a frozen feed will go stale
        assert_eq!(publish_ms(Some(1_000), 9_000), 1_000);
        // a FUTURE exchange timestamp (clock skew) is clamped to now (the gate rejects
        // a publish time in the future)
        assert_eq!(publish_ms(Some(9_000), 5_000), 5_000);
        // no exchange timestamp → fall back to now
        assert_eq!(publish_ms(None, 5_000), 5_000);
    }

    #[test]
    fn a_frozen_exchange_timestamp_goes_stale_at_the_gate() {
        use perp_core::oracle::OracleError;
        let m = test_market(); // max_oracle_staleness_ms = 10s
                               // exchange published this tick at t = 1_000ms
        let t = signed_transcript("59585.6", "59586.7", "59586.8", 1_000).unwrap();
        assert_eq!(
            t.validate(&m, 6_000),
            Ok(t.price),
            "fresh within the 10s window"
        );
        assert_eq!(
            t.validate(&m, 12_000),
            Err(OracleError::Stale),
            "a feed frozen at t=1000 is stale 11s later, even if it still returns HTTP 200",
        );
    }

    #[test]
    fn rejects_nonpositive_or_unparseable_last() {
        assert!(signed_transcript("0", "1", "1", 1).is_none());
        assert!(signed_transcript("-5", "1", "1", 1).is_none());
        assert!(signed_transcript("bad", "1", "1", 1).is_none());
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
        let m = test_market();
        let t = signed_transcript("70000", "59586.7", "59586.8", 1_000).unwrap();
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
        let m = test_market();
        let t = signed_transcript("59585.6", "30000", "90000", 1_000).unwrap();
        assert!(
            t.validate(&m, 1_000).is_err(),
            "a book with an absurd spread must be rejected, not marked"
        );
    }

    #[test]
    fn one_sided_book_outage_falls_back_to_last_and_still_marks() {
        // Only ONE side of the book drops (ask feed momentarily empty, bid present).
        // Graceful degradation must fall the missing side back to `last`, not treat
        // the empty string as a literal 0 — which would make spread = |0 − bid| a
        // huge spurious band and get the whole transcript rejected by the §8 gate,
        // stalling the mark on a perfectly healthy `last`.
        let m = test_market();
        let t = signed_transcript("59585.6", "59586.7", "", 1_000).unwrap();
        assert_eq!(
            t.validate(&m, 1_000),
            Ok(t.price),
            "a one-sided book outage must still mark against a healthy last"
        );
    }

    #[test]
    fn a_book_outage_falls_back_to_last_and_still_marks() {
        // bid/ask unparseable (a book outage): the adapter falls back to `last`
        // for both the band floor and the TWAP, so a healthy last still produces
        // a transcript that clears the gate (graceful degradation, not a stall).
        let m = test_market();
        let t = signed_transcript("59585.6", "", "", 1_000).unwrap();
        assert_eq!(t.backup_twap, t.price);
        assert_eq!(t.validate(&m, 1_000), Ok(t.price));
    }

    #[cfg(feature = "http")]
    #[test]
    fn parses_candlesticks_ascending_and_skips_malformed_rows() {
        // the real get-candlestick response layout, plus one malformed row that
        // must be skipped (not poison the backfill), delivered out of order
        let body: serde_json::Value = serde_json::from_str(
            r#"{"code":0,"result":{"instrument_name":"BTC_USDT","interval":"M5","data":[
                {"o":"59600.1","h":"59650.0","l":"59580.5","c":"59640.2","v":"12.3","t":1720000300000},
                {"o":"59585.6","h":"59620.0","l":"59570.1","c":"59600.1","v":"10.1","t":1720000000000},
                {"o":"bogus","h":"1","l":"1","c":"1","v":"0","t":1720000600000}
            ]}}"#,
        )
        .unwrap();
        let cs = parse_candles(&body).unwrap();
        assert_eq!(cs.len(), 2, "the malformed row is skipped");
        assert!(cs[0].start_ms < cs[1].start_ms, "ascending by time");
        assert_eq!(cs[0].open, parse_price("59585.6").unwrap());
        assert_eq!(cs[1].high, parse_price("59650.0").unwrap());
    }
}

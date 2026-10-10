//! Live oracle adapter (§8): turns a real exchange ticker into the protocol's
//! [`OracleTranscript`] — the signed price the engine marks, liquidates, and funds
//! against. The conversion (decimal price strings → fixed-point, spread → confidence
//! band, same-book midpoint → legacy backup field) is offline-testable; the optional
//! `http` feature adds a live fetch from Crypto.com's public REST API.
//!
//! This is the backend counterpart to the frontend's `oracleFeed.ts`: both feed the
//! SAME `OracleTranscript` shape, so swapping the source (Crypto.com now, Pyth /
//! committee-attested later) is a parser change, not an architecture change.

#[cfg(feature = "http")]
mod live;
#[cfg(feature = "http")]
pub use live::{fetch_candles, fetch_transcript, parse_ticker_response};

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
    signer_from_value(std::env::var("ORACLE_SIGNER_KEY"))
}

fn signer_from_value(
    value: Result<String, std::env::VarError>,
) -> Result<(SigningKey, bool), String> {
    let (key, is_default) = match value {
        Ok(s) => (
            parse_hex32(&s).ok_or("ORACLE_SIGNER_KEY is set but is not a 32-byte hex value")?,
            false,
        ),
        Err(std::env::VarError::NotPresent) => (DEV_ORACLE_SIGNER_KEY, true),
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err("ORACLE_SIGNER_KEY is not valid UTF-8".into())
        }
    };
    let signer = SigningKey::from_slice(&key)
        .map_err(|e| format!("ORACLE_SIGNER_KEY is not a valid secp256k1 scalar: {e}"))?;
    Ok((signer, is_default))
}

/// Detect the known public demonstration publisher even if explicitly configured.
/// This does not establish secrecy or compromise status of any other key.
pub fn is_known_dev_signer(signer: &SigningKey) -> bool {
    signer.verifying_key()
        == SigningKey::from_slice(&DEV_ORACLE_SIGNER_KEY)
            .expect("valid public fixture scalar")
            .verifying_key()
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

/// Parse a decimal price string (e.g. "59585.60") into a [`PRICE_SCALE`] i128,
/// without floats. Returns `None` on malformed input or overflow.
pub fn parse_price(s: &str) -> Option<i128> {
    // Bound work/allocation independently of the transport. Preserve the existing
    // eight-decimal truncation contract, not Rust's permissive integer signs.
    if s.len() > 96 {
        return None;
    }
    let s = s.trim();
    let neg = s.starts_with('-');
    let body = s.strip_prefix('-').unwrap_or(s);
    let (whole, frac) = body.split_once('.').unwrap_or((body, ""));
    if (whole.is_empty() && frac.is_empty())
        || !whole.bytes().all(|b| b.is_ascii_digit())
        || !frac.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let integer = whole.bytes().try_fold(0i128, |value, digit| {
        value.checked_mul(10)?.checked_add(i128::from(digit - b'0'))
    })?;
    let mut fractional = 0i128;
    for index in 0..8 {
        let digit = frac.as_bytes().get(index).copied().unwrap_or(b'0') - b'0';
        fractional = fractional.checked_mul(10)?.checked_add(i128::from(digit))?;
    }
    let scaled = integer.checked_mul(PRICE_SCALE)?.checked_add(fractional)?;
    if neg {
        scaled.checked_neg()
    } else {
        Some(scaled)
    }
}

/// Build an [`OracleTranscript`] from a ticker's last/bid/ask decimal strings at
/// `now_ms`. Confidence is the bid/ask spread; the legacy `backup_twap` field
/// is this SAME book's midpoint, not an independent TWAP. All three prices must
/// parse positive; a missing or crossed book is refused, not replaced with last.
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
    let b = parse_price(bid)?;
    let a = parse_price(ask)?;
    if b <= 0 || a <= 0 || b > a {
        return None;
    }
    let spread = a.checked_sub(b)?;
    let mid = b.checked_add(spread / 2)?;
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

/// Preserve a valid exchange timestamp. Missing, zero or future time is not
/// repaired with receipt time. Market-specific maximum age is checked at gateway
/// admission and again by the unchanged guest oracle gate.
pub fn publish_ms(exchange_t: Option<u64>, now_ms: u64) -> Option<u64> {
    exchange_t.filter(|t| *t > 0 && *t <= now_ms)
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
        // A digit-less string is absent, not a zero or an invented book side.
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
    fn publish_time_preserves_source_and_refuses_missing_zero_or_future() {
        assert_eq!(publish_ms(Some(1_000), 9_000), Some(1_000));
        assert_eq!(publish_ms(Some(5_000), 5_000), Some(5_000));
        assert_eq!(publish_ms(Some(9_000), 5_000), None);
        assert_eq!(publish_ms(None, 5_000), None);
        assert_eq!(publish_ms(Some(0), 5_000), None);
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
    fn missing_bid_or_ask_refuses_transcript_instead_of_inventing_backup() {
        assert!(signed_transcript("59585.6", "59586.7", "", 1_000).is_none());
        assert!(signed_transcript("59585.6", "", "59586.8", 1_000).is_none());
        assert!(signed_transcript("59585.6", "", "", 1_000).is_none());
    }

    #[test]
    fn signer_configuration_only_falls_back_when_truly_absent() {
        use std::env::VarError;
        let (default, used_default) = signer_from_value(Err(VarError::NotPresent)).unwrap();
        assert!(used_default && is_known_dev_signer(&default));
        let configured: String = DEV_ORACLE_SIGNER_KEY
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let (explicit, used_default) = signer_from_value(Ok(configured)).unwrap();
        assert!(!used_default && is_known_dev_signer(&explicit));
        assert!(!is_known_dev_signer(
            &SigningKey::from_slice(&[0x33; 32]).unwrap()
        ));
        for bad in [
            "private-sentinel".to_string(),
            "00".repeat(32),
            "ff".repeat(32),
        ] {
            let error = signer_from_value(Ok(bad)).unwrap_err();
            assert!(!error.contains("private-sentinel"));
        }
        assert!(signer_from_value(Err(VarError::NotUnicode("private-sentinel".into()))).is_err());
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

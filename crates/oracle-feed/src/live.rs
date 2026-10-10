//! Strict host-side exchange intake. Same-source book midpoint is not a quorum.
use super::{parse_candles, publish_ms, transcript_from_ticker, FeedCandle};
use k256::ecdsa::SigningKey;
use perp_core::oracle::OracleTranscript;
use serde::Deserialize;
use std::{
    io::Read,
    time::{Duration, Instant},
};

const TICKER_URL: &str = "https://api.crypto.com/exchange/v1/public/get-tickers";
const CANDLE_URL: &str = "https://api.crypto.com/exchange/v1/public/get-candlestick";
const TICKER_LIMIT: usize = 64 * 1024;
const CANDLE_LIMIT: usize = 1024 * 1024;
const FETCH_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Deserialize)]
struct Envelope {
    code: u64,
    method: String,
    result: Tickers,
}
#[derive(Deserialize)]
struct Tickers {
    data: Vec<Ticker>,
}
#[derive(Deserialize)]
struct Ticker {
    i: String,
    a: String,
    b: String,
    k: String,
    t: u64,
}

fn validate_instrument(instrument: &str) -> Result<(), String> {
    if instrument.is_empty()
        || instrument.len() > 64
        || !instrument
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
    {
        return Err("invalid exchange instrument".into());
    }
    Ok(())
}

/// Parse one explicitly identified ticker. Typed fields reject duplicate known
/// keys, missing/null/wrong-type critical data, nonfinite numbers and trailing
/// JSON. Extra noncritical exchange metadata is ignored for forward compatibility.
/// Old timestamps remain old; caller applies its actual market's age policy.
pub fn parse_ticker_response(
    body: &[u8],
    instrument: &str,
    received_ms: u64,
    market: u64,
    signer: &SigningKey,
) -> Result<OracleTranscript, String> {
    validate_instrument(instrument)?;
    if body.len() > TICKER_LIMIT {
        return Err("ticker response exceeds byte limit".into());
    }
    let envelope: Envelope = serde_json::from_slice(body).map_err(|_| "invalid ticker JSON")?;
    if envelope.code != 0 || envelope.method != "public/get-tickers" {
        return Err("exchange ticker response is not successful".into());
    }
    if envelope.result.data.len() != 1 {
        return Err("exactly one requested ticker required".into());
    }
    let row = &envelope.result.data[0];
    if row.i != instrument {
        return Err("exchange ticker instrument mismatch".into());
    }
    let published =
        publish_ms(Some(row.t), received_ms).ok_or("missing or future source timestamp")?;
    transcript_from_ticker(&row.a, &row.b, &row.k, published, market, signer)
        .ok_or_else(|| "invalid last price or two-sided book".into())
}

fn agent(timeout: Duration) -> ureq::Agent {
    ureq::AgentBuilder::new()
        .redirects(0)
        .timeout(timeout)
        .build()
}

fn read_body(request: ureq::Request, limit: usize) -> Result<Vec<u8>, String> {
    let response = request.call().map_err(|_| "exchange transport failure")?;
    if response.status() != 200 {
        return Err("exchange HTTP status is not 200".into());
    }
    if response
        .header("Content-Length")
        .and_then(|v| v.parse::<u64>().ok())
        .is_some_and(|length| length > limit as u64)
    {
        return Err("exchange response exceeds byte limit".into());
    }
    let mut body = Vec::new();
    response
        .into_reader()
        .take(limit as u64 + 1)
        .read_to_end(&mut body)
        .map_err(|_| "exchange response read failed")?;
    if body.len() > limit {
        return Err("exchange response exceeds byte limit".into());
    }
    Ok(body)
}

fn received_time(start_ms: u64, elapsed: Duration) -> Result<u64, String> {
    if start_ms == 0 {
        return Err("valid request-start clock required".into());
    }
    let elapsed: u64 = elapsed
        .as_millis()
        .try_into()
        .map_err(|_| "request clock overflow")?;
    start_ms
        .checked_add(elapsed)
        .ok_or_else(|| "request clock overflow".into())
}

/// Fixed HTTPS endpoint and source identity. `now_ms` is sampled at request
/// start; elapsed monotonic time accounts for the response arriving later. It
/// never substitutes for the exchange's timestamp inside the signed transcript.
pub fn fetch_transcript(
    instrument: &str,
    now_ms: u64,
    market_id: u64,
    signer: &SigningKey,
) -> Result<OracleTranscript, String> {
    validate_instrument(instrument)?;
    received_time(now_ms, Duration::ZERO)?;
    let start = Instant::now();
    let body = read_body(
        agent(FETCH_TIMEOUT)
            .get(TICKER_URL)
            .query("instrument_name", instrument),
        TICKER_LIMIT,
    )?;
    parse_ticker_response(
        &body,
        instrument,
        received_time(now_ms, start.elapsed())?,
        market_id,
        signer,
    )
}

/// Chart-only history also has a bounded response and no redirect following.
pub fn fetch_candles(
    instrument: &str,
    timeframe: &str,
    count: usize,
) -> Result<Vec<FeedCandle>, String> {
    validate_instrument(instrument)?;
    let request = agent(FETCH_TIMEOUT)
        .get(CANDLE_URL)
        .query("instrument_name", instrument)
        .query("timeframe", timeframe)
        .query("count", &count.to_string());
    let bytes = read_body(request, CANDLE_LIMIT)?;
    let body = serde_json::from_slice(&bytes).map_err(|_| "invalid candle JSON")?;
    parse_candles(&body)
}

#[cfg(test)]
#[path = "live_tests.rs"]
mod tests;

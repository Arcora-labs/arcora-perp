//! Fixed HTTPS source adapters. No authentication, redirects, or fallback venue.
use crate::{
    crosscheck::{Exchange, SourceTick, SpotPair},
    live, publish_ms, transcript_from_ticker,
};
use k256::ecdsa::SigningKey;
use serde::Deserialize;
use std::time::Instant;

const OKX_TICKER_URL: &str = "https://openapi.okx.com/api/v5/market/ticker";
#[derive(Deserialize)]
struct Envelope {
    code: String,
    msg: String,
    data: Vec<Ticker>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Ticker {
    inst_type: String,
    inst_id: String,
    last: String,
    bid_px: String,
    ask_px: String,
    ts: String,
}

pub fn parse_crypto_spot_response(
    body: &[u8],
    pair: &SpotPair,
    received_ms: u64,
    market_id: u64,
    signer: &SigningKey,
) -> Result<SourceTick, String> {
    let transcript = live::parse_ticker_response(
        body,
        &pair.crypto_instrument(),
        received_ms,
        market_id,
        signer,
    )?;
    Ok(SourceTick {
        exchange: Exchange::CryptoCom,
        pair: pair.clone(),
        transcript,
    })
}

/// OKX's success code and millisecond timestamp are STRINGS, unlike Crypto.com.
/// Typed decode rejects duplicate known fields, nulls, wrong types and trailing
/// JSON. Extra noncritical metadata is ignored, never used to repair missing data.
pub fn parse_okx_spot_response(
    body: &[u8],
    pair: &SpotPair,
    received_ms: u64,
    market_id: u64,
    signer: &SigningKey,
) -> Result<SourceTick, String> {
    if body.len() > live::TICKER_LIMIT {
        return Err("OKX ticker exceeds byte limit".into());
    }
    let envelope: Envelope = serde_json::from_slice(body).map_err(|_| "invalid OKX ticker JSON")?;
    if envelope.code != "0" || !envelope.msg.is_empty() || envelope.data.len() != 1 {
        return Err("OKX requires one successful requested ticker".into());
    }
    let row = &envelope.data[0];
    if row.inst_type != "SPOT" || row.inst_id != pair.okx_instrument() {
        return Err("OKX spot instrument / quote mismatch".into());
    }
    if row.ts.is_empty() || row.ts.len() > 20 || !row.ts.bytes().all(|b| b.is_ascii_digit()) {
        return Err("invalid OKX source timestamp".into());
    }
    let ts = row
        .ts
        .parse::<u64>()
        .map_err(|_| "invalid OKX source timestamp")?;
    let published = publish_ms(Some(ts), received_ms).ok_or("missing or future OKX timestamp")?;
    let transcript = transcript_from_ticker(
        &row.last,
        &row.bid_px,
        &row.ask_px,
        published,
        market_id,
        signer,
    )
    .ok_or("invalid OKX price or two-sided book")?;
    Ok(SourceTick {
        exchange: Exchange::Okx,
        pair: pair.clone(),
        transcript,
    })
}

/// Both requests must succeed. Fixed independent venue URLs, 64 KiB per body,
/// no redirects, and a configured 5-second timeout PER request. Serial requests
/// can total approximately 10 seconds plus platform/DNS behavior; not a 5s SLA.
/// Both observations are revalidated at gateway receipt after the second fetch.
pub fn fetch_spot_pair(
    pair: &SpotPair,
    now_ms: u64,
    market_id: u64,
    signer: &SigningKey,
) -> Result<(SourceTick, SourceTick), String> {
    fetch_pair_at(
        pair,
        now_ms,
        market_id,
        signer,
        live::TICKER_URL,
        OKX_TICKER_URL,
        live::FETCH_TIMEOUT,
    )
}

// Private endpoint injection exists only so owned loopback tests exercise the
// SAME production request path; no environment/configurable endpoint override.
fn fetch_pair_at(
    pair: &SpotPair,
    now_ms: u64,
    market_id: u64,
    signer: &SigningKey,
    crypto_url: &str,
    okx_url: &str,
    timeout: std::time::Duration,
) -> Result<(SourceTick, SourceTick), String> {
    live::received_time(now_ms, std::time::Duration::ZERO)?;
    let start = Instant::now();
    let agent = live::agent(timeout);
    let primary = live::read_body(
        agent
            .get(crypto_url)
            .query("instrument_name", &pair.crypto_instrument()),
        live::TICKER_LIMIT,
    )?;
    let primary = parse_crypto_spot_response(
        &primary,
        pair,
        live::received_time(now_ms, start.elapsed())?,
        market_id,
        signer,
    )?;
    let secondary = live::read_body(
        agent.get(okx_url).query("instId", &pair.okx_instrument()),
        live::TICKER_LIMIT,
    )?;
    let secondary = parse_okx_spot_response(
        &secondary,
        pair,
        live::received_time(now_ms, start.elapsed())?,
        market_id,
        signer,
    )?;
    Ok((primary, secondary))
}

#[cfg(test)]
#[path = "crosscheck_http_tests.rs"]
mod tests;

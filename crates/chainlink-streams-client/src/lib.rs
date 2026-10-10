//! Bounded, authenticated REST retrieval for Chainlink Data Streams v3.
//! Retrieval and ABI parsing are NOT DON signature verification or admission.
//! No environment/file credential discovery, signing of oracle prices, or chain writes.
#![forbid(unsafe_code)]
mod auth;
mod transport;
pub use auth::Credentials;
use chainlink_oracle::report::{body_from_full_report, Report, ReportBody, MAX_FULL_REPORT};
use serde::Deserialize;
use std::fmt;
pub use transport::Client;

pub const MAX_RESPONSE_BYTES: usize = 64 * 1024;
pub type Result<T> = std::result::Result<T, Error>;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Credentials,
    NetworkMismatch,
    Feed,
    Clock,
    Deadline,
    Transport,
    Http(u16),
    RateLimited,
    ResponseTooLarge,
    ResponseEncoding,
    Json,
    Report,
    Metadata,
    Stale,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Fixed categories only: never retain or echo credentials, headers or provider bodies.
        write!(f, "Chainlink REST {:?}", self)
    }
}
impl std::error::Error for Error {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    Testnet,
    Mainnet,
}
impl Network {
    pub fn origin(self) -> &'static str {
        match self {
            Self::Testnet => "https://api.testnet-dataengine.chain.link",
            Self::Mainnet => "https://api.dataengine.chain.link",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeedId([u8; 32]);
impl FeedId {
    pub fn parse_v3(value: &str) -> Result<Self> {
        if value.len() != 66 || !value.starts_with("0x") {
            return Err(Error::Feed);
        }
        let bytes = decode_hex(value, 32).map_err(|_| Error::Feed)?;
        let id: [u8; 32] = bytes.try_into().map_err(|_| Error::Feed)?;
        if id[..2] != [0, 3] {
            return Err(Error::Feed);
        }
        Ok(Self(id))
    }
    pub fn bytes(self) -> [u8; 32] {
        self.0
    }
    pub fn hex(self) -> String {
        format!("0x{}", hex(&self.0))
    }
}

#[derive(Clone, Debug)]
pub struct Request {
    network: Network,
    feed: FeedId,
    max_age_ms: u64,
}
impl Request {
    /// Feed identity/network and age are caller-pinned policy, not inferred from a response.
    /// No production feed or economically approved freshness value is supplied by this crate.
    pub fn new(network: Network, feed: FeedId, max_age_ms: u64) -> Result<Self> {
        if max_age_ms == 0 {
            return Err(Error::Stale);
        }
        Ok(Self {
            network,
            feed,
            max_age_ms,
        })
    }
    fn path(&self) -> String {
        format!("/api/v1/reports/latest?feedID={}", self.feed.hex())
    }
}

/// Immutable original bytes plus checked metadata. The name is a trust boundary:
/// the configured Chainlink verifier must authenticate this exact full report later.
#[derive(Clone, Debug)]
pub struct UnverifiedReport {
    full_report: Vec<u8>,
    body: ReportBody,
    decoded: Report,
    network: Network,
    received_ms: u64,
}
impl UnverifiedReport {
    pub fn full_report(&self) -> &[u8] {
        &self.full_report
    }
    pub fn body(&self) -> &ReportBody {
        &self.body
    }
    pub fn decoded(&self) -> &Report {
        &self.decoded
    }
    pub fn network(&self) -> Network {
        self.network
    }
    pub fn received_ms(&self) -> u64 {
        self.received_ms
    }
    /// Queue delay never refreshes signed source time. Caller must recheck at use.
    pub fn check_freshness(&self, now_ms: u64, max_age_ms: u64) -> Result<()> {
        if max_age_ms == 0 {
            return Err(Error::Stale);
        }
        self.decoded
            .check_time(now_ms, max_age_ms)
            .map_err(|_| Error::Stale)
    }
}
#[derive(Deserialize)]
struct Envelope {
    report: Row,
}
#[derive(Deserialize)]
struct Row {
    #[serde(rename = "feedID")]
    feed_id: String,
    #[serde(rename = "validFromTimestamp")]
    valid_from: u32,
    #[serde(rename = "observationsTimestamp")]
    observations: u32,
    #[serde(rename = "fullReport")]
    full_report: String,
}
/// Typed decoding refuses duplicate known fields, noninteger times and trailing JSON.
/// Unknown provider metadata is ignored; it is never part of the trust decision.
pub fn parse_response(
    bytes: &[u8],
    request: &Request,
    received_ms: u64,
) -> Result<UnverifiedReport> {
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(Error::ResponseTooLarge);
    }
    let e: Envelope = serde_json::from_slice(bytes).map_err(|_| Error::Json)?;
    if FeedId::parse_v3(&e.report.feed_id)? != request.feed {
        return Err(Error::Metadata);
    }
    let full_report = decode_hex(&e.report.full_report, MAX_FULL_REPORT)?;
    let body = body_from_full_report(&full_report).map_err(|_| Error::Report)?;
    let decoded = body.decode().map_err(|_| Error::Report)?;
    if decoded.feed_id != request.feed.bytes()
        || decoded.valid_from != e.report.valid_from
        || decoded.observations != e.report.observations
    {
        return Err(Error::Metadata);
    }
    decoded
        .check_time(received_ms, request.max_age_ms)
        .map_err(|_| Error::Stale)?;
    Ok(UnverifiedReport {
        full_report,
        body,
        decoded,
        network: request.network,
        received_ms,
    })
}
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 15) as usize] as char);
    }
    out
}
fn decode_hex(value: &str, limit: usize) -> Result<Vec<u8>> {
    let s = value.strip_prefix("0x").unwrap_or(value).as_bytes();
    if s.is_empty() || !s.len().is_multiple_of(2) || s.len() / 2 > limit {
        return Err(Error::Report);
    }
    let digit = |b| match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(Error::Report),
    };
    s.as_chunks::<2>()
        .0
        .iter()
        .map(|p| Ok(digit(p[0])? * 16 + digit(p[1])?))
        .collect()
}

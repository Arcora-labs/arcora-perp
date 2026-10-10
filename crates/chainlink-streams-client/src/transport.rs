use crate::{
    parse_response, Credentials, Error, Request, Result, UnverifiedReport, MAX_RESPONSE_BYTES,
};
use std::{
    io::Read,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

/// Blocking REST client for a spawn_blocking worker. Public construction permits
/// only Chainlink's fixed HTTPS origins; no custom destination or TLS bypass.
pub struct Client {
    credentials: Credentials,
    limits: Limits,
}
#[derive(Clone, Copy)]
struct Limits {
    attempt: Duration,
    total: Duration,
    backoff: Duration,
    attempts: u32,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            attempt: Duration::from_secs(5),
            total: Duration::from_secs(12),
            backoff: Duration::from_millis(100),
            attempts: 3,
        }
    }
}
impl Client {
    pub fn new(credentials: Credentials) -> Self {
        Self {
            credentials,
            limits: Limits::default(),
        }
    }
    pub fn fetch_latest(&self, request: &Request) -> Result<UnverifiedReport> {
        self.fetch_at(request, self.credentials.network.origin(), clock_ms)
    }
    // Origin and clock injection are private and used only by owned loopback unit tests.
    pub(super) fn fetch_at(
        &self,
        request: &Request,
        origin: &str,
        mut clock: impl FnMut() -> Result<u64>,
    ) -> Result<UnverifiedReport> {
        if request.network != self.credentials.network {
            return Err(Error::NetworkMismatch);
        }
        let path = request.path();
        let url = format!("{origin}{path}");
        let began = Instant::now();
        let first = clock()?;
        if first == 0 {
            return Err(Error::Clock);
        }
        let mut previous_clock = first;
        for attempt in 0..self.limits.attempts {
            let remaining = self
                .limits
                .total
                .checked_sub(began.elapsed())
                .ok_or(Error::Deadline)?;
            if remaining.is_zero() {
                return Err(Error::Deadline);
            }
            let now = clock()?;
            if now < previous_clock || now == 0 {
                return Err(Error::Clock);
            }
            previous_clock = now;
            let signature = self.credentials.sign_get(&path, now)?;
            match fetch_once(
                &url,
                &self.credentials,
                &signature,
                now,
                self.limits.attempt.min(remaining),
            ) {
                Ok(bytes) => {
                    if began.elapsed() >= self.limits.total {
                        return Err(Error::Deadline);
                    }
                    let wall = clock()?;
                    if wall < previous_clock {
                        return Err(Error::Clock);
                    }
                    let elapsed: u64 = began
                        .elapsed()
                        .as_millis()
                        .try_into()
                        .map_err(|_| Error::Clock)?;
                    let received = wall.max(first.checked_add(elapsed).ok_or(Error::Clock)?);
                    return parse_response(&bytes, request, received);
                }
                Err(error) => {
                    let retryable =
                        matches!(error, Error::Transport | Error::Http(500 | 502 | 503 | 504));
                    if !retryable || attempt + 1 == self.limits.attempts {
                        return Err(error);
                    }
                    let delay = self.limits.backoff.saturating_mul(1 << attempt);
                    let left = self
                        .limits
                        .total
                        .checked_sub(began.elapsed())
                        .ok_or(Error::Deadline)?;
                    if delay >= left {
                        return Err(Error::Deadline);
                    }
                    std::thread::sleep(delay);
                }
            }
        }
        Err(Error::Transport)
    }
}
fn clock_ms() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Clock)?
        .as_millis()
        .try_into()
        .map_err(|_| Error::Clock)
}
fn status_error(status: u16) -> Error {
    if status == 429 {
        Error::RateLimited
    } else {
        Error::Http(status)
    }
}
fn fetch_once(
    url: &str,
    credentials: &Credentials,
    signature: &str,
    timestamp: u64,
    timeout: Duration,
) -> Result<Vec<u8>> {
    let agent = ureq::AgentBuilder::new()
        .redirects(0)
        .try_proxy_from_env(false)
        .max_idle_connections(0)
        .timeout(timeout)
        .build();
    let response = match agent
        .get(url)
        .set("Authorization", &credentials.username)
        .set("X-Authorization-Timestamp", &timestamp.to_string())
        .set("X-Authorization-Signature-SHA256", signature)
        .set("Accept", "application/json")
        .set("Accept-Encoding", "identity")
        .call()
    {
        Ok(r) => r,
        Err(ureq::Error::Status(s, _)) => return Err(status_error(s)),
        Err(ureq::Error::Transport(_)) => return Err(Error::Transport),
    };
    if response.status() != 200 {
        return Err(status_error(response.status()));
    }
    let lengths = response.all("Content-Length");
    if lengths.len() > 1 || (!lengths.is_empty() && response.has("Transfer-Encoding")) {
        return Err(Error::ResponseEncoding);
    }
    if let Some(v) = lengths.first() {
        let len = v.parse::<u64>().map_err(|_| Error::ResponseEncoding)?;
        if len > MAX_RESPONSE_BYTES as u64 {
            return Err(Error::ResponseTooLarge);
        }
    }
    if response
        .all("Content-Encoding")
        .iter()
        .any(|v| !v.eq_ignore_ascii_case("identity"))
    {
        return Err(Error::ResponseEncoding);
    }
    let mut bytes = Vec::new();
    response
        .into_reader()
        .take(MAX_RESPONSE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Transport)?;
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(Error::ResponseTooLarge);
    }
    Ok(bytes)
}

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
        let mut receipt_clock = ReceiptClock::new(first, Instant::now())?;
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
            // Preserve elapsed time across retries and forward wall-clock steps.
            // Authentication still uses the sampled wall time, not this floor.
            receipt_clock.observe(now, Instant::now())?;
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
                    let received = receipt_clock.observe(wall, Instant::now())?;
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
/// Receipt-time lower bound; never a substitute for the signed source time.
/// A forward wall-clock step establishes a new monotonic anchor. A stalled clock
/// does not reset that anchor on retries, so elapsed time and sub-ms remainder
/// are retained. Backward wall time and arithmetic overflow are errors.
struct ReceiptClock {
    last_wall: u64,
    anchor_ms: u64,
    anchor: Instant,
}
impl ReceiptClock {
    fn new(wall: u64, sampled: Instant) -> Result<Self> {
        if wall == 0 {
            return Err(Error::Clock);
        }
        Ok(Self {
            last_wall: wall,
            anchor_ms: wall,
            anchor: sampled,
        })
    }

    fn observe(&mut self, wall: u64, sampled: Instant) -> Result<u64> {
        if wall == 0 || wall < self.last_wall {
            return Err(Error::Clock);
        }
        let elapsed: u64 = sampled
            .checked_duration_since(self.anchor)
            .ok_or(Error::Clock)?
            .as_millis()
            .try_into()
            .map_err(|_| Error::Clock)?;
        let projected = self.anchor_ms.checked_add(elapsed).ok_or(Error::Clock)?;
        if wall > projected {
            self.anchor_ms = wall;
            self.anchor = sampled;
        }
        self.last_wall = wall;
        Ok(wall.max(projected))
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
    let transfers = response.all("Transfer-Encoding");
    // Only a single chunked transfer coding is supported. Validate the actual
    // headers before the HTTP library selects a body decoder.
    if lengths.len() > 1
        || transfers.len() > 1
        || (!lengths.is_empty() && !transfers.is_empty())
        || transfers
            .first()
            .is_some_and(|v| !v.eq_ignore_ascii_case("chunked"))
    {
        return Err(Error::ResponseEncoding);
    }
    if let Some(v) = lengths.first() {
        // HTTP Content-Length is 1*DIGIT; integer parsing alone permits '+'.
        if v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) {
            return Err(Error::ResponseEncoding);
        }
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

#[cfg(test)]
#[path = "transport_tests.rs"]
mod tests;

#[cfg(test)]
mod receipt_clock_tests {
    use super::*;

    #[test]
    fn forward_step_retains_elapsed_time_at_the_age_boundary() {
        let start = Instant::now();
        let mut clock = ReceiptClock::new(1, start).unwrap();
        let jump = start + Duration::from_millis(3);
        assert_eq!(clock.observe(110_000, jump), Ok(110_000));
        assert_eq!(
            clock.observe(110_000, jump + Duration::from_millis(40)),
            Ok(110_040)
        );
    }

    #[test]
    fn retry_samples_do_not_erase_time_after_a_forward_step() {
        let start = Instant::now();
        let mut clock = ReceiptClock::new(1, start).unwrap();
        let jump = start + Duration::from_millis(1);
        assert_eq!(clock.observe(100_000, jump), Ok(100_000));
        for elapsed in [40, 80, 120] {
            assert_eq!(
                clock.observe(100_000, jump + Duration::from_millis(elapsed)),
                Ok(100_000 + elapsed)
            );
        }
    }

    #[test]
    fn ordinary_wall_time_and_elapsed_time_are_not_double_counted() {
        let start = Instant::now();
        let mut clock = ReceiptClock::new(100_000, start).unwrap();
        assert_eq!(
            clock.observe(100_040, start + Duration::from_millis(40)),
            Ok(100_040)
        );
        assert_eq!(
            clock.observe(100_080, start + Duration::from_millis(80)),
            Ok(100_080)
        );
        assert_eq!(
            clock.observe(100_080, start + Duration::from_millis(120)),
            Ok(100_120)
        );
    }

    #[test]
    fn repeated_submillisecond_samples_keep_the_original_anchor() {
        let start = Instant::now();
        let mut clock = ReceiptClock::new(100_000, start).unwrap();
        assert_eq!(
            clock.observe(100_000, start + Duration::from_micros(600)),
            Ok(100_000)
        );
        assert_eq!(
            clock.observe(100_000, start + Duration::from_micros(1_200)),
            Ok(100_001)
        );
        assert_eq!(
            clock.observe(100_000, start + Duration::from_micros(1_800)),
            Ok(100_001)
        );
    }

    #[test]
    fn zero_backward_and_reversed_monotonic_samples_fail_closed() {
        let start = Instant::now();
        assert!(matches!(ReceiptClock::new(0, start), Err(Error::Clock)));
        let anchor = start + Duration::from_millis(1);
        let mut clock = ReceiptClock::new(100_000, anchor).unwrap();
        assert_eq!(clock.observe(0, anchor), Err(Error::Clock));
        assert_eq!(clock.observe(99_999, anchor), Err(Error::Clock));
        assert_eq!(clock.observe(100_000, start), Err(Error::Clock));
        assert_eq!(clock.observe(100_000, anchor), Ok(100_000));
    }

    #[test]
    fn elapsed_time_overflow_is_rejected_instead_of_wrapping() {
        let start = Instant::now();
        let mut clock = ReceiptClock::new(u64::MAX, start).unwrap();
        assert_eq!(
            clock.observe(u64::MAX, start + Duration::from_millis(1)),
            Err(Error::Clock)
        );
    }
}

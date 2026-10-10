//! Real transport through owned loopback sockets, synthetic credentials only.
use super::*;
use crate::{
    tests::{credentials, request, response, value, NOW, SECRET, USER},
    Network,
};
use std::{
    collections::VecDeque,
    io::{Read, Write},
    net::TcpListener,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
};

struct Reply {
    bytes: Vec<u8>,
    before: Duration,
    after: Duration,
}
impl Reply {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            before: Duration::ZERO,
            after: Duration::ZERO,
        }
    }
}
struct Server {
    origin: String,
    stop: Arc<AtomicBool>,
    seen: Arc<Mutex<Vec<String>>>,
    task: Option<thread::JoinHandle<()>>,
}
impl Server {
    fn new(replies: Vec<Reply>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let captured = seen.clone();
        let task = thread::spawn(move || {
            let mut replies: VecDeque<_> = replies.into();
            while !stopping.load(Ordering::SeqCst) {
                let (mut stream, _) = match listener.accept() {
                    Ok(s) => s,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1));
                        continue;
                    }
                    Err(e) => panic!("owned listener failed: {e}"),
                };
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut header = Vec::new();
                let mut byte = [0];
                while !header.ends_with(b"\r\n\r\n") {
                    if stream.read(&mut byte).unwrap_or(0) == 0 {
                        break;
                    }
                    header.push(byte[0]);
                    assert!(header.len() < 8192);
                }
                captured
                    .lock()
                    .unwrap()
                    .push(String::from_utf8(header).unwrap());
                let reply = replies
                    .pop_front()
                    .unwrap_or_else(|| Reply::new(wire(500, "", b"unexpected request")));
                thread::sleep(reply.before);
                let _ = stream.write_all(&reply.bytes);
                thread::sleep(reply.after);
            }
        });
        Self {
            origin,
            stop,
            seen,
            task: Some(task),
        }
    }
    fn count(&self) -> usize {
        self.seen.lock().unwrap().len()
    }
    fn requests(&self) -> Vec<String> {
        self.seen.lock().unwrap().clone()
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.task.take().unwrap().join().unwrap();
    }
}
fn wire(status: u16, headers: &str, body: &[u8]) -> Vec<u8> {
    let mut b =
        format!("HTTP/1.1 {status} Test\r\nConnection: close\r\n{headers}\r\n").into_bytes();
    b.extend_from_slice(body);
    b
}
fn framed(status: u16, body: &[u8]) -> Vec<u8> {
    wire(status, &format!("Content-Length: {}\r\n", body.len()), body)
}
fn healthy() -> Reply {
    Reply::new(framed(200, &response()))
}
fn client() -> Client {
    Client {
        credentials: credentials(),
        limits: Limits {
            attempt: Duration::from_secs(2),
            total: Duration::from_secs(5),
            backoff: Duration::from_millis(1),
            attempts: 3,
        },
    }
}
fn fetch(server: &Server) -> Result<UnverifiedReport> {
    client().fetch_at(&request(), &server.origin, || Ok(NOW))
}
fn once(bytes: Vec<u8>) -> Result<UnverifiedReport> {
    let server = Server::new(vec![Reply::new(bytes)]);
    let mut c = client();
    c.limits.attempts = 1;
    c.fetch_at(&request(), &server.origin, || Ok(NOW))
}
fn header<'a>(request: &'a str, key: &str) -> &'a str {
    let found: Vec<_> = request
        .split("\r\n")
        .filter_map(|line| line.split_once(':'))
        .filter(|(k, _)| k.eq_ignore_ascii_case(key))
        .map(|(_, v)| v.trim())
        .collect();
    assert_eq!(found.len(), 1, "one expected header");
    found[0]
}
#[test]
fn real_http_sends_canonical_hmac_headers_and_preserves_report_bytes() {
    let server = Server::new(vec![healthy()]);
    let r = fetch(&server).unwrap();
    assert_eq!(r.full_report(), crate::tests::full_report());
    assert_eq!(server.count(), 1);
    let req = &server.requests()[0];
    assert!(req.starts_with(&format!("GET {} HTTP/1.1\r\n", request().path())));
    assert_eq!(header(req, "Authorization"), USER);
    assert_eq!(header(req, "X-Authorization-Timestamp"), "100000");
    assert_eq!(
        header(req, "X-Authorization-Signature-SHA256"),
        "8d4c0cc73a3f73e3c35c9bc545a626d8f448ce9c0b7c73e13bb7f9c2e93bba37"
    );
    assert_eq!(header(req, "Accept-Encoding"), "identity");
    assert!(!req.contains(std::str::from_utf8(SECRET).unwrap()));
}
#[test]
fn real_http_network_mismatch_refuses_before_clock_or_connection() {
    let server = Server::new(vec![]);
    let req = Request::new(Network::Mainnet, crate::tests::feed(), 10_000).unwrap();
    let result = client().fetch_at(&req, &server.origin, || {
        panic!("mismatch must fail before clock")
    });
    assert_eq!(result.unwrap_err(), Error::NetworkMismatch);
    assert_eq!(server.count(), 0);
}
#[test]
fn real_http_retryable_statuses_retry_with_new_auth_timestamp() {
    for status in [500, 502, 503, 504] {
        let server = Server::new(vec![Reply::new(framed(status, b"transient")), healthy()]);
        let mut t = NOW;
        assert!(client()
            .fetch_at(&request(), &server.origin, || {
                let n = t;
                t += 1;
                Ok(n)
            })
            .is_ok());
        assert_eq!(server.count(), 2);
        let requests = server.requests();
        for (i, r) in requests.iter().enumerate() {
            let ts = NOW + 1 + i as u64;
            assert_eq!(header(r, "X-Authorization-Timestamp"), ts.to_string());
            assert_eq!(
                header(r, "X-Authorization-Signature-SHA256"),
                credentials()
                    .sign_get(&request().path(), ts)
                    .unwrap()
                    .as_str()
            );
        }
        assert_ne!(
            header(&requests[0], "X-Authorization-Signature-SHA256"),
            header(&requests[1], "X-Authorization-Signature-SHA256")
        );
    }
}
#[test]
fn real_http_retry_count_is_bounded_and_error_body_not_echoed() {
    let server = Server::new(
        (0..3)
            .map(|_| Reply::new(framed(503, b"private-provider-sentinel")))
            .collect(),
    );
    let error = fetch(&server).unwrap_err();
    assert_eq!(error, Error::Http(503));
    assert_eq!(server.count(), 3);
    assert!(!error.to_string().contains("private-provider-sentinel"));
}
#[test]
fn real_http_auth_rate_limit_redirect_and_non_200_do_not_retry() {
    for status in [
        201, 204, 206, 301, 302, 307, 308, 400, 401, 403, 404, 429, 501,
    ] {
        let server = Server::new(vec![Reply::new(framed(
            status,
            b"private-provider-sentinel",
        ))]);
        let error = fetch(&server).unwrap_err();
        assert_eq!(server.count(), 1, "status {status} not retryable");
        assert_eq!(
            error,
            if status == 429 {
                Error::RateLimited
            } else {
                Error::Http(status)
            }
        );
    }
}
#[test]
fn real_http_redirect_does_not_send_credentials_to_target() {
    let target = Server::new(vec![healthy()]);
    let server = Server::new(vec![Reply::new(wire(
        302,
        &format!("Location: {}/steal\r\nContent-Length: 0\r\n", target.origin),
        b"",
    ))]);
    assert_eq!(fetch(&server).unwrap_err(), Error::Http(302));
    assert_eq!(target.count(), 0);
    assert_eq!(server.count(), 1);
}
#[test]
fn real_http_malformed_metadata_and_stale_report_do_not_retry() {
    let mut wrong = value();
    wrong["report"]["observationsTimestamp"] = serde_json::json!(99);
    for body in [b"not-json".to_vec(), serde_json::to_vec(&wrong).unwrap()] {
        let server = Server::new(vec![Reply::new(framed(200, &body))]);
        assert!(fetch(&server).is_err());
        assert_eq!(server.count(), 1);
    }
    let server = Server::new(vec![healthy()]);
    assert_eq!(
        client()
            .fetch_at(&request(), &server.origin, || Ok(200_000))
            .unwrap_err(),
        Error::Stale
    );
    assert_eq!(server.count(), 1);
}
#[test]
fn real_http_reconnects_after_truncated_body() {
    let server = Server::new(vec![
        Reply::new(wire(200, "Content-Length: 999\r\n", b"{")),
        healthy(),
    ]);
    assert!(fetch(&server).is_ok());
    assert_eq!(server.count(), 2);
}
#[test]
fn real_http_bounds_content_length_chunked_and_eof_bodies() {
    let huge = vec![b' '; MAX_RESPONSE_BYTES + 1];
    assert_eq!(
        once(framed(200, &huge)).unwrap_err(),
        Error::ResponseTooLarge
    );
    assert_eq!(
        once(wire(200, "", &huge)).unwrap_err(),
        Error::ResponseTooLarge
    );
    let mut chunk = format!("{:x}\r\n", huge.len()).into_bytes();
    chunk.extend(&huge);
    chunk.extend(b"\r\n0\r\n\r\n");
    assert_eq!(
        once(wire(200, "Transfer-Encoding: chunked\r\n", &chunk)).unwrap_err(),
        Error::ResponseTooLarge
    );
    let mut exact = response();
    exact.resize(MAX_RESPONSE_BYTES, b' ');
    assert!(once(framed(200, &exact)).is_ok());
}
#[test]
fn real_http_accepts_correct_chunked_framing() {
    let body = response();
    let mut chunks = Vec::new();
    for part in body.chunks(79) {
        chunks.extend(format!("{:x}\r\n", part.len()).as_bytes());
        chunks.extend(part);
        chunks.extend(b"\r\n");
    }
    chunks.extend(b"0\r\n\r\n");
    assert!(once(wire(200, "Transfer-Encoding: chunked\r\n", &chunks)).is_ok());
}
#[test]
fn real_http_ambiguous_or_encoded_framing_is_rejected() {
    let body = response();
    for extra in [
        format!(
            "Content-Length: {}\r\nContent-Length: {}\r\n",
            body.len(),
            body.len()
        ),
        format!(
            "Content-Length: {}\r\nTransfer-Encoding: chunked\r\n",
            body.len()
        ),
        "Content-Length: nope\r\n".into(),
        "Content-Length: -1\r\n".into(),
        "Content-Encoding: gzip\r\n".into(),
        "Content-Encoding: br\r\n".into(),
    ] {
        assert!(
            once(wire(200, &extra, &body)).is_err(),
            "invalid framing {extra:?}"
        );
    }
}
#[test]
fn real_http_unknown_or_duplicate_transfer_encoding_must_not_be_treated_as_plain_json() {
    let body = response();
    for extra in [
        "Transfer-Encoding: gzip\r\n",
        "Transfer-Encoding: identity\r\n",
        "Transfer-Encoding: gzip, chunked\r\n",
        "Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n",
    ] {
        assert!(
            once(wire(200, extra, &body)).is_err(),
            "unsupported framing {extra:?}"
        );
    }
}
#[test]
fn real_http_signed_content_length_must_not_be_accepted() {
    assert!(once(wire(
        200,
        &format!("Content-Length: +{}\r\n", response().len()),
        &response()
    ))
    .is_err());
}
#[test]
fn real_http_stalled_body_timeout_never_yields_partial_success() {
    let mut r = Reply::new(wire(200, "Content-Length: 100\r\n", b"{"));
    r.after = Duration::from_millis(350);
    let server = Server::new(vec![r]);
    let mut c = client();
    c.limits.attempts = 1;
    c.limits.attempt = Duration::from_millis(100);
    let start = Instant::now();
    assert_eq!(
        c.fetch_at(&request(), &server.origin, || Ok(NOW))
            .unwrap_err(),
        Error::Transport
    );
    assert!(start.elapsed() < Duration::from_secs(2));
    assert_eq!(server.count(), 1);
}
#[test]
fn real_http_total_deadline_prevents_backoff_and_extra_request() {
    let server = Server::new(vec![Reply::new(framed(503, b"retry"))]);
    let mut c = client();
    c.limits.total = Duration::from_millis(100);
    c.limits.backoff = Duration::from_secs(1);
    assert_eq!(
        c.fetch_at(&request(), &server.origin, || Ok(NOW))
            .unwrap_err(),
        Error::Deadline
    );
    assert_eq!(server.count(), 1);
}
#[test]
fn real_http_failed_or_backward_clock_does_not_refresh_data() {
    let server = Server::new(vec![healthy()]);
    for first in [Ok(0), Err(Error::Clock)] {
        assert_eq!(
            client()
                .fetch_at(&request(), &server.origin, || first)
                .unwrap_err(),
            Error::Clock
        );
    }
    let mut values = [Ok(NOW), Ok(NOW - 1)].into_iter();
    assert_eq!(
        client()
            .fetch_at(&request(), &server.origin, || values.next().unwrap())
            .unwrap_err(),
        Error::Clock
    );
    assert_eq!(server.count(), 0);
    let mut values = [Ok(NOW), Ok(NOW), Ok(NOW - 1)].into_iter();
    assert_eq!(
        client()
            .fetch_at(&request(), &server.origin, || values.next().unwrap())
            .unwrap_err(),
        Error::Clock
    );
    assert_eq!(server.count(), 1);
}
#[test]
fn real_http_retry_clock_rollback_stops_before_second_request() {
    let server = Server::new(vec![Reply::new(framed(503, b"retry"))]);
    let mut values = [Ok(NOW), Ok(NOW + 100), Ok(NOW + 99)].into_iter();
    assert_eq!(
        client()
            .fetch_at(&request(), &server.origin, || values.next().unwrap())
            .unwrap_err(),
        Error::Clock
    );
    assert_eq!(server.count(), 1);
}
#[test]
fn real_http_monotonic_receipt_counts_elapsed_time_when_wall_clock_stalls() {
    let mut r = healthy();
    r.before = Duration::from_millis(40);
    let server = Server::new(vec![r]);
    let report = fetch(&server).unwrap();
    assert!(report.received_ms() >= NOW + 40);
    assert_eq!(report.decoded().observations, 100);
}
#[test]
fn real_http_forward_clock_step_cannot_hide_attempt_elapsed_time() {
    let mut r = healthy();
    r.before = Duration::from_millis(40);
    let server = Server::new(vec![r]);
    // Startup clock is old; request clock steps ahead to the exact age boundary,
    // then stops advancing. Forty ms of I/O must make the report stale.
    let mut values = [Ok(1), Ok(NOW + 10_000), Ok(NOW + 10_000)].into_iter();
    assert_eq!(
        client()
            .fetch_at(&request(), &server.origin, || values.next().unwrap())
            .unwrap_err(),
        Error::Stale
    );
}

#[test]
fn real_http_duplicate_transfer_encoding_rejected_even_with_valid_chunks() {
    let body = response();
    let mut chunk = format!("{:x}\r\n", body.len()).into_bytes();
    chunk.extend(body);
    chunk.extend(b"\r\n0\r\n\r\n");
    assert!(once(wire(
        200,
        "Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n",
        &chunk
    ))
    .is_err());
}
#[test]
fn real_http_unknown_transfer_encoding_rejected_even_when_chunk_decode_would_work() {
    let body = response();
    let mut chunk = format!("{:x}\r\n", body.len()).into_bytes();
    chunk.extend(body);
    chunk.extend(b"\r\n0\r\n\r\n");
    for extra in [
        "Transfer-Encoding: gzip\r\n",
        "Transfer-Encoding: gzip, chunked\r\n",
    ] {
        assert!(once(wire(200, extra, &chunk)).is_err());
    }
}

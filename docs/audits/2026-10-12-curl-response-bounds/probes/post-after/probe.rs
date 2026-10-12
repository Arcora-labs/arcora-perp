#[path="/Users/huseyinarslan/Desktop/arcora-perp/candidate-protocol-20261011/crates/service-transport/curl.rs"] mod curl_transport;
mod prover_client {
#[derive(Debug)] pub enum ProverClientError { Http(String), Unauthorized }
const STATUS_SENTINEL: &str = "__DPHTTP_STATUS__";
const MAX_PROVE_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
fn prove_curl_args(endpoint: &str, timeout_secs: u64, bearer: Option<&str>) -> Vec<String> {
    let mut args = vec![
        "-q".into(),
        "-s".into(),
        "-S".into(),
        "--connect-timeout".into(),
        "20".into(),
        "--keepalive-time".into(),
        "30".into(),
        "--max-time".into(),
        timeout_secs.to_string(),
        "-X".into(),
        "POST".into(),
        "-H".into(),
        "Content-Type: application/json".into(),
    ];
    if let Some(token) = bearer {
        args.push("-H".into());
        args.push(format!("Authorization: Bearer {token}"));
    }
    // Append the HTTP status after the body under STATUS_SENTINEL (see `split_status`).
    args.push("-w".into());
    args.push(format!("\n{STATUS_SENTINEL}%{{http_code}}"));
    args.push("--data-binary".into());
    args.push("@-".into());
    args.push("--".into());
    args.push(endpoint.into());
    args
}
fn split_status(raw: &str) -> Result<(String, u16), ProverClientError> {
    let marker = format!("\n{STATUS_SENTINEL}");
    let idx = raw
        .rfind(&marker)
        .ok_or_else(|| ProverClientError::Http("curl -w status marker missing".into()))?;
    let body = raw[..idx].to_string();
    let code = raw[idx + marker.len()..].trim();
    if code.len() != 3 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ProverClientError::Http("invalid HTTP status marker".into()));
    }
    let status = code
        .parse::<u16>()
        .map_err(|_| ProverClientError::Http("invalid HTTP status marker".into()))?;
    if !(100..=599).contains(&status) {
        return Err(ProverClientError::Http("invalid HTTP status marker".into()));
    }
    Ok((body, status))
}
pub(super) fn http_post(
    url: &str,
    body: &str,
    timeout_secs: u64,
    bearer: Option<&str>,
) -> Result<String, ProverClientError> {
    http_post_command(
        url,
        body,
        timeout_secs,
        bearer,
        std::process::Command::new("curl"),
    )
}
pub(super) fn http_post_command(
    url: &str,
    body: &str,
    timeout_secs: u64,
    bearer: Option<&str>,
    mut command: std::process::Command,
) -> Result<String, ProverClientError> {
    use crate::curl_transport::{self, Limits};
    use std::time::Duration;
    let deadline = timeout_secs
        .checked_add(5)
        .filter(|_| timeout_secs > 0)
        .ok_or_else(|| ProverClientError::Http("invalid HTTP transport timeout".into()))?;
    let endpoint = format!("{}/prove", url.trim_end_matches('/'));
    command.args(prove_curl_args(&endpoint, timeout_secs, bearer));
    let out = curl_transport::run(
        command,
        Some(body.as_bytes()),
        Limits {
            stdout: MAX_PROVE_RESPONSE_BYTES + STATUS_SENTINEL.len() + 4,
            stderr: curl_transport::MAX_STDERR_BYTES,
            timeout: Duration::from_secs(deadline),
        },
    )
    .map_err(|e| ProverClientError::Http(e.to_string()))?;
    // Without `--fail`, a non-zero curl exit now means a TRANSPORT failure (connect
    // timeout, DNS, tunnel down) — the HTTP status itself rides the `-w` sentinel.
    if !out.status.success() {
        return Err(ProverClientError::Http(format!(
            "prover HTTP transport exit {}",
            out.status,
        )));
    }
    let raw = std::str::from_utf8(&out.stdout)
        .map_err(|_| ProverClientError::Http("invalid UTF-8 HTTP response".into()))?;
    let (resp_body, status) = split_status(raw)?;
    if resp_body.len() > MAX_PROVE_RESPONSE_BYTES {
        return Err(ProverClientError::Http(
            "HTTP response exceeds byte limit".into(),
        ));
    }
    match status {
        200..=299 => Ok(resp_body),
        // SEC-020 Task 5: the /prove gate rejected the bearer — surface as a typed
        // 401 so `prove` can re-handshake once and retry (fail-closed on a second 401).
        401 => Err(ProverClientError::Unauthorized),
        s => Err(ProverClientError::Http(format!("prover /prove HTTP {s}"))),
    }
}
}
use std::{
    io::{Read, Write},
    net::TcpListener,
    process::Command,
    thread::JoinHandle,
    time::{Duration, Instant},
};

fn curl() -> Command {
    let mut command = Command::new("curl");
    for name in ["http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"] {
        command.env_remove(name);
    }
    command.env("NO_PROXY", "*").env("no_proxy", "*");
    command
}

#[derive(Clone, Copy)]
enum Framing { Length, Chunked, Close }

fn fixture(status: u16, payload: Vec<u8>, framing: Framing) -> (String, JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    listener.set_nonblocking(true).unwrap();
    let handle = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(8);
        let mut socket = loop {
            match listener.accept() {
                Ok((socket, peer)) => { assert!(peer.ip().is_loopback()); break socket; }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "owned fixture never contacted");
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(e) => panic!("owned accept failed: {e}"),
            }
        };
        socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        socket.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut request = Vec::new();
        let header_end = loop {
            let mut bytes = [0u8; 8192];
            let n = socket.read(&mut bytes).unwrap();
            assert!(n > 0);
            request.extend_from_slice(&bytes[..n]);
            assert!(request.len() <= 256 * 1024);
            if let Some(i) = request.windows(4).position(|w| w == b"\r\n\r\n") { break i + 4; }
        };
        let headers = std::str::from_utf8(&request[..header_end]).unwrap();
        let content_length = headers.lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length").then(|| value.trim().parse::<usize>().unwrap())
        }).unwrap_or(0);
        assert!(content_length <= 192 * 1024);
        while request.len() < header_end + content_length {
            let mut bytes = [0u8; 8192];
            let n = socket.read(&mut bytes).unwrap();
            assert!(n > 0);
            request.extend_from_slice(&bytes[..n]);
        }
        let framing_header = match framing {
            Framing::Length => format!("Content-Length: {}\r\n", payload.len()),
            Framing::Chunked => "Transfer-Encoding: chunked\r\n".into(),
            Framing::Close => String::new(),
        };
        let header = format!("HTTP/1.1 {status} Fixture\r\n{framing_header}Connection: close\r\n\r\n");
        if socket.write_all(header.as_bytes()).is_ok() {
            for chunk in payload.chunks(8192) {
                if matches!(framing, Framing::Chunked) && write!(socket, "{:x}\r\n", chunk.len()).is_err() { break; }
                if socket.write_all(chunk).is_err() { break; }
                if matches!(framing, Framing::Chunked) && socket.write_all(b"\r\n").is_err() { break; }
            }
            if matches!(framing, Framing::Chunked) { let _ = socket.write_all(b"0\r\n\r\n"); }
        }
        request
    });
    (url, handle)
}


#[test]
fn non2xx_prover_error_cannot_echo_peer_data() {
 let (url, peer)=fixture(503,b"synthetic-peer-private-canary".to_vec(),Framing::Length);
 let result=prover_client::http_post(&url,"{}",5,None);
 peer.join().unwrap();
 match result { Err(prover_client::ProverClientError::Http(message)) => assert!(!message.contains("synthetic-peer-private-canary"),"peer content reached the returned transport error"), _=>panic!("wrong result") }
}

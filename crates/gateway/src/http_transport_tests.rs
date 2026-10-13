//! Real curl against owned loopback fixtures; no attestation or proof acceptance.
use crate::prover_client::{http_post_command, parse_prove_resp, ProverClientError};
use std::{
    io::{Read, Write},
    net::{Shutdown, TcpListener},
    process::Command,
    thread::JoinHandle,
    time::{Duration, Instant},
};

fn curl() -> Command {
    let mut command = Command::new("curl");
    for name in [
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
    ] {
        command.env_remove(name);
    }
    command.env("NO_PROXY", "*").env("no_proxy", "*");
    command
}

#[derive(Clone, Copy)]
enum Framing {
    Length,
    Chunked,
    Close,
}

struct Exchange {
    request: Vec<u8>,
    response_complete: bool,
}

fn fixture(status: u16, payload: Vec<u8>, framing: Framing) -> (String, JoinHandle<Exchange>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    listener.set_nonblocking(true).unwrap();
    let handle = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(8);
        let mut socket = loop {
            match listener.accept() {
                Ok((socket, peer)) => {
                    assert!(peer.ip().is_loopback());
                    break socket;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "owned fixture never contacted");
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(e) => panic!("owned accept failed: {e}"),
            }
        };
        // BSD/macOS may inherit O_NONBLOCK from the listener. These owned
        // streams use blocking I/O with explicit read/write budgets.
        socket.set_nonblocking(false).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut request = Vec::new();
        let header_end = loop {
            let mut bytes = [0u8; 8192];
            let n = socket.read(&mut bytes).unwrap();
            assert!(n > 0);
            request.extend_from_slice(&bytes[..n]);
            assert!(request.len() <= 256 * 1024);
            if let Some(i) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                break i + 4;
            }
        };
        let headers = std::str::from_utf8(&request[..header_end]).unwrap();
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().unwrap())
            })
            .unwrap_or(0);
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
        let header =
            format!("HTTP/1.1 {status} Fixture\r\n{framing_header}Connection: close\r\n\r\n");
        let mut response_complete = socket.write_all(header.as_bytes()).is_ok();
        if response_complete {
            for chunk in payload.chunks(8192) {
                if matches!(framing, Framing::Chunked)
                    && write!(socket, "{:x}\r\n", chunk.len()).is_err()
                {
                    response_complete = false;
                    break;
                }
                if socket.write_all(chunk).is_err() {
                    response_complete = false;
                    break;
                }
                if matches!(framing, Framing::Chunked) && socket.write_all(b"\r\n").is_err() {
                    response_complete = false;
                    break;
                }
            }
            if response_complete && matches!(framing, Framing::Chunked) {
                response_complete = socket.write_all(b"0\r\n\r\n").is_ok();
            }
        }
        // Finish the response direction before dropping the socket. Wait for
        // client close to avoid cutting short a queued positive response;
        // over-limit clients may reset their own connection.
        let _ = socket.shutdown(Shutdown::Write);
        let mut tail = [0u8; 1];
        let _ = socket.read(&mut tail);
        Exchange {
            request,
            response_complete,
        }
    });
    (url, handle)
}

fn json_body(len: usize) -> Vec<u8> {
    let mut bytes = b"{\"padding\":\"".to_vec();
    bytes.resize(len - 2, b'x');
    bytes.extend_from_slice(b"\"}");
    bytes
}

#[test]
fn get_small_and_exact_limit_valid_json_succeed() {
    for len in [1024, crate::curl_transport::MAX_GET_RESPONSE_BYTES] {
        let (url, peer) = fixture(200, json_body(len), Framing::Length);
        let response = crate::http_get_json_command(&url, curl());
        let exchange = peer.join().unwrap();
        assert!(
            exchange.response_complete,
            "positive fixture response was truncated"
        );
        assert!(exchange.request.starts_with(b"GET / HTTP/1.1"));
        assert_eq!(
            response.unwrap()["padding"].as_str().unwrap().len(),
            len - 14
        );
    }
}

#[test]
fn get_overflow_refused_with_or_without_content_length() {
    for framing in [Framing::Length, Framing::Chunked, Framing::Close] {
        let (url, peer) = fixture(
            200,
            json_body(crate::curl_transport::MAX_GET_RESPONSE_BYTES + 1),
            framing,
        );
        let response = crate::http_get_json_command(&url, curl());
        peer.join().unwrap();
        assert_eq!(response.unwrap_err(), "HTTP response exceeds byte limit");
    }
}

#[test]
fn get_http_and_json_failures_do_not_echo_peer_content() {
    for status in [200, 503] {
        let (url, peer) = fixture(
            status,
            b"synthetic-peer-private-canary".to_vec(),
            Framing::Length,
        );
        let response = crate::http_get_json_command(&url, curl());
        peer.join().unwrap();
        let error = response.unwrap_err();
        assert!(!error.contains("synthetic-peer-private-canary"));
        assert!(!error.contains(&url));
    }
}

#[test]
fn post_streams_large_input_and_preserves_bearer_and_body() {
    let body = "x".repeat(160 * 1024);
    let (url, peer) = fixture(200, b"{\"synthetic\":true}".to_vec(), Framing::Length);
    let response = http_post_command(&url, &body, 5, Some("synthetic-bearer"), curl());
    let exchange = peer.join().unwrap();
    assert!(exchange.response_complete);
    let request = exchange.request;
    assert_eq!(response.unwrap(), "{\"synthetic\":true}");
    assert!(request.starts_with(b"POST /prove HTTP/1.1"));
    assert!(request
        .windows(b"Authorization: Bearer synthetic-bearer".len())
        .any(|w| w == b"Authorization: Bearer synthetic-bearer"));
    assert!(request.ends_with(body.as_bytes()));
}

#[test]
fn post_exact_limit_succeeds_and_limit_plus_one_refuses() {
    for (len, expected) in [(4 * 1024 * 1024, true), (4 * 1024 * 1024 + 1, false)] {
        let (url, peer) = fixture(200, vec![b'x'; len], Framing::Chunked);
        let response = http_post_command(&url, "{}", 5, None, curl());
        peer.join().unwrap();
        if expected {
            assert_eq!(response.unwrap().len(), len);
        } else {
            assert!(
                matches!(response, Err(ProverClientError::Http(ref message)) if message == "HTTP response exceeds byte limit")
            );
        }
    }
}

#[test]
fn post_401_is_typed_and_other_errors_are_redacted() {
    for status in [401, 422, 503] {
        let (url, peer) = fixture(
            status,
            b"synthetic-peer-private-canary".to_vec(),
            Framing::Length,
        );
        let response = http_post_command(&url, "{}", 5, None, curl());
        peer.join().unwrap();
        if status == 401 {
            assert!(matches!(response, Err(ProverClientError::Unauthorized)));
        } else {
            assert!(
                matches!(response, Err(ProverClientError::Http(ref message)) if message == &format!("prover /prove HTTP {status}"))
            );
        }
    }
}

#[test]
fn post_invalid_timeouts_refuse_before_process_creation() {
    for timeout in [0, u64::MAX] {
        let command = Command::new("this-synthetic-executable-must-not-run");
        assert!(
            matches!(http_post_command("http://127.0.0.1:1", "{}", timeout, None, command),
            Err(ProverClientError::Http(ref message)) if message == "invalid HTTP transport timeout")
        );
    }
}

#[test]
fn prover_decode_errors_do_not_echo_remote_values() {
    let canary = "synthetic-peer-private-canary";
    for field in ["prev_root", "commitment", "proof"] {
        let mut response =
            serde_json::json!({"commitment":format!("0x{}", "11".repeat(32)),"proof":"0x00"});
        response[field] = serde_json::json!(canary);
        let error = parse_prove_resp(&response.to_string()).unwrap_err();
        assert!(!format!("{error:?}").contains(canary));
    }
    let response = format!("{{\"commitment\":{{\"{canary}\":0}},\"proof\":\"0x00\"}}");
    assert!(!format!("{:?}", parse_prove_resp(&response).unwrap_err()).contains(canary));
}

#[test]
fn get_glob_characters_are_one_literal_http_target() {
    for path in ["/case{a,b}/attest", "/case[1-2]/attest"] {
        let (url, peer) = fixture(200, b"{\"synthetic\":true}".to_vec(), Framing::Length);
        let response = crate::http_get_json_command(&format!("{url}{path}"), curl());
        let exchange = peer.join().unwrap();
        assert!(exchange.response_complete);
        assert!(exchange
            .request
            .starts_with(format!("GET {path} HTTP/1.1\r\n").as_bytes()));
        assert_eq!(response.unwrap()["synthetic"], true);
    }
}

#[test]
fn post_glob_characters_are_one_literal_http_target() {
    for path in ["/case{a,b}", "/case[1-2]"] {
        let (url, peer) = fixture(200, b"{\"synthetic\":true}".to_vec(), Framing::Length);
        let body = "synthetic-single-target-body";
        let response = http_post_command(
            &format!("{url}{path}"),
            body,
            5,
            Some("synthetic-bearer"),
            curl(),
        );
        let exchange = peer.join().unwrap();
        assert!(exchange.response_complete);
        assert!(exchange
            .request
            .starts_with(format!("POST {path}/prove HTTP/1.1\r\n").as_bytes()));
        assert!(exchange.request.ends_with(body.as_bytes()));
        assert_eq!(response.unwrap(), "{\"synthetic\":true}");
    }
}

#[test]
fn scheme_less_loopback_http_remains_compatible() {
    let (url, peer) = fixture(200, b"{\"synthetic\":true}".to_vec(), Framing::Length);
    let response = crate::http_get_json_command(url.strip_prefix("http://").unwrap(), curl());
    assert!(peer.join().unwrap().response_complete);
    assert_eq!(response.unwrap()["synthetic"], true);

    let (url, peer) = fixture(200, b"{\"synthetic\":true}".to_vec(), Framing::Length);
    let response = http_post_command(url.strip_prefix("http://").unwrap(), "{}", 5, None, curl());
    assert!(peer.join().unwrap().response_complete);
    assert_eq!(response.unwrap(), "{\"synthetic\":true}");
}

#[test]
fn file_protocol_cannot_supply_attestation_or_receive_proof_body() {
    // Only an owned public fixture is used; no operator files are read.
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("arcora-http-only-{}-{nonce}", std::process::id()));
    std::fs::create_dir(&dir).unwrap();
    struct OwnedDir(std::path::PathBuf);
    impl Drop for OwnedDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _owned = OwnedDir(dir.clone());
    let bytes = b"{\"synthetic-public-canary\":true}";
    let file = dir.join("prove");
    std::fs::write(&file, bytes).unwrap();
    let url = format!("file://{}", file.display());
    let get_error = crate::http_get_json_command(&url, curl()).unwrap_err();
    assert!(get_error.starts_with("attestation HTTP transport exit "));
    assert!(!get_error.contains("synthetic-public-canary"));
    assert!(!get_error.contains(&url));

    let post_error = http_post_command(
        &format!("file://{}", dir.display()),
        "synthetic-proof-input",
        5,
        Some("synthetic-bearer"),
        curl(),
    )
    .unwrap_err();
    assert!(matches!(post_error, ProverClientError::Http(ref message)
        if message.starts_with("prover HTTP transport exit ")
        && !message.contains("synthetic-bearer")
        && !message.contains("synthetic-proof-input")
        && !message.contains("synthetic-public-canary")));
    assert_eq!(std::fs::read(file).unwrap(), bytes);
}

#[test]
fn post_query_fragment_bases_refuse_before_process_creation() {
    for tail in [
        "?",
        "?x=synthetic-private-canary",
        "#",
        "#synthetic-private-canary",
        "?x=1#note",
    ] {
        let base = format!("http://127.0.0.1:1/base{tail}");
        let command = Command::new("this-synthetic-executable-must-not-run");
        let result = http_post_command(
            &base,
            "synthetic-body",
            5,
            Some("synthetic-bearer"),
            command,
        );
        assert!(matches!(result, Err(ProverClientError::Http(ref message))
            if message == "invalid HTTP service base URL"));
    }
}

#[test]
fn post_nested_encoded_base_paths_reach_the_exact_prove_route() {
    for path in ["/nested/base///", "/base/%3F%23/", "/base/%3f%23/"] {
        let (url, peer) = fixture(200, b"{\"synthetic\":true}".to_vec(), Framing::Length);
        let body = "synthetic-base-body";
        let response = http_post_command(
            &format!("{url}{path}"),
            body,
            5,
            Some("synthetic-bearer"),
            curl(),
        );
        let exchange = peer.join().unwrap();
        assert!(exchange.response_complete);
        let target = format!("POST {}/prove HTTP/1.1\r\n", path.trim_end_matches('/'));
        assert!(exchange.request.starts_with(target.as_bytes()));
        assert!(exchange.request.ends_with(body.as_bytes()));
        assert_eq!(response.unwrap(), "{\"synthetic\":true}");
    }
}

#[test]
fn get_nested_encoded_base_paths_reach_the_exact_attest_route() {
    for path in ["/nested/base///", "/base/%3F%23/", "/base/%3f%23/"] {
        let (url, peer) = fixture(200, b"{\"synthetic\":true}".to_vec(), Framing::Length);
        let endpoint =
            crate::curl_transport::service_endpoint(&format!("{url}{path}"), "/attest").unwrap();
        let response = crate::http_get_json_command(&endpoint, curl());
        let exchange = peer.join().unwrap();
        assert!(exchange.response_complete);
        let target = format!("GET {}/attest HTTP/1.1\r\n", path.trim_end_matches('/'));
        assert!(exchange.request.starts_with(target.as_bytes()));
        assert_eq!(response.unwrap()["synthetic"], true);
    }
}

#[test]
fn direct_full_url_get_query_support_remains_unchanged() {
    let (url, peer) = fixture(200, b"{\"synthetic\":true}".to_vec(), Framing::Length);
    let response = crate::http_get_json_command(&format!("{url}/resource?x=1"), curl());
    let exchange = peer.join().unwrap();
    assert!(exchange.response_complete);
    assert!(exchange
        .request
        .starts_with(b"GET /resource?x=1 HTTP/1.1\r\n"));
    assert_eq!(response.unwrap()["synthetic"], true);
}

#[test]
fn post_injected_body_limit_refuses_before_process_creation() {
    let error = crate::prover_client::http_post_command_with_body_limit(
        "http://127.0.0.1:1",
        "synthetic-private-body",
        1,
        Some("synthetic-private-bearer"),
        Command::new("arcora-owned-nonexistent-body-limit-command"),
        4,
    )
    .unwrap_err();
    assert!(matches!(error, ProverClientError::Http(ref message)
        if message == "HTTP request exceeds byte limit"));
}

#[test]
fn post_exact_body_byte_limit_preserves_unicode_body_and_bearer() {
    let body = "éé";
    assert_eq!(body.len(), 4);
    let (url, peer) = fixture(200, b"{}".to_vec(), Framing::Length);
    let response = crate::prover_client::http_post_command_with_body_limit(
        &url,
        body,
        2,
        Some("synthetic-body-budget-token"),
        curl(),
        4,
    );
    let exchange = peer.join().unwrap();
    assert!(exchange.response_complete);
    assert!(exchange.request.starts_with(b"POST /prove HTTP/1.1\r\n"));
    let header_end = exchange
        .request
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .unwrap()
        + 4;
    assert_eq!(&exchange.request[header_end..], body.as_bytes());
    assert!(exchange.request[..header_end]
        .windows(b"Authorization: Bearer synthetic-body-budget-token".len())
        .any(|bytes| bytes == b"Authorization: Bearer synthetic-body-budget-token"));
    assert_eq!(response.unwrap(), "{}");
}

#[cfg(unix)]
#[test]
fn post_one_byte_over_small_budget_creates_no_child_marker_or_peer_request() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let directory = std::env::temp_dir().join(format!(
        "arcora-body-budget-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::create_dir(&directory).unwrap();
    let marker = directory.join("child");
    let mut command = Command::new("/bin/sh");
    command
        .args([
            "-c",
            "printf child > \"$1\"; shift; exec curl \"$@\"",
            "arcora-owned-body-budget",
        ])
        .arg(&marker);
    let error =
        crate::prover_client::http_post_command_with_body_limit(&url, "éé", 1, None, command, 3)
            .unwrap_err();
    assert!(matches!(error, ProverClientError::Http(ref message)
        if message == "HTTP request exceeds byte limit"));
    assert!(!marker.exists(), "owned child started before body refusal");
    assert!(
        matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
    );
    std::fs::remove_dir(directory).unwrap();
}

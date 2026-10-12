#[path="/Users/huseyinarslan/Desktop/arcora-perp/candidate-protocol-20261011/crates/service-transport/curl.rs"]mod curl_transport;
fn http_get_json(url: &str) -> Result<serde_json::Value, String> {
    http_get_json_command(url, std::process::Command::new("curl"))
}
fn http_get_json_command(
    url: &str,
    mut command: std::process::Command,
) -> Result<serde_json::Value, String> {
    command.args([
        "-q",
        "-s",
        "-S",
        "--fail",
        "--connect-timeout",
        "10",
        "--max-time",
        "30",
        "--",
        url,
    ]);
    let out = curl_transport::run(
        command,
        None,
        curl_transport::Limits {
            stdout: curl_transport::MAX_GET_RESPONSE_BYTES,
            stderr: curl_transport::MAX_STDERR_BYTES,
            timeout: std::time::Duration::from_secs(35),
        },
    )
    .map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(format!("attestation HTTP transport exit {}", out.status));
    }
    serde_json::from_slice(&out.stdout).map_err(|_| "invalid attestation JSON response".into())
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

fn fixture(status: u16, payload: Vec<u8>, framing: Framing) -> (String, JoinHandle<Vec<u8>>) {
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
        if socket.write_all(header.as_bytes()).is_ok() {
            for chunk in payload.chunks(8192) {
                if matches!(framing, Framing::Chunked)
                    && write!(socket, "{:x}\r\n", chunk.len()).is_err()
                {
                    break;
                }
                if socket.write_all(chunk).is_err() {
                    break;
                }
                if matches!(framing, Framing::Chunked) && socket.write_all(b"\r\n").is_err() {
                    break;
                }
            }
            if matches!(framing, Framing::Chunked) {
                let _ = socket.write_all(b"0\r\n\r\n");
            }
        }
        request
    });
    (url, handle)
}

fn json_body(len: usize) -> Vec<u8> {
    let mut bytes = b"{\"padding\":\"".to_vec();
    bytes.resize(len - 2, b'x');
    bytes.extend_from_slice(b"\"}");
    bytes
}

#[test]fn exact_fixture(){ for len in [1024usize,1048576] {let(url,peer)=fixture(200,json_body(len),Framing::Length);let result=http_get_json_command(&url,curl());peer.join().unwrap();eprintln!("case={} error={:?}",len,result.as_ref().err());assert!(result.is_ok());} }
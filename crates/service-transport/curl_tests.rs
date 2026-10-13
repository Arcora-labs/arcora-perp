//! Owned native-process and loopback tests; no service, SDK, proxy, or real endpoint is started.
use super::{run, Captured, Error, Limits, MAX_GET_RESPONSE_BYTES, MAX_STDERR_BYTES};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant},
};

const WORKER_MODE: &str = "ARCORA_OWNED_CURL_TEST_WORKER";
const WORKER_PID: &str = "ARCORA_OWNED_CURL_TEST_PID";
const PRIVATE_MARKER: &str = "synthetic-peer-value-must-not-enter-diagnostics";
const LARGE_INPUT: usize = 512 * 1024;
static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

#[test]
fn service_base_query_and_fragment_refuse_without_echoing_values() {
    for tail in [
        "?",
        "?x=synthetic-private-canary",
        "#",
        "#synthetic-private-canary",
        "?x=1#note",
    ] {
        let base = format!("https://example.invalid/base{tail}");
        for path in ["/attest", "/prove"] {
            let error = super::service_endpoint(&base, path).unwrap_err();
            assert_eq!(error, Error::Endpoint);
            assert_eq!(error.to_string(), "invalid HTTP service base URL");
            assert!(!error.to_string().contains(&base));
            assert!(!error.to_string().contains("synthetic-private-canary"));
        }
    }
}

#[test]
fn service_base_join_preserves_encoded_paths_and_existing_address_forms() {
    for (base, expected_attest, expected_prove) in [
        (
            "http://127.0.0.1:8091",
            "http://127.0.0.1:8091/attest",
            "http://127.0.0.1:8091/prove",
        ),
        (
            "https://example.invalid/",
            "https://example.invalid/attest",
            "https://example.invalid/prove",
        ),
        (
            "https://example.invalid/nested/base///",
            "https://example.invalid/nested/base/attest",
            "https://example.invalid/nested/base/prove",
        ),
        (
            "http://[::1]:8091/base/",
            "http://[::1]:8091/base/attest",
            "http://[::1]:8091/base/prove",
        ),
        (
            "127.0.0.1:8091/base/",
            "127.0.0.1:8091/base/attest",
            "127.0.0.1:8091/base/prove",
        ),
        (
            "https://example.invalid/base/%3F%23/",
            "https://example.invalid/base/%3F%23/attest",
            "https://example.invalid/base/%3F%23/prove",
        ),
        (
            "https://example.invalid/base/%3f%23/",
            "https://example.invalid/base/%3f%23/attest",
            "https://example.invalid/base/%3f%23/prove",
        ),
    ] {
        assert_eq!(
            super::service_endpoint(base, "/attest").unwrap(),
            expected_attest
        );
        assert_eq!(
            super::service_endpoint(base, "/prove").unwrap(),
            expected_prove
        );
    }
}

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let parent = std::env::temp_dir()
            .canonicalize()
            .expect("owned temp parent");
        loop {
            let path = parent.join(format!(
                "arcora-owned-curl-test-{}-{}",
                std::process::id(),
                NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
            ));
            let mut builder = fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            match builder.create(&path) {
                Ok(()) => return Self(path),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(_) => panic!("owned temp directory creation failed"),
            }
        }
    }

    fn pid_path(&self) -> PathBuf {
        self.0.join("direct-child.pid")
    }

    fn assert_reaped(&self) {
        let pid: u32 = fs::read_to_string(self.pid_path())
            .expect("direct child published its PID")
            .parse()
            .expect("owned PID is numeric");
        assert_ne!(pid, std::process::id());
        #[cfg(unix)]
        {
            // Signal zero is a read-only existence check. A zombie still exists,
            // so failure also distinguishes kill-only cleanup from wait/reap.
            let status = Command::new("/bin/kill")
                .args(["-0", &pid.to_string()])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .expect("read-only direct child existence check");
            assert!(!status.success(), "direct child remains after run returned");
        }
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).expect("remove only owned curl fixture");
    }
}

fn worker(mode: &str, scratch: &Scratch) -> Command {
    let module = module_path!()
        .split_once("::")
        .expect("test module has a crate prefix")
        .1;
    let mut command = Command::new(std::env::current_exe().expect("current test executable"));
    command
        .env_clear()
        .env(WORKER_MODE, mode)
        .env(WORKER_PID, scratch.pid_path())
        .args([
            "--exact",
            &format!("{module}::subprocess_worker"),
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ]);
    command
}

fn limits(stdout: usize, stderr: usize, timeout: Duration) -> Limits {
    Limits {
        stdout,
        stderr,
        timeout,
    }
}

fn failure(result: Result<Captured, Error>) -> Error {
    match result {
        Err(error) => {
            assert!(!error.to_string().contains(PRIVATE_MARKER));
            error
        }
        Ok(_) => panic!("transport unexpectedly accepted the fixture failure"),
    }
}

fn curl(address: SocketAddr) -> Command {
    assert!(address.ip().is_loopback());
    let mut command = Command::new("curl");
    command.args([
        "-q",
        "-s",
        "-S",
        "--noproxy",
        "*",
        "--connect-timeout",
        "2",
        "--max-time",
        "4",
    ]);
    command
}

fn peer<T: Send + 'static>(
    handler: impl FnOnce(TcpStream) -> T + Send + 'static,
) -> (SocketAddr, thread::JoinHandle<T>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("owned loopback listener");
    let address = listener.local_addr().expect("owned listener address");
    listener
        .set_nonblocking(true)
        .expect("bounded owned accept");
    let handle = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(6);
        let stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "owned curl did not connect");
                    thread::sleep(Duration::from_millis(1));
                }
                Err(_) => panic!("owned listener accept failed"),
            }
        };
        // Accepted sockets can inherit the listener's nonblocking flag on BSD.
        // The fixture's read/write timeouts require blocking socket operations.
        stream.set_nonblocking(false).expect("owned blocking peer");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("owned peer read budget");
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .expect("owned peer write budget");
        handler(stream)
    });
    (address, handle)
}

fn request(stream: &mut TcpStream) -> (String, Vec<u8>) {
    let mut headers = Vec::new();
    while !headers.ends_with(b"\r\n\r\n") {
        assert!(
            headers.len() < 8192,
            "owned request headers exceeded fixture cap"
        );
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte).expect("owned request headers");
        headers.push(byte[0]);
    }
    let headers = String::from_utf8(headers).expect("owned ASCII HTTP headers");
    let mut length = 0;
    for line in headers.lines() {
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                length = value.trim().parse::<usize>().expect("owned body length");
            }
            if name.eq_ignore_ascii_case("expect")
                && value.trim().eq_ignore_ascii_case("100-continue")
            {
                stream
                    .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
                    .expect("owned continue response");
            }
        }
    }
    assert!(length <= LARGE_INPUT, "fixture request body is bounded");
    let mut body = vec![0u8; length];
    stream.read_exact(&mut body).expect("owned request body");
    (headers, body)
}

#[test]
fn curl_get_exact_byte_cap_is_accepted_and_one_more_is_refused() {
    for over in [false, true] {
        let body = vec![b'G'; MAX_GET_RESPONSE_BYTES + usize::from(over)];
        let (address, server) = peer(move |mut stream| {
            let (headers, input) = request(&mut stream);
            assert!(headers.starts_with("GET /bounded-get HTTP/1.1\r\n"));
            assert!(input.is_empty());
            let headers = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream
                .write_all(headers.as_bytes())
                .expect("owned response headers");
            // The over-limit client may close while this owned peer is writing.
            let _ = stream.write_all(&body);
        });
        let mut command = curl(address);
        command.args(["--", &format!("http://{address}/bounded-get")]);
        let result = run(
            command,
            None,
            limits(
                MAX_GET_RESPONSE_BYTES,
                MAX_STDERR_BYTES,
                Duration::from_secs(5),
            ),
        );
        server.join().expect("owned GET peer joined");
        if over {
            assert_eq!(failure(result), Error::StdoutLimit);
        } else {
            let captured = result.expect("exact GET byte cap succeeds");
            assert!(captured.status.success());
            assert_eq!(captured.stdout, vec![b'G'; MAX_GET_RESPONSE_BYTES]);
        }
    }
}

#[test]
fn curl_post_sends_large_stdin_exactly_and_keeps_status_suffix() {
    let input = vec![b'I'; LARGE_INPUT];
    let expected = input.clone();
    let reply = br#"{"fixture":"synthetic"}"#;
    let (address, server) = peer(move |mut stream| {
        let (headers, body) = request(&mut stream);
        assert!(headers.starts_with("POST /bounded-post HTTP/1.1\r\n"));
        assert!(headers.contains("Authorization: Bearer synthetic-fixture-token\r\n"));
        assert_eq!(body, expected);
        let headers = format!(
            "HTTP/1.1 201 Created\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            reply.len()
        );
        stream
            .write_all(headers.as_bytes())
            .expect("owned POST response headers");
        stream.write_all(reply).expect("owned POST response body");
    });
    let mut command = curl(address);
    command.args([
        "-X",
        "POST",
        "-H",
        "Content-Type: application/json",
        "-H",
        "Authorization: Bearer synthetic-fixture-token",
        "--data-binary",
        "@-",
        "-w",
        "\n__CURL_FIXTURE_STATUS__%{http_code}",
        "--",
        &format!("http://{address}/bounded-post"),
    ]);
    let captured = run(
        command,
        Some(&input),
        limits(1024, MAX_STDERR_BYTES, Duration::from_secs(5)),
    )
    .expect("owned POST transfer succeeds");
    server.join().expect("owned POST peer joined");
    assert!(captured.status.success());
    let mut expected = reply.to_vec();
    expected.extend_from_slice(b"\n__CURL_FIXTURE_STATUS__201");
    assert_eq!(captured.stdout, expected);
}

#[test]
fn curl_incomplete_body_keeps_non_success_exit_even_with_valid_json_prefix() {
    let body = br#"{"commitment":"synthetic-prefix"}"#;
    let (address, server) = peer(move |mut stream| {
        let _ = request(&mut stream);
        let headers = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len() + 1
        );
        stream
            .write_all(headers.as_bytes())
            .expect("owned truncated headers");
        stream.write_all(body).expect("owned truncated body");
    });
    let mut command = curl(address);
    command.args(["--", &format!("http://{address}/incomplete")]);
    let captured = run(
        command,
        None,
        limits(1024, MAX_STDERR_BYTES, Duration::from_secs(5)),
    )
    .expect("ordinary curl failure remains a captured exit status");
    server.join().expect("owned truncated peer joined");
    assert_eq!(captured.status.code(), Some(18));
    assert_eq!(captured.stdout, body.to_vec());
}

#[test]
fn simultaneous_stdout_stderr_and_large_stdin_complete_without_pipe_deadlock() {
    let scratch = Scratch::new();
    let input = vec![b'I'; LARGE_INPUT];
    let captured = run(
        worker("pressure", &scratch),
        Some(&input),
        limits(128 * 1024, 128 * 1024, Duration::from_secs(5)),
    )
    .expect("simultaneous bounded pipes succeed");
    assert!(captured.status.success());
    assert!(captured
        .stdout
        .windows(b"OWNED_PRESSURE_COMPLETE".len())
        .any(|bytes| bytes == b"OWNED_PRESSURE_COMPLETE"));
    assert!(!captured
        .stdout
        .windows(PRIVATE_MARKER.len())
        .any(|bytes| bytes == PRIVATE_MARKER.as_bytes()));
    scratch.assert_reaped();
}

#[test]
fn either_pipe_overflow_reaps_child_and_unblocks_large_stdin_writer() {
    for (mode, expected) in [
        ("stdout-overflow", Error::StdoutLimit),
        ("stderr-overflow", Error::StderrLimit),
    ] {
        let scratch = Scratch::new();
        let input = vec![b'I'; 8 * 1024 * 1024];
        let started = Instant::now();
        let result = run(
            worker(mode, &scratch),
            Some(&input),
            limits(32 * 1024, 32 * 1024, Duration::from_secs(5)),
        );
        assert_eq!(failure(result), expected);
        assert!(started.elapsed() < Duration::from_secs(8));
        scratch.assert_reaped();
    }
}

#[test]
fn supervisor_deadline_reaps_stalled_child_and_unblocks_stdin() {
    let scratch = Scratch::new();
    let input = vec![b'I'; 8 * 1024 * 1024];
    let started = Instant::now();
    let result = run(
        worker("stall", &scratch),
        Some(&input),
        limits(32 * 1024, 32 * 1024, Duration::from_secs(2)),
    );
    assert_eq!(failure(result), Error::Deadline);
    assert!(started.elapsed() < Duration::from_secs(8));
    scratch.assert_reaped();
}

#[test]
fn early_closed_stdin_spawn_and_configuration_errors_are_static_and_redacted() {
    let scratch = Scratch::new();
    let input = vec![b'I'; 8 * 1024 * 1024];
    assert_eq!(
        failure(run(
            worker("close-stdin", &scratch),
            Some(&input),
            limits(32 * 1024, 32 * 1024, Duration::from_secs(5)),
        )),
        Error::Write
    );
    scratch.assert_reaped();
    let missing = scratch.0.join(PRIVATE_MARKER);
    assert_eq!(
        failure(run(
            Command::new(&missing),
            Some(PRIVATE_MARKER.as_bytes()),
            limits(1024, 1024, Duration::from_secs(1)),
        )),
        Error::Spawn
    );
    assert_eq!(
        failure(run(
            Command::new(&missing),
            Some(PRIVATE_MARKER.as_bytes()),
            limits(0, 1024, Duration::from_secs(1)),
        )),
        Error::Configuration
    );
}

#[test]
#[ignore = "private native child fixture; invoked by exact name with owned synthetic env only"]
fn subprocess_worker() {
    let mode = std::env::var(WORKER_MODE).expect("explicit owned worker mode");
    let path = PathBuf::from(std::env::var_os(WORKER_PID).expect("explicit owned PID fixture"));
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).expect("exclusive owned PID file");
    write!(file, "{}", std::process::id()).expect("publish owned child PID");
    file.sync_all().expect("durable owned child PID");
    match mode.as_str() {
        "pressure" => {
            let output = thread::spawn(|| {
                std::io::stdout()
                    .write_all(&vec![b'O'; 64 * 1024])
                    .expect("owned stdout pressure");
            });
            let diagnostics = thread::spawn(|| {
                let mut stderr = std::io::stderr();
                stderr
                    .write_all(PRIVATE_MARKER.as_bytes())
                    .expect("owned synthetic diagnostics");
                stderr
                    .write_all(&vec![b'E'; 64 * 1024])
                    .expect("owned stderr pressure");
            });
            let mut input = Vec::new();
            std::io::stdin()
                .take((LARGE_INPUT + 1) as u64)
                .read_to_end(&mut input)
                .expect("owned large stdin");
            assert_eq!(input, vec![b'I'; LARGE_INPUT]);
            output.join().expect("owned stdout writer joined");
            diagnostics.join().expect("owned stderr writer joined");
            println!("OWNED_PRESSURE_COMPLETE");
        }
        "stdout-overflow" | "stderr-overflow" => {
            let bytes = vec![b'X'; 1024 * 1024];
            if mode == "stdout-overflow" {
                let _ = std::io::stdout().write_all(&bytes);
            } else {
                let _ = std::io::stderr().write_all(PRIVATE_MARKER.as_bytes());
                let _ = std::io::stderr().write_all(&bytes);
            }
            // Never consume stdin or exit after a reader closes: the supervisor
            // must kill this direct child and unblock its own pipe writer.
            thread::sleep(Duration::from_secs(60));
        }
        "stall" => thread::sleep(Duration::from_secs(60)),
        "close-stdin" => {
            let _ = std::io::stderr().write_all(PRIVATE_MARKER.as_bytes());
            std::process::exit(23);
        }
        _ => panic!("unknown owned worker mode"),
    }
}

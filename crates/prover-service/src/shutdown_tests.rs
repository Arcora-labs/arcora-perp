//! Owned-process SIGTERM tests. The HTTP and admission/signal/spawn boundaries
//! are production code; only the expensive proof closure is synthetic.
use super::{admission::Gate, serve_until_shutdown, shutdown_signal, ProofAdmission};
use axum::{
    body::Body,
    extract::{FromRef, State},
    http::{Request, StatusCode},
    routing::{get, post},
    Json, Router,
};
use std::{
    io::{Read, Write},
    net::{Shutdown, SocketAddr, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};
use tower::ServiceExt;

const CHILD_TEST: &str = "shutdown_tests::owned_shutdown_child";
const TEST_BEARER: &str = "owned-process-test";

struct ChildState {
    gate: Gate,
    dir: PathBuf,
}

impl FromRef<Arc<ChildState>> for Gate {
    fn from_ref(state: &Arc<ChildState>) -> Self {
        state.gate.clone()
    }
}

struct HandlerDrop(PathBuf);
impl Drop for HandlerDrop {
    fn drop(&mut self) {
        // This records whether the transport actually cancelled its service
        // future. Some HTTP transports retain the waiter after client EOF.
        std::fs::write(&self.0, b"handler dropped").unwrap();
    }
}

async fn synthetic_prove(
    State(state): State<Arc<ChildState>>,
    admission: ProofAdmission,
) -> Result<&'static str, StatusCode> {
    let _handler = HandlerDrop(state.dir.join("handler-dropped"));
    let dir = state.dir.clone();
    let runtime = tokio::runtime::Handle::current();
    admission
        .run_blocking(move || {
            std::fs::write(dir.join("worker-started"), b"started").unwrap();
            let deadline = Instant::now() + Duration::from_secs(10);
            while !dir.join("release-worker").exists() {
                assert!(
                    Instant::now() < deadline,
                    "parent failed to release owned worker"
                );
                std::thread::sleep(Duration::from_millis(5));
            }
            // Sp1GnarkProver also enters its captured Tokio handle from the
            // blocking closure. Keep timer/I/O services alive, not just the OS
            // worker thread, until this accepted operation has truly finished.
            runtime.block_on(async {
                tokio::time::sleep(Duration::from_millis(10)).await;
            });
            // Record the actual work outcome before releasing its permit. This
            // is test observation only, not durable production proof storage.
            std::fs::write(
                dir.join("worker-outcome.json"),
                br#"{"synthetic":true,"completed":true,"result":"owned-worker-complete"}"#,
            )
            .unwrap();
            "owned-worker-complete"
        })
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

async fn status(State(state): State<Arc<ChildState>>) -> Json<serde_json::Value> {
    let (closed, available) = state.gate.test_status();
    Json(serde_json::json!({"admissionClosed":closed,"availableSlots":available}))
}

/// Invoked only by the two parent tests below. It never initializes SP1.
#[test]
#[ignore = "owned subprocess fixture; launched by the SIGTERM parent tests"]
fn owned_shutdown_child() {
    let dir =
        PathBuf::from(std::env::var_os("ARCORA_PROVER_CHILD_DIR").expect("parent fixture dir"));
    let gate = Gate::new(Some(TEST_BEARER.into()), u64::MAX, 1);
    let final_gate = gate.clone();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let state = Arc::new(ChildState {
            gate: gate.clone(),
            dir: dir.clone(),
        });
        let router = Router::new()
            .route("/prove", post(synthetic_prove))
            .route("/status", get(status))
            .with_state(state);
        // Production constructs the OS signal streams synchronously before
        // binding, without needing a test-only pre-poll of the shutdown future.
        let signal = shutdown_signal(gate.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        std::fs::write(
            dir.join("address.tmp"),
            listener.local_addr().unwrap().to_string(),
        )
        .unwrap();
        // Publish readiness only after the full address is visible: existence
        // alone must not let the parent read a newly created but empty file.
        std::fs::rename(dir.join("address.tmp"), dir.join("address")).unwrap();
        let stopped_dir = dir.clone();
        let stopped_gate = gate.clone();
        serve_until_shutdown(listener, router.clone(), gate.clone(), async move {
            signal.await;
            assert!(
                stopped_gate.test_status().0,
                "signal must close admission first"
            );
            std::fs::write(stopped_dir.join("admission-closed"), b"closed").unwrap();
        })
        .await
        .unwrap();
        // The same extractor still rejects after the server has drained. This
        // checks gate closure as well as the externally closed listener.
        let response = router
            .oneshot(
                Request::post("/prove")
                    .header("authorization", format!("Bearer {TEST_BEARER}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        std::fs::write(dir.join("gate-rejected-after-drain"), b"503").unwrap();
        std::fs::write(dir.join("server-drained"), b"drained").unwrap();
    });
    // Match #[tokio::main]'s actual runtime teardown. Detached blocking work
    // survives an HTTP cancellation and must finish before this returns.
    drop(runtime);
    assert!(
        dir.join("worker-outcome.json").exists(),
        "runtime exited before work completed"
    );
    assert_eq!(final_gate.test_status(), (true, 1));
    std::fs::write(dir.join("runtime-dropped"), b"completed and slot released").unwrap();
}

struct OwnedChild {
    child: Child,
    dir: PathBuf,
}

impl OwnedChild {
    fn start() -> Self {
        let mut random = [0u8; 8];
        getrandom::getrandom(&mut random).unwrap();
        let dir = std::env::temp_dir().join(format!(
            "arcora-prover-shutdown-{}-{}",
            std::process::id(),
            hex::encode(random)
        ));
        std::fs::create_dir(&dir).unwrap();
        let log = std::fs::File::create(dir.join("child.log")).unwrap();
        let child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                CHILD_TEST,
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("ARCORA_PROVER_CHILD_DIR", &dir)
            .stdin(Stdio::null())
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap();
        Self { child, dir }
    }

    fn wait_for(&mut self, name: &str) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !self.dir.join(name).exists() {
            assert!(
                self.child.try_wait().unwrap().is_none(),
                "child exited before {name}: {}",
                self.log()
            );
            assert!(
                Instant::now() < deadline,
                "timeout waiting for {name}: {}",
                self.log()
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.dir.join("child.log")).unwrap_or_default()
    }

    fn finish(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(status.success(), "child failed: {}", self.log());
                break;
            }
            assert!(
                Instant::now() < deadline,
                "child failed to drain: {}",
                self.log()
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill(); // Only this test's owned child, on failure.
            let _ = self.child.wait();
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn open_request(address: SocketAddr, path: &str, method: &str) -> TcpStream {
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(2)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    write!(stream, "{method} {path} HTTP/1.1\r\nHost: {address}\r\nAuthorization: Bearer {TEST_BEARER}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
    stream
}

fn read_response(mut stream: TcpStream) -> String {
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
}

fn assert_marker(dir: &Path, name: &str) {
    assert!(dir.join(name).exists(), "missing child evidence: {name}");
}

fn sigterm_scenario(cancel_http: bool) {
    let mut owned = OwnedChild::start();
    owned.wait_for("address");
    let address: SocketAddr = std::fs::read_to_string(owned.dir.join("address"))
        .unwrap()
        .parse()
        .unwrap();
    assert!(address.ip().is_loopback());
    let accepted = open_request(address, "/prove", "POST");
    owned.wait_for("worker-started");
    let accepted = if cancel_http {
        accepted.shutdown(Shutdown::Both).unwrap();
        drop(accepted);
        owned.wait_for("handler-dropped");
        None
    } else {
        Some(accepted)
    };
    let status = read_response(open_request(address, "/status", "GET"));
    assert!(status.starts_with("HTTP/1.1 200"), "{status}");
    assert!(
        status.contains("\"availableSlots\":0"),
        "worker slot released early: {status}"
    );
    assert!(status.contains("\"admissionClosed\":false"), "{status}");
    let overload = read_response(open_request(address, "/prove", "POST"));
    assert!(overload.starts_with("HTTP/1.1 503"), "{overload}");
    assert!(!owned.dir.join("worker-outcome.json").exists());
    assert!(owned.child.try_wait().unwrap().is_none());
    let signal_at = Instant::now();
    let signal = Command::new("/bin/kill")
        .args(["-TERM", &owned.child.id().to_string()])
        .status()
        .unwrap();
    assert!(signal.success());
    owned.wait_for("admission-closed");
    // Hold a known unfinished worker for a bounded observation interval. A
    // shutdown that silently cancels work would exit or report success here.
    std::thread::sleep(Duration::from_millis(100));
    assert!(
        owned.child.try_wait().unwrap().is_none(),
        "process exited with unfinished work: {}",
        owned.log()
    );
    assert!(!owned.dir.join("worker-outcome.json").exists());
    assert!(!owned.dir.join("runtime-dropped").exists());
    assert!(
        TcpStream::connect_timeout(&address, Duration::from_millis(200)).is_err(),
        "listener still accepted after SIGTERM"
    );
    let handler_cancelled_before_release = owned.dir.join("handler-dropped").exists();
    std::fs::write(owned.dir.join("release-worker"), b"release").unwrap();
    if let Some(stream) = accepted {
        let result = read_response(stream);
        assert!(result.starts_with("HTTP/1.1 200"), "{result}");
        assert!(
            result.ends_with("owned-worker-complete"),
            "accepted outcome lost: {result}"
        );
    }
    owned.finish();
    for marker in [
        "worker-outcome.json",
        "gate-rejected-after-drain",
        "server-drained",
        "runtime-dropped",
    ] {
        assert_marker(&owned.dir, marker);
    }
    let result: serde_json::Value =
        serde_json::from_slice(&std::fs::read(owned.dir.join("worker-outcome.json")).unwrap())
            .unwrap();
    assert_eq!(result["completed"], true);
    println!(
        "PROVER_PROCESS_DRAIN {}",
        serde_json::json!({
            "cancelledHttpClient":cancel_http,
            "handlerCancelledBeforeWorkerRelease":handler_cancelled_before_release,
            "signal":"SIGTERM", "listenerClosedBeforeWorkerRelease":true,
            "slotRetainedAfterClientDisconnect":cancel_http,
            "admissionClosed":true,"postDrainAdmissionStatus":503,
            "workerCompletedBeforeExit":true,"processExit":0,
            "elapsedAfterSignalMs":signal_at.elapsed().as_millis(),
            "realProof":false
        })
    );
}

#[test]
fn sigterm_drains_accepted_request_before_owned_process_exit() {
    sigterm_scenario(false);
}

#[test]
fn sigterm_after_http_cancellation_keeps_owned_worker_until_completion() {
    sigterm_scenario(true);
}

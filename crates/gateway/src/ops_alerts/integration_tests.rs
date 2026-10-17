//! Controlled local faults through production state transitions and real sealed
//! snapshot writes. The collector uses actual HTTP sockets; L1 observations are
//! explicit fixtures, and no live-chain/operator delivery is implied.
use super::*;
use crate::*;
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    sync::atomic::{AtomicBool, AtomicU16, AtomicUsize, Ordering},
    thread::JoinHandle,
    time::Duration,
};

const SECRET_ERROR: &str =
    "fixture failure at https://user:fake-password@rpc.example/?key=fake-rpc-token";

struct Collector {
    url: String,
    events: Arc<std::sync::Mutex<Vec<serde_json::Value>>>,
    status: Arc<AtomicU16>,
    /// Requests still to be answered 503 before `status` applies.
    reject_first: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

/// Same attempt bound as production with millisecond backoff, so retry tests
/// exercise the real worker loop without slowing the suite.
const FAST_RETRY: RetryPolicy = RetryPolicy {
    attempts: DELIVERY_RETRY.attempts,
    backoff: Duration::from_millis(5),
};
impl Collector {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/alerts", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let output = events.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let status = Arc::new(AtomicU16::new(204));
        let response = status.clone();
        let reject_first = Arc::new(AtomicUsize::new(0));
        let rejecting = reject_first.clone();
        let worker = std::thread::spawn(move || {
            while !stopped.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut socket, peer)) => {
                        assert!(peer.ip().is_loopback());
                        // BSD/macOS accepts may inherit O_NONBLOCK. This parser
                        // is deliberately blocking with a timeout, even though
                        // accept itself is polled so shutdown remains bounded.
                        socket.set_nonblocking(false).unwrap();
                        socket
                            .set_write_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        socket
                            .set_read_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        let body = read_body(&mut socket);
                        let event: serde_json::Value = serde_json::from_slice(&body).unwrap();
                        output.lock().unwrap().push(event);
                        // Only this collector thread decrements; tests set the
                        // count before any alert is raised.
                        let remaining = rejecting.load(Ordering::SeqCst);
                        let rejected = remaining > 0;
                        if rejected {
                            rejecting.store(remaining - 1, Ordering::SeqCst);
                        }
                        let status = if rejected {
                            503
                        } else {
                            response.load(Ordering::SeqCst)
                        };
                        write!(socket, "HTTP/1.1 {status} Test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("collector failed: {error}"),
                }
            }
        });
        Self {
            url,
            events,
            status,
            reject_first,
            stop,
            worker: Some(worker),
        }
    }
    fn dispatcher(&self) -> OpsAlerts {
        OpsAlerts::configured_with(Some(&self.url), None, FAST_RETRY).unwrap()
    }
    fn observed(&self, alerts: &OpsAlerts) -> Vec<serde_json::Value> {
        alerts.flush();
        self.events.lock().unwrap().clone()
    }
}
impl Drop for Collector {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            let joined = worker.join();
            // Preserve the first failed assertion; never abort the whole test
            // process with a second panic while unwinding. A worker panic still
            // fails normal teardown rather than silently becoming a pass.
            if !std::thread::panicking() {
                joined.expect("collector worker failed");
            }
        }
    }
}
fn read_body(socket: &mut TcpStream) -> Vec<u8> {
    let mut data = Vec::new();
    let mut buffer = [0; 2048];
    let header_end = loop {
        let n = socket.read(&mut buffer).unwrap();
        assert!(n > 0 && data.len() < 8192, "bounded collector request");
        data.extend_from_slice(&buffer[..n]);
        if let Some(i) = data.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
    };
    let header = std::str::from_utf8(&data[..header_end]).unwrap();
    assert!(header.starts_with("POST /alerts HTTP/1.1\r\n"));
    assert!(header
        .to_ascii_lowercase()
        .contains("content-type: application/json"));
    let length = header
        .lines()
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().unwrap())
        })
        .unwrap();
    assert!(length <= 512);
    while data.len() < header_end + length {
        let n = socket.read(&mut buffer).unwrap();
        assert!(n > 0);
        data.extend_from_slice(&buffer[..n]);
    }
    data[header_end..header_end + length].to_vec()
}

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "arcora-alert-drill-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let removed = std::fs::remove_dir_all(&self.0);
        if !std::thread::panicking() {
            removed.expect("alert scratch cleanup failed");
        }
    }
}
fn check_event(event: &serde_json::Value, kind: &str, transition: &str, episode: u64) {
    assert_eq!(
        event,
        &serde_json::json!({
            "schema": "arcora.ops-alert.v1", "event": kind,
            "transition": transition, "episode": episode,
        })
    );
    let raw = event.to_string();
    for secret in ["fake-password", "fake-rpc-token", "rpc.example", "user:"] {
        assert!(!raw.contains(secret));
    }
}
fn evidence(name: &str, events: &[serde_json::Value]) {
    println!(
        "ALERT_DRILL_EVIDENCE {}",
        serde_json::json!({"case": name, "transport": "actual-loopback-http", "events": events})
    );
}

#[tokio::test]
async fn held_production_transitions_deliver_once_recover_and_rearm() {
    let collector = Collector::start();
    let alerts = collector.dispatcher();
    let app = crate::tests::test_app();
    let snapshot_before = app.gw.lock().await.snapshot_plain();
    {
        let mut gw = app.gw.lock().await;
        gw.ops_alerts = alerts.clone();
        gw.settle_health =
            settle_health::SettleHealth::new(3, Duration::from_secs(1), Duration::from_secs(2));
        for _ in 0..4 {
            gw.settle_breaker_failed(SECRET_ERROR.into());
        }
        assert_eq!(gw.settle_health.health(), settle_health::Health::Held);
    }
    assert_eq!(
        snapshot_before,
        app.gw.lock().await.snapshot_plain(),
        "runtime alert and breaker state must not alter the historical snapshot layout"
    );
    let first = collector.observed(&alerts);
    assert_eq!(first.len(), 1);
    check_event(&first[0], "settlement_held", "active", 1);
    assert!(app.gw.lock().await.settle_breaker_recovered());
    hold_settlement_for_recovery(&app, SECRET_ERROR.into()).await;
    hold_settlement_for_recovery(&app, SECRET_ERROR.into()).await;
    {
        let gw = app.gw.lock().await;
        assert!(gw.settle_health.recovery_required());
        assert!(request_settlement_retry(&gw, &app.force_settle).is_err());
        assert_eq!(gw.settle_health.health(), settle_health::Health::Held);
    }
    let events = collector.observed(&alerts);
    assert_eq!(events.len(), 3);
    check_event(&events[1], "settlement_held", "recovered", 1);
    check_event(&events[2], "settlement_held", "active", 2);
    evidence("held-recovery-rearm", &events);
}

#[tokio::test]
async fn real_snapshot_write_failure_delivers_once_and_real_write_recovers() {
    let collector = Collector::start();
    let alerts = collector.dispatcher();
    let app = crate::tests::test_app();
    app.gw.lock().await.ops_alerts = alerts.clone();
    let dir = Scratch::new();
    let parent_file = dir.0.join("parent-file");
    std::fs::write(&parent_file, b"preserve").unwrap();
    let bad = parent_file.join("state");
    let serial = Arc::new(tokio::sync::Mutex::new(()));
    for _ in 0..2 {
        assert!(!write_snapshot(&app, &bad, [41; 32], serial.clone()).await);
    }
    let (frozen, ok) = final_snapshot(&app, &bad, [41; 32], serial.clone()).await;
    assert!(
        !ok,
        "failed persistence must remain failed regardless of notification"
    );
    drop(frozen);
    assert_eq!(std::fs::read(parent_file).unwrap(), b"preserve");
    assert_eq!(collector.observed(&alerts).len(), 1);
    let good = dir.0.join("state");
    assert!(write_snapshot(&app, &good, [41; 32], serial.clone()).await);
    let plain = snapshot::open(&std::fs::read(good).unwrap(), &[41; 32]).unwrap();
    let restored = Gw::boot_restored(&plain).unwrap();
    assert_eq!(
        restored.snapshot_plain(),
        app.gw.lock().await.snapshot_plain()
    );
    assert!(!write_snapshot(&app, &bad, [41; 32], serial.clone()).await);
    let events = collector.observed(&alerts);
    assert_eq!(events.len(), 3);
    check_event(&events[0], "persistence_failed", "active", 1);
    check_event(&events[1], "persistence_failed", "recovered", 1);
    check_event(&events[2], "persistence_failed", "active", 2);
    evidence("filesystem-failure-recovery-rearm", &events);
}

struct ReorgRpc {
    calls: Arc<AtomicUsize>,
    chain: u64,
}
impl deposit_rpc::Rpc for ReorgRpc {
    fn call(
        &self,
        method: &str,
        params: Vec<serde_json::Value>,
    ) -> Result<serde_json::Value, String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match method {
            "eth_chainId" => Ok(serde_json::json!(format!("0x{:x}", self.chain))),
            "eth_getBlockByNumber" if params[0] == "finalized" => {
                Ok(deposit_rpc::test_header(2, 0))
            }
            "eth_getBlockByNumber" if params[0] == "0x1" => {
                // The previously persisted finalized block had hash 7, whereas
                // this canonical-height lookup now yields another (valid) header.
                // VaultSource's real anchor validator, not this fixture, constructs
                // Error::Halt.
                Ok(deposit_rpc::test_header(1, 9))
            }
            _ => panic!("unexpected reader request: {method}"),
        }
    }
}

#[tokio::test]
async fn deposit_halt_production_ingestion_delivers_once_and_stays_halted_after_restore() {
    let collector = Collector::start();
    let alerts = collector.dispatcher();
    let mut app = crate::tests::test_app();
    let calls = Arc::new(AtomicUsize::new(0));
    let (tx, mut rx) = tokio::sync::mpsc::channel::<SnapshotAck>(4);
    let inner = Arc::get_mut(&mut app).unwrap();
    inner.snapshot_req = Some(tx);
    let gw = inner.gw.get_mut();
    gw.ops_alerts = alerts.clone();
    gw.deposits.anchor = Some(deposit_rpc::Block {
        number: 1,
        hash: [7; 32],
        timestamp: None,
    });
    inner.deposit_source = Some(Arc::new(deposit_rpc::VaultSource::new(ReorgRpc {
        calls: calls.clone(),
        chain: gw.chain_id,
    })));
    let dir = Scratch::new();
    let state = dir.0.join("state");
    let writer_app = app.clone();
    let writer_path = state.clone();
    let writer = tokio::spawn(async move {
        let ack = rx.recv().await.unwrap();
        let ok = write_snapshot(
            &writer_app,
            &writer_path,
            [42; 32],
            Arc::new(tokio::sync::Mutex::new(())),
        )
        .await;
        assert!(ok);
        ack.send(ok).unwrap();
    });
    for _ in 0..2 {
        assert!(deposit_ingestion::ingest_once(&app).await.is_err());
    }
    writer.await.unwrap();
    assert_eq!(
        calls.load(Ordering::SeqCst),
        3,
        "the second poll must honor the persisted halt without repeating the three RPC reads"
    );
    let events = collector.observed(&alerts);
    assert_eq!(events.len(), 1);
    check_event(&events[0], "deposit_halted", "active", 1);
    let sealed = std::fs::read(state).unwrap();
    let restored = Gw::boot_restored(&snapshot::open(&sealed, &[42; 32]).unwrap()).unwrap();
    assert!(restored.deposits.halt.is_some());
    assert!(restored.deposits.check_ready().is_err());
    assert!(app.gw.lock().await.deposits.check_ready().is_err());
    evidence("durable-deposit-halt", &events);
}

#[tokio::test]
async fn collector_rejection_never_makes_failed_persistence_succeed() {
    let collector = Collector::start();
    collector.status.store(503, Ordering::SeqCst);
    let alerts = collector.dispatcher();
    let app = crate::tests::test_app();
    app.gw.lock().await.ops_alerts = alerts.clone();
    let dir = Scratch::new();
    let file = dir.0.join("file");
    std::fs::write(&file, b"keep").unwrap();
    for _ in 0..2 {
        assert!(
            !write_snapshot(
                &app,
                &file.join("state"),
                [43; 32],
                Arc::new(tokio::sync::Mutex::new(()))
            )
            .await
        );
    }
    // One episode; a rejecting collector receives the same redacted body once
    // per bounded attempt and the failure stays failed.
    let events = collector.observed(&alerts);
    assert_eq!(events.len(), DELIVERY_RETRY.attempts as usize);
    for event in &events {
        check_event(event, "persistence_failed", "active", 1);
    }
    evidence("collector-503-retains-failure", &events);
}

#[test]
fn rejected_delivery_stops_at_the_attempt_bound() {
    let collector = Collector::start();
    collector.status.store(503, Ordering::SeqCst);
    let alerts = collector.dispatcher();
    alerts.activate(AlertKind::SettlementHeld);
    let events = collector.observed(&alerts);
    assert_eq!(events.len(), DELIVERY_RETRY.attempts as usize);
    for event in &events {
        check_event(event, "settlement_held", "active", 1);
    }
}

#[test]
fn delivery_retries_a_transient_rejection_then_stops() {
    let collector = Collector::start();
    collector.reject_first.store(1, Ordering::SeqCst);
    let alerts = collector.dispatcher();
    alerts.activate(AlertKind::DepositHalted);
    let events = collector.observed(&alerts);
    assert_eq!(events.len(), 2, "one rejected attempt, one accepted retry");
    for event in &events {
        check_event(event, "deposit_halted", "active", 1);
    }
}

#[test]
fn production_retry_is_bounded() {
    assert_eq!(DELIVERY_RETRY.attempts, 3);
    // Worst case per event: every attempt hits curl's 2 s max-time, plus the
    // doubling backoff between attempts. One stuck event must not hold the
    // single worker (32-slot queue) for long.
    let backoff: Duration = (0..DELIVERY_RETRY.attempts - 1)
        .map(|i| DELIVERY_RETRY.backoff * 2u32.pow(i))
        .sum();
    assert!(backoff + Duration::from_secs(2) * DELIVERY_RETRY.attempts <= Duration::from_secs(10));
}

#[test]
fn configuration_accepts_only_explicit_local_fixture_and_safe_ntfy_topic() {
    for url in ["http://127.0.0.1:1/alerts", "http://[::1]:65535/alerts"] {
        assert!(matches!(
            Target::parse(Some(url), None),
            Ok(Some(Target::Loopback(_)))
        ));
    }
    for url in [
        "http://localhost:80/alerts",
        "http://127.0.0.2:80/alerts",
        "https://127.0.0.1:80/alerts",
        "http://127.0.0.1:0/alerts",
        "http://127.0.0.1:65536/alerts",
        "http://127.0.0.1:80/alerts?token=fake",
        "http://user:pass@127.0.0.1:80/alerts",
        "http://127.0.0.1:80/alerts#fragment",
        "http://example.com:80/alerts",
        "http://127.0.0.1:80/other",
        "http://127.0.0.1:80/../alerts",
    ] {
        assert!(Target::parse(Some(url), None).is_err(), "{url}");
    }
    assert!(Target::parse(Some("http://127.0.0.1:80/alerts"), Some("topic")).is_err());
    assert!(matches!(
        Target::parse(None, Some("arcora-valid_1")),
        Ok(Some(Target::Ntfy(_)))
    ));
    for topic in [
        "../evil",
        "topic?query",
        "topic#fragment",
        "other/topic",
        "topic\nheader",
        "topic token",
    ] {
        assert!(Target::parse(None, Some(topic)).is_err());
    }
    assert!(Target::parse(None, None).unwrap().is_none());
}

#[test]
fn transport_has_bounded_timeout_and_rejects_redirects() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/alerts", listener.local_addr().unwrap());
    let peer = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        let _ = read_body(&mut socket);
        std::thread::sleep(Duration::from_millis(2300));
    });
    let target = Target::parse(Some(&url), None).unwrap().unwrap();
    let start = std::time::Instant::now();
    assert!(!target.deliver("{}"));
    assert!(start.elapsed() < Duration::from_secs(3));
    peer.join().unwrap();

    let destination = TcpListener::bind("127.0.0.1:0").unwrap();
    destination.set_nonblocking(true).unwrap();
    let redirect = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/alerts", redirect.local_addr().unwrap());
    let location = format!("http://{}/alerts", destination.local_addr().unwrap());
    let peer = std::thread::spawn(move || {
        let (mut socket, _) = redirect.accept().unwrap();
        let _ = read_body(&mut socket);
        write!(socket, "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
    });
    assert!(!Target::parse(Some(&url), None)
        .unwrap()
        .unwrap()
        .deliver("{}"));
    peer.join().unwrap();
    assert!(matches!(destination.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock));
}

#[test]
fn alert_kinds_have_stable_names_and_active_lists_open_episodes() {
    let names: Vec<String> = AlertKind::ALL
        .iter()
        .map(|k| {
            serde_json::to_value(k)
                .unwrap()
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect();
    assert_eq!(
        names,
        [
            "settlement_held",
            "persistence_failed",
            "deposit_halted",
            "archive_pressure",
            "bond_shortfall",
            "unanswerable_challenge",
            "challenge_discovery_failed",
            "stale_anchor",
            "liveness_low",
        ]
    );
    let alerts = OpsAlerts::default();
    assert!(alerts.active().is_empty());
    alerts.activate(AlertKind::StaleAnchor);
    alerts.activate(AlertKind::LivenessLow);
    alerts.recover(AlertKind::StaleAnchor);
    assert_eq!(alerts.active(), vec![AlertKind::LivenessLow]);
    alerts.clone().recover(AlertKind::LivenessLow);
    assert!(alerts.active().is_empty(), "clones share episode state");
}

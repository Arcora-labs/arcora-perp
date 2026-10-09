//! Owned loopback JSON-RPC fixtures using the actual cast transport and pinned
//! L1 readers. No signing, chain mutation, external RPC, or real proof is used.
use super::*;
use axum::{extract::State, routing::post, Json, Router};
use serde_json::{json, Value};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};

struct Script {
    context: Mutex<ClockContext>,
    mode: AtomicUsize,
    finalized_reads: AtomicUsize,
    calls: Mutex<Vec<String>>,
}
struct Server {
    url: String,
    script: Arc<Script>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}
fn hex_words(words: &[Digest]) -> String {
    crate::hex0x(&words.iter().flatten().copied().collect::<Vec<_>>())
}
fn selector(s: &str) -> String {
    crate::hex0x(&perp_core::clock::keccak(s.as_bytes())[..4])
}
async fn handle(State(s): State<Arc<Script>>, Json(req): Json<Value>) -> Json<Value> {
    let method = req["method"].as_str().unwrap();
    s.calls.lock().unwrap().push(method.into());
    let c = *s.context.lock().unwrap();
    let mode = s.mode.load(Ordering::SeqCst);
    let result = match method {
        "eth_chainId" => json!(if mode == 4 { "0x1" } else { "0x14a34" }),
        "eth_getBlockByNumber" => {
            let tag = req["params"][0].as_str().unwrap();
            let height = if tag == "latest" {
                20
            } else if tag == "finalized" {
                let n = s.finalized_reads.fetch_add(1, Ordering::SeqCst);
                if mode == 1 && n == 0 {
                    19
                } else {
                    20
                }
            } else {
                u8::from_str_radix(tag.strip_prefix("0x").unwrap(), 16).unwrap()
            };
            let hash = if mode == 3 && tag.starts_with("0x") {
                [0xEE; 32]
            } else {
                [height; 32]
            };
            json!({"number":format!("0x{height:x}"),"hash":crate::hex32(&hash)})
        }
        "eth_call" => {
            assert_eq!(req["params"][1]["requireCanonical"], true);
            let input = req["params"][0]["data"].as_str().unwrap();
            let sig = &input[..10];
            let words = if sig == selector("verifier()") {
                vec![perp_core::clock::abi_address(&c.verifier)]
            } else if sig == selector("settlement()") {
                vec![perp_core::clock::abi_address(&c.settlement)]
            } else if sig == selector("proofVersion()") {
                vec![perp_core::clock::abi_u64(2)]
            } else if sig == selector("batchCount()") {
                vec![perp_core::clock::abi_u64(c.batch_id)]
            } else if sig == selector("currentStateRoot()") {
                vec![c.previous_root]
            } else if sig == selector("closeOnly()") || sig == selector("windDownSettled()") {
                vec![[0; 32]]
            } else if sig == selector("maxWindowMs()") {
                vec![perp_core::clock::abi_u64(c.max_window_ms)]
            } else if sig == selector("clockSkewMs()") {
                vec![perp_core::clock::abi_u64(c.clock_skew_ms)]
            } else if sig == selector("anchor(uint64,uint8)") {
                if req["params"][1]["blockHash"] == crate::hex32(&[19; 32]) {
                    vec![[0; 32]; 8]
                } else {
                    let mut receipt = c.receipt();
                    if mode == 2 {
                        receipt[0] ^= 1;
                    }
                    vec![
                        c.previous_root,
                        c.base_commitment,
                        receipt,
                        perp_core::clock::abi_u64(c.first_ms),
                        perp_core::clock::abi_u64(c.last_ms),
                        perp_core::clock::abi_u64(c.timed_ops),
                        perp_core::clock::abi_u64(c.anchored_at_ms),
                        perp_core::clock::abi_u64(1),
                    ]
                }
            } else {
                panic!("unexpected fixture method {sig}")
            };
            json!(hex_words(&words))
        }
        _ => panic!("read-only clock fixture received {method}"),
    };
    Json(json!({"jsonrpc":"2.0","id":req["id"],"result":result}))
}
impl Server {
    fn new(c: ClockContext, mode: usize) -> Self {
        let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        socket.set_nonblocking(true).unwrap();
        let url = format!("http://{}", socket.local_addr().unwrap());
        let script = Arc::new(Script {
            context: Mutex::new(c),
            mode: AtomicUsize::new(mode),
            finalized_reads: AtomicUsize::new(0),
            calls: Mutex::new(Vec::new()),
        });
        let state = script.clone();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let thread = std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async move {
                    let listener = tokio::net::TcpListener::from_std(socket).unwrap();
                    axum::serve(
                        listener,
                        Router::new().route("/", post(handle)).with_state(state),
                    )
                    .with_graceful_shutdown(async {
                        let _ = rx.await;
                    })
                    .await
                    .unwrap();
                });
        });
        Self {
            url,
            script,
            stop: Some(tx),
            thread: Some(thread),
        }
    }
    fn l1(&self) -> L1 {
        let c = *self.script.context.lock().unwrap();
        let mut l1 = L1::test_reader(self.url.clone());
        l1.settlement = crate::hex0x(&c.settlement);
        l1.clock = Some(ClockConfig {
            verifier: c.verifier,
            chain_id: c.chain_id,
            stop: None,
        });
        l1
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        if let Some(tx) = self.stop.take() {
            let _ = tx.send(());
        }
        if let Some(t) = self.thread.take() {
            t.join().unwrap();
        }
    }
}
fn fixture() -> (
    sequencer::WindowWitness,
    Vec<crate::withdrawals::Withdrawal>,
    ClockContext,
) {
    let (w, ww) = crate::prover_client::tests_support::sample_window();
    let d =
        perp_core::commitment::derive_roots(&mut w.pre_state.clone(), &w.ops, &w.manifest).unwrap();
    let b = TimeBounds::derive(&w.ops).unwrap();
    let c = ClockContext {
        chain_id: 84532,
        verifier: [0x11; 20],
        settlement: [0x22; 20],
        batch_id: w.batch_id,
        previous_root: d.prev_state_root,
        base_commitment: d.commitment::<perp_core::Keccak256>(),
        phase: d.wind_down_phase,
        first_ms: b.first_ms,
        last_ms: b.last_ms,
        timed_ops: b.count,
        anchored_at_ms: b.last_ms,
        max_window_ms: 10_000,
        clock_skew_ms: 2_000,
    };
    (w, ww, c)
}
#[test]
#[ignore = "requires real cast and owned loopback; run explicitly in CI"]
fn runtime_clock_native_cast_waits_for_finality_without_restamping_or_sending() {
    let (w, _, c) = fixture();
    let server = Server::new(c, 1);
    let result = server.l1().register_clock(&w).unwrap();
    assert_eq!(result, c);
    assert!(server.script.finalized_reads.load(Ordering::SeqCst) >= 2);
    assert!(server
        .script
        .calls
        .lock()
        .unwrap()
        .iter()
        .all(|m| !m.contains("send")));
}
#[test]
#[ignore = "requires real cast and owned loopback; run explicitly in CI"]
fn runtime_clock_native_cast_refuses_wrong_chain_receipt_and_mid_read_reorg() {
    for mode in [2, 3, 4] {
        let (w, _, c) = fixture();
        let server = Server::new(c, mode);
        assert!(server.l1().register_clock(&w).is_err(), "mode {mode}");
        assert!(server
            .script
            .calls
            .lock()
            .unwrap()
            .iter()
            .all(|m| !m.contains("send")));
    }
}
#[test]
#[ignore = "requires real cast and owned loopback; run explicitly in CI"]
fn runtime_clock_native_cast_rechecks_receipt_before_broadcast() {
    let (w, ww, c) = fixture();
    let server = Server::new(c, 0);
    let l1 = server.l1();
    assert_eq!(
        l1.clock_seal_period().unwrap(),
        std::time::Duration::from_millis(500)
    );
    let mut prepared = crate::prover_client::prepare_unproved(&w, &ww).unwrap();
    prepared.outcome.proof = perp_core::clock::PROOF_MAGIC.to_vec();
    prepared.outcome.proof.extend(c.receipt());
    prepared.outcome.proof.extend([7; 32]);
    assert_eq!(
        l1.clock_proof_for_send(&prepared.outcome).unwrap(),
        vec![7; 32]
    );
    server.script.context.lock().unwrap().anchored_at_ms += 1;
    assert!(l1.clock_proof_for_send(&prepared.outcome).is_err());
}

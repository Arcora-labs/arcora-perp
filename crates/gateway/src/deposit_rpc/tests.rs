use super::*;
#[test]
fn a01_missing_finalized_header_is_not_an_empty_page() {
    struct Absent;
    impl Rpc for Absent {
        fn call(&self, m: &str, _: Vec<Value>) -> Result<Value, String> {
            Ok(if m == "eth_chainId" {
                json!("0x1")
            } else {
                Value::Null
            })
        }
    }
    let source = VaultSource::new(Absent);
    assert!(source
        .fetch(Cursor {
            domain: Domain {
                chain: 1,
                vault: [1; 20]
            },
            count: 0,
            tip: [0; 32],
            anchor: None
        })
        .is_err());
}

use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};
type Requests = Arc<Mutex<Vec<(String, Vec<Value>)>>>;
#[derive(Clone)]
struct MockRpc {
    calls: Arc<AtomicUsize>,
    requests: Requests,
    fail: Option<usize>,
    missing: bool,
    reversed: bool,
    duplicate: bool,
    reorg: bool,
    chain: u64,
}
impl Default for MockRpc {
    fn default() -> Self {
        Self {
            calls: Arc::new(0.into()),
            requests: Arc::new(Mutex::new(vec![])),
            fail: None,
            missing: false,
            reversed: false,
            duplicate: false,
            reorg: false,
            chain: 1,
        }
    }
}
fn block(n: u64) -> Block {
    let mut hash = [0u8; 32];
    hash[24..].copy_from_slice(&n.to_be_bytes());
    Block { number: n, hash }
}
fn count(n: u64) -> u64 {
    if n < 2 {
        0
    } else if n < 4 {
        2
    } else {
        3
    }
}
fn all_events() -> Vec<Event> {
    let mut tip = [0u8; 32];
    (0..3)
        .map(|id| {
            let from = [0x42; 20];
            let commit = [id as u8 + 10; 32];
            let amount = (id + 1) as u128 * 1_000_000;
            tip = deposit_chain_fold(&tip, &deposit_leaf(&from, &commit, amount, id));
            Event {
                id,
                from,
                commit,
                amount,
                tip,
                tx: [id as u8 + 50; 32],
                tx_index: id % 2,
                log_index: id % 2,
                block: block(if id < 2 { 2 } else { 4 }),
            }
        })
        .collect()
}
fn log(e: &Event) -> Value {
    let mut from = [0u8; 32];
    from[12..].copy_from_slice(&e.from);
    let mut data = [0u8; 96];
    data[16..32].copy_from_slice(&e.amount.to_be_bytes());
    data[56..64].copy_from_slice(&e.id.to_be_bytes());
    data[64..].copy_from_slice(&e.tip);
    json!({"removed":false,"address":hex0x(&[1;20]),"blockHash":hex0x(&e.block.hash),"blockNumber":format!("0x{:x}",e.block.number),
        "topics":[TOPIC,hex0x(&from),hex0x(&e.commit)],"data":hex0x(&data),"transactionHash":hex0x(&e.tx),
        "transactionIndex":format!("0x{:x}",e.tx_index),"logIndex":format!("0x{:x}",e.log_index)})
}
fn cursor() -> Cursor {
    Cursor {
        domain: Domain {
            chain: 1,
            vault: [1; 20],
        },
        count: 0,
        tip: [0; 32],
        anchor: None,
    }
}
impl Rpc for MockRpc {
    fn call(&self, m: &str, p: Vec<Value>) -> Result<Value, String> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        self.requests.lock().unwrap().push((m.into(), p.clone()));
        if self.fail == Some(call) {
            return Err("injected RPC failure".into());
        }
        match m {
            "eth_chainId" => Ok(json!(format!("0x{:x}", self.chain))),
            "eth_getBlockByNumber" => {
                let n = if p[0] == json!("finalized") {
                    4
                } else {
                    quantity(&p[0]).unwrap()
                };
                let mut b = block(n);
                if self.reorg && n == 2 {
                    b.hash[0] ^= 1;
                }
                Ok(json!({"number":format!("0x{n:x}"),"hash":hex0x(&b.hash)}))
            }
            "eth_call" => {
                assert_eq!(p[0]["to"], hex0x(&[1; 20]));
                assert_eq!(p[1]["requireCanonical"], true);
                let hash = digest(&p[1]["blockHash"]).unwrap();
                let n = u64::from_be_bytes(hash[24..].try_into().unwrap());
                let data = bytes(&p[0]["data"]).unwrap();
                use sha3::{Digest, Keccak256};
                if data[..4] == Keccak256::digest(b"depositCount()")[..4] {
                    let mut w = [0u8; 32];
                    w[24..].copy_from_slice(&count(n).to_be_bytes());
                    Ok(json!(hex0x(&w)))
                } else {
                    assert_eq!(data[..4], Keccak256::digest(b"depositTipAt(uint64)")[..4]);
                    let id = uint64(&data[4..]).unwrap();
                    assert!(id > 0 && id <= count(n));
                    Ok(json!(hex0x(&all_events()[id as usize - 1].tip)))
                }
            }
            "eth_getLogs" => {
                assert_eq!(p[0]["address"], hex0x(&[1; 20]));
                assert_eq!(p[0]["topics"], json!([TOPIC]));
                assert!(p[0].get("fromBlock").is_none());
                let hash = digest(&p[0]["blockHash"]).unwrap();
                let mut rows: Vec<_> = all_events()
                    .iter()
                    .filter(|e| e.block.hash == hash)
                    .map(log)
                    .collect();
                if self.missing {
                    rows.pop();
                }
                if self.reversed {
                    rows.reverse();
                }
                if self.duplicate {
                    rows.push(rows[0].clone());
                }
                Ok(json!(rows))
            }
            other => panic!("unexpected RPC method: {other}"),
        }
    }
}
#[test]
fn a01_rpc_pages_whole_blocks_in_canonical_order_deduplicates_and_catches_up() {
    let mock = MockRpc {
        reversed: true,
        duplicate: true,
        ..Default::default()
    };
    let source = VaultSource::new(mock);
    let first = source.fetch(cursor()).unwrap();
    assert_eq!(first.end, block(2));
    assert_eq!(
        first.events.iter().map(|e| e.id).collect::<Vec<_>>(),
        vec![0, 1]
    );
    let mut c = cursor();
    c.count = 2;
    c.tip = first.events[1].tip;
    c.anchor = Some(first.end);
    let next = source.fetch(c).unwrap();
    assert_eq!(next.events.len(), 1);
    assert_eq!(next.events[0].id, 2);
    let mut c = cursor();
    c.count = 3;
    c.tip = next.events[0].tip;
    c.anchor = Some(next.end);
    assert!(source.fetch(c).unwrap().events.is_empty());
}
#[test]
fn a01_rpc_failure_at_each_read_never_becomes_an_empty_success() {
    let mock = MockRpc::default();
    let counter = mock.calls.clone();
    VaultSource::new(mock).fetch(cursor()).unwrap();
    for i in 0..counter.load(Ordering::SeqCst) {
        let source = VaultSource::new(MockRpc {
            fail: Some(i),
            ..Default::default()
        });
        assert!(
            source.fetch(cursor()).is_err(),
            "RPC call {i} failed but page was accepted"
        );
    }
}
#[test]
fn a01_rpc_missing_log_and_reordered_ids_do_not_advance_prefix() {
    assert!(VaultSource::new(MockRpc {
        missing: true,
        ..Default::default()
    })
    .fetch(cursor())
    .is_err());
    let events = all_events();
    let mut rows = vec![log(&events[0]), log(&events[1])];
    rows[0]["transactionIndex"] = json!("0x2");
    assert!(validate_logs(
        &json!(rows),
        &cursor().domain,
        &block(2),
        0,
        2,
        [0; 32],
        events[1].tip
    )
    .is_err());
}
#[test]
fn a01_rpc_legacy_midblock_prefix_resumes_without_skipping_or_recrediting() {
    let mut c = cursor();
    c.count = 1;
    c.tip = all_events()[0].tip;
    let p = VaultSource::new(MockRpc::default()).fetch(c).unwrap();
    assert_eq!(p.events.len(), 1);
    assert_eq!(p.events[0].id, 1);
}
#[test]
fn a01_rpc_domain_prefix_and_credited_anchor_reorg_are_durable_halts() {
    assert!(matches!(
        VaultSource::new(MockRpc {
            chain: 2,
            ..Default::default()
        })
        .fetch(cursor()),
        Err(Error::Halt(_))
    ));
    let mut c = cursor();
    c.count = 1;
    c.tip = [4; 32];
    assert!(matches!(
        VaultSource::new(MockRpc::default()).fetch(c),
        Err(Error::Halt(_))
    ));
    let mut c = cursor();
    c.count = 2;
    c.tip = all_events()[1].tip;
    c.anchor = Some(block(2));
    assert!(matches!(
        VaultSource::new(MockRpc {
            reorg: true,
            ..Default::default()
        })
        .fetch(c),
        Err(Error::Halt(_))
    ));
}
#[test]
fn a01_rpc_malformed_removed_forked_or_conflicting_logs_fail_closed() {
    let events = all_events();
    let first = log(&events[0]);
    let second = log(&events[1]);
    for (field, bad) in [
        ("removed", Value::Null),
        ("removed", json!(true)),
        ("address", json!(hex0x(&[9; 20]))),
        ("blockHash", json!(hex0x(&[9; 32]))),
        ("transactionHash", json!("bad")),
        ("data", json!("0xéé")),
        ("data", json!("0x00")),
        ("topics", json!([TOPIC])),
    ] {
        let mut row = first.clone();
        row[field] = bad;
        assert!(
            validate_logs(
                &json!([row, second.clone()]),
                &cursor().domain,
                &block(2),
                0,
                2,
                [0; 32],
                events[1].tip
            )
            .is_err(),
            "{field}"
        );
    }
    let mut conflict = first.clone();
    conflict["transactionHash"] = json!(hex0x(&[7; 32]));
    assert!(validate_logs(
        &json!([first, second, conflict]),
        &cursor().domain,
        &block(2),
        0,
        2,
        [0; 32],
        events[1].tip
    )
    .is_err());
}

/// Runs only in the offline Foundry-equipped verification job. The native cast
/// transport talks solely to a loopback scripted JSON-RPC server; it cannot send
/// transactions and no real L1 service or signing key is involved.
#[test]
#[ignore = "requires the real cast binary; explicitly exercised by A01 verification"]
fn a01_native_cast_hash_pinned_jsonrpc_roundtrip() {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let server_stop = stop.clone();
    let server = std::thread::spawn(move || {
        let mock = MockRpc::default();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
        while !server_stop.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
            let (mut stream, _) = match listener.accept() {
                Ok(v) => v,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(2));
                    continue;
                }
                Err(e) => panic!("{e}"),
            };
            // Accepted sockets inherit O_NONBLOCK on macOS. The listener polls
            // for shutdown, but each HTTP request uses a bounded blocking read.
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut data = vec![];
            let mut buf = [0u8; 4096];
            let offset = loop {
                let n = stream.read(&mut buf).unwrap();
                assert!(n > 0);
                data.extend_from_slice(&buf[..n]);
                if let Some(i) = data.windows(4).position(|w| w == b"\r\n\r\n") {
                    break i + 4;
                }
            };
            let head = String::from_utf8_lossy(&data[..offset]).to_ascii_lowercase();
            let len: usize = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .unwrap()
                .trim()
                .parse()
                .unwrap();
            while data.len() < offset + len {
                let n = stream.read(&mut buf).unwrap();
                assert!(n > 0);
                data.extend_from_slice(&buf[..n]);
            }
            let req: Value = serde_json::from_slice(&data[offset..offset + len]).unwrap();
            let result = mock
                .call(
                    req["method"].as_str().unwrap(),
                    req["params"].as_array().unwrap().clone(),
                )
                .unwrap();
            let body = json!({"jsonrpc":"2.0","id":req["id"],"result":result}).to_string();
            write!(stream,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",body.len(),body).unwrap();
        }
    });
    let l1 = L1::test_reader(format!("http://{address}"));
    let result = VaultSource::new(l1).fetch(cursor());
    stop.store(true, Ordering::SeqCst);
    server.join().unwrap();
    let p = result.unwrap();
    assert_eq!(p.events.len(), 2);
}

#[test]
fn a01_rpc_wrong_historical_header_number_is_rejected() {
    struct WrongHeight(MockRpc);
    impl Rpc for WrongHeight {
        fn call(&self, m: &str, p: Vec<Value>) -> Result<Value, String> {
            let historical = m == "eth_getBlockByNumber" && p[0] != json!("finalized");
            let mut v = self.0.call(m, p)?;
            if historical {
                v["number"] = json!("0xffff");
            }
            Ok(v)
        }
    }
    assert!(VaultSource::new(WrongHeight(MockRpc::default()))
        .fetch(cursor())
        .is_err());
}

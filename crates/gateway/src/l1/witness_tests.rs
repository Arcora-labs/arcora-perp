//! The policy uses exact production parsing; native cases additionally cross the
//! real cast subprocess and loopback HTTP boundary. These servers are fixtures,
//! not evidence of independent providers or a live deployment.
use super::*;
use crate::deposit_rpc::Rpc;
use serde_json::{json, Value};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};

pub(super) const SETTLEMENT: &str = "0x00000000000000000000000000000000000000aa";
pub(super) const SECRET: &str = "SYNTHETIC_RPC_CREDENTIAL_MUST_NOT_ESCAPE";
#[derive(Clone, Copy, Debug, Default)]
pub(super) enum Fault {
    #[default]
    None,
    Chain,
    LaggingHead,
    Bool,
    Overflow,
    Tuple,
    Log(usize),
    ForkWorld,
    Deadline(u8),
    Lagging,
    FinalizedHash,
    AnchorHash,
    CanonicalAfter,
    WrongHeight,
    Word(usize),
    MalformedWord,
    Failure(usize),
}
pub(super) struct Fixture {
    fault: Fault,
    pub(super) calls: Mutex<Vec<(String, Vec<Value>)>>,
}
impl Fixture {
    pub(super) fn new(fault: Fault) -> Self {
        Self {
            fault,
            calls: Mutex::new(vec![]),
        }
    }
}
impl Rpc for Fixture {
    fn call(&self, method: &str, params: Vec<Value>) -> Result<Value, String> {
        let mut calls = self.calls.lock().unwrap();
        calls.push((method.into(), params.clone()));
        if matches!(self.fault, Fault::Failure(n) if calls.len() == n) {
            return Err(SECRET.into());
        }
        match method {
            "eth_chainId" => Ok(json!(if matches!(self.fault, Fault::Chain) {
                "0x1"
            } else {
                "0x14a34"
            })),
            "eth_getBlockByNumber" => {
                let finalized = params[0] == json!("finalized");
                let latest = params[0] == json!("latest");
                assert_eq!(params[1], json!(false));
                if !finalized && !latest {
                    assert!(params[0] == json!("0x10") || params[0] == json!("0x1c"));
                }
                let historical_reads = calls
                    .iter()
                    .filter(|(m, p)| {
                        m == method && p[0] != json!("finalized") && p[0] != json!("latest")
                    })
                    .count();
                let hash = if matches!(self.fault, Fault::ForkWorld)
                    || matches!(self.fault, Fault::FinalizedHash) && finalized
                    || matches!(self.fault, Fault::AnchorHash) && !finalized
                    || matches!(self.fault, Fault::CanonicalAfter)
                        && !finalized
                        && historical_reads >= 2
                {
                    [8; 32]
                } else if latest || params[0] == json!("0x1c") {
                    [10; 32]
                } else {
                    [9; 32]
                };
                let number = if matches!(self.fault, Fault::Lagging) && finalized {
                    "0xf"
                } else if matches!(self.fault, Fault::WrongHeight) && !finalized {
                    "0x11"
                } else if latest && matches!(self.fault, Fault::LaggingHead) {
                    "0x1b"
                } else if latest || params[0] == json!("0x1c") {
                    "0x1c"
                } else {
                    "0x10"
                };
                Ok(json!({"number": number, "hash": crate::hex32(&hash)}))
            }
            "eth_call" => {
                use sha3::{Digest as _, Keccak256};
                assert_eq!(params[0]["to"], json!(SETTLEMENT));
                let last_tag = &calls
                    .iter()
                    .rev()
                    .find(|(m, _)| m == "eth_getBlockByNumber")
                    .unwrap()
                    .1[0];
                let expected_hash = if matches!(self.fault, Fault::ForkWorld) {
                    [8; 32]
                } else if *last_tag == json!("latest") || *last_tag == json!("0x1c") {
                    [10; 32]
                } else {
                    [9; 32]
                };
                assert_eq!(
                    params[1],
                    json!({"blockHash":crate::hex32(&expected_hash),"requireCanonical":true})
                );
                let words = [
                    ("batchCount()", 6),
                    ("currentStateRoot()", 3),
                    ("sequencerBond()", 77),
                    ("closeOnly()", 0),
                    ("depositCount()", 7),
                    ("depositTipAt(uint64)", 4),
                    ("claimed(bytes32)", 1),
                    ("requiredBond()", 30),
                    ("challengeWindowBlocks()", 200),
                    ("challenges(bytes32)", 1),
                    ("windDownSettled()", 0),
                ];
                let data = params[0]["data"].as_str().unwrap();
                let (index, (signature, value)) = words
                    .iter()
                    .enumerate()
                    .find(|(_, (signature, _))| {
                        data.starts_with(&crate::hex0x(
                            &Keccak256::digest(signature.as_bytes())[..4],
                        ))
                    })
                    .expect("known state getter");
                assert_eq!(data.len(), if [5, 6, 9].contains(&index) { 74 } else { 10 });
                if index == 5 {
                    assert_eq!(&data[10..], &crate::hex32(&observation::u64_word(5))[2..]);
                }
                if matches!(self.fault, Fault::MalformedWord) {
                    return Ok(json!("0xbad"));
                }
                let mut word = if index == 1 || index == 5 {
                    [*value; 32]
                } else {
                    [0; 32]
                };
                word[31] = *value;
                if index == 6 && data.ends_with("02") {
                    word[31] = 0;
                }
                if matches!(self.fault, Fault::Word(n) if n == index) {
                    word[31] += 1;
                }
                if matches!(self.fault, Fault::Bool) && [3, 6, 9].contains(&index) {
                    word[31] = 2;
                }
                if matches!(self.fault, Fault::Overflow) {
                    word[0] = 1;
                }
                if index == 9 {
                    let mut tuple = vec![0; 192];
                    tuple[63] = 16;
                    tuple[95] = 16;
                    tuple[127] = match self.fault {
                        Fault::Deadline(n) => n,
                        _ => 200,
                    };
                    tuple[160..].copy_from_slice(&word);
                    if matches!(self.fault, Fault::Tuple) {
                        tuple.pop();
                    }
                    return Ok(json!(crate::hex0x(&tuple)));
                }
                let _ = signature;
                Ok(json!(crate::hex32(&word)))
            }
            "eth_getCode" => {
                assert_eq!(
                    params[1],
                    json!({"blockHash":crate::hex32(&[9;32]),"requireCanonical":true})
                );
                Ok(json!(if matches!(self.fault, Fault::Word(10)) {
                    "0x01"
                } else {
                    "0x"
                }))
            }
            "eth_getLogs" => {
                if params[0].get("blockHash").is_some() {
                    assert_eq!(params[0]["blockHash"], json!(crate::hex32(&[9; 32])));
                    return Ok(if matches!(self.fault, Fault::Word(11)) {
                        json!([{"removed":true}])
                    } else {
                        json!([])
                    });
                }
                use sha3::{Digest as _, Keccak256};
                assert_eq!(params[0]["fromBlock"], json!("0x10"));
                assert_eq!(params[0]["toBlock"], json!("0x1c"));
                let topic = crate::hex0x(&Keccak256::digest(
                    b"InclusionChallenged(bytes32,address,uint256)",
                ));
                assert_eq!(params[0]["topics"], json!([topic]));
                assert_eq!(params[0]["address"], json!(SETTLEMENT));
                if matches!(self.fault, Fault::Log(0)) {
                    return Ok(json!([]));
                }
                let mut event = json!({"address":SETTLEMENT,"removed":false,"blockNumber":"0x10","blockHash":crate::hex32(&[9;32]),"transactionHash":crate::hex32(&[7;32]),"transactionIndex":"0x0","logIndex":"0x1","topics":[topic,crate::hex32(&[5;32]),crate::hex32(&observation::u64_word(1))],"data":crate::hex32(&observation::u64_word(200))});
                match self.fault {
                    Fault::ForkWorld => {
                        event["blockHash"] = json!(crate::hex32(&[8; 32]));
                        event["topics"][1] = json!(crate::hex32(&[6; 32]));
                    }
                    Fault::Log(1) => event["removed"] = json!(true),
                    Fault::Log(2) => {
                        event["address"] = json!("0x00000000000000000000000000000000000000bb")
                    }
                    Fault::Log(3) => event["topics"][0] = json!(crate::hex32(&[6; 32])),
                    Fault::Log(4) => event["blockHash"] = json!(crate::hex32(&[8; 32])),
                    Fault::Log(5) => event["blockNumber"] = json!("0xf"),
                    Fault::Log(6) => event["data"] = json!("0xbad"),
                    Fault::Log(7) => return Ok(json!([event, event])),
                    Fault::Log(8) => {
                        event["address"] =
                            json!(format!("0x{}{}", "00".repeat(12), &SETTLEMENT[2..]))
                    }
                    Fault::Log(9) => {
                        event["data"] = json!(crate::hex32(&observation::u64_word(16)))
                    }
                    Fault::Log(10) => {
                        let mut duplicate = event.clone();
                        duplicate["transactionIndex"] = json!("0x1");
                        return Ok(json!([event, duplicate]));
                    }
                    _ => {}
                }
                Ok(json!([event]))
            }
            _ => panic!("non-read method reached fixture: {method}"),
        }
    }
}
fn observe(primary: &Fixture, witness: &Fixture) -> Result<(u64, String, u128), String> {
    settlement_observation_from(primary, Some(witness), Some(84532), SETTLEMENT)
}
#[test]
fn witness_policy_agreement_uses_same_finalized_canonical_hash_for_every_word() {
    let primary = Fixture::new(Fault::None);
    let witness = Fixture::new(Fault::None);
    assert_eq!(
        observe(&primary, &witness).unwrap(),
        (6, crate::hex32(&[3; 32]), 77)
    );
    assert_eq!(primary.calls.lock().unwrap().len(), 6);
    assert_eq!(witness.calls.lock().unwrap().len(), 7);
}
#[test]
fn witness_policy_accepts_ahead_finality_only_when_historical_anchor_agrees() {
    struct Ahead(Fixture);
    impl Rpc for Ahead {
        fn call(&self, method: &str, params: Vec<Value>) -> Result<Value, String> {
            let finalized = method == "eth_getBlockByNumber" && params[0] == json!("finalized");
            let mut value = self.0.call(method, params)?;
            if finalized {
                value["number"] = json!("0x20");
                value["hash"] = json!(crate::hex32(&[7; 32]));
            }
            Ok(value)
        }
    }
    assert!(settlement_observation_from(
        &Fixture::new(Fault::None),
        Some(&Ahead(Fixture::new(Fault::None))),
        Some(84532),
        SETTLEMENT
    )
    .is_ok());
}
#[test]
fn witness_policy_refuses_finality_chain_fork_and_each_getter_disagreement() {
    for fault in [
        Fault::Chain,
        Fault::Lagging,
        Fault::FinalizedHash,
        Fault::AnchorHash,
        Fault::CanonicalAfter,
        Fault::WrongHeight,
        Fault::Word(0),
        Fault::Word(1),
        Fault::Word(2),
        Fault::MalformedWord,
    ] {
        assert!(
            observe(&Fixture::new(Fault::None), &Fixture::new(fault)).is_err(),
            "{fault:?} accepted"
        );
    }
}
#[test]
fn witness_policy_never_falls_back_when_either_provider_fails_any_read() {
    for n in 1..=6 {
        assert!(
            observe(&Fixture::new(Fault::Failure(n)), &Fixture::new(Fault::None)).is_err(),
            "primary read {n}"
        );
    }
    for n in 1..=7 {
        assert!(
            observe(&Fixture::new(Fault::None), &Fixture::new(Fault::Failure(n))).is_err(),
            "witness read {n}"
        );
    }
}
#[test]
fn witness_policy_refuses_malformed_chain_and_finalized_header() {
    struct Bad {
        method: &'static str,
        value: Value,
    }
    impl Rpc for Bad {
        fn call(&self, method: &str, params: Vec<Value>) -> Result<Value, String> {
            if method == self.method {
                Ok(self.value.clone())
            } else {
                Fixture::new(Fault::None).call(method, params)
            }
        }
    }
    for value in [
        json!(null),
        json!("0x"),
        json!("0x+1"),
        json!("0x10000000000000000"),
        json!(0),
    ] {
        assert!(settlement_observation_from(
            &Fixture::new(Fault::None),
            Some(&Bad {
                method: "eth_chainId",
                value
            }),
            Some(84532),
            SETTLEMENT
        )
        .is_err());
    }
    for value in [
        json!(null),
        json!({"number":"0x10","hash":"0xdead"}),
        json!({"number":"0x+10","hash":crate::hex32(&[9;32])}),
    ] {
        assert!(settlement_observation_from(
            &Fixture::new(Fault::None),
            Some(&Bad {
                method: "eth_getBlockByNumber",
                value
            }),
            Some(84532),
            SETTLEMENT
        )
        .is_err());
    }
}
#[test]
fn witness_configuration_rejects_same_host_aliases_without_echoing_credentials() {
    for (primary, witness) in [
        ("https://rpc.example/a", "http://RPC.EXAMPLE.:123/b"),
        (
            "https://user:pass@rpc.example/a?token=secret",
            "https://rpc.example/b",
        ),
        ("http://127.0.0.1:1", "http://localhost:2"),
        ("http://127.1.2.3:1", "http://[::1]:2"),
        ("http://[::ffff:192.0.2.1]:1", "http://192.0.2.1:2"),
        ("http://[2001:db8::1]:1", "http://[2001:0db8:0:0:0:0:0:1]:2"),
    ] {
        assert!(witness_endpoint(primary, Some(witness.into()))
            .unwrap_err()
            .contains("distinct endpoint host"));
    }
    for bad in [
        "",
        "file:///secret",
        "https://",
        "http://127.1",
        "http://2130706433",
        "http://0x7f000001",
        "http://0177.0.0.1",
        "https://rpc.example:999999/path",
        "https://rpc%2eexample/path",
    ] {
        let error = witness_endpoint("https://primary.example", Some(bad.into())).unwrap_err();
        assert!(
            !error.contains(bad) || bad.is_empty(),
            "endpoint echoed: {error}"
        );
    }
    let second = "https://user:pass@witness.example/private?token=secret";
    assert_eq!(
        witness_endpoint("https://primary.example/private", Some(second.into())).unwrap(),
        Some(second.into())
    );
    assert!(witness_endpoint("legacy RPC left untouched", None)
        .unwrap()
        .is_none());
}
#[test]
fn witness_transport_refuses_mutation_methods_before_spawning_cast() {
    let l1 = L1::test_reader("http://127.0.0.1:1".into());
    let reader = SettlementReader {
        l1: &l1,
        endpoint: &l1.rpc,
        role: "witness",
    };
    assert_eq!(
        reader
            .call("eth_sendRawTransaction", vec![json!(SECRET)])
            .unwrap_err(),
        "settlement observation: unsupported read method"
    );
}

pub(super) struct Server {
    pub(super) url: String,
    pub(super) fixture: Arc<Fixture>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Server {
    pub(super) fn start(fault: Fault) -> Self {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!(
            "http://{}/{SECRET}?token={SECRET}",
            listener.local_addr().unwrap()
        );
        let stop = Arc::new(AtomicBool::new(false));
        let fixture = Arc::new(Fixture::new(fault));
        let (server_stop, server_fixture) = (stop.clone(), fixture.clone());
        let thread = std::thread::spawn(move || {
            while !server_stop.load(Ordering::SeqCst) {
                let (mut stream, _) = match listener.accept() {
                    Ok(v) => v,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(2));
                        continue;
                    }
                    Err(e) => panic!("loopback accept: {e}"),
                };
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                    .unwrap();
                let mut bytes = vec![];
                let mut buf = [0; 4096];
                let offset = loop {
                    let n = stream.read(&mut buf).unwrap();
                    assert!(n > 0);
                    bytes.extend_from_slice(&buf[..n]);
                    assert!(bytes.len() < 16384);
                    if let Some(pos) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                        break pos + 4;
                    }
                };
                let headers = String::from_utf8_lossy(&bytes[..offset]).to_ascii_lowercase();
                let length: usize = headers
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length:"))
                    .unwrap()
                    .trim()
                    .parse()
                    .unwrap();
                assert!(length < 16384);
                while bytes.len() < offset + length {
                    let n = stream.read(&mut buf).unwrap();
                    assert!(n > 0);
                    bytes.extend_from_slice(&buf[..n]);
                }
                let request: Value =
                    serde_json::from_slice(&bytes[offset..offset + length]).unwrap();
                let result = server_fixture.call(
                    request["method"].as_str().unwrap(),
                    request["params"].as_array().unwrap().clone(),
                );
                let response = match result {
                    Ok(value) => json!({"jsonrpc":"2.0","id":request["id"],"result":value}),
                    Err(_) => json!({"jsonrpc":"2.0","id":request["id"],"error":{"code":-32000,"message":SECRET,"data":{"url":SECRET}}}),
                }.to_string();
                write!(stream,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",response.len(),response).unwrap();
            }
        });
        Self {
            url,
            fixture,
            stop,
            thread: Some(thread),
        }
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.thread.take().unwrap().join().unwrap();
    }
}
fn native_observe(primary: &Server, witness: &Server) -> Result<(u64, String, u128), String> {
    let mut l1 = L1::test_reader(primary.url.clone());
    l1.settlement = SETTLEMENT.into();
    // Both endpoints are deliberately local fixtures on ephemeral ports. The
    // production distinct-host configuration guard is tested separately above.
    l1.rpc_witness = Some(witness.url.clone());
    l1.witness_chain = Some(84532);
    l1.settlement_observation()
}
#[test]
#[ignore = "requires real cast; explicitly run in native verification"]
fn runtime_witness_native_cast_agreement_and_disagreement_matrix() {
    let primary = Server::start(Fault::None);
    let witness = Server::start(Fault::None);
    assert_eq!(
        native_observe(&primary, &witness).unwrap(),
        (6, crate::hex32(&[3; 32]), 77)
    );
    assert_eq!(primary.fixture.calls.lock().unwrap().len(), 6);
    assert_eq!(witness.fixture.calls.lock().unwrap().len(), 7);
    let error =
        native_observe(&Server::start(Fault::Chain), &Server::start(Fault::Chain)).unwrap_err();
    assert!(error.contains("startup domain"));
    for fault in [
        Fault::Chain,
        Fault::Lagging,
        Fault::FinalizedHash,
        Fault::AnchorHash,
        Fault::CanonicalAfter,
        Fault::WrongHeight,
        Fault::Word(0),
        Fault::Word(1),
        Fault::Word(2),
        Fault::MalformedWord,
    ] {
        let error = native_observe(&Server::start(Fault::None), &Server::start(fault)).unwrap_err();
        assert!(!error.contains(SECRET), "{fault:?}: leaked credential");
    }
    // The final primary read is equally binding: a witness match before it does
    // not permit a primary canonical hash or historical height to change later.
    for fault in [Fault::AnchorHash, Fault::WrongHeight] {
        let error = native_observe(&Server::start(fault), &Server::start(Fault::None)).unwrap_err();
        assert!(error.contains("canonical block changed"));
        assert!(!error.contains(SECRET));
    }
}
#[test]
#[ignore = "requires real cast; explicitly run in native verification"]
fn runtime_witness_native_cast_failure_at_every_read_redacts_and_never_falls_back() {
    for n in 1..=6 {
        let error = native_observe(
            &Server::start(Fault::Failure(n)),
            &Server::start(Fault::None),
        )
        .unwrap_err();
        assert!(error.contains("primary"));
        assert!(!error.contains(SECRET));
    }
    for n in 1..=7 {
        let error = native_observe(
            &Server::start(Fault::None),
            &Server::start(Fault::Failure(n)),
        )
        .unwrap_err();
        assert!(error.contains("witness"));
        assert!(!error.contains(SECRET));
    }
    let primary = Server::start(Fault::None);
    let unavailable = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/{SECRET}", unavailable.local_addr().unwrap());
    drop(unavailable);
    let mut l1 = L1::test_reader(primary.url.clone());
    l1.settlement = SETTLEMENT.into();
    l1.rpc_witness = Some(url);
    l1.witness_chain = Some(84532);
    let error = l1.settlement_observation().unwrap_err();
    assert!(error.contains("witness"));
    assert!(!error.contains(SECRET));
}

#[test]
fn witness_policy_binds_agreement_to_the_startup_chain() {
    let error = observe(&Fixture::new(Fault::Chain), &Fixture::new(Fault::Chain)).unwrap_err();
    assert!(error.contains("startup domain"));
    for expected in [None, Some(0)] {
        assert!(settlement_observation_from(
            &Fixture::new(Fault::None),
            Some(&Fixture::new(Fault::None)),
            expected,
            SETTLEMENT
        )
        .unwrap_err()
        .contains("missing expected"));
    }
}
#[test]
fn witness_unsafe_override_requires_explicit_valid_chain() {
    assert_eq!(witness_chain_override(Some("84532")).unwrap(), 84532);
    for value in [
        None,
        Some(""),
        Some("0"),
        Some("-1"),
        Some("+1"),
        Some(" 84532"),
        Some("0x14a34"),
        Some("18446744073709551616"),
        Some(SECRET),
    ] {
        let error = witness_chain_override(value).unwrap_err();
        assert!(!error.contains(SECRET));
    }
}

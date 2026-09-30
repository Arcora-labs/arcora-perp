//! Local fixtures assert the real methods, calldata and EIP-1898 pin. These are
//! not live-provider or full deposit/trade/withdrawal lifecycle evidence.
use super::witness_tests::{Fault, Fixture, Server, SECRET, SETTLEMENT};
use super::*;
use crate::deposit_rpc::Rpc;
use observation::{AnchorPolicy, CanonicalRead};
use serde_json::{json, Value};

fn configured(primary: &Server, witness: &Server) -> L1 {
    let mut l1 = L1::test_reader(primary.url.clone());
    l1.settlement = SETTLEMENT.into();
    l1.vault = Some(SETTLEMENT.into());
    l1.usdc = Some(SETTLEMENT.into());
    l1.rpc_witness = Some(witness.url.clone());
    l1.witness_chain = Some(84532);
    l1
}
fn read_pair(primary: &Fixture, witness: &Fixture, policy: AnchorPolicy) -> Result<(), String> {
    let read = CanonicalRead::with_policy(primary, Some(witness), Some(84532), policy)?;
    abi_u64(
        read.word(SETTLEMENT, "depositCount()", None)?,
        "depositCount",
    )?;
    read.word(
        SETTLEMENT,
        "depositTipAt(uint64)",
        Some(observation::u64_word(5)),
    )?;
    read.finish()
}
#[test]
fn state_snapshot_refuses_each_transport_failure_without_a_partial_pair() {
    for n in 1..=5 {
        assert!(
            read_pair(
                &Fixture::new(Fault::Failure(n)),
                &Fixture::new(Fault::None),
                AnchorPolicy::Finalized
            )
            .is_err(),
            "primary {n}"
        );
    }
    for n in 1..=6 {
        assert!(
            read_pair(
                &Fixture::new(Fault::None),
                &Fixture::new(Fault::Failure(n)),
                AnchorPolicy::Finalized
            )
            .is_err(),
            "witness {n}"
        );
    }
}
#[test]
fn state_snapshot_refuses_chain_fork_prefix_disagreement_malformed_and_overflow() {
    for fault in [
        Fault::Chain,
        Fault::Lagging,
        Fault::FinalizedHash,
        Fault::AnchorHash,
        Fault::CanonicalAfter,
        Fault::WrongHeight,
        Fault::Word(4),
        Fault::Word(5),
        Fault::MalformedWord,
    ] {
        assert!(
            read_pair(
                &Fixture::new(Fault::None),
                &Fixture::new(fault),
                AnchorPolicy::Finalized
            )
            .is_err(),
            "{fault:?}"
        );
    }
    assert!(read_pair(
        &Fixture::new(Fault::Overflow),
        &Fixture::new(Fault::Overflow),
        AnchorPolicy::Finalized
    )
    .is_err());
}
#[test]
fn state_snapshot_gate_retains_confirmation_depth_and_detects_mid_read_reorg() {
    for fault in [Fault::None, Fault::LaggingHead, Fault::CanonicalAfter] {
        let primary = Fixture::new(Fault::None);
        let witness = Fixture::new(fault);
        let result = read_pair(
            &primary,
            &witness,
            AnchorPolicy::Confirmed(crate::trading_gate::GATE_OPEN_CONFIRMATIONS),
        );
        assert_eq!(result.is_ok(), matches!(fault, Fault::None), "{fault:?}");
        let calls = primary.calls.lock().unwrap();
        assert_eq!(calls[1].1[0], json!("latest"));
        assert_eq!(calls[2].1[0], json!("0x10"));
        assert!(!calls
            .iter()
            .any(|(m, p)| m == "eth_getBlockByNumber" && p[0] == json!("finalized")));
    }
}
#[test]
fn state_snapshot_terminal_policy_reads_latest_hash_without_finality_delay() {
    let primary = Fixture::new(Fault::None);
    let witness = Fixture::new(Fault::None);
    let r = CanonicalRead::with_policy(&primary, Some(&witness), Some(84532), AnchorPolicy::Latest)
        .unwrap();
    assert_eq!(r.height(), 28);
    assert!(!abi_bool(
        r.word(SETTLEMENT, "closeOnly()", None).unwrap(),
        "closeOnly"
    )
    .unwrap());
    r.finish().unwrap();
    for fixture in [&primary, &witness] {
        let calls = fixture.calls.lock().unwrap();
        assert!(!calls
            .iter()
            .any(|(m, p)| m == "eth_getBlockByNumber" && p[0] == json!("finalized")));
        assert_eq!(calls.last().unwrap().1[0], json!("0x1c"));
    }
}
#[test]
fn state_snapshot_abi_booleans_and_quantities_are_canonical_not_truthy() {
    assert!(!abi_bool([0; 32], "flag").unwrap());
    assert!(abi_bool(observation::u64_word(1), "flag").unwrap());
    for n in [2, 255, u64::MAX] {
        assert!(abi_bool(observation::u64_word(n), "flag").is_err());
    }
    assert!(abi_bool([1; 32], "flag").is_err());
    for v in [
        json!("0x00"),
        json!("0x+1"),
        json!("0x"),
        json!("0x10000000000000000"),
        json!(null),
    ] {
        assert!(observation::quantity(&v).is_err());
    }
}

#[test]
#[ignore = "requires real cast; explicitly run in native verification"]
fn runtime_state_native_cast_gate_vault_claims_terminal_and_bond_positive() {
    let primary = Server::start(Fault::None);
    let witness = Server::start(Fault::None);
    let l1 = configured(&primary, &witness);
    assert_eq!(
        l1.vault_deposit_observation(5).unwrap(),
        (7, crate::hex32(&[4; 32]))
    );
    assert_eq!(l1.claimed_many(&[[1; 32], [2; 32]]).unwrap(), vec![[1; 32]]);
    assert_eq!(l1.close_only_observation().unwrap(), (28, false));
    assert_eq!(l1.gate_observation().unwrap(), (16, 6, [3; 32], false));
    assert_eq!(
        crate::observe_gate_once(&l1, 5, [3; 32]),
        crate::trading_gate::GateObservation::OpensGate
    );
    assert_eq!(l1.batch_count().unwrap(), 6);
    assert_eq!(l1.current_root().unwrap(), crate::hex32(&[3; 32]));
    assert_eq!(l1.sequencer_bond().unwrap(), 77);
    // req=30/have=77: exercise the real paired bond read; no transaction/signing.
    assert_eq!(l1.ensure_bond().unwrap(), None);
    assert_eq!(l1.challenge_scan_start_observation().unwrap(), (28, 200));
    assert!(l1.challenge_answerable(&crate::hex32(&[1; 32])).unwrap());
    assert!(primary
        .fixture
        .calls
        .lock()
        .unwrap()
        .iter()
        .all(|(m, _)| !m.contains("send")));
}
#[test]
#[ignore = "requires real cast; explicitly run in native verification"]
fn runtime_state_native_cast_refusals_are_all_or_nothing_and_redacted() {
    for fault in [
        Fault::Word(4),
        Fault::Word(5),
        Fault::CanonicalAfter,
        Fault::MalformedWord,
        Fault::Failure(5),
    ] {
        let primary = Server::start(Fault::None);
        let witness = Server::start(fault);
        let error = configured(&primary, &witness)
            .vault_deposit_observation(5)
            .unwrap_err();
        assert!(!error.contains(SECRET));
    }
    for fault in [Fault::Word(6), Fault::CanonicalAfter, Fault::Failure(5)] {
        let primary = Server::start(Fault::None);
        let witness = Server::start(fault);
        let error = configured(&primary, &witness)
            .claimed_many(&[[1; 32], [2; 32]])
            .unwrap_err();
        assert!(!error.contains(SECRET));
    }
    for fault in [Fault::Bool, Fault::Overflow, Fault::Tuple] {
        let primary = Server::start(fault);
        let witness = Server::start(fault);
        let l1 = configured(&primary, &witness);
        assert!(
            l1.challenge_answerable(&crate::hex32(&[1; 32])).is_err(),
            "{fault:?}"
        );
    }
    let primary = Server::start(Fault::Bool);
    let witness = Server::start(Fault::Bool);
    let l1 = configured(&primary, &witness);
    assert!(l1.claimed_many(&[[1; 32]]).is_err());
    assert!(l1.close_only_observation().is_err());
    assert_eq!(
        crate::observe_gate_once(&l1, 5, [3; 32]),
        crate::trading_gate::GateObservation::Inconclusive
    );
    for fault in [
        Fault::LaggingHead,
        Fault::CanonicalAfter,
        Fault::Word(3),
        Fault::Failure(6),
    ] {
        let primary = Server::start(Fault::None);
        let witness = Server::start(fault);
        assert_eq!(
            crate::observe_gate_once(&configured(&primary, &witness), 5, [3; 32]),
            crate::trading_gate::GateObservation::Inconclusive,
            "{fault:?}"
        );
    }
}

// Deposit adapter tests validate secondary state independently of the existing
// page validator's log/prefix/reorg matrix. Hash-pinned calls cannot be widened.
struct DepositFixture {
    disagree: bool,
    calls: std::sync::Mutex<Vec<(String, Vec<Value>)>>,
}
impl DepositFixture {
    fn new(disagree: bool) -> Self {
        Self {
            disagree,
            calls: Default::default(),
        }
    }
}
impl Rpc for DepositFixture {
    fn call(&self, method: &str, params: Vec<Value>) -> Result<Value, String> {
        self.calls
            .lock()
            .unwrap()
            .push((method.into(), params.clone()));
        Ok(match method {
            "eth_chainId" => json!("0x14a34"),
            "eth_getBlockByNumber" => {
                json!({"number":"0x10","hash":crate::hex32(&[if self.disagree {8}else{9};32])})
            }
            "eth_call" => json!(crate::hex32(&observation::u64_word(if self.disagree {
                2
            } else {
                1
            }))),
            "eth_getCode" => json!(if self.disagree { "0x01" } else { "0x" }),
            "eth_getLogs" => {
                if self.disagree {
                    json!([{"removed":true}])
                } else {
                    json!([])
                }
            }
            _ => panic!("unsupported method {method}"),
        })
    }
}
#[test]
fn deposit_witness_adapter_requires_pinned_matching_words_code_logs_and_headers() {
    let pin = json!({"blockHash":crate::hex32(&[9;32]),"requireCanonical":true});
    for (method, params) in [
        (
            "eth_getBlockByNumber",
            vec![json!("finalized"), json!(false)],
        ),
        ("eth_getBlockByNumber", vec![json!("0x10"), json!(false)]),
        (
            "eth_call",
            vec![json!({"to":SETTLEMENT,"data":"0x"}), pin.clone()],
        ),
        ("eth_getCode", vec![json!(SETTLEMENT), pin]),
        (
            "eth_getLogs",
            vec![json!({"blockHash":crate::hex32(&[9;32])})],
        ),
    ] {
        assert!(
            observation::deposit_read(
                &DepositFixture::new(false),
                Some(&DepositFixture::new(false)),
                Some(84532),
                method,
                params.clone()
            )
            .is_ok(),
            "{method}"
        );
        assert!(
            observation::deposit_read(
                &DepositFixture::new(false),
                Some(&DepositFixture::new(true)),
                Some(84532),
                method,
                params
            )
            .is_err(),
            "{method}"
        );
    }
}
#[test]
fn deposit_witness_adapter_rejects_unpinned_reads_before_transport() {
    for (method, params) in [
        ("eth_getBlockByNumber", vec![json!("latest"), json!(false)]),
        ("eth_call", vec![json!({}), json!("latest")]),
        ("eth_getCode", vec![json!(SETTLEMENT), json!("latest")]),
        (
            "eth_getLogs",
            vec![json!({"fromBlock":"0x1","toBlock":"latest"})],
        ),
        ("eth_sendRawTransaction", vec![json!(SECRET)]),
    ] {
        let primary = DepositFixture::new(false);
        let witness = DepositFixture::new(false);
        assert!(
            observation::deposit_read(&primary, Some(&witness), Some(84532), method, params)
                .is_err()
        );
        assert!(primary.calls.lock().unwrap().is_empty());
        assert!(witness.calls.lock().unwrap().is_empty());
    }
}

#[test]
#[ignore = "requires real cast; explicitly run in native verification"]
fn runtime_state_native_cast_deposit_adapter_checks_secondary_code_logs_and_words() {
    use sha3::{Digest as _, Keccak256};
    let pin = json!({"blockHash":crate::hex32(&[9;32]),"requireCanonical":true});
    let fixtures = [
        (
            "eth_getBlockByNumber",
            vec![json!("finalized"), json!(false)],
            Fault::FinalizedHash,
        ),
        (
            "eth_call",
            vec![
                json!({"to":SETTLEMENT,"data":crate::hex0x(&Keccak256::digest(b"depositCount()")[..4])}),
                pin.clone(),
            ],
            Fault::Word(4),
        ),
        ("eth_getCode", vec![json!(SETTLEMENT), pin], Fault::Word(10)),
        (
            "eth_getLogs",
            vec![json!({"blockHash":crate::hex32(&[9;32])})],
            Fault::Word(11),
        ),
    ];
    for (method, params, fault) in fixtures {
        let primary = Server::start(Fault::None);
        let witness = Server::start(Fault::None);
        let l1 = configured(&primary, &witness);
        l1.read_rpc("eth_getBlockByNumber", &[json!("finalized"), json!(false)])
            .unwrap();
        assert!(l1.read_rpc(method, &params).is_ok(), "{method}");
        let primary = Server::start(Fault::None);
        let witness = Server::start(fault);
        let l1 = configured(&primary, &witness);
        if method != "eth_getBlockByNumber" {
            l1.read_rpc("eth_getBlockByNumber", &[json!("finalized"), json!(false)])
                .unwrap();
        }
        let err = l1.read_rpc(method, &params).unwrap_err();
        assert!(!err.contains(SECRET));
    }
    let primary = Server::start(Fault::None);
    let witness = Server::start(Fault::Failure(2));
    let err = configured(&primary, &witness)
        .read_rpc(
            "eth_getCode",
            &[
                json!(SETTLEMENT),
                json!({"blockHash":crate::hex32(&[9;32]),"requireCanonical":true}),
            ],
        )
        .unwrap_err();
    assert!(!err.contains(SECRET));
}

#[test]
fn challenge_discovery_binds_logs_to_canonical_page_and_refuses_malformed_events() {
    let run = |p: Fault, w: Fault| -> Result<(Vec<String>, u64, Option<Digest>), String> {
        let primary = Fixture::new(p);
        let witness = Fixture::new(w);
        let r = CanonicalRead::with_policy(
            &primary,
            Some(&witness),
            Some(84532),
            AnchorPolicy::Latest,
        )?;
        let result = r.challenges(SETTLEMENT, 16)?;
        r.finish()?;
        Ok(result)
    };
    assert_eq!(
        run(Fault::None, Fault::None).unwrap(),
        (vec![crate::hex32(&[5; 32])], 29, Some([10; 32]))
    );
    assert!(run(Fault::None, Fault::Log(0)).is_err());
    assert_eq!(
        run(Fault::Log(0), Fault::Log(0)).unwrap(),
        (vec![], 29, Some([10; 32]))
    );
    for i in 1..=10 {
        assert!(
            run(Fault::Log(i), Fault::Log(i)).is_err(),
            "invalid matching log {i}"
        );
    }
    for f in [Fault::CanonicalAfter, Fault::WrongHeight, Fault::Failure(5)] {
        assert!(run(Fault::None, f).is_err(), "{f:?}");
    }
}
#[test]
fn challenge_discovery_caps_page_size_and_never_uses_latest_as_log_bound() {
    struct Empty {
        calls: std::sync::Mutex<Vec<(String, Vec<Value>)>>,
    }
    impl Rpc for Empty {
        fn call(&self, m: &str, p: Vec<Value>) -> Result<Value, String> {
            self.calls.lock().unwrap().push((m.into(), p.clone()));
            Ok(match m {
                "eth_chainId" => json!("0x14a34"),
                "eth_getBlockByNumber" => {
                    json!({"number":if p[0]==json!("latest"){json!("0x1000")}else{p[0].clone()},"hash":crate::hex32(&[9;32])})
                }
                "eth_getLogs" => json!([]),
                _ => panic!("unexpected method"),
            })
        }
    }
    let primary = Empty {
        calls: Default::default(),
    };
    let witness = Empty {
        calls: Default::default(),
    };
    let r = CanonicalRead::with_policy(&primary, Some(&witness), Some(84532), AnchorPolicy::Latest)
        .unwrap();
    assert_eq!(
        r.challenges(SETTLEMENT, 16).unwrap(),
        (vec![], 1040, Some([9; 32]))
    );
    r.finish().unwrap();
    for fixture in [&primary, &witness] {
        let calls = fixture.calls.lock().unwrap();
        let (_, p) = calls.iter().find(|(m, _)| m == "eth_getLogs").unwrap();
        assert_eq!(p[0]["fromBlock"], json!("0x10"));
        assert_eq!(p[0]["toBlock"], json!("0x40f"));
    }
}
#[test]
#[ignore = "requires real cast; explicitly run in native verification"]
fn runtime_state_native_cast_challenge_discovery_requires_matching_canonical_logs() {
    let primary = Server::start(Fault::None);
    let witness = Server::start(Fault::None);
    assert_eq!(
        configured(&primary, &witness).fetch_challenges(16).unwrap(),
        (vec![crate::hex32(&[5; 32])], 29, Some([10; 32]))
    );
    let primary = Server::start(Fault::None);
    let witness = Server::start(Fault::Log(0));
    assert!(configured(&primary, &witness).fetch_challenges(16).is_err());
    for fault in [Fault::Log(1), Fault::Log(4), Fault::Log(6), Fault::Log(7)] {
        let primary = Server::start(fault);
        let witness = Server::start(fault);
        assert!(configured(&primary, &witness).fetch_challenges(16).is_err());
    }
    for fault in [Fault::CanonicalAfter, Fault::Failure(5)] {
        let primary = Server::start(Fault::None);
        let witness = Server::start(fault);
        let e = configured(&primary, &witness)
            .fetch_challenges(16)
            .unwrap_err();
        assert!(!e.contains(SECRET));
    }
}

#[test]
#[ignore = "requires real cast; explicitly run in native verification"]
fn runtime_state_native_cast_prior_page_reorg_and_challenge_deadline_boundaries() {
    let old_primary = Server::start(Fault::None);
    let old_witness = Server::start(Fault::None);
    let old = configured(&old_primary, &old_witness);
    let (_, next, anchor) = old.fetch_challenges(16).unwrap();
    let anchor = anchor.unwrap();
    assert!(old.challenge_scan_anchor_matches(next - 1, anchor).unwrap());
    let primary = Server::start(Fault::ForkWorld);
    let witness = Server::start(Fault::ForkWorld);
    let replacement = configured(&primary, &witness);
    assert!(!replacement
        .challenge_scan_anchor_matches(next - 1, anchor)
        .unwrap());
    assert_eq!(
        replacement.fetch_challenges(16).unwrap().0,
        vec![crate::hex32(&[6; 32])]
    );
    let primary = Server::start(Fault::None);
    let witness = Server::start(Fault::ForkWorld);
    assert!(configured(&primary, &witness)
        .challenge_scan_anchor_matches(next - 1, anchor)
        .is_err());
    // Contract allows equality; expired entries can stay open but are unanswerable.
    for (deadline, answerable) in [(27, false), (28, true), (29, true)] {
        let primary = Server::start(Fault::Deadline(deadline));
        let witness = Server::start(Fault::Deadline(deadline));
        assert_eq!(
            configured(&primary, &witness)
                .challenge_answerable(&crate::hex32(&[1; 32]))
                .unwrap(),
            answerable
        );
    }
}

#[test]
#[ignore = "requires real cast and local loopback; explicitly run in native verification"]
fn runtime_state_native_cast_wind_down_pair_is_hash_pinned() {
    let primary = Server::start(Fault::None);
    let witness = Server::start(Fault::None);
    let observed = configured(&primary, &witness)
        .wind_down_observation()
        .unwrap();
    assert_eq!(observed.block, 28);
    assert!(!observed.close_only);
    assert!(!observed.settled);
    assert_eq!(observed.batch_count, 6);
    assert_eq!(observed.root, [3; 32]);
    for fixture in [&primary.fixture, &witness.fixture] {
        let calls = fixture.calls.lock().unwrap();
        assert_eq!(calls.iter().filter(|(m, _)| m == "eth_call").count(), 4);
        assert_eq!(calls.last().unwrap().1[0], json!("0x1c"));
    }
}

#[test]
#[ignore = "requires real cast and local loopback; explicitly run in native verification"]
fn runtime_state_native_cast_wind_down_refuses_incoherent_or_failed_reads() {
    for fault in [
        Fault::Chain,
        Fault::ForkWorld,
        Fault::CanonicalAfter,
        Fault::Word(10),
        Fault::Word(0),
        Fault::Word(1),
        Fault::Bool,
        Fault::MalformedWord,
        Fault::Failure(4),
    ] {
        let primary = Server::start(Fault::None);
        let witness = Server::start(fault);
        assert!(
            configured(&primary, &witness)
                .wind_down_observation()
                .is_err(),
            "{fault:?}"
        );
    }
}

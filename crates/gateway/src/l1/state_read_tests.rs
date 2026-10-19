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
    assert_eq!(
        l1.ensure_bond().unwrap(),
        BondOutcome::Covered {
            bond: 77,
            target: 60,
            capacity: 1_000_000
        }
    );
    let open = l1
        .open_challenge_set(&std::collections::BTreeSet::new(), 16)
        .unwrap();
    assert_eq!((open.head, open.hashes), (28, vec![[5; 32]]));
    assert_eq!(l1.open_challenge_count().unwrap(), 1);
    assert_eq!(l1.consumed_deposit_count().unwrap(), 5);
    let gate = l1.deposit_gate_observation().unwrap();
    assert!(gate.accepting_deposits && !gate.close_only);
    assert_eq!(gate.deposit_capacity, 1_000_000);
    let live = l1.liveness_observation().unwrap();
    assert_eq!((live.head, live.last_progress_block), (28, 20));
    // slashCount() is 0: only that exact count is acknowledged.
    assert!(l1.acknowledge_slashes(1).is_err());
    assert_eq!(l1.acknowledged_slash_count(), 0);
    assert_eq!(l1.acknowledge_slashes(0), Ok(0));
    assert_eq!(l1.settlement_params().unwrap().progress_batches, 2);
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
    for fault in [
        Fault::Bool,
        Fault::Overflow,
        Fault::Tuple,
        Fault::OpenSet(0),
    ] {
        let primary = Server::start(fault);
        let witness = Server::start(fault);
        let l1 = configured(&primary, &witness);
        assert!(
            l1.open_challenge_set(&Default::default(), 16).is_err(),
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

fn open_set(
    p: Fault,
    w: Fault,
    known: &std::collections::BTreeSet<Digest>,
    max_details: usize,
) -> Result<OpenSetRead, String> {
    let primary = Fixture::new(p);
    let witness = Fixture::new(w);
    let r =
        CanonicalRead::with_policy(&primary, Some(&witness), Some(84532), AnchorPolicy::Latest)?;
    let result = r.open_challenges(SETTLEMENT, known, max_details)?;
    r.finish()?;
    Ok(result)
}
#[test]
fn open_challenge_set_reads_count_pages_and_details_at_one_anchor() {
    let read = open_set(Fault::None, Fault::None, &Default::default(), 16).unwrap();
    assert_eq!(
        read,
        OpenSetRead {
            head: 28,
            batch_count: 6,
            hashes: vec![[5; 32]],
            details: vec![OpenChallenge {
                order_hash: [5; 32],
                beneficiary: [0x33; 20],
                batch_id_hint: 0,
                opened_block: 16,
                open_batch_count: 6,
                stake: 1,
            }],
        }
    );
    // Known hashes are not re-read: their details cannot change while open.
    let primary = Fixture::new(Fault::None);
    let r = CanonicalRead::with_policy(&primary, None, None, AnchorPolicy::Latest).unwrap();
    let known = std::collections::BTreeSet::from([[5; 32]]);
    let read = r.open_challenges(SETTLEMENT, &known, 16).unwrap();
    assert!(read.details.is_empty());
    use sha3::{Digest as _, Keccak256};
    let detail = crate::hex0x(&Keccak256::digest(b"challenges(bytes32)")[..4]);
    assert!(!primary
        .calls
        .lock()
        .unwrap()
        .iter()
        .any(|(m, p)| m == "eth_call" && p[0]["data"].as_str().unwrap().starts_with(&detail)));
}
#[test]
fn open_challenge_set_spans_pages_and_bounds_new_detail_reads() {
    let read = open_set(
        Fault::LargeOpenSet,
        Fault::LargeOpenSet,
        &Default::default(),
        4,
    )
    .unwrap();
    assert_eq!(read.hashes.len(), 513);
    assert_eq!(
        read.hashes
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        513
    );
    assert_eq!(read.details.len(), 4);
}
#[test]
fn open_challenge_set_refuses_malformed_impossible_or_disagreeing_reads() {
    // 0 short page, 1 bad offset, 2 length past the data, 3 duplicate, 4 listed
    // but not open, 5 opened after the current batch count, 6 opened after the
    // anchor block, 7 zero beneficiary.
    for i in 0..=7 {
        assert!(
            open_set(
                Fault::OpenSet(i),
                Fault::OpenSet(i),
                &Default::default(),
                16
            )
            .is_err(),
            "open set fault {i}"
        );
    }
    for f in [
        Fault::Bool,
        Fault::Overflow,
        Fault::Tuple,
        Fault::MalformedWord,
    ] {
        assert!(open_set(f, f, &Default::default(), 16).is_err(), "{f:?}");
    }
    // The witness must agree on the count, every page and every detail.
    for f in [
        Fault::Word(12),
        Fault::Word(9),
        Fault::OpenSet(0),
        Fault::OpenSet(5),
        Fault::CanonicalAfter,
        Fault::Failure(5),
    ] {
        assert!(
            open_set(Fault::None, f, &Default::default(), 16).is_err(),
            "witness {f:?}"
        );
    }
}
#[test]
fn boot_posture_reads_every_term_from_one_snapshot() {
    let read = |p: Fault, w: Fault| {
        let primary = Fixture::new(p);
        let witness = Fixture::new(w);
        let r = CanonicalRead::with_policy(
            &primary,
            Some(&witness),
            Some(84532),
            AnchorPolicy::Finalized,
        )?;
        let posture = super::read_boot_posture(&r, SETTLEMENT, Some(SETTLEMENT))?;
        r.finish()?;
        Ok::<_, String>(posture)
    };
    let me = crate::parse_addr20_hex(SETTLEMENT).unwrap();
    assert_eq!(
        read(Fault::None, Fault::None).unwrap(),
        BootPosture {
            abi_version: 3,
            verifier: me,
            proof_version: 2,
            vault: me,
            vault_settlement: me,
            anchor_timeout_ms: Some(3_600_000),
            liveness_timeout_blocks: 43_200,
            consumed_deposit_count: 5,
            current_root: [3; 32],
            enclave_signer: me,
            sequencer: me,
            governance: me,
        }
    );
    let error = read(Fault::Word(14), Fault::Word(14)).unwrap_err();
    assert!(error.contains("ABI_VERSION is 4"), "{error}");
    for f in [
        Fault::Word(14),
        Fault::Word(16),
        Fault::Word(19),
        Fault::Word(21),
        Fault::Word(30),
        Fault::Word(31),
        Fault::Word(32),
        Fault::Failure(4),
    ] {
        assert!(read(Fault::None, f).is_err(), "witness {f:?}");
    }
}
#[test]
fn the_slash_count_an_acknowledgement_is_checked_against_is_read_strictly() {
    let read = |p: Fault, w: Fault| {
        let primary = Fixture::new(p);
        let witness = Fixture::new(w);
        let r = CanonicalRead::with_policy(
            &primary,
            Some(&witness),
            Some(84532),
            AnchorPolicy::Latest,
        )?;
        let count = super::read_slash_count(&r, SETTLEMENT)?;
        r.finish()?;
        Ok::<_, String>(count)
    };
    assert_eq!(read(Fault::None, Fault::None), Ok(0));
    // index 8 is slashCount(): a disagreeing witness, or a malformed or
    // overflowing word, is refused rather than acknowledged.
    for (p, w) in [
        (Fault::None, Fault::Word(8)),
        (Fault::MalformedWord, Fault::MalformedWord),
        (Fault::Overflow, Fault::Overflow),
        (Fault::None, Fault::CanonicalAfter),
    ] {
        assert!(read(p, w).is_err(), "{p:?} {w:?}");
    }
}
#[test]
fn bond_terms_and_settlement_params_are_read_strictly() {
    let primary = Fixture::new(Fault::None);
    let witness = Fixture::new(Fault::None);
    let r = CanonicalRead::with_policy(&primary, Some(&witness), Some(84532), AnchorPolicy::Latest)
        .unwrap();
    assert_eq!(
        super::read_bond_terms(&r, SETTLEMENT).unwrap(),
        super::BondTerms {
            required: 30,
            bond: 77,
            slash_count: 0,
            capacity: 1_000_000
        }
    );
    assert_eq!(
        super::read_settlement_params(&r, SETTLEMENT).unwrap(),
        SettlementParams {
            liveness_timeout_blocks: 43_200,
            challenge_grace_blocks: 3_600,
            progress_batches: 2,
            slash_payout_cap: 1_000_000_000,
            challenge_bond: 10_000_000_000_000_000,
            inclusion_deadline_secs: 3_600,
        }
    );
    r.finish().unwrap();
    let primary = Fixture::new(Fault::None);
    let witness = Fixture::new(Fault::Word(8));
    let r = CanonicalRead::with_policy(&primary, Some(&witness), Some(84532), AnchorPolicy::Latest)
        .unwrap();
    assert!(
        super::read_bond_terms(&r, SETTLEMENT).is_err(),
        "slashCount disagreement"
    );
}
#[test]
#[ignore = "requires real cast; explicitly run in native verification"]
fn runtime_state_native_cast_open_set_and_boot_posture_are_hash_pinned() {
    let primary = Server::start(Fault::None);
    let witness = Server::start(Fault::None);
    let mut l1 = configured(&primary, &witness);
    l1.clock = Some(clock_binding::ClockConfig {
        verifier: crate::parse_addr20_hex(SETTLEMENT).unwrap(),
        chain_id: 84532,
        stop: None,
        program_vkey: Default::default(),
    });
    assert_eq!(
        l1.open_challenge_set(&Default::default(), 16)
            .unwrap()
            .details
            .len(),
        1
    );
    assert_eq!(l1.boot_posture().unwrap().abi_version, 3);
    assert_eq!(l1.anchor_timeout_ms().unwrap(), 3_600_000);
    for fault in [Fault::OpenSet(3), Fault::CanonicalAfter, Fault::Failure(5)] {
        let primary = Server::start(Fault::None);
        let witness = Server::start(fault);
        let e = configured(&primary, &witness)
            .open_challenge_set(&Default::default(), 16)
            .unwrap_err();
        assert!(!e.contains(SECRET));
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

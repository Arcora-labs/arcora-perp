//! Versioned witness/native-guest constraint tests. No real Groth16 proof claim.
use perp_core::clock::{ClockContext, ClockWitness, TimeBounds, WIRE_MAGIC};
use perp_core::commitment::derive_roots;
use perp_core::engine::BatchOp;
use perp_core::fixed::PRICE_SCALE;
use perp_core::hash::Keccak256;
use perp_core::market::Market;
use perp_core::oracle::{oracle_digest, OracleSig, OracleTranscript};
use perp_core::order::BatchManifest;
use perp_core::{DefaultState, EngineError};
fn fixture() -> ClockWitness {
    let key = k256::ecdsa::SigningKey::from_slice(&[7; 32]).unwrap();
    let price = 100_000 * PRICE_SCALE;
    let digest = oracle_digest(0, price, 10_000, 0, price);
    let sig = OracleSig::sign(&key, &digest);
    let mut m = Market::conservative(0);
    m.oracle_pubkey = sig.recover(&digest).unwrap();
    let mut state = DefaultState::new(16);
    state.add_market(m);
    let ops = vec![BatchOp::AccrueFunding {
        market_id: 0,
        mark: price,
        now_ms: 10_000,
        oracle: OracleTranscript {
            price,
            publish_time_ms: 10_000,
            confidence: 0,
            backup_twap: price,
            signature: sig,
        },
    }];
    let manifest = BatchManifest {
        previous_state_root: state.state_root(),
        batch_id: 0,
        batch_time_ms: 10_000,
        ordered: vec![],
        rejected: vec![],
        oracle_updates: vec![],
        matching_rule_version: 0,
        enclave_measurement: [0; 32],
        sequencer_pubkey_epoch: 0,
    };
    let d = derive_roots(&mut state.clone(), &ops, &manifest).unwrap();
    let c = ClockContext {
        chain_id: 84532,
        verifier: [0x11; 20],
        settlement: [0x22; 20],
        batch_id: 0,
        previous_root: d.prev_state_root,
        base_commitment: d.commitment::<Keccak256>(),
        phase: 0,
        first_ms: 10_000,
        last_ms: 10_000,
        timed_ops: 1,
        anchored_at_ms: 10_000,
        max_window_ms: 5_000,
        clock_skew_ms: 1_000,
    };
    (state, ops, manifest, c)
}
fn encode(w: &ClockWitness) -> Vec<u8> {
    let mut b = WIRE_MAGIC.to_vec();
    b.extend(postcard::to_allocvec(w).unwrap());
    b
}
#[test]
fn clock_wire_native_derives_bound_commitment_and_keeps_legacy_distinct() {
    let w = fixture();
    let public = prover::public_from_witness(&encode(&w)).unwrap();
    assert_eq!(public.commitment::<Keccak256>(), w.3.commitment());
    assert_eq!(public.clock_receipt, Some(w.3.receipt()));
    let legacy = postcard::to_allocvec(&(&w.0, &w.1, &w.2)).unwrap();
    assert_ne!(
        prover::public_from_witness(&legacy)
            .unwrap()
            .commitment::<Keccak256>(),
        public.commitment::<Keccak256>()
    );
}
#[test]
fn clock_wire_derives_every_time_and_count_instead_of_trusting_bounds() {
    for n in 0..10 {
        let mut w = fixture();
        match n {
            0 => w.3.first_ms = 9_999,
            1 => w.3.last_ms = 10_001,
            2 => w.3.timed_ops = 0,
            3 => w.3.previous_root = [9; 32],
            4 => w.3.base_commitment = [8; 32],
            5 => w.3.batch_id = 1,
            6 => w.3.phase = 1,
            7 => w.3.chain_id = 0,
            8 => w.3.verifier = [0; 20],
            _ => w.3.settlement = [0; 20],
        }
        assert!(
            prover::public_from_witness(&encode(&w)).is_err(),
            "mutation {n}"
        );
    }
}
#[test]
fn clock_wire_refuses_backdating_future_dating_and_zero_policy() {
    for at in [8_999, 11_001] {
        let mut w = fixture();
        w.3.anchored_at_ms = at;
        assert!(prover::public_from_witness(&encode(&w)).is_err());
    }
    for at in [9_000, 11_000] {
        let mut w = fixture();
        w.3.anchored_at_ms = at;
        assert!(prover::public_from_witness(&encode(&w)).is_ok());
    }
    let mut w = fixture();
    w.3.max_window_ms = 0;
    assert!(prover::public_from_witness(&encode(&w)).is_err());
}
#[test]
fn clock_wire_rejects_trailing_truncated_and_misversioned_payloads() {
    let b = encode(&fixture());
    let mut trailing = b.clone();
    trailing.push(0);
    assert!(prover::public_from_witness(&trailing).is_err());
    for end in [0, 1, 8, 9, b.len() - 1] {
        assert!(prover::public_from_witness(&b[..end]).is_err());
    }
    let mut bad = b;
    bad[5] = b'3';
    assert!(prover::public_from_witness(&bad).is_err());
}
#[test]
fn clock_bounds_reject_backward_order_without_rewriting_inputs() {
    let w = fixture();
    let mut ops = w.1.clone();
    let mut earlier = ops[0].clone();
    if let BatchOp::AccrueFunding { now_ms, .. } = &mut earlier {
        *now_ms = 9_000;
    }
    ops.push(earlier);
    assert_eq!(TimeBounds::derive(&ops), Err(EngineError::ClockMismatch));
    assert_eq!(TimeBounds::derive(&w.1).unwrap().last_ms, 10_000);
}
#[test]
fn clock_empty_and_terminal_batches_are_price_free_not_fake_timestamps() {
    assert_eq!(TimeBounds::derive(&[]).unwrap(), TimeBounds::default());
    assert_eq!(
        TimeBounds::derive(&[BatchOp::SettleAll]).unwrap(),
        TimeBounds::default()
    );
}
#[test]
fn clock_receipt_domain_and_every_policy_field_is_bound() {
    let w = fixture();
    let original = w.3.receipt();
    for i in 0..6 {
        let mut c = w.3;
        match i {
            0 => c.chain_id += 1,
            1 => c.verifier[0] ^= 1,
            2 => c.settlement[0] ^= 1,
            3 => c.anchored_at_ms += 1,
            4 => c.max_window_ms += 1,
            _ => c.clock_skew_ms += 1,
        };
        assert_ne!(c.receipt(), original);
    }
}
#[test]
fn clock_receipt_matches_solidity_v2_vector() {
    let c = ClockContext {
        chain_id: 84532,
        verifier: [0x11; 20],
        settlement: [0x22; 20],
        batch_id: 7,
        previous_root: [0x33; 32],
        base_commitment: [0x44; 32],
        phase: 0,
        first_ms: 9_000,
        last_ms: 10_000,
        timed_ops: 2,
        anchored_at_ms: 11_000,
        max_window_ms: 5_000,
        clock_skew_ms: 1_000,
    };
    let hex = |d: [u8; 32]| d.iter().map(|b| format!("{b:02x}")).collect::<String>();
    assert_eq!(
        hex(c.receipt()),
        "cbfb7dcc2d499142a37c266092a6fa09588217870260d0141df68e3cb256f411"
    );
    assert_eq!(
        hex(c.commitment()),
        "5b443bd8d8b1939c024bb51c33edcb759be76402d0a06b6ecd67f703261fb77b"
    );
}

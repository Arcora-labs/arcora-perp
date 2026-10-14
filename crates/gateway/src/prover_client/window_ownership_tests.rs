//! Fixed public Sequencer fixtures; goldens come from the actual pre-change seal.
use k256::ecdsa::SigningKey;
use perp_core::clock::{ClockContext, TimeBounds, WIRE_MAGIC};
use perp_core::commitment::derive_roots;
use perp_core::engine::BatchOp;
use perp_core::fixed::{PRICE_SCALE, QUOTE_SCALE, SIZE_SCALE};
use perp_core::hash::{word_u64, Digest, Keccak256};
use perp_core::market::Market;
use perp_core::note::owner_from_spend_key;
use perp_core::oracle::{oracle_digest, OracleSig, OracleTranscript};
use perp_core::order::{Order, RejectReason, Side, TimeInForce};
use perp_core::Note;
use sequencer::{EnclaveIdentity, Sequencer, WindowWitness};

type Rows = Vec<(&'static str, Vec<u8>)>;
type Golden = &'static [u8];
// Actual old-source bytes, captured before the ownership change.
macro_rules! golden {
    ($name:literal) => {
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/audits/2026-10-14-seal-window-ownership/baseline-export/",
            $name
        )) as &[u8]
    };
}
const NORMAL_GOLDEN: [Golden; 10] = [
    golden!("normal-00-before_first_seal_seq.bin"),
    golden!("normal-01-first_witness.bin"),
    golden!("normal-02-first_legacy.bin"),
    golden!("normal-03-first_clocked.bin"),
    golden!("normal-04-after_first_seal_seq.bin"),
    golden!("normal-05-live_mutated_seq.bin"),
    golden!("normal-06-second_witness.bin"),
    golden!("normal-07-second_legacy.bin"),
    golden!("normal-08-second_clocked.bin"),
    golden!("normal-09-after_second_seal_seq.bin"),
];
const ROLLBACK_GOLDEN: [Golden; 11] = [
    golden!("rollback-00-before_first_seal_seq.bin"),
    golden!("rollback-01-first_witness.bin"),
    golden!("rollback-02-first_legacy.bin"),
    golden!("rollback-03-first_clocked.bin"),
    golden!("rollback-04-after_first_seal_seq.bin"),
    golden!("rollback-05-intervening_seq.bin"),
    golden!("rollback-06-after_rollback_seq.bin"),
    golden!("rollback-07-resealed_witness.bin"),
    golden!("rollback-08-resealed_legacy.bin"),
    golden!("rollback-09-resealed_clocked.bin"),
    golden!("rollback-10-after_reseal_seq.bin"),
];

fn oracle(at: u64) -> OracleTranscript {
    let key = SigningKey::from_slice(&[7; 32]).unwrap();
    let price = 100_000 * PRICE_SCALE;
    let confidence = 10 * PRICE_SCALE;
    OracleTranscript {
        price,
        publish_time_ms: at,
        confidence,
        backup_twap: price,
        signature: OracleSig::sign(&key, &oracle_digest(0, price, at, confidence, price)),
    }
}

fn order(owner: u8, side: Side, nonce: u64) -> Order {
    Order {
        owner: owner_from_spend_key::<Keccak256>(&[owner; 32]),
        market_id: 0,
        side,
        size: SIZE_SCALE / 100,
        limit_price: 100_000 * PRICE_SCALE,
        tif: TimeInForce::Gtc,
        reduce_only: false,
        nonce,
        expiry_ms: 0,
        ciphertext_commit: word_u64(nonce * 13),
    }
}

fn deposit(seq: &mut Sequencer, owner: u8, blind: u8) {
    seq.apply(&BatchOp::Deposit {
        owner: owner_from_spend_key::<Keccak256>(&[owner; 32]),
        asset_id: 0,
        amount: 40_000 * QUOTE_SCALE,
        blinding: [blind; 32],
        from: [0; 20],
        deposit_id: seq.state.consumed_deposit_count,
        deposit_blind: [0; 32],
    })
    .unwrap();
}

fn fixture() -> Sequencer {
    let mut seq = Sequencer::new(EnclaveIdentity::from_seed([9; 32], 3, [0xab; 32]), 8);
    let transcript = oracle(1_000);
    let digest = oracle_digest(
        0,
        transcript.price,
        1_000,
        transcript.confidence,
        transcript.backup_twap,
    );
    let mut market = Market::conservative(0);
    market.oracle_pubkey = transcript.signature.recover(&digest).unwrap();
    seq.add_market(market);
    seq.set_oracle(0, transcript);
    seq.set_retain_tick_snapshots(false);
    for (owner, blind) in [(1, 0x11), (2, 0x22)] {
        deposit(&mut seq, owner, blind);
        let owner_id = owner_from_spend_key::<Keccak256>(&[owner; 32]);
        let note = Note::new(owner_id, 0, 40_000 * QUOTE_SCALE, [blind; 32]);
        seq.apply(&BatchOp::FundPosition {
            owner: owner_id,
            market_id: 0,
            note_commitment: note.commitment::<Keccak256>(),
            spend_key: [owner; 32],
        })
        .unwrap();
    }
    seq.seal_genesis_baseline();
    let warmup = seq.seal_batch(&[order(1, Side::Sell, 1), order(2, Side::Buy, 2)], 1_000);
    assert!(!warmup.applied_fills.is_empty());
    assert!(warmup.receipts.iter().all(|receipt| receipt.verify()));
    let window = seq.seal_window();
    seq.mark_window_settled(window.batch_id);
    assert_eq!((seq.current_batch_id(), seq.current_window_id()), (1, 1));
    assert_eq!(seq.state.consumed_deposit_count, 2);
    seq
}

fn tick(seq: &mut Sequencer, at: u64, nonce: u64) -> sequencer::SealedBatch {
    seq.set_oracle(0, oracle(at));
    let mut expired = order(1, Side::Sell, nonce + 2);
    expired.expiry_ms = at - 1;
    let sealed = seq.seal_batch(
        &[
            order(1, Side::Sell, nonce),
            order(2, Side::Buy, nonce + 1),
            expired,
        ],
        at,
    );
    assert!(!sealed.applied_fills.is_empty());
    assert!(sealed.receipts.len() >= 2 && sealed.receipts.iter().all(|receipt| receipt.verify()));
    assert!(sealed.manifest.ordered.len() >= 2);
    assert!(sealed
        .manifest
        .rejected
        .contains(&(expired.order_hash::<Keccak256>(), RejectReason::Expired)));
    sealed
}

fn observation_hashes(ops: &[BatchOp]) -> Vec<Digest> {
    ops.iter()
        .filter_map(|op| match op {
            BatchOp::Fill { oracle, .. }
            | BatchOp::AccrueFunding { oracle, .. }
            | BatchOp::Liquidate { oracle, .. }
            | BatchOp::Unbind { oracle, .. } => Some(oracle.hash::<Keccak256>()),
            _ => None,
        })
        .collect()
}

fn clock(w: &WindowWitness) -> ClockContext {
    let mut replay = w.pre_state.clone();
    let roots = derive_roots(&mut replay, &w.ops, &w.manifest).unwrap();
    let bounds = TimeBounds::derive(&w.ops).unwrap();
    let context = ClockContext {
        chain_id: 84532,
        verifier: [1; 20],
        settlement: [2; 20],
        batch_id: w.batch_id,
        previous_root: roots.prev_state_root,
        base_commitment: roots.commitment::<Keccak256>(),
        phase: roots.wind_down_phase,
        first_ms: bounds.first_ms,
        last_ms: bounds.last_ms,
        timed_ops: bounds.count,
        anchored_at_ms: bounds.last_ms,
        max_window_ms: 60_000,
        clock_skew_ms: 2_000,
    };
    context.validate(w.batch_id, &roots, &w.ops).unwrap();
    context
}

fn record_witness(rows: &mut Rows, w: &WindowWitness, seq: &Sequencer, labels: [&'static str; 3]) {
    let mut replay = w.pre_state.clone();
    let roots = derive_roots(&mut replay, &w.ops, &w.manifest).unwrap();
    assert_eq!(roots.new_state_root, seq.state.state_root());
    assert_eq!(replay.next_batch_id, seq.current_window_id());
    assert_eq!(w.manifest.previous_state_root, w.pre_state.state_root());
    rows.push((labels[0], postcard::to_allocvec(w).unwrap()));
    rows.push((
        labels[1],
        postcard::to_allocvec(&(&w.pre_state, &w.ops, &w.manifest)).unwrap(),
    ));
    let mut wire = WIRE_MAGIC.to_vec();
    wire.extend(postcard::to_allocvec(&(&w.pre_state, &w.ops, &w.manifest, clock(w))).unwrap());
    rows.push((labels[2], wire));
}

fn first_window(rows: &mut Rows) -> (Sequencer, WindowWitness, [u64; 2]) {
    let mut seq = fixture();
    let a = tick(&mut seq, 2_000, 11);
    let b = tick(&mut seq, 2_100, 21);
    let ordered = [a.manifest.ordered.clone(), b.manifest.ordered.clone()].concat();
    let rejected = [a.manifest.rejected.clone(), b.manifest.rejected.clone()].concat();
    seq.set_oracle(0, oracle(2_200)); // live feed must not replace historical observations.
    rows.push((
        "before_first_seal_seq",
        postcard::to_allocvec(&seq).unwrap(),
    ));
    let witness = seq.seal_window();
    assert_eq!(witness.batch_id, 1);
    assert_eq!(witness.pre_state.next_batch_id, 1);
    assert_eq!(witness.manifest.ordered, ordered);
    assert_eq!(witness.manifest.rejected, rejected);
    assert_eq!(
        witness.manifest.oracle_updates,
        observation_hashes(&witness.ops)
    );
    assert!(witness
        .manifest
        .oracle_updates
        .contains(&oracle(2_000).hash::<Keccak256>()));
    assert!(witness
        .manifest
        .oracle_updates
        .contains(&oracle(2_100).hash::<Keccak256>()));
    assert!(!witness
        .manifest
        .oracle_updates
        .contains(&oracle(2_200).hash::<Keccak256>()));
    assert_eq!(
        (clock(&witness).first_ms, clock(&witness).last_ms),
        (2_000, 2_100)
    );
    record_witness(
        rows,
        &witness,
        &seq,
        ["first_witness", "first_legacy", "first_clocked"],
    );
    rows.push(("after_first_seal_seq", postcard::to_allocvec(&seq).unwrap()));
    (seq, witness, [a.batch_id, b.batch_id])
}

fn normal_trace() -> Rows {
    let mut rows = Rows::new();
    let (mut seq, first, _) = first_window(&mut rows);
    let witness_before = postcard::to_allocvec(&first).unwrap();
    deposit(&mut seq, 3, 0x33); // mutate live Merkle leaves/maps after ownership transfer.
    let later = tick(&mut seq, 2_300, 31);
    assert_eq!(
        seq.window_for_tick(later.batch_id),
        Some(first.batch_id + 1)
    );
    assert_eq!(postcard::to_allocvec(&first).unwrap(), witness_before);
    rows.push(("live_mutated_seq", postcard::to_allocvec(&seq).unwrap()));
    let second = seq.seal_window();
    assert_eq!(second.pre_state.next_batch_id, first.batch_id + 1);
    assert_eq!(second.batch_id, first.batch_id + 1);
    assert_eq!(second.pre_state.consumed_deposit_count, 2);
    assert_eq!(seq.state.consumed_deposit_count, 3);
    record_witness(
        &mut rows,
        &second,
        &seq,
        ["second_witness", "second_legacy", "second_clocked"],
    );
    rows.push((
        "after_second_seal_seq",
        postcard::to_allocvec(&seq).unwrap(),
    ));
    assert_eq!(postcard::to_allocvec(&first).unwrap(), witness_before);
    rows
}

fn rollback_trace() -> Rows {
    let mut rows = Rows::new();
    let (mut seq, first, old_ticks) = first_window(&mut rows);
    let witness_before = postcard::to_allocvec(&first).unwrap();
    let old_clock = clock(&first);
    let later = tick(&mut seq, 2_500, 31);
    let counter_a = seq.current_batch_id();
    assert_eq!(
        seq.window_for_tick(later.batch_id),
        Some(first.batch_id + 1)
    );
    seq.set_oracle(0, oracle(2_600));
    rows.push(("intervening_seq", postcard::to_allocvec(&seq).unwrap()));
    let mut expected_live = seq.state.clone();
    expected_live.next_batch_id = first.batch_id;
    seq.rollback_window(&first);
    assert_eq!(
        postcard::to_allocvec(&seq.state).unwrap(),
        postcard::to_allocvec(&expected_live).unwrap()
    );
    assert_eq!(
        (seq.current_batch_id(), seq.current_window_id()),
        (counter_a, first.batch_id)
    );
    for tick_id in old_ticks.into_iter().chain([later.batch_id]) {
        assert_eq!(seq.window_for_tick(tick_id), Some(first.batch_id));
    }
    rows.push(("after_rollback_seq", postcard::to_allocvec(&seq).unwrap()));
    let resealed = seq.seal_window();
    assert_eq!(resealed.batch_id, first.batch_id);
    assert_eq!(
        postcard::to_allocvec(&resealed.pre_state).unwrap(),
        postcard::to_allocvec(&first.pre_state).unwrap()
    );
    assert_eq!(
        postcard::to_allocvec(&resealed.ops).unwrap(),
        postcard::to_allocvec(&[first.ops.clone(), later.ops].concat()).unwrap()
    );
    assert_eq!(
        resealed.manifest.ordered,
        [first.manifest.ordered.clone(), later.manifest.ordered].concat()
    );
    assert_eq!(
        resealed.manifest.rejected,
        [first.manifest.rejected.clone(), later.manifest.rejected].concat()
    );
    assert_eq!(
        resealed.manifest.oracle_updates,
        observation_hashes(&resealed.ops)
    );
    assert!(!resealed
        .manifest
        .oracle_updates
        .contains(&oracle(2_600).hash::<Keccak256>()));
    assert_eq!(
        (clock(&resealed).first_ms, clock(&resealed).last_ms),
        (2_000, 2_500)
    );
    assert_eq!(clock(&first), old_clock);
    assert_eq!(postcard::to_allocvec(&first).unwrap(), witness_before);
    record_witness(
        &mut rows,
        &resealed,
        &seq,
        ["resealed_witness", "resealed_legacy", "resealed_clocked"],
    );
    rows.push(("after_reseal_seq", postcard::to_allocvec(&seq).unwrap()));
    rows
}

fn assert_golden(rows: Rows, expected: &[Golden]) {
    assert_eq!(rows.len(), expected.len());
    for ((name, bytes), golden) in rows.iter().zip(expected) {
        assert_eq!(
            bytes.as_slice(),
            *golden,
            "old-source complete postcard bytes: {name}"
        );
    }
}

#[test]
fn old_seal_bytes_and_second_baseline_survive_live_mutation() {
    assert_golden(normal_trace(), &NORMAL_GOLDEN);
}

#[test]
fn old_rollback_reseal_bytes_keep_intervening_order_clocks_and_maps() {
    assert_golden(rollback_trace(), &ROLLBACK_GOLDEN);
}

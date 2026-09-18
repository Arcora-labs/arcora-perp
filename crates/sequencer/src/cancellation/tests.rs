//! These tests use the real sequencer and native proof replay, never live RPC.
use super::*;
use perp_core::commitment::derive_roots;
use perp_core::fixed::{PRICE_SCALE, QUOTE_SCALE, SIZE_SCALE};
use perp_core::note::owner_from_spend_key;
use perp_core::oracle::{oracle_digest, OracleSig};
use perp_core::order::TimeInForce;
use perp_core::Note;

const NOW: u64 = 1_000;
const PRICE: i128 = 100_000 * PRICE_SCALE;

fn owner(n: u8) -> PubKey {
    owner_from_spend_key::<Keccak256>(&[n; 32])
}
fn order(n: u8, side: Side, size: i128, nonce: u64) -> Order {
    Order {
        owner: owner(n),
        market_id: 0,
        side,
        size,
        limit_price: PRICE,
        tif: TimeInForce::Gtc,
        reduce_only: false,
        nonce,
        expiry_ms: 0,
        ciphertext_commit: word_u64(nonce),
    }
}
fn setup() -> Sequencer {
    let key = SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
    let digest = oracle_digest(0, PRICE, NOW, PRICE / 1_000, PRICE);
    let signature = OracleSig::sign(&key, &digest);
    let mut market = Market::conservative(0);
    market.oracle_pubkey = signature.recover(&digest).unwrap();
    let mut seq = Sequencer::new(EnclaveIdentity::from_seed([9; 32], 1, [0xAB; 32]), 20);
    seq.add_market(market);
    seq.set_oracle(
        0,
        OracleTranscript {
            price: PRICE,
            publish_time_ms: NOW,
            confidence: PRICE / 1_000,
            backup_twap: PRICE,
            signature,
        },
    );
    for n in [1u8, 2u8] {
        let amount = 50_000 * QUOTE_SCALE;
        let blinding = [n + 10; 32];
        seq.apply(&BatchOp::Deposit {
            owner: owner(n),
            asset_id: 0,
            amount,
            blinding,
            from: [n; 20],
            deposit_id: seq.state.consumed_deposit_count,
            deposit_blind: [n + 20; 32],
        })
        .unwrap();
        seq.apply(&BatchOp::FundPosition {
            owner: owner(n),
            market_id: 0,
            note_commitment: Note::new(owner(n), 0, amount, blinding).commitment::<Keccak256>(),
            spend_key: [n; 32],
        })
        .unwrap();
    }
    seq.seal_genesis_baseline();
    seq
}
fn rest(seq: &mut Sequencer) -> Order {
    let maker = order(1, Side::Sell, SIZE_SCALE, 1);
    seq.accept_order(&maker, NOW);
    seq.seal_batch(&[maker], NOW);
    assert_eq!(
        seq.cancellable_size(&maker.owner, &maker, true),
        Some(SIZE_SCALE)
    );
    maker
}
fn assert_replay(seq: &mut Sequencer, cancelled: Digest) {
    let witness = seq.seal_window();
    assert!(witness
        .manifest
        .rejected
        .contains(&(cancelled, RejectReason::Cancelled)));
    let mut state = witness.pre_state.clone();
    let roots = derive_roots(&mut state, &witness.ops, &witness.manifest).unwrap();
    assert_eq!(roots.new_state_root, seq.state.state_root());
    assert!(seq.state.conservation_holds());
}

#[test]
fn resting_cancel_removes_depth_and_records_manifest_without_mutating_accounting() {
    let mut seq = setup();
    let maker = rest(&mut seq);
    let before = seq.state.state_root();
    assert_eq!(
        seq.cancel_order(&maker.owner, &maker, true),
        Some(SIZE_SCALE)
    );
    assert_eq!(seq.state.state_root(), before);
    assert_eq!(seq.book(0).unwrap().resting_size(Side::Sell), 0);
    assert!(seq.window_has_pending_manifest());
    assert_replay(&mut seq, maker.order_hash::<Keccak256>());
}

#[test]
fn pending_cancellation_resolves_the_acceptance_receipt() {
    let mut seq = setup();
    let pending = order(1, Side::Sell, SIZE_SCALE, 2);
    seq.accept_order(&pending, NOW);
    assert_eq!(
        seq.cancel_order(&pending.owner, &pending, false),
        Some(SIZE_SCALE)
    );
    assert_eq!(seq.cancel_order(&pending.owner, &pending, false), None);
    for _ in 0..4 {
        seq.seal_batch(&[], NOW);
    }
    assert!(!seq
        .inclusion_violations(1)
        .contains(&pending.order_hash::<Keccak256>()));
    assert_replay(&mut seq, pending.order_hash::<Keccak256>());
}

#[test]
fn wrong_owner_and_unknown_order_cannot_cancel() {
    let mut seq = setup();
    let maker = rest(&mut seq);
    let before = seq.state.state_root();
    assert_eq!(seq.cancel_order(&owner(2), &maker, true), None);
    assert_eq!(
        seq.cancel_order(&owner(1), &order(1, Side::Sell, SIZE_SCALE, 99), false),
        None
    );
    assert_eq!(seq.book(0).unwrap().resting_size(Side::Sell), SIZE_SCALE);
    assert_eq!(seq.state.state_root(), before);
    assert!(seq.window_rejected.is_empty());
}

#[test]
fn already_processed_ioc_is_not_a_pending_cancellable_order() {
    let mut seq = setup();
    let mut ioc = order(1, Side::Sell, SIZE_SCALE, 2);
    ioc.tif = TimeInForce::Ioc;
    seq.accept_order(&ioc, NOW);
    seq.seal_batch(&[ioc], NOW);
    assert_eq!(seq.cancel_order(&ioc.owner, &ioc, true), None);
    // Even a bad caller-supplied submission marker cannot resurrect an IOC.
    assert_eq!(seq.cancel_order(&ioc.owner, &ioc, false), None);
}

#[test]
fn partial_cancel_uses_real_remaining_size_and_preserves_the_fill() {
    let mut seq = setup();
    let maker = rest(&mut seq);
    let taker = order(2, Side::Buy, SIZE_SCALE / 4, 2);
    let batch = seq.seal_batch(&[taker], NOW + 1);
    assert_eq!(batch.settled_order_hashes.len(), 2);
    assert_eq!(
        seq.state.position(&maker.owner, 0).unwrap().size,
        -SIZE_SCALE / 4
    );
    let before = seq.state.state_root();
    assert_eq!(
        seq.cancel_order(&maker.owner, &maker, true),
        Some(SIZE_SCALE * 3 / 4)
    );
    assert_eq!(seq.state.state_root(), before);
    assert_eq!(
        seq.finality_of(&maker.order_hash::<Keccak256>()),
        Some(Finality::Matched)
    );
    assert_replay(&mut seq, maker.order_hash::<Keccak256>());
}

#[test]
fn settled_partial_fill_does_not_block_remainder_cancellation() {
    let mut seq = setup();
    let maker = rest(&mut seq);
    let batch = seq.seal_batch(&[order(2, Side::Buy, SIZE_SCALE / 4, 2)], NOW + 1);
    let first = seq.seal_window();
    seq.mark_settled(batch.batch_id);
    let hash = maker.order_hash::<Keccak256>();
    assert_eq!(seq.finality_of(&hash), Some(Finality::Settled));
    assert_eq!(
        seq.cancel_order(&maker.owner, &maker, true),
        Some(SIZE_SCALE * 3 / 4)
    );
    assert_eq!(seq.finality_of(&hash), Some(Finality::Settled));
    // The already-sealed witness is immutable: the cancel belongs to the next window.
    assert!(!first
        .manifest
        .rejected
        .contains(&(hash, RejectReason::Cancelled)));
    assert_replay(&mut seq, hash);
}

#[test]
fn full_fill_has_no_cancellable_remainder() {
    let mut seq = setup();
    let maker = rest(&mut seq);
    seq.seal_batch(&[order(2, Side::Buy, SIZE_SCALE, 2)], NOW + 1);
    let before = seq.state.state_root();
    assert_eq!(seq.cancel_order(&maker.owner, &maker, true), None);
    assert_eq!(seq.state.state_root(), before);
    assert!(seq.window_rejected.is_empty());
}

#[test]
fn both_cancel_fill_orderings_replay_to_the_live_root() {
    for cancel_first in [true, false] {
        let mut seq = setup();
        let maker = rest(&mut seq);
        let taker = order(2, Side::Buy, SIZE_SCALE / 4, 2);
        if cancel_first {
            assert_eq!(
                seq.cancel_order(&maker.owner, &maker, true),
                Some(SIZE_SCALE)
            );
        }
        let batch = seq.seal_batch(&[taker], NOW + 1);
        let applied = batch
            .ops
            .iter()
            .filter(|op| matches!(op, BatchOp::Fill { .. }))
            .count();
        if cancel_first {
            assert_eq!(applied, 0);
        } else {
            assert_eq!(applied, 1);
            assert_eq!(
                seq.cancel_order(&maker.owner, &maker, true),
                Some(SIZE_SCALE * 3 / 4)
            );
        }
        assert_eq!(seq.book(0).unwrap().resting_size(Side::Sell), 0);
        assert_replay(&mut seq, maker.order_hash::<Keccak256>());
    }
}

#[test]
fn window_rollback_preserves_intervening_cancellation_and_its_manifest() {
    let mut seq = setup();
    let maker = rest(&mut seq);
    let failed = seq.seal_window();
    seq.seal_batch(&[order(2, Side::Buy, SIZE_SCALE / 4, 2)], NOW + 1);
    assert_eq!(
        seq.cancel_order(&maker.owner, &maker, true),
        Some(SIZE_SCALE * 3 / 4)
    );
    seq.rollback_window(&failed);
    assert_eq!(seq.book(0).unwrap().resting_size(Side::Sell), 0);
    assert_eq!(
        seq.window_rejected
            .iter()
            .filter(|(h, _)| *h == maker.order_hash::<Keccak256>())
            .count(),
        1
    );
    assert_replay(&mut seq, maker.order_hash::<Keccak256>());
}

#[test]
fn legacy_tick_rollback_cannot_restore_a_cancelled_maker() {
    let mut seq = setup();
    let maker = rest(&mut seq);
    let failed = seq.seal_batch(&[], NOW + 1);
    assert_eq!(
        seq.cancel_order(&maker.owner, &maker, true),
        Some(SIZE_SCALE)
    );
    assert!(seq.mark_failed(failed.batch_id));
    assert_eq!(seq.book(0).unwrap().resting_size(Side::Sell), 0);
    assert!(!seq
        .inclusion_violations(0)
        .contains(&maker.order_hash::<Keccak256>()));
}

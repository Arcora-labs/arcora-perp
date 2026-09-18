use perp_core::engine::BatchOp;
use perp_core::fixed::QUOTE_SCALE;
use perp_core::hash::{word_u64, Keccak256};
use perp_core::market::Market;
use perp_core::note::{owner_from_spend_key, Note};
use perp_core::position::Position;
use perp_core::state::Mode;
use perp_core::{DefaultState, EngineError};

fn flat_state(collateral: i128) -> (DefaultState, [u8; 32], [u8; 32]) {
    let spend = [7u8; 32];
    let owner = owner_from_spend_key::<Keccak256>(&spend);
    let mut s = DefaultState::new(16);
    s.add_market(Market::conservative(0));
    s.positions.insert(
        (owner, 0),
        Position {
            owner,
            market_id: 0,
            size: 2_000_000,
            entry_price: 100_000_000,
            collateral,
            funding_entry: 0,
        },
    );
    s.external_in = collateral;
    assert!(s.conservation_holds());
    (s, owner, spend)
}

#[test]
fn a06_stranded_healthy_position_closes_without_counterparty_or_oracle() {
    let (mut s, owner, spend) = flat_state(100 * QUOTE_SCALE);
    s.apply_batch(&[BatchOp::SettleAll]).unwrap();
    let p = s.position(&owner, 0).unwrap();
    assert_eq!(p.size, 0);
    assert_eq!(p.entry_price, 0);
    assert_eq!(p.collateral, 100 * QUOTE_SCALE);
    assert_eq!(s.mode, Mode::CloseOnly);

    let blind = [0xA6; 32];
    let note = Note::new(owner, 0, 100 * QUOTE_SCALE, blind);
    let cm = note.commitment::<Keccak256>();
    let out = s
        .apply_batch(&[
            BatchOp::WindDownUnbind {
                owner,
                market_id: 0,
                amount: 100 * QUOTE_SCALE,
                blinding: blind,
            },
            BatchOp::WindDownWithdraw {
                note_commitment: cm,
                spend_key: spend,
                to: Some([0x44; 20]),
                nonce: 9,
            },
        ])
        .unwrap();
    assert_eq!(out.withdrawals.len(), 1);
    assert_eq!(out.withdrawals[0].amount, 100 * QUOTE_SCALE);
    assert_eq!(s.position(&owner, 0).unwrap().collateral, 0);
    assert_eq!(s.external_out, 100 * QUOTE_SCALE);
    assert!(s.conservation_holds());
}

#[test]
fn a06_mixed_wind_down_batch_is_rejected_before_mutation() {
    let (mut s, owner, _) = flat_state(50 * QUOTE_SCALE);
    let before = s.state_root();
    let err = s
        .apply_batch(&[
            BatchOp::SettleAll,
            BatchOp::WindDownUnbind {
                owner,
                market_id: 0,
                amount: QUOTE_SCALE,
                blinding: [1; 32],
            },
        ])
        .unwrap_err();
    assert_eq!(err, EngineError::WindDownGrammar);
    assert_eq!(s.state_root(), before);
}

#[test]
fn a06_settle_all_reconciles_preexisting_pool_deficit_globally() {
    let spend = [8u8; 32];
    let owner = owner_from_spend_key::<Keccak256>(&spend);
    let mut s = DefaultState::new(16);
    s.add_market(Market::conservative(0));
    s.positions.insert(
        (owner, 0),
        Position {
            owner,
            market_id: 0,
            size: 1_000_000,
            entry_price: 100_000_000,
            collateral: 100 * QUOTE_SCALE,
            funding_entry: 0,
        },
    );
    let note = Note::new(owner, 0, 100 * QUOTE_SCALE, [3; 32]);
    let cm = note.commitment::<Keccak256>();
    s.tree.append(cm).unwrap();
    s.notes.insert(cm, note);
    s.vault_pool = -50 * QUOTE_SCALE;
    s.external_in = 150 * QUOTE_SCALE;
    assert!(s.conservation_holds());

    s.apply_batch(&[BatchOp::SettleAll]).unwrap();
    assert_eq!(s.vault_pool, 0);
    assert!(s
        .positions
        .values()
        .all(|p| p.size == 0 && p.collateral >= 0));
    assert!(s.notes.values().all(|n| n.amount >= 0));
    assert_eq!(s.internal_value(), 150 * QUOTE_SCALE);
    assert!(s.conservation_holds());
}

#[test]
fn a06_settle_all_is_atomic_when_note_reissue_cannot_fit_tree() {
    let owner = word_u64(1);
    let mut s = DefaultState::new(1); // capacity two
    s.add_market(Market::conservative(0));
    for i in 1..=2u8 {
        let n = Note::new(owner, 0, 100 * QUOTE_SCALE, [i; 32]);
        let cm = n.commitment::<Keccak256>();
        s.tree.append(cm).unwrap();
        s.notes.insert(cm, n);
    }
    s.vault_pool = -10 * QUOTE_SCALE;
    s.external_in = 190 * QUOTE_SCALE;
    assert!(s.conservation_holds());
    let before = s.state_root();
    assert_eq!(
        s.apply_batch(&[BatchOp::SettleAll]).unwrap_err(),
        EngineError::Overflow
    );
    assert_eq!(s.state_root(), before);
}

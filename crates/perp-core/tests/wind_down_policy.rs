//! Pins the existing R07 wind-down loss allocation; it does not select a new policy.

use perp_core::engine::BatchOp;
use perp_core::fixed::QUOTE_SCALE;
use perp_core::hash::{word_u64, Keccak256};
use perp_core::note::Note;
use perp_core::position::Position;
use perp_core::{DefaultState, Market};

#[test]
fn wind_down_uses_insurance_then_treasury_then_pro_rata_position_and_note() {
    // (pool deficit, insurance left, treasury left, position left, note left),
    // in half-quote units so the last case has an exact 37.5% global haircut.
    for (deficit, insurance, treasury, position, note_amount) in [
        (40, 20, 40, 200, 600),
        (80, 0, 20, 200, 600),
        (400, 0, 0, 125, 375),
    ] {
        let unit = QUOTE_SCALE / 2;
        let owner = word_u64(1);
        let note_owner = word_u64(2);
        let mut state = DefaultState::new(16);
        state.add_market(Market::conservative(0));
        state.positions.insert(
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
        let note = Note::new(note_owner, 0, 300 * QUOTE_SCALE, [3; 32]);
        let cm = note.commitment::<Keccak256>();
        state.tree.append(cm).unwrap();
        state.notes.insert(cm, note);
        state.insurance_fund = 30 * QUOTE_SCALE;
        state.treasury = 20 * QUOTE_SCALE;
        state.vault_pool = -deficit * unit;
        state.external_in = 450 * QUOTE_SCALE - deficit * unit;
        assert!(state.conservation_holds());

        state.apply_batch(&[BatchOp::SettleAll]).unwrap();

        assert_eq!(state.insurance_fund, insurance * unit);
        assert_eq!(state.treasury, treasury * unit);
        assert_eq!(state.vault_pool, 0);
        let position_after = state.position(&owner, 0).unwrap();
        assert_eq!(position_after.collateral, position * unit);
        assert_eq!(position_after.size, 0);
        assert_eq!(position_after.entry_price, 0);
        assert_eq!(state.notes.len(), 1);
        let note_after = state.notes.values().next().unwrap();
        assert_eq!(note_after.owner, note_owner);
        assert_eq!(note_after.amount, note_amount * unit);
        assert_eq!(state.internal_value(), state.external_in);
        assert!(state.conservation_holds());
    }
}

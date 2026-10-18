//! Pins the wind-down settlement policy of `SettleAll`:
//!
//! * open positions close at their market's last recorded oracle price, or at
//!   their own entry price when the market never recorded one;
//! * every negative balance left (a position's collateral, the clearing pool) is
//!   covered, in order, by the clearing pool's positive balance, the insurance
//!   fund, the treasury, and then one pro-rata haircut over all positive position
//!   collateral and unspent notes;
//! * whatever the three reserves hold afterwards is paid out as one withdrawal to
//!   the wind-down recipient, with the next withdrawal nonce. With no recipient
//!   set (tests and demos only) the reserves stay in place.

use perp_core::engine::{BatchOp, WithdrawalOut};
use perp_core::fixed::{PRICE_SCALE, QUOTE_SCALE, SIZE_SCALE};
use perp_core::hash::{word_u64, Keccak256};
use perp_core::note::{Note, PubKey};
use perp_core::position::Position;
use perp_core::state::Mode;
use perp_core::{DefaultState, Market};

const RECIPIENT: [u8; 20] = [0x5E; 20];

/// Half a quote unit, so the haircut cases below are exact.
const U: i128 = QUOTE_SCALE / 2;

fn holder() -> PubKey {
    word_u64(1)
}
fn note_owner() -> PubKey {
    word_u64(2)
}
fn debtor() -> PubKey {
    word_u64(3)
}

/// One open position of 200 U that closes at zero PnL (no recorded price, so it
/// closes at its own entry price), one note of 600 U, insurance 60 U, treasury
/// 40 U, the clearing pool at `pool` U and, when `parked > 0`, a flat entry
/// carrying `parked` U of debt. Conservation holds.
fn fixture(pool: i128, parked: i128, recipient: bool) -> DefaultState {
    let mut s = DefaultState::new(16);
    s.add_market(Market::conservative(0));
    if recipient {
        s.set_wind_down_recipient(RECIPIENT);
    }
    s.positions.insert(
        (holder(), 0),
        Position {
            owner: holder(),
            market_id: 0,
            size: SIZE_SCALE / 100,
            entry_price: 100_000 * PRICE_SCALE,
            collateral: 200 * U,
            funding_entry: 0,
        },
    );
    if parked > 0 {
        let mut p = Position::empty(debtor(), 0);
        p.collateral = -parked * U;
        s.positions.insert((debtor(), 0), p);
    }
    let note = Note::new(note_owner(), 0, 600 * U, [3; 32]);
    let cm = note.commitment::<Keccak256>();
    s.tree.append(cm).unwrap();
    s.notes.insert(cm, note);
    s.insurance_fund = 60 * U;
    s.treasury = 40 * U;
    s.vault_pool = pool * U;
    s.external_in = (900 + pool - parked) * U;
    assert!(s.conservation_holds());
    s
}

#[test]
fn deficits_draw_on_the_pool_then_insurance_then_treasury_then_a_pro_rata_haircut() {
    // (pool, parked debt, recipient set) =>
    // (pool, insurance, treasury, position, note, payout) after SettleAll, in U.
    let cases: [((i128, i128, bool), [i128; 6]); 12] = [
        // a pool deficit alone: insurance first, then the treasury
        ((-40, 0, false), [0, 20, 40, 200, 600, 0]),
        ((-80, 0, false), [0, 0, 20, 200, 600, 0]),
        // reserves exhausted: an exact 37.5% haircut of the 800 U of claims
        ((-400, 0, false), [0, 0, 0, 125, 375, 0]),
        // a positive pool covers parked debt before insurance is touched
        ((50, 30, false), [20, 60, 40, 200, 600, 0]),
        ((20, 50, false), [0, 30, 40, 200, 600, 0]),
        // pool, insurance and treasury all used up; 100 U taken from 800 U
        ((100, 300, false), [0, 0, 0, 175, 525, 0]),
        // with a recipient, the reserves left are paid out in full
        ((0, 0, true), [0, 0, 0, 200, 600, 100]),
        ((-40, 0, true), [0, 0, 0, 200, 600, 60]),
        ((-80, 0, true), [0, 0, 0, 200, 600, 20]),
        ((50, 30, true), [0, 0, 0, 200, 600, 120]),
        // nothing left to pay out: no withdrawal at all
        ((-400, 0, true), [0, 0, 0, 125, 375, 0]),
        ((100, 300, true), [0, 0, 0, 175, 525, 0]),
    ];
    for ((pool, parked, recipient), expected) in cases {
        let ctx = format!("pool {pool} parked {parked} recipient {recipient}");
        let mut s = fixture(pool, parked, recipient);
        let external_in = s.external_in;

        let out = s.apply_batch(&[BatchOp::SettleAll]).unwrap();

        let [pool_after, insurance, treasury, position, note_amount, payout] = expected;
        assert_eq!(s.vault_pool, pool_after * U, "{ctx}");
        assert_eq!(s.insurance_fund, insurance * U, "{ctx}");
        assert_eq!(s.treasury, treasury * U, "{ctx}");
        let p = s.position(&holder(), 0).unwrap();
        assert_eq!((p.size, p.entry_price), (0, 0), "{ctx}");
        assert_eq!(p.collateral, position * U, "{ctx}");
        assert!(
            s.position(&debtor(), 0).is_none(),
            "a covered debt leaves an empty entry, which is removed: {ctx}"
        );
        assert_eq!(s.notes.len(), 1, "{ctx}");
        let n = s.notes.values().next().unwrap();
        assert_eq!(
            (n.owner, n.amount),
            (note_owner(), note_amount * U),
            "{ctx}"
        );
        if payout > 0 {
            assert_eq!(
                out.withdrawals,
                [WithdrawalOut {
                    to: RECIPIENT,
                    amount: payout * U,
                    nonce: 1,
                }],
                "{ctx}"
            );
            assert_eq!(s.last_withdrawal_nonce, 1, "{ctx}");
        } else {
            assert!(out.withdrawals.is_empty(), "{ctx}");
            assert_eq!(s.last_withdrawal_nonce, 0, "{ctx}");
        }
        assert_eq!(s.external_out, payout * U, "{ctx}");
        assert_eq!(s.internal_value(), Some(external_in - payout * U), "{ctx}");
        assert_eq!(s.mode, Mode::CloseOnly, "{ctx}");
        assert!(s.conservation_holds(), "{ctx}");
    }
}

#[test]
fn open_positions_close_at_the_last_recorded_price_or_else_at_entry() {
    // A long and a short of 1 BTC, both from $100k with $20k each.
    let build = |last_price_usd: i128| {
        let mut s = DefaultState::new(16);
        s.add_market(Market::conservative(0));
        s.set_wind_down_recipient(RECIPIENT);
        for (owner, size) in [(holder(), SIZE_SCALE), (note_owner(), -SIZE_SCALE)] {
            s.positions.insert(
                (owner, 0),
                Position {
                    owner,
                    market_id: 0,
                    size,
                    entry_price: 100_000 * PRICE_SCALE,
                    collateral: 20_000 * QUOTE_SCALE,
                    funding_entry: 0,
                },
            );
        }
        if last_price_usd > 0 {
            let f = s.funding.get_mut(&0).unwrap();
            f.last_price = last_price_usd * PRICE_SCALE;
            f.last_price_ms = 1;
        }
        s.external_in = 40_000 * QUOTE_SCALE;
        assert!(s.conservation_holds());
        s
    };
    // (last recorded price, long's collateral after, short's collateral after)
    for (last, long_after, short_after) in [
        (0, 20_000, 20_000),       // never recorded: closes at entry, no PnL
        (110_000, 30_000, 10_000), // recorded: the long gains what the short loses
        (85_000, 5_000, 35_000),
    ] {
        let mut s = build(last);
        let out = s.apply_batch(&[BatchOp::SettleAll]).unwrap();
        assert!(out.withdrawals.is_empty(), "the pool nets to zero: {last}");
        assert_eq!(
            s.position(&holder(), 0).unwrap().collateral,
            long_after * QUOTE_SCALE,
            "{last}"
        );
        assert_eq!(
            s.position(&note_owner(), 0).unwrap().collateral,
            short_after * QUOTE_SCALE,
            "{last}"
        );
        assert_eq!(s.vault_pool, 0);
        assert!(s.positions.values().all(|p| p.size == 0));
        assert!(s.conservation_holds());
    }
}

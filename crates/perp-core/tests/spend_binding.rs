//! audit DP-003: a note may only be consumed by presenting the spend key whose
//! derived owner (`owner = H(spend_key)`) matches the note's owner. A spend key that
//! does not derive the owner must be rejected on every spend path (fund + withdraw).

use perp_core::engine::BatchOp;
use perp_core::hash::Keccak256;
use perp_core::note::owner_from_spend_key;
use perp_core::{Market, Note, State};

fn deposit(s: &mut State<Keccak256>, owner: [u8; 32], amount: i128, blind: [u8; 32]) -> [u8; 32] {
    s.apply_op(&BatchOp::Deposit {
        owner,
        asset_id: 0,
        amount,
        blinding: blind,
        from: [0u8; 20],
        deposit_id: 0,
    })
    .expect("deposit");
    Note::new(owner, 0, amount, blind).commitment::<Keccak256>()
}

#[test]
fn fund_position_rejects_a_spend_key_that_does_not_derive_the_owner() {
    let mut s: State<Keccak256> = State::new(16);
    s.add_market(Market::conservative(0));

    let good = [7u8; 32];
    let owner = owner_from_spend_key::<Keccak256>(&good);
    let cm = deposit(&mut s, owner, 1_000_000, [1u8; 32]);

    // a spend key that does NOT derive the note owner must be rejected
    let wrong = [8u8; 32];
    assert!(
        s.apply_op(&BatchOp::FundPosition {
            owner,
            market_id: 0,
            note_commitment: cm,
            spend_key: wrong,
        })
        .is_err(),
        "a spend key that does not derive the note owner must be rejected (DP-003)",
    );

    // the owner's real spend key spends the note
    assert!(
        s.apply_op(&BatchOp::FundPosition {
            owner,
            market_id: 0,
            note_commitment: cm,
            spend_key: good,
        })
        .is_ok(),
        "the owner's own spend key spends the note",
    );
}

#[test]
fn withdraw_rejects_a_spend_key_that_does_not_derive_the_owner() {
    let mut s: State<Keccak256> = State::new(16);

    let good = [9u8; 32];
    let owner = owner_from_spend_key::<Keccak256>(&good);
    let cm = deposit(&mut s, owner, 2_000_000, [3u8; 32]);

    // withdraw carries no expected owner, so the spend-key→owner binding is the ONLY
    // guard: an arbitrary key must not be able to burn someone else's note.
    let wrong = [10u8; 32];
    assert!(
        s.apply_op(&BatchOp::Withdraw {
            note_commitment: cm,
            spend_key: wrong,
            to: None,
            nonce: 0,
        })
        .is_err(),
        "withdraw with a non-deriving spend key must be rejected (DP-003)",
    );
    assert!(
        s.apply_op(&BatchOp::Withdraw {
            note_commitment: cm,
            spend_key: good,
            to: None,
            nonce: 0,
        })
        .is_ok(),
        "the owner's own spend key withdraws the note",
    );
}

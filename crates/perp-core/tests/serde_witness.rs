//! Witness serialization round-trips (the documented prerequisite for the real
//! zkVM guest, docs/PROVING.md). Run with `cargo test -p perp-core --features serde`.
//! Proves a full state + the batch ops encode and decode losslessly with a
//! no_std-friendly binary format (postcard), so the host can write the witness to
//! the prover and the guest can read it back identically.
#![cfg(feature = "serde")]

use perp_core::engine::BatchOp;
use perp_core::fixed::{PRICE_SCALE, QUOTE_SCALE, SIZE_SCALE};
use perp_core::hash::{word_u64, Keccak256};
use perp_core::market::Market;
use perp_core::note::owner_from_spend_key;
use perp_core::oracle::OracleTranscript;
use perp_core::order::Side;
use perp_core::{DefaultState, Note};

/// Owner id bound to spend key `[i as u8; 32]` (audit DP-003): each owner funds its
/// note with this key, so the note owner must derive from it.
fn owner(i: u64) -> [u8; 32] {
    owner_from_spend_key::<Keccak256>(&[i as u8; 32])
}

fn oracle(p: i128, now: u64) -> OracleTranscript {
    OracleTranscript {
        price: p * PRICE_SCALE,
        publish_time_ms: now,
        confidence: 10 * PRICE_SCALE,
        backup_twap: p * PRICE_SCALE,
    }
}

fn built_state() -> DefaultState {
    let mut s = DefaultState::new(20);
    s.add_market(Market::conservative(0));
    s.add_market(Market::conservative(1));
    for i in 1u64..=3 {
        let o = owner(i);
        let blind = [i as u8; 32];
        let amt = 50_000 * QUOTE_SCALE;
        let cm = Note::new(o, 0, amt, blind).commitment::<Keccak256>();
        s.apply_op(&BatchOp::Deposit {
            owner: o,
            asset_id: 0,
            amount: amt,
            blinding: blind,
            from: [i as u8; 20],
            deposit_id: i - 1,
            deposit_blind: [0xDBu8; 32],
        })
        .unwrap();
        s.apply_op(&BatchOp::FundPosition {
            owner: o,
            market_id: 0,
            note_commitment: cm,
            spend_key: [i as u8; 32],
        })
        .unwrap();
    }
    // open a couple of positions so the state has interesting structure
    s.apply_op(&BatchOp::Fill {
        taker: owner(1),
        maker: owner(2),
        market_id: 0,
        taker_side: Side::Buy,
        size: SIZE_SCALE / 2,
        price: 100_000 * PRICE_SCALE,
        oracle: oracle(100_000, 1_000),
        now_ms: 1_000,
    })
    .unwrap();
    s
}

#[test]
fn state_round_trips_losslessly() {
    let s = built_state();
    let bytes = postcard::to_allocvec(&s).expect("serialize state");
    let back: DefaultState = postcard::from_bytes(&bytes).expect("deserialize state");
    // the state root is the canonical fingerprint — equal ⇒ identical witness
    assert_eq!(
        s.state_root(),
        back.state_root(),
        "state root survives round-trip"
    );
    assert_eq!(s.conservation_holds(), back.conservation_holds());
    assert_eq!(
        s.position(&owner(1), 0).map(|p| p.size),
        back.position(&owner(1), 0).map(|p| p.size),
    );
}

#[test]
fn ops_round_trip_and_replay_identically() {
    // a witness's ops list must decode to the same ops that re-derive the same root
    let ops = vec![
        BatchOp::Deposit {
            owner: word_u64(9),
            asset_id: 0,
            amount: 1_000 * QUOTE_SCALE,
            blinding: [9; 32],
            from: [9u8; 20],
            // built_state() consumes 3 L1 deposits (ids 0..2); this is the next one.
            deposit_id: 3,
            deposit_blind: [0xDBu8; 32],
        },
        BatchOp::AccrueFunding {
            market_id: 0,
            mark: 100_050 * PRICE_SCALE,
            oracle: oracle(100_000, 2_000),
            now_ms: 2_000,
        },
        BatchOp::EnterCloseOnly,
    ];
    let bytes = postcard::to_allocvec(&ops).expect("serialize ops");
    let back: Vec<BatchOp> = postcard::from_bytes(&bytes).expect("deserialize ops");

    let mut a = built_state();
    let mut b = built_state();
    for op in &ops {
        let _ = a.apply_op(op);
    }
    for op in &back {
        let _ = b.apply_op(op);
    }
    assert_eq!(
        a.state_root(),
        b.state_root(),
        "decoded ops replay to the same root"
    );
}

#[test]
fn full_witness_round_trips_and_rederives_commitment() {
    use perp_core::commitment::derive_roots;
    use perp_core::order::BatchManifest;

    let mut s = built_state();
    let ops = vec![BatchOp::AccrueFunding {
        market_id: 0,
        mark: 100_050 * PRICE_SCALE,
        oracle: oracle(100_000, 2_000),
        now_ms: 2_000,
    }];
    let manifest = BatchManifest {
        previous_state_root: s.state_root(),
        batch_id: s.next_batch_id,
        ordered: vec![],
        rejected: vec![],
        oracle_updates: vec![],
        matching_rule_version: 0,
        enclave_measurement: [0u8; 32],
        sequencer_pubkey_epoch: 0,
    };
    let witness: (DefaultState, Vec<BatchOp>, BatchManifest) =
        (s.clone(), ops.clone(), manifest.clone());
    let bytes = postcard::to_allocvec(&witness).expect("serialize witness");
    let (mut s2, ops2, manifest2): (DefaultState, Vec<BatchOp>, BatchManifest) =
        postcard::from_bytes(&bytes).expect("deserialize witness");

    let a = derive_roots(&mut s, &ops, &manifest)
        .unwrap()
        .commitment::<Keccak256>();
    let b = derive_roots(&mut s2, &ops2, &manifest2)
        .unwrap()
        .commitment::<Keccak256>();
    assert_eq!(a, b, "decoded witness re-derives the identical commitment");
}

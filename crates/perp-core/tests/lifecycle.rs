//! End-to-end engine tests: a full position lifecycle and each of the six
//! Proof-v1 invariants (§4) exercised through `apply_batch`, with the collateral
//! conservation identity asserted at every step.

use perp_core::engine::BatchOp;
use perp_core::fixed::{PRICE_SCALE, QUOTE_SCALE, SIZE_SCALE};
use perp_core::hash::{word_u64, Keccak256};
use perp_core::oracle::OracleTranscript;
use perp_core::order::Side;
use perp_core::{DefaultState, EngineError, Market, Mode, Note};

const TREE_DEPTH: u8 = 20;

fn pk(n: u64) -> [u8; 32] {
    word_u64(n)
}

fn oracle(price_usd: i128, now: u64) -> OracleTranscript {
    OracleTranscript {
        price: price_usd * PRICE_SCALE,
        publish_time_ms: now,
        confidence: 10 * PRICE_SCALE, // $10, well inside 1%
        backup_twap: price_usd * PRICE_SCALE,
    }
}

/// Commitment of a deposited note, so we can later fund/withdraw with it.
fn deposit_commit(owner: [u8; 32], amount: i128, blinding: [u8; 32]) -> [u8; 32] {
    Note::new(owner, 0, amount, blinding).commitment::<Keccak256>()
}

fn fresh_state() -> DefaultState {
    let mut s = DefaultState::new(TREE_DEPTH);
    s.add_market(Market::conservative(0));
    s
}

#[test]
fn full_lifecycle_conserves_throughout() {
    let mut s = fresh_state();
    let (a, b) = (pk(1), pk(2));
    let (ba, bb) = ([0x11u8; 32], [0x22u8; 32]);

    // Two traders each deposit $20k and fund a position.
    let cm_a = deposit_commit(a, 20_000 * QUOTE_SCALE, ba);
    let cm_b = deposit_commit(b, 20_000 * QUOTE_SCALE, bb);
    s.apply_batch(&[
        BatchOp::Deposit {
            owner: a,
            asset_id: 0,
            amount: 20_000 * QUOTE_SCALE,
            blinding: ba,
        },
        BatchOp::Deposit {
            owner: b,
            asset_id: 0,
            amount: 20_000 * QUOTE_SCALE,
            blinding: bb,
        },
        BatchOp::FundPosition {
            owner: a,
            market_id: 0,
            note_commitment: cm_a,
            spend_key: [1; 32],
        },
        BatchOp::FundPosition {
            owner: b,
            market_id: 0,
            note_commitment: cm_b,
            spend_key: [2; 32],
        },
    ])
    .unwrap();
    assert!(s.conservation_holds());
    assert_eq!(s.external_in, 40_000 * QUOTE_SCALE);

    // A goes long 1 BTC, B short, at $100k. Both have 20k margin vs 10k initial.
    s.apply_batch(&[BatchOp::Fill {
        taker: a,
        maker: b,
        market_id: 0,
        taker_side: Side::Buy,
        size: SIZE_SCALE,
        price: 100_000 * PRICE_SCALE,
        oracle: oracle(100_000, 1_000),
        now_ms: 1_000,
    }])
    .unwrap();
    assert!(s.conservation_holds());
    assert_eq!(s.position(&a, 0).unwrap().size, SIZE_SCALE);
    assert_eq!(s.position(&b, 0).unwrap().size, -SIZE_SCALE);

    // Price rises to $108k; A closes for +$8k, B realizes -$8k. Conservation holds
    // because realized PnL routes through the vault pool.
    s.apply_batch(&[BatchOp::Fill {
        taker: a,
        maker: b,
        market_id: 0,
        taker_side: Side::Sell,
        size: SIZE_SCALE,
        price: 108_000 * PRICE_SCALE,
        oracle: oracle(108_000, 2_000),
        now_ms: 2_000,
    }])
    .unwrap();
    assert!(s.conservation_holds());
    assert_eq!(s.position(&a, 0).unwrap().size, 0);
    assert_eq!(s.position(&a, 0).unwrap().collateral, 28_000 * QUOTE_SCALE);
    assert_eq!(s.position(&b, 0).unwrap().collateral, 12_000 * QUOTE_SCALE);

    // A unbinds $28k to a note and withdraws it.
    let bw = [0x33u8; 32];
    let cm_w = deposit_commit(a, 28_000 * QUOTE_SCALE, bw);
    s.apply_batch(&[
        BatchOp::Unbind {
            owner: a,
            market_id: 0,
            amount: 28_000 * QUOTE_SCALE,
            blinding: bw,
            oracle: oracle(108_000, 3_000),
            now_ms: 3_000,
        },
        BatchOp::Withdraw {
            note_commitment: cm_w,
            spend_key: [1; 32],
        },
    ])
    .unwrap();
    assert!(s.conservation_holds());
    assert_eq!(s.external_out, 28_000 * QUOTE_SCALE);
}

#[test]
fn invariant_collateral_conservation_under_random_ops() {
    // Deterministic pseudo-sequence (no RNG: determinism is the point).
    let mut s = fresh_state();
    let owners = [pk(10), pk(11), pk(12)];
    for (i, o) in owners.iter().enumerate() {
        let b = [(0x40 + i as u8); 32];
        let cm = deposit_commit(*o, 50_000 * QUOTE_SCALE, b);
        s.apply_batch(&[
            BatchOp::Deposit {
                owner: *o,
                asset_id: 0,
                amount: 50_000 * QUOTE_SCALE,
                blinding: b,
            },
            BatchOp::FundPosition {
                owner: *o,
                market_id: 0,
                note_commitment: cm,
                spend_key: [i as u8; 32],
            },
        ])
        .unwrap();
    }
    // a sequence of matched fills + funding accrual at varying prices
    let prices = [100_000i128, 101_000, 99_500, 103_000, 97_000];
    for (k, p) in prices.iter().enumerate() {
        let now = 1_000 + k as u64 * 1_000;
        s.apply_batch(&[
            BatchOp::Fill {
                taker: owners[0],
                maker: owners[1],
                market_id: 0,
                taker_side: if k % 2 == 0 { Side::Buy } else { Side::Sell },
                size: SIZE_SCALE / 4,
                price: p * PRICE_SCALE,
                oracle: oracle(*p, now),
                now_ms: now,
            },
            BatchOp::AccrueFunding {
                market_id: 0,
                mark: (p + 50) * PRICE_SCALE,
                oracle: oracle(*p, now),
                now_ms: now,
            },
        ])
        .unwrap();
        assert!(s.conservation_holds(), "conservation broke at step {k}");
    }
}

#[test]
fn invariant_no_double_spend() {
    let mut s = fresh_state();
    let o = pk(5);
    let b = [0x55u8; 32];
    let cm = deposit_commit(o, 10_000 * QUOTE_SCALE, b);
    s.apply_op(&BatchOp::Deposit {
        owner: o,
        asset_id: 0,
        amount: 10_000 * QUOTE_SCALE,
        blinding: b,
    })
    .unwrap();
    // first fund consumes the note
    s.apply_op(&BatchOp::FundPosition {
        owner: o,
        market_id: 0,
        note_commitment: cm,
        spend_key: [5; 32],
    })
    .unwrap();
    // second attempt to spend the same note must fail
    let err = s
        .apply_op(&BatchOp::FundPosition {
            owner: o,
            market_id: 0,
            note_commitment: cm,
            spend_key: [5; 32],
        })
        .unwrap_err();
    assert_eq!(err, EngineError::UnknownOrSpentNote);
    assert!(s.conservation_holds());
}

#[test]
fn invariant_post_fill_margin_sufficiency() {
    let mut s = fresh_state();
    let (a, b) = (pk(7), pk(8));
    // A funds only $5k; a 1 BTC position at $100k needs $10k initial → reject.
    for (o, sk) in [(a, 7u8), (b, 8u8)] {
        let bl = [sk; 32];
        let cm = deposit_commit(o, 5_000 * QUOTE_SCALE, bl);
        s.apply_batch(&[
            BatchOp::Deposit {
                owner: o,
                asset_id: 0,
                amount: 5_000 * QUOTE_SCALE,
                blinding: bl,
            },
            BatchOp::FundPosition {
                owner: o,
                market_id: 0,
                note_commitment: cm,
                spend_key: [sk; 32],
            },
        ])
        .unwrap();
    }
    let err = s
        .apply_op(&BatchOp::Fill {
            taker: a,
            maker: b,
            market_id: 0,
            taker_side: Side::Buy,
            size: SIZE_SCALE,
            price: 100_000 * PRICE_SCALE,
            oracle: oracle(100_000, 1_000),
            now_ms: 1_000,
        })
        .unwrap_err();
    assert_eq!(
        err,
        EngineError::Risk(perp_core::RiskError::InsufficientMargin)
    );
    // atomic: the rejected fill left NO position open
    assert!(s.position(&a, 0).is_none_or(|p| p.size == 0));
    assert!(s.conservation_holds());
}

#[test]
fn invariant_oracle_freshness_enforced() {
    let mut s = fresh_state();
    let (a, b) = (pk(7), pk(8));
    for (o, sk) in [(a, 7u8), (b, 8u8)] {
        let bl = [sk; 32];
        let cm = deposit_commit(o, 20_000 * QUOTE_SCALE, bl);
        s.apply_batch(&[
            BatchOp::Deposit {
                owner: o,
                asset_id: 0,
                amount: 20_000 * QUOTE_SCALE,
                blinding: bl,
            },
            BatchOp::FundPosition {
                owner: o,
                market_id: 0,
                note_commitment: cm,
                spend_key: [sk; 32],
            },
        ])
        .unwrap();
    }
    // oracle published 30s before now (max staleness 10s) → rejected
    let stale = OracleTranscript {
        price: 100_000 * PRICE_SCALE,
        publish_time_ms: 1_000,
        confidence: 10 * PRICE_SCALE,
        backup_twap: 100_000 * PRICE_SCALE,
    };
    let err = s
        .apply_op(&BatchOp::Fill {
            taker: a,
            maker: b,
            market_id: 0,
            taker_side: Side::Buy,
            size: SIZE_SCALE,
            price: 100_000 * PRICE_SCALE,
            oracle: stale,
            now_ms: 31_000,
        })
        .unwrap_err();
    assert_eq!(err, EngineError::Oracle(perp_core::OracleError::Stale));
}

#[test]
fn invariant_liquidation_threshold() {
    let mut s = fresh_state();
    let (a, b) = (pk(1), pk(2));
    // A long 1 BTC with only $6k margin (maintenance 5% = $5k).
    for (o, sk, amt) in [(a, 1u8, 6_000i128), (b, 2u8, 20_000)] {
        let bl = [sk; 32];
        let cm = deposit_commit(o, amt * QUOTE_SCALE, bl);
        s.apply_batch(&[
            BatchOp::Deposit {
                owner: o,
                asset_id: 0,
                amount: amt * QUOTE_SCALE,
                blinding: bl,
            },
            BatchOp::FundPosition {
                owner: o,
                market_id: 0,
                note_commitment: cm,
                spend_key: [sk; 32],
            },
        ])
        .unwrap();
    }
    // open at $100k: A initial margin needs $10k but only has $6k... so reduce
    // leverage: open 0.5 BTC ($50k notional, $5k initial) — A's $6k qualifies.
    s.apply_op(&BatchOp::Fill {
        taker: a,
        maker: b,
        market_id: 0,
        taker_side: Side::Buy,
        size: SIZE_SCALE / 2,
        price: 100_000 * PRICE_SCALE,
        oracle: oracle(100_000, 1_000),
        now_ms: 1_000,
    })
    .unwrap();

    // healthy at $100k → liquidation rejected
    let err = s
        .apply_op(&BatchOp::Liquidate {
            owner: a,
            market_id: 0,
            oracle: oracle(100_000, 1_100),
            now_ms: 1_100,
        })
        .unwrap_err();
    assert_eq!(err, EngineError::NotLiquidatable);

    // price drops to $98k: 0.5 BTC long loses $1k → equity ~$5k, notional $49k,
    // maintenance $2.45k → still healthy. Drop further to $90k: loss $5k →
    // equity ~$1k < maintenance $2.25k → liquidatable.
    s.apply_op(&BatchOp::Liquidate {
        owner: a,
        market_id: 0,
        oracle: oracle(90_000, 2_000),
        now_ms: 2_000,
    })
    .unwrap();
    assert_eq!(
        s.position(&a, 0).unwrap().size,
        0,
        "position closed by liquidation"
    );
    assert!(
        s.insurance_fund > 0,
        "liquidation fee funded the insurance pool"
    );
    assert!(s.conservation_holds());
}

#[test]
fn duplicate_commitment_deposit_rejected() {
    // two deposits with identical (owner, asset, amount, blinding) collide on the
    // commitment; the second must be rejected, not silently alias and lose value
    // (found by the conservation fuzzer).
    let mut s = fresh_state();
    let o = pk(1);
    let bl = [9u8; 32];
    let amt = 1_000 * QUOTE_SCALE;
    s.apply_op(&BatchOp::Deposit {
        owner: o,
        asset_id: 0,
        amount: amt,
        blinding: bl,
    })
    .unwrap();
    let err = s
        .apply_op(&BatchOp::Deposit {
            owner: o,
            asset_id: 0,
            amount: amt,
            blinding: bl,
        })
        .unwrap_err();
    assert_eq!(err, EngineError::DuplicateCommitment);
    assert!(s.conservation_holds());
    // a different blinding is fine
    s.apply_op(&BatchOp::Deposit {
        owner: o,
        asset_id: 0,
        amount: amt,
        blinding: [10u8; 32],
    })
    .unwrap();
    assert!(s.conservation_holds());
}

#[test]
fn self_trade_is_rejected_at_settlement() {
    // defensive: a fill whose taker == maker must be rejected (it would otherwise
    // drop a leg and break conservation). The matcher prevents this upstream.
    let mut s = fresh_state();
    let a = pk(1);
    let bl = [1u8; 32];
    let cm = deposit_commit(a, 20_000 * QUOTE_SCALE, bl);
    s.apply_batch(&[
        BatchOp::Deposit {
            owner: a,
            asset_id: 0,
            amount: 20_000 * QUOTE_SCALE,
            blinding: bl,
        },
        BatchOp::FundPosition {
            owner: a,
            market_id: 0,
            note_commitment: cm,
            spend_key: [1; 32],
        },
    ])
    .unwrap();
    let err = s
        .apply_op(&BatchOp::Fill {
            taker: a,
            maker: a,
            market_id: 0,
            taker_side: Side::Buy,
            size: SIZE_SCALE,
            price: 100_000 * PRICE_SCALE,
            oracle: oracle(100_000, 1_000),
            now_ms: 1_000,
        })
        .unwrap_err();
    assert_eq!(err, EngineError::SelfTrade);
    assert!(s.conservation_holds());
}

#[test]
fn forced_exit_close_only_blocks_increase() {
    let mut s = fresh_state();
    let (a, b) = (pk(1), pk(2));
    for (o, sk) in [(a, 1u8), (b, 2u8)] {
        let bl = [sk; 32];
        let cm = deposit_commit(o, 20_000 * QUOTE_SCALE, bl);
        s.apply_batch(&[
            BatchOp::Deposit {
                owner: o,
                asset_id: 0,
                amount: 20_000 * QUOTE_SCALE,
                blinding: bl,
            },
            BatchOp::FundPosition {
                owner: o,
                market_id: 0,
                note_commitment: cm,
                spend_key: [sk; 32],
            },
        ])
        .unwrap();
    }
    // open a position, then enter close-only
    s.apply_op(&BatchOp::Fill {
        taker: a,
        maker: b,
        market_id: 0,
        taker_side: Side::Buy,
        size: SIZE_SCALE / 4,
        price: 100_000 * PRICE_SCALE,
        oracle: oracle(100_000, 1_000),
        now_ms: 1_000,
    })
    .unwrap();
    s.apply_op(&BatchOp::EnterCloseOnly).unwrap();
    assert_eq!(s.mode, Mode::CloseOnly);

    // increasing exposure is now blocked
    let err = s
        .apply_op(&BatchOp::Fill {
            taker: a,
            maker: b,
            market_id: 0,
            taker_side: Side::Buy,
            size: SIZE_SCALE / 4,
            price: 100_000 * PRICE_SCALE,
            oracle: oracle(100_000, 1_100),
            now_ms: 1_100,
        })
        .unwrap_err();
    assert_eq!(err, EngineError::CloseOnly);

    // but reducing (closing) is still allowed
    s.apply_op(&BatchOp::Fill {
        taker: a,
        maker: b,
        market_id: 0,
        taker_side: Side::Sell,
        size: SIZE_SCALE / 4,
        price: 100_000 * PRICE_SCALE,
        oracle: oracle(100_000, 1_200),
        now_ms: 1_200,
    })
    .unwrap();
    assert_eq!(s.position(&a, 0).unwrap().size, 0);
    assert!(s.conservation_holds());
}

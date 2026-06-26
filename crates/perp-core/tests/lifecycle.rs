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
fn bad_debt_is_clawed_from_the_winners_via_adl() {
    // A gap-down past A's maintenance buffer leaves A underwater by MORE than its
    // collateral (bad debt). With no insurance seeded, the auto-deleverage cascade
    // funds the shortfall from the WINNER (B, the profitable short) rather than
    // parking it or silently socializing it onto the clearing pool. Conservation
    // holds and the loser walks away flat (covered), not with a stranded debt.
    let mut s = bad_debt_setup(0);
    let (a, b) = (pk(1), pk(2));
    let b_before = s.position(&b, 0).unwrap().collateral;

    s.apply_op(&BatchOp::Liquidate {
        owner: a,
        market_id: 0,
        oracle: oracle(80_000, 2_000),
        now_ms: 2_000,
    })
    .unwrap();

    let a_pos = s.position(&a, 0).unwrap();
    assert_eq!(a_pos.size, 0, "the bad-debt position is closed");
    assert_eq!(
        a_pos.collateral, 0,
        "ADL covers the bad debt from the winner — nothing parked"
    );
    let b_after = s.position(&b, 0).unwrap().collateral;
    assert!(
        b_after < b_before,
        "the winning short funded the loser's shortfall"
    );
    assert_eq!(
        s.mode,
        Mode::Normal,
        "a fully-covered loss keeps the system open"
    );
    assert_eq!(s.insurance_fund, 0, "no insurance was used (none seeded)");
    assert!(s.conservation_holds(), "ADL is conservation-neutral");
}

/// Canonical bad-debt setup: A funds $6k and opens 0.5 BTC long at $100k; the
/// caller then liquidates after a gap-down. `seed_usd > 0` capitalizes insurance.
fn bad_debt_setup(seed_usd: i128) -> DefaultState {
    let mut s = fresh_state();
    let (a, b) = (pk(1), pk(2));
    for (o, sk, amt) in [(a, 1u8, 6_000i128), (b, 2u8, 50_000)] {
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
    if seed_usd > 0 {
        s.apply_op(&BatchOp::SeedInsurance {
            amount: seed_usd * QUOTE_SCALE,
        })
        .unwrap();
    }
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
    s
}

#[test]
fn insurance_backstop_absorbs_bad_debt() {
    // Seed the fund above the shortfall: the ~$4k gap-down bad debt is fully drawn
    // from insurance, the position closes flat (no parked debt), and the system
    // stays open — the audit's "insurance is a one-way sink" is closed.
    let mut s = bad_debt_setup(10_000);
    let before = s.insurance_fund;
    s.apply_op(&BatchOp::Liquidate {
        owner: pk(1),
        market_id: 0,
        oracle: oracle(80_000, 2_000),
        now_ms: 2_000,
    })
    .unwrap();
    assert_eq!(
        s.position(&pk(1), 0).unwrap().collateral,
        0,
        "bad debt fully covered by insurance"
    );
    assert!(
        s.insurance_fund < before && s.insurance_fund > 0,
        "fund drawn down, not exhausted"
    );
    assert_eq!(
        s.mode,
        Mode::Normal,
        "a covered loss does not trip the halt"
    );
    assert!(s.conservation_holds());
}

#[test]
fn adl_covers_residual_after_insurance() {
    // A small seed plus the auto-deleverage cascade together absorb the bad debt:
    // insurance pays what it can, the winner (B) funds the rest, the loser walks
    // away flat, and the system stays open.
    let mut s = bad_debt_setup(1_000);
    let b_before = s.position(&pk(2), 0).unwrap().collateral;
    s.apply_op(&BatchOp::Liquidate {
        owner: pk(1),
        market_id: 0,
        oracle: oracle(80_000, 2_000),
        now_ms: 2_000,
    })
    .unwrap();
    assert_eq!(
        s.position(&pk(1), 0).unwrap().collateral,
        0,
        "insurance + ADL cover the bad debt"
    );
    assert_eq!(s.insurance_fund, 0, "the small fund is fully drawn first");
    assert!(
        s.position(&pk(2), 0).unwrap().collateral < b_before,
        "the winner funded the residual"
    );
    assert_eq!(s.mode, Mode::Normal, "fully covered → no halt");
    assert!(s.conservation_holds());
}

#[test]
fn true_insolvency_trips_close_only_when_winners_have_exited() {
    // The one case ADL cannot cover: the winning side already cashed out before the
    // loser blows up. B closes its profitable short against a fresh, flat maker (C)
    // and exits; A is then liquidated into bad debt with no open winner to claw and
    // no insurance — so the residual is parked (conservation-safe) and the system
    // trips to close-only (the final depletion halt).
    let mut s = fresh_state();
    let (a, b, c) = (pk(1), pk(2), pk(3));
    for (o, sk, amt) in [(a, 1u8, 6_000i128), (b, 2u8, 50_000), (c, 3u8, 10_000)] {
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
    // A longs 0.5 BTC at $100k, with B as the (short) maker.
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
    // Price drops to $80k; B closes its winning short against a fresh maker C (who
    // enters flat at $80k) and is out of the market.
    s.apply_op(&BatchOp::Fill {
        taker: b,
        maker: c,
        market_id: 0,
        taker_side: Side::Buy,
        size: SIZE_SCALE / 2,
        price: 80_000 * PRICE_SCALE,
        oracle: oracle(80_000, 1_500),
        now_ms: 1_500,
    })
    .unwrap();
    assert_eq!(
        s.position(&b, 0).unwrap().size,
        0,
        "B has exited the market"
    );

    s.apply_op(&BatchOp::Liquidate {
        owner: a,
        market_id: 0,
        oracle: oracle(80_000, 2_000),
        now_ms: 2_000,
    })
    .unwrap();
    assert!(
        s.position(&a, 0).unwrap().collateral < 0,
        "no winner to claw and no insurance → the shortfall is parked"
    );
    assert_eq!(
        s.mode,
        Mode::CloseOnly,
        "true insolvency trips the depletion halt"
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

//! End-to-end engine tests: a full position lifecycle and each of the six
//! Proof-v1 invariants (§4) exercised through `apply_batch`, with the collateral
//! conservation identity asserted at every step.

use k256::ecdsa::SigningKey;
use perp_core::engine::{AdlHaircut, BatchOp};
use perp_core::fixed::{PRICE_SCALE, QUOTE_SCALE, SIZE_SCALE};
use perp_core::hash::{word_u64, Keccak256};
use perp_core::note::owner_from_spend_key;
use perp_core::oracle::{oracle_digest, OracleSig, OracleTranscript};
use perp_core::order::Side;
use perp_core::{DefaultState, EngineError, FillLeg, Market, Mode, Note};

const TREE_DEPTH: u8 = 20;

fn pk(n: u64) -> [u8; 32] {
    word_u64(n)
}

/// Owner id bound to spend key `[sk; 32]` (audit DP-003): the engine now requires a
/// note's owner to equal `owner_from_spend_key(spend_key)`, so every fixture derives
/// its owner from the `[sk; 32]` it later funds/withdraws that owner's note with.
fn owner_of(sk: u8) -> [u8; 32] {
    owner_from_spend_key::<Keccak256>(&[sk; 32])
}

/// ZK-001: the fixed publisher key the fixtures sign oracle transcripts with. Every
/// market these tests build sets its `oracle_pubkey` to this key's address (see
/// [`signed_market`]), so transcripts run through the REAL fail-closed signature gate.
fn oracle_key() -> SigningKey {
    SigningKey::from_bytes((&[7u8; 32]).into()).unwrap()
}

/// The publisher's eth address, recovered via the public API (the raw `eth_address`
/// helper is private to `perp_core::oracle`).
fn oracle_addr() -> [u8; 20] {
    let d = oracle_digest(0, 1, 1, 0, 1);
    OracleSig::sign(&oracle_key(), &d).recover(&d).unwrap()
}

/// A market with its `oracle_pubkey` set to the fixture publisher, so signed
/// transcripts validate.
fn signed_market(m: Market) -> Market {
    let mut m = m;
    m.oracle_pubkey = oracle_addr();
    m
}

/// A transcript signed by the fixture publisher over `oracle_digest(market_id, ..)`.
fn signed_oracle(
    market_id: u64,
    price: i128,
    publish_time_ms: u64,
    confidence: i128,
    backup_twap: i128,
) -> OracleTranscript {
    let d = oracle_digest(market_id, price, publish_time_ms, confidence, backup_twap);
    OracleTranscript {
        price,
        publish_time_ms,
        confidence,
        backup_twap,
        signature: OracleSig::sign(&oracle_key(), &d),
    }
}

fn oracle(price_usd: i128, now: u64) -> OracleTranscript {
    signed_oracle(
        0,
        price_usd * PRICE_SCALE,
        now,
        10 * PRICE_SCALE, // $10, well inside 1%
        price_usd * PRICE_SCALE,
    )
}

/// Commitment of a deposited note, so we can later fund/withdraw with it.
fn deposit_commit(owner: [u8; 32], amount: i128, blinding: [u8; 32]) -> [u8; 32] {
    Note::new(owner, 0, amount, blinding).commitment::<Keccak256>()
}

fn fresh_state() -> DefaultState {
    let mut s = DefaultState::new(TREE_DEPTH);
    s.add_market(signed_market(Market::conservative(0)));
    s
}

#[test]
fn full_lifecycle_conserves_throughout() {
    let mut s = fresh_state();
    let (a, b) = (owner_of(1), owner_of(2));
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
            from: [0xA1u8; 20],
            deposit_id: 0,
            deposit_blind: [0xDBu8; 32],
        },
        BatchOp::Deposit {
            owner: b,
            asset_id: 0,
            amount: 20_000 * QUOTE_SCALE,
            blinding: bb,
            from: [0xB2u8; 20],
            deposit_id: 1,
            deposit_blind: [0xDBu8; 32],
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
            to: Some([0xCC; 20]),
            nonce: 0,
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
    // each owner is funded with spend key `[i; 32]` below, so its owner derives from it
    let owners = [owner_of(0), owner_of(1), owner_of(2)];
    for (i, o) in owners.iter().enumerate() {
        let b = [(0x40 + i as u8); 32];
        let cm = deposit_commit(*o, 50_000 * QUOTE_SCALE, b);
        s.apply_batch(&[
            BatchOp::Deposit {
                owner: *o,
                asset_id: 0,
                amount: 50_000 * QUOTE_SCALE,
                blinding: b,
                from: [i as u8; 20],
                deposit_id: i as u64,
                deposit_blind: [0xDBu8; 32],
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
    let o = owner_of(5);
    let b = [0x55u8; 32];
    let cm = deposit_commit(o, 10_000 * QUOTE_SCALE, b);
    s.apply_op(&BatchOp::Deposit {
        owner: o,
        asset_id: 0,
        amount: 10_000 * QUOTE_SCALE,
        blinding: b,
        from: [0u8; 20],
        deposit_id: 0,
        deposit_blind: [0xDBu8; 32],
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
    let (a, b) = (owner_of(7), owner_of(8));
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
                from: [sk; 20],
                deposit_id: s.consumed_deposit_count,
                deposit_blind: [0xDBu8; 32],
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
    // SEC-024 (SEC-022 carry-in): a fill margin failure names the staged leg that
    // violated — the taker here, checked first with only half the required initial.
    assert_eq!(
        err,
        EngineError::Risk {
            source: perp_core::RiskError::InsufficientMargin,
            leg: Some(FillLeg::Taker),
        }
    );
    // atomic: the rejected fill left NO position open
    assert!(s.position(&a, 0).is_none_or(|p| p.size == 0));
    assert!(s.conservation_holds());
}

#[test]
fn invariant_oracle_freshness_enforced() {
    let mut s = fresh_state();
    let (a, b) = (owner_of(7), owner_of(8));
    for (o, sk) in [(a, 7u8), (b, 8u8)] {
        let bl = [sk; 32];
        let cm = deposit_commit(o, 20_000 * QUOTE_SCALE, bl);
        s.apply_batch(&[
            BatchOp::Deposit {
                owner: o,
                asset_id: 0,
                amount: 20_000 * QUOTE_SCALE,
                blinding: bl,
                from: [sk; 20],
                deposit_id: s.consumed_deposit_count,
                deposit_blind: [0xDBu8; 32],
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
    // oracle published 30s before now (max staleness 10s) → rejected. Properly signed
    // so it clears the (first) signature gate and is refused specifically for staleness.
    let stale = signed_oracle(
        0,
        100_000 * PRICE_SCALE,
        1_000,
        10 * PRICE_SCALE,
        100_000 * PRICE_SCALE,
    );
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
    let (a, b) = (owner_of(1), owner_of(2));
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
                from: [sk; 20],
                deposit_id: s.consumed_deposit_count,
                deposit_blind: [0xDBu8; 32],
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
    let (a, b) = (owner_of(1), owner_of(2));
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
    let (a, b) = (owner_of(1), owner_of(2));
    for (o, sk, amt) in [(a, 1u8, 6_000i128), (b, 2u8, 50_000)] {
        let bl = [sk; 32];
        let cm = deposit_commit(o, amt * QUOTE_SCALE, bl);
        s.apply_batch(&[
            BatchOp::Deposit {
                owner: o,
                asset_id: 0,
                amount: amt * QUOTE_SCALE,
                blinding: bl,
                from: [sk; 20],
                deposit_id: s.consumed_deposit_count,
                deposit_blind: [0xDBu8; 32],
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
        // SEC-024: insurance is capitalized by TRANSFER — deposit a real note
        // (owner 0x0F, distinct from A/B), then move it into the fund. The old
        // `SeedInsurance` mint is a rejected stub now.
        let sk = [0x0Fu8; 32];
        let o = owner_of(0x0F);
        let amt = seed_usd * QUOTE_SCALE;
        let cm = deposit_commit(o, amt, sk);
        s.apply_batch(&[
            BatchOp::Deposit {
                owner: o,
                asset_id: 0,
                amount: amt,
                blinding: sk,
                from: [0x0Fu8; 20],
                deposit_id: s.consumed_deposit_count,
                deposit_blind: [0xDBu8; 32],
            },
            BatchOp::FundInsurance {
                note_commitment: cm,
                spend_key: sk,
            },
        ])
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
        owner: owner_of(1),
        market_id: 0,
        oracle: oracle(80_000, 2_000),
        now_ms: 2_000,
    })
    .unwrap();
    assert_eq!(
        s.position(&owner_of(1), 0).unwrap().collateral,
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
    let b_before = s.position(&owner_of(2), 0).unwrap().collateral;
    s.apply_op(&BatchOp::Liquidate {
        owner: owner_of(1),
        market_id: 0,
        oracle: oracle(80_000, 2_000),
        now_ms: 2_000,
    })
    .unwrap();
    assert_eq!(
        s.position(&owner_of(1), 0).unwrap().collateral,
        0,
        "insurance + ADL cover the bad debt"
    );
    assert_eq!(s.insurance_fund, 0, "the small fund is fully drawn first");
    assert!(
        s.position(&owner_of(2), 0).unwrap().collateral < b_before,
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
    let (a, b, c) = (owner_of(1), owner_of(2), owner_of(3));
    for (o, sk, amt) in [(a, 1u8, 6_000i128), (b, 2u8, 50_000), (c, 3u8, 10_000)] {
        let bl = [sk; 32];
        let cm = deposit_commit(o, amt * QUOTE_SCALE, bl);
        s.apply_batch(&[
            BatchOp::Deposit {
                owner: o,
                asset_id: 0,
                amount: amt * QUOTE_SCALE,
                blinding: bl,
                from: [sk; 20],
                deposit_id: s.consumed_deposit_count,
                deposit_blind: [0xDBu8; 32],
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
fn adl_distributes_pro_rata_across_multiple_winners() {
    // A's bad debt is clawed from TWO winners — B (short 0.3) and C (short 0.2) —
    // pro-rata to their profit: the bigger winner pays more, the takes exactly
    // cover the loss (exercising the floor-pro-rata + remainder distribution), and
    // neither winner is pushed underwater.
    let mut s = fresh_state();
    let (a, b, c) = (owner_of(1), owner_of(2), owner_of(3));
    for (o, sk, amt) in [(a, 1u8, 6_000i128), (b, 2u8, 50_000), (c, 3u8, 50_000)] {
        let bl = [sk; 32];
        let cm = deposit_commit(o, amt * QUOTE_SCALE, bl);
        s.apply_batch(&[
            BatchOp::Deposit {
                owner: o,
                asset_id: 0,
                amount: amt * QUOTE_SCALE,
                blinding: bl,
                from: [sk; 20],
                deposit_id: s.consumed_deposit_count,
                deposit_blind: [0xDBu8; 32],
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
    // A longs 0.3 from B and 0.2 from C at $100k (A long 0.5 total).
    s.apply_op(&BatchOp::Fill {
        taker: a,
        maker: b,
        market_id: 0,
        taker_side: Side::Buy,
        size: 3 * SIZE_SCALE / 10,
        price: 100_000 * PRICE_SCALE,
        oracle: oracle(100_000, 1_000),
        now_ms: 1_000,
    })
    .unwrap();
    s.apply_op(&BatchOp::Fill {
        taker: a,
        maker: c,
        market_id: 0,
        taker_side: Side::Buy,
        size: 2 * SIZE_SCALE / 10,
        price: 100_000 * PRICE_SCALE,
        oracle: oracle(100_000, 1_100),
        now_ms: 1_100,
    })
    .unwrap();
    let b0 = s.position(&b, 0).unwrap().collateral;
    let c0 = s.position(&c, 0).unwrap().collateral;

    // gap to $80k → A bad debt; no insurance → ADL claws across B and C.
    s.apply_op(&BatchOp::Liquidate {
        owner: a,
        market_id: 0,
        oracle: oracle(80_000, 2_000),
        now_ms: 2_000,
    })
    .unwrap();

    let b_take = b0 - s.position(&b, 0).unwrap().collateral;
    let c_take = c0 - s.position(&c, 0).unwrap().collateral;
    assert_eq!(
        s.position(&a, 0).unwrap().collateral,
        0,
        "ADL fully covered the loss across both winners"
    );
    assert!(b_take > 0 && c_take > 0, "both winners contributed");
    assert!(
        b_take > c_take,
        "the larger winner (B) pays more, pro-rata to profit"
    );
    assert!(
        s.position(&b, 0).unwrap().collateral >= 0 && s.position(&c, 0).unwrap().collateral >= 0,
        "ADL never pushes a winner underwater"
    );
    assert_eq!(s.mode, Mode::Normal);
    assert!(s.conservation_holds());
}

#[test]
fn trading_fees_pay_the_maker_and_fund_insurance() {
    // A market with a 10 bps taker fee / 4 bps maker rebate: on a $100k fill the
    // taker loses $100, the maker EARNS $40 (the LP incentive), and insurance
    // collects the $60 remainder. Conservation holds.
    let mut s = DefaultState::new(TREE_DEPTH);
    s.add_market(signed_market(Market::with_fees(0, 10, 4)));
    let (a, b) = (owner_of(1), owner_of(2));
    for (o, sk) in [(a, 1u8), (b, 2u8)] {
        let bl = [sk; 32];
        let cm = deposit_commit(o, 20_000 * QUOTE_SCALE, bl);
        s.apply_batch(&[
            BatchOp::Deposit {
                owner: o,
                asset_id: 0,
                amount: 20_000 * QUOTE_SCALE,
                blinding: bl,
                from: [sk; 20],
                deposit_id: s.consumed_deposit_count,
                deposit_blind: [0xDBu8; 32],
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
    let ins0 = s.insurance_fund;
    s.apply_op(&BatchOp::Fill {
        taker: a,
        maker: b,
        market_id: 0,
        taker_side: Side::Buy,
        size: SIZE_SCALE,
        price: 100_000 * PRICE_SCALE,
        oracle: oracle(100_000, 1_000),
        now_ms: 1_000,
    })
    .unwrap();

    assert_eq!(
        20_000 * QUOTE_SCALE - s.position(&a, 0).unwrap().collateral,
        100 * QUOTE_SCALE,
        "taker paid the 10 bps fee"
    );
    assert_eq!(
        s.position(&b, 0).unwrap().collateral - 20_000 * QUOTE_SCALE,
        40 * QUOTE_SCALE,
        "maker earned the 4 bps rebate"
    );
    assert_eq!(
        s.insurance_fund - ins0,
        60 * QUOTE_SCALE,
        "insurance got the remainder"
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
        from: [0u8; 20],
        deposit_id: 0,
        deposit_blind: [0xDBu8; 32],
    })
    .unwrap();
    let err = s
        .apply_op(&BatchOp::Deposit {
            owner: o,
            asset_id: 0,
            amount: amt,
            blinding: bl,
            from: [0u8; 20],
            // in-order id (1 == count): the order gate passes, so the DUPLICATE
            // COMMITMENT check is what rejects this — the property under test.
            deposit_id: 1,
            deposit_blind: [0xDBu8; 32],
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
        from: [0u8; 20],
        // the rejected duplicate above never advanced the count, so the next
        // in-order id is still 1.
        deposit_id: 1,
        deposit_blind: [0xDBu8; 32],
    })
    .unwrap();
    assert!(s.conservation_holds());
}

#[test]
fn self_trade_is_rejected_at_settlement() {
    // defensive: a fill whose taker == maker must be rejected (it would otherwise
    // drop a leg and break conservation). The matcher prevents this upstream.
    let mut s = fresh_state();
    let a = owner_of(1);
    let bl = [1u8; 32];
    let cm = deposit_commit(a, 20_000 * QUOTE_SCALE, bl);
    s.apply_batch(&[
        BatchOp::Deposit {
            owner: a,
            asset_id: 0,
            amount: 20_000 * QUOTE_SCALE,
            blinding: bl,
            from: [0u8; 20],
            deposit_id: 0,
            deposit_blind: [0xDBu8; 32],
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
    let (a, b) = (owner_of(1), owner_of(2));
    for (o, sk) in [(a, 1u8), (b, 2u8)] {
        let bl = [sk; 32];
        let cm = deposit_commit(o, 20_000 * QUOTE_SCALE, bl);
        s.apply_batch(&[
            BatchOp::Deposit {
                owner: o,
                asset_id: 0,
                amount: 20_000 * QUOTE_SCALE,
                blinding: bl,
                from: [sk; 20],
                deposit_id: s.consumed_deposit_count,
                deposit_blind: [0xDBu8; 32],
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

#[test]
fn adl_surfaces_the_per_winner_haircut_attribution() {
    // The same gap-down that claws B and C (cf. adl_distributes_pro_rata...), but
    // here we assert the engine RETURNS the attribution (audit Q2): each haircut
    // names the winner and the exact amount clawed, so a socialized loss can be
    // reported back to the affected account instead of vanishing silently.
    let mut s = fresh_state();
    let (a, b, c) = (owner_of(1), owner_of(2), owner_of(3));
    for (o, sk, amt) in [(a, 1u8, 6_000i128), (b, 2u8, 50_000), (c, 3u8, 50_000)] {
        let bl = [sk; 32];
        let cm = deposit_commit(o, amt * QUOTE_SCALE, bl);
        s.apply_batch(&[
            BatchOp::Deposit {
                owner: o,
                asset_id: 0,
                amount: amt * QUOTE_SCALE,
                blinding: bl,
                from: [sk; 20],
                deposit_id: s.consumed_deposit_count,
                deposit_blind: [0xDBu8; 32],
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
    s.apply_op(&BatchOp::Fill {
        taker: a,
        maker: b,
        market_id: 0,
        taker_side: Side::Buy,
        size: 3 * SIZE_SCALE / 10,
        price: 100_000 * PRICE_SCALE,
        oracle: oracle(100_000, 1_000),
        now_ms: 1_000,
    })
    .unwrap();
    s.apply_op(&BatchOp::Fill {
        taker: a,
        maker: c,
        market_id: 0,
        taker_side: Side::Buy,
        size: 2 * SIZE_SCALE / 10,
        price: 100_000 * PRICE_SCALE,
        oracle: oracle(100_000, 1_100),
        now_ms: 1_100,
    })
    .unwrap();
    let b0 = s.position(&b, 0).unwrap().collateral;
    let c0 = s.position(&c, 0).unwrap().collateral;

    // the event-returning liquidation entry surfaces the ADL haircuts
    let haircuts: Vec<AdlHaircut> = s.liquidate(&a, 0, &oracle(80_000, 2_000), 2_000).unwrap();

    let b_take = b0 - s.position(&b, 0).unwrap().collateral;
    let c_take = c0 - s.position(&c, 0).unwrap().collateral;
    assert_eq!(haircuts.len(), 2, "both clawed winners are attributed");
    let clawed_of = |o: &[u8; 32]| haircuts.iter().find(|h| &h.owner == o).map(|h| h.clawed);
    assert_eq!(
        clawed_of(&b),
        Some(b_take),
        "B's receipt matches the collateral taken"
    );
    assert_eq!(
        clawed_of(&c),
        Some(c_take),
        "C's receipt matches the collateral taken"
    );
    assert!(
        clawed_of(&b) > clawed_of(&c),
        "the larger winner's receipt is larger"
    );
    let total: i128 = haircuts.iter().map(|h| h.clawed).sum();
    assert_eq!(
        total,
        b_take + c_take,
        "the receipts account for every clawed unit"
    );
    assert!(s.conservation_holds());
}

#[test]
fn a_liquidation_absorbed_by_insurance_reports_no_adl_haircuts() {
    // When the insurance fund covers the whole shortfall, no winner is clawed — so
    // there is nothing to attribute and the returned receipt list is empty.
    let mut s = bad_debt_setup(1_000_000); // deep insurance seed absorbs the gap
    let haircuts = s
        .liquidate(&owner_of(1), 0, &oracle(80_000, 2_000), 2_000)
        .unwrap();
    assert!(
        haircuts.is_empty(),
        "no ADL when insurance absorbs the bad debt"
    );
    assert!(s.conservation_holds());
}

/// A SOLVENT-but-liquidatable fixture for the SEC-024 atomicity tests: A funds $6k
/// and opens 0.5 BTC long at $100k against B. At $90k the loss is $5k → equity
/// ~$1k < maintenance $2.25k (5% of $45k), so A is liquidatable — yet the close
/// leaves ~$550 positive collateral after the 1% penalty, so BOTH fallible
/// post-close paths (vault-pool arithmetic AND the insurance penalty add) are
/// reached with no bad-debt waterfall in play. The caller MUST assert the
/// liquidatability precondition at its chosen price (mandated: a fixture that
/// silently exercises `NotLiquidatable` passes for the wrong reason).
fn solvent_liquidatable_setup() -> DefaultState {
    let mut s = fresh_state();
    let (a, b) = (owner_of(1), owner_of(2));
    for (o, sk, amt) in [(a, 1u8, 6_000i128), (b, 2u8, 20_000)] {
        let bl = [sk; 32];
        let cm = deposit_commit(o, amt * QUOTE_SCALE, bl);
        s.apply_batch(&[
            BatchOp::Deposit {
                owner: o,
                asset_id: 0,
                amount: amt * QUOTE_SCALE,
                blinding: bl,
                from: [sk; 20],
                deposit_id: s.consumed_deposit_count,
                deposit_blind: [0xDBu8; 32],
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

/// The mandated fixture precondition: A really is liquidatable at $90k. Without
/// this, a drifted fixture would exercise `NotLiquidatable` and the overflow tests
/// below would pass without ever reaching the poisoned arithmetic.
fn assert_liquidatable_at_90k(s: &DefaultState) {
    let market = *s.markets.get(&0).unwrap();
    let fi = s.funding.get(&0).map(|f| f.cumulative_index).unwrap_or(0);
    assert!(
        s.position(&owner_of(1), 0)
            .unwrap()
            .is_liquidatable(&market, 90_000 * PRICE_SCALE, fi),
        "fixture precondition violated: A must be liquidatable at $90k"
    );
}

/// SEC-024 (SEC-022 carry-in): op_liquidate mutated the position via apply_fill and
/// THEN ran fallible vault/insurance arithmetic. A late overflow returned Err with
/// the position already closed, while run_maintenance logs an op only on success —
/// so the live root reflected a mutation the replayable op-log did not contain, and
/// the next proof wedged. Every fallible path must leave state byte-identical.
///
/// Variant 1: poison the VAULT POOL so the post-close pool arithmetic overflows.
/// The liquidated loser's realized PnL is negative, so the pool GAINS
/// (`checked_sub` of a negative) — the poison that trips is `i128::MAX`, not MIN.
#[test]
fn liquidation_overflow_in_vault_pool_leaves_state_byte_identical() {
    let mut s = solvent_liquidatable_setup();
    let a = owner_of(1);
    assert_liquidatable_at_90k(&s);
    s.vault_pool = i128::MAX;
    let before = s.state_root();
    let err = s
        .apply_op(&BatchOp::Liquidate {
            owner: a,
            market_id: 0,
            oracle: oracle(90_000, 2_000),
            now_ms: 2_000,
        })
        .expect_err("vault-pool overflow must reject");
    assert_eq!(err, EngineError::Overflow);
    assert_eq!(
        s.state_root(),
        before,
        "the position must NOT be closed by a failed liquidation"
    );
    assert!(
        s.position(&a, 0).unwrap().is_open(),
        "the position survives the rejected liquidation"
    );
}

/// Variant 2: poison the INSURANCE FUND so the penalty `checked_add` overflows —
/// the LAST fallible step, reached with the position closed, the vault pool moved,
/// and the penalty already taken from collateral under the old ordering.
#[test]
fn liquidation_overflow_in_insurance_fund_leaves_state_byte_identical() {
    let mut s = solvent_liquidatable_setup();
    let a = owner_of(1);
    assert_liquidatable_at_90k(&s);
    s.insurance_fund = i128::MAX;
    let before = s.state_root();
    let err = s
        .apply_op(&BatchOp::Liquidate {
            owner: a,
            market_id: 0,
            oracle: oracle(90_000, 2_000),
            now_ms: 2_000,
        })
        .expect_err("insurance-fund overflow must reject");
    assert_eq!(err, EngineError::Overflow);
    assert_eq!(
        s.state_root(),
        before,
        "the position must NOT be closed by a failed liquidation"
    );
    assert!(
        s.position(&a, 0).unwrap().is_open(),
        "the position survives the rejected liquidation"
    );
}

/// SEC-024 review carry-in: `EngineError::WrongAsset` is reachable — `op_deposit`
/// accepts ANY `asset_id` and mints it into the note — and `op_fund_insurance`
/// must refuse a non-canonical asset BEFORE its first mutation, or a wrong-asset
/// note would be destroyed while the fund is credited in the quote unit. Pins both
/// the rejection and the "checked before the first mutation" ordering the guard's
/// comment claims (state root byte-identical, note still spendable).
#[test]
fn fund_insurance_with_non_canonical_asset_is_rejected_untouched() {
    let mut s = fresh_state();
    let o = owner_of(1);
    let bl = [0x77u8; 32];
    let amt = 1_000 * QUOTE_SCALE;
    // An asset-1 note: `deposit_commit` hardcodes asset 0, so commit directly.
    let cm = Note::new(o, 1, amt, bl).commitment::<Keccak256>();
    s.apply_batch(&[BatchOp::Deposit {
        owner: o,
        asset_id: 1,
        amount: amt,
        blinding: bl,
        from: [0xA1u8; 20],
        deposit_id: 0,
        deposit_blind: [0xDBu8; 32],
    }])
    .unwrap();
    let before = s.state_root();
    let err = s
        .apply_batch(&[BatchOp::FundInsurance {
            note_commitment: cm,
            spend_key: [1; 32],
        }])
        .expect_err("a non-canonical asset must not capitalize the insurance fund");
    assert_eq!(err, EngineError::WrongAsset);
    assert_eq!(
        s.state_root(),
        before,
        "WrongAsset is checked before the first mutation — state byte-identical"
    );
    assert!(
        s.notes.contains_key(&cm),
        "the wrong-asset note survives, unspent"
    );
}

// ---------------------------------------------------------------------------
// SEC-026 — historical commitment uniqueness. A mint (Deposit or Unbind) that
// reconstructs a previously-SPENT `(owner, asset_id, amount, blinding)` tuple used
// to be accepted, because uniqueness was checked against the live unspent map while
// nullifiers are retained forever: the value was credited (`external_in` rose, the
// vault holds the money) but every later spend recomputed the same nullifier and
// was refused with `UnknownOrSpentNote` — credited-but-frozen funds that
// `conservation_holds()` cannot see. Both mint paths must reject against the
// HISTORICAL leaf list (every commitment ever appended to the tree).
// ---------------------------------------------------------------------------

/// The fund-loss regression itself: `Deposit → spend → Deposit` with the same tuple.
/// Before SEC-026 the second deposit was ACCEPTED (the live map had forgotten the
/// commitment) and the credited value was permanently unspendable.
#[test]
fn sec026_deposit_spend_deposit_same_tuple_rejected() {
    let mut s = fresh_state();
    let o = owner_of(1);
    let bl = [9u8; 32];
    let amt = 1_000 * QUOTE_SCALE;
    let cm = deposit_commit(o, amt, bl);
    s.apply_op(&BatchOp::Deposit {
        owner: o,
        asset_id: 0,
        amount: amt,
        blinding: bl,
        from: [0xA1u8; 20],
        deposit_id: 0,
        deposit_blind: [0xDBu8; 32],
    })
    .unwrap();
    // spend it — the commitment leaves the live unspent map, the nullifier stays forever
    s.apply_op(&BatchOp::Withdraw {
        note_commitment: cm,
        spend_key: [1u8; 32],
        to: None,
        nonce: 0,
    })
    .unwrap();
    assert!(
        !s.notes.contains_key(&cm),
        "spent: the live map no longer knows the commitment"
    );

    let external_in_before = s.external_in;
    let count_before = s.consumed_deposit_count;
    let tip_before = s.consumed_deposit_tip;
    let root_before = s.state_root();
    let err = s
        .apply_op(&BatchOp::Deposit {
            owner: o,
            asset_id: 0,
            amount: amt,
            blinding: bl,
            from: [0xA1u8; 20],
            // in-order id (1 == count): the SEC-019 order gate passes, so historical
            // uniqueness is the property under test.
            deposit_id: 1,
            deposit_blind: [0xDBu8; 32],
        })
        .unwrap_err();
    assert_eq!(err, EngineError::DuplicateCommitment);
    assert_eq!(s.external_in, external_in_before, "no value credited");
    assert_eq!(
        s.consumed_deposit_count, count_before,
        "deposit count did not advance"
    );
    assert_eq!(
        s.consumed_deposit_tip, tip_before,
        "deposit chain did not fold"
    );
    assert_eq!(s.state_root(), root_before, "state unchanged");
    assert!(s.conservation_holds());
}

/// `Unbind → Withdraw → Unbind` with the same tuple: the second unbind would debit
/// position collateral and mint an unspendable note. Must be rejected atomically.
#[test]
fn sec026_unbind_withdraw_unbind_same_tuple_rejected() {
    let mut s = fresh_state();
    let o = owner_of(1);
    let dep_bl = [1u8; 32];
    let cm0 = deposit_commit(o, 20_000 * QUOTE_SCALE, dep_bl);
    s.apply_batch(&[
        BatchOp::Deposit {
            owner: o,
            asset_id: 0,
            amount: 20_000 * QUOTE_SCALE,
            blinding: dep_bl,
            from: [0xA1u8; 20],
            deposit_id: 0,
            deposit_blind: [0xDBu8; 32],
        },
        BatchOp::FundPosition {
            owner: o,
            market_id: 0,
            note_commitment: cm0,
            spend_key: [1u8; 32],
        },
    ])
    .unwrap();

    let bl = [0x77u8; 32];
    let amt = 1_000 * QUOTE_SCALE;
    // an unbound note is (owner, asset 0, amount, blinding) — same shape as a deposit
    let cm = deposit_commit(o, amt, bl);
    s.apply_op(&BatchOp::Unbind {
        owner: o,
        market_id: 0,
        amount: amt,
        blinding: bl,
        oracle: oracle(100_000, 1_000),
        now_ms: 1_000,
    })
    .unwrap();
    // spend it as a real L1 withdrawal
    s.apply_op(&BatchOp::Withdraw {
        note_commitment: cm,
        spend_key: [1u8; 32],
        to: Some([0xEEu8; 20]),
        nonce: 7,
    })
    .unwrap();

    let collateral_before = s.position(&o, 0).unwrap().collateral;
    let root_before = s.state_root();
    let err = s
        .apply_op(&BatchOp::Unbind {
            owner: o,
            market_id: 0,
            amount: amt,
            blinding: bl,
            oracle: oracle(100_000, 2_000),
            now_ms: 2_000,
        })
        .unwrap_err();
    assert_eq!(err, EngineError::DuplicateCommitment);
    assert_eq!(
        s.position(&o, 0).unwrap().collateral,
        collateral_before,
        "the rejected mint must not debit position collateral"
    );
    assert_eq!(s.state_root(), root_before, "state unchanged");
    assert!(s.conservation_holds());
}

/// `Unbind → spend → Deposit`: a deposit-side check alone would miss this — the
/// commitment was created by the OTHER mint path.
#[test]
fn sec026_unbind_spend_deposit_same_tuple_rejected() {
    let mut s = fresh_state();
    let o = owner_of(1);
    let dep_bl = [1u8; 32];
    let cm0 = deposit_commit(o, 20_000 * QUOTE_SCALE, dep_bl);
    s.apply_batch(&[
        BatchOp::Deposit {
            owner: o,
            asset_id: 0,
            amount: 20_000 * QUOTE_SCALE,
            blinding: dep_bl,
            from: [0xA1u8; 20],
            deposit_id: 0,
            deposit_blind: [0xDBu8; 32],
        },
        BatchOp::FundPosition {
            owner: o,
            market_id: 0,
            note_commitment: cm0,
            spend_key: [1u8; 32],
        },
    ])
    .unwrap();

    let bl = [0x55u8; 32];
    let amt = 2_000 * QUOTE_SCALE;
    let cm = deposit_commit(o, amt, bl);
    s.apply_op(&BatchOp::Unbind {
        owner: o,
        market_id: 0,
        amount: amt,
        blinding: bl,
        oracle: oracle(100_000, 1_000),
        now_ms: 1_000,
    })
    .unwrap();
    s.apply_op(&BatchOp::Withdraw {
        note_commitment: cm,
        spend_key: [1u8; 32],
        to: None,
        nonce: 0,
    })
    .unwrap();

    let root_before = s.state_root();
    let err = s
        .apply_op(&BatchOp::Deposit {
            owner: o,
            asset_id: 0,
            amount: amt,
            blinding: bl,
            from: [0xA1u8; 20],
            deposit_id: s.consumed_deposit_count, // in-order: uniqueness is what rejects
            deposit_blind: [0xDBu8; 32],
        })
        .unwrap_err();
    assert_eq!(err, EngineError::DuplicateCommitment);
    assert_eq!(s.state_root(), root_before, "state unchanged");
    assert!(s.conservation_holds());
}

/// `Deposit → spend → Unbind`: the mirror gap — an unbind-side check against only
/// the live map would re-mint a commitment the DEPOSIT path created.
#[test]
fn sec026_deposit_spend_unbind_same_tuple_rejected() {
    let mut s = fresh_state();
    let o = owner_of(1);
    let dep_bl = [1u8; 32];
    let cm0 = deposit_commit(o, 20_000 * QUOTE_SCALE, dep_bl);
    s.apply_batch(&[
        BatchOp::Deposit {
            owner: o,
            asset_id: 0,
            amount: 20_000 * QUOTE_SCALE,
            blinding: dep_bl,
            from: [0xA1u8; 20],
            deposit_id: 0,
            deposit_blind: [0xDBu8; 32],
        },
        BatchOp::FundPosition {
            owner: o,
            market_id: 0,
            note_commitment: cm0,
            spend_key: [1u8; 32],
        },
    ])
    .unwrap();

    // deposit the tuple that the later unbind will collide with, then spend it
    let bl = [0x66u8; 32];
    let amt = 1_500 * QUOTE_SCALE;
    let cm = deposit_commit(o, amt, bl);
    s.apply_op(&BatchOp::Deposit {
        owner: o,
        asset_id: 0,
        amount: amt,
        blinding: bl,
        from: [0xA1u8; 20],
        deposit_id: 1,
        deposit_blind: [0xDBu8; 32],
    })
    .unwrap();
    s.apply_op(&BatchOp::FundPosition {
        owner: o,
        market_id: 0,
        note_commitment: cm,
        spend_key: [1u8; 32],
    })
    .unwrap();

    let collateral_before = s.position(&o, 0).unwrap().collateral;
    let root_before = s.state_root();
    let err = s
        .apply_op(&BatchOp::Unbind {
            owner: o,
            market_id: 0,
            amount: amt,
            blinding: bl,
            oracle: oracle(100_000, 1_000),
            now_ms: 1_000,
        })
        .unwrap_err();
    assert_eq!(err, EngineError::DuplicateCommitment);
    assert_eq!(s.position(&o, 0).unwrap().collateral, collateral_before);
    assert_eq!(s.state_root(), root_before, "state unchanged");
    assert!(s.conservation_holds());
}

/// A duplicate unbind while the first note is STILL UNSPENT must also stay rejected
/// (the deposit-side twin of `duplicate_commitment_deposit_rejected`).
#[test]
fn sec026_duplicate_unbind_while_unspent_rejected() {
    let mut s = fresh_state();
    let o = owner_of(1);
    let dep_bl = [1u8; 32];
    let cm0 = deposit_commit(o, 20_000 * QUOTE_SCALE, dep_bl);
    s.apply_batch(&[
        BatchOp::Deposit {
            owner: o,
            asset_id: 0,
            amount: 20_000 * QUOTE_SCALE,
            blinding: dep_bl,
            from: [0xA1u8; 20],
            deposit_id: 0,
            deposit_blind: [0xDBu8; 32],
        },
        BatchOp::FundPosition {
            owner: o,
            market_id: 0,
            note_commitment: cm0,
            spend_key: [1u8; 32],
        },
    ])
    .unwrap();
    let bl = [0x33u8; 32];
    let amt = 500 * QUOTE_SCALE;
    s.apply_op(&BatchOp::Unbind {
        owner: o,
        market_id: 0,
        amount: amt,
        blinding: bl,
        oracle: oracle(100_000, 1_000),
        now_ms: 1_000,
    })
    .unwrap();
    let err = s
        .apply_op(&BatchOp::Unbind {
            owner: o,
            market_id: 0,
            amount: amt,
            blinding: bl,
            oracle: oracle(100_000, 1_100),
            now_ms: 1_100,
        })
        .unwrap_err();
    assert_eq!(err, EngineError::DuplicateCommitment);
    assert!(s.conservation_holds());
}

/// Two mints differing ONLY in blinding must both be accepted — on both mint paths,
/// and even after the first is spent. Uniqueness is per-commitment, not per-value.
#[test]
fn sec026_mints_differing_only_in_blinding_both_accepted() {
    let mut s = fresh_state();
    let o = owner_of(1);
    let amt = 1_000 * QUOTE_SCALE;

    // deposits: same (owner, asset, amount), different blinding — first one spent
    let cm1 = deposit_commit(o, amt, [0x01u8; 32]);
    s.apply_op(&BatchOp::Deposit {
        owner: o,
        asset_id: 0,
        amount: amt,
        blinding: [0x01u8; 32],
        from: [0xA1u8; 20],
        deposit_id: 0,
        deposit_blind: [0xDBu8; 32],
    })
    .unwrap();
    s.apply_op(&BatchOp::Withdraw {
        note_commitment: cm1,
        spend_key: [1u8; 32],
        to: None,
        nonce: 0,
    })
    .unwrap();
    s.apply_op(&BatchOp::Deposit {
        owner: o,
        asset_id: 0,
        amount: amt,
        blinding: [0x02u8; 32],
        from: [0xA1u8; 20],
        deposit_id: 1,
        deposit_blind: [0xDBu8; 32],
    })
    .unwrap();
    assert!(s.conservation_holds());

    // unbinds: fund a position, then two same-amount unbinds under fresh blinds
    let dep_bl = [0x03u8; 32];
    let cm0 = deposit_commit(o, 10_000 * QUOTE_SCALE, dep_bl);
    s.apply_batch(&[
        BatchOp::Deposit {
            owner: o,
            asset_id: 0,
            amount: 10_000 * QUOTE_SCALE,
            blinding: dep_bl,
            from: [0xA1u8; 20],
            deposit_id: 2,
            deposit_blind: [0xDBu8; 32],
        },
        BatchOp::FundPosition {
            owner: o,
            market_id: 0,
            note_commitment: cm0,
            spend_key: [1u8; 32],
        },
    ])
    .unwrap();
    s.apply_op(&BatchOp::Unbind {
        owner: o,
        market_id: 0,
        amount: amt,
        blinding: [0x04u8; 32],
        oracle: oracle(100_000, 1_000),
        now_ms: 1_000,
    })
    .unwrap();
    s.apply_op(&BatchOp::Unbind {
        owner: o,
        market_id: 0,
        amount: amt,
        blinding: [0x05u8; 32],
        oracle: oracle(100_000, 1_100),
        now_ms: 1_100,
    })
    .unwrap();
    assert!(s.conservation_holds());
}

// ── SEC-024: insurance is a transfer of L1-bound value, never a mint ─────────

/// SEC-024: insurance must be a TRANSFER of already-L1-bound value, not a mint.
/// `FundInsurance` consumes a real note and raises `insurance_fund` while leaving
/// `external_in` untouched — the note's value already entered through `op_deposit`.
#[test]
fn fund_insurance_moves_note_value_without_asserting_new_external_value() {
    let mut s = fresh_state();
    let a = owner_of(1);
    let blind = [0x51u8; 32];
    let amount = 10_000 * QUOTE_SCALE;
    let cm = deposit_commit(a, amount, blind);
    s.apply_batch(&[BatchOp::Deposit {
        owner: a,
        asset_id: 0,
        amount,
        blinding: blind,
        from: [0xA1u8; 20],
        deposit_id: 0,
        deposit_blind: [0xDBu8; 32],
    }])
    .expect("deposit");

    let ext_in_before = s.external_in;
    let ins_before = s.insurance_fund;

    s.apply_batch(&[BatchOp::FundInsurance {
        note_commitment: cm,
        spend_key: [1u8; 32],
    }])
    .expect("fund insurance from a real note");

    assert_eq!(s.insurance_fund, ins_before + amount, "value moved in");
    assert_eq!(
        s.external_in, ext_in_before,
        "external_in MUST NOT move — the value entered at deposit, not here"
    );
    assert!(!s.notes.contains_key(&cm), "note consumed");
    assert!(s.conservation_holds());
}

/// The spend key still authorizes: nobody can donate another account's note.
#[test]
fn fund_insurance_rejects_a_wrong_spend_key() {
    let mut s = fresh_state();
    let a = owner_of(1);
    let blind = [0x52u8; 32];
    let amount = 1_000 * QUOTE_SCALE;
    let cm = deposit_commit(a, amount, blind);
    s.apply_batch(&[BatchOp::Deposit {
        owner: a,
        asset_id: 0,
        amount,
        blinding: blind,
        from: [0xA1u8; 20],
        deposit_id: 0,
        deposit_blind: [0xDBu8; 32],
    }])
    .expect("deposit");
    let before = s.state_root();
    assert_eq!(
        s.apply_batch(&[BatchOp::FundInsurance {
            note_commitment: cm,
            spend_key: [9u8; 32], // not the owner's key
        }])
        .expect_err("wrong key"),
        EngineError::BadSpendKey
    );
    assert_eq!(s.state_root(), before, "state unchanged");
}

/// **The atomicity test.** `consume_note` inserts the nullifier and removes the note
/// immediately, so a fallible `insurance_fund` addition afterwards would destroy the
/// note and return `Err`. The sequencer logs an op only on success, so live state
/// would diverge from the proven op-log and wedge the next proof.
#[test]
fn fund_insurance_overflow_leaves_state_byte_identical() {
    let mut s = fresh_state();
    let a = owner_of(1);
    let blind = [0x53u8; 32];
    let amount = 1_000 * QUOTE_SCALE;
    let cm = deposit_commit(a, amount, blind);
    s.apply_batch(&[BatchOp::Deposit {
        owner: a,
        asset_id: 0,
        amount,
        blinding: blind,
        from: [0xA1u8; 20],
        deposit_id: 0,
        deposit_blind: [0xDBu8; 32],
    }])
    .expect("deposit");
    s.insurance_fund = i128::MAX;
    let before = s.state_root();
    assert_eq!(
        s.apply_batch(&[BatchOp::FundInsurance {
            note_commitment: cm,
            spend_key: [1u8; 32],
        }])
        .expect_err("insurance overflow"),
        EngineError::Overflow
    );
    assert_eq!(
        s.state_root(),
        before,
        "the note must NOT be destroyed by a failed credit"
    );
    assert!(s.notes.contains_key(&cm), "note still unspent");
}

/// A newly-encoded deprecated op is refused deterministically.
#[test]
fn deprecated_seed_insurance_is_always_rejected() {
    let mut s = fresh_state();
    let before = s.state_root();
    assert_eq!(
        s.apply_batch(&[BatchOp::DeprecatedSeedInsurance {
            amount: 1_000 * QUOTE_SCALE
        }])
        .expect_err("deprecated"),
        EngineError::DeprecatedOp
    );
    assert_eq!(s.state_root(), before);
}

/// **The migration test that actually proves the ordinal choice.** `LEGACY_BYTES` is
/// a REAL pre-change encoding — captured by running `postcard::to_allocvec` on
/// `[SeedInsurance { amount: 7_500 }, EnterCloseOnly]` against the pre-SEC-024 tree
/// (commit 8a43792), NOT re-derived from the current enum. It must decode under the
/// CURRENT enum to the ordinal-8 stub with its amount intact, leave the op that
/// follows it correctly aligned, and the current enum must re-encode the stub to the
/// same bytes (postcard writes the variant ordinal as a varint BEFORE the fields, so
/// replacing ordinal 8 in place would silently mis-parse legacy bytes).
///
/// Feature-gated on `serde`, which is NOT a `perp-core` default: this test runs
/// under `cargo test --workspace` (resolver-2 unifies the feature because
/// `sequencer` declares `perp-core = { features = ["serde"] }`) or under
/// `-p perp-core --features serde` — a plain `-p perp-core` run silently filters
/// it out.
#[cfg(feature = "serde")]
#[test]
fn legacy_seed_insurance_bytes_decode_to_the_stub_and_stay_aligned() {
    // [len=2, ordinal 8, zigzag-varint(7500) = 152 117, ordinal 7 (EnterCloseOnly)]
    const LEGACY_BYTES: [u8; 5] = [2, 8, 152, 117, 7];
    let back: Vec<BatchOp> = postcard::from_bytes(&LEGACY_BYTES).expect("decode");
    assert_eq!(back.len(), 2, "the following op stayed aligned");
    match back[0] {
        BatchOp::DeprecatedSeedInsurance { amount } => assert_eq!(amount, 7_500),
        ref other => panic!("expected the deprecated stub, got {other:?}"),
    }
    assert!(matches!(back[1], BatchOp::EnterCloseOnly));
    // …and the byte freeze holds in the encode direction too: the retained stub
    // re-encodes to exactly the legacy bytes.
    let reenc = postcard::to_allocvec(&vec![
        BatchOp::DeprecatedSeedInsurance { amount: 7_500 },
        BatchOp::EnterCloseOnly,
    ])
    .expect("encode");
    assert_eq!(reenc, LEGACY_BYTES);
}

/// SEC-024's finding, made mechanical. `external_in` asserts that value entered
/// the system from outside. Before this branch there were TWO writers:
/// `op_deposit`, bound to the SEC-019 L1 hash chain, and `op_seed_insurance`,
/// bound to nothing — it fabricated the accounting representation of collateral
/// that never arrived, and the guest proved it. After this branch there must be
/// exactly one.
///
/// A source scan rather than a type-level restriction because `external_in` is
/// `pub` (`state.rs`) and used across the crate; making it private is a larger
/// refactor than this finding warrants. The scan strips ALL whitespace first so
/// the count is formatting-independent: rustfmt currently splits the op_deposit
/// READ across lines (`self\n.external_in`), so a raw substring count would see 1
/// today and drift to 2 under a harmless re-join. On the normalized text there
/// are exactly 2 touches of `self.external_in` — the READ
/// (`self.external_in.checked_add(amount)`) and the WRITE
/// (`self.external_in = external_in;`), both in `op_deposit` — and exactly 1 of
/// those is an assignment.
///
/// If you add a legitimate writer, update the counts AND state in the message
/// what binds it to real external value — an UNBOUND writer is the bug SEC-024
/// exists to close. (Mutation-checked: `self.external_in = self.external_in + 1;`
/// anywhere in engine.rs moves both counts and fails both asserts.)
///
/// Because `external_in` is `pub`, engine.rs is not automatically the whole
/// story — any module could write it. state.rs (at the time of writing, the only
/// other file in the crate that mentions the field) is scanned too, with its
/// `#[cfg(test)] mod tests` excluded: the module's root-sensitivity test mutates
/// the field, and a test is not a production writer.
#[test]
fn external_in_has_exactly_one_writer_and_it_is_op_deposit() {
    let src = include_str!("../src/engine.rs");
    let norm: String = src.chars().filter(|c| !c.is_whitespace()).collect();
    let touches = norm.matches("self.external_in").count();
    assert_eq!(
        touches, 2,
        "expected exactly 2 whitespace-normalized occurrences of `self.external_in` \
         in engine.rs — the read (`self.external_in.checked_add`) and the write \
         (`self.external_in = …`), both in op_deposit — found {touches}. A NEW \
         writer of external_in must be bound to real external value (op_deposit's \
         is the SEC-019 L1 deposit hash chain); an unbound writer is the \
         fabrication SEC-024 removed. Update this count only with that binding \
         named here."
    );
    // The sharper pin: the ASSIGNMENT form specifically. `==` comparisons are
    // excluded so a future assert/debug check does not masquerade as a writer.
    let writes =
        norm.matches("self.external_in=").count() - norm.matches("self.external_in==").count();
    assert_eq!(
        writes, 1,
        "expected exactly 1 assignment to `self.external_in` in engine.rs — \
         op_deposit's `self.external_in = external_in;`, the L1-bound deposit \
         path — found {writes}. op_seed_insurance was the second writer and it \
         was the SEC-024 fabrication; do not add another without an L1 binding."
    );

    // The same scan over state.rs, minus its `#[cfg(test)] mod tests` (whose
    // root-sensitivity test mutates the field). The split-at-marker exclusion is
    // sound only while the marker is unique, so pin that first — a second
    // `#[cfg(test)]` would silently shrink the scanned text.
    let state_src = include_str!("../src/state.rs");
    assert_eq!(
        state_src.matches("#[cfg(test)]").count(),
        1,
        "state.rs no longer has exactly one `#[cfg(test)]` marker — re-derive \
         this scan's non-test split before trusting its counts"
    );
    let (state_prod, _state_tests) = state_src
        .split_once("#[cfg(test)]")
        .expect("uniqueness was just asserted");
    let snorm: String = state_prod.chars().filter(|c| !c.is_whitespace()).collect();
    let stouches = snorm.matches("self.external_in").count();
    assert_eq!(
        stouches, 2,
        "expected exactly 2 whitespace-normalized occurrences of `self.external_in` \
         in state.rs outside its #[cfg(test)] module — the conservation identity \
         read (`self.external_in - self.external_out`) and the root-binding read \
         (`word_i128(self.external_in)`) — found {stouches}. A NEW writer of \
         external_in belongs behind op_deposit's L1 binding in engine.rs; an \
         unbound writer is the fabrication SEC-024 removed."
    );
    let swrites =
        snorm.matches("self.external_in=").count() - snorm.matches("self.external_in==").count();
    assert_eq!(
        swrites, 0,
        "expected 0 assignments to `self.external_in` in state.rs outside its \
         #[cfg(test)] module — both non-test touches are reads — found {swrites}. \
         The only production writer of external_in is op_deposit in engine.rs \
         (the SEC-019 L1-bound deposit path)."
    );
}

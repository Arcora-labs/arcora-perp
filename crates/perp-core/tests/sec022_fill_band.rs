//! SEC-022 — fill-price band, per-fill solvency postcondition, and `op_fill` atomicity.
//!
//! Spec: `docs/superpowers/specs/2026-07-26-sec022-fill-price-band-and-bad-debt-design.md`

use k256::ecdsa::SigningKey;
use perp_core::engine::BatchOp;
use perp_core::fixed::{PRICE_SCALE, QUOTE_SCALE, SIZE_SCALE};
use perp_core::hash::Keccak256;
use perp_core::note::owner_from_spend_key;
use perp_core::oracle::{oracle_digest, OracleSig, OracleTranscript};
use perp_core::order::Side;
use perp_core::{DefaultState, EngineError, Market, Note};
// Task 4 adds `FillLeg` to this import.

const TREE_DEPTH: u8 = 20;

fn owner_of(sk: u8) -> [u8; 32] {
    owner_from_spend_key::<Keccak256>(&[sk; 32])
}

fn oracle_key() -> SigningKey {
    SigningKey::from_bytes((&[7u8; 32]).into()).unwrap()
}

fn oracle_addr() -> [u8; 20] {
    let d = oracle_digest(0, 1, 1, 0, 1);
    OracleSig::sign(&oracle_key(), &d).recover(&d).unwrap()
}

/// A transcript signed by the fixture publisher, at `price_usd`, for market 0.
fn oracle(price_usd: i128, now: u64) -> OracleTranscript {
    let price = price_usd * PRICE_SCALE;
    let confidence = 10 * PRICE_SCALE; // $10, well inside 1%
    let d = oracle_digest(0, price, now, confidence, price);
    OracleTranscript {
        price,
        publish_time_ms: now,
        confidence,
        backup_twap: price,
        signature: OracleSig::sign(&oracle_key(), &d),
    }
}

fn deposit_commit(owner: [u8; 32], amount: i128, blinding: [u8; 32]) -> [u8; 32] {
    Note::new(owner, 0, amount, blinding).commitment::<Keccak256>()
}

/// A state with market 0 built from `m`, its oracle pubkey set to the fixture publisher.
fn state_with(m: Market) -> DefaultState {
    let mut m = m;
    m.oracle_pubkey = oracle_addr();
    let mut s = DefaultState::new(TREE_DEPTH);
    s.add_market(m);
    s
}

/// Deposit `amount` for `owner` and bind it all as position collateral on market 0.
fn fund(s: &mut DefaultState, owner: [u8; 32], sk: u8, amount: i128, blinding: [u8; 32], id: u64) {
    let cm = deposit_commit(owner, amount, blinding);
    s.apply_batch(&[
        BatchOp::Deposit {
            owner,
            asset_id: 0,
            amount,
            blinding,
            from: [0xA1u8; 20],
            deposit_id: id,
            deposit_blind: [0xDBu8; 32],
        },
        BatchOp::FundPosition {
            owner,
            market_id: 0,
            note_commitment: cm,
            spend_key: [sk; 32],
        },
    ])
    .expect("deposit + fund");
}

/// Two funded accounts, $20k each, on a market built from `m`.
fn two_funded(m: Market) -> (DefaultState, [u8; 32], [u8; 32]) {
    let mut s = state_with(m);
    let (a, b) = (owner_of(1), owner_of(2));
    fund(&mut s, a, 1, 20_000 * QUOTE_SCALE, [0x11u8; 32], 0);
    fund(&mut s, b, 2, 20_000 * QUOTE_SCALE, [0x22u8; 32], 1);
    (s, a, b)
}

fn fill(a: [u8; 32], b: [u8; 32], side: Side, size: i128, price_usd: i128, now: u64) -> BatchOp {
    BatchOp::Fill {
        taker: a,
        maker: b,
        market_id: 0,
        taker_side: side,
        size,
        price: price_usd * PRICE_SCALE,
        oracle: oracle(price_usd, now),
        now_ms: now,
    }
}

// ---------------------------------------------------------------- Task 2: atomicity

/// SEC-022 §4: `op_fill` committed `vault_pool` and both positions BEFORE the fallible
/// `treasury` / `insurance_fund` additions. A late overflow returned `Err` with state
/// already mutated — and the sequencer's rejection arm then omits the op entirely
/// (`sequencer/src/lib.rs:901-906`), leaving live host state diverged from what was
/// proven. Every fallible path must leave the state byte-for-byte unchanged.
///
/// `state_root()` binds the whole state — the note tree, nullifiers, notes, positions,
/// funding, market params, every balance counter, the mode and the counters — so root
/// equality IS whole-state equality, which is what the spec's test table demands.
#[test]
fn treasury_overflow_leaves_state_untouched() {
    // `with_fees` routes 0 bps to the treasury (`with_fees_treasury(.., 0)`), which
    // would make the treasury `checked_add` unreachable (MAX + 0 is fine); a nonzero
    // treasury cut (2 <= taker − maker = 6 bps, per `is_coherent`) forces it.
    let (mut s, a, b) = two_funded(Market::with_fees_treasury(0, 10, 4, 2));
    s.treasury = i128::MAX;
    let before = s.state_root();
    let err = s
        .apply_op(&fill(a, b, Side::Buy, SIZE_SCALE, 100_000, 1_000))
        .expect_err("treasury overflow must reject");
    assert_eq!(err, EngineError::Overflow);
    assert_eq!(
        s.state_root(),
        before,
        "state must be byte-for-byte unchanged"
    );
}

#[test]
fn insurance_overflow_leaves_state_untouched() {
    let (mut s, a, b) = two_funded(Market::with_fees(0, 10, 4));
    s.insurance_fund = i128::MAX;
    let before = s.state_root();
    let err = s
        .apply_op(&fill(a, b, Side::Buy, SIZE_SCALE, 100_000, 1_000))
        .expect_err("insurance overflow must reject");
    assert_eq!(err, EngineError::Overflow);
    assert_eq!(
        s.state_root(),
        before,
        "state must be byte-for-byte unchanged"
    );
}

/// Regression pin: the `vault_pool` add is already the first fallible step of the
/// commit block, before any mutation — this test passes both before and after the
/// restructure and pins that ordering.
#[test]
fn vault_pool_overflow_leaves_state_untouched() {
    // Open A↔B, then have A close against a THIRD account at a different price. In a
    // two-party close both legs realize exactly opposite PnL and `pool_delta` is 0
    // (the pool never moves); against a fresh counterparty only A's leg realizes, so
    // `pool_delta = −realized ≠ 0` — with `vault_pool` at the bound, that overflows.
    let (mut s, a, b) = two_funded(Market::with_fees(0, 10, 4));
    let c = owner_of(3);
    fund(&mut s, c, 3, 20_000 * QUOTE_SCALE, [0x33u8; 32], 2);
    s.apply_op(&fill(a, b, Side::Buy, SIZE_SCALE, 100_000, 1_000))
        .expect("open");
    s.vault_pool = i128::MIN;
    let before = s.state_root();
    let err = s
        .apply_op(&fill(a, c, Side::Sell, SIZE_SCALE, 101_000, 2_000))
        .expect_err("vault pool overflow must reject");
    assert_eq!(err, EngineError::Overflow);
    assert_eq!(
        s.state_root(),
        before,
        "state must be byte-for-byte unchanged"
    );
}

// ------------------------------------------------------------------- Task 3: the band

/// The headline attack: two accounts, one user, crossing far off-market. No credential
/// compromise, no operator involvement — the ordinary order API is enough.
#[test]
fn off_market_cross_is_rejected_with_state_unchanged() {
    let (mut s, a, b) = two_funded(Market::conservative(0));
    let before = s.state_root();
    // Oracle says $100k; they trade at $150k — 50% through the mark.
    let op = BatchOp::Fill {
        taker: a,
        maker: b,
        market_id: 0,
        taker_side: Side::Buy,
        size: SIZE_SCALE,
        price: 150_000 * PRICE_SCALE,
        oracle: oracle(100_000, 1_000),
        now_ms: 1_000,
    };
    let err = s.apply_op(&op).expect_err("off-market fill must reject");
    assert_eq!(err, EngineError::FillPriceOutOfBand);
    assert_eq!(s.state_root(), before, "whole state and root unchanged");
    assert!(s.conservation_holds());
}

#[test]
fn fill_exactly_at_the_band_edge_is_accepted() {
    let (mut s, a, b) = two_funded(Market::conservative(0));
    // 2% band around a $100k mark → $102,000 is exactly the edge.
    let op = BatchOp::Fill {
        taker: a,
        maker: b,
        market_id: 0,
        taker_side: Side::Buy,
        size: SIZE_SCALE,
        price: 102_000 * PRICE_SCALE,
        oracle: oracle(100_000, 1_000),
        now_ms: 1_000,
    };
    s.apply_op(&op).expect("the band edge is inclusive");
    assert!(s.conservation_holds());
}

#[test]
fn fill_just_outside_the_band_is_rejected_in_both_directions() {
    for price in [
        102_000 * PRICE_SCALE + 1, // one unit above the upper edge
        98_000 * PRICE_SCALE - 1,  // one unit below the lower edge
    ] {
        let (mut s, a, b) = two_funded(Market::conservative(0));
        let before = s.state_root();
        let op = BatchOp::Fill {
            taker: a,
            maker: b,
            market_id: 0,
            taker_side: Side::Buy,
            size: SIZE_SCALE,
            price,
            oracle: oracle(100_000, 1_000),
            now_ms: 1_000,
        };
        assert_eq!(
            s.apply_op(&op).expect_err("out of band"),
            EngineError::FillPriceOutOfBand,
        );
        assert_eq!(s.state_root(), before, "band is symmetric and fail-closed");
    }
}

/// The band's right-hand side multiplies the ATTESTED mark, never the untrusted `price`.
/// Anchoring to the value under attack would let a prover widen its own band.
#[test]
fn inflated_price_cannot_widen_its_own_band() {
    let (mut s, a, b) = two_funded(Market::conservative(0));
    // A price 100x the mark is 100x out of band — it must not scale the allowance.
    let op = BatchOp::Fill {
        taker: a,
        maker: b,
        market_id: 0,
        taker_side: Side::Buy,
        size: SIZE_SCALE / 1_000,
        price: 10_000_000 * PRICE_SCALE,
        oracle: oracle(100_000, 1_000),
        now_ms: 1_000,
    };
    assert_eq!(
        s.apply_op(&op).expect_err("inflated price"),
        EngineError::FillPriceOutOfBand,
    );
}

/// An invalid publisher signature must be rejected by `validate()` BEFORE the band, so no
/// band check is ever reachable without a valid signature.
#[test]
fn unsigned_oracle_is_rejected_before_the_band() {
    let mut m = Market::conservative(0);
    m.oracle_pubkey = [0u8; 20]; // fail-closed: unset key refuses every price
    let mut s = DefaultState::new(TREE_DEPTH);
    s.add_market(m);
    let (a, b) = (owner_of(1), owner_of(2));
    fund(&mut s, a, 1, 20_000 * QUOTE_SCALE, [0x11u8; 32], 0);
    fund(&mut s, b, 2, 20_000 * QUOTE_SCALE, [0x22u8; 32], 1);
    // The fill must be OUT of band relative to the (unverifiable) transcript: price
    // $150k against a $100k transcript. With an in-band fill this test could not
    // detect a band-before-signature reordering — both orderings would return
    // `Oracle(_)`. Off-band, a wrong ordering returns `FillPriceOutOfBand` instead,
    // so the assert genuinely pins that the signature gate fires first.
    let op = BatchOp::Fill {
        taker: a,
        maker: b,
        market_id: 0,
        taker_side: Side::Buy,
        size: SIZE_SCALE,
        price: 150_000 * PRICE_SCALE,
        oracle: oracle(100_000, 1_000),
        now_ms: 1_000,
    };
    let err = s.apply_op(&op).expect_err("unsigned oracle");
    assert!(
        matches!(err, EngineError::Oracle(_)),
        "signature gate must fire before the band, got {err:?}",
    );
}

/// Overflow anywhere in the band arithmetic rejects — it never wraps and never panics
/// (this code runs in the SP1 guest).
#[test]
fn band_arithmetic_overflow_rejects_without_panicking() {
    let mut s = state_with(Market::conservative(0));
    // Set the band AFTER add_market: `add_market` hard-asserts is_coherent(), and an
    // i128::MAX band is (correctly) incoherent — Task 1's joint band/fee/maintenance
    // inequality overflows on it and fails closed — so building the market with it
    // would panic in setup instead of exercising op_fill's checked band arithmetic.
    s.markets.get_mut(&0).unwrap().max_fill_deviation_ratio = i128::MAX;
    let (a, b) = (owner_of(1), owner_of(2));
    fund(&mut s, a, 1, 20_000 * QUOTE_SCALE, [0x11u8; 32], 0);
    fund(&mut s, b, 2, 20_000 * QUOTE_SCALE, [0x22u8; 32], 1);
    let before = s.state_root();
    assert_eq!(
        s.apply_op(&fill(a, b, Side::Buy, SIZE_SCALE, 101_000, 1_000))
            .expect_err("overflowing band"),
        EngineError::FillPriceOutOfBand,
    );
    assert_eq!(s.state_root(), before);
}

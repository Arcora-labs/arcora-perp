//! Margin rounding, the initial-margin floor, and position-entry pruning.
//!
//! * Initial and maintenance margin are computed from the notional rounded up, and
//!   the ratio product is rounded up too. An open position's initial margin is at
//!   least [`MIN_INITIAL_MARGIN`] ($1), so every open position is backed by
//!   collateral however small its notional.
//! * The engine never stores a position entry with zero size and zero collateral:
//!   every op that would leave one removes it instead (`SettleAll` removes the ones
//!   it empties before it returns). An entry of that shape in an anchored pre-state
//!   is still accepted, and behaves exactly like a missing entry.
//! * A position exactly at its maintenance boundary can always close in full at
//!   the edge of the fill band, fee included.
//! * `RejectReason::BelowMinimumSize` is a manifest reason the transition accepts.

use k256::ecdsa::SigningKey;
use perp_core::commitment::{batch_time_ms, derive_roots, DerivedRoots};
use perp_core::engine::BatchOp;
use perp_core::fixed::{
    abs, apply_rate, notional_quote, PRICE_SCALE, QUOTE_SCALE, RATE_SCALE, SIZE_SCALE,
};
use perp_core::hash::{word_u64, Digest, Keccak256};
use perp_core::note::{owner_from_spend_key, Note, PubKey};
use perp_core::oracle::{oracle_digest, OracleSig, OracleTranscript};
use perp_core::order::{BatchManifest, RejectReason, Side};
use perp_core::position::{Position, RiskError, MIN_INITIAL_MARGIN};
use perp_core::state::Mode;
use perp_core::{DefaultState, EngineError, FillLeg, Market};
use std::collections::BTreeMap;

const TREE_DEPTH: u8 = 20;
const T0: u64 = 1_700_000_000_000;

fn usd(x: i128) -> i128 {
    x * QUOTE_SCALE
}

fn owner_of(sk: u8) -> PubKey {
    owner_from_spend_key::<Keccak256>(&[sk; 32])
}

fn oracle_key() -> SigningKey {
    SigningKey::from_bytes((&[7u8; 32]).into()).unwrap()
}

fn oracle_addr() -> [u8; 20] {
    let d = oracle_digest(0, 1, 1, 0, 1);
    OracleSig::sign(&oracle_key(), &d).recover(&d).unwrap()
}

/// A transcript for market 0 at `price` (price-scaled), published at `now`.
fn oracle_raw(price: i128, now: u64) -> OracleTranscript {
    let confidence = price / 1_000; // 0.1%
    let d = oracle_digest(0, price, now, confidence, price);
    OracleTranscript {
        price,
        publish_time_ms: now,
        confidence,
        backup_twap: price,
        signature: OracleSig::sign(&oracle_key(), &d),
    }
}

fn oracle(price_usd: i128, now: u64) -> OracleTranscript {
    oracle_raw(price_usd * PRICE_SCALE, now)
}

fn state_with(mut m: Market) -> DefaultState {
    m.oracle_pubkey = oracle_addr();
    let mut s = DefaultState::new(TREE_DEPTH);
    s.add_market(m);
    s
}

/// Credit a fresh note of `amount` to owner `sk` and return its commitment.
fn deposit(s: &mut DefaultState, sk: u8, amount: i128) -> Digest {
    let owner = owner_of(sk);
    let mut blind = [sk; 32];
    blind[..8].copy_from_slice(&s.consumed_deposit_count.to_le_bytes());
    let cm = Note::new(owner, 0, amount, blind).commitment::<Keccak256>();
    s.apply_batch(&[BatchOp::Deposit {
        owner,
        asset_id: 0,
        amount,
        blinding: blind,
        from: [sk; 20],
        deposit_id: s.consumed_deposit_count,
        deposit_blind: [0xDB; 32],
    }])
    .expect("deposit");
    cm
}

fn fund_op(sk: u8, cm: Digest) -> BatchOp {
    BatchOp::FundPosition {
        owner: owner_of(sk),
        market_id: 0,
        note_commitment: cm,
        spend_key: [sk; 32],
    }
}

/// Deposit `amount` for owner `sk` and bind all of it as market-0 collateral.
fn fund(s: &mut DefaultState, sk: u8, amount: i128) {
    let cm = deposit(s, sk, amount);
    s.apply_batch(&[fund_op(sk, cm)]).expect("fund");
}

fn fill_with(
    taker: PubKey,
    maker: PubKey,
    side: Side,
    size: i128,
    price: i128,
    oracle: OracleTranscript,
) -> BatchOp {
    BatchOp::Fill {
        taker,
        maker,
        market_id: 0,
        taker_side: side,
        size,
        price,
        now_ms: oracle.publish_time_ms,
        oracle,
    }
}

fn fill(taker: u8, maker: u8, side: Side, size: i128, price_usd: i128, now: u64) -> BatchOp {
    fill_with(
        owner_of(taker),
        owner_of(maker),
        side,
        size,
        price_usd * PRICE_SCALE,
        oracle(price_usd, now),
    )
}

/// A blinding unique to `(sk, amount, now)`, so each minted note is fresh.
fn blind_for(sk: u8, amount: i128, now: u64) -> Digest {
    let mut b = [0u8; 32];
    b[0] = sk;
    b[1..17].copy_from_slice(&amount.to_le_bytes());
    b[17..25].copy_from_slice(&now.to_le_bytes());
    b
}

fn unbind_with(owner: PubKey, amount: i128, blinding: Digest, oracle: OracleTranscript) -> BatchOp {
    BatchOp::Unbind {
        owner,
        market_id: 0,
        amount,
        blinding,
        now_ms: oracle.publish_time_ms,
        oracle,
    }
}

fn unbind(sk: u8, amount: i128, price_usd: i128, now: u64) -> BatchOp {
    unbind_with(
        owner_of(sk),
        amount,
        blind_for(sk, amount, now),
        oracle(price_usd, now),
    )
}

fn liquidate(sk: u8, price_usd: i128, now: u64) -> BatchOp {
    BatchOp::Liquidate {
        owner: owner_of(sk),
        market_id: 0,
        oracle: oracle(price_usd, now),
        now_ms: now,
    }
}

fn insufficient(leg: Option<FillLeg>) -> EngineError {
    EngineError::Risk {
        source: RiskError::InsufficientMargin,
        leg,
    }
}

fn manifest_for(s: &DefaultState, ops: &[BatchOp]) -> BatchManifest {
    BatchManifest {
        previous_state_root: s.state_root(),
        batch_id: s.next_batch_id,
        batch_time_ms: batch_time_ms(ops),
        ordered: vec![],
        rejected: vec![],
        oracle_updates: vec![],
        matching_rule_version: 1,
        enclave_measurement: [0u8; 32],
        sequencer_pubkey_epoch: 0,
    }
}

/// Derive the batch's roots on `s`. With the `serde` feature, the same batch is
/// also derived on a copy of `s` that went through the witness encoding, and both
/// must agree (that copy is what the guest sees).
fn derive(s: &mut DefaultState, ops: &[BatchOp], m: &BatchManifest) -> DerivedRoots {
    #[cfg(feature = "serde")]
    let decoded = {
        let bytes = postcard::to_allocvec(&*s).expect("encode pre-state");
        let mut d: DefaultState = postcard::from_bytes(&bytes).expect("decode pre-state");
        let roots = derive_roots(&mut d, ops, m).expect("derive on the decoded pre-state");
        (roots, d.state_root())
    };
    let roots = derive_roots(s, ops, m).expect("derive");
    #[cfg(feature = "serde")]
    assert_eq!(decoded, (roots, s.state_root()), "native and decoded agree");
    roots
}

fn no_empty_entries(s: &DefaultState) -> bool {
    s.positions.values().all(|p| !p.is_empty())
}

// --- the initial-margin floor -------------------------------------------------

#[test]
fn fills_between_owners_with_no_collateral_are_refused() {
    let mut s = state_with(Market::conservative(0));
    let orc = oracle(150, T0);
    let root = s.state_root();
    for i in 0..200u64 {
        // 1e-8 base at $150: a notional of 1.5 micro-USD
        let op = fill_with(
            word_u64(10_000 + 2 * i),
            word_u64(10_001 + 2 * i),
            Side::Buy,
            1,
            150 * PRICE_SCALE,
            orc,
        );
        assert_eq!(
            s.apply_op(&op).unwrap_err(),
            insufficient(Some(FillLeg::Taker))
        );
    }
    assert!(s.positions.is_empty(), "no entry is created");
    assert_eq!(s.state_root(), root, "the state is unchanged");

    // a funded taker against a maker with no collateral names the maker
    fund(&mut s, 1, usd(10));
    let root = s.state_root();
    let op = fill_with(
        owner_of(1),
        word_u64(42),
        Side::Buy,
        1,
        150 * PRICE_SCALE,
        orc,
    );
    assert_eq!(
        s.apply_op(&op).unwrap_err(),
        insufficient(Some(FillLeg::Maker))
    );
    assert_eq!(s.state_root(), root);
    assert_eq!(s.positions.len(), 1, "only the funded entry exists");
}

#[test]
fn an_opening_leg_needs_at_least_one_dollar_of_equity() {
    let below = MIN_INITIAL_MARGIN - 1;
    // (size, price in USD): a 1.5 micro-USD notional, and a $5 notional whose 10%
    // initial margin ($0.50) is below the floor
    for (size, price_usd) in [(1i128, 150i128), (5 * SIZE_SCALE / 100, 100)] {
        for (taker_amt, maker_amt, refused) in [
            (below, MIN_INITIAL_MARGIN, Some(FillLeg::Taker)),
            (MIN_INITIAL_MARGIN, below, Some(FillLeg::Maker)),
            (MIN_INITIAL_MARGIN, MIN_INITIAL_MARGIN, None),
        ] {
            let mut s = state_with(Market::conservative(0));
            fund(&mut s, 1, taker_amt);
            fund(&mut s, 2, maker_amt);
            let root = s.state_root();
            let r = s.apply_op(&fill(1, 2, Side::Buy, size, price_usd, T0));
            match refused {
                Some(leg) => {
                    assert_eq!(r.unwrap_err(), insufficient(Some(leg)));
                    assert_eq!(s.state_root(), root);
                }
                None => {
                    r.expect("exactly $1 on each leg is enough");
                    assert_eq!(s.position(&owner_of(1), 0).unwrap().size, size);
                    assert_eq!(s.position(&owner_of(2), 0).unwrap().size, -size);
                    assert!(s.conservation_holds());
                }
            }
        }
    }
}

#[test]
fn unbinding_from_an_open_position_keeps_the_floor() {
    let mut s = state_with(Market::conservative(0));
    fund(&mut s, 1, usd(3));
    fund(&mut s, 2, usd(3));
    s.apply_op(&fill(1, 2, Side::Buy, 1, 150, T0)).unwrap();
    let root = s.state_root();
    // $3 → $0.999999 would leave the open position below the floor
    assert_eq!(
        s.apply_op(&unbind(1, usd(2) + 1, 150, T0)).unwrap_err(),
        insufficient(None)
    );
    assert_eq!(s.state_root(), root);
    // $3 → $1 is allowed
    s.apply_op(&unbind(1, usd(2), 150, T0)).unwrap();
    assert_eq!(
        s.position(&owner_of(1), 0).unwrap().collateral,
        MIN_INITIAL_MARGIN
    );
}

#[test]
fn closing_is_not_subject_to_the_floor() {
    let mut s = state_with(Market::conservative(0));
    fund(&mut s, 1, usd(5));
    fund(&mut s, 2, usd(5));
    s.apply_op(&fill(1, 2, Side::Buy, 1, 150, T0)).unwrap();
    // move all but one micro-USD of each side's collateral to the insurance fund
    // (conservation unchanged), leaving both open positions far below the floor
    for sk in [1u8, 2] {
        let p = s.positions.get_mut(&(owner_of(sk), 0)).unwrap();
        s.insurance_fund += p.collateral - 1;
        p.collateral = 1;
    }
    assert!(s.conservation_holds());
    // a reduction checks maintenance margin only, and both close
    s.apply_op(&fill(1, 2, Side::Sell, 1, 150, T0))
        .expect("a close is exempt from the initial-margin floor");
    for sk in [1u8, 2] {
        let p = s.position(&owner_of(sk), 0).unwrap();
        assert_eq!((p.size, p.collateral), (0, 1));
    }
}

// --- pruning --------------------------------------------------------------------

#[test]
fn closed_and_emptied_positions_leave_the_state() {
    let mut s = state_with(Market::conservative(0));
    let maker = 0xEEu8;
    fund(&mut s, maker, usd(1_000_000));
    let orc = oracle(100_000, T0);
    let px = 100_000 * PRICE_SCALE;
    for sk in 1..=20u8 {
        fund(&mut s, sk, usd(20_000));
        let (t, m) = (owner_of(sk), owner_of(maker));
        s.apply_op(&fill_with(t, m, Side::Buy, SIZE_SCALE / 10, px, orc))
            .unwrap();
        s.apply_op(&fill_with(t, m, Side::Sell, SIZE_SCALE / 10, px, orc))
            .unwrap();
        let flat = *s.position(&t, 0).unwrap();
        assert_eq!((flat.size, flat.collateral), (0, usd(20_000)));
        s.apply_op(&unbind_with(t, usd(20_000), blind_for(sk, 0, T0), orc))
            .unwrap();
        assert!(
            s.position(&t, 0).is_none(),
            "unbinding everything removes it"
        );
    }
    assert_eq!(
        s.positions.len(),
        1,
        "only the maker's funded entry remains"
    );
    let m = owner_of(maker);
    let c = s.position(&m, 0).unwrap().collateral;
    s.apply_op(&unbind_with(m, c, blind_for(maker, 0, T0), orc))
        .unwrap();
    assert!(s.positions.is_empty());
    assert_eq!(
        s.positions_digest(),
        state_with(Market::conservative(0)).positions_digest(),
        "the positions digest is back to its genesis value"
    );
    assert!(s.conservation_holds());
}

/// Owner 1 holds $6k behind a 0.5 BTC long opened at $100k against owner 2, a
/// well-funded short; `insurance` is moved into the fund first.
fn half_btc_long(insurance: i128) -> DefaultState {
    let mut s = state_with(Market::conservative(0));
    fund(&mut s, 1, usd(6_000));
    fund(&mut s, 2, usd(100_000));
    if insurance > 0 {
        let cm = deposit(&mut s, 0x0F, insurance);
        s.apply_batch(&[BatchOp::FundInsurance {
            note_commitment: cm,
            spend_key: [0x0F; 32],
        }])
        .unwrap();
    }
    s.apply_op(&fill(1, 2, Side::Buy, SIZE_SCALE / 2, 100_000, T0))
        .unwrap();
    s
}

#[test]
fn a_liquidation_ending_at_exactly_zero_collateral_removes_the_entry() {
    let mut s = half_btc_long(0);
    // At $88.5k the close realizes −$5,750, leaving $250; the 1% penalty on the
    // $44,250 notional ($442.50) takes all of it.
    s.apply_batch(&[liquidate(1, 88_500, T0 + 1_000)]).unwrap();
    assert!(s.position(&owner_of(1), 0).is_none());
    assert_eq!(s.insurance_fund, usd(250));
    assert_eq!(s.mode, Mode::Normal);
    assert!(no_empty_entries(&s));
    assert!(s.conservation_holds());
}

#[test]
fn insurance_covering_the_bad_debt_exactly_removes_the_entry() {
    // At $80k the close realizes −$10,000: a $4,000 shortfall, and the fund holds
    // exactly $4,000.
    let mut s = half_btc_long(usd(4_000));
    s.apply_batch(&[liquidate(1, 80_000, T0 + 1_000)]).unwrap();
    assert!(s.position(&owner_of(1), 0).is_none());
    assert_eq!(s.insurance_fund, 0);
    assert_eq!(s.mode, Mode::Normal);
    assert!(no_empty_entries(&s));
    assert!(s.conservation_holds());
}

#[test]
fn a_full_wind_down_exit_removes_the_entry() {
    let mut s = state_with(Market::conservative(0));
    fund(&mut s, 1, usd(20_000));
    fund(&mut s, 2, usd(20_000));
    s.apply_op(&fill(1, 2, Side::Buy, SIZE_SCALE / 10, 100_000, T0))
        .unwrap();
    s.apply_batch(&[BatchOp::SettleAll]).unwrap();
    assert!(no_empty_entries(&s));
    for sk in [1u8, 2] {
        let owner = owner_of(sk);
        let c = s.position(&owner, 0).unwrap().collateral;
        assert!(c > 0);
        let blinding = [sk ^ 0xA5; 32];
        let cm = Note::new(owner, 0, c, blinding).commitment::<Keccak256>();
        let out = s
            .apply_batch(&[
                BatchOp::WindDownUnbind {
                    owner,
                    market_id: 0,
                    amount: c,
                    blinding,
                },
                BatchOp::WindDownWithdraw {
                    note_commitment: cm,
                    spend_key: [sk; 32],
                    to: Some([sk; 20]),
                    nonce: s.last_withdrawal_nonce + 1,
                },
            ])
            .unwrap();
        assert_eq!(out.withdrawals.len(), 1);
        assert!(s.position(&owner, 0).is_none(), "a full exit removes it");
    }
    assert!(s.positions.is_empty());
    assert!(s.conservation_holds());
}

/// A liquidation the reserves and the winners cannot fully cover leaves a flat
/// entry with negative collateral. Funding exactly that amount into it leaves zero
/// size and zero collateral: the entry is removed, and the following batches, an
/// ordinary one and `SettleAll`, both derive their roots.
#[test]
fn repaying_a_flat_debt_removes_the_entry_and_later_batches_derive() {
    let mut s = state_with(Market::conservative(0));
    let a = owner_of(1);
    fund(&mut s, 1, usd(10_000));
    fund(&mut s, 2, usd(10_000)); // exactly the initial margin of 1 BTC at $100k
    s.apply_op(&fill(1, 2, Side::Buy, SIZE_SCALE, 100_000, T0))
        .expect("open 1 BTC");
    let liq = liquidate(1, 70_000, T0 + 1_000);
    // the debt the liquidation leaves, from a dry run on a copy
    let debt = {
        let mut dry = s.clone();
        dry.apply_batch(std::slice::from_ref(&liq)).unwrap();
        -dry.position(&a, 0).unwrap().collateral
    };
    assert!(debt > 0, "the scenario leaves debt behind");
    // A holds a note of exactly that amount, credited while the engine is open
    let cm = deposit(&mut s, 1, debt);
    s.apply_batch(&[liq]).unwrap();
    let parked = *s.position(&a, 0).unwrap();
    assert_eq!((parked.size, parked.collateral), (0, -debt));
    assert_eq!(s.mode, Mode::CloseOnly);

    // the top-up batch; its manifest also carries a minimum-size rejection
    let ops = vec![fund_op(1, cm)];
    let mut m = manifest_for(&s, &ops);
    m.rejected
        .push((word_u64(0xB0), RejectReason::BelowMinimumSize));
    derive(&mut s, &ops, &m);
    assert!(s.position(&a, 0).is_none(), "the repaid entry is removed");
    assert!(no_empty_entries(&s));
    assert!(s.conservation_holds());

    // the next ordinary batch
    let m = manifest_for(&s, &[]);
    let roots = derive(&mut s, &[], &m);
    assert_eq!(roots.wind_down_phase, 0);

    // and the wind-down settlement
    let ops = vec![BatchOp::SettleAll];
    let m = manifest_for(&s, &ops);
    let roots = derive(&mut s, &ops, &m);
    assert_eq!(roots.wind_down_phase, 1);
    assert!(no_empty_entries(&s));
    assert!(s
        .positions
        .values()
        .all(|p| p.size == 0 && p.collateral > 0));
    assert!(s.conservation_holds());
}

/// The shape check verifies binding only: an anchored pre-state may hold an entry
/// with zero size and zero collateral. A batch that leaves it alone derives and
/// keeps it; a batch that funds it and withdraws everything again removes it.
#[test]
fn an_anchored_entry_with_zero_size_and_collateral_is_accepted() {
    let mut s = state_with(Market::conservative(0));
    fund(&mut s, 1, usd(20_000));
    fund(&mut s, 2, usd(20_000));
    let cm = deposit(&mut s, 9, usd(5));
    let e = owner_of(9);
    let mut legacy = Position::empty(e, 0);
    legacy.funding_entry = 12_345; // any funding index; it is irrelevant at size 0
    s.positions.insert((e, 0), legacy);
    assert_eq!(s.validate_witness_shape(), Ok(()));
    #[cfg(feature = "serde")]
    {
        let bytes = postcard::to_allocvec(&s).unwrap();
        let back: DefaultState = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(back.validate_witness_shape(), Ok(()));
        assert_eq!(back.state_root(), s.state_root());
    }

    let ops = vec![fill(1, 2, Side::Buy, SIZE_SCALE / 10, 100_000, T0)];
    let m = manifest_for(&s, &ops);
    derive(&mut s, &ops, &m);
    assert_eq!(s.position(&e, 0), Some(&legacy), "an untouched entry stays");

    let ops = vec![fund_op(9, cm), unbind(9, usd(5), 100_000, T0)];
    let m = manifest_for(&s, &ops);
    derive(&mut s, &ops, &m);
    assert!(s.position(&e, 0).is_none(), "a touched entry is removed");
    assert!(no_empty_entries(&s));
    assert!(s.conservation_holds());
}

// --- an empty entry behaves like a missing one -------------------------------------

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn digest(&mut self) -> Digest {
        let mut d = [0u8; 32];
        for c in d.chunks_mut(8) {
            c.copy_from_slice(&self.next().to_le_bytes());
        }
        d
    }
}

/// Signed transcripts on a price grid, one set per epoch, signed on first use.
struct Oracles(BTreeMap<(u64, usize), OracleTranscript>);
const GRID: [i128; 21] = [
    80_000, 82_000, 84_000, 86_000, 88_000, 90_000, 92_000, 94_000, 96_000, 98_000, 100_000,
    102_000, 104_000, 106_000, 108_000, 110_000, 112_000, 114_000, 116_000, 118_000, 120_000,
];
impl Oracles {
    fn at(&mut self, epoch: u64, i: usize) -> OracleTranscript {
        *self
            .0
            .entry((epoch, i))
            .or_insert_with(|| oracle(GRID[i], T0 + epoch * 5_000))
    }
}

/// Owners `1..=TRADERS` act; the anchored copy also starts with empty entries for
/// them and for two owners that never act.
const TRADERS: u8 = 5;

fn random_size(rng: &mut Rng) -> i128 {
    match rng.below(4) {
        0 => 1 + rng.below(100) as i128,
        1 => 1 + rng.below(1_000_000) as i128,
        2 => (1 + rng.below(10) as i128) * SIZE_SCALE / 100,
        _ => (1 + rng.below(30) as i128) * SIZE_SCALE / 10,
    }
}

fn note_of(rng: &mut Rng, s: &DefaultState, owner: &PubKey) -> Digest {
    let mine: Vec<Digest> = s
        .notes
        .iter()
        .filter(|(_, n)| &n.owner == owner)
        .map(|(cm, _)| *cm)
        .collect();
    if mine.is_empty() {
        rng.digest()
    } else {
        mine[rng.below(mine.len() as u64) as usize]
    }
}

fn random_op(rng: &mut Rng, s: &DefaultState, orc: OracleTranscript) -> BatchOp {
    let sk = 1 + rng.below(TRADERS as u64) as u8;
    let owner = owner_of(sk);
    let mark = orc.price;
    let held = s.position(&owner, 0).map(|p| p.collateral).unwrap_or(0);
    let some_of = |rng: &mut Rng, c: i128| -> i128 {
        if c > 0 && rng.below(2) == 0 {
            c
        } else if c > 1 {
            1 + (rng.next() as i128).rem_euclid(c)
        } else {
            1 + rng.below(usd(1_000) as u64) as i128
        }
    };
    match rng.below(20) {
        0..=2 => BatchOp::Deposit {
            owner,
            asset_id: 0,
            amount: if rng.below(3) == 0 {
                1 + rng.below(usd(2) as u64) as i128
            } else {
                usd(1 + rng.below(5_000) as i128)
            },
            blinding: rng.digest(),
            from: [sk; 20],
            deposit_id: s.consumed_deposit_count,
            deposit_blind: [0xDB; 32],
        },
        3..=5 => fund_op(sk, note_of(rng, s, &owner)),
        6..=10 => {
            let other = 1 + (sk + rng.below(TRADERS as u64 - 1) as u8) % TRADERS;
            let side = if rng.below(2) == 0 {
                Side::Buy
            } else {
                Side::Sell
            };
            let price = mark + (rng.below(3) as i128 - 1) * mark / 100;
            fill_with(owner, owner_of(other), side, random_size(rng), price, orc)
        }
        11..=12 => unbind_with(owner, some_of(rng, held), rng.digest(), orc),
        13..=15 => BatchOp::Liquidate {
            owner,
            market_id: 0,
            oracle: orc,
            now_ms: orc.publish_time_ms,
        },
        16 => BatchOp::AccrueFunding {
            market_id: 0,
            mark: mark + (rng.below(3) as i128 - 1) * mark / 100,
            oracle: orc,
            now_ms: orc.publish_time_ms,
        },
        17 => {
            let real = rng.below(2) == 0;
            BatchOp::Withdraw {
                note_commitment: note_of(rng, s, &owner),
                spend_key: [sk; 32],
                to: real.then_some([sk; 20]),
                nonce: if real { s.last_withdrawal_nonce + 1 } else { 0 },
            }
        }
        18 if s.mode == Mode::CloseOnly => BatchOp::WindDownUnbind {
            owner,
            market_id: 0,
            amount: some_of(rng, held),
            blinding: rng.digest(),
        },
        18 => BatchOp::EnterCloseOnly,
        _ if rng.below(40) == 0 => BatchOp::SettleAll,
        _ => BatchOp::FundInsurance {
            note_commitment: note_of(rng, s, &owner),
            spend_key: [sk; 32],
        },
    }
}

/// The state with entries of zero size and zero collateral removed, and with the
/// fields a flat entry never reads (entry price and funding index) cleared.
fn behaviour(s: &DefaultState) -> Vec<((PubKey, u64), Position)> {
    s.positions
        .iter()
        .filter(|(_, p)| !p.is_empty())
        .map(|(k, p)| {
            let mut p = *p;
            if p.size == 0 {
                p.entry_price = 0;
                p.funding_entry = 0;
            }
            (*k, p)
        })
        .collect()
}

fn assert_same_behaviour(a: &DefaultState, b: &DefaultState, ctx: &str) {
    assert_eq!(behaviour(a), behaviour(b), "positions differ: {ctx}");
    assert_eq!(a.notes, b.notes, "notes differ: {ctx}");
    assert_eq!(a.funding, b.funding, "funding differs: {ctx}");
    assert_eq!(a.tree.len(), b.tree.len(), "tree differs: {ctx}");
    assert_eq!(
        a.nullifiers.digest(),
        b.nullifiers.digest(),
        "nullifiers differ: {ctx}"
    );
    assert_eq!(
        (
            a.insurance_fund,
            a.vault_pool,
            a.treasury,
            a.external_in,
            a.external_out
        ),
        (
            b.insurance_fund,
            b.vault_pool,
            b.treasury,
            b.external_in,
            b.external_out
        ),
        "balances differ: {ctx}"
    );
    assert_eq!(a.mode, b.mode, "mode differs: {ctx}");
    assert_eq!(
        (
            a.last_withdrawal_nonce,
            a.consumed_deposit_count,
            a.consumed_deposit_tip
        ),
        (
            b.last_withdrawal_nonce,
            b.consumed_deposit_count,
            b.consumed_deposit_tip
        ),
        "counters differ: {ctx}"
    );
}

#[test]
fn an_empty_entry_behaves_like_a_missing_one() {
    const SEEDS: u64 = 6;
    const STEPS: usize = 2_500;
    const STEPS_PER_EPOCH: usize = 250;
    let mut oracles = Oracles(BTreeMap::new());
    let mut ops_ok = 0usize;
    let mut touched_empty = 0usize;
    for seed in 1..=SEEDS {
        let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
        let mut b = state_with(Market::conservative(0));
        for sk in 1..=TRADERS {
            deposit(&mut b, sk, usd(20_000));
            deposit(&mut b, sk, usd(5_000));
        }
        // the anchored copy: the same state plus empty entries
        let mut a = b.clone();
        let mut empty_keys = Vec::new();
        for (i, sk) in (1..=TRADERS + 2).enumerate() {
            let o = owner_of(sk);
            let mut p = Position::empty(o, 0);
            p.funding_entry = [0, 0, 7, -3_000][i % 4];
            a.positions.insert((o, 0), p);
            empty_keys.push((o, 0u64));
        }
        assert_same_behaviour(&a, &b, "start");

        let mut grid = GRID.len() / 2;
        for step in 0..STEPS {
            let epoch = (step / STEPS_PER_EPOCH) as u64;
            // a random walk on the price grid, with an occasional gap of 8%
            let jump = if rng.below(40) == 0 { 4 } else { 1 };
            grid = (grid + jump + rng.below(2 * jump as u64 + 1) as usize)
                .clamp(2 * jump, GRID.len() - 1 + 2 * jump)
                - 2 * jump;
            let orc = oracles.at(epoch, grid);
            let op = random_op(&mut rng, &b, orc);
            let had_empty = a.positions.values().filter(|p| p.is_empty()).count();
            let ra = a.apply_op(&op);
            let rb = b.apply_op(&op);
            let ctx = format!("seed {seed} step {step} op {op:?}");
            assert_eq!(
                ra.is_ok(),
                rb.is_ok(),
                "outcome differs: {ctx} {ra:?} {rb:?}"
            );
            if let (Ok(x), Ok(y)) = (&ra, &rb) {
                assert_eq!(x, y, "outputs differ: {ctx}");
                ops_ok += 1;
            }
            assert_same_behaviour(&a, &b, &ctx);
            assert!(no_empty_entries(&b), "an empty entry was stored: {ctx}");
            assert!(
                a.positions
                    .iter()
                    .all(|(k, p)| !p.is_empty() || empty_keys.contains(k)),
                "a new empty entry was stored: {ctx}"
            );
            if a.positions.values().filter(|p| p.is_empty()).count() < had_empty {
                touched_empty += 1;
            }
            assert!(a.conservation_holds() && b.conservation_holds(), "{ctx}");
            if b.mode == Mode::CloseOnly && rng.below(8) == 0 {
                a.mode = Mode::Normal;
                b.mode = Mode::Normal;
            }
        }
        // once every anchored empty entry is gone, the two roots agree
        let mut stripped = a.clone();
        stripped.positions.retain(|_, p| !p.is_empty());
        for p in stripped
            .positions
            .values_mut()
            .chain(b.positions.values_mut())
        {
            if p.size == 0 {
                p.funding_entry = 0;
                p.entry_price = 0;
            }
        }
        assert_eq!(stripped.state_root(), b.state_root(), "seed {seed}");
    }
    // the sessions really exercised the engine and the anchored entries
    assert!(
        ops_ok > (SEEDS as usize * STEPS) / 4,
        "{ops_ok} ops applied"
    );
    assert!(
        touched_empty > 0,
        "no anchored empty entry was ever touched"
    );
}

// --- maintenance boundary at the band edge ------------------------------------

/// A coherent market drawn at random: `0 < mmr < imr`, a positive fill band `d`
/// and a taker fee `f` with `d·RATE_SCALE + f·(RATE_SCALE + d) < mmr·RATE_SCALE`.
fn random_market(rng: &mut Rng) -> Market {
    let mmr = 1_000 + rng.below(200_000) as i128; // 0.1% .. 20.1%
    let d = 1 + rng.below(mmr as u64 - 1) as i128;
    let f_cap = ((mmr - d) * RATE_SCALE - 1) / (RATE_SCALE + d);
    let f = if f_cap > 0 {
        rng.below(f_cap as u64 + 1) as i128
    } else {
        0
    };
    let mut m = Market::conservative(0);
    m.maintenance_margin_ratio = mmr;
    m.initial_margin_ratio = mmr + 1 + rng.below(300_000) as i128;
    m.liquidation_fee_ratio = mmr / 2;
    m.max_fill_deviation_ratio = d;
    m.taker_fee_ratio = f;
    m.maker_rebate_ratio = 0;
    m.treasury_fee_ratio = 0;
    assert!(m.is_coherent(), "{m:?}");
    m
}

fn random_magnitude(rng: &mut Rng) -> i128 {
    match rng.below(4) {
        0 => 1 + rng.below(1_000) as i128,
        1 => 1 + rng.below(SIZE_SCALE as u64) as i128,
        2 => 1 + rng.below(100 * SIZE_SCALE as u64) as i128,
        _ => 1 + rng.below(10_000 * SIZE_SCALE as u64) as i128,
    }
}

/// A position whose equity is exactly its maintenance requirement at `mark`.
fn at_maintenance_boundary(
    rng: &mut Rng,
    m: &Market,
    mark: i128,
    idx: i128,
    owner: PubKey,
) -> Position {
    let mag = random_magnitude(rng);
    let size = if rng.below(2) == 0 { mag } else { -mag };
    let entry = mark / 2 + (rng.next() as i128).rem_euclid(mark);
    let mut p = Position {
        owner,
        market_id: 0,
        size,
        entry_price: entry,
        collateral: 0,
        funding_entry: if idx == 0 {
            0
        } else {
            idx - (rng.next() % 2_000_000) as i128 + 1_000_000
        },
    };
    let mm = p.maintenance_required(m, mark).unwrap();
    p.collateral = mm - p.unrealized_pnl(mark).unwrap() + p.funding_owed(idx).unwrap();
    assert_eq!(p.equity(mark, idx), Some(mm));
    p
}

/// The fill price at the band edge that is adverse for closing `size`.
fn adverse_edge(m: &Market, mark: i128, size: i128) -> i128 {
    let edge = mark * m.max_fill_deviation_ratio / RATE_SCALE;
    let price = if size > 0 { mark - edge } else { mark + edge };
    assert!(abs(price - mark) * RATE_SCALE <= m.max_fill_deviation_ratio * mark);
    price
}

/// Maintenance margin rounds up and never sits below the exact requirement, so a
/// position at its maintenance boundary can always close in full at the band edge,
/// taker fee included, without leaving negative collateral. The postcondition the
/// fill checks and the liquidation test agree exactly at that boundary.
#[test]
fn a_position_at_its_maintenance_boundary_can_always_close_in_full() {
    let mut rng = Rng(0x5EC0_22B0_0DA7_A5E7);
    let mut rounded = 0usize;
    for i in 0..20_000 {
        let m = random_market(&mut rng);
        let mark = 1_000_000 + rng.below(20_000_000_000_000) as i128; // $0.01 .. $200k
        let idx = if rng.below(2) == 0 {
            0
        } else {
            (rng.next() % 2_000_000_000) as i128 - 1_000_000_000
        };
        let p = at_maintenance_boundary(&mut rng, &m, mark, idx, word_u64(1));
        let mm = p.maintenance_required(&m, mark).unwrap();

        // never below the exact requirement, and at most two micro-USD above the
        // floor-rounded value
        let exact = abs(p.size) * mark * m.maintenance_margin_ratio;
        assert!(mm * SIZE_SCALE * (PRICE_SCALE / QUOTE_SCALE) * RATE_SCALE >= exact);
        let floor = apply_rate(p.notional(mark).unwrap(), m.maintenance_margin_ratio).unwrap();
        assert!(mm >= 1 && mm <= floor + 2, "sample {i}: {mm} vs {floor}");
        if mm != floor {
            rounded += 1;
        }
        let im = p.initial_required(&m, mark).unwrap();
        assert!(im >= mm && im >= MIN_INITIAL_MARGIN, "sample {i}");

        // the boundary: exactly compliant, one micro-USD less is liquidatable
        assert_eq!(p.check_maintenance_margin(&m, mark, idx), Ok(()));
        assert!(!p.is_liquidatable(&m, mark, idx));
        let mut short_by_one = p;
        short_by_one.collateral -= 1;
        assert_eq!(
            short_by_one.check_maintenance_margin(&m, mark, idx),
            Err(RiskError::InsufficientMargin)
        );
        assert!(short_by_one.is_liquidatable(&m, mark, idx));

        // the closing leg, staged as the engine stages a taker's fill
        let price = adverse_edge(&m, mark, p.size);
        let mut leg = p;
        leg.apply_fill(-p.size, price, idx).unwrap();
        let fee = apply_rate(
            notional_quote(abs(p.size), price).unwrap(),
            m.taker_fee_ratio,
        )
        .unwrap();
        leg.collateral -= fee;
        assert_eq!(leg.size, 0);
        assert!(
            leg.collateral >= 0,
            "sample {i}: closing from the boundary left {} ({p:?}, {m:?}, mark {mark})",
            leg.collateral
        );
    }
    assert!(
        rounded > 1_000,
        "rounding mattered in only {rounded} samples"
    );
}

/// The same property through the engine's fill, with signed transcripts.
#[test]
fn a_position_at_its_maintenance_boundary_closes_through_the_engine() {
    let mut rng = Rng(0x0B0D_A121_E5ED_6E01);
    let (a, b) = (owner_of(1), owner_of(2));
    for _ in 0..40 {
        let m = random_market(&mut rng);
        let mark = 1_000_000 + rng.below(20_000_000_000_000) as i128;
        let mut s = state_with(m);
        let p = at_maintenance_boundary(&mut rng, &m, mark, 0, a);
        let mut counter = Position::empty(b, 0);
        counter.size = -p.size;
        counter.entry_price = p.entry_price;
        counter.collateral = i128::MAX / 4;
        s.positions.insert((a, 0), p);
        s.positions.insert((b, 0), counter);
        let side = if p.size > 0 { Side::Sell } else { Side::Buy };
        let price = adverse_edge(&m, mark, p.size);
        let op = fill_with(a, b, side, abs(p.size), price, oracle_raw(mark, T0));
        s.apply_op(&op)
            .unwrap_or_else(|e| panic!("refused: {e:?} ({p:?}, {m:?}, mark {mark})"));
        match s.position(&a, 0) {
            None => {}
            Some(left) => assert!(left.size == 0 && left.collateral > 0),
        }
    }
}

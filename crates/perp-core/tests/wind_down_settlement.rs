//! The wind-down settlement (`SettleAll`), the prices it uses, and deposits in
//! close-only.
//!
//! * Every op that carries a validated oracle price records it for its market
//!   (`FundingState::last_price`): `Fill`, `Liquidate` and `Unbind` always;
//!   `AccrueFunding` when it changed the funding state, when the recorded price
//!   is from an earlier refresh epoch, or while the system is close-only. A
//!   refused op records nothing, and an older transcript never moves the recorded
//!   price back.
//! * `SettleAll` closes open positions at that price, so what the clearing pool
//!   holds for the open positions reaches them. The pool's positive balance
//!   covers deficits before the insurance fund and the treasury do, and what the
//!   three still hold leaves as one withdrawal to the wind-down recipient, with
//!   the next withdrawal nonce.
//! * `SettleAll` creates no value (the value inside before it equals the value
//!   inside after it plus the payout) and is atomic, and after it the phase-2
//!   exits drain the vault exactly.
//! * No deposit is credited while the system is close-only.

use k256::ecdsa::SigningKey;
use perp_core::commitment::{batch_time_ms, derive_roots};
use perp_core::engine::{BatchOp, WithdrawalOut};
use perp_core::fixed::{PRICE_SCALE, QUOTE_SCALE, SIZE_SCALE};
use perp_core::funding::{FundingState, PRICE_REFRESH_MS};
use perp_core::hash::{Digest, Keccak256};
use perp_core::merkle::{verify, withdrawal_leaf};
use perp_core::note::{owner_from_spend_key, Note, PubKey};
use perp_core::oracle::{oracle_digest, OracleSig, OracleTranscript};
use perp_core::order::{BatchManifest, Side};
use perp_core::position::Position;
use perp_core::state::Mode;
use perp_core::{DefaultState, EngineError, Market};

const TREE_DEPTH: u8 = 20;
const T0: u64 = 1_700_000_000_000;
const RECIPIENT: [u8; 20] = [0x5E; 20];

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

/// A signed market-0 transcript at `price_usd`, published at `publish_ms`.
fn oracle(price_usd: i128, publish_ms: u64) -> OracleTranscript {
    let price = price_usd * PRICE_SCALE;
    let confidence = price / 10_000; // 0.01%
    let d = oracle_digest(0, price, publish_ms, confidence, price);
    OracleTranscript {
        price,
        publish_time_ms: publish_ms,
        confidence,
        backup_twap: price,
        signature: OracleSig::sign(&oracle_key(), &d),
    }
}

fn state_with(mut m: Market) -> DefaultState {
    m.oracle_pubkey = oracle_addr();
    let mut s = DefaultState::new(TREE_DEPTH);
    s.add_market(m);
    s
}

/// The deposit crediting `amount` to owner `sk` at the next L1 index, and the
/// commitment of the note it mints.
fn deposit_op(s: &DefaultState, sk: u8, amount: i128) -> (BatchOp, Digest) {
    let owner = owner_of(sk);
    let mut blinding = [sk; 32];
    blinding[..8].copy_from_slice(&s.consumed_deposit_count.to_le_bytes());
    let cm = Note::new(owner, 0, amount, blinding).commitment::<Keccak256>();
    let op = BatchOp::Deposit {
        owner,
        asset_id: 0,
        amount,
        blinding,
        from: [sk; 20],
        deposit_id: s.consumed_deposit_count,
        deposit_blind: [0xDB; 32],
    };
    (op, cm)
}

fn deposit(s: &mut DefaultState, sk: u8, amount: i128) -> Digest {
    let (op, cm) = deposit_op(s, sk, amount);
    s.apply_batch(&[op]).expect("deposit");
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

fn fill_at(
    taker: u8,
    maker: u8,
    side: Side,
    size: i128,
    price_usd: i128,
    oracle: OracleTranscript,
    now_ms: u64,
) -> BatchOp {
    BatchOp::Fill {
        taker: owner_of(taker),
        maker: owner_of(maker),
        market_id: 0,
        taker_side: side,
        size,
        price: price_usd * PRICE_SCALE,
        oracle,
        now_ms,
    }
}

fn fill(taker: u8, maker: u8, side: Side, size: i128, price_usd: i128, now: u64) -> BatchOp {
    fill_at(
        taker,
        maker,
        side,
        size,
        price_usd,
        oracle(price_usd, now),
        now,
    )
}

/// A funding tick with the mark `mark_bps` basis points away from the index.
fn tick(index_usd: i128, mark_bps: i128, now: u64) -> BatchOp {
    let index = index_usd * PRICE_SCALE;
    BatchOp::AccrueFunding {
        market_id: 0,
        mark: index + index * mark_bps / 10_000,
        oracle: oracle(index_usd, now),
        now_ms: now,
    }
}

fn unbind(sk: u8, amount: i128, price_usd: i128, now: u64) -> BatchOp {
    let mut blinding = [0xB1; 32];
    blinding[0] = sk;
    blinding[1..9].copy_from_slice(&now.to_le_bytes());
    BatchOp::Unbind {
        owner: owner_of(sk),
        market_id: 0,
        amount,
        blinding,
        oracle: oracle(price_usd, now),
        now_ms: now,
    }
}

fn liquidate(sk: u8, price_usd: i128, now: u64) -> BatchOp {
    BatchOp::Liquidate {
        owner: owner_of(sk),
        market_id: 0,
        oracle: oracle(price_usd, now),
        now_ms: now,
    }
}

fn withdraw(sk: u8, cm: Digest, to: Option<[u8; 20]>, nonce: u64) -> BatchOp {
    BatchOp::Withdraw {
        note_commitment: cm,
        spend_key: [sk; 32],
        to,
        nonce,
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

fn collateral(s: &DefaultState, sk: u8) -> i128 {
    s.position(&owner_of(sk), 0).map_or(0, |p| p.collateral)
}

/// What the users hold: all position collateral and all unspent notes.
fn claims(s: &DefaultState) -> i128 {
    s.positions_collateral().unwrap() + s.notes_value().unwrap()
}

fn reserves(s: &DefaultState) -> (i128, i128, i128) {
    (s.vault_pool, s.insurance_fund, s.treasury)
}

/// Phase 2: every position and every note of owners `1..=max_sk` leaves through
/// the wind-down exits, one owner per batch, each withdrawal carrying the next
/// nonce. Returns the withdrawals.
fn exit_all(s: &mut DefaultState, max_sk: u8) -> Vec<WithdrawalOut> {
    let mut leaves = Vec::new();
    for sk in 1..=max_sk {
        let owner = owner_of(sk);
        let mut nonce = s.last_withdrawal_nonce;
        let mut ops = Vec::new();
        if let Some(p) = s.position(&owner, 0) {
            let amount = p.collateral;
            let mut blinding = [0xE7; 32];
            blinding[0] = sk;
            blinding[1..9].copy_from_slice(&s.tree.len().to_le_bytes());
            ops.push(BatchOp::WindDownUnbind {
                owner,
                market_id: 0,
                amount,
                blinding,
            });
            nonce += 1;
            ops.push(BatchOp::WindDownWithdraw {
                note_commitment: Note::new(owner, 0, amount, blinding).commitment::<Keccak256>(),
                spend_key: [sk; 32],
                to: Some([sk; 20]),
                nonce,
            });
        }
        for (cm, _) in s.notes.iter().filter(|(_, n)| n.owner == owner) {
            nonce += 1;
            ops.push(BatchOp::WindDownWithdraw {
                note_commitment: *cm,
                spend_key: [sk; 32],
                to: Some([sk; 20]),
                nonce,
            });
        }
        if ops.is_empty() {
            continue;
        }
        let out = s.apply_batch(&ops).expect("phase-2 exit");
        leaves.extend(out.withdrawals);
    }
    leaves
}

/// After every exit, nothing is left inside and the vault is drained exactly.
fn assert_drained(s: &DefaultState) {
    assert!(s.positions.is_empty(), "{:?}", s.positions);
    assert!(s.notes.is_empty());
    assert_eq!(reserves(s), (0, 0, 0));
    assert_eq!(s.internal_value(), Some(0));
    assert_eq!(
        s.external_in, s.external_out,
        "the exits drain the vault exactly"
    );
}

// --- settlement at the last recorded price ------------------------------------

/// A long and a short of 1 BTC from $100k; the long then sells to a third trader
/// at $99k. The long realizes −$1,000 into the clearing pool, and the two open
/// positions (short from $100k, long from $99k) are together owed exactly that
/// $1,000 at any common price. Settlement pays it to them, and every exit then
/// drains the vault exactly.
#[test]
fn the_pool_balance_owed_to_open_positions_reaches_them_at_settlement() {
    let mut s = state_with(Market::conservative(0));
    s.set_wind_down_recipient(RECIPIENT);
    for sk in 1..=3 {
        fund(&mut s, sk, usd(20_000));
    }
    s.apply_op(&fill(1, 2, Side::Buy, SIZE_SCALE, 100_000, T0))
        .unwrap();
    s.apply_op(&fill(1, 3, Side::Sell, SIZE_SCALE, 99_000, T0 + 1_000))
        .unwrap();
    assert_eq!(s.vault_pool, usd(1_000));
    assert_eq!(s.funding[&0].last_price, 99_000 * PRICE_SCALE);
    let claims_before = claims(&s);

    let out = s.apply_batch(&[BatchOp::SettleAll]).unwrap();

    assert!(out.withdrawals.is_empty(), "no fees, so no reserve is left");
    assert_eq!(reserves(&s), (0, 0, 0));
    assert_eq!(claims(&s), claims_before + usd(1_000));
    assert_eq!(collateral(&s, 1), usd(19_000));
    assert_eq!(
        collateral(&s, 2),
        usd(21_000),
        "short from $100k, closed at $99k"
    );
    assert_eq!(
        collateral(&s, 3),
        usd(20_000),
        "long from $99k, closed at $99k"
    );
    assert!(s.positions.values().all(|p| p.size == 0));
    assert_eq!(s.mode, Mode::CloseOnly);
    assert!(s.conservation_holds());

    let leaves = exit_all(&mut s, 3);
    assert_eq!(leaves.len(), 3);
    assert_drained(&s);
}

/// The fee reserves left after settlement leave as one withdrawal leaf to the
/// recipient, with the nonce after the last withdrawal; the phase-1 withdrawals
/// root is that one leaf, and phase 2 continues above its nonce.
#[test]
fn the_reserves_left_leave_as_one_leaf_to_the_recipient_with_the_next_nonce() {
    let mut s = state_with(Market::with_fees_treasury(0, 10, 2, 5));
    s.set_wind_down_recipient(RECIPIENT);
    fund(&mut s, 1, usd(20_000));
    fund(&mut s, 2, usd(20_000));
    s.apply_op(&fill(1, 2, Side::Buy, SIZE_SCALE / 2, 100_000, T0))
        .unwrap();
    let cm = deposit(&mut s, 3, usd(500));
    s.apply_batch(&[withdraw(3, cm, Some([3; 20]), 7)]).unwrap();
    assert_eq!(s.last_withdrawal_nonce, 7);
    // $50,000 notional: $15 to insurance and $25 to the treasury
    assert_eq!(reserves(&s), (0, usd(15), usd(25)));
    let before = s.internal_value().unwrap();

    let ops = vec![BatchOp::SettleAll];
    let m = manifest_for(&s, &ops);
    let roots = derive_roots(&mut s, &ops, &m).unwrap();

    assert_eq!(roots.wind_down_phase, 1);
    let leaf = withdrawal_leaf(&RECIPIENT, usd(40) as u128, 8);
    assert_eq!(roots.withdrawals_root, leaf, "a one-leaf root is the leaf");
    assert!(verify(roots.withdrawals_root, leaf, &[]));
    assert_eq!(s.last_withdrawal_nonce, 8);
    assert_eq!(reserves(&s), (0, 0, 0));
    assert_eq!(s.internal_value().unwrap() + usd(40), before);
    assert!(s.conservation_holds());

    // phase 2 may not reuse the payout's nonce
    let owner = owner_of(1);
    let amount = collateral(&s, 1);
    let blinding = [0x77; 32];
    let cm = Note::new(owner, 0, amount, blinding).commitment::<Keccak256>();
    let reuse = [
        BatchOp::WindDownUnbind {
            owner,
            market_id: 0,
            amount,
            blinding,
        },
        BatchOp::WindDownWithdraw {
            note_commitment: cm,
            spend_key: [1; 32],
            to: Some([1; 20]),
            nonce: 8,
        },
    ];
    assert_eq!(
        s.clone().apply_batch(&reuse).unwrap_err(),
        EngineError::WithdrawalNonceNotIncreasing
    );
    let leaves = exit_all(&mut s, 2);
    assert_eq!(leaves.iter().map(|w| w.nonce).collect::<Vec<_>>(), [9, 10]);
    assert_drained(&s);
}

#[test]
fn without_a_recipient_the_reserves_stay_and_no_leaf_is_emitted() {
    let mut s = state_with(Market::with_fees_treasury(0, 10, 2, 5));
    fund(&mut s, 1, usd(20_000));
    fund(&mut s, 2, usd(20_000));
    s.apply_op(&fill(1, 2, Side::Buy, SIZE_SCALE / 2, 100_000, T0))
        .unwrap();
    let out = s.apply_batch(&[BatchOp::SettleAll]).unwrap();
    assert!(out.withdrawals.is_empty());
    assert_eq!(s.last_withdrawal_nonce, 0);
    assert_eq!(reserves(&s), (0, usd(15), usd(25)));
    assert!(s.conservation_holds());
}

// --- price recording ---------------------------------------------------------

#[test]
fn fills_unbinds_and_liquidations_record_their_validated_price() {
    let mut s = state_with(Market::conservative(0));
    fund(&mut s, 1, usd(10_000));
    fund(&mut s, 2, usd(20_000));
    let recorded = |s: &DefaultState| {
        let f = s.funding[&0];
        (f.last_price / PRICE_SCALE, f.last_price_ms)
    };
    assert_eq!(recorded(&s), (0, 0));
    s.apply_op(&fill(1, 2, Side::Buy, SIZE_SCALE, 100_000, T0))
        .unwrap();
    assert_eq!(recorded(&s), (100_000, T0));
    s.apply_op(&unbind(2, usd(1_000), 101_000, T0 + 1_000))
        .unwrap();
    assert_eq!(recorded(&s), (101_000, T0 + 1_000));
    // at $94k the long's equity ($4,000) is below maintenance ($4,700)
    s.apply_op(&liquidate(1, 94_000, T0 + 2_000)).unwrap();
    assert_eq!(recorded(&s), (94_000, T0 + 2_000));
    assert_eq!(s.mode, Mode::Normal);
}

#[test]
fn a_refused_op_records_no_price() {
    let mut s = state_with(Market::conservative(0));
    fund(&mut s, 1, usd(10_000));
    fund(&mut s, 2, usd(20_000));
    s.apply_op(&fill(1, 2, Side::Buy, SIZE_SCALE, 100_000, T0))
        .unwrap();
    let root = s.state_root();
    let funding = s.funding[&0];
    let t = T0 + 1_000;
    for (op, err) in [
        (
            fill_at(1, 2, Side::Buy, SIZE_SCALE, 100_000, oracle(110_000, t), t),
            EngineError::FillPriceOutOfBand,
        ),
        (liquidate(1, 99_000, t), EngineError::NotLiquidatable),
        (
            unbind(2, usd(30_000), 99_000, t),
            EngineError::Risk {
                source: perp_core::position::RiskError::InsufficientMargin,
                leg: None,
            },
        ),
    ] {
        assert_eq!(s.apply_op(&op), Err(err), "{op:?}");
        assert_eq!(s.funding[&0], funding, "{op:?}");
        assert_eq!(s.state_root(), root, "{op:?}");
    }
}

#[test]
fn an_older_transcript_never_moves_the_recorded_price_back() {
    let mut s = state_with(Market::conservative(0));
    fund(&mut s, 1, usd(20_000));
    fund(&mut s, 2, usd(20_000));
    s.apply_op(&fill(1, 2, Side::Buy, SIZE_SCALE / 10, 100_000, T0 + 5_000))
        .unwrap();
    // accepted (still fresh at T0 + 6s), but published before the recorded price
    s.apply_op(&fill_at(
        1,
        2,
        Side::Buy,
        SIZE_SCALE / 10,
        101_000,
        oracle(101_000, T0 + 1_000),
        T0 + 6_000,
    ))
    .unwrap();
    let f = s.funding[&0];
    assert_eq!(
        (f.last_price, f.last_price_ms),
        (100_000 * PRICE_SCALE, T0 + 5_000)
    );
}

#[test]
fn a_tick_records_the_price_when_it_changes_state_when_a_refresh_is_due_or_in_close_only() {
    let mut s = state_with(Market::conservative(0));
    // a market that never recorded a price: idle ticks stay root-neutral, even
    // across refresh epochs
    let root = s.state_root();
    for t in [T0, T0 + PRICE_REFRESH_MS, T0 + 3 * PRICE_REFRESH_MS] {
        s.apply_op(&tick(100_000, 0, t)).unwrap();
    }
    assert_eq!(s.state_root(), root);
    assert_eq!(s.funding[&0], FundingState::default());

    // a fill records a price
    let start = T0 + 4 * PRICE_REFRESH_MS;
    let epoch_end = (start / PRICE_REFRESH_MS + 1) * PRICE_REFRESH_MS;
    fund(&mut s, 1, usd(20_000));
    fund(&mut s, 2, usd(20_000));
    s.apply_op(&fill(1, 2, Side::Buy, SIZE_SCALE / 10, 100_000, start))
        .unwrap();
    let recorded = |s: &DefaultState| {
        let f = s.funding[&0];
        (f.last_price / PRICE_SCALE, f.last_price_ms)
    };
    assert_eq!(recorded(&s), (100_000, start));

    // idle ticks within the same epoch change nothing
    let root = s.state_root();
    s.apply_op(&tick(100_500, 0, start + 1_000)).unwrap();
    s.apply_op(&tick(100_700, 0, epoch_end - 1)).unwrap();
    assert_eq!(s.state_root(), root);
    assert_eq!(recorded(&s), (100_000, start));

    // the first idle tick of the next epoch refreshes it, and only that one
    s.apply_op(&tick(102_000, 0, epoch_end)).unwrap();
    assert_eq!(recorded(&s), (102_000, epoch_end));
    assert_ne!(s.state_root(), root);
    let root = s.state_root();
    s.apply_op(&tick(102_500, 0, epoch_end + 1_000)).unwrap();
    assert_eq!(s.state_root(), root);

    // a tick that changes the funding state records its index
    s.apply_op(&tick(103_000, 100, epoch_end + 2_000)).unwrap();
    assert_ne!(s.funding[&0].rate, 0);
    assert_eq!(recorded(&s), (103_000, epoch_end + 2_000));
    s.apply_op(&tick(103_500, 0, epoch_end + 3_000)).unwrap();
    assert_eq!(s.funding[&0].rate, 0);
    assert_eq!(recorded(&s), (103_500, epoch_end + 3_000));

    // in close-only every tick records, even one that changes nothing else
    s.apply_op(&BatchOp::EnterCloseOnly).unwrap();
    let before = s.funding[&0];
    s.apply_op(&tick(104_000, 0, epoch_end + 4_000)).unwrap();
    assert_eq!(recorded(&s), (104_000, epoch_end + 4_000));
    let after = s.funding[&0];
    assert_eq!(
        (
            after.cumulative_index,
            after.last_update_ms,
            after.rate,
            after.remainder
        ),
        (
            before.cumulative_index,
            before.last_update_ms,
            before.rate,
            before.remainder
        ),
        "only the recorded price moved"
    );
}

/// The value of owner `sk`'s notes (a haircut note is reissued under a new
/// commitment).
fn note_value(s: &DefaultState, sk: u8) -> i128 {
    s.notes
        .values()
        .filter(|n| n.owner == owner_of(sk))
        .map(|n| n.amount)
        .sum()
}

/// In close-only the last recorded price follows the oracle, so a settlement
/// after a trip uses the latest committed price rather than the trip's.
#[test]
fn after_a_trip_ticks_keep_the_settlement_price_current() {
    let (tripped, winner) = tripped_with_note(usd(4_000));
    let mut s = tripped.clone();
    let t = T0 + 10_000;
    s.apply_op(&tick(74_000, 0, t)).unwrap();
    let f = s.funding[&0];
    assert_eq!((f.last_price, f.last_price_ms), (74_000 * PRICE_SCALE, t));

    s.apply_batch(&[BatchOp::SettleAll]).unwrap();

    // At $74k the short gains $26k and the pool keeps $4k, which covers part of
    // the $10k parked on the loser; the other $6k is a 20% haircut of the
    // short's $26k and the $4k note.
    assert_eq!(collateral(&s, winner), usd(20_800));
    assert_eq!(note_value(&s, 3), usd(3_200));
    assert_eq!(claims(&s), s.external_in);
    assert!(s.conservation_holds());

    // settled at the trip's $70k instead, the pool would keep nothing and the
    // note would carry more of the debt
    let mut at_trip = tripped;
    at_trip.apply_batch(&[BatchOp::SettleAll]).unwrap();
    assert!(note_value(&at_trip, 3) < usd(3_200));
}

// --- no deposit is credited in close-only ------------------------------------

/// Trader 1 long and trader 2 short 1 BTC from $100k with $10k each, no
/// insurance, and trader 3 holding an unbound note of `note` (none when 0).
/// Liquidating the long at $70k leaves $20k of debt; auto-deleverage claws the
/// short's $10k of collateral, the other $10k stays parked on the closed long,
/// and the system trips to close-only. Returns the short's key.
fn tripped_with_note(note: i128) -> (DefaultState, u8) {
    let mut s = state_with(Market::conservative(0));
    fund(&mut s, 1, usd(10_000));
    fund(&mut s, 2, usd(10_000));
    if note > 0 {
        deposit(&mut s, 3, note);
    }
    s.apply_op(&fill(1, 2, Side::Buy, SIZE_SCALE, 100_000, T0))
        .unwrap();
    s.apply_op(&liquidate(1, 70_000, T0 + 1_000)).unwrap();
    assert_eq!(s.mode, Mode::CloseOnly);
    assert_eq!(collateral(&s, 1), -usd(10_000));
    assert_eq!(collateral(&s, 2), 0);
    (s, 2)
}

fn assert_deposit_refused(s: &mut DefaultState) {
    let root = s.state_root();
    let count = s.consumed_deposit_count;
    let (op, _) = deposit_op(s, 9, usd(50_000));
    assert_eq!(s.apply_op(&op), Err(EngineError::CloseOnly));
    assert_eq!(s.state_root(), root, "a refused deposit changes nothing");
    assert_eq!(
        s.consumed_deposit_count, count,
        "the L1 deposit stays unconsumed"
    );
}

#[test]
fn no_deposit_is_credited_while_close_only() {
    // entered by the mode op
    let mut s = state_with(Market::conservative(0));
    fund(&mut s, 1, usd(1_000));
    s.apply_op(&BatchOp::EnterCloseOnly).unwrap();
    assert_deposit_refused(&mut s);

    // tripped by an uncovered liquidation: a deposit can not join the haircut
    // base of the later settlement
    let (mut s, winner) = tripped_with_note(0);
    assert_deposit_refused(&mut s);
    let external_in = s.external_in;
    s.apply_batch(&[BatchOp::SettleAll]).unwrap();
    // the short realizes $30k at $70k and alone absorbs the parked $10k
    assert_eq!(collateral(&s, winner), usd(20_000));
    assert_eq!(claims(&s), external_in);

    // and after the settlement
    assert_deposit_refused(&mut s);
    let leaves = exit_all(&mut s, 2);
    assert_eq!(leaves.len(), 1);
    assert_drained(&s);
}

// --- atomicity ---------------------------------------------------------------

fn assert_settlement_refused(mut s: DefaultState, err: EngineError, ctx: &str) {
    assert!(s.conservation_holds(), "{ctx}: fixture");
    let root = s.state_root();
    let leaves = s.tree.len();
    assert_eq!(s.apply_batch(&[BatchOp::SettleAll]), Err(err), "{ctx}");
    assert_eq!(
        s.state_root(),
        root,
        "{ctx}: a refused settlement changes nothing"
    );
    assert_eq!(s.tree.len(), leaves, "{ctx}");
    assert_eq!(s.mode, Mode::Normal, "{ctx}");
}

fn bare() -> DefaultState {
    let mut s = DefaultState::new(4);
    s.add_market(Market::conservative(0));
    s
}

fn put(s: &mut DefaultState, sk: u8, size: i128, entry: i128, collateral: i128) {
    let owner = owner_of(sk);
    s.positions.insert(
        (owner, 0),
        Position {
            owner,
            market_id: 0,
            size,
            entry_price: entry,
            collateral,
            funding_entry: 0,
        },
    );
}

fn add_note(s: &mut DefaultState, sk: u8, amount: i128) {
    let note = Note::new(owner_of(sk), 0, amount, [sk; 32]);
    let cm = note.commitment::<Keccak256>();
    s.tree.append(cm).unwrap();
    s.notes.insert(cm, note);
}

#[test]
fn a_refused_settlement_changes_nothing() {
    // the claims are smaller than the deficit
    let mut s = bare();
    put(&mut s, 1, 0, 0, -usd(100));
    add_note(&mut s, 2, usd(40));
    s.external_out = usd(60);
    assert_settlement_refused(s, EngineError::WindDownInsolvent, "insolvent");

    // the close overflows
    let mut s = bare();
    put(&mut s, 1, i128::MAX / 4, PRICE_SCALE, usd(10));
    s.funding.get_mut(&0).unwrap().last_price = i128::MAX / 4;
    s.funding.get_mut(&0).unwrap().last_price_ms = 1;
    s.external_in = usd(10);
    assert_settlement_refused(s, EngineError::Overflow, "close overflow");

    // the payout would need a nonce past the end of the range
    let mut s = bare();
    s.set_wind_down_recipient(RECIPIENT);
    s.insurance_fund = usd(5);
    s.external_in = usd(5);
    s.last_withdrawal_nonce = u64::MAX;
    assert_settlement_refused(s, EngineError::Overflow, "nonce exhausted");

    // a haircut note can not be reissued into a full tree (capacity 16)
    let mut s = bare();
    for sk in 1..=16 {
        add_note(&mut s, sk, usd(10));
    }
    s.vault_pool = -usd(16);
    s.external_in = usd(160 - 16);
    assert_settlement_refused(s, EngineError::Overflow, "tree full");

    // a reserve the engine never drives negative is refused, not normalized
    let mut s = bare();
    put(&mut s, 1, 0, 0, usd(10));
    s.treasury = -usd(1);
    s.external_in = usd(9);
    assert_settlement_refused(s, EngineError::WindDownInsolvent, "negative reserve");
}

// --- the invariants, over random sessions --------------------------------------

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    /// Uniform in `[-n, n]`.
    fn signed(&mut self, n: i128) -> i128 {
        (self.below(2 * n as u64 + 1) as i128) - n
    }
}

const TRADERS: u8 = 4;

fn note_of(rng: &mut Rng, s: &DefaultState, sk: u8) -> Option<Digest> {
    let mine: Vec<Digest> = s
        .notes
        .iter()
        .filter(|(_, n)| n.owner == owner_of(sk))
        .map(|(cm, _)| *cm)
        .collect();
    (!mine.is_empty()).then(|| mine[rng.below(mine.len() as u64) as usize])
}

/// The settlement worked out independently of the engine's staging: close each
/// open position at its market's recorded price (entry when none), add up the
/// debts and the claims, cover the debt from the pool, insurance and treasury,
/// and take the rest from the claims. Returns (claims after, payout, haircut).
fn settle_by_hand(s: &DefaultState) -> (i128, i128, i128) {
    let mut pool = s.vault_pool;
    let (mut debt, mut position_claims) = (0i128, 0i128);
    for p in s.positions.values() {
        let mut q = *p;
        let f = s.funding[&p.market_id];
        if q.size != 0 {
            let price = if f.last_price > 0 {
                f.last_price
            } else {
                q.entry_price
            };
            let (realized, paid) = q.apply_fill(-q.size, price, f.cumulative_index).unwrap();
            pool = pool - realized + paid;
        }
        if q.collateral < 0 {
            debt -= q.collateral;
        } else {
            position_claims += q.collateral;
        }
    }
    if pool < 0 {
        debt -= pool;
        pool = 0;
    }
    let reserves = pool + s.insurance_fund + s.treasury;
    let covered = debt.min(reserves);
    let haircut = debt - covered;
    let notes = s.notes_value().unwrap();
    (
        position_claims + notes - haircut,
        reserves - covered,
        haircut,
    )
}

#[test]
fn settlement_creates_no_value_and_every_claim_can_exit() {
    const SESSIONS: u64 = 40;
    const STEPS: usize = 60;
    let (mut paid, mut haircuts, mut moved) = (0, 0, 0);
    for seed in 1..=SESSIONS {
        let mut rng = Rng(seed.wrapping_mul(0xD1B5_4A32_D192_ED03));
        let mut s = state_with(Market::with_fees_treasury(0, 10, 2, 5));
        s.set_wind_down_recipient(RECIPIENT);
        let mut leaves: Vec<WithdrawalOut> = Vec::new();
        for sk in 1..=TRADERS {
            fund(&mut s, sk, usd(3_000 + rng.below(20_000) as i128));
        }
        let mut price = 100_000i128;
        let mut now = T0;
        for step in 0..STEPS {
            now += 1_000;
            // a random walk, with an occasional 15% gap so liquidations leave debt
            let swing = if rng.below(10) == 0 {
                price * 15 / 100
            } else {
                price / 100
            };
            price = (price + rng.signed(swing)).clamp(20_000, 400_000);
            let orc = oracle(price, now);
            let sk = 1 + rng.below(TRADERS as u64) as u8;
            let other = 1 + (sk + rng.below(TRADERS as u64 - 1) as u8) % TRADERS;
            let op = match rng.below(16) {
                0..=5 => {
                    let side = if rng.below(2) == 0 {
                        Side::Buy
                    } else {
                        Side::Sell
                    };
                    let size = (1 + rng.below(50) as i128) * SIZE_SCALE / 100;
                    let px = price + rng.signed(price / 100);
                    fill_at(sk, other, side, size, px, orc, now)
                }
                6..=7 => BatchOp::AccrueFunding {
                    market_id: 0,
                    mark: (price + rng.signed(price / 100)) * PRICE_SCALE,
                    oracle: orc,
                    now_ms: now,
                },
                8..=10 => BatchOp::Liquidate {
                    owner: owner_of(sk),
                    market_id: 0,
                    oracle: orc,
                    now_ms: now,
                },
                11 => {
                    let held = collateral(&s, sk).max(1);
                    let mut blinding = [0xC3; 32];
                    blinding[0] = sk;
                    blinding[1..9].copy_from_slice(&now.to_le_bytes());
                    BatchOp::Unbind {
                        owner: owner_of(sk),
                        market_id: 0,
                        amount: 1 + rng.below(held as u64) as i128,
                        blinding,
                        oracle: orc,
                        now_ms: now,
                    }
                }
                12 => deposit_op(&s, sk, usd(1 + rng.below(5_000) as i128)).0,
                13 => match note_of(&mut rng, &s, sk) {
                    Some(cm) => fund_op(sk, cm),
                    None => continue,
                },
                14 => match note_of(&mut rng, &s, sk) {
                    Some(cm) if rng.below(2) == 0 => withdraw(sk, cm, None, 0),
                    Some(cm) => withdraw(
                        sk,
                        cm,
                        Some([sk; 20]),
                        s.last_withdrawal_nonce + 1 + rng.below(3),
                    ),
                    None => continue,
                },
                _ if rng.below(8) == 0 => BatchOp::EnterCloseOnly,
                _ => continue,
            };
            let ctx = format!("seed {seed} step {step} {op:?}");
            let close_only = s.mode == Mode::CloseOnly;
            let root = s.state_root();
            let result = s.apply_op(&op);
            if close_only && matches!(op, BatchOp::Deposit { .. }) {
                assert_eq!(result, Err(EngineError::CloseOnly), "{ctx}");
                assert_eq!(s.state_root(), root, "{ctx}");
            }
            if let Ok(out) = result {
                leaves.extend(out.withdrawal);
            }
            assert!(s.conservation_holds(), "{ctx}");
        }

        // SettleAll against the hand-worked result
        let ctx = format!("seed {seed}");
        let (claims_after, payout, haircut) = settle_by_hand(&s);
        let value_before = s.internal_value().unwrap();
        let last = s.last_withdrawal_nonce;
        moved += s
            .positions
            .values()
            .filter(|p| p.size != 0 && s.funding[&0].last_price != p.entry_price)
            .count();
        let out = s.apply_batch(&[BatchOp::SettleAll]).expect(&ctx);
        assert_eq!(claims(&s), claims_after, "{ctx}");
        assert_eq!(reserves(&s), (0, 0, 0), "{ctx}: a recipient is set");
        if payout > 0 {
            assert_eq!(
                out.withdrawals,
                [WithdrawalOut {
                    to: RECIPIENT,
                    amount: payout,
                    nonce: last + 1,
                }],
                "{ctx}"
            );
            paid += 1;
        } else {
            assert!(out.withdrawals.is_empty(), "{ctx}");
        }
        haircuts += usize::from(haircut > 0);
        assert_eq!(
            s.internal_value().unwrap() + payout,
            value_before,
            "{ctx}: no value is created"
        );
        assert!(
            s.positions
                .values()
                .all(|p| p.size == 0 && p.collateral > 0),
            "{ctx}"
        );
        assert_eq!(s.mode, Mode::CloseOnly, "{ctx}");
        assert!(s.conservation_holds(), "{ctx}");
        leaves.extend(out.withdrawals);

        // phase 2: every claim leaves, and nothing is left behind
        assert_deposit_refused(&mut s);
        leaves.extend(exit_all(&mut s, TRADERS));
        assert_drained(&s);
        assert!(
            leaves.windows(2).all(|w| w[0].nonce < w[1].nonce),
            "{ctx}: withdrawal nonces strictly increase across all phases"
        );
    }
    // the sessions exercised the interesting cases
    assert!(paid > 0, "no session paid out a reserve");
    assert!(moved > 0, "no position closed away from its entry price");
    assert!(haircuts > 0, "no session needed a haircut");
}

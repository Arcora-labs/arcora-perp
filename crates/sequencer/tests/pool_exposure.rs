//! The audit 2026-11-16 PC-1 scenario, run through the sequencer's own loop
//! (`seal_batch` → maintenance liquidation → `seal_window`), not the engine API.
//!
//! Two colluding accounts open opposite sides of one BTC. The price falls far
//! enough to liquidate the long and keeps falling. Before the fix the short stayed
//! open against the clearing pool and closed later at the lower price: the pair
//! deposited $20,200 and withdrew $43,755, the pool ended $24,500 short, and in
//! `SettleAll` a passive $50,000 account that never traded was left with $35,278.
//! Now the liquidation closes the short with the long, so the pool holds no
//! position, the pair cannot take out more than it put in, and the passive
//! account keeps all of its collateral.

use k256::ecdsa::SigningKey;
use perp_core::engine::BatchOp;
use perp_core::fixed::{PRICE_SCALE, QUOTE_SCALE, SIZE_SCALE};
use perp_core::hash::{word_u64, Keccak256};
use perp_core::market::Market;
use perp_core::note::{owner_from_spend_key, PubKey};
use perp_core::oracle::{oracle_digest, OracleSig, OracleTranscript};
use perp_core::order::{Order, Side, TimeInForce};
use perp_core::position::Position;
use perp_core::{EngineError, Note};
use sequencer::{adl_tag, adl_tag_key, forced_close_tag, EnclaveIdentity, Sequencer};

const PAIR_LONG: u64 = 1;
const PAIR_SHORT: u64 = 2;
const PASSIVE: u64 = 3;
const TAKER: u64 = 4;

fn usd(x: i128) -> i128 {
    x * QUOTE_SCALE
}

fn spend_key(owner: u64) -> [u8; 32] {
    [owner as u8; 32]
}

fn owner_id(owner: u64) -> PubKey {
    owner_from_spend_key::<Keccak256>(&spend_key(owner))
}

fn oracle_key() -> SigningKey {
    SigningKey::from_bytes((&[7u8; 32]).into()).expect("valid dev scalar")
}

fn oracle_addr() -> [u8; 20] {
    let probe = oracle_digest(0, 0, 0, 0, 0);
    OracleSig::sign(&oracle_key(), &probe)
        .recover(&probe)
        .expect("fresh signature recovers")
}

fn oracle(price_usd: i128, now: u64) -> OracleTranscript {
    let price = price_usd * PRICE_SCALE;
    let confidence = 10 * PRICE_SCALE;
    let d = oracle_digest(0, price, now, confidence, price);
    OracleTranscript {
        price,
        publish_time_ms: now,
        confidence,
        backup_twap: price,
        signature: OracleSig::sign(&oracle_key(), &d),
    }
}

fn order(owner: u64, side: Side, size: i128, price_usd: i128, nonce: u64) -> Order {
    Order {
        owner: owner_id(owner),
        market_id: 0,
        side,
        size,
        limit_price: price_usd * PRICE_SCALE,
        tif: TimeInForce::Gtc,
        reduce_only: false,
        nonce,
        expiry_ms: 0,
        ciphertext_commit: word_u64(nonce.wrapping_mul(13)),
    }
}

/// Deposit `amount` for `owner` and bind it to its market-0 position.
fn fund(seq: &mut Sequencer, owner: u64, amount: i128) {
    let o = owner_id(owner);
    let blinding = [0x40 + owner as u8; 32];
    let cm = Note::new(o, 0, amount, blinding).commitment::<Keccak256>();
    let deposit_id = seq.state.consumed_deposit_count;
    seq.apply_atomic(&[
        BatchOp::Deposit {
            owner: o,
            asset_id: 0,
            amount,
            blinding,
            from: [0u8; 20],
            deposit_id,
            deposit_blind: [0u8; 32],
        },
        BatchOp::FundPosition {
            owner: o,
            market_id: 0,
            note_commitment: cm,
            spend_key: spend_key(owner),
        },
    ])
    .expect("deposit and fund");
}

fn position(seq: &Sequencer, owner: u64) -> Position {
    seq.state
        .position(&owner_id(owner), 0)
        .copied()
        .unwrap_or_else(|| Position::empty(owner_id(owner), 0))
}

/// The sum of every market-0 position's size: the clearing pool's implicit
/// position is its negation.
fn net_size(seq: &Sequencer) -> i128 {
    seq.state
        .positions
        .iter()
        .filter(|((_, m), _)| *m == 0)
        .map(|(_, p)| p.size)
        .sum()
}

/// Withdraw what the gateway lets `owner` withdraw from market 0 at `price_usd`:
/// its collateral less the initial margin of what it still holds. Returns the
/// amount, which is zero when nothing is free.
fn withdraw_free(seq: &mut Sequencer, owner: u64, price_usd: i128, now: u64) -> i128 {
    let p = position(seq, owner);
    let market = seq.state.markets[&0];
    let locked = p
        .initial_required(&market, price_usd * PRICE_SCALE)
        .unwrap();
    let amount = p.collateral - locked;
    if amount <= 0 {
        return 0;
    }
    let blinding = [0xD0 + owner as u8; 32];
    let cm = Note::new(owner_id(owner), 0, amount, blinding).commitment::<Keccak256>();
    let nonce = seq.state.last_withdrawal_nonce + 1;
    seq.apply_atomic(&[
        BatchOp::Unbind {
            owner: owner_id(owner),
            market_id: 0,
            amount,
            blinding,
            oracle: oracle(price_usd, now),
            now_ms: now,
        },
        BatchOp::Withdraw {
            note_commitment: cm,
            spend_key: spend_key(owner),
            to: Some([owner as u8; 20]),
            nonce,
        },
    ])
    .expect("the free collateral withdraws");
    amount
}

/// What the scenario observes, amounts in whole dollars. Every assertion prints
/// it, so a failure shows the whole run (the numbers before the fix are in the
/// module documentation).
#[derive(Debug)]
struct Outcome {
    /// The market's net size right after the liquidation, in size units; the
    /// clearing pool's implicit position is its negation.
    net_size_after_liquidation: i128,
    short_size_after_liquidation: i128,
    pair_in: i128,
    pair_out: i128,
    vault_pool: i128,
    external_in: i128,
    external_out: i128,
    settle_all: Result<(), EngineError>,
    passive_after_settle_all: Option<i128>,
}

#[test]
fn audit_1116_pc1_a_liquidation_through_the_sequencer_leaves_the_pool_flat() {
    let mut seq = Sequencer::new(EnclaveIdentity::from_seed([7u8; 32], 1, [0xABu8; 32]), 20);
    let mut market = Market::conservative(0);
    market.oracle_pubkey = oracle_addr();
    seq.add_market(market);
    seq.set_wind_down_recipient([0x5E; 20]);
    seq.set_oracle(0, oracle(100_000, 1_000));
    let pair_in = usd(10_100) * 2;
    fund(&mut seq, PAIR_LONG, usd(10_100));
    fund(&mut seq, PAIR_SHORT, usd(10_100));
    fund(&mut seq, PASSIVE, usd(50_000));
    fund(&mut seq, TAKER, usd(30_000));
    seq.seal_genesis_baseline();

    // The pair opens 1 BTC long against 1 BTC short at $100k.
    seq.seal_batch(
        &[
            order(PAIR_LONG, Side::Buy, SIZE_SCALE, 100_000, 1),
            order(PAIR_SHORT, Side::Sell, SIZE_SCALE, 100_000, 2),
        ],
        1_000,
    );
    assert_eq!(position(&seq, PAIR_LONG).size, SIZE_SCALE);
    assert_eq!(position(&seq, PAIR_SHORT).size, -SIZE_SCALE);

    // $94.5k: the long's equity ($4,600) is under its maintenance margin ($4,725),
    // and the maintenance pass of the next seal liquidates it.
    seq.set_oracle(0, oracle(94_500, 5_000));
    let sealed = seq.seal_batch(&[], 5_000);
    assert_eq!(sealed.liquidation_tags.len(), 1, "the long is liquidated");
    assert_eq!(position(&seq, PAIR_LONG).size, 0);
    assert!(seq.state.conservation_holds());
    let net_size_after_liquidation = net_size(&seq);
    let short_size_after_liquidation = position(&seq, PAIR_SHORT).size;

    // The window that holds the liquidation replays to the live root.
    let w = seq.seal_window();
    assert!(w.ops.iter().any(|o| matches!(o, BatchOp::Liquidate { .. })));
    let derived =
        perp_core::commitment::derive_roots(&mut w.pre_state.clone(), &w.ops, &w.manifest)
            .expect("the window witness replays");
    assert_eq!(derived.new_state_root, seq.state.state_root());

    // The price keeps falling.
    let mut now = 5_000;
    for price in [90_000, 80_000, 70_000] {
        now += 5_000;
        seq.set_oracle(0, oracle(price, now));
        seq.seal_batch(&[], now);
        assert_eq!(net_size(&seq), net_size_after_liquidation, "${price}");
        assert!(seq.state.conservation_holds(), "${price}");
    }

    // The pair's playbook: the short closes whatever it still holds against a
    // third party at the low price, then both withdraw everything they can.
    let short = position(&seq, PAIR_SHORT).size;
    if short < 0 {
        now += 1_000;
        seq.set_oracle(0, oracle(70_000, now));
        seq.seal_batch(
            &[
                order(TAKER, Side::Sell, -short, 70_000, 3),
                order(PAIR_SHORT, Side::Buy, -short, 70_000, 4),
            ],
            now,
        );
    }
    now += 1_000;
    seq.set_oracle(0, oracle(70_000, now));
    let pair_out = withdraw_free(&mut seq, PAIR_LONG, 70_000, now)
        + withdraw_free(&mut seq, PAIR_SHORT, 70_000, now);
    assert!(seq.state.conservation_holds());
    assert_eq!(position(&seq, PASSIVE).collateral, usd(50_000));

    // The wind-down.
    let mut wind_down = seq.state.clone();
    let settle_all = wind_down.apply_batch(&[BatchOp::SettleAll]).map(|_| ());
    let passive_after_settle_all = settle_all.is_ok().then(|| {
        wind_down
            .position(&owner_id(PASSIVE), 0)
            .map_or(0, |p| p.collateral)
            / QUOTE_SCALE
    });
    let outcome = Outcome {
        net_size_after_liquidation,
        short_size_after_liquidation,
        pair_in: pair_in / QUOTE_SCALE,
        pair_out: pair_out / QUOTE_SCALE,
        vault_pool: seq.state.vault_pool / QUOTE_SCALE,
        external_in: seq.state.external_in / QUOTE_SCALE,
        external_out: seq.state.external_out / QUOTE_SCALE,
        settle_all,
        passive_after_settle_all,
    };

    assert_eq!(
        outcome.net_size_after_liquidation, 0,
        "the clearing pool holds no position after the liquidation: {outcome:#?}"
    );
    assert_eq!(
        outcome.short_size_after_liquidation, 0,
        "the short is closed with the long: {outcome:#?}"
    );
    assert!(
        outcome.pair_out <= outcome.pair_in,
        "the pair takes out no more than it put in: {outcome:#?}"
    );
    assert!(
        outcome.vault_pool >= 0,
        "the pool paid no one's gain: {outcome:#?}"
    );
    assert!(outcome.external_out <= outcome.external_in, "{outcome:#?}");
    assert_eq!(
        outcome.settle_all,
        Ok(()),
        "the wind-down is solvent: {outcome:#?}"
    );
    assert_eq!(
        outcome.passive_after_settle_all,
        Some(50_000),
        "the passive account pays for nobody: {outcome:#?}"
    );
    assert!(wind_down.conservation_holds());
}

/// The scenario's pair with the short holding a take-profit: a plain GTC buy of
/// its whole size below the market. Returns the sequencer, the take-profit's hash
/// and the batch that liquidated the long at $94.5k.
fn take_profit_scenario() -> (Sequencer, [u8; 32], sequencer::SealedBatch) {
    let mut seq = Sequencer::new(EnclaveIdentity::from_seed([7u8; 32], 1, [0xABu8; 32]), 20);
    let mut market = Market::conservative(0);
    market.oracle_pubkey = oracle_addr();
    seq.add_market(market);
    seq.set_wind_down_recipient([0x5E; 20]);
    seq.set_oracle(0, oracle(100_000, 1_000));
    fund(&mut seq, PAIR_LONG, usd(10_100));
    fund(&mut seq, PAIR_SHORT, usd(10_100));
    fund(&mut seq, PASSIVE, usd(50_000));
    fund(&mut seq, TAKER, usd(30_000));
    seq.seal_genesis_baseline();
    seq.seal_batch(
        &[
            order(PAIR_LONG, Side::Buy, SIZE_SCALE, 100_000, 1),
            order(PAIR_SHORT, Side::Sell, SIZE_SCALE, 100_000, 2),
        ],
        1_000,
    );
    // The short's take-profit: buy its 1 BTC back at $92k.
    let take_profit = order(PAIR_SHORT, Side::Buy, SIZE_SCALE, 92_000, 3);
    let hash = take_profit.order_hash::<Keccak256>();
    seq.set_oracle(0, oracle(100_000, 2_000));
    seq.seal_batch(&[take_profit], 2_000);
    assert_eq!(
        seq.remaining_order_size(&hash),
        Some(SIZE_SCALE),
        "the take-profit rests"
    );
    // $94.5k: the long is liquidated and the short is closed with it.
    seq.set_oracle(0, oracle(94_500, 5_000));
    let sealed = seq.seal_batch(&[], 5_000);
    assert_eq!(sealed.liquidation_tags.len(), 1, "the long is liquidated");
    assert_eq!(position(&seq, PAIR_SHORT).size, 0, "the short is closed");
    (seq, hash, sealed)
}

/// Round-1 review: the liquidation's close of the other side left the
/// counterparty's resting orders on the book. A take-profit that was a close
/// then opened a fresh position the trader never asked for: at $92k a taker
/// sold into the stale buy and the short ended 1 BTC long. The orders of every
/// account the close reduced are cancelled in that market, as a liquidated
/// owner's are, and the removal says why.
#[test]
fn audit_1116_pc1_a_forced_close_cancels_the_counterpartys_resting_orders() {
    let (mut seq, hash, sealed) = take_profit_scenario();
    assert_eq!(
        seq.remaining_order_size(&hash),
        None,
        "the forced close cancels the take-profit"
    );
    let removal = sealed.removals.iter().find(|r| r.order_hash == hash);
    assert_eq!(
        removal.map(|r| r.reason),
        Some("ForcedClose"),
        "the removal is published with its reason"
    );

    // A taker sells into the old take-profit price: nothing is left to match.
    let now = 6_000;
    seq.set_oracle(0, oracle(92_000, now));
    seq.seal_batch(&[order(TAKER, Side::Sell, SIZE_SCALE, 92_000, 4)], now);
    assert_eq!(
        position(&seq, PAIR_SHORT).size,
        0,
        "the closed short is not reopened as a long"
    );
    assert_eq!(net_size(&seq), 0);
    assert!(seq.state.conservation_holds());
}

/// Only the accounts the close reduced lose their orders: an account on the
/// liquidated side and one with no position keep theirs.
#[test]
fn audit_1116_pc1_a_forced_close_leaves_other_accounts_orders_resting() {
    let mut seq = Sequencer::new(EnclaveIdentity::from_seed([7u8; 32], 1, [0xABu8; 32]), 20);
    let mut market = Market::conservative(0);
    market.oracle_pubkey = oracle_addr();
    seq.add_market(market);
    seq.set_wind_down_recipient([0x5E; 20]);
    seq.set_oracle(0, oracle(100_000, 1_000));
    fund(&mut seq, PAIR_LONG, usd(10_100));
    fund(&mut seq, PAIR_SHORT, usd(10_100));
    fund(&mut seq, PASSIVE, usd(50_000));
    fund(&mut seq, TAKER, usd(30_000));
    seq.seal_genesis_baseline();
    seq.seal_batch(
        &[
            order(PAIR_LONG, Side::Buy, SIZE_SCALE, 100_000, 1),
            order(PAIR_SHORT, Side::Sell, SIZE_SCALE, 100_000, 2),
        ],
        1_000,
    );
    // TAKER is long 0.1 BTC against PASSIVE's short 0.1 BTC; then TAKER and an
    // account with no position rest bids far below the market.
    seq.set_oracle(0, oracle(100_000, 2_000));
    seq.seal_batch(
        &[
            order(TAKER, Side::Buy, SIZE_SCALE / 10, 100_000, 3),
            order(PASSIVE, Side::Sell, SIZE_SCALE / 10, 100_000, 4),
        ],
        2_000,
    );
    let taker_bid = order(TAKER, Side::Buy, SIZE_SCALE / 10, 80_000, 5);
    let passive_bid = order(PASSIVE, Side::Buy, SIZE_SCALE / 100, 80_000, 6);
    seq.set_oracle(0, oracle(100_000, 3_000));
    seq.seal_batch(&[taker_bid, passive_bid], 3_000);
    seq.set_oracle(0, oracle(94_500, 5_000));
    let sealed = seq.seal_batch(&[], 5_000);
    assert_eq!(sealed.liquidation_tags.len(), 1, "the long is liquidated");
    // The short side gave up 1 BTC pro rata: PAIR_SHORT and PASSIVE were reduced.
    assert!(position(&seq, PAIR_SHORT).size > -SIZE_SCALE);
    assert!(position(&seq, PASSIVE).size > -SIZE_SCALE / 10);
    assert_eq!(net_size(&seq), 0);
    // TAKER, a long the close did not touch, keeps its bid. PASSIVE's bid is
    // cancelled with the forced close of its short.
    assert_eq!(
        seq.remaining_order_size(&taker_bid.order_hash::<Keccak256>()),
        Some(SIZE_SCALE / 10)
    );
    assert_eq!(
        seq.remaining_order_size(&passive_bid.order_hash::<Keccak256>()),
        None
    );
}

/// Round-1 review: the forced close left no trace the counterparty could see,
/// while an ADL haircut gets an attributable receipt. Each reduced position now
/// gets a receipt under a tag only its owner can recompute.
#[test]
fn audit_1116_pc1_a_forced_close_is_reported_to_its_owner_only() {
    let (_, _, sealed) = take_profit_scenario();
    let short_key = adl_tag_key(&spend_key(PAIR_SHORT));
    let short_tag = forced_close_tag(&short_key, 0, sealed.batch_id);
    assert_eq!(
        sealed.forced_close_receipts.len(),
        1,
        "only the short is closed"
    );
    let receipt = sealed.forced_close_receipts[0];
    assert_eq!(receipt.tag, short_tag);
    // The short bought its 1 BTC back at $94.5k: $5,500 realized; it was healthy,
    // so no penalty.
    assert_eq!(receipt.size, SIZE_SCALE);
    assert_eq!(receipt.price, 94_500 * PRICE_SCALE);
    assert_eq!(receipt.realized, usd(5_500));
    assert_eq!(receipt.penalty, 0);
    // Not the liquidated long's, not the short's ADL tag, and not computable from
    // the public owner id.
    let long_tag = forced_close_tag(&adl_tag_key(&spend_key(PAIR_LONG)), 0, sealed.batch_id);
    assert_ne!(receipt.tag, long_tag);
    assert_ne!(receipt.tag, adl_tag(&short_key, 0, sealed.batch_id));
    assert_ne!(
        receipt.tag,
        forced_close_tag(&owner_id(PAIR_SHORT), 0, sealed.batch_id)
    );
    assert!(sealed.adl_receipts.is_empty(), "nothing was clawed");
}

/// Round-1 review: an upgrade to this build changes what a `Liquidate` means.
/// A snapshot written by the earlier build holds the state its rules produced
/// (the short left open against the pool) and an open window whose `Liquidate`
/// this build replays to another state (the short closed). The sequencer
/// detects it, so the gateway can refuse to start instead of proving a root the
/// live state does not have.
#[test]
fn audit_1116_pc1_an_open_window_from_the_earlier_rules_does_not_replay() {
    let (mut seq, _, _) = take_profit_scenario();
    assert_eq!(seq.check_open_window_replays(), Ok(()));

    // The live state as the earlier build left it: the short still open at its
    // entry, the $5,500 it realized here still in the clearing pool.
    let short = owner_id(PAIR_SHORT);
    let funding_entry = seq.state.funding[&0].cumulative_index;
    seq.state.positions.insert(
        (short, 0),
        Position {
            owner: short,
            market_id: 0,
            size: -SIZE_SCALE,
            entry_price: 100_000 * PRICE_SCALE,
            collateral: usd(10_100),
            funding_entry,
        },
    );
    seq.state.vault_pool += usd(5_500);
    assert!(seq.state.conservation_holds());
    let refused = seq.check_open_window_replays().unwrap_err();
    assert!(refused.contains("does not replay"), "{refused}");
}

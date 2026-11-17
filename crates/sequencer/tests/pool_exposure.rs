//! The audit 2026-11-16 PC-1 scenario, run through the sequencer's own loop
//! (`seal_batch` → maintenance liquidation → `seal_window`), not the engine API.
//!
//! Two colluding accounts open opposite sides of one BTC. The price falls far
//! enough to liquidate the long and keeps falling. Before the fix the short stayed
//! open against the clearing pool, closed later at the lower price, and the pair
//! withdrew more than it deposited; the pool went negative and a passive account
//! that never traded paid for it in `SettleAll`. Now the liquidation closes the
//! short with the long, so the pool holds no position, the pair cannot take out
//! more than it put in, and the passive account keeps all of its collateral.

use k256::ecdsa::SigningKey;
use perp_core::engine::BatchOp;
use perp_core::fixed::{PRICE_SCALE, QUOTE_SCALE, SIZE_SCALE};
use perp_core::hash::{word_u64, Keccak256};
use perp_core::market::Market;
use perp_core::note::{owner_from_spend_key, PubKey};
use perp_core::oracle::{oracle_digest, OracleSig, OracleTranscript};
use perp_core::order::{Order, Side, TimeInForce};
use perp_core::position::Position;
use perp_core::Note;
use sequencer::{EnclaveIdentity, Sequencer};

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
    assert_eq!(
        net_size(&seq),
        0,
        "the clearing pool holds no position after the liquidation"
    );
    assert_eq!(
        position(&seq, PAIR_SHORT).size,
        0,
        "the short is closed with the long"
    );
    assert!(seq.state.conservation_holds());

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
        assert_eq!(net_size(&seq), 0, "${price}");
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
    assert!(
        pair_out <= pair_in,
        "the pair took out {pair_out} against {pair_in} deposited"
    );
    assert!(seq.state.vault_pool >= 0, "the pool paid no one's gain");
    assert!(seq.state.external_out <= seq.state.external_in);
    assert!(seq.state.conservation_holds());

    // The wind-down needs no haircut: the passive account keeps everything.
    let passive = position(&seq, PASSIVE);
    assert_eq!(passive.collateral, usd(50_000));
    let mut wind_down = seq.state.clone();
    wind_down
        .apply_batch(&[BatchOp::SettleAll])
        .expect("the wind-down is solvent");
    assert_eq!(
        wind_down
            .position(&owner_id(PASSIVE), 0)
            .unwrap()
            .collateral,
        usd(50_000),
        "the passive account pays for nobody"
    );
    assert!(wind_down.conservation_holds());
}

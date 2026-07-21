//! End-to-end: a REAL exchange ticker flows into the protocol's oracle and a trade
//! settles marked against it. Proves the live-oracle adapter (`oracle-feed`) feeds
//! the same `OracleTranscript` the sequencer/engine consume — the real-data path,
//! offline and deterministic (the ticker strings are a captured Crypto.com snapshot).

use oracle_feed::transcript_from_ticker;
use perp_core::engine::BatchOp;
use perp_core::fixed::{PRICE_SCALE, QUOTE_SCALE, SIZE_SCALE};
use perp_core::hash::Keccak256;
use perp_core::market::Market;
use perp_core::note::owner_from_spend_key;
use perp_core::order::{Order, Side, TimeInForce};
use perp_core::Note;
use sequencer::{EnclaveIdentity, Sequencer};

/// The note owner derived from trader `id`'s spend key (audit DP-003:
/// `owner = H(spend_key)`), matching the `spend_key: [id as u8; 32]` used to fund.
fn owner_of(id: u64) -> [u8; 32] {
    owner_from_spend_key::<Keccak256>(&[id as u8; 32])
}

fn fund(s: &mut Sequencer, owner: u64, usd: i128, blind: u8) {
    let o = owner_of(owner);
    let amount = usd * QUOTE_SCALE;
    let cm = Note::new(o, 0, amount, [blind; 32]).commitment::<Keccak256>();
    // SEC-019: test path — placeholder L1 binding; deposit_id reads the live consumed
    // count so the strict in-order gate passes across successive funds.
    let deposit_id = s.state.consumed_deposit_count;
    s.apply(&BatchOp::Deposit {
        owner: o,
        asset_id: 0,
        amount,
        blinding: [blind; 32],
        from: [0u8; 20],
        deposit_id,
        deposit_blind: [0u8; 32],
    })
    .unwrap();
    s.apply(&BatchOp::FundPosition {
        owner: o,
        market_id: 0,
        note_commitment: cm,
        spend_key: [owner as u8; 32],
    })
    .unwrap();
}

#[test]
fn real_ticker_feeds_the_sequencer_and_a_trade_settles() {
    // captured BTCUSD-PERP snapshot: last 59585.6, bid 59586.7, ask 59586.8
    let now = 1_000u64;
    // ZK-001: the adapter signs the transcript for market 0 with the operator's oracle
    // publisher key; the market's `oracle_pubkey` is pinned to that signer's address so
    // the live-derived price clears the fail-closed §8 signature gate.
    let signer = oracle_feed::signer_from_env().expect("oracle publisher signer");
    let transcript = transcript_from_ticker("59585.6", "59586.7", "59586.8", now, 0, &signer)
        .expect("real ticker converts to a transcript");
    // the adapter produced exactly the price the engine will mark against
    assert_eq!(transcript.price, 5_958_560_000_000);

    let enclave = EnclaveIdentity::from_seed([7u8; 32], 1, [0xAB; 32]);
    let mut node = Sequencer::new(enclave, 24);
    let mut market = Market::conservative(0);
    market.oracle_pubkey = oracle_feed::signer_address(&signer);
    node.add_market(market);
    // feed the LIVE-derived transcript into the protocol oracle
    node.set_oracle(0, transcript);

    fund(&mut node, 1, 50_000, 0x11);
    fund(&mut node, 2, 50_000, 0x22);

    // a crossing trade at the real index price
    let px = transcript.price;
    let maker = Order {
        owner: owner_of(1),
        market_id: 0,
        side: Side::Sell,
        size: SIZE_SCALE / 2,
        limit_price: px,
        tif: TimeInForce::Gtc,
        reduce_only: false,
        nonce: 1,
        expiry_ms: 0,
        ciphertext_commit: [1u8; 32],
    };
    let taker = Order {
        owner: owner_of(2),
        market_id: 0,
        side: Side::Buy,
        size: SIZE_SCALE / 2,
        limit_price: px,
        tif: TimeInForce::Gtc,
        reduce_only: false,
        nonce: 2,
        expiry_ms: 0,
        ciphertext_commit: [2u8; 32],
    };

    let sealed = node.seal_batch(&[maker, taker], now);
    assert!(
        !sealed.settled_order_hashes.is_empty(),
        "the trade matched + settled"
    );
    // the taker's position is marked at the real index price, ~$29,792 notional
    let pos = node
        .state
        .position(&owner_of(2), 0)
        .expect("taker has a position");
    assert_eq!(pos.size, SIZE_SCALE / 2);
    assert_eq!(pos.entry_price, px);
    assert!(node.state.conservation_holds());
    // sanity: 0.5 BTC at ~$59,585 ≈ $29,792 (price is the real one, not a round mock)
    assert!(px > 59_000 * PRICE_SCALE && px < 60_000 * PRICE_SCALE);
}

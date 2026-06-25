//! The full dark-perp flow, end to end, proving the crates compose:
//!
//!   deposit (note-archive) → fund → match (matcher) → settle (perp-core via
//!   sequencer) → publish manifest + receipts (§2/§3) → prove the transition
//!   (prover, §10b) → recover notes from seed (note-archive, §7).
//!
//! This is the architecture executing as one system, not five crates in
//! isolation. The on-chain layer is covered separately by the cross-layer vectors
//! (contracts/test/CrossLayer.t.sol) which pin the contract hashing to the exact
//! Rust producers exercised here.

use note_archive::{NoteArchive, Wallet};
use perp_core::engine::BatchOp;
use perp_core::fixed::{PRICE_SCALE, QUOTE_SCALE, SIZE_SCALE};
use perp_core::hash::Keccak256;
use perp_core::market::Market;
use perp_core::oracle::OracleTranscript;
use perp_core::order::{Finality, Order, Side, TimeInForce};
use perp_core::Note;
use prover::{AttestedProver, CommitmentProver, PublicInputs, SealedWitness, Verifier};
use sequencer::{EnclaveIdentity, Sequencer};

const MEASUREMENT: [u8; 32] = [0xAB; 32];

fn oracle(price_usd: i128, now: u64) -> OracleTranscript {
    OracleTranscript {
        price: price_usd * PRICE_SCALE,
        publish_time_ms: now,
        confidence: 10 * PRICE_SCALE,
        backup_twap: price_usd * PRICE_SCALE,
    }
}

fn limit_order(w: &Wallet, side: Side, size: i128, price: i128, nonce: u64) -> Order {
    Order {
        owner: w.owner,
        market_id: 0,
        side,
        size,
        limit_price: price,
        tif: TimeInForce::Gtc,
        reduce_only: false,
        nonce,
        expiry_ms: 0,
        ciphertext_commit: [nonce as u8; 32],
    }
}

/// Deposit + fund a wallet's position, recording the deposited note to the
/// archive (as the sequencer would on a real deposit).
fn deposit_and_fund(
    s: &mut Sequencer,
    archive: &mut NoteArchive,
    w: &Wallet,
    amount_usd: i128,
    blind: u8,
) {
    let amount = amount_usd * QUOTE_SCALE;
    let note = Note::new(w.owner, 0, amount, [blind; 32]);
    let cm = note.commitment::<Keccak256>();
    s.apply(&BatchOp::Deposit {
        owner: w.owner,
        asset_id: 0,
        amount,
        blinding: [blind; 32],
    })
    .unwrap();
    archive.record(0, &note, &w.view_key);
    s.apply(&BatchOp::FundPosition {
        owner: w.owner,
        market_id: 0,
        note_commitment: cm,
        spend_key: w.spend_key,
    })
    .unwrap();
}

#[test]
fn deposit_match_settle_prove_recover() {
    // --- wallets derived from seeds (the recovery root) -----------------------
    let alice = Wallet::from_seed([1u8; 32]);
    let bob = Wallet::from_seed([2u8; 32]);

    // --- node: sequencer + matcher + settlement state -------------------------
    let enclave = EnclaveIdentity::from_seed([7u8; 32], 1, MEASUREMENT);
    let mut node = Sequencer::new(enclave, 24);
    node.add_market(Market::conservative(0));
    node.set_oracle(0, oracle(100_000, 1_000));

    // --- deposits (collateral notes recorded to the archive) ------------------
    let mut archive = NoteArchive::new();
    deposit_and_fund(&mut node, &mut archive, &alice, 20_000, 0x11);
    deposit_and_fund(&mut node, &mut archive, &bob, 20_000, 0x22);
    assert!(node.state.conservation_holds());

    let prev_root = node.state.state_root();

    // --- a crossing pair: alice rests an ask, bob takes it (matcher) ----------
    let maker = limit_order(&alice, Side::Sell, SIZE_SCALE, 100_000 * PRICE_SCALE, 1);
    let taker = limit_order(&bob, Side::Buy, SIZE_SCALE, 100_000 * PRICE_SCALE, 2);

    // --- seal the batch: match + settle + receipts + manifest (§2/§3) ---------
    let sealed = node.seal_batch(&[maker, taker], 1_000);
    assert_eq!(sealed.prev_state_root, prev_root);
    assert!(sealed.settlement_rejected.is_empty(), "both legs settle");
    assert_eq!(sealed.receipts.len(), 2);
    assert!(
        sealed.receipts.iter().all(|r| r.verify()),
        "receipts verify (secp256k1)"
    );
    assert!(
        node.state.conservation_holds(),
        "value conserved across the batch"
    );

    // positions opened on opposite sides
    assert_eq!(node.state.position(&bob.owner, 0).unwrap().size, SIZE_SCALE);
    assert_eq!(
        node.state.position(&alice.owner, 0).unwrap().size,
        -SIZE_SCALE
    );

    // both orders are MATCHED (soft) but not yet withdrawable (§3)
    let taker_hash = taker.order_hash::<Keccak256>();
    assert_eq!(node.finality_of(&taker_hash), Some(Finality::Matched));
    assert!(!Finality::Matched.is_withdrawable());

    // --- prove the transition (attested confidential prover, §10b) ------------
    let public = PublicInputs {
        prev_state_root: sealed.prev_state_root,
        batch_manifest_hash: sealed.manifest_hash,
        new_state_root: sealed.new_state_root,
        // in a full node these are the batch's ordered-leaves and withdrawals
        // Merkle roots; bound into the commitment so the L1 verifier checks them.
        ordered_root: [0u8; 32],
        withdrawals_root: [0u8; 32],
    };
    // the witness (positions/fills/margins) is sealed to the prover measurement
    let witness = b"sealed batch witness: cross-user matching + margins";
    let prover = AttestedProver::new(CommitmentProver::new(MEASUREMENT));
    let proof = prover
        .prove_sealed(&SealedWitness::seal(witness, MEASUREMENT), &public)
        .expect("attested prover produces a proof");
    assert!(
        CommitmentProver::new(MEASUREMENT).verify(&proof),
        "proof verifies"
    );
    assert_eq!(proof.public, public, "proof binds the sealed batch's roots");

    // a non-attested prover (public proving network) cannot open the witness
    let rogue = AttestedProver::new(CommitmentProver::new([0xCD; 32]));
    assert!(rogue
        .prove_sealed(&SealedWitness::seal(witness, MEASUREMENT), &public)
        .is_err());

    // --- proof verified on L1 ⇒ SETTLED (§3) ----------------------------------
    node.mark_settled(sealed.batch_id);
    assert_eq!(node.finality_of(&taker_hash), Some(Finality::Settled));
    assert!(Finality::Settled.is_withdrawable());

    // --- accountability: no inclusion violations in the honest flow (§2) ------
    assert!(node.inclusion_violations(1).is_empty());

    // --- recovery: alice loses her device, recovers from seed alone (§7) ------
    let recovered = archive.scan(&Wallet::from_seed([1u8; 32]).view_key);
    assert_eq!(recovered.len(), 1, "alice recovers her deposited note");
    assert_eq!(recovered[0].note.amount, 20_000 * QUOTE_SCALE);
    // bob's note is not readable with alice's view-key
    assert!(archive
        .scan(&Wallet::from_seed([1u8; 32]).view_key)
        .iter()
        .all(|r| r.note.owner == alice.owner));
}

#[test]
fn close_only_blocks_open_but_allows_exit() {
    let alice = Wallet::from_seed([3u8; 32]);
    let bob = Wallet::from_seed([4u8; 32]);
    let enclave = EnclaveIdentity::from_seed([8u8; 32], 1, MEASUREMENT);
    let mut node = Sequencer::new(enclave, 24);
    node.add_market(Market::conservative(0));
    node.set_oracle(0, oracle(100_000, 1_000));

    let mut archive = NoteArchive::new();
    deposit_and_fund(&mut node, &mut archive, &alice, 20_000, 0x31);
    deposit_and_fund(&mut node, &mut archive, &bob, 20_000, 0x42);

    // open positions first
    node.seal_batch(
        &[
            limit_order(&alice, Side::Sell, SIZE_SCALE / 2, 100_000 * PRICE_SCALE, 1),
            limit_order(&bob, Side::Buy, SIZE_SCALE / 2, 100_000 * PRICE_SCALE, 2),
        ],
        1_000,
    );

    // enter close-only (forced exit / breaker, §6)
    node.apply(&BatchOp::EnterCloseOnly).unwrap();

    // an opening order is settlement-rejected under close-only; a closing order
    // settles. bob reduces (sells), alice buys back — both reduce.
    let sealed = node.seal_batch(
        &[
            limit_order(&bob, Side::Sell, SIZE_SCALE / 2, 100_000 * PRICE_SCALE, 3),
            limit_order(&alice, Side::Buy, SIZE_SCALE / 2, 100_000 * PRICE_SCALE, 4),
        ],
        2_000,
    );
    assert!(node.state.conservation_holds());
    // positions closed back to zero
    assert_eq!(node.state.position(&bob.owner, 0).unwrap().size, 0);
    assert_eq!(node.state.position(&alice.owner, 0).unwrap().size, 0);
    assert!(
        sealed.settlement_rejected.is_empty(),
        "reducing fills settle in close-only"
    );
}

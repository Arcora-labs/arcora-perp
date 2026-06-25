//! A narrated run of the whole dark-perp flow. `cargo run -p demo`.
//!
//! This is not a test (the tests prove correctness); it's a readable trace of the
//! architecture operating as one system, end to end.

use bridge::{Direction, MixBatch};
use committee::{Committee, EnclaveSig, QuorumCertificate};
use note_archive::{NoteArchive, Wallet};
use perp_core::engine::BatchOp;
use perp_core::fixed::{PRICE_SCALE, QUOTE_SCALE, SIZE_SCALE};
use perp_core::hash::Keccak256;
use perp_core::market::Market;
use perp_core::order::{Order, Side, TimeInForce};
use perp_core::oracle::OracleTranscript;
use perp_core::Note;
use prover::{AttestedProver, CommitmentProver, PublicInputs, SealedWitness, Verifier};
use sequencer::{EnclaveIdentity, Sequencer};

const MEASUREMENT: [u8; 32] = [0xAB; 32];

fn hx(d: &[u8; 32]) -> String {
    d[..4].iter().map(|b| format!("{b:02x}")).collect()
}

/// Format a scaled integer with `dec` decimals (demo display only).
fn formatd(v: i128, scale: i128, dec: usize) -> String {
    let neg = v < 0;
    let x = if neg { -v } else { v };
    let whole = x / scale;
    let frac = (x % scale) * 10i128.pow(dec as u32) / scale;
    let sign = if neg { "-" } else { "" };
    if dec == 0 {
        format!("{sign}{whole}")
    } else {
        format!("{sign}{whole}.{:0width$}", frac, width = dec)
    }
}

fn oracle(price_usd: i128, now: u64) -> OracleTranscript {
    OracleTranscript {
        price: price_usd * PRICE_SCALE,
        publish_time_ms: now,
        confidence: 10 * PRICE_SCALE,
        backup_twap: price_usd * PRICE_SCALE,
    }
}

fn order(w: &Wallet, side: Side, size: i128, price: i128, nonce: u64) -> Order {
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

fn fund(s: &mut Sequencer, a: &mut NoteArchive, w: &Wallet, usd: i128, blind: u8) {
    let amount = usd * QUOTE_SCALE;
    let note = Note::new(w.owner, 0, amount, [blind; 32]);
    let cm = note.commitment::<Keccak256>();
    s.apply(&BatchOp::Deposit { owner: w.owner, asset_id: 0, amount, blinding: [blind; 32] }).unwrap();
    a.record(0, &note, &w.view_key);
    s.apply(&BatchOp::FundPosition { owner: w.owner, market_id: 0, note_commitment: cm, spend_key: w.spend_key }).unwrap();
}

fn main() {
    println!("\n=== dark-perp — full flow ===\n");

    // wallets from seeds (the recovery root)
    let alice = Wallet::from_seed([1u8; 32]);
    let bob = Wallet::from_seed([2u8; 32]);
    println!("alice owner={}…  bob owner={}…", hx(&alice.owner), hx(&bob.owner));

    // the node: matcher + settlement + an attested enclave identity
    let enclave = EnclaveIdentity::from_seed([7u8; 32], 1, MEASUREMENT);
    println!("enclave L1 address=0x{}…", hx(&{
        let mut p = [0u8; 32];
        p[..20].copy_from_slice(&enclave.eth_address());
        p
    }));
    let mut node = Sequencer::new(enclave, 24);
    node.add_market(Market::conservative(0));
    node.set_oracle(0, oracle(100_000, 1_000));

    // deposits (notes recorded to the archive)
    let mut archive = NoteArchive::new();
    fund(&mut node, &mut archive, &alice, 20_000, 0x11);
    fund(&mut node, &mut archive, &bob, 20_000, 0x22);
    println!("\n[1] deposits: alice & bob each $20,000  →  conservation {}",
        if node.state.conservation_holds() { "holds ✓" } else { "BROKEN ✗" });

    // a crossing trade
    let prev_root = node.state.state_root();
    let maker = order(&alice, Side::Sell, SIZE_SCALE, 100_000 * PRICE_SCALE, 1);
    let taker = order(&bob, Side::Buy, SIZE_SCALE, 100_000 * PRICE_SCALE, 2);
    let sealed = node.seal_batch(&[maker, taker], 1_000);
    println!("\n[2] batch #{}: matched 1.0 BTC @ $100,000", sealed.batch_id);
    println!("    receipts issued: {} (all verify: {})", sealed.receipts.len(),
        sealed.receipts.iter().all(|r| r.verify()));
    println!("    state root {}… → {}…", hx(&sealed.prev_state_root), hx(&sealed.new_state_root));
    let bob_pos = node.state.position(&bob.owner, 0).unwrap();
    println!("    bob position: {} BTC @ ${}",
        formatd(bob_pos.size, SIZE_SCALE, 2), formatd(bob_pos.entry_price, PRICE_SCALE, 0));

    // finality: MATCHED (soft) until the proof lands
    let th = taker.order_hash::<Keccak256>();
    println!("\n[3] finality: bob's order is {:?}  (withdrawable: {})",
        node.finality_of(&th).unwrap(), node.finality_of(&th).unwrap().is_withdrawable());

    // prove the transition with the attested confidential prover
    let public = PublicInputs {
        prev_state_root: prev_root,
        batch_manifest_hash: sealed.manifest_hash,
        new_state_root: sealed.new_state_root,
        ordered_root: [0u8; 32],
        withdrawals_root: [0u8; 32],
    };
    let prover = AttestedProver::new(CommitmentProver::new(MEASUREMENT));
    let proof = prover
        .prove_sealed(&SealedWitness::seal(b"sealed batch witness", MEASUREMENT), &public)
        .unwrap();
    println!("\n[4] attested prover produced a proof (verifies: {})",
        CommitmentProver::new(MEASUREMENT).verify(&proof));
    let rogue = AttestedProver::new(CommitmentProver::new([0xCD; 32]));
    println!("    a public proving network (wrong measurement) cannot open the witness: {}",
        rogue.prove_sealed(&SealedWitness::seal(b"x", MEASUREMENT), &public).is_err());

    // proof verified on L1 → SETTLED
    node.mark_settled(sealed.batch_id);
    println!("\n[5] proof verified on L1 → bob's order is {:?}  (withdrawable: {})",
        node.finality_of(&th).unwrap(), node.finality_of(&th).unwrap().is_withdrawable());

    // a price crash liquidates an underwater position
    node.set_oracle(0, oracle(84_000, 5_000));
    let m = node.seal_batch(&[], 5_000);
    println!("\n[6] price → $84,000. maintenance pass liquidated {} position(s); insurance = ${}",
        m.liquidations.len(), formatd(node.state.insurance_fund, QUOTE_SCALE, 2));

    // device-loss recovery from seed alone
    let recovered = archive.scan(&Wallet::from_seed([1u8; 32]).view_key);
    let total: i128 = recovered.iter().map(|r| r.note.amount).sum();
    println!("\n[7] recovery: alice's seed → view-key → scanned archive → {} note(s), ${}",
        recovered.len(), formatd(total, QUOTE_SCALE, 2));

    // committee-of-enclaves: 3-of-5 quorum preconfirmation
    quorum_demo();

    // privacy bridge: amount bucketing + anonymity set
    bridge_demo();

    println!("\n=== done ===\n");
}

fn quorum_demo() {
    use committee::shamir;
    let keys: Vec<_> = (1..=5u8)
        .map(|n| {
            let mut s = [0u8; 32];
            s[31] = n;
            k256_key(s)
        })
        .collect();
    let members = keys.iter().map(|k| committee::eth_address(k.verifying_key())).collect();
    let committee = Committee::new(members, 3);
    let digest = [0x42u8; 32];
    let mut qc = QuorumCertificate::new(digest);
    for k in keys.iter().take(3) {
        qc.add(EnclaveSig::sign(k, &digest));
    }
    println!("\n[8] committee 3-of-5 quorum preconf: reached = {} (weight {})",
        qc.verify(&committee), qc.weight(&committee));

    // threshold order key: split among 5, any 3 reconstruct
    let key = b"order-symmetric-key-here!!";
    let shares = shamir::split(key, 3, 5, &[9u8; 32]);
    let subset = vec![shares[0].clone(), shares[2].clone(), shares[4].clone()];
    println!("    threshold order key: 3 of 5 shares reconstruct = {}",
        shamir::combine(&subset).as_deref() == Some(&key[..]));
}

fn k256_key(seed: [u8; 32]) -> k256::ecdsa::SigningKey {
    k256::ecdsa::SigningKey::from_bytes((&seed).into()).unwrap()
}

fn bridge_demo() {
    let mut batch = MixBatch::new();
    batch.add_transfer(Direction::Deposit, [1u8; 32], 4_137 * QUOTE_SCALE, [0xA; 32]);
    batch.add_transfer(Direction::Withdraw, [2u8; 32], 4_137 * QUOTE_SCALE, [0xB; 32]);
    batch.mix(&[0x5Eu8; 32]);
    println!("\n[9] privacy bridge: two $4,137 transfers → {} bucketed entries; $1,000 anonymity set = {}",
        batch.len(), batch.anonymity_set(1_000 * QUOTE_SCALE));
}

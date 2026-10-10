use super::*;
use alloc::{string::ToString, vec, vec::Vec};
use binding::*;
use k256::ecdsa::SigningKey;
use perp_core::{
    clock::{abi_u64, ClockContext},
    engine::BatchOp,
    fixed::PRICE_SCALE,
    hash::Keccak256,
    market::Market,
    oracle::{oracle_digest, OracleSig},
    order::{BatchManifest, Side},
    DefaultState,
};
use policy::*;
use report::*;

fn feed(n: u8) -> [u8; 32] {
    let mut id = [n; 32];
    id[..2].copy_from_slice(&[0, 3]);
    id
}
pub(crate) fn body(id: [u8; 32], price: i128, bid: i128, ask: i128, at: u32) -> ReportBody {
    let mut bytes = Vec::new();
    bytes.extend(id);
    bytes.extend(abi_u64(at as u64));
    bytes.extend(abi_u64(at as u64));
    bytes.extend([0; 64]);
    bytes.extend(abi_u64((at + 60) as u64));
    for n in [price, bid, ask] {
        bytes.extend([0; 16]);
        bytes.extend(n.to_be_bytes());
    }
    ReportBody(bytes)
}
fn bodies() -> (ReportBody, ReportBody) {
    (
        body(
            feed(1),
            60_000 * PRICE_SCALE,
            59_999 * PRICE_SCALE,
            60_001 * PRICE_SCALE,
            100,
        ),
        body(feed(2), PRICE_SCALE, PRICE_SCALE, PRICE_SCALE, 100),
    )
}
fn policy() -> Policy {
    Policy {
        chain_id: 84532,
        network: 0,
        verifier_proxy: [3; 20],
        oracle_wrapper: [4; 20],
        markets: vec![MarketFeed {
            market_id: 0,
            base_symbol: "BTC".to_string(),
            base_usd_feed: feed(1),
            base_decimals: 8,
            usdc_usd_feed: feed(2),
            usdc_decimals: 8,
            max_report_age_ms: 10_000,
            max_pair_skew_ms: 1_000,
        }],
    }
}
fn key() -> SigningKey {
    SigningKey::from_slice(&[0x33; 32]).unwrap()
}
fn sign(n: Normalized) -> perp_core::oracle::OracleTranscript {
    let sig = OracleSig::sign(
        &key(),
        &oracle_digest(0, n.price, n.publish_time_ms, n.confidence, n.backup_twap),
    );
    n.with_signature(sig)
}
fn witness() -> CandidateWitness {
    let p = policy();
    let (b, q) = bodies();
    let o = sign(
        p.markets[0]
            .normalize(&b.decode().unwrap(), &q.decode().unwrap(), 100_000)
            .unwrap(),
    );
    let mut state = DefaultState::new(16);
    let mut market = Market::conservative(0);
    market.oracle_pubkey = o
        .signature
        .recover(&oracle_digest(
            0,
            o.price,
            o.publish_time_ms,
            o.confidence,
            o.backup_twap,
        ))
        .unwrap();
    state.add_market(market);
    let ops = vec![BatchOp::AccrueFunding {
        market_id: 0,
        mark: o.price,
        oracle: o,
        now_ms: 100_000,
    }];
    let manifest = BatchManifest {
        previous_state_root: state.state_root(),
        batch_id: state.next_batch_id,
        batch_time_ms: 100_000,
        ordered: vec![],
        rejected: vec![],
        oracle_updates: vec![],
        matching_rule_version: 0,
        enclave_measurement: [0; 32],
        sequencer_pubkey_epoch: 0,
    };
    let roots = perp_core::commitment::derive_roots(&mut state.clone(), &ops, &manifest).unwrap();
    let clock = ClockContext {
        chain_id: 84532,
        verifier: [5; 20],
        settlement: [6; 20],
        batch_id: manifest.batch_id,
        previous_root: state.state_root(),
        base_commitment: roots.commitment::<Keccak256>(),
        phase: 0,
        first_ms: 100_000,
        last_ms: 100_000,
        timed_ops: 1,
        anchored_at_ms: 100_000,
        max_window_ms: 10_000,
        clock_skew_ms: 2_000,
    };
    CandidateWitness {
        clock: (state, ops, manifest, clock),
        policy: p,
        evidence: vec![PairEvidence {
            market_id: 0,
            now_ms: 100_000,
            base: b,
            quote: q,
        }],
    }
}
#[test]
fn v3_decodes_canonical_body_without_authenticity_claim() {
    let (b, _) = bodies();
    let r = b.decode().unwrap();
    assert_eq!(r.feed_id, feed(1));
    assert_eq!(r.price, 60_000 * PRICE_SCALE);
    assert_eq!(r.valid_from, 100);
    assert_eq!(r.observations, 100);
}
#[test]
fn canonical_size_schema_uint_padding_and_signed_ranges_are_enforced() {
    let (b, _) = bodies();
    for n in [0, 1, 287, 289, 320] {
        let mut x = b.clone();
        x.0.resize(n, 0);
        assert!(x.decode().is_err());
    }
    for index in [0, 32, 64, 96, 128, 160, 192, 224, 256] {
        let mut x = b.clone();
        x.0[index] = 0x80;
        assert!(x.decode().is_err(), "word {index}");
    }
    for index in [192, 224, 256] {
        let mut x = b.clone();
        x.0[index..index + 32].fill(0);
        assert!(x.decode().is_err());
    }
}
#[test]
fn report_intervals_zero_future_stale_and_expiration_fail_closed() {
    let (b, _) = bodies();
    let r = b.decode().unwrap();
    assert!(r.check_time(100_000, 10_000).is_ok());
    assert!(r.check_time(110_000, 10_000).is_ok());
    for now in [0, 99_999, 110_001, 160_001] {
        assert!(r.check_time(now, 10_000).is_err());
    }
    let mut x = b.clone();
    x.0[32..64].copy_from_slice(&abi_u64(101));
    assert!(x.decode().is_err());
    let mut x = b.clone();
    x.0[160..192].copy_from_slice(&abi_u64(99));
    assert!(x.decode().is_err());
}
#[test]
fn usdc_depeg_changes_quote_price_instead_of_assuming_one_dollar() {
    let p = policy();
    let (b, _) = bodies();
    let q = body(feed(2), 80_000_000, 80_000_000, 80_000_000, 100);
    let n = p.markets[0]
        .normalize(&b.decode().unwrap(), &q.decode().unwrap(), 100_000)
        .unwrap();
    assert_eq!(n.price, 75_000 * PRICE_SCALE);
    assert_eq!(n.publish_time_ms, 100_000);
    assert_eq!(n.backup_twap, n.price);
    assert!(n.confidence >= PRICE_SCALE);
}
#[test]
fn different_decimals_and_rounding_enclose_liquidity_range() {
    let mut p = policy();
    p.markets[0].base_decimals = 18;
    let b = body(
        feed(1),
        123_450_000_000_000_000_000,
        123_440_000_000_000_000_000,
        123_460_000_000_000_000_000,
        100,
    );
    let q = body(feed(2), 100_000_000, 99_999_999, 100_000_001, 100);
    let n = p.markets[0]
        .normalize(&b.decode().unwrap(), &q.decode().unwrap(), 100_000)
        .unwrap();
    assert_eq!(n.price, 12_345_000_000);
    assert!(n.confidence >= 1_000_000);
    // Impact-price ordering is not silently reinterpreted as exchange top-of-book.
    let reversed = body(
        feed(1),
        123_450_000_000_000_000_000,
        123_460_000_000_000_000_000,
        123_440_000_000_000_000_000,
        100,
    );
    assert_eq!(
        p.markets[0]
            .normalize(&reversed.decode().unwrap(), &q.decode().unwrap(), 100_000)
            .unwrap(),
        n
    );
}
#[test]
fn extreme_values_cannot_overflow_normalization() {
    let p = policy();
    let b = body(feed(1), i128::MAX, i128::MAX, i128::MAX, 100);
    let (_, q) = bodies();
    assert_eq!(
        p.markets[0].normalize(&b.decode().unwrap(), &q.decode().unwrap(), 100_000),
        Err(Error::Bounds)
    );
}
#[test]
fn wrong_feed_old_quote_future_quote_and_pair_skew_are_rejected() {
    let p = policy();
    let (b, q) = bodies();
    for (id, at) in [
        (feed(1), 100),
        (feed(3), 100),
        (feed(2), 0),
        (feed(2), 98),
        (feed(2), 101),
    ] {
        let x = body(id, PRICE_SCALE, PRICE_SCALE, PRICE_SCALE, at);
        assert!(x
            .decode()
            .and_then(|r| p.markets[0].normalize(&b.decode().unwrap(), &r, 100_000))
            .is_err());
    }
    let old = body(feed(2), PRICE_SCALE, PRICE_SCALE, PRICE_SCALE, 99);
    let n = p.markets[0]
        .normalize(&b.decode().unwrap(), &old.decode().unwrap(), 100_000)
        .unwrap();
    assert_eq!(n.publish_time_ms, 99_000);
    assert!(p.markets[0]
        .normalize(&b.decode().unwrap(), &q.decode().unwrap(), 110_001)
        .is_err());
}
#[test]
fn policy_commits_network_addresses_feed_mapping_and_limits() {
    let p = policy();
    let h = p.hash().unwrap();
    let mut x = p.clone();
    x.markets[0].base_decimals = 18;
    assert_ne!(x.hash().unwrap(), h);
    let mut x = p.clone();
    x.verifier_proxy = [9; 20];
    assert_eq!(x.hash().unwrap(), h);
    assert_ne!(bind([7; 32], &x, h, [8; 32]), bind([7; 32], &p, h, [8; 32]));
    let mut x = p.clone();
    x.markets[0].base_usd_feed = feed(9);
    assert_ne!(x.hash().unwrap(), h);
    let mut x = p.clone();
    x.chain_id = 8453;
    assert!(x.hash().is_err());
    let mut x = p.clone();
    x.markets.push(x.markets[0].clone());
    assert!(x.hash().is_err());
    let mut x = p;
    x.markets[0].base_usd_feed = x.markets[0].usdc_usd_feed;
    assert!(x.hash().is_err());
}
#[test]
fn real_native_transition_produces_distinct_candidate_commitment() {
    let w = witness();
    let output = run(w.clone()).unwrap();
    assert_ne!(output.commitment, w.clock.3.commitment());
    let mut encoded = WIRE_MAGIC.to_vec();
    encoded.extend(postcard::to_allocvec(&w).unwrap());
    assert_eq!(run_encoded(&encoded).unwrap(), output);
    encoded.push(0);
    assert_eq!(run_encoded(&encoded), Err(Error::Encoding));
    assert_eq!(
        run_encoded(perp_core::clock::WIRE_MAGIC),
        Err(Error::Version)
    );
}
#[test]
fn v2_publisher_fabrication_passes_old_transition_but_not_new_binding() {
    let mut w = witness();
    if let BatchOp::AccrueFunding { mark, oracle, .. } = &mut w.clock.1[0] {
        oracle.price *= 2;
        oracle.backup_twap *= 2;
        *mark = oracle.price;
        oracle.signature = OracleSig::sign(
            &key(),
            &oracle_digest(
                0,
                oracle.price,
                oracle.publish_time_ms,
                oracle.confidence,
                oracle.backup_twap,
            ),
        );
    }
    assert!(
        perp_core::commitment::derive_roots(&mut w.clock.0.clone(), &w.clock.1, &w.clock.2).is_ok()
    );
    assert_eq!(run(w), Err(Error::Oracle));
}
#[test]
fn missing_extra_reordered_or_wrong_market_evidence_cannot_be_hidden_by_manifest() {
    let w = witness();
    let mut x = w.clone();
    x.evidence.clear();
    assert_eq!(run(x), Err(Error::Evidence));
    let mut x = w.clone();
    x.evidence.push(x.evidence[0].clone());
    assert_eq!(run(x), Err(Error::Evidence));
    let mut x = w.clone();
    x.evidence[0].market_id = 99;
    assert_eq!(run(x), Err(Error::Evidence));
    let mut x = w.clone();
    x.evidence[0].now_ms += 1;
    assert_eq!(run(x), Err(Error::Evidence));
    let mut x = w;
    x.policy.markets[0].max_report_age_ms = 10_001;
    assert_eq!(run(x), Err(Error::Policy));
}
#[test]
fn all_four_oracle_operation_variants_require_matching_evidence() {
    let w = witness();
    let oracle = match w.clock.1[0] {
        BatchOp::AccrueFunding { oracle, .. } => oracle,
        _ => unreachable!(),
    };
    let ops = vec![
        BatchOp::Fill {
            taker: [1; 32],
            maker: [2; 32],
            market_id: 0,
            taker_side: Side::Buy,
            size: 1,
            price: oracle.price,
            oracle,
            now_ms: 100_000,
        },
        BatchOp::Liquidate {
            owner: [1; 32],
            market_id: 0,
            oracle,
            now_ms: 100_000,
        },
        BatchOp::Unbind {
            owner: [1; 32],
            market_id: 0,
            amount: 1,
            blinding: [0; 32],
            oracle,
            now_ms: 100_000,
        },
        w.clock.1[0].clone(),
    ];
    let evidence = vec![w.evidence[0].clone(); 4];
    assert!(check_evidence(&w.clock.0, &ops, &w.policy, &evidence).is_ok());
    for keep in 0..4 {
        assert!(check_evidence(&w.clock.0, &ops, &w.policy, &evidence[..keep]).is_err());
    }
}
#[test]
fn unsigned_structural_container_is_never_called_verified() {
    let (b, _) = bodies();
    let mut full = vec![0u8; 224];
    full[96..128].copy_from_slice(&abi_u64(224));
    full[128..160].copy_from_slice(&abi_u64(544));
    full[160..192].copy_from_slice(&abi_u64(608));
    full.extend(abi_u64(288));
    full.extend(&b.0);
    full.extend(abi_u64(1));
    full.extend([1; 32]);
    full.extend(abi_u64(1));
    full.extend([2; 32]);
    // Deliberately fake nonzero signatures: decoder only validates ABI structure.
    assert_eq!(body_from_full_report(&full).unwrap(), b);
    for at in [96, 128, 160, 224, 544, 608] {
        let mut x = full.clone();
        x[at] = 1;
        assert!(body_from_full_report(&x).is_err());
    }
    let mut x = full.clone();
    x.push(0);
    assert!(body_from_full_report(&x).is_err());
    let mut x = full;
    x[576..608].fill(0);
    assert!(body_from_full_report(&x).is_err());
}
#[test]
fn stale_replay_and_tampered_chain_context_are_rejected() {
    let mut w = witness();
    w.clock.3.chain_id = 8453;
    assert_eq!(run(w), Err(Error::Policy));
    let mut w = witness();
    w.evidence[0].base.0[64..96].copy_from_slice(&abi_u64(1));
    assert!(run(w).is_err());
    let mut w = witness();
    w.clock.3.base_commitment = [9; 32];
    assert_eq!(run(w), Err(Error::Clock));
}
#[test]
fn binding_vectors_for_solidity() {
    let w = witness();
    let ph = w.policy.hash().unwrap();
    let eh = initial_evidence(ph, 1).unwrap();
    let eh = append_evidence(eh, &w.evidence[0]);
    let bound = bind([7; 32], &w.policy, ph, eh);
    let hex = |b: [u8; 32]| -> alloc::string::String {
        b.iter().map(|x| alloc::format!("{x:02x}")).collect()
    };
    std::println!(
        "POLICY={} EVIDENCE={} BOUND={}",
        hex(ph),
        hex(eh),
        hex(bound)
    );
    assert_eq!(
        hex(ph),
        "316e98693d753c35a99d0a50fdfe9aa60508c59ddd2247b8182281fd3e809365"
    );
    assert_eq!(
        hex(eh),
        "a9908a9b909655b6998b2892e828a2acc9a6b34a79a70b7fb15c62cb7d16d342"
    );
    assert_eq!(
        hex(bound),
        "237fcafee06b3ff6c4de8de8b6699ad97a6b12fb82600b599f32257627934d00"
    );
}

#[path = "replay_vectors.rs"]
mod replay_vectors;

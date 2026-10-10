//! Public synthetic regression inputs, never live Chainlink reports or user state.
use super::*;
use std::{fs, io::Write, path::Path};

struct Case {
    name: &'static str,
    bytes: Vec<u8>,
    expected: core::result::Result<[u8; 32], Error>,
}
fn encode(w: &CandidateWitness) -> Vec<u8> {
    let mut bytes = WIRE_MAGIC.to_vec();
    bytes.extend(postcard::to_allocvec(w).unwrap());
    bytes
}
fn reanchor(w: &mut CandidateWitness) {
    let (state, ops, manifest, clock) = &mut w.clock;
    manifest.previous_state_root = state.state_root();
    manifest.batch_time_ms = perp_core::commitment::batch_time_ms(ops);
    let roots = perp_core::commitment::derive_roots(&mut state.clone(), ops, manifest).unwrap();
    let times = perp_core::clock::TimeBounds::derive(ops).unwrap();
    clock.previous_root = roots.prev_state_root;
    clock.base_commitment = roots.commitment::<Keccak256>();
    clock.phase = roots.wind_down_phase;
    clock.first_ms = times.first_ms;
    clock.last_ms = times.last_ms;
    clock.timed_ops = times.count;
    clock.anchored_at_ms = times.last_ms.max(100_000);
}
fn funding(e: &PairEvidence, p: &Policy) -> BatchOp {
    let n = p
        .market(e.market_id)
        .unwrap()
        .normalize(
            &e.base.decode().unwrap(),
            &e.quote.decode().unwrap(),
            e.now_ms,
        )
        .unwrap();
    BatchOp::AccrueFunding {
        market_id: e.market_id,
        mark: n.price,
        oracle: sign(n),
        now_ms: e.now_ms,
    }
}
fn good(name: &'static str, mut w: CandidateWitness) -> Case {
    reanchor(&mut w);
    let bytes = encode(&w);
    let expected = Ok(run_encoded(&bytes).unwrap().commitment);
    Case {
        name,
        bytes,
        expected,
    }
}
fn bad(name: &'static str, w: CandidateWitness, error: Error) -> Case {
    let bytes = encode(&w);
    assert_eq!(run_encoded(&bytes), Err(error), "native rejection: {name}");
    Case {
        name,
        bytes,
        expected: Err(error),
    }
}
fn cases() -> Vec<Case> {
    let mut cases = vec![good("funding", witness())];
    let mut w = witness();
    w.evidence[0].quote = body(feed(2), 80_000_000, 80_000_000, 80_000_000, 100);
    w.clock.1[0] = funding(&w.evidence[0], &w.policy);
    cases.push(good("depeg-funding", w));
    let mut w = witness();
    let e = PairEvidence {
        market_id: 0,
        now_ms: 101_000,
        base: body(
            feed(1),
            60_010 * PRICE_SCALE,
            60_009 * PRICE_SCALE,
            60_011 * PRICE_SCALE,
            101,
        ),
        quote: body(feed(2), PRICE_SCALE, PRICE_SCALE, PRICE_SCALE, 101),
    };
    w.clock.1.push(funding(&e, &w.policy));
    w.evidence.push(e);
    cases.push(good("two-observations", w));
    let mut w = witness();
    w.clock.1.clear();
    w.evidence.clear();
    cases.push(good("price-free-empty", w));
    let mut w = witness();
    w.evidence.clear();
    cases.push(bad("missing-evidence", w, Error::Evidence));
    let mut w = witness();
    w.evidence.push(w.evidence[0].clone());
    cases.push(bad("extra-evidence", w, Error::Evidence));
    let mut w = witness();
    w.evidence[0].market_id = 1;
    cases.push(bad("wrong-market", w, Error::Evidence));
    let mut w = witness();
    w.evidence[0].quote.0[..32].copy_from_slice(&feed(9));
    cases.push(bad("wrong-feed", w, Error::Feed));
    let mut w = witness();
    w.evidence[0].quote = body(feed(2), PRICE_SCALE, PRICE_SCALE, PRICE_SCALE, 89);
    cases.push(bad("stale-quote", w, Error::Time));
    let mut w = witness();
    w.evidence[0].quote = body(feed(2), PRICE_SCALE, PRICE_SCALE, PRICE_SCALE, 101);
    cases.push(bad("future-quote", w, Error::Time));
    let mut forged = witness();
    let n = Normalized {
        price: 120_000 * PRICE_SCALE,
        publish_time_ms: 100_000,
        confidence: PRICE_SCALE,
        backup_twap: 120_000 * PRICE_SCALE,
    };
    let oracle = sign(n);
    forged.clock.1[0] = BatchOp::AccrueFunding {
        market_id: 0,
        mark: n.price,
        oracle,
        now_ms: 100_000,
    };
    // This forged value still passes the original publisher-only transition.
    reanchor(&mut forged);
    cases.push(bad("forged-funding", forged.clone(), Error::Oracle));
    for (name, op) in [
        (
            "forged-fill",
            BatchOp::Fill {
                taker: [1; 32],
                maker: [2; 32],
                market_id: 0,
                taker_side: Side::Buy,
                size: 1,
                price: n.price,
                oracle,
                now_ms: 100_000,
            },
        ),
        (
            "forged-liquidation",
            BatchOp::Liquidate {
                owner: [1; 32],
                market_id: 0,
                oracle,
                now_ms: 100_000,
            },
        ),
        (
            "forged-unbind",
            BatchOp::Unbind {
                owner: [1; 32],
                market_id: 0,
                amount: 1,
                blinding: [2; 32],
                oracle,
                now_ms: 100_000,
            },
        ),
    ] {
        let mut w = forged.clone();
        w.clock.1[0] = op;
        cases.push(bad(name, w, Error::Oracle));
    }
    let mut w = witness();
    w.policy.chain_id = 8453;
    w.policy.network = 1;
    cases.push(bad("wrong-chain-context", w, Error::Policy));
    let mut w = witness();
    w.clock.3.previous_root[0] ^= 1;
    cases.push(bad("wrong-clock-context", w, Error::Clock));
    let mut w = witness();
    w.clock.0.markets.get_mut(&0).unwrap().id = 7;
    cases.push(bad("invalid-state-market", w, Error::Transition));
    let mut bytes = encode(&witness());
    bytes.push(0);
    assert_eq!(run_encoded(&bytes), Err(Error::Encoding));
    cases.push(Case {
        name: "trailing-bytes",
        bytes,
        expected: Err(Error::Encoding),
    });
    let mut bytes = encode(&witness());
    bytes[..8].copy_from_slice(perp_core::clock::WIRE_MAGIC);
    assert_eq!(run_encoded(&bytes), Err(Error::Version));
    cases.push(Case {
        name: "legacy-wire",
        bytes,
        expected: Err(Error::Version),
    });
    cases
}
fn hex(bytes: &[u8]) -> std::string::String {
    use std::fmt::Write as _;
    let mut s = std::string::String::new();
    for byte in bytes {
        write!(&mut s, "{byte:02x}").unwrap();
    }
    s
}
fn index_line(case: &Case) -> std::string::String {
    match case.expected {
        Ok(public) => std::format!("{}\tPASS\t{}\n", case.name, hex(&public)),
        Err(error) => std::format!("{}\tREJECT\t{error:?}\n", case.name),
    }
}
#[test]
fn committed_synthetic_vectors_match_native_regeneration() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/replay-v1");
    let cases = cases();
    let mut index = std::string::String::new();
    for case in &cases {
        let name = std::format!("{}.witness.bin", case.name);
        assert_eq!(
            fs::read(root.join(name)).unwrap(),
            case.bytes,
            "{}",
            case.name
        );
        assert_eq!(
            run_encoded(&case.bytes).map(|o| o.commitment),
            case.expected
        );
        index.push_str(&index_line(case));
    }
    assert_eq!(
        fs::read_to_string(root.join("native-results.tsv")).unwrap(),
        index
    );
    assert_eq!(cases.iter().filter(|c| c.expected.is_ok()).count(), 4);
    assert_eq!(cases.iter().filter(|c| c.expected.is_err()).count(), 15);
}
#[test]
#[ignore = "explicit export of public synthetic inputs to a fresh directory"]
fn export_synthetic_vectors() {
    let destination =
        std::env::var_os("ARCORA_CHAINLINK_REPLAY_EXPORT").expect("explicit export directory");
    let root = Path::new(&destination);
    fs::create_dir(root).expect("fresh directory required");
    let mut index = std::string::String::new();
    for case in cases() {
        let name = std::format!("{}.witness.bin", case.name);
        let mut out = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(root.join(name))
            .unwrap();
        out.write_all(&case.bytes).unwrap();
        out.sync_all().unwrap();
        index.push_str(&index_line(&case));
    }
    fs::write(root.join("native-results.tsv"), index).unwrap();
}

//! Deterministic property fuzzer. It applies long, randomized sequences of valid
//! and invalid operations to the engine and asserts the core invariants survive
//! EVERY step — most importantly collateral conservation. Because `apply_op` is
//! atomic, conservation must hold whether an op succeeds or is rejected; the
//! fuzzer hammers exactly that. No external crates: a small xorshift PRNG keeps
//! the run deterministic and reproducible from the seed printed on failure.

use perp_core::engine::BatchOp;
use perp_core::fixed::{PRICE_SCALE, QUOTE_SCALE, SIZE_SCALE};
use perp_core::hash::{word_u64, Keccak256};
use perp_core::market::Market;
use perp_core::oracle::OracleTranscript;
use perp_core::order::Side;
use perp_core::{DefaultState, Note};

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
}

fn owner(i: u64) -> [u8; 32] {
    word_u64(i + 1)
}

fn oracle(price_usd: i128, now: u64) -> OracleTranscript {
    OracleTranscript {
        price: price_usd * PRICE_SCALE,
        publish_time_ms: now,
        confidence: 5 * PRICE_SCALE,
        backup_twap: price_usd * PRICE_SCALE,
    }
}

/// Run one randomized session from `seed`, asserting conservation after each op.
fn run_session(seed: u64, steps: usize) {
    const N_OWNERS: u64 = 4;
    let mut s = DefaultState::new(20);
    s.add_market(Market::conservative(0));
    let mut rng = Rng(seed | 1);
    let mut now = 1_000u64;
    let mut price = 100_000i128;
    // pre-fund every owner so fills have collateral to work with
    for i in 0..N_OWNERS {
        let o = owner(i);
        let blind = [(i as u8) | 0x80; 32];
        let amount = 50_000 * QUOTE_SCALE;
        let cm = Note::new(o, 0, amount, blind).commitment::<Keccak256>();
        s.apply_op(&BatchOp::Deposit {
            owner: o,
            asset_id: 0,
            amount,
            blinding: blind,
        })
        .unwrap();
        s.apply_op(&BatchOp::FundPosition {
            owner: o,
            market_id: 0,
            note_commitment: cm,
            spend_key: [i as u8; 32],
        })
        .unwrap();
        assert!(s.conservation_holds());
    }

    for step in 0..steps {
        now += 1 + rng.below(5);
        // random walk the price within sane bounds
        let delta = (rng.below(2001) as i128) - 1000; // ±$1000
        price = (price + delta).clamp(40_000, 200_000);
        let orc = oracle(price, now);

        let op = match rng.below(6) {
            0 => {
                // matched fill between two distinct owners
                let a = rng.below(N_OWNERS);
                let b = (a + 1 + rng.below(N_OWNERS - 1)) % N_OWNERS;
                let size = (1 + rng.below(8)) as i128 * (SIZE_SCALE / 10);
                let side = if rng.below(2) == 0 {
                    Side::Buy
                } else {
                    Side::Sell
                };
                BatchOp::Fill {
                    taker: owner(a),
                    maker: owner(b),
                    market_id: 0,
                    taker_side: side,
                    size,
                    price: price * PRICE_SCALE,
                    oracle: orc,
                    now_ms: now,
                }
            }
            1 => BatchOp::AccrueFunding {
                market_id: 0,
                mark: (price + (rng.below(200) as i128) - 100) * PRICE_SCALE,
                oracle: orc,
                now_ms: now,
            },
            2 => BatchOp::Liquidate {
                owner: owner(rng.below(N_OWNERS)),
                market_id: 0,
                oracle: orc,
                now_ms: now,
            },
            3 => {
                let i = rng.below(N_OWNERS);
                let amount = (1 + rng.below(5000)) as i128 * QUOTE_SCALE;
                BatchOp::Deposit {
                    owner: owner(i),
                    asset_id: 0,
                    amount,
                    blinding: [(step as u8); 32],
                }
            }
            4 => {
                let i = rng.below(N_OWNERS);
                let amount = (1 + rng.below(2000)) as i128 * QUOTE_SCALE;
                BatchOp::Unbind {
                    owner: owner(i),
                    market_id: 0,
                    amount,
                    blinding: [0x40 | (step as u8); 32],
                    oracle: orc,
                    now_ms: now,
                }
            }
            _ => BatchOp::EnterCloseOnly,
        };

        // apply; success or rejection, conservation MUST hold (atomicity).
        let _ = s.apply_op(&op);
        assert!(
            s.conservation_holds(),
            "conservation broken — seed={seed} step={step} op={op:?}"
        );

        // re-open from close-only occasionally so the session keeps exercising fills
        if matches!(s.mode, perp_core::Mode::CloseOnly) && rng.below(4) == 0 {
            s.mode = perp_core::Mode::Normal;
        }
    }
}

#[test]
fn fuzz_conservation_holds_over_random_sessions() {
    // many independent seeds × long sessions
    for seed in 1..=200u64 {
        run_session(seed.wrapping_mul(0x9E3779B97F4A7C15), 300);
    }
}

#[test]
fn fuzz_state_root_is_deterministic() {
    // same seed ⇒ identical final state root (determinism is load-bearing for ZK)
    let root = |seed: u64| {
        let mut s = DefaultState::new(20);
        s.add_market(Market::conservative(0));
        // mirror run_session setup deterministically, then a few ops
        let mut rng = Rng(seed | 1);
        for i in 0..4u64 {
            let o = owner(i);
            let blind = [(i as u8) | 0x80; 32];
            let amount = 50_000 * QUOTE_SCALE;
            let cm = Note::new(o, 0, amount, blind).commitment::<Keccak256>();
            s.apply_op(&BatchOp::Deposit {
                owner: o,
                asset_id: 0,
                amount,
                blinding: blind,
            })
            .unwrap();
            s.apply_op(&BatchOp::FundPosition {
                owner: o,
                market_id: 0,
                note_commitment: cm,
                spend_key: [i as u8; 32],
            })
            .unwrap();
        }
        for _ in 0..20 {
            let a = rng.below(4);
            let b = (a + 1) % 4;
            let _ = s.apply_op(&BatchOp::Fill {
                taker: owner(a),
                maker: owner(b),
                market_id: 0,
                taker_side: Side::Buy,
                size: SIZE_SCALE / 5,
                price: 100_000 * PRICE_SCALE,
                oracle: oracle(100_000, 2_000),
                now_ms: 2_000,
            });
        }
        s.state_root()
    };
    assert_eq!(root(42), root(42), "same seed ⇒ same state root");
}

/// Oracle gate property fuzzer (validates the P4 checked-math fix at scale).
///
/// Feeds wild prices/confidence/twaps — including i128 extremes — at random clocks
/// and asserts the gate (1) NEVER panics (no overflow/wrap, since it must also run
/// in the zkVM guest), and (2) only returns `Ok(p)` when p == price and EVERY bound
/// genuinely holds. A single overflowing multiply slipping a bad price through, or
/// panicking the circuit, would show up here.
#[test]
fn fuzz_oracle_validate_is_total_and_sound() {
    use perp_core::fixed::{abs, RATE_SCALE};
    let m = Market::conservative(0);
    let mut rng = Rng(0xACE1);
    // a spread of magnitudes incl. extremes that exercise the checked multiplies
    let pool: [i128; 9] = [
        0,
        1,
        -1,
        100_000 * PRICE_SCALE,
        i128::MAX,
        i128::MIN,
        i128::MAX / 2,
        RATE_SCALE,
        1_000_000_000_000,
    ];
    let pick = |rng: &mut Rng| pool[(rng.below(pool.len() as u64)) as usize];

    for _ in 0..100_000 {
        let price = pick(&mut rng);
        let confidence = pick(&mut rng);
        let backup_twap = pick(&mut rng);
        let publish_time_ms = rng.next();
        let now_ms = rng.next();
        let t = OracleTranscript {
            price,
            publish_time_ms,
            confidence,
            backup_twap,
        };
        // (1) totality: must return a value, never panic/wrap.
        let res = t.validate(&m, now_ms);
        // (2) soundness: Ok ⇒ price returned verbatim AND every gate truly holds.
        if let Ok(p) = res {
            assert_eq!(p, price, "Ok must echo the price");
            assert!(price > 0, "Ok price must be positive");
            assert!(publish_time_ms <= now_ms, "Ok price not from the future");
            assert!(
                now_ms - publish_time_ms <= m.max_oracle_staleness_ms,
                "Ok price within staleness"
            );
            // confidence and deviation bounds recomputed with i128 headroom (i256-ish
            // via checked ops is overkill here; the pool values keep products in range
            // EXCEPT the extremes, which the gate rejects — so Ok ⇒ products fit).
            let conf_ok = abs(confidence)
                .checked_mul(RATE_SCALE)
                .zip(m.max_oracle_confidence_ratio.checked_mul(price))
                .map(|(l, r)| l <= r)
                .unwrap_or(false);
            assert!(conf_ok, "Ok ⇒ confidence bound holds");
            if backup_twap > 0 {
                let dev_ok = abs(price - backup_twap)
                    .checked_mul(RATE_SCALE)
                    .zip(m.max_oracle_deviation_ratio.checked_mul(price))
                    .map(|(l, r)| l <= r)
                    .unwrap_or(false);
                assert!(dev_ok, "Ok ⇒ deviation bound holds");
            }
        }
    }
}

/// Merkle tree property fuzzer (validates the P5 leaf-domain fix at scale).
///
/// Appends random leaves to random-depth trees and asserts: (1) every appended
/// leaf proves+verifies against the live root; (2) a wrong leaf, a tampered
/// sibling, or a re-pointed index all FAIL; (3) the inner-node value of any pair
/// is rejected when offered as a leaf (the second-preimage property the leaf
/// domain enforces). Determinism is also checked: same leaves ⇒ same root.
#[test]
fn fuzz_merkle_proofs_sound_and_second_preimage_safe() {
    use perp_core::hash::{Domain, Hasher};
    use perp_core::merkle::{MerkleProof, MerkleTree};

    let mut rng = Rng(0x5EED);
    for _ in 0..400 {
        let depth = (rng.below(6) + 2) as u8; // depth 2..=7 (cap 4..=128)
        let cap = 1u64 << depth;
        let n = 1 + rng.below(cap.min(40)); // at least one leaf
        let mut t: MerkleTree<Keccak256> = MerkleTree::new(depth);
        let mut leaves: Vec<[u8; 32]> = Vec::new();
        for _ in 0..n {
            let leaf = word_u64(rng.next());
            if t.append(leaf).is_ok() {
                leaves.push(leaf);
            }
        }
        let root = t.root();
        // determinism: rebuilding the same leaves gives the same root
        let mut t2: MerkleTree<Keccak256> = MerkleTree::new(depth);
        for l in &leaves {
            let _ = t2.append(*l);
        }
        assert_eq!(root, t2.root(), "same leaves ⇒ same root");

        for (i, leaf) in leaves.iter().enumerate() {
            let p = t.prove(i as u64).unwrap();
            assert!(
                MerkleTree::<Keccak256>::verify(&root, leaf, &p),
                "leaf verifies"
            );
            // wrong leaf rejected
            assert!(!MerkleTree::<Keccak256>::verify(
                &root,
                &word_u64(0xDEAD_0000 + i as u64),
                &p
            ));
            // tampered sibling rejected (if any siblings)
            if !p.siblings.is_empty() {
                let mut bad = p.clone();
                bad.siblings[0] = word_u64(0xBAD);
                assert!(
                    !MerkleTree::<Keccak256>::verify(&root, leaf, &bad),
                    "tampered rejected"
                );
            }
            // re-pointed index rejected (unless it happens to collide, vanishingly rare)
            if leaves.len() > 1 {
                let mut moved = p.clone();
                moved.leaf_index ^= 1;
                assert!(
                    !MerkleTree::<Keccak256>::verify(&root, leaf, &moved),
                    "index-bound"
                );
            }
        }
        // second-preimage: the inner node over leaves 0,1 must not pass as a leaf
        if leaves.len() >= 2 {
            let l0 = Keccak256::hash_words(Domain::MerkleLeaf, &[leaves[0]]);
            let l1 = Keccak256::hash_words(Domain::MerkleLeaf, &[leaves[1]]);
            let inner = Keccak256::compress(Domain::MerkleNode, &l0, &l1);
            let p0 = t.prove(0).unwrap();
            if p0.siblings.len() >= 2 {
                let forged = MerkleProof {
                    leaf_index: 0,
                    siblings: p0.siblings[1..].to_vec(),
                };
                assert!(
                    !MerkleTree::<Keccak256>::verify(&root, &inner, &forged),
                    "inner node rejected as leaf"
                );
            }
        }
    }
}

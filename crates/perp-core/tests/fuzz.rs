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
use perp_core::order::Side;
use perp_core::oracle::OracleTranscript;
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
        s.apply_op(&BatchOp::Deposit { owner: o, asset_id: 0, amount, blinding: blind }).unwrap();
        s.apply_op(&BatchOp::FundPosition { owner: o, market_id: 0, note_commitment: cm, spend_key: [i as u8; 32] }).unwrap();
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
                let side = if rng.below(2) == 0 { Side::Buy } else { Side::Sell };
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
                BatchOp::Deposit { owner: owner(i), asset_id: 0, amount, blinding: [(step as u8); 32] }
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
            s.apply_op(&BatchOp::Deposit { owner: o, asset_id: 0, amount, blinding: blind }).unwrap();
            s.apply_op(&BatchOp::FundPosition { owner: o, market_id: 0, note_commitment: cm, spend_key: [i as u8; 32] }).unwrap();
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

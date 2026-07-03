//! Multi-batch sequencer fuzzer. Drives many randomized batches (orders,
//! deposits, oracle moves, close-only) and asserts the cross-batch invariants
//! after EVERY sealed batch — the surface where the maker-drift bug lived:
//!
//!  * collateral conservation holds;
//!  * the manifest's `ordered` and `rejected` sets are disjoint;
//!  * every settled order is in `ordered`;
//!  * no order hash appears in both `ordered` and `settlement_rejected`;
//!  * the honest flow surfaces no inclusion violations.

use perp_core::engine::BatchOp;
use perp_core::fixed::{PRICE_SCALE, QUOTE_SCALE, SIZE_SCALE};
use perp_core::hash::{word_u64, Keccak256};
use perp_core::market::Market;
use perp_core::note::{owner_from_spend_key, PubKey};
use perp_core::oracle::OracleTranscript;
use perp_core::order::{Finality, Order, Side, TimeInForce};
use perp_core::Note;
use sequencer::{EnclaveIdentity, Sequencer};
use std::collections::BTreeSet;

/// Owner `i`'s public owner id, derived from the spend key `[i; 32]` used to fund
/// and spend its notes (audit DP-003: a note's `owner` MUST equal
/// `owner_from_spend_key(&spend_key)`). Used wherever the account is named.
fn owner_id(i: u64) -> PubKey {
    owner_from_spend_key::<Keccak256>(&[i as u8; 32])
}

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

fn oracle(price_usd: i128, now: u64) -> OracleTranscript {
    OracleTranscript {
        price: price_usd * PRICE_SCALE,
        publish_time_ms: now,
        confidence: 5 * PRICE_SCALE,
        backup_twap: price_usd * PRICE_SCALE,
    }
}

fn rand_order(rng: &mut Rng, n_owners: u64, price: i128, nonce: u64) -> Order {
    let side = if rng.below(2) == 0 {
        Side::Buy
    } else {
        Side::Sell
    };
    Order {
        owner: owner_id(rng.below(n_owners)),
        market_id: 0,
        side,
        size: (1 + rng.below(15)) as i128 * (SIZE_SCALE / 10),
        limit_price: if rng.below(4) == 0 {
            0
        } else {
            (price - 50 + rng.below(100) as i128) * PRICE_SCALE
        },
        tif: match rng.below(4) {
            0 => TimeInForce::Ioc,
            1 => TimeInForce::Fok,
            2 => TimeInForce::PostOnly,
            _ => TimeInForce::Gtc,
        },
        reduce_only: false,
        nonce,
        expiry_ms: 0,
        ciphertext_commit: word_u64(nonce.wrapping_mul(40503)),
    }
}

fn assert_invariants(
    s: &Sequencer,
    sealed: &sequencer::SealedBatch,
    this_batch: &BTreeSet<[u8; 32]>,
    seed: u64,
) {
    assert!(
        s.state.conservation_holds(),
        "seed={seed}: conservation broke at batch {}",
        sealed.batch_id
    );
    let ordered: BTreeSet<_> = sealed.manifest.ordered.iter().copied().collect();
    let rejected: BTreeSet<_> = sealed.manifest.rejected.iter().map(|(h, _)| *h).collect();
    // disjointness is an absolute manifest invariant
    assert!(
        ordered.is_disjoint(&rejected),
        "seed={seed}: ordered∩rejected non-empty"
    );
    // `ordered` only ever contains THIS batch's submitted orders (not cross-batch
    // resting makers that happen to settle here)
    assert!(
        ordered.is_subset(this_batch),
        "seed={seed}: ordered has a non-this-batch hash"
    );
    // a settled order that was submitted THIS batch must be in `ordered`
    for h in &sealed.settled_order_hashes {
        if this_batch.contains(h) {
            assert!(
                ordered.contains(h),
                "seed={seed}: this-batch settled order not in ordered"
            );
        }
    }
    // a this-batch order that did NOT settle but was settlement-rejected must not
    // remain in `ordered`
    for (h, _) in &sealed.settlement_rejected {
        if this_batch.contains(h) && !sealed.settled_order_hashes.contains(h) {
            assert!(
                !ordered.contains(h),
                "seed={seed}: unsettled reject still in ordered"
            );
        }
    }
}

fn run_session(seed: u64, batches: usize) {
    const N: u64 = 5;
    let enclave = EnclaveIdentity::from_seed([7u8; 32], 1, [0xAB; 32]);
    let mut s = Sequencer::new(enclave, 22);
    s.add_market(Market::conservative(0));
    let mut rng = Rng(seed | 1);
    let mut now = 1_000u64;
    let mut price = 100_000i128;
    let mut blind_ctr: u64 = 0;

    // pre-fund all owners
    s.set_oracle(0, oracle(price, now));
    for i in 0..N {
        let o = owner_id(i);
        blind_ctr += 1;
        let mut blind = [0u8; 32];
        blind[..8].copy_from_slice(&blind_ctr.to_le_bytes());
        let amt = 100_000 * QUOTE_SCALE;
        let cm = Note::new(o, 0, amt, blind).commitment::<Keccak256>();
        s.apply(&BatchOp::Deposit {
            owner: o,
            asset_id: 0,
            amount: amt,
            blinding: blind,
        })
        .unwrap();
        s.apply(&BatchOp::FundPosition {
            owner: o,
            market_id: 0,
            note_commitment: cm,
            spend_key: [i as u8; 32],
        })
        .unwrap();
    }

    let mut nonce = 0u64;
    for _ in 0..batches {
        now += 1 + rng.below(10);
        price = (price + (rng.below(401) as i128) - 200).clamp(60_000, 160_000);
        s.set_oracle(0, oracle(price, now));

        // occasional close-only toggle / re-open
        if rng.below(20) == 0 {
            s.apply(&BatchOp::EnterCloseOnly).ok();
        }

        let k = rng.below(8) as usize;
        let mut orders = Vec::new();
        for _ in 0..k {
            nonce += 1;
            orders.push(rand_order(&mut rng, N, price, nonce));
        }
        let this_batch: BTreeSet<[u8; 32]> =
            orders.iter().map(|o| o.order_hash::<Keccak256>()).collect();
        let sealed = s.seal_batch(&orders, now);
        assert_invariants(&s, &sealed, &this_batch, seed);

        // sometimes the batch fails to prove → rollback must restore the exact
        // pre-batch root and keep conservation (§3 failure matrix).
        if rng.below(5) == 0 {
            assert!(
                s.mark_failed(sealed.batch_id),
                "seed={seed}: rollback should apply"
            );
            assert_eq!(
                s.state.state_root(),
                sealed.prev_state_root,
                "seed={seed}: rollback must restore the pre-batch root"
            );
            assert!(
                s.state.conservation_holds(),
                "seed={seed}: conservation broke on rollback"
            );
        } else if rng.below(2) == 0 {
            // proof landed
            s.mark_settled(sealed.batch_id);
        }
        // re-open from close-only so the session keeps trading
        if matches!(s.state.mode, perp_core::Mode::CloseOnly) {
            s.state.mode = perp_core::Mode::Normal;
        }
    }
    // honest flow: with reasonable inclusion timeout, no censorship violations
    assert!(
        s.inclusion_violations(1_000).is_empty(),
        "seed={seed}: spurious inclusion violation"
    );
}

#[test]
fn fuzz_sequencer_multi_batch_invariants() {
    for seed in 1..=120u64 {
        run_session(seed.wrapping_mul(0x9E3779B97F4A7C15), 40);
    }
}

/// P3 property fuzzer: an order the sequencer REJECTED for cause must never be
/// reported as an inclusion violation (censorship). Accept a batch of orders
/// (issuing receipts), submit a random subset to a seal, then advance past the
/// inclusion timeout and assert every surfaced violation is a genuinely WITHHELD
/// order (accepted but never submitted) — never a submitted-then-rejected one.
fn run_p3_session(seed: u64) {
    const N: u64 = 5;
    // fund only owners 0,1,2 — orders from 3,4 are pre-trade rejected at seal.
    let enclave = EnclaveIdentity::from_seed([7u8; 32], 1, [0xAB; 32]);
    let mut s = Sequencer::new(enclave, 22);
    s.add_market(Market::conservative(0));
    let now = 1_000u64;
    s.set_oracle(0, oracle(100_000, now));
    for i in 0..3u64 {
        let o = owner_id(i);
        let mut blind = [0u8; 32];
        blind[..8].copy_from_slice(&(i + 1).to_le_bytes());
        let amt = 100_000 * QUOTE_SCALE;
        let cm = Note::new(o, 0, amt, blind).commitment::<Keccak256>();
        s.apply(&BatchOp::Deposit {
            owner: o,
            asset_id: 0,
            amount: amt,
            blinding: blind,
        })
        .unwrap();
        s.apply(&BatchOp::FundPosition {
            owner: o,
            market_id: 0,
            note_commitment: cm,
            spend_key: [i as u8; 32],
        })
        .unwrap();
    }

    let mut rng = Rng(seed | 1);
    let mut submitted: BTreeSet<[u8; 32]> = BTreeSet::new();
    let mut withheld: BTreeSet<[u8; 32]> = BTreeSet::new();
    let mut to_submit = Vec::new();
    let m = 4 + rng.below(8);
    for n in 0..m {
        let o = rand_order(&mut rng, N, 100_000, n + 1);
        let h = o.order_hash::<Keccak256>();
        // accept_order issues a receipt (and an inclusion record) for every order
        let _ = s.accept_order(&o, now);
        if rng.below(2) == 0 {
            submitted.insert(h);
            to_submit.push(o);
        } else {
            withheld.insert(h);
        }
    }
    // a submitted order may share a hash with nothing else (unique nonces); seal them
    s.seal_batch(&to_submit, now);
    // advance well past the inclusion timeout with empty batches
    let timeout = 2u64;
    for _ in 0..(timeout + 2) {
        s.seal_batch(&[], now);
    }
    let violations: BTreeSet<[u8; 32]> = s.inclusion_violations(timeout).into_iter().collect();
    // CORE P3 PROPERTY: nothing the sequencer handled (ordered OR rejected) is a violation.
    for v in &violations {
        assert!(
            !submitted.contains(v),
            "seed={seed}: a submitted (handled) order surfaced as a censorship violation"
        );
        assert!(
            withheld.contains(v),
            "seed={seed}: a violation that was never an accepted+withheld order"
        );
    }
}

#[test]
fn fuzz_rejected_orders_are_not_inclusion_violations() {
    for seed in 1..=200u64 {
        run_p3_session(seed.wrapping_mul(0x9E3779B97F4A7C15));
    }
}

/// §3 height-finalization property: a proof for batch H finalizes H **and every
/// still-pending batch before it** (the snapshots ≤ H are pruned, so they are
/// hard — a hard fill is SETTLED, never stranded at MATCHED). Seal a run of
/// batches that all stay pending (MATCHED), then settle ONE random height H and
/// assert every order in a batch ≤ H is SETTLED while later batches stay MATCHED.
fn run_height_settle(seed: u64) {
    let enclave = EnclaveIdentity::from_seed([7u8; 32], 1, [0xAB; 32]);
    let mut s = Sequencer::new(enclave, 22);
    s.add_market(Market::conservative(0));
    let mut rng = Rng(seed | 1);
    let mut now = 1_000u64;
    let price = 100_000i128;
    s.set_oracle(0, oracle(price, now));
    // fund two opposing traders
    for i in 0..2u64 {
        let o = owner_id(i);
        let mut blind = [0u8; 32];
        blind[..8].copy_from_slice(&(i + 1).to_le_bytes());
        let amt = 1_000_000 * QUOTE_SCALE;
        let cm = Note::new(o, 0, amt, blind).commitment::<Keccak256>();
        s.apply(&BatchOp::Deposit {
            owner: o,
            asset_id: 0,
            amount: amt,
            blinding: blind,
        })
        .unwrap();
        s.apply(&BatchOp::FundPosition {
            owner: o,
            market_id: 0,
            note_commitment: cm,
            spend_key: [i as u8; 32],
        })
        .unwrap();
    }

    // seal a run of crossing pairs; keep every batch PENDING (no settle/fail).
    let n_batches = 2 + rng.below(8);
    let mut hashes_by_batch: Vec<(u64, Vec<[u8; 32]>)> = Vec::new();
    let mut nonce = 0u64;
    for _ in 0..n_batches {
        now += 1 + rng.below(5);
        s.set_oracle(0, oracle(price, now));
        nonce += 1;
        let buy = Order {
            owner: owner_id(0),
            market_id: 0,
            side: Side::Buy,
            size: SIZE_SCALE / 10,
            limit_price: price * PRICE_SCALE,
            tif: TimeInForce::Gtc,
            reduce_only: false,
            nonce,
            expiry_ms: 0,
            ciphertext_commit: word_u64(nonce.wrapping_mul(7)),
        };
        nonce += 1;
        let sell = Order {
            owner: owner_id(1),
            side: Side::Sell,
            nonce,
            ciphertext_commit: word_u64(nonce.wrapping_mul(7)),
            ..buy
        };
        let sealed = s.seal_batch(&[buy, sell], now);
        hashes_by_batch.push((sealed.batch_id, sealed.settled_order_hashes.clone()));
    }

    // every order is MATCHED while pending
    for (_, hs) in &hashes_by_batch {
        for h in hs {
            assert_eq!(
                s.finality_of(h),
                Some(Finality::Matched),
                "seed={seed}: pre-settle finality"
            );
        }
    }

    // settle ONE random height; everything ≤ H must become SETTLED, the rest MATCHED.
    let h = hashes_by_batch[rng.below(hashes_by_batch.len() as u64) as usize].0;
    s.mark_settled(h);
    for (bid, hs) in &hashes_by_batch {
        let expected = if *bid <= h {
            Finality::Settled
        } else {
            Finality::Matched
        };
        for oh in hs {
            assert_eq!(
                s.finality_of(oh),
                Some(expected),
                "seed={seed}: batch {bid} vs settled height {h} — wrong finality"
            );
        }
    }
}

#[test]
fn fuzz_settling_a_height_finalizes_all_prior_batches() {
    for seed in 1..=200u64 {
        run_height_settle(seed.wrapping_mul(0x9E3779B97F4A7C15));
    }
}

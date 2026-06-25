//! Property fuzzer for the bridge: decomposition must be value-exact (buckets +
//! remainder == amount, remainder < unit, all denominations valid), and mixing
//! must preserve the entry multiset.

use bridge::{decompose, denominations, unit, Direction, MixBatch};
use perp_core::fixed::QUOTE_SCALE;

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
}

#[test]
fn fuzz_decompose_is_value_exact() {
    let denoms = denominations();
    let mut rng = Rng(0x1234_5678);
    for _ in 0..5000 {
        // amounts from 0 up to ~$1.2M in micro-USD granularity
        let amount = (rng.next() % (1_200_000 * QUOTE_SCALE as u64)) as i128;
        let (buckets, remainder) = decompose(amount);
        let sum: i128 = buckets.iter().map(|(d, c)| d * *c as i128).sum();
        assert_eq!(
            sum + remainder,
            amount,
            "buckets + remainder must equal amount"
        );
        assert!(
            remainder >= 0 && remainder < unit(),
            "remainder in [0, unit)"
        );
        for (d, c) in &buckets {
            assert!(denoms.contains(d), "bucket uses a valid denomination");
            assert!(*c > 0, "bucket count positive");
        }
    }
}

#[test]
fn fuzz_negative_amount_is_inert() {
    let mut rng = Rng(0xBEEF);
    for _ in 0..1000 {
        let amount = -((rng.next() % 1_000_000) as i128) - 1;
        let (buckets, remainder) = decompose(amount);
        assert!(
            buckets.is_empty() && remainder == 0,
            "negatives bridge nothing"
        );
    }
}

#[test]
fn fuzz_mix_preserves_multiset() {
    let mut rng = Rng(0xACE);
    for round in 0..300u64 {
        let mut batch = MixBatch::new();
        let k = 1 + (rng.next() % 8) as usize;
        for i in 0..k {
            let amt = (1 + rng.next() % 9999) as i128 * QUOTE_SCALE;
            batch.add_transfer(
                Direction::Deposit,
                [(i as u8); 32],
                amt,
                [(round as u8); 32],
            );
        }
        let mut before: Vec<i128> = batch.public_denominations();
        batch.mix(&[(round as u8).wrapping_add(1); 32]);
        let mut after: Vec<i128> = batch.public_denominations();
        before.sort_unstable();
        after.sort_unstable();
        assert_eq!(before, after, "mixing preserves the denomination multiset");
    }
}

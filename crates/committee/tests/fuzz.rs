//! Property fuzzer for Shamir t-of-n: for random (secret, t, n) and a random
//! t-subset of shares, reconstruction must return the exact secret; a (t-1)-subset
//! must not. Deterministic xorshift PRNG.

use committee::shamir;

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

#[test]
fn fuzz_any_t_subset_reconstructs() {
    for seed in 1..=400u64 {
        let mut rng = Rng(seed.wrapping_mul(0x9E3779B97F4A7C15) | 1);
        let n = (2 + rng.below(8)) as usize; // 2..=9
        let t = (1 + rng.below(n as u64)) as usize; // 1..=n
        let len = (1 + rng.below(40)) as usize;
        let secret: Vec<u8> = (0..len).map(|_| rng.below(256) as u8).collect();
        let mut seed_bytes = [0u8; 32];
        for b in seed_bytes.iter_mut() {
            *b = rng.below(256) as u8;
        }

        let shares = shamir::split(&secret, t, n, &seed_bytes);
        assert_eq!(shares.len(), n);

        // pick a random t-subset (Fisher-Yates over indices)
        let mut idx: Vec<usize> = (0..n).collect();
        for i in (1..n).rev() {
            let j = (rng.below(i as u64 + 1)) as usize;
            idx.swap(i, j);
        }
        let subset: Vec<_> = idx[..t].iter().map(|&i| shares[i].clone()).collect();
        assert_eq!(
            shamir::combine(&subset).as_deref(),
            Some(&secret[..]),
            "seed={seed}: t-of-n subset must reconstruct"
        );

        // a (t-1)-subset must NOT reconstruct the secret (negligible chance of a
        // multi-byte secret matching by accident).
        if t >= 2 && len >= 2 {
            let smaller: Vec<_> = idx[..t - 1].iter().map(|&i| shares[i].clone()).collect();
            assert_ne!(
                shamir::combine(&smaller).as_deref(),
                Some(&secret[..]),
                "seed={seed}: fewer than t shares must not reveal the secret"
            );
        }
    }
}

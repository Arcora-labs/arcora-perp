//! Shamir secret sharing over GF(256) — the threshold order-key mechanism (§11).
//!
//! An order's symmetric key is split into `n` shares such that any `t` of them
//! reconstruct it and any `t-1` reveal nothing. Held one-per-enclave, this means
//! **no single enclave can decrypt an order alone** — the "operatör-kör +
//! threshold" confidentiality redundancy of the committee. GF(256) (the AES
//! field) gives byte-wise sharing with standard, auditable arithmetic.
//!
//! Coefficients here are derived deterministically from a caller seed via Keccak
//! so tests are reproducible; **production must use a CSPRNG** for the non-constant
//! coefficients. This is documented, not hidden.
//!
//! ## Why the seed must be secret AND fresh per secret
//!
//! The threshold guarantee assumes coefficients `a1..a_{t-1}` are *secret*. With a
//! known seed they are recomputable, and then **a single share breaks
//! confidentiality**: an attacker holding one share `(x, y)` and the seed can
//! evaluate `a1·x + … + a_{t-1}·x^{t-1}` and solve `a0 = y ⊖ (…)` — recovering the
//! secret with *one* share instead of `t`. So in production the seed must come from
//! a CSPRNG, never be revealed, and never be reused across secrets (reuse leaks the
//! difference of two secrets). The deterministic seed here is strictly a test
//! affordance.

use perp_core::hash::{word_u64, Domain, Hasher, Keccak256};

/// GF(256) multiplication (AES reduction polynomial 0x11b).
fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    for _ in 0..8 {
        if b & 1 != 0 {
            p ^= a;
        }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    p
}

fn gf_pow(mut base: u8, mut exp: u32) -> u8 {
    let mut acc = 1u8;
    while exp > 0 {
        if exp & 1 == 1 {
            acc = gf_mul(acc, base);
        }
        base = gf_mul(base, base);
        exp >>= 1;
    }
    acc
}

/// Multiplicative inverse in GF(256): a^254 (a ≠ 0).
fn gf_inv(a: u8) -> u8 {
    gf_pow(a, 254)
}

/// One participant's share: an x-coordinate and the y-bytes (one per secret byte).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Share {
    pub x: u8,
    pub y: Vec<u8>,
}

/// Split `secret` into `n` shares with threshold `t` (`1 <= t <= n <= 255`).
/// Non-constant coefficients are derived from `seed` (deterministic for tests;
/// use a CSPRNG in production).
pub fn split(secret: &[u8], t: usize, n: usize, seed: &[u8; 32]) -> Vec<Share> {
    assert!(t >= 1 && t <= n && n <= 255, "invalid (t, n)");
    let mut shares: Vec<Share> = (1..=n as u8)
        .map(|x| Share {
            x,
            y: Vec::with_capacity(secret.len()),
        })
        .collect();

    for (bi, &s) in secret.iter().enumerate() {
        // polynomial coefficients: a0 = secret byte, a1..a_{t-1} from the seed
        let mut coeffs = Vec::with_capacity(t);
        coeffs.push(s);
        for k in 1..t {
            // Dedicated tag — secret-sharing coefficients must not share a preimage
            // structure with note nullifiers (one-domain-one-purpose).
            let h = Keccak256::hash_words(
                Domain::ShamirShare,
                &[*seed, word_u64(bi as u64), word_u64(k as u64)],
            );
            coeffs.push(h[0]);
        }
        for sh in shares.iter_mut() {
            sh.y.push(eval(&coeffs, sh.x));
        }
    }
    shares
}

/// Evaluate polynomial (Horner) at `x` in GF(256).
fn eval(coeffs: &[u8], x: u8) -> u8 {
    let mut acc = 0u8;
    for &c in coeffs.iter().rev() {
        acc = gf_mul(acc, x) ^ c;
    }
    acc
}

/// Reconstruct the secret from `>= t` shares via Lagrange interpolation at x = 0.
/// Returns `None` if shares are inconsistent (e.g. duplicate x, empty).
pub fn combine(shares: &[Share]) -> Option<Vec<u8>> {
    if shares.is_empty() {
        return None;
    }
    let len = shares[0].y.len();
    if shares.iter().any(|s| s.y.len() != len) {
        return None;
    }
    // duplicate x-coordinates are invalid
    for i in 0..shares.len() {
        for j in (i + 1)..shares.len() {
            if shares[i].x == shares[j].x {
                return None;
            }
        }
    }

    let mut secret = Vec::with_capacity(len);
    for bi in 0..len {
        let mut acc = 0u8;
        for (j, sj) in shares.iter().enumerate() {
            // Lagrange basis l_j(0) = prod_{m != j} x_m / (x_m - x_j)
            let mut num = 1u8;
            let mut den = 1u8;
            for (m, sm) in shares.iter().enumerate() {
                if m == j {
                    continue;
                }
                num = gf_mul(num, sm.x);
                den = gf_mul(den, sm.x ^ sj.x); // subtraction == xor
            }
            let l0 = gf_mul(num, gf_inv(den));
            acc ^= gf_mul(sj.y[bi], l0);
        }
        secret.push(acc);
    }
    Some(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: [u8; 32] = [9u8; 32];

    #[test]
    fn any_t_subset_reconstructs() {
        let secret = b"order-symmetric-key-32-bytes!!!!";
        let shares = split(secret, 3, 5, &SEED);
        // every 3-of-5 subset reconstructs
        for combo in [[0, 1, 2], [0, 2, 4], [1, 3, 4], [2, 3, 4]] {
            let subset: Vec<Share> = combo.iter().map(|&i| shares[i].clone()).collect();
            assert_eq!(combine(&subset).as_deref(), Some(&secret[..]));
        }
    }

    #[test]
    fn fewer_than_t_does_not_reveal() {
        let secret = b"top-secret-key";
        let shares = split(secret, 3, 5, &SEED);
        // 2 shares (< t=3) must NOT reconstruct the secret
        let two: Vec<Share> = shares[..2].to_vec();
        let guessed = combine(&two);
        assert!(guessed.is_none() || guessed.as_deref() != Some(&secret[..]));
    }

    #[test]
    fn duplicate_x_rejected() {
        let shares = split(b"x", 2, 3, &SEED);
        let dup = vec![shares[0].clone(), shares[0].clone()];
        assert!(combine(&dup).is_none());
    }

    #[test]
    fn t_equals_n_needs_everyone() {
        let secret = b"all-must-agree";
        let shares = split(secret, 4, 4, &SEED);
        assert_eq!(combine(&shares).as_deref(), Some(&secret[..]));
        assert_ne!(combine(&shares[..3]).as_deref(), Some(&secret[..]));
    }
}

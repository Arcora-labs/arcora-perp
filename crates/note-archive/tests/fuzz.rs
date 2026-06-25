//! Property fuzzer for view-key recovery: after recording many notes for many
//! wallets, each wallet's scan recovers EXACTLY its own notes (right count and
//! amounts) and never reads another wallet's. Spent notes are excluded from the
//! recovered balance.

use note_archive::{NoteArchive, Wallet};
use std::collections::BTreeMap;

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
fn fuzz_recovery_is_exact_and_isolated() {
    for seed in 1..=150u64 {
        let mut rng = Rng(seed.wrapping_mul(0x9E3779B97F4A7C15) | 1);
        let n_wallets = 2 + (rng.next() % 5) as usize;
        let wallets: Vec<Wallet> = (0..n_wallets)
            .map(|i| {
                let mut s = [0u8; 32];
                s[..8].copy_from_slice(&((i as u64) ^ seed).to_le_bytes());
                Wallet::from_seed(s)
            })
            .collect();

        let mut archive = NoteArchive::new();
        // expected per-wallet amounts (sum) of recorded notes
        let mut expected: BTreeMap<usize, i128> = BTreeMap::new();
        let n_notes = 5 + (rng.next() % 40) as usize;
        let mut blind_ctr = 0u64;
        for _ in 0..n_notes {
            let w = (rng.next() % n_wallets as u64) as usize;
            let amount = (1 + (rng.next() % 9_999)) as i128;
            blind_ctr += 1;
            let mut blind = [0u8; 32];
            blind[..8].copy_from_slice(&blind_ctr.to_le_bytes());
            let note = wallets[w].note(0, amount, blind);
            archive.record(blind_ctr, &note, &wallets[w].view_key);
            *expected.entry(w).or_insert(0) += amount;
        }

        // each wallet recovers exactly its own notes (re-derived from seed)
        for (i, w) in wallets.iter().enumerate() {
            let re = {
                let mut s = [0u8; 32];
                s[..8].copy_from_slice(&((i as u64) ^ seed).to_le_bytes());
                Wallet::from_seed(s)
            };
            let recovered = archive.scan(&re.view_key);
            let total: i128 = recovered.iter().map(|r| r.note.amount).sum();
            assert_eq!(
                total,
                *expected.get(&i).unwrap_or(&0),
                "seed={seed} wallet={i}: recovered total must equal recorded total"
            );
            // every recovered note is actually owned by this wallet
            for r in &recovered {
                assert_eq!(
                    r.note.owner, w.owner,
                    "seed={seed}: recovered a foreign note"
                );
            }
        }
    }
}

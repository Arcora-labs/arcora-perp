//! Canonical batch root-derivation — the ONE implementation the zkVM guest, the
//! prover's `run_transition`, and the SP1 host's native reference all share. The
//! guest DERIVES these roots (it does not accept them as trusted witness inputs), so
//! under a real verifier the prover cannot supply an arbitrary withdrawals/ordered/
//! rejected root. Matching-fairness (the ordered-vs-rejected SPLIT) is NOT proven
//! here — that is Proof-v2; this derives the roots structurally from the manifest and
//! constrains withdrawals to the burned notes.

use crate::engine::BatchOp;
use crate::hash::{word_u64, Digest, Domain, Hasher};
use crate::merkle::{ordered_root, rejected_root, withdrawals_root, WithdrawalLeaf};
use crate::order::BatchManifest;
use crate::{DefaultState, EngineError};
use alloc::vec::Vec;

/// The seven roots the batch proof commits to (byte-identical to the L1
/// `DarkPerpSettlement.publicCommitment`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DerivedRoots {
    pub prev_state_root: Digest,
    pub manifest_hash: Digest,
    pub new_state_root: Digest,
    pub ordered_root: Digest,
    pub withdrawals_root: Digest,
    pub rejected_root: Digest,
    /// SEC-019: the post-batch deposit hash-chain tip. L1 compares this against the
    /// vault's own `depositChainTip` for the same count, so a batch cannot credit a
    /// deposit that no `Deposited` event produced.
    pub deposits_root: Digest,
    /// 0 = ordinary batch, 1 = one-shot SettleAll, 2 = post-wind-down exits.
    pub wind_down_phase: u8,
}

pub fn classify_wind_down_ops(ops: &[BatchOp]) -> Result<u8, EngineError> {
    if ops.len() == 1 && matches!(ops[0], BatchOp::SettleAll) {
        return Ok(1);
    }
    if !ops.is_empty()
        && ops.iter().all(|op| {
            matches!(
                op,
                BatchOp::WindDownUnbind { .. } | BatchOp::WindDownWithdraw { .. }
            )
        })
    {
        return Ok(2);
    }
    if ops.iter().any(|op| {
        matches!(
            op,
            BatchOp::SettleAll | BatchOp::WindDownUnbind { .. } | BatchOp::WindDownWithdraw { .. }
        )
    }) {
        return Err(EngineError::WindDownGrammar);
    }
    Ok(0)
}

impl DerivedRoots {
    /// The proof's public commitment: `keccak_words(StateRoot, [seven roots])`.
    pub fn commitment<H: Hasher>(&self) -> Digest {
        let ordinary = [
            self.prev_state_root,
            self.manifest_hash,
            self.new_state_root,
            self.ordered_root,
            self.withdrawals_root,
            self.rejected_root,
            self.deposits_root,
        ];
        if self.wind_down_phase == 0 {
            H::hash_words(Domain::StateRoot, &ordinary)
        } else {
            let mut words = ordinary.to_vec();
            words.push(word_u64(self.wind_down_phase as u64));
            H::hash_words(Domain::StateRoot, &words)
        }
    }
}

/// Execute the batch transition and DERIVE all seven roots. Mutates `state` to the
/// post-state. Fails `ManifestMismatch` if the manifest is not the one for this
/// pre-state, or propagates any engine rejection.
pub fn derive_roots(
    state: &mut DefaultState,
    ops: &[BatchOp],
    manifest: &BatchManifest,
) -> Result<DerivedRoots, EngineError> {
    let wind_down_phase = classify_wind_down_ops(ops)?;
    let prev_state_root = state.state_root();
    let batch_id = state.next_batch_id;
    // tie the manifest to the state (BOUNDARY 1: structural only — no matcher rerun)
    if manifest.previous_state_root != prev_state_root || manifest.batch_id != batch_id {
        return Err(EngineError::ManifestMismatch);
    }
    // 2026-10-08 review: the state root hashes the markets map KEY, never
    // `Market.id` — a decoded witness state could carry `Market { id: X }` under
    // key `Y ≠ X` with an unchanged root. Fail closed before deriving anything.
    state.validate_market_keys()?;
    // 2026-10-08 review: every clock-carrying op must agree with the manifest's
    // committed reference clock, so oracle freshness is checked against a publicly
    // committed time (see `BatchManifest::batch_time_ms`), not a per-op private value.
    for op in ops {
        let op_now = match op {
            BatchOp::Fill { now_ms, .. }
            | BatchOp::AccrueFunding { now_ms, .. }
            | BatchOp::Liquidate { now_ms, .. }
            | BatchOp::Unbind { now_ms, .. } => *now_ms,
            _ => continue,
        };
        if op_now != manifest.batch_time_ms {
            return Err(EngineError::ClockMismatch);
        }
    }
    let outputs = state.apply_batch(ops)?;
    let new_state_root = state.state_root();
    // SEC-019: the POST-apply tip — every deposit this batch consumed is already
    // folded in (`op_deposit`), so the 7th commitment word is what L1 must match.
    let deposits_root = state.consumed_deposit_tip;

    let manifest_hash = manifest.hash::<crate::hash::Keccak256>();
    let ordered_root = ordered_root(batch_id, &manifest.ordered);
    let rejected_hashes: Vec<Digest> = manifest.rejected.iter().map(|(h, _)| *h).collect();
    let rejected_root = rejected_root(batch_id, &rejected_hashes);
    let wl: Vec<WithdrawalLeaf> = outputs
        .withdrawals
        .iter()
        .map(WithdrawalLeaf::from)
        .collect();
    let withdrawals_root = withdrawals_root(&wl);

    Ok(DerivedRoots {
        prev_state_root,
        manifest_hash,
        new_state_root,
        ordered_root,
        withdrawals_root,
        rejected_root,
        deposits_root,
        wind_down_phase,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixed::QUOTE_SCALE;
    use crate::hash::Keccak256;
    use crate::market::Market;
    use crate::note::owner_from_spend_key;
    use crate::order::BatchManifest;
    use crate::Note;
    use alloc::vec;

    fn manifest_for(state: &DefaultState, ordered: Vec<Digest>) -> BatchManifest {
        BatchManifest {
            previous_state_root: state.state_root(),
            batch_id: state.next_batch_id,
            batch_time_ms: 0,
            ordered,
            rejected: vec![],
            oracle_updates: vec![],
            matching_rule_version: 0,
            enclave_measurement: [0u8; 32],
            sequencer_pubkey_epoch: 0,
        }
    }

    #[test]
    fn rejects_market_id_not_matching_map_key() {
        let mut s = DefaultState::new(16);
        s.add_market(Market::conservative(0));
        // Corrupt the in-map copy's id after insertion, simulating a witness whose
        // Market.id disagrees with the map key it was decoded under.
        s.markets.get_mut(&0).unwrap().id = 99;
        assert_eq!(s.validate_market_keys(), Err(EngineError::MarketIdMismatch));
        let manifest = manifest_for(&s, vec![]);
        assert_eq!(
            derive_roots(&mut s, &[], &manifest).unwrap_err(),
            EngineError::MarketIdMismatch
        );
    }

    #[test]
    fn rejects_op_clock_disagreeing_with_manifest_time() {
        let mut s = DefaultState::new(16);
        s.add_market(Market::conservative(0));
        let manifest = manifest_for(&s, vec![]);
        // manifest.batch_time_ms = 0; the op claims a different clock. The
        // transcript is never validated — ClockMismatch fires first.
        let ops = vec![BatchOp::AccrueFunding {
            market_id: 0,
            mark: 1_000 * QUOTE_SCALE,
            oracle: crate::oracle::OracleTranscript {
                price: 1_000 * crate::fixed::PRICE_SCALE,
                publish_time_ms: 0,
                confidence: 0,
                backup_twap: 1_000 * crate::fixed::PRICE_SCALE,
                signature: crate::oracle::OracleSig {
                    r: [0u8; 32],
                    s: [0u8; 32],
                    v: 0,
                },
            },
            now_ms: 60_000,
        }];
        assert_eq!(
            derive_roots(&mut s, &ops, &manifest).unwrap_err(),
            EngineError::ClockMismatch
        );
    }

    #[test]
    fn manifest_hash_binds_batch_time() {
        let s = DefaultState::new(16);
        let mut m1 = manifest_for(&s, vec![]);
        let mut m2 = m1.clone();
        m2.batch_time_ms = 1;
        assert_ne!(m1.hash::<Keccak256>(), m2.hash::<Keccak256>());
        // sanity: identical manifests hash identically
        m1.batch_time_ms = 1;
        assert_eq!(m1.hash::<Keccak256>(), m2.hash::<Keccak256>());
    }

    #[test]
    fn derives_withdrawals_root_from_burned_note() {
        let spend_key = [3u8; 32];
        let owner = owner_from_spend_key::<Keccak256>(&spend_key);
        let blind = [7u8; 32];
        let amount = 4_000 * QUOTE_SCALE;
        let mut s = DefaultState::new(16);
        s.add_market(Market::conservative(0));
        let cm = Note::new(owner, 0, amount, blind).commitment::<Keccak256>();
        let ops = vec![
            BatchOp::Deposit {
                owner,
                asset_id: 0,
                amount,
                blinding: blind,
                from: [0u8; 20],
                deposit_id: 0,
                deposit_blind: [0x77u8; 32],
            },
            BatchOp::Withdraw {
                note_commitment: cm,
                spend_key,
                to: Some([0xAB; 20]),
                nonce: 42,
            },
        ];
        let manifest = manifest_for(&s, vec![]);
        let d = derive_roots(&mut s.clone(), &ops, &manifest).unwrap();
        // the withdrawals root equals the merkle root over exactly this batch's leaf
        let expected = crate::merkle::withdrawals_root(&[crate::merkle::WithdrawalLeaf {
            to: [0xAB; 20],
            amount: amount as u128,
            nonce: 42,
        }]);
        assert_eq!(d.withdrawals_root, expected);
    }

    #[test]
    fn rejects_manifest_with_wrong_prev_root() {
        let mut s = DefaultState::new(16);
        let mut manifest = manifest_for(&s, vec![]);
        manifest.previous_state_root = [0x99u8; 32]; // wrong
        assert_eq!(
            derive_roots(&mut s, &[], &manifest).unwrap_err(),
            EngineError::ManifestMismatch
        );
    }

    #[test]
    fn rejects_manifest_with_wrong_batch_id() {
        let mut s = DefaultState::new(16);
        // correct previous_state_root (from `manifest_for`), but wrong batch_id
        let mut manifest = manifest_for(&s, vec![]);
        manifest.batch_id = s.next_batch_id + 1; // wrong
        assert_eq!(
            derive_roots(&mut s, &[], &manifest).unwrap_err(),
            EngineError::ManifestMismatch
        );
    }

    #[test]
    fn deposits_root_is_post_batch_tip_and_in_commitment() {
        let owner = owner_from_spend_key::<Keccak256>(&[9u8; 32]);
        let amount = 1_000 * QUOTE_SCALE;
        let from = [0xCDu8; 20];
        // distinct from the note `blinding` below — the two must never be conflated.
        let deposit_blind = [0xB1u8; 32];
        let mut s = DefaultState::new(16);
        s.add_market(Market::conservative(0));
        let ops = vec![BatchOp::Deposit {
            owner,
            asset_id: 0,
            amount,
            blinding: [11u8; 32],
            from,
            deposit_id: 0,
            deposit_blind,
        }];
        let manifest = manifest_for(&s, vec![]);

        let mut post = s.clone();
        let roots = derive_roots(&mut post, &ops, &manifest).expect("derive");

        // deposits_root is the tip AFTER this batch's deposits folded, not the pre-tip.
        // The leaf binds the BLINDED owner commit, never the raw owner (spec §1a).
        let commit = crate::merkle::owner_commit(&owner, &deposit_blind);
        let leaf = crate::merkle::deposit_leaf(&from, &commit, amount as u128, 0);
        let expected = crate::merkle::deposit_chain_fold(&[0u8; 32], &leaf);
        assert_eq!(roots.deposits_root, expected);
        assert_eq!(roots.deposits_root, post.consumed_deposit_tip);
        assert_ne!(roots.deposits_root, s.consumed_deposit_tip, "pre-state tip");

        // the 7th word really enters the commitment
        let mut r2 = roots;
        r2.deposits_root = [1u8; 32];
        assert_ne!(
            r2.commitment::<Keccak256>(),
            roots.commitment::<Keccak256>()
        );
    }

    #[test]
    fn commitment_is_seven_field_state_root_domain() {
        let d = DerivedRoots {
            prev_state_root: [1u8; 32],
            manifest_hash: [2u8; 32],
            new_state_root: [3u8; 32],
            ordered_root: [4u8; 32],
            withdrawals_root: [5u8; 32],
            rejected_root: [6u8; 32],
            deposits_root: [7u8; 32],
            wind_down_phase: 0,
        };
        let expected = Keccak256::hash_words(
            crate::hash::Domain::StateRoot,
            &[
                [1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32], [5u8; 32], [6u8; 32], [7u8; 32],
            ],
        );
        assert_eq!(d.commitment::<Keccak256>(), expected);

        // KAT-COMMIT7 — the canonical 7-word known-answer. The L1
        // `DarkPerpSettlement.publicCommitment` MUST reproduce this byte-for-byte for
        // the same seven roots ([0x01;32]..[0x07;32]); preimage is the one-byte
        // `DOMAIN_STATE_ROOT` tag (0x07) followed by the seven 32-byte words, in order.
        // 0x27e3e52688359d5759ff4c7b0bea4d25a14b3c81652a4083d531592f827d8902
        const KAT_COMMIT7: Digest = [
            0x27, 0xe3, 0xe5, 0x26, 0x88, 0x35, 0x9d, 0x57, 0x59, 0xff, 0x4c, 0x7b, 0x0b, 0xea,
            0x4d, 0x25, 0xa1, 0x4b, 0x3c, 0x81, 0x65, 0x2a, 0x40, 0x83, 0xd5, 0x31, 0x59, 0x2f,
            0x82, 0x7d, 0x89, 0x02,
        ];
        assert_eq!(d.commitment::<Keccak256>(), KAT_COMMIT7);
    }
}

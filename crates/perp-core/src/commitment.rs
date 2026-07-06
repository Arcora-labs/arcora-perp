//! Canonical batch root-derivation — the ONE implementation the zkVM guest, the
//! prover's `run_transition`, and the SP1 host's native reference all share. The
//! guest DERIVES these roots (it does not accept them as trusted witness inputs), so
//! under a real verifier the prover cannot supply an arbitrary withdrawals/ordered/
//! rejected root. Matching-fairness (the ordered-vs-rejected SPLIT) is NOT proven
//! here — that is Proof-v2; this derives the roots structurally from the manifest and
//! constrains withdrawals to the burned notes.

use crate::engine::BatchOp;
use crate::hash::{Digest, Domain, Hasher};
use crate::merkle::{ordered_root, rejected_root, withdrawals_root, WithdrawalLeaf};
use crate::order::BatchManifest;
use crate::{DefaultState, EngineError};
use alloc::vec::Vec;

/// The six roots the batch proof commits to (byte-identical to the L1
/// `DarkPerpSettlement.publicCommitment`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DerivedRoots {
    pub prev_state_root: Digest,
    pub manifest_hash: Digest,
    pub new_state_root: Digest,
    pub ordered_root: Digest,
    pub withdrawals_root: Digest,
    pub rejected_root: Digest,
}

impl DerivedRoots {
    /// The proof's public commitment: `keccak_words(StateRoot, [six roots])`.
    pub fn commitment<H: Hasher>(&self) -> Digest {
        H::hash_words(
            Domain::StateRoot,
            &[
                self.prev_state_root,
                self.manifest_hash,
                self.new_state_root,
                self.ordered_root,
                self.withdrawals_root,
                self.rejected_root,
            ],
        )
    }
}

/// Execute the batch transition and DERIVE all six roots. Mutates `state` to the
/// post-state. Fails `ManifestMismatch` if the manifest is not the one for this
/// pre-state, or propagates any engine rejection.
pub fn derive_roots(
    state: &mut DefaultState,
    ops: &[BatchOp],
    manifest: &BatchManifest,
) -> Result<DerivedRoots, EngineError> {
    let prev_state_root = state.state_root();
    let batch_id = state.next_batch_id;
    // tie the manifest to the state (BOUNDARY 1: structural only — no matcher rerun)
    if manifest.previous_state_root != prev_state_root || manifest.batch_id != batch_id {
        return Err(EngineError::ManifestMismatch);
    }
    let outputs = state.apply_batch(ops)?;
    let new_state_root = state.state_root();

    let manifest_hash = manifest.hash::<crate::hash::Keccak256>();
    let ordered_root = ordered_root(batch_id, &manifest.ordered);
    let rejected_hashes: Vec<Digest> = manifest.rejected.iter().map(|(h, _)| *h).collect();
    let rejected_root = rejected_root(batch_id, &rejected_hashes);
    let wl: Vec<WithdrawalLeaf> = outputs.withdrawals.iter().map(WithdrawalLeaf::from).collect();
    let withdrawals_root = withdrawals_root(&wl);

    Ok(DerivedRoots {
        prev_state_root,
        manifest_hash,
        new_state_root,
        ordered_root,
        withdrawals_root,
        rejected_root,
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
            ordered,
            rejected: vec![],
            oracle_updates: vec![],
            matching_rule_version: 0,
            enclave_measurement: [0u8; 32],
            sequencer_pubkey_epoch: 0,
        }
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
            BatchOp::Deposit { owner, asset_id: 0, amount, blinding: blind },
            BatchOp::Withdraw { note_commitment: cm, spend_key, to: Some([0xAB; 20]), nonce: 42 },
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
    fn commitment_is_six_field_state_root_domain() {
        let d = DerivedRoots {
            prev_state_root: [1u8; 32],
            manifest_hash: [2u8; 32],
            new_state_root: [3u8; 32],
            ordered_root: [4u8; 32],
            withdrawals_root: [5u8; 32],
            rejected_root: [6u8; 32],
        };
        let expected = Keccak256::hash_words(
            crate::hash::Domain::StateRoot,
            &[[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32], [5u8; 32], [6u8; 32]],
        );
        assert_eq!(d.commitment::<Keccak256>(), expected);
    }
}

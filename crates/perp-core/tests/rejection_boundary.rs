//! Characterization of the OPEN R04 proof boundary, not security acceptance tests.
//! A passing test here demonstrates that Proof-v1 still accepts the adversarial
//! manifest. Replace these expectations when signed-order/matcher replay becomes
//! part of the guest; do not report these passes as matching-fairness proof.

use perp_core::commitment::{derive_roots, DerivedRoots};
use perp_core::hash::{word_u64, Keccak256};
use perp_core::order::{BatchManifest, Order, RejectReason, Side, TimeInForce};
use perp_core::{DefaultState, Market};

fn state_and_manifest() -> (DefaultState, BatchManifest) {
    let mut state = DefaultState::new(16);
    state.add_market(Market::conservative(0));
    let manifest = BatchManifest {
        previous_state_root: state.state_root(),
        batch_id: state.next_batch_id,
        batch_time_ms: 0,
        ordered: vec![],
        rejected: vec![],
        oracle_updates: vec![],
        matching_rule_version: 1,
        enclave_measurement: [0; 32],
        sequencer_pubkey_epoch: 0,
    };
    (state, manifest)
}

fn derive(state: &DefaultState, manifest: &BatchManifest) -> DerivedRoots {
    derive_roots(&mut state.clone(), &[], manifest)
        .expect("Proof-v1 currently accepts an unconstrained manifest disposition")
}

#[test]
fn proof_v1_accepts_fabricated_expiry_rejection() {
    let (state, mut manifest) = state_and_manifest();
    let order = Order {
        owner: word_u64(1),
        market_id: 0,
        side: Side::Buy,
        size: 100_000_000,
        limit_price: 1_000_000_000,
        tif: TimeInForce::Gtc,
        reduce_only: false,
        nonce: 1,
        expiry_ms: 0, // Never expires, so Expired is a false claim at every time.
        ciphertext_commit: word_u64(2),
    };
    let hash = order.order_hash::<Keccak256>();
    manifest.ordered.push(hash);
    let included = derive(&state, &manifest);

    manifest.ordered.clear();
    manifest.rejected.push((hash, RejectReason::Expired));
    let falsely_rejected = derive(&state, &manifest);

    assert_eq!(included.new_state_root, falsely_rejected.new_state_root);
    assert_ne!(included.manifest_hash, falsely_rejected.manifest_hash);
    assert_eq!(
        falsely_rejected.rejected_root,
        perp_core::merkle::rejected_root(manifest.batch_id, &[hash])
    );

    // A different unproven reason changes the manifest commitment, but is also
    // accepted; neither signature nor order preimage reaches derive_roots.
    manifest.rejected[0].1 = RejectReason::PostOnlyWouldTake;
    let different_false_reason = derive(&state, &manifest);
    assert_ne!(
        falsely_rejected.manifest_hash,
        different_false_reason.manifest_hash
    );
    assert_eq!(
        falsely_rejected.rejected_root,
        different_false_reason.rejected_root
    );
}

#[test]
fn proof_v1_accepts_reordered_manifest_without_changed_operations() {
    let (state, mut manifest) = state_and_manifest();
    manifest.ordered = vec![word_u64(1), word_u64(2), word_u64(3)];
    let original = derive(&state, &manifest);
    manifest.ordered.swap(0, 2);
    let reversed = derive(&state, &manifest);

    assert_eq!(original.new_state_root, reversed.new_state_root);
    assert_ne!(original.manifest_hash, reversed.manifest_hash);
    // Binding the claimed sequence is different from proving receipt priority.
}

#[test]
fn proof_v1_accepts_duplicate_and_overlapping_dispositions() {
    let (state, mut manifest) = state_and_manifest();
    let hash = word_u64(1);
    manifest.ordered = vec![hash, hash];
    manifest.rejected = vec![
        (hash, RejectReason::Cancelled),
        (hash, RejectReason::FillOrKillUnfillable),
    ];
    let roots = derive(&state, &manifest);
    assert_eq!(
        roots.rejected_root,
        perp_core::merkle::rejected_root(manifest.batch_id, &[hash, hash])
    );
    // Blanket disjointness is not a sound repair: multi-tick windows can contain
    // a fill followed by cancellation/rejection of the same order's remainder.
    // The guest needs authenticated lifecycle events and remaining quantities.
}

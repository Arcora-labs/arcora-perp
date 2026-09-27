//! Release-boundary controls for the local S4 accounting review.
use perp_core::engine::BatchOp;
use perp_core::hash::Keccak256;
use perp_core::note::owner_from_spend_key;
use perp_core::{DefaultState, EngineError};

fn deposit() -> BatchOp {
    BatchOp::Deposit {
        owner: owner_from_spend_key::<Keccak256>(&[91; 32]),
        asset_id: 0,
        amount: 1_000_000,
        blinding: [92; 32],
        from: [93; 20],
        deposit_id: 0,
        deposit_blind: [94; 32],
    }
}

#[test]
fn exhausted_batch_counter_rejects_before_deposit_mutation() {
    let mut state = DefaultState::new(16);
    state.next_batch_id = u64::MAX;
    let before = state.state_root();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        state.apply_batch(&[deposit()])
    }));
    assert!(
        result.is_ok(),
        "batch counter overflow must be a controlled error"
    );
    assert!(matches!(result.unwrap(), Err(EngineError::Overflow)));
    assert_eq!(
        state.state_root(),
        before,
        "a rejected batch must not mint a deposit"
    );
    assert_eq!(state.external_in, 0);
    assert_eq!(state.consumed_deposit_count, 0);
}

#[test]
fn last_representable_batch_completes_then_empty_batch_rejects() {
    let mut state = DefaultState::new(16);
    state.next_batch_id = u64::MAX - 1;
    state.apply_batch(&[deposit()]).unwrap();
    assert_eq!(state.next_batch_id, u64::MAX);
    assert_eq!(state.external_in, 1_000_000);
    assert!(state.conservation_holds());
    let before = state.state_root();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| state.apply_batch(&[])));
    assert!(
        result.is_ok(),
        "even an empty batch must not wrap its identity"
    );
    assert!(matches!(result.unwrap(), Err(EngineError::Overflow)));
    assert_eq!(state.state_root(), before);
}

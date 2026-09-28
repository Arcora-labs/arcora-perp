use sp1_prover::shapes::{SP1NormalizeCache, SP1NormalizeInputShape};
use std::sync::Arc;

fn shape(id: usize) -> SP1NormalizeInputShape {
    SP1NormalizeInputShape {
        proof_shapes: vec![], max_log_row_count: id, log_blowup: 1, log_stacking_height: 1,
    }
}

#[test]
fn actual_sp1_normalize_cache_promotes_evicts_and_replaces() {
    let cache = SP1NormalizeCache::new(2);
    let first = Arc::new(Default::default());
    let second = Arc::new(Default::default());
    let third = Arc::new(Default::default());
    cache.push(shape(1), Arc::clone(&first));
    cache.push(shape(2), Arc::clone(&second));
    // Reading the older entry must promote it so inserting a third evicts key2.
    assert!(Arc::ptr_eq(&cache.get(&shape(1)).unwrap(), &first));
    cache.push(shape(3), Arc::clone(&third));
    assert!(cache.get(&shape(2)).is_none());
    assert!(Arc::ptr_eq(&cache.get(&shape(1)).unwrap(), &first));
    assert!(Arc::ptr_eq(&cache.get(&shape(3)).unwrap(), &third));
    // Replacing an existing shape must return the newly compiled program.
    let replacement = Arc::new(Default::default());
    cache.push(shape(1), Arc::clone(&replacement));
    assert!(Arc::ptr_eq(&cache.get(&shape(1)).unwrap(), &replacement));
    assert!(!Arc::ptr_eq(&cache.get(&shape(1)).unwrap(), &first));
}

// Test-only adapter, appended inside each actual historical deposit module.
// Calls the production ingestion transition; never duplicates its schema/logic.
#[cfg(test)]
pub(crate) fn frozen_fixture_credit(gw: &mut Gw, key: &[u8; 32]) {
    let commit = gw.authorize_routed_deposit(key, [0x44;20], 5_000_000, 0, Purpose::Collateral).unwrap();
    let start = gw.deposit_cursor();
    let block = Block { number: 42, hash: [0x42;32] };
    let event = Event {
        id: start.count, from: [0x44;20], commit, amount: 5_000_000,
        tip: perp_core::merkle::deposit_chain_fold(&start.tip,
            &perp_core::merkle::deposit_leaf(&[0x44;20], &commit, 5_000_000, start.count)),
        tx: [0x89;32], tx_index: 0, log_index: 0, block: block.clone(),
    };
    let page = Page { start, end: block, events: vec![event] };
    assert_eq!(gw.apply_deposit_page(page.clone()).unwrap(), 1);
    let credited = postcard::to_allocvec(&gw.seq.state).unwrap();
    assert!(gw.apply_deposit_page(page).is_err(), "duplicate page must not credit twice");
    assert_eq!(postcard::to_allocvec(&gw.seq.state).unwrap(), credited);
}

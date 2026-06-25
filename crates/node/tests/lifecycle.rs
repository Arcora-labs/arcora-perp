//! Lock the node's operating-loop lifecycle into CI.
//!
//! The binary asserts these only at runtime; here they are regression-guarded so
//! a change that breaks funding, liquidation, or collateral conservation fails
//! `cargo test` instead of silently passing because nobody ran `cargo run -p node`.

use node::Node;

/// Drive the same scenario the binary shows and assert its invariants.
#[test]
fn thin_long_liquidates_and_conservation_holds_every_tick() {
    let mut node = Node::boot();

    let reports: Vec<_> = (0..12).map(|_| node.step()).collect();

    // 1. Collateral conservation is the headline safety property — every tick.
    for r in &reports {
        assert!(
            r.conservation_holds,
            "collateral conservation broke at tick {}",
            r.tick
        );
    }

    // 2. The thin long is funded too lightly to survive a sustained −1%/tick
    //    drawdown: it must liquidate exactly once and stay flat afterward.
    let liq_ticks: Vec<u64> = reports
        .iter()
        .filter(|r| r.liquidated)
        .map(|r| r.tick)
        .collect();
    assert_eq!(
        liq_ticks.len(),
        1,
        "expected exactly one liquidation, got ticks {liq_ticks:?}"
    );
    let liq = liq_ticks[0];

    // 3. Before liquidation the long is open and marking down (PnL present and
    //    monotonically worsening as the index falls); after, it is flat for good.
    for r in &reports {
        if r.tick < liq {
            assert!(
                r.long_open,
                "long should be open before liq at tick {}",
                r.tick
            );
        } else {
            assert!(
                !r.long_open,
                "long should be flat after liq at tick {}",
                r.tick
            );
            assert!(
                r.long_pnl.is_none(),
                "flat long has no PnL at tick {}",
                r.tick
            );
        }
    }

    // 4. The long is underwater the whole way down (it is the losing side).
    for r in reports.iter().take(liq as usize) {
        assert!(
            r.long_pnl.unwrap_or(0) <= 0,
            "long PnL should be <= 0 while marking down at tick {}",
            r.tick
        );
    }

    // 5. The index actually fell across the run (the driver of the whole story).
    assert!(
        reports.last().unwrap().price < reports.first().unwrap().price,
        "index should have dropped across the run"
    );
}

/// `boot()` is deterministic — two boots produce identical first-tick reports.
#[test]
fn boot_is_deterministic() {
    let a = Node::boot().step();
    let b = Node::boot().step();
    assert_eq!(a.price, b.price);
    assert_eq!(a.batch_id, b.batch_id);
    assert_eq!(a.insurance_fund, b.insurance_fund);
    assert_eq!(a.long_open, b.long_open);
    assert_eq!(a.long_pnl, b.long_pnl);
}

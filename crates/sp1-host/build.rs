//! Compiles the SP1 guest (`crates/sp1-guest`, package `perp-core-guest`) so the host's
//! `include_elf!("perp-core-guest")` can embed it. Requires the SP1 toolchain (`cargo prove`).
fn main() {
    sp1_build::build_program("../sp1-guest");
}

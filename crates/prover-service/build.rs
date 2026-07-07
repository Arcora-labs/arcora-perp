//! Compiles the SP1 guest so `include_elf!("perp-core-guest")` resolves. Requires the
//! SP1 toolchain (`cargo prove`).
fn main() {
    sp1_build::build_program("../sp1-guest");
}

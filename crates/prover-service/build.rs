//! Compiles the SP1 guest so `include_elf!("perp-core-guest")` resolves. Requires the
//! SP1 toolchain (`cargo prove`).
#[path = "../service-identity/build_support.rs"]
mod service_identity_build;

fn main() {
    service_identity_build::build();
    sp1_build::build_program("../sp1-guest");
}

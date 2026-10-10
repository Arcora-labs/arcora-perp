//! Separate candidate v3 guest; NEVER a replacement for the reviewed v2 ELF.
#![no_main]
sp1_zkvm::entrypoint!(main);
pub fn main() {
    let bytes = sp1_zkvm::io::read_vec();
    let output =
        chainlink_oracle::binding::run_encoded(&bytes).expect("chainlink-bound transition");
    sp1_zkvm::io::commit_slice(&output.commitment);
}

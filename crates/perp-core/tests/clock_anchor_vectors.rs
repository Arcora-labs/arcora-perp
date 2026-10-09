//! Fixed ABI/Keccak vector for the isolated experimental clock-anchor registry.
//! This is encoding parity only, not guest/public-input integration or a proof.
use tiny_keccak::{Hasher, Keccak};

fn hash(bytes: &[u8]) -> [u8; 32] {
    let mut k = Keccak::v256();
    k.update(bytes);
    let mut out = [0; 32];
    k.finalize(&mut out);
    out
}
fn number(n: u64) -> [u8; 32] {
    let mut out = [0; 32];
    out[24..].copy_from_slice(&n.to_be_bytes());
    out
}
fn digest(s: &str) -> [u8; 32] {
    assert_eq!(s.len(), 64);
    let mut out = [0; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}
#[test]
fn experimental_clock_anchor_matches_solidity_abi_vector() {
    let domain = hash(b"arcora:batch-clock-anchor:prototype:v1");
    assert_eq!(
        domain,
        digest("a45aa03554e9127f800c61cc9d9bb4cdd303becd1f3e4e9e6f0fcb9c390104f2")
    );
    let mut address = [0; 32];
    address[12..].fill(0x11);
    let key = hash(&[domain, number(84532), address, number(7), [0x22; 32]].concat());
    assert_eq!(
        key,
        digest("0e791057196a63b166928fc9de3e66da9f43a305b1046362f1b174eafd712371")
    );
    let content = hash(&[[0x33; 32], number(1700000000000), number(1700000008000)].concat());
    assert_eq!(
        content,
        digest("96afa7383dee3597dd343ceccddac7d1bf4bc39dac9e0348bced647368152d8c")
    );
    let commitment = hash(&[domain, key, content, number(1700000008000)].concat());
    assert_eq!(
        commitment,
        digest("d92348d70cb007574825881e4dc5d21d66f49a084ec2b2410572a7c5ea49fb6f")
    );
}

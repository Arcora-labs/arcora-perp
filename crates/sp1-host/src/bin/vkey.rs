//! Prints the SP1 program verification key (bytes32) for the perp-core guest — the
//! immutable `programVKey` the on-chain SP1ZkVerifier constructor pins. `setup` only;
//! no proof / no Docker / no GPU.
use sp1_sdk::{include_elf, Elf, HashableKey, Prover, ProverClient, ProvingKey};

const ELF: Elf = include_elf!("perp-core-guest");

#[tokio::main]
async fn main() {
    let client = ProverClient::builder().cpu().build().await;
    let pk = client.setup(ELF).await.unwrap();
    println!("VKEY={}", pk.verifying_key().bytes32());
}

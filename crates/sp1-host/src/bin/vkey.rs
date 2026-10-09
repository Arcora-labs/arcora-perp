//! Prints the SP1 program verification key (bytes32) for the perp-core guest — the
//! immutable `programVKey` the on-chain SP1ZkVerifier constructor pins. `setup` only;
//! no proof / no Docker / no GPU.
//! Use `--elf PATH` to derive from an explicit rebuilt artifact without replacing
//! the embedded guest. The printed digest identifies that input, not its approval.
use sp1_host::sha256;
use sp1_sdk::{include_elf, Elf, HashableKey, Prover, ProverClient, ProvingKey};

const ELF: Elf = include_elf!("perp-core-guest");

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let elf = match args.as_slice() {
        [] => ELF,
        [flag, path] if flag == "--elf" => {
            let bytes = std::fs::read(path)?;
            println!("ELF_SHA256={}", sha256(&bytes));
            Elf::from(bytes)
        }
        _ => return Err("usage: vkey [--elf PATH]".into()),
    };
    let client = ProverClient::builder().cpu().build().await;
    let pk = client.setup(elf).await?;
    println!("VKEY={}", pk.verifying_key().bytes32());
    Ok(())
}

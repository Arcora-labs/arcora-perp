//! `Sp1GnarkProver` — a real SP1 Groth16 backend implementing `prover::Prover`. Caches
//! the SP1 proving key (setup is expensive) and blocks on the async SP1 client from the
//! sync trait method. Runs where the SP1 toolchain + (emulated) gnark are (the prover
//! machine), NOT in the workspace. Pattern validated by `crates/sp1-host/src/bin/prove.rs`.
use perp_core::hash::{Digest, Hasher, Keccak256};
use prover::{Prover, PublicInputs};
use sp1_sdk::{
    include_elf, Elf, HashableKey, ProveRequest, Prover as _, ProverClient, ProvingKey, SP1Stdin,
};
use std::sync::Arc;

const ELF: Elf = include_elf!("perp-core-guest");

/// Type aliases for the concrete SP1 CPU client + proving key (see prove.rs).
type Client = sp1_sdk::cpu::CpuProver;
type Pk = sp1_sdk::SP1ProvingKey;

pub struct Sp1GnarkProver {
    client: Arc<Client>,
    pk: Arc<Pk>,
    vkey: String,
    measurement: Digest,
    rt: tokio::runtime::Handle,
}

impl Sp1GnarkProver {
    /// Build the CPU prover, run `setup(ELF)` ONCE (cache pk), capture the vkey. Call from
    /// an async context (holds the current runtime handle for later `block_on`).
    pub async fn new(measurement: Digest) -> Self {
        let client = ProverClient::builder().cpu().build().await;
        let pk = client.setup(ELF).await.expect("sp1 setup");
        let vkey = pk.verifying_key().bytes32();
        Self {
            client: Arc::new(client),
            pk: Arc::new(pk),
            vkey,
            measurement,
            rt: tokio::runtime::Handle::current(),
        }
    }

    pub fn vkey(&self) -> String {
        self.vkey.clone()
    }
}

impl Prover for Sp1GnarkProver {
    fn measurement(&self) -> Digest {
        self.measurement
    }

    /// Generate a real Groth16 proof. `witness` is the postcard `(state, ops, manifest)`
    /// the guest reads; the guest DERIVES the roots inside, so the proof's public values
    /// equal `public.commitment()`. Blocks on the async SP1 client (call inside a
    /// blocking task — see the service).
    fn prove(&self, public: &PublicInputs, witness: &[u8]) -> Vec<u8> {
        let mut stdin = SP1Stdin::new();
        stdin.write_vec(witness.to_vec());
        let client = self.client.clone();
        let pk = self.pk.clone();
        let proof = self
            .rt
            .block_on(async move { client.prove(&pk, stdin).groth16().await })
            .expect("sp1 groth16 prove");
        // Sanity: the guest-derived public value must match the natively-derived commitment.
        debug_assert_eq!(
            proof.public_values.as_slice(),
            public.commitment::<Keccak256>().as_slice(),
            "proof public_values must equal the derived commitment"
        );
        proof.bytes()
    }
}

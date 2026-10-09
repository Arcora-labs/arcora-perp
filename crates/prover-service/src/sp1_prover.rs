//! `Sp1GnarkProver` — a real SP1 Groth16 backend implementing `prover::Prover`. Caches
//! the SP1 proving key (setup is expensive) and blocks on the async SP1 client from the
//! sync trait method. Runs where the SP1 toolchain + (emulated) gnark are (the prover
//! machine), NOT in the workspace. SP1 v6.x Groth16 API — validated on the SP1 prover
//! machine (GB10); build steps in `docs/PROVING-RUNBOOK.md`.
use perp_core::hash::{Digest, Keccak256};
use prover::{Prover, PublicInputs};
use sp1_sdk::{
    include_elf, Elf, HashableKey, ProveRequest, Prover as _, ProverClient, ProvingKey, SP1Stdin,
};
use std::sync::Arc;

const ELF: Elf = include_elf!("perp-core-guest");

/// Type aliases for the concrete SP1 CPU client + proving key. The `CpuProver`/
/// `SP1ProvingKey` types are confirmed at build time on the SP1 prover machine (GB10).
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
        // Worker configuration captures dump paths at construction, so checking
        // only at prove time would be too late if the environment later changed.
        prover::validate_sp1_environment().expect("private SP1 proving environment");
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

    /// Generate a real Groth16 proof. `witness` is the explicit legacy tuple or
    /// DPCLK2-prefixed clock-context tuple. The guest derives the roots and validates
    /// the clock context, so public values equal `public.commitment()`. Call inside a
    /// blocking task — see the service).
    fn prove(&self, public: &PublicInputs, witness: &[u8]) -> Vec<u8> {
        // Also protect direct backend callers before the first SDK-owned copy.
        // The sealed entrypoint has already refused before opening its witness.
        prover::validate_sp1_environment().expect("private SP1 proving environment");
        let mut stdin = SP1Stdin::new();
        stdin.write_vec(witness.to_vec());
        let client = self.client.clone();
        let pk = self.pk.clone();
        let proof = self
            .rt
            .block_on(async move { client.prove(&pk, stdin).groth16().await })
            .expect("sp1 groth16 prove");
        // SEC-025-B §2: the guest's committed public value MUST equal the natively derived
        // commitment. This was a debug_assert, which compiles out of the release builds the
        // prover box runs — so a native/guest divergence would return a proof the gateway
        // happily accepts (its local replay matches the NATIVE roots) and L1 then rejects,
        // late and inside the rollback machinery. Fail here instead, naming both values.
        // A panic (not a Result): the `Prover` trait's `prove` is infallible by signature,
        // this function already panics on prove failure (the `.expect` above), and the
        // /prove call site runs us inside `spawn_blocking`, whose JoinError on panic is
        // mapped to a 500 — so the panic IS the propagated /prove 500.
        // COVERAGE HONESTY: this check has NO automated coverage — exercising it needs
        // a real SP1 prover (this crate is workspace-excluded and CI only typechecks
        // it). Its operational counterpart is the pre-cutover parity step in
        // docs/FINAL_SETTLE_RUNBOOK.md (`cargo run --release --bin sp1-host`).
        let expected = public.commitment::<Keccak256>();
        if proof.public_values.as_slice() != expected.as_slice() {
            panic!(
                "guest/native divergence: guest committed {} but native derivation gives {} \
                 — the guest ELF and the host perp-core are not the same code",
                hex::encode(proof.public_values.as_slice()),
                hex::encode(expected),
            );
        }
        proof.bytes()
    }
}

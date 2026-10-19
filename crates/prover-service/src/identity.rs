//! Read-only public identity route. No backend, admission or attestation handles.
use axum::{
    extract::{FromRef, State},
    routing::get,
    Json, Router,
};
use serde_json::{json, Value};
use std::time::Duration;

/// The one witness domain `/prove` accepts: the clock-bound framing magic
/// `perp_core::clock::WIRE_MAGIC` without its NUL padding (the service's tests
/// check the two agree). Every other body, including the unframed tuple and
/// earlier framings, is refused before proving. A literal, so this file builds
/// without perp-core.
pub(crate) const WITNESS_DOMAIN: &str = "DPCLK4";

/// The witness framing each reviewed guest program accepts, by the SHA-256 of
/// its ELF bytes. A program that is not listed accepts no framing this service
/// can vouch for. A reviewed guest that accepts `WITNESS_DOMAIN` is listed with
/// it when its ELF is pinned; test_pin_coherence.py checks that every such entry
/// is REVIEWED_GUEST's ELF, and that REVIEWED_GUEST's ELF is listed with it
/// unless it is a listed earlier program.
pub(crate) const PROGRAM_WITNESS_DOMAINS: &[(&str, &str)] = &[
    // The clock-v2 guest of the committed real proof: it accepts the unframed
    // tuple and the DPCLK2 framing, so it proves no body `/prove` admits.
    (
        "df59a19b310258b4d01d0d5e3cfa31bb7de9ca2f4ea7c2302cf76650c79967c5",
        "DPCLK2",
    ),
    // The reviewed guest (REVIEWED_GUEST in verify_clock_proof.py): it accepts
    // exactly the clock-bound framing `/prove` admits.
    (
        "a6d516488c542673ef750c6c6d7cd0fb6b9c004d0cb6c82eb5b4bc57d630e7df",
        "DPCLK4",
    ),
];

/// The witness domains both `/prove` and the program `elf` accept, judged by
/// `programs` (the reviewed table, `PROGRAM_WITNESS_DOMAINS`, in production):
/// `[WITNESS_DOMAIN]` when the ELF is listed with that domain, otherwise none.
pub(crate) fn witness_domains_in(elf: &[u8], programs: &[(&str, &str)]) -> Vec<&'static str> {
    let digest = crate::service_identity::sha256(elf);
    if programs
        .iter()
        .any(|(sha, domain)| *sha == digest && *domain == WITNESS_DOMAIN)
    {
        vec![WITNESS_DOMAIN]
    } else {
        Vec::new()
    }
}

/// [`witness_domains_in`] over the reviewed table.
pub(crate) fn witness_domains(elf: &[u8]) -> Vec<&'static str> {
    witness_domains_in(elf, PROGRAM_WITNESS_DOMAINS)
}

/// Whether a service whose embedded program accepts `domains` may start: in
/// production only when the program accepts `WITNESS_DOMAIN`, the one framing
/// `/prove` admits. Otherwise every admitted body would fail in the guest.
pub(crate) fn admit_program(domains: &[&str], prod: bool) -> Result<(), String> {
    if !prod || domains.contains(&WITNESS_DOMAIN) {
        return Ok(());
    }
    Err(format!(
        "the embedded guest ELF is not a reviewed program that accepts {WITNESS_DOMAIN} \
         witnesses (crate::identity::PROGRAM_WITNESS_DOMAINS); refusing to start"
    ))
}

/// This byte slice is the actual embedded ELF in production. Router tests inject
/// an existing reviewed fixture explicitly, without booting a loaded service.
/// `supported_witness_domains` is [`witness_domains`] of these bytes.
pub(crate) fn program_descriptor(elf: &[u8], vkey: &str) -> Value {
    json!({
        "sdk_version": "6.1.0",
        "elf_sha256": crate::service_identity::sha256(elf),
        "elf_bytes": elf.len(),
        "program_vkey": vkey,
        "supported_witness_domains": witness_domains(elf)
    })
}

/// Only already-resolved public values enter the identity route. It has no
/// reference to proving, seal, handshake, admission or session state.
#[derive(Clone)]
pub(crate) struct PublicIdentity {
    program: Value,
    public_config: Value,
}

impl PublicIdentity {
    pub(crate) fn resolved(
        program: Value,
        measurement: [u8; 32],
        dev_insecure: bool,
        max_concurrent: usize,
        body_bytes: usize,
        body_timeout: Duration,
    ) -> Self {
        Self {
            program,
            public_config: json!({
                "measurement": format!("0x{}", hex::encode(measurement)),
                "dev_insecure": dev_insecure,
                "admission": {
                    "max_concurrent": max_concurrent,
                    "body_bytes": body_bytes,
                    "body_timeout_ms": body_timeout.as_millis()
                }
            }),
        }
    }
}

async fn identity(State(public): State<PublicIdentity>) -> impl axum::response::IntoResponse {
    (
        [("cache-control", "no-store")],
        Json(crate::service_identity::envelope(
            "prover",
            public.program,
            public.public_config,
        )),
    )
}

pub(crate) fn routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    PublicIdentity: FromRef<S>,
{
    Router::new().route("/identity", get(identity))
}

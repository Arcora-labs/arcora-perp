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

/// This byte slice is the actual embedded ELF in production. Router tests inject
/// an existing reviewed fixture explicitly, without booting a loaded service.
pub(crate) fn program_descriptor(elf: &[u8], vkey: &str) -> Value {
    json!({
        "sdk_version": "6.1.0",
        "elf_sha256": crate::service_identity::sha256(elf),
        "elf_bytes": elf.len(),
        "program_vkey": vkey,
        "supported_witness_domains": [WITNESS_DOMAIN]
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

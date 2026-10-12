//! GPU-free exact-route harness. Public descriptor bytes are injected from the
//! committed reviewed fixture; no real prover-service/backend is booted.
#![cfg(test)]
#[path = "../../../crates/prover-service/src/identity.rs"]
mod identity;
#[cfg(test)]
#[path = "../../../crates/prover-service/src/identity_tests.rs"]
mod identity_tests;
#[path = "../../../crates/service-identity/public.rs"]
mod service_identity;

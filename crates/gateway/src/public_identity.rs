//! A snapshot of resolved public configuration; no env, transport or settlement action.
use super::*;
use serde_json::{json, Value};

fn configured_address(value: Option<&str>) -> Result<Value, StatusCode> {
    match value {
        None => Ok(Value::Null),
        Some(value) => parse_addr20_hex(value)
            .filter(|address| *address != [0; 20])
            .map(|address| json!(hex0x(&address)))
            .ok_or(StatusCode::SERVICE_UNAVAILABLE),
    }
}

pub(super) async fn get(State(app): State<Shared>) -> Result<impl IntoResponse, StatusCode> {
    // Follow the existing gateway -> archive order, and never wait on the blocking
    // archive mutex from an async worker. Contention/poison is an unavailable read.
    let gateway = app.gw.lock().await;
    let archive = match app.archive.as_ref() {
        Some(archive) => {
            let binding = archive
                .try_lock()
                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
            let policy = binding
                .policy()
                .hash()
                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
            json!({
                "policy_binding": hex0x(&binding.policy_binding()),
                "oracle_policy_hash": hex0x(&policy)
            })
        }
        None if gateway.candidate_archive_required => return Err(StatusCode::SERVICE_UNAVAILABLE),
        None => Value::Null,
    };
    let l1 = match app.l1.as_ref() {
        None => Value::Null,
        Some(l1) => json!({
            "settlement": configured_address(Some(&l1.settlement))?,
            "vault": configured_address(l1.vault.as_deref())?,
            "token": configured_address(l1.usdc.as_deref())?,
            "clock": l1.public_clock_identity().map(|(chain_id, verifier)| json!({
                "chain_id": chain_id,
                "verifier": hex0x(&verifier)
            }))
        }),
    };
    let config = json!({
        "chain_id": gateway.chain_id,
        "vault": hex0x(&gateway.vault),
        "gateway_signer": hex0x(&app.gateway_signer.address()),
        "l1": l1,
        "prover_configured": app.prover.is_some(),
        "clocked_prover_configured": app.prover.as_ref().is_some_and(|prover| prover.clock_enabled()),
        "candidate_archive_required": gateway.candidate_archive_required,
        "candidate_archive": archive
    });
    Ok((
        [(axum::http::header::CACHE_CONTROL, "no-store")],
        Json(service_identity::envelope("gateway", Value::Null, config)),
    ))
}

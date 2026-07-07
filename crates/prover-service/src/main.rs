//! Attested prover HTTP service (§10b). Holds one `AttestedProver<Sp1GnarkProver>` and a
//! `SoftwareSealProvider` stand-in (P3 replaces the SealKeyProvider with real TDX/Nitro
//! key-release). `POST /prove` takes a sealed witness, opens+derives+proves+zeroizes, and
//! returns the 6 roots, the commitment, and the real Groth16 proof.
mod sp1_prover;

use axum::{extract::State, http::StatusCode, routing::{get, post}, Json, Router};
use perp_core::hash::Digest;
use prover::{AttestedProver, SealedWitness, SoftwareSealProvider};
use serde::{Deserialize, Serialize};
use sp1_prover::Sp1GnarkProver;
use std::sync::Arc;

/// Stand-in measurement + seal root (env-overridable). P3 supplies the real attested
/// measurement + TDX/Nitro key-release; here both sides share a software root.
fn measurement() -> Digest {
    [0xABu8; 32]
}
fn seal_root() -> [u8; 32] {
    let hex = std::env::var("PROVER_SEAL_ROOT").unwrap_or_default();
    let mut root = [0x5Eu8; 32];
    if let Ok(bytes) = hex::decode(hex.trim_start_matches("0x")) {
        if bytes.len() == 32 {
            root.copy_from_slice(&bytes);
        }
    }
    root
}

struct App {
    prover: AttestedProver<Sp1GnarkProver>,
    vkey: String,
    measurement: Digest,
}

#[derive(Deserialize)]
struct ProveReq {
    /// hex postcard-encoded `SealedWitness`.
    sealed: String,
}

#[derive(Serialize)]
struct ProveResp {
    prev_root: String,
    manifest_hash: String,
    new_root: String,
    ordered_root: String,
    withdrawals_root: String,
    rejected_root: String,
    commitment: String,
    proof: String,
}

fn hx(b: &[u8]) -> String {
    format!("0x{}", hex::encode(b))
}

async fn prove(
    State(app): State<Arc<App>>,
    Json(req): Json<ProveReq>,
) -> Result<Json<ProveResp>, (StatusCode, String)> {
    // Bad hex / bad postcard are caller errors: 400 so a client checking the status
    // sees the failure (axum's `IntoResponse for String` would 200 the error text).
    let raw = hex::decode(req.sealed.trim_start_matches("0x"))
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let sealed: SealedWitness =
        postcard::from_bytes(&raw).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    // The SP1 prove blocks; run the whole open+derive+prove off the async worker.
    let app2 = app.clone();
    let bp = tokio::task::spawn_blocking(move || app2.prover.prove_batch(&sealed))
        .await
        // A panicked/cancelled blocking task is a server fault: 500.
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        // A rejected witness / prove failure is unprocessable input: 422.
        .map_err(|e| (StatusCode::UNPROCESSABLE_ENTITY, format!("{e:?}")))?;
    let p = &bp.public;
    Ok(Json(ProveResp {
        prev_root: hx(&p.prev_state_root),
        manifest_hash: hx(&p.batch_manifest_hash),
        new_root: hx(&p.new_state_root),
        ordered_root: hx(&p.ordered_root),
        withdrawals_root: hx(&p.withdrawals_root),
        rejected_root: hx(&p.rejected_root),
        commitment: hx(&p.commitment::<perp_core::hash::Keccak256>()),
        proof: hx(&bp.proof_bytes),
    }))
}

async fn vkey(State(app): State<Arc<App>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({ "vkey": app.vkey }))
}
async fn measurement_ep(State(app): State<Arc<App>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({ "measurement": hx(&app.measurement) }))
}

#[tokio::main]
async fn main() {
    let m = measurement();
    let backend = Sp1GnarkProver::new(m).await;
    let program_vkey = backend.vkey();
    let app = Arc::new(App {
        prover: AttestedProver::new(backend, SoftwareSealProvider::new(seal_root(), m)),
        vkey: program_vkey,
        measurement: m,
    });
    let router = Router::new()
        .route("/prove", post(prove))
        .route("/vkey", get(vkey))
        .route("/measurement", get(measurement_ep))
        .with_state(app);
    let bind = std::env::var("PROVER_BIND").unwrap_or_else(|_| "127.0.0.1:8091".into());
    println!("prover-service on {bind}");
    let listener = tokio::net::TcpListener::bind(&bind).await.unwrap();
    axum::serve(listener, router).await.unwrap();
}

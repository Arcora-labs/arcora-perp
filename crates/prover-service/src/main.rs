//! Attested prover HTTP service (§10b). Holds one `AttestedProver<Sp1GnarkProver>` and a
//! `SoftwareSealProvider` stand-in (P3 replaces the SealKeyProvider with real TDX/Nitro
//! key-release). `POST /prove` takes a sealed witness, opens+derives+proves+zeroizes, and
//! returns the 6 roots, the commitment, and the real Groth16 proof.
mod sp1_prover;

use axum::{
    extract::{Query, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
// SEC-020 Task 4: mutual-attestation handshake — AzureTdxAttestor verifies the
// GATEWAY's TD quote, NvidiaCcAttestor produces OUR self-quote (fail-closed
// CcNotEnabled until GB10 CC mode is on), and the pure session secret/token
// math is shared with the gateway.
use dark_perp_attestation::{
    session_secret, session_token, Attestor as _, AzureTdxAttestor, NvidiaCcAttestor,
    DEV_INSECURE_SESSION_TOKEN,
};
use perp_core::hash::Digest;
use prover::{AttestedProver, SealedWitness, SoftwareSealProvider};
use serde::{Deserialize, Serialize};
use sp1_prover::Sp1GnarkProver;
use std::sync::Arc;

/// Stand-in measurement (env-overridable). P3 supplies the real attested
/// measurement + TDX/Nitro key-release; here both sides share a software root
/// resolved fail-closed by `prover::resolve_seal_root` (SEC-020).
fn measurement() -> Digest {
    [0xABu8; 32]
}

struct App {
    prover: AttestedProver<Sp1GnarkProver>,
    vkey: String,
    measurement: Digest,
    /// SEC-020 Task 4: the session token minted by the boot mutual-attestation
    /// handshake. `None` ⇒ the handshake refused or failed (fail-closed) — the
    /// /prove gate must then reject every caller. Task 4 mints + stores only;
    /// the gate that reads it on /prove is a later task.
    #[allow(dead_code)] // the /prove gate (next task) is the reader
    session_token: Option<String>,
    /// This host's per-boot handshake nonce: served in the /attest response
    /// (so the gateway derives the shared transcript) and used in our own boot
    /// fetch of the gateway's /attest.
    hs_nonce: [u8; 32],
    /// Per-boot token epoch, advertised in /attest — the gateway mints ITS copy
    /// of the token under this epoch, so both sides compare equal on /prove.
    hs_epoch: u64,
    /// DEV_INSECURE mode (non-prod only; prod refuses to boot with it).
    dev_insecure: bool,
    /// The NVIDIA CC self-quote backend — fail-closed (`CcNotEnabled`) until
    /// GB10 CC mode is enabled (Phase 2).
    nv: NvidiaCcAttestor,
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

// ── SEC-020 Task 4: mutual-attestation handshake (prover side) ───────────────

/// Parse a `0x`-optional 64-hex string into 32 bytes.
fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    let b = hex::decode(s.trim_start_matches("0x")).ok()?;
    if b.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&b);
    Some(out)
}

/// GET `url` via a curl subprocess (the repo's HTTP transport pattern — the
/// gateway's prover client uses the same) and parse the JSON body. Boot-time
/// only; short timeouts so a dead peer fails the handshake fast (fail-closed),
/// never wedges startup.
fn http_get_json(url: &str) -> Result<serde_json::Value, String> {
    let out = std::process::Command::new("curl")
        .args([
            "-s",
            "-S",
            "--fail",
            "--connect-timeout",
            "10",
            "--max-time",
            "30",
            url,
        ])
        .output()
        .map_err(|e| format!("curl spawn: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "curl exit {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    serde_json::from_slice(&out.stdout).map_err(|e| format!("json: {e}"))
}

/// A pinned expected-measurement env var (32-byte hex): required for the
/// attestation handshake unless `DEV_INSECURE` — unset/malformed refuses the
/// handshake (fail-closed), never a default. `GATEWAY_EXPECTED_MEASUREMENT`
/// pins the gateway CVM, `PROVER_EXPECTED_MEASUREMENT` pins this GB10 prover;
/// Phase 2 requires both to be APP-level identities (see the C1 note below).
fn expected_measurement_env(var: &str) -> Result<Digest, String> {
    let s = std::env::var(var).map_err(|_| {
        format!("{var} unset — required for the attestation handshake unless DEV_INSECURE")
    })?;
    parse_hex32(&s).ok_or_else(|| format!("{var} is not 32-byte hex"))
}

/// SEC-020 Task 4: the prover's side of the boot mutual-attestation handshake.
/// Fetches the gateway's `/attest` quote over OUR fresh per-boot nonce, verifies
/// it against the pinned `GATEWAY_EXPECTED_MEASUREMENT`, and mints the session
/// token from the shared transcript.
///
/// Fail-closed by construction: ANY `Err` at ANY step (env pin unset, no pinned
/// collateral, unreachable peer, malformed response, failed verify) aborts the
/// WHOLE handshake — the caller leaves the session token unset and the /prove
/// gate stays closed. A token is never minted from a partial transcript.
fn boot_handshake(pv_nonce: &[u8; 32], epoch: u64) -> Result<String, String> {
    let gw_url = std::env::var("GATEWAY_URL")
        .map_err(|_| "GATEWAY_URL unset — cannot reach the gateway's /attest".to_string())?;
    let gw_expected = expected_measurement_env("GATEWAY_EXPECTED_MEASUREMENT")?;
    let pv_expected = expected_measurement_env("PROVER_EXPECTED_MEASUREMENT")?;
    // The pinned DCAP collateral the gateway's TD quote is verified against —
    // the same ATTESTATION_DIR bundle layout the gateway's §5c self-attest uses
    // (this box carries a pinned copy).
    let dir = std::env::var("ATTESTATION_DIR").map_err(|_| {
        "ATTESTATION_DIR unset — no pinned collateral to verify the gateway quote".to_string()
    })?;
    let collateral = std::fs::read(std::path::Path::new(&dir).join("collateral.json"))
        .map_err(|e| format!("read {dir}/collateral.json: {e}"))?;
    let azure =
        AzureTdxAttestor::from_collateral_json(&collateral).map_err(|e| format!("{e:?}"))?;

    let url = format!(
        "{}/attest?nonce=0x{}",
        gw_url.trim_end_matches('/'),
        hex::encode(pv_nonce)
    );
    let resp = http_get_json(&url)?;
    let quote = resp
        .get("quote")
        .and_then(|v| v.as_str())
        .map(|s| hex::decode(s.trim_start_matches("0x")))
        .and_then(Result::ok)
        .ok_or("no hex `quote` in the gateway /attest response")?;
    // The gateway's own per-boot handshake nonce rides its /attest response so
    // both sides derive the identical transcript.
    let gw_nonce = resp
        .get("nonce")
        .and_then(|v| v.as_str())
        .and_then(parse_hex32)
        .ok_or("no 32-byte `nonce` in the gateway /attest response")?;

    // PHASE 2 (C2): per-handshake freshness must ride the vTPM AK quote extraData
    // (AzureVtpmReport.nonce, vtpm.rs), and /attest must carry the full tee-capture
    // vTPM bundle (hcl_report.bin/ak_quote_msg.bin/ak_quote_sig.bin/pcrs.txt), not
    // just quote.bin. TD-quote report_data is a per-boot static value — no
    // standalone replay protection.
    //
    // PHASE 2 (C1): GATEWAY_EXPECTED_MEASUREMENT must be the APP-level
    // azure_app_measurement (MRTD‖pcr_digest, see vtpm.rs), NOT the firmware-only
    // TD-quote fold; AzureTdxAttestor::verify pins firmware-level today. Do NOT
    // enable CC until this is app-level or two app binaries on one SKU cross-verify.
    let gw_meas = azure
        .verify(&quote, &gw_expected, pv_nonce)
        .map_err(|e| format!("gateway quote verify: {e:?}"))?;

    // Shared transcript orientation (both sides identical): gateway nonce +
    // measurement first, prover second. `gw_meas` is verify-enforced ==
    // `gw_expected`; `pv_expected` stands in for our own measurement (the
    // gateway's NVIDIA-side verify enforces the same pin on its half).
    let secret = session_secret(&gw_nonce, pv_nonce, &gw_meas, &pv_expected);
    Ok(session_token(&secret, epoch))
}

#[derive(Deserialize)]
struct AttestQuery {
    nonce: String,
}

/// `GET /attest?nonce=0x…` — this prover's self-quote, for the gateway's side of
/// the SEC-020 mutual-attestation handshake. The quote is
/// `NvidiaCcAttestor::quote(nonce)`: on today's CC-off GB10 that is
/// `Err(CcNotEnabled)`, so this endpoint answers 503 (attestation not ready)
/// rather than fabricating a quote — fail-closed. The response also carries this
/// host's per-boot handshake nonce + token epoch so the caller derives the
/// shared transcript (and mints under OUR epoch — the value /prove compares).
async fn attest(
    State(app): State<Arc<App>>,
    Query(q): Query<AttestQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let Some(nonce) = parse_hex32(&q.nonce) else {
        return Err((StatusCode::BAD_REQUEST, "nonce must be 32-byte hex".into()));
    };
    if app.dev_insecure {
        // DEV_INSECURE (non-prod only — prod refuses to boot with it): a clearly
        // labeled placeholder, never mistakable for a real quote.
        return Ok(Json(serde_json::json!({
            "quote": "dev-insecure-placeholder-quote",
            "nonce": hx(&app.hs_nonce),
            "epoch": app.hs_epoch,
        })));
    }
    match app.nv.quote(&nonce) {
        Ok(quote) => Ok(Json(serde_json::json!({
            "quote": hx(&quote),
            "nonce": hx(&app.hs_nonce),
            "epoch": app.hs_epoch,
        }))),
        // CcNotEnabled / Backend: this prover cannot attest itself yet — 503 and
        // the gateway's handshake refuses (fail-closed); never a fabricated quote.
        Err(e) => Err((
            StatusCode::SERVICE_UNAVAILABLE,
            format!("attestation not ready: {e:?}"),
        )),
    }
}

#[tokio::main]
async fn main() {
    let m = measurement();
    let backend = Sp1GnarkProver::new(m).await;
    let program_vkey = backend.vkey();
    let prod = std::env::var("PROD").as_deref() != Ok("0"); // released binary defaults prod
    let root = match prover::resolve_seal_root(prod) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("prover-service: {e}");
            std::process::exit(1);
        }
    };
    if !prod || std::env::var("DEV_INSECURE").as_deref() == Ok("1") {
        eprintln!("WARN prover-service: DEV_INSECURE seal root in use — NEVER production");
    }
    // ── SEC-020 Task 4: mutual-attestation handshake (boot) ──
    // The Phase-1 fail-closed guarantee comes from the NVIDIA side plus
    // refuse-on-any-error: our own /attest quote is `CcNotEnabled` until GB10 CC
    // mode is on (so the gateway's half refuses), and ANY `Err` in the
    // boot_handshake below leaves `session_token = None` — a token is never
    // minted from a partial or failed handshake, regardless of whether the
    // Azure-side verify would have passed. Task 4 mints + stores only; the
    // /prove gate that consumes the token is a later task.
    let dev_insecure = std::env::var("DEV_INSECURE").as_deref() == Ok("1");
    if prod && dev_insecure {
        // Task-1 posture, unconditional here: resolve_seal_root only refuses
        // DEV_INSECURE when the seal root is ALSO unset.
        eprintln!("prover-service: DEV_INSECURE is forbidden when PROD is set — refusing to start");
        std::process::exit(1);
    }
    let mut hs_nonce = [0u8; 32];
    getrandom::getrandom(&mut hs_nonce).expect("OS CSPRNG");
    // Per-boot token epoch (hour granularity), advertised in /attest so the
    // gateway mints the token /prove will compare. Rotation/expiry lands with
    // the /prove gate.
    let hs_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs()
        / 3600;
    let session_token = if dev_insecure {
        // Non-prod only (prod exits above): skip BOTH verifications and use the
        // FIXED dev token — never derived from real quotes.
        eprintln!(
            "WARN prover-service: INSECURE: attestation handshake skipped — never production"
        );
        Some(DEV_INSECURE_SESSION_TOKEN.to_string())
    } else {
        match boot_handshake(&hs_nonce, hs_epoch) {
            Ok(t) => {
                println!("prover-service: attestation handshake OK — session token minted");
                Some(t)
            }
            Err(e) => {
                // Fail-closed: no token. Expected on today's hardware (the static
                // Azure TD quote cannot bind our fresh nonce, and our own side is
                // CcNotEnabled) — proving stays closed until Phase 2.
                eprintln!(
                    "prover-service: attestation handshake REFUSED ({e}) — no session token; \
                     /prove stays closed once gated (SEC-020 fail-closed)"
                );
                None
            }
        }
    };
    let app = Arc::new(App {
        prover: AttestedProver::new(backend, SoftwareSealProvider::new(root, m)),
        vkey: program_vkey,
        measurement: m,
        session_token,
        hs_nonce,
        hs_epoch,
        dev_insecure,
        nv: NvidiaCcAttestor::detect(),
    });
    let router = Router::new()
        .route("/prove", post(prove))
        .route("/vkey", get(vkey))
        .route("/measurement", get(measurement_ep))
        .route("/attest", get(attest))
        // The /prove body is the sealed witness, which embeds the full engine pre_state
        // (hex-encoded) and grows with the number of accounts — it exceeds axum's 2 MB
        // default once the state is non-trivial (413 Payload Too Large → settles wedge).
        // Raise the cap generously; the witness is trusted, gateway-produced input.
        // NOTE: the full-state witness is a scaling limit (proof cost grows with total
        // accounts, not window activity) — a sparse-witness redesign is post-alpha.
        .layer(axum::extract::DefaultBodyLimit::max(512 * 1024 * 1024))
        .with_state(app);
    let bind = std::env::var("PROVER_BIND").unwrap_or_else(|_| "127.0.0.1:8091".into());
    println!("prover-service on {bind}");
    let listener = tokio::net::TcpListener::bind(&bind).await.unwrap();
    axum::serve(listener, router).await.unwrap();
}

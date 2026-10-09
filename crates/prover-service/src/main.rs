//! Attested prover HTTP service (§10b). Holds one `AttestedProver<Sp1GnarkProver>` and a
//! `SoftwareSealProvider` stand-in (P3 replaces the SealKeyProvider with real TDX/Nitro
//! key-release). `POST /prove` takes a sealed witness, opens+derives+proves+zeroizes, and
//! returns the 6 roots, the commitment, and the real Groth16 proof.
mod admission;
#[cfg(all(test, unix))]
mod shutdown_tests;
mod sp1_prover;

use admission::{Gate, Limits, ProofAdmission};

use axum::{
    extract::{FromRef, Request, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
// SEC-020 mutual-attestation handshake — AzureTdxAttestor verifies the
// GATEWAY's evidence bundle, NvidiaCcAttestor produces OUR self-quote
// (fail-closed CcNotEnabled until GB10 CC mode is on), and the pure ephemeral-
// DH transcript math is shared with the gateway. `StaticSecret` is the
// attestation crate's re-export of the ephemeral x25519 secret type.
use dark_perp_attestation::{
    derive_session, dh_shared, ephemeral_keypair, Attestor as _, AzureTdxAttestor,
    NvidiaCcAttestor, StaticSecret, DEV_INSECURE_SESSION_TOKEN,
};
use perp_core::hash::Digest;
use prover::{
    AttestedProver, AttestedSealProvider, SealKeyProvider, SealedWitness, SoftwareSealProvider,
};
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
    admission: Gate,
    limits: Limits,
    prover: AttestedProver<Sp1GnarkProver>,
    vkey: String,
    measurement: Digest,
    /// SEC-020 Phase-2 (C3): this prover's per-boot ephemeral x25519 DH PUBLIC
    /// key — served in /attest (and bound as our self-quote challenge) so the
    /// gateway derives the shared transcript. Freshness = this single-use key;
    /// no fetcher-supplied nonce exists anymore. The matching SECRET is
    /// consumed by `boot_handshake` at boot and dropped — it never lands here.
    pv_pub: [u8; 32],
    /// SEC-020 Phase-2 (C5): the session expiry this boot advertises and mints
    /// under — `now + SESSION_TTL_MS`, computed ONCE at boot. The PROVER owns
    /// expiry; the gateway echoes this value into its own token so both sides
    /// compare equal on /prove.
    session_not_after: u64,
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

impl FromRef<Arc<App>> for Gate {
    fn from_ref(app: &Arc<App>) -> Self {
        app.admission.clone()
    }
}

async fn prove(
    State(app): State<Arc<App>>,
    admission: ProofAdmission,
    request: Request,
) -> Result<Json<ProveResp>, (StatusCode, String)> {
    // Recheck before receiving/decoding the sealed body. A diagnostic output
    // setting is a server configuration fault, not unprocessable client input.
    prover::validate_sp1_environment()
        .map_err(|error| (StatusCode::SERVICE_UNAVAILABLE, error.to_string()))?;
    // The parts-only extractor above authenticates and reserves capacity before
    // Json can poll the body. Also limit how long reception may occupy a slot.
    let Json(req) =
        admission::read_json::<ProveReq, _>(request, &app, app.limits.body_timeout).await?;
    // Bad hex / bad postcard are caller errors: 400 so a client checking the status
    // sees the failure (axum's `IntoResponse for String` would 200 the error text).
    let raw = hex::decode(req.sealed.trim_start_matches("0x"))
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let sealed: SealedWitness =
        postcard::from_bytes(&raw).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    // The SP1 prove blocks; run the whole open+derive+prove off the async worker.
    let app2 = app.clone();
    let bp = admission
        .run_blocking(move || app2.prover.prove_batch(&sealed))
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

/// SEC-020 Phase-2 (C5): how long a boot-minted attestation session lives. The
/// PROVER owns expiry (it enforces the /prove gate): `not_after = now +
/// SESSION_TTL_MS` is computed ONCE at boot, advertised on /attest, and bound
/// into both sides' tokens. This is the ONLY clock read in the token path.
const SESSION_TTL_MS: u64 = 15 * 60 * 1000;

/// SEC-020 Phase-2 (C3): the prover's side of the boot mutual-attestation
/// handshake — the ephemeral-DH flow. No query nonce: freshness is the
/// single-use ephemeral keypair each side binds into its OWN attested evidence.
/// Fetches the gateway's `/attest` `{bundle, eph_pub}` (NO `not_after` there —
/// WE own expiry), verifies the bundle over the gateway's advertised `eph_pub`
/// against the pinned `GATEWAY_EXPECTED_MEASUREMENT`, folds the x25519 ECDH
/// shared point into the session secret, and mints the token under OUR
/// `not_after` (the caller computed it once at boot and already holds it).
///
/// Fail-closed by construction: ANY `Err` at ANY step (env pin unset, no pinned
/// collateral, unreachable peer, malformed response, failed verify) aborts the
/// WHOLE handshake — the caller leaves the session token unset and the /prove
/// gate stays closed. A token is never minted from a partial transcript.
///
/// Returns BOTH the `/prove` session token AND the raw `session_secret` — the
/// attested seal key rests on that secret (see `AttestedSealProvider`). The
/// secret must never be logged or served; it stays in process memory only to
/// build the provider. On any `Err` the caller gets neither, so the attested
/// provider is never built from a partial handshake.
fn boot_handshake(
    pv_sk: &StaticSecret,
    pv_pub: &[u8; 32],
    not_after: u64,
) -> Result<(String, [u8; 32]), String> {
    let gw_url = std::env::var("GATEWAY_URL")
        .map_err(|_| "GATEWAY_URL unset — cannot reach the gateway's /attest".to_string())?;
    let gw_expected = expected_measurement_env("GATEWAY_EXPECTED_MEASUREMENT")?;
    let pv_expected = expected_measurement_env("PROVER_EXPECTED_MEASUREMENT")?;
    // The pinned DCAP collateral the gateway's evidence bundle is verified
    // against — the same ATTESTATION_DIR bundle layout the gateway's §5c
    // self-attest uses (this box carries a pinned copy).
    let dir = std::env::var("ATTESTATION_DIR").map_err(|_| {
        "ATTESTATION_DIR unset — no pinned collateral to verify the gateway quote".to_string()
    })?;
    let collateral = std::fs::read(std::path::Path::new(&dir).join("collateral.json"))
        .map_err(|e| format!("read {dir}/collateral.json: {e}"))?;
    let azure =
        AzureTdxAttestor::from_collateral_json(&collateral).map_err(|e| format!("{e:?}"))?;

    let url = format!("{}/attest", gw_url.trim_end_matches('/'));
    let resp = http_get_json(&url)?;
    let bundle = resp
        .get("bundle")
        .and_then(|v| v.as_str())
        .map(|s| hex::decode(s.trim_start_matches("0x")))
        .and_then(Result::ok)
        .ok_or("no hex `bundle` in the gateway /attest response")?;
    // The gateway's own per-boot ephemeral DH pubkey rides its /attest response;
    // its evidence must bind that key (verify's challenge below), so a MITM
    // cannot substitute its own DH key without failing the verify.
    let gw_pub = resp
        .get("eph_pub")
        .and_then(|v| v.as_str())
        .and_then(parse_hex32)
        .ok_or("no 32-byte `eph_pub` in the gateway /attest response")?;

    // Local reality: the STATIC Azure fixture's AK-extraData cannot bind our
    // fresh gw_pub, so this verify is NonceMismatch locally — the real-binary
    // handshake is window-deferred (a live tee-capture binds eph_pub on the CVM).
    let gw_meas = azure
        .verify(&bundle, &gw_expected, &gw_pub)
        .map_err(|e| format!("gateway quote verify: {e:?}"))?;

    // Shared transcript orientation (both sides identical): gateway fields
    // first, prover second — the SAME call shape as the gateway's
    // `prover_handshake`. `gw_meas` is verify-enforced == `gw_expected`;
    // `pv_expected` stands in for our own measurement (the gateway's
    // NVIDIA-side verify enforces the same pin on its half). The ECDH `shared`
    // requires OUR ephemeral PRIVATE key, so the secret is not derivable from
    // the public /attest transcript (C3).
    let shared = dh_shared(pv_sk, &gw_pub);
    let (secret, token) =
        derive_session(&shared, &gw_meas, &pv_expected, &gw_pub, pv_pub, not_after);
    Ok((token, secret))
}

/// `GET /attest` — this prover's self-quote evidence, for the gateway's side of
/// the SEC-020 mutual-attestation handshake. No `?nonce=` query (C2/C3):
/// freshness IS the single-use `eph_pub` this boot bound into its own evidence
/// (`NvidiaCcAttestor::quote(&pv_pub)`) — a replayed `{bundle, eph_pub}` is
/// useless without the matching ephemeral PRIVATE key. On today's CC-off GB10
/// the quote is `Err(CcNotEnabled)`, so this endpoint answers 503 (attestation
/// not ready) rather than fabricating evidence — fail-closed. The response also
/// carries `not_after` — WE own session expiry (C5); the gateway mints its
/// token under this value, so both sides compare equal on /prove.
async fn attest(
    State(app): State<Arc<App>>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if app.dev_insecure {
        // DEV_INSECURE (non-prod only — prod refuses to boot with it): a clearly
        // labeled placeholder, never mistakable for a real evidence bundle.
        return Ok(Json(serde_json::json!({
            "bundle": "dev-insecure-placeholder-bundle",
            "eph_pub": hx(&app.pv_pub),
            "not_after": app.session_not_after,
        })));
    }
    match app.nv.quote(&app.pv_pub) {
        Ok(bundle) => Ok(Json(serde_json::json!({
            "bundle": hx(&bundle),
            "eph_pub": hx(&app.pv_pub),
            "not_after": app.session_not_after,
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
    // SP1 captures worker dump paths during setup. Refuse before constructing
    // the client or accepting requests; Drop cannot undo a dump followed by exit.
    prover::validate_sp1_environment().unwrap_or_else(|error| {
        eprintln!("prover-service: {error}");
        std::process::exit(1);
    });
    let limits = Limits::from_env().unwrap_or_else(|error| {
        eprintln!("prover-service: {error}");
        std::process::exit(1);
    });
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
    // SEC-020 Phase-2 (C3): the per-boot ephemeral x25519 keypair — the
    // freshness for BOTH directions of the handshake. The public half rides our
    // /attest (and is the challenge our self-quote binds); the SECRET half is
    // consumed by boot_handshake below and dropped (zeroize-on-drop) — it is
    // never stored, logged, or served.
    let mut ikm = [0u8; 32];
    getrandom::getrandom(&mut ikm).expect("OS CSPRNG");
    let (pv_sk, pv_pub) = ephemeral_keypair(&ikm);
    // (C5) The PROVER owns session expiry: `not_after` is computed ONCE at
    // boot, advertised on /attest, and bound into both sides' tokens — the
    // /prove gate compares against it. This is the only boot-time clock read.
    // DEV_INSECURE (non-prod only; prod exits above): the FIXED dev token
    // never expires — `u64::MAX` keeps the dev gate open for the whole run.
    let session_not_after = if dev_insecure {
        u64::MAX
    } else {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_millis() as u64
            + SESSION_TTL_MS
    };
    // SEC-020 Task 6: the handshake now yields the raw `session_secret` too (never
    // logged/served) — the attested seal key rests on it. `session_secret = None` ⇒
    // no attested session (dev-insecure skips the handshake; a refused prod handshake
    // returns Err) ⇒ the attested provider is NOT built (fail-closed selection below).
    let (session_token, session_secret): (Option<String>, Option<[u8; 32]>) = if dev_insecure {
        // Non-prod only (prod exits above): skip BOTH verifications and use the
        // FIXED dev token — never derived from real quotes. No real session secret:
        // the dev seal path uses SoftwareSealProvider (branch 2 below), NOT attested.
        eprintln!(
            "WARN prover-service: INSECURE: attestation handshake skipped — never production"
        );
        (Some(DEV_INSECURE_SESSION_TOKEN.to_string()), None)
    } else {
        match boot_handshake(&pv_sk, &pv_pub, session_not_after) {
            Ok((t, secret)) => {
                println!("prover-service: attestation handshake OK — session token minted");
                (Some(t), Some(secret))
            }
            Err(e) => {
                // Fail-closed: no token, no secret. Expected on today's hardware (the
                // static Azure TD quote cannot bind our fresh nonce, and our own side
                // is CcNotEnabled) — proving stays closed until Phase 2.
                eprintln!(
                    "prover-service: attestation handshake REFUSED ({e}) — no session token; \
                     /prove stays closed once gated (SEC-020 fail-closed)"
                );
                (None, None)
            }
        }
    };
    // Single-use ephemeral: the DH secret's job ended with the handshake —
    // drop it now (StaticSecret zeroizes on drop) so it never outlives boot.
    drop(pv_sk);
    // ── SEC-020 Task 6: fail-closed seal-provider selection ──
    // 1. attested session present ⇒ AttestedSealProvider (seal key bound to the
    //    session secret + measurement). Phase-2-active: today the prod handshake
    //    refuses, so this branch is reached only once GB10 CC enables the handshake.
    // 2. else if !prod && DEV_INSECURE ⇒ SoftwareSealProvider (dev-only stand-in).
    // 3. else ⇒ refuse to start. There is NO path where prod builds a
    //    SoftwareSealProvider or any public-constant-rooted provider.
    let seal_provider: Box<dyn SealKeyProvider + Send + Sync> = if let Some(secret) = session_secret
    {
        Box::new(AttestedSealProvider {
            session_secret: secret,
            measurement: m,
        })
    } else if !prod && dev_insecure {
        eprintln!("WARN prover-service: SoftwareSealProvider (DEV_INSECURE) — NEVER production");
        Box::new(SoftwareSealProvider::new(root, m))
    } else {
        eprintln!(
            "prover-service: SEC-020 no attested session and not DEV_INSECURE — \
             refusing to start (no fail-open software seal provider in production)"
        );
        std::process::exit(1);
    };
    let admission = Gate::new(session_token, session_not_after, limits.max_concurrent);
    let app = Arc::new(App {
        admission: admission.clone(),
        limits: limits.clone(),
        prover: AttestedProver::from_boxed(backend, seal_provider),
        vkey: program_vkey,
        measurement: m,
        pv_pub,
        session_not_after,
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
        // Authenticated admissions alone can reach this configurable bounded cap.
        // NOTE: the full-state witness is a scaling limit (proof cost grows with total
        // accounts, not window activity) — a sparse-witness redesign is post-alpha.
        .layer(axum::extract::DefaultBodyLimit::max(limits.body_bytes))
        .with_state(app);
    let bind = std::env::var("PROVER_BIND").unwrap_or_else(|_| "127.0.0.1:8091".into());
    let shutdown = shutdown_signal(admission.clone());
    println!("prover-service on {bind}");
    let listener = tokio::net::TcpListener::bind(&bind).await.unwrap();
    serve_until_shutdown(listener, router, admission.clone(), shutdown)
        .await
        .unwrap();
}

/// Axum can finish draining after an HTTP client disconnects while its blocking
/// proof still runs. Keep the runtime (timers, I/O, spawned async work) alive
/// until those admitted workers finish, including after a listener error.
async fn serve_until_shutdown<F>(
    listener: tokio::net::TcpListener,
    router: Router,
    admission: Gate,
    shutdown: F,
) -> std::io::Result<()>
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    let result = axum::serve(listener, router)
        .with_graceful_shutdown(shutdown)
        .await;
    admission.drain().await;
    result
}

// Construct the signal streams before opening the listener. A lazily polled
// async function can otherwise accept work before installing the OS handlers.
fn shutdown_signal(admission: Gate) -> impl std::future::Future<Output = ()> + Send {
    #[cfg(unix)]
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("install SIGTERM handler");
    #[cfg(unix)]
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .expect("install SIGINT handler");
    async move {
        #[cfg(unix)]
        tokio::select! {
            _ = interrupt.recv() => {},
            _ = terminate.recv() => {},
        }
        #[cfg(not(unix))]
        tokio::signal::ctrl_c()
            .await
            .expect("install ctrl-c handler");
        // Stop admission before asking axum to stop accepting and drain requests.
        // serve_until_shutdown explicitly drains admitted workers before Tokio exits.
        admission.close();
    }
}

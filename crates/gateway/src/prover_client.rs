//! Slice 3b-2a: the gateway's client for turning a sealed window into the seven on-chain
//! roots + a proof. `MockProverClient` derives the roots in-process (no network, no
//! confidentiality boundary) and uses the commitment as the proof — accepted by the
//! on-chain MockZkVerifier (proof == commitment). Slice 3b-2b adds `HttpProverClient`
//! (seal → POST /prove → real Groth16 proof); this module's trait is that seam.
//!
//! SEC-025-B trust boundary: a `ProverClient` returns the RAW `/prove` response
//! (`RemoteProveResp`) and is trusted for NOTHING but the proof bytes.
//! `prove_and_prepare` replays the `WindowWitness` itself (`derive_roots` is pure over
//! explicit inputs — deterministic), derives all seven roots + the cumulative
//! `new_deposit_count` locally, and requires the prover's commitment to equal its own;
//! since the commitment is a keccak over all seven roots, that one comparison covers
//! them all. The remote's itemised roots serve only to name WHICH root differs on a
//! mismatch.

use crate::withdrawals::Withdrawal;
use perp_core::commitment::derive_roots;
use perp_core::hash::{Domain, Hasher};
use perp_core::merkle::{merkle_proof, merkle_root};
use perp_core::{Digest, EngineError, Keccak256};
use sequencer::WindowWitness;
use std::collections::BTreeMap;

/// The six on-chain roots + commitment + proof for one window's `settleBatch`.
/// Serde: persisted (sealed) in the rollback journal once the prove returns, so a boot
/// after a crash between prove and commit can roll the landed settle forward.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ProveOutcome {
    pub prev_root: Digest,
    pub manifest_hash: Digest,
    pub new_root: Digest,
    pub ordered_root: Digest,
    pub withdrawals_root: Digest,
    pub rejected_root: Digest,
    /// SEC-019: the post-batch deposit hash-chain tip — the 7th commitment word.
    /// SEC-025-B: derived by the gateway's OWN replay in `prove_and_prepare` (never
    /// taken from the prover), like every other root in this struct.
    pub deposits_root: Digest,
    /// SEC-025-B: the POST-replay cumulative `consumed_deposit_count`, which is the
    /// `newDepositCount` argument of the nine-parameter `settleBatch`. Cumulative, not
    /// per-window: a zero-deposit window over a pre-state of five submits five.
    /// `_requireDepositPrefix` pins this to the L1 deposit hash chain BEFORE the proof
    /// is verified, so it is a fund-safety input and is derived locally, never accepted
    /// from the prover.
    pub new_deposit_count: u64,
    pub commitment: Digest,
    pub proof: Vec<u8>,
}

#[derive(Debug)]
// All variants are live (Derive by MockProverClient; Seal/Http/Decode by HttpProverClient
// and its helpers), but their payloads are only ever read via `{e:?}` in prove_and_prepare,
// and dead-code analysis does not count derived-Debug as a read — hence the allow.
#[allow(dead_code)]
pub enum ProverClientError {
    /// The window witness failed to replay (should not happen for a live-sealed window).
    Derive(EngineError),
    /// Sealing refused (provider returned None for the measurement/nonce).
    Seal,
    /// Transport failure talking to the prover-service (curl error / non-2xx / timeout).
    Http(String),
    /// Malformed prover-service response (bad JSON, missing field, or bad hex).
    Decode(String),
    /// SEC-020 Task 5: the prover's `/prove` gate rejected our bearer (HTTP 401) —
    /// the attestation session token is stale/absent. `HttpProverClient::prove`
    /// re-handshakes ONCE and retries; a second 401 (or no re-handshake wired)
    /// surfaces here and proving stays closed (fail-closed).
    Unauthorized,
}

/// SEC-020 Task 5 / C4: re-runs the mutual-attestation handshake with the prover
/// and returns a fresh `(session_token, session_secret, not_after)` triple (or an
/// error). ALL THREE ride the refresh: a rebooted prover derives a NEW session
/// secret, so refreshing only the token would leave the gateway sealing under the
/// STALE secret — the /prove bearer would pass while every seal failed to open
/// (`SealAuthFailed`), wedging proving until a gateway restart (the C4 bug).
/// Boxed so the attestation machinery stays in `main.rs` while `HttpProverClient`
/// can refresh its session on a 401. `Send + Sync` so the client stays
/// `Send + Sync` behind an `Arc`.
pub type ReHandshake = Box<dyn Fn() -> Result<(String, [u8; 32], u64), String> + Send + Sync>;

/// The six roots the prover-service currently emits, plus the 7th it does not yet.
/// Every field is optional: these are DIAGNOSTIC only. Under SEC-025-B the gateway
/// derives its own authoritative roots (see `prove_and_prepare`), so a response that
/// omits a root is not an error — it just yields a less specific message on mismatch.
#[derive(Debug, Default)]
pub struct RemoteRoots {
    pub prev_root: Option<Digest>,
    pub manifest_hash: Option<Digest>,
    pub new_root: Option<Digest>,
    pub ordered_root: Option<Digest>,
    pub withdrawals_root: Option<Digest>,
    pub rejected_root: Option<Digest>,
    pub deposits_root: Option<Digest>,
}

/// What `/prove` actually returns. Distinct from `ProveOutcome`, which is the
/// AUTHORITATIVE post-replay value and cannot be built until the gateway has replayed
/// the witness itself.
#[derive(Debug)]
pub struct RemoteProveResp {
    pub roots: RemoteRoots,
    pub commitment: Digest,
    pub proof: Vec<u8>,
}

/// Turns a sealed window into a proof over its commitment.
pub trait ProverClient: Send + Sync {
    /// Returns the prover's RAW response. The gateway derives the authoritative roots
    /// itself in `prove_and_prepare`; a client is trusted only for `proof` bytes.
    fn prove(&self, witness: &WindowWitness) -> Result<RemoteProveResp, ProverClientError>;
}

/// In-process client: derive the roots locally and use the commitment as the proof
/// (accepted by the on-chain MockZkVerifier, proof == commitment). SEC-025-B: it
/// returns the raw remote shape — a stand-in for the remote prover, NOT a source of
/// truth; `prove_and_prepare`'s own replay is the authority either way.
pub struct MockProverClient;

impl ProverClient for MockProverClient {
    fn prove(&self, w: &WindowWitness) -> Result<RemoteProveResp, ProverClientError> {
        let mut state = w.pre_state.clone();
        let d = derive_roots(&mut state, &w.ops, &w.manifest).map_err(ProverClientError::Derive)?;
        let commitment = d.commitment::<Keccak256>();
        Ok(RemoteProveResp {
            roots: RemoteRoots {
                prev_root: Some(d.prev_state_root),
                manifest_hash: Some(d.manifest_hash),
                new_root: Some(d.new_state_root),
                ordered_root: Some(d.ordered_root),
                withdrawals_root: Some(d.withdrawals_root),
                rejected_root: Some(d.rejected_root),
                deposits_root: Some(d.deposits_root),
            },
            commitment,
            proof: commitment.to_vec(),
        })
    }
}

/// The proven outcome plus the per-note claim proofs the gateway serves.
/// Serde: journaled alongside `ProveOutcome` so a roll-forward at boot can re-commit the
/// exact claim proofs the crashed process would have served (never recomputed from a
/// possibly-drifted state).
/// Clone: the settle loop's stage-2 journal write clones a copy into the journal while
/// the original proceeds to `settle_proved`/`commit_window_settle` (Task 2).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct PreparedSettle {
    pub outcome: ProveOutcome,
    pub withdraw_proofs: BTreeMap<[u8; 32], (Digest, Vec<[u8; 32]>)>,
}

/// Prove a sealed window and prepare its claim proofs. SEC-025-B §1: the gateway
/// replays the witness ITSELF and its derivation is the outcome — the prover's
/// commitment must equal the local one, and the prover contributes only proof bytes.
/// Also builds the window's withdrawal tree from `ww` (op-application order) and
/// asserts its root byte-matches the locally derived `withdrawals_root` — the two are
/// the same `merkle_root` over the same `withdrawal_leaf`s, so any divergence is a
/// hard error, never silently published.
pub fn prove_and_prepare(
    client: &dyn ProverClient,
    witness: &WindowWitness,
    ww: &[Withdrawal],
) -> Result<PreparedSettle, String> {
    // SEC-025-B §1 — derive the answer ourselves. `derive_roots` is pure over explicit
    // inputs (no clock: `now_ms` is a stored BatchOp field), so replaying the witness we
    // are about to send is deterministic and reproduces what the prover must derive.
    // This replaces a check that re-hashed the PROVER's own roots and therefore only
    // established that the prover agreed with itself.
    let mut post = witness.pre_state.clone();
    let derived = derive_roots(&mut post, &witness.ops, &witness.manifest)
        .map_err(|e| format!("local replay failed: {e:?}"))?;
    let local_commitment = derived.commitment::<Keccak256>();

    let remote = client.prove(witness).map_err(|e| format!("prove: {e:?}"))?;

    // The commitment is a keccak over all seven roots, so this ONE comparison verifies
    // every root. The per-root loop below exists only to turn "commitment mismatch" into
    // "the prover's new_root differs", which is the difference between a five-minute and
    // a five-hour cutover debug.
    if remote.commitment != local_commitment {
        let mut which = Vec::new();
        for (name, ours, theirs) in [
            ("prev_root", derived.prev_state_root, remote.roots.prev_root),
            (
                "manifest_hash",
                derived.manifest_hash,
                remote.roots.manifest_hash,
            ),
            ("new_root", derived.new_state_root, remote.roots.new_root),
            (
                "ordered_root",
                derived.ordered_root,
                remote.roots.ordered_root,
            ),
            (
                "withdrawals_root",
                derived.withdrawals_root,
                remote.roots.withdrawals_root,
            ),
            (
                "rejected_root",
                derived.rejected_root,
                remote.roots.rejected_root,
            ),
            (
                "deposits_root",
                derived.deposits_root,
                remote.roots.deposits_root,
            ),
        ] {
            if let Some(t) = theirs {
                if t != ours {
                    which.push(format!(
                        "{name} (ours {} vs prover {})",
                        crate::hex32(&ours),
                        crate::hex32(&t)
                    ));
                }
            }
        }
        let detail = if which.is_empty() {
            // either the prover itemised no roots, or every root it DID itemise matches
            // ours — then the commitment derivation itself (domain tag / hash) differs
            "no itemised prover root differs (roots absent or all matching ours)".to_string()
        } else {
            which.join(", ")
        };
        return Err(format!(
            "commitment mismatch: ours {} vs prover {} — {detail}",
            crate::hex32(&local_commitment),
            crate::hex32(&remote.commitment)
        ));
    }

    let outcome = ProveOutcome {
        prev_root: derived.prev_state_root,
        manifest_hash: derived.manifest_hash,
        new_root: derived.new_state_root,
        ordered_root: derived.ordered_root,
        withdrawals_root: derived.withdrawals_root,
        rejected_root: derived.rejected_root,
        deposits_root: derived.deposits_root,
        new_deposit_count: post.consumed_deposit_count,
        commitment: local_commitment,
        proof: remote.proof,
    };

    // Independent gateway-internal consistency check (kept from 3b-2a): the drained
    // window withdrawal set must byte-match the withdrawals the replay derived. Under
    // SEC-025-B the prover can no longer steer `withdrawals_root`; a mismatch here
    // means the gateway's own `ww` drifted from the witness ops — still a hard error.
    let leaves: Vec<[u8; 32]> = ww.iter().map(|w| w.leaf()).collect();
    let wroot = merkle_root(&leaves);
    if wroot != outcome.withdrawals_root {
        return Err(format!(
            "withdrawals root mismatch: gateway tree {} vs derived {}",
            crate::hex32(&wroot),
            crate::hex32(&outcome.withdrawals_root)
        ));
    }
    let mut withdraw_proofs = BTreeMap::new();
    for (i, w) in ww.iter().enumerate() {
        withdraw_proofs.insert(
            w.leaf(),
            (outcome.withdrawals_root, merkle_proof(&leaves, i)),
        );
    }
    Ok(PreparedSettle {
        outcome,
        withdraw_proofs,
    })
}

/// The clear per-seal nonce, secret-keyed with `seal_root`:
/// `keccak_words(SealNonce, [seal_root, keccak256(plaintext)])`. Still deterministic
/// in the plaintext (identical rollback re-seal / retry reproduces it — no two-time
/// pad; different plaintext → different nonce), but no longer a public function of the
/// plaintext, so an interceptor of the sealed witness cannot confirm a guessed witness
/// by matching the clear nonce. Its strength scales with `seal_root`'s secrecy (P3
/// Slice B — attested key-release — hardens that secret).
pub(crate) fn seal_nonce(seal_root: &[u8; 32], plaintext: &[u8]) -> Digest {
    use sha3::{Digest as _, Keccak256 as RawKeccak};
    let plaintext_hash: Digest = RawKeccak::digest(plaintext).into();
    Keccak256::hash_words(Domain::SealNonce, &[*seal_root, plaintext_hash])
}

/// Seal a window witness exactly as the prover-service's seal-client does, so the service
/// (same seal params) can open it. Plaintext is the postcard-encoded `(pre_state, ops,
/// manifest)` triple; the nonce is the secret-keyed `seal_nonce(root, plaintext)`
/// (content-derived and reuse-proof across rollback re-seals, but keyed with `root` so
/// the clear nonce can't confirm a guessed witness). Returns 0x-prefixed hex of the
/// postcard-encoded SealedWitness.
///
/// SEC-020 Task 6: fail-closed seal-provider selection, MIRRORING the prover-service:
/// - `session_secret = Some` (an attested session) ⇒ `AttestedSealProvider`, so the seal
///   key rests on the mutual-attestation session secret + measurement (Phase-2-active).
/// - `session_secret = None` (DEV_INSECURE, non-prod) ⇒ `SoftwareSealProvider` keyed with
///   the dev `root` — the dev-only stand-in the prover opens with on its matching branch.
///
/// The prover reads the nonce off the wire (`SealedWitness.nonce`), so the `root`-keyed
/// nonce derivation stays purely local and needs no agreement across the boundary.
pub fn seal_witness(
    w: &WindowWitness,
    root: &[u8; 32],
    measurement: &Digest,
    session_secret: Option<&[u8; 32]>,
) -> Result<String, ProverClientError> {
    let bytes = postcard::to_allocvec(&(&w.pre_state, &w.ops, &w.manifest))
        .map_err(|e| ProverClientError::Decode(format!("witness encode: {e}")))?;
    // Secret-keyed, content-derived nonce (see `seal_nonce`): keyed with `root` so the
    // clear nonce is not a plaintext-confirmation oracle, while identical re-seals still
    // reproduce it (rollback/retry-safe, no two-time pad).
    let nonce = seal_nonce(root, &bytes);
    let sealed = match session_secret {
        Some(secret) => {
            let provider = prover::AttestedSealProvider {
                session_secret: *secret,
                measurement: *measurement,
            };
            prover::SealedWitness::seal(&bytes, &provider, *measurement, nonce)
        }
        None => {
            let provider = prover::SoftwareSealProvider::new(*root, *measurement);
            prover::SealedWitness::seal(&bytes, &provider, *measurement, nonce)
        }
    }
    .ok_or(ProverClientError::Seal)?;
    let out = postcard::to_allocvec(&sealed)
        .map_err(|e| ProverClientError::Decode(format!("sealed encode: {e}")))?;
    let mut hexed = String::with_capacity(2 + out.len() * 2);
    hexed.push_str("0x");
    for b in &out {
        hexed.push_str(&format!("{b:02x}"));
    }
    Ok(hexed)
}

/// Parse the prover-service /prove JSON into the raw remote shape. SEC-025-B break 3:
/// the service's `ProveResp` has EIGHT fields and does not emit `deposits_root`, so
/// every root is OPTIONAL here (absent ⇒ `None`, never a decode failure) — the gateway
/// derives the authoritative roots itself in `prove_and_prepare`, and the remote roots
/// are diagnostic only. The commitment + proof are what the gateway actually consumes,
/// so those stay required.
pub fn parse_prove_resp(json: &str) -> Result<RemoteProveResp, ProverClientError> {
    #[derive(serde::Deserialize)]
    struct Resp {
        #[serde(default)]
        prev_root: Option<String>,
        #[serde(default)]
        manifest_hash: Option<String>,
        #[serde(default)]
        new_root: Option<String>,
        #[serde(default)]
        ordered_root: Option<String>,
        #[serde(default)]
        withdrawals_root: Option<String>,
        #[serde(default)]
        rejected_root: Option<String>,
        #[serde(default)]
        deposits_root: Option<String>,
        commitment: String,
        proof: String,
    }
    let r: Resp =
        serde_json::from_str(json).map_err(|e| ProverClientError::Decode(format!("json: {e}")))?;

    // An ABSENT root is fine (today's service omits `deposits_root`); a PRESENT but
    // unparseable one is not — leniency is about absence, never about garbage.
    let opt = |s: &Option<String>, name: &str| -> Result<Option<Digest>, ProverClientError> {
        match s {
            None => Ok(None),
            Some(v) => crate::parse_hex32(v)
                .map(Some)
                .ok_or_else(|| ProverClientError::Decode(format!("bad {name}: {v}"))),
        }
    };

    Ok(RemoteProveResp {
        roots: RemoteRoots {
            prev_root: opt(&r.prev_root, "prev_root")?,
            manifest_hash: opt(&r.manifest_hash, "manifest_hash")?,
            new_root: opt(&r.new_root, "new_root")?,
            ordered_root: opt(&r.ordered_root, "ordered_root")?,
            withdrawals_root: opt(&r.withdrawals_root, "withdrawals_root")?,
            rejected_root: opt(&r.rejected_root, "rejected_root")?,
            deposits_root: opt(&r.deposits_root, "deposits_root")?,
        },
        commitment: crate::parse_hex32(&r.commitment).ok_or_else(|| {
            ProverClientError::Decode(format!("bad commitment: {}", r.commitment))
        })?,
        proof: crate::decode_hex(&r.proof)
            .ok_or_else(|| ProverClientError::Decode(format!("bad proof: {}", r.proof)))?,
    })
}

/// SEC-020 Task 5: the marker the `-w` HTTP status is appended under, so `http_post`
/// can split the body from the status code regardless of the body's contents (the
/// prover's `/prove` JSON is single-line, so a leading newline + this marker never
/// collides). We deliberately DROP curl's `--fail`: `--fail` collapses every 4xx/5xx
/// into a bare non-zero exit, but the 401 from the `/prove` gate must be
/// distinguishable from a 5xx (401 ⇒ re-handshake + retry), so we read the status
/// ourselves instead.
const STATUS_SENTINEL: &str = "__DPHTTP_STATUS__";

/// Curl argv for a `/prove` POST. Factored out so the transport-hardening flags are
/// unit-testable. Beyond the wall-clock `--max-time`:
/// - `--connect-timeout 20`: a dead prover / down reverse-tunnel is detected on CONNECT
///   in 20s instead of blocking the settle loop for the full `--max-time` (a half-open
///   connection to a killed prover once hung a settle for the entire 30-min cap, wedging
///   `openWindowId` ahead of the chain until the timeout let the loop roll back).
/// - `--keepalive-time 30`: the HTTP connection sits IDLE for the whole multi-minute
///   proof (request sent, awaiting the response), so without TCP keepalives a NAT /
///   tunnel / firewall idle-timeout silently RSTs it mid-proof ("Recv failure: Connection
///   reset by peer"), wasting the proof. Keepalives every 30s hold it open.
///
/// SEC-020 Task 5: when `bearer` is `Some`, attach `Authorization: Bearer <token>` so
/// the prover's `/prove` gate authorizes the request. When `None` (the boot handshake
/// refused — Phase-1 prod), NO auth header is sent: the prover 401s (fail-closed). We
/// never fabricate an empty bearer that could accidentally pass a mis-implemented gate.
fn prove_curl_args(endpoint: &str, timeout_secs: u64, bearer: Option<&str>) -> Vec<String> {
    let mut args = vec![
        "-s".into(),
        "-S".into(),
        "--connect-timeout".into(),
        "20".into(),
        "--keepalive-time".into(),
        "30".into(),
        "--max-time".into(),
        timeout_secs.to_string(),
        "-X".into(),
        "POST".into(),
        "-H".into(),
        "Content-Type: application/json".into(),
    ];
    if let Some(token) = bearer {
        args.push("-H".into());
        args.push(format!("Authorization: Bearer {token}"));
    }
    // Append the HTTP status after the body under STATUS_SENTINEL (see `split_status`).
    args.push("-w".into());
    args.push(format!("\n{STATUS_SENTINEL}%{{http_code}}"));
    args.push("--data-binary".into());
    args.push("@-".into());
    args.push(endpoint.into());
    args
}

/// SEC-020 Task 5: split the curl stdout (`<body>\n__DPHTTP_STATUS__<code>`, from the
/// `-w` sentinel) into the response body and the numeric HTTP status. `rfind` on the
/// marker so any body content is safe. Returns a `Decode`-style error if the marker or
/// a numeric status is missing (a curl/flag regression, never a normal prover response).
fn split_status(raw: &str) -> Result<(String, u16), ProverClientError> {
    let marker = format!("\n{STATUS_SENTINEL}");
    let idx = raw
        .rfind(&marker)
        .ok_or_else(|| ProverClientError::Http("curl -w status marker missing".into()))?;
    let body = raw[..idx].to_string();
    let code = raw[idx + marker.len()..].trim();
    let status = code
        .parse::<u16>()
        .map_err(|_| ProverClientError::Http(format!("non-numeric http_code: {code:?}")))?;
    Ok((body, status))
}

/// POST `body` as application/json to `<url>/prove` via curl (mirrors L1::cast: a
/// subprocess with a wall-clock cap), piping the body on stdin so a large sealed witness
/// never hits an argv limit. The stdin write runs on its own thread to avoid a pipe
/// deadlock when the body exceeds the OS pipe buffer.
fn http_post(
    url: &str,
    body: &str,
    timeout_secs: u64,
    bearer: Option<&str>,
) -> Result<String, ProverClientError> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let endpoint = format!("{}/prove", url.trim_end_matches('/'));
    let mut child = Command::new("curl")
        .args(prove_curl_args(&endpoint, timeout_secs, bearer))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| ProverClientError::Http(format!("curl spawn: {e}")))?;
    let mut stdin = child.stdin.take().expect("piped stdin");
    let body_owned = body.to_string();
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(body_owned.as_bytes());
    });
    let out = child
        .wait_with_output()
        .map_err(|e| ProverClientError::Http(format!("curl wait: {e}")))?;
    let _ = writer.join();
    // Without `--fail`, a non-zero curl exit now means a TRANSPORT failure (connect
    // timeout, DNS, tunnel down) — the HTTP status itself rides the `-w` sentinel.
    if !out.status.success() {
        return Err(ProverClientError::Http(format!(
            "curl exit {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    let (resp_body, status) = split_status(&String::from_utf8_lossy(&out.stdout))?;
    match status {
        200..=299 => Ok(resp_body),
        // SEC-020 Task 5: the /prove gate rejected the bearer — surface as a typed
        // 401 so `prove` can re-handshake once and retry (fail-closed on a second 401).
        401 => Err(ProverClientError::Unauthorized),
        s => Err(ProverClientError::Http(format!(
            "prover /prove HTTP {s}: {resp_body}"
        ))),
    }
}

/// SEC-020 Task 5 / C4: the mutual-attestation session state, refreshed as ONE
/// unit by the 401 re-handshake. A single `Mutex` over all three fields (not one
/// per field) so no interleaving can ever observe a fresh token next to a stale
/// secret — exactly the seal/open mismatch C4 is about. The lock is only ever
/// held to read/replace the fields, never across the long-blocking POST.
struct SessionState {
    /// The /prove bearer from the (re-)handshake, sent as `Authorization:
    /// Bearer <token>`. `None` ⇒ the handshake refused (Phase-1 prod) ⇒ no
    /// bearer is sent and the prover's gate 401s (fail-closed).
    token: Option<String>,
    /// The raw mutual-attestation `session_secret` the attested seal key rests
    /// on (see `AttestedSealProvider`). `Some` ⇒ seal with the attested provider
    /// (Phase-2-active); `None` ⇒ the DEV_INSECURE fallback seals with
    /// `SoftwareSealProvider` keyed on `seal_root`. Never logged/served.
    secret: Option<[u8; 32]>,
    /// The PROVER-owned session expiry (unix ms) the current token was minted
    /// under. Stored so the refreshed session is complete; nothing reads it yet
    /// — D6's expiry-aware (pre-401) refresh will.
    #[allow(dead_code)]
    not_after: u64,
}

/// The real transport: seal the window and POST it to the attested prover-service.
pub struct HttpProverClient {
    url: String,
    seal_root: [u8; 32],
    measurement: Digest,
    timeout_secs: u64,
    /// SEC-020 Task 5 / C4: the attestation session from the boot handshake
    /// (token + secret + not_after), refreshed IN PLACE — all three together —
    /// by the 401 re-handshake. `Mutex` for interior mutability (the trait's
    /// `prove` is `&self`); see `SessionState` for the per-field contracts.
    session: std::sync::Mutex<SessionState>,
    /// SEC-020 Task 5: re-runs the mutual-attestation handshake on a 401 (a rotated /
    /// rebooted prover) and yields a fresh `(token, secret, not_after)`. `None` ⇒ no
    /// re-handshake wired (mock/dev construction) — a 401 is then terminal (still
    /// fail-closed).
    rehandshake: Option<ReHandshake>,
}

impl HttpProverClient {
    /// Build from PROVER_URL, matching the prover-service's seal params: PROVER_SEAL_ROOT
    /// (64-hex) resolved FAIL-CLOSED by `prover::resolve_seal_root` (SEC-020: no public
    /// default; unset refuses to boot the settle path, `DEV_INSECURE=1` only outside
    /// production) and the 0xAB.. stand-in measurement; PROVER_TIMEOUT_SECS (default 900
    /// — a real Groth16 proof under qemu takes minutes).
    ///
    /// The client is built session-less; `with_session_token` / `with_session_secret` /
    /// `with_rehandshake` inject the SEC-020 handshake state (main.rs wires them after
    /// the boot handshake).
    pub fn from_env(url: &str, prod: bool) -> Result<Self, String> {
        let seal_root = prover::resolve_seal_root(prod).map_err(|e| format!("seal root: {e}"))?;
        if std::env::var("PROVER_SEAL_ROOT").is_err() {
            // resolve_seal_root succeeds without PROVER_SEAL_ROOT only on the
            // DEV_INSECURE non-prod path — make that loud.
            eprintln!("WARN gateway: DEV_INSECURE seal root in use — NEVER production");
        }
        let timeout_secs = std::env::var("PROVER_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(900);
        Ok(Self {
            url: url.to_string(),
            seal_root,
            measurement: [0xABu8; 32],
            timeout_secs,
            session: std::sync::Mutex::new(SessionState {
                token: None,
                secret: None,
                not_after: 0,
            }),
            rehandshake: None,
        })
    }

    /// SEC-020 Task 5: set the boot-minted session token (`None` ⇒ handshake refused ⇒
    /// fail-closed: no bearer is sent and every `/prove` 401s).
    pub fn with_session_token(mut self, token: Option<String>) -> Self {
        self.session.get_mut().unwrap().token = token;
        self
    }

    /// SEC-020 Task 6 / C4: set the boot-derived `session_secret` plus the
    /// prover-owned `not_after` it was minted under (`None` secret ⇒ no attested
    /// session ⇒ the DEV_INSECURE `SoftwareSealProvider` seal path). Mirrors the
    /// prover-service's attested-vs-dev provider selection so seal/open round-trips.
    pub fn with_session_secret(mut self, secret: Option<[u8; 32]>, not_after: u64) -> Self {
        let s = self.session.get_mut().unwrap();
        s.secret = secret;
        s.not_after = not_after;
        self
    }

    /// SEC-020 Task 5: wire the re-handshake used to refresh the token on a 401.
    pub fn with_rehandshake(mut self, rehandshake: ReHandshake) -> Self {
        self.rehandshake = Some(rehandshake);
        self
    }
}

/// SEC-020 Task 5 / C4: run `post` with the current bearer; on a 401 (a stale
/// session — e.g. the prover rebooted with a new epoch) call `rehandshake` ONCE to
/// mint a fresh `(token, secret, not_after)`, persist ALL THREE via `store`, and
/// retry the POST. `store` runs BEFORE the retry so the retry's re-seal is keyed
/// by the REFRESHED secret — refreshing only the token would pass the bearer gate
/// while every seal still failed to open on the rebooted prover (the C4 wedge).
/// Still bounded to exactly ONE retry: a second 401, a missing re-handshake, or a
/// re-handshake error is terminal — proving stays closed (fail-closed). Factored
/// out (no I/O of its own) so the retry control flow is unit-testable without a
/// live prover.
fn prove_with_reauth(
    token: Option<String>,
    rehandshake: Option<&ReHandshake>,
    mut post: impl FnMut(Option<&str>) -> Result<RemoteProveResp, ProverClientError>,
    store: impl FnOnce(String, [u8; 32], u64),
) -> Result<RemoteProveResp, ProverClientError> {
    match post(token.as_deref()) {
        Err(ProverClientError::Unauthorized) => {
            let Some(rehandshake) = rehandshake else {
                return Err(ProverClientError::Unauthorized);
            };
            let (fresh_token, fresh_secret, fresh_not_after) = rehandshake().map_err(|e| {
                ProverClientError::Http(format!("re-handshake after 401 failed: {e}"))
            })?;
            store(fresh_token.clone(), fresh_secret, fresh_not_after);
            post(Some(&fresh_token))
        }
        other => other,
    }
}

impl ProverClient for HttpProverClient {
    fn prove(&self, w: &WindowWitness) -> Result<RemoteProveResp, ProverClientError> {
        // Snapshot the token (lock released at the end of this statement — never
        // held across the multi-minute POST). `None` ⇒ no bearer sent ⇒ the
        // prover 401s (fail-closed).
        let token = self.session.lock().unwrap().token.clone();
        prove_with_reauth(
            token,
            self.rehandshake.as_ref(),
            |bearer| {
                // Re-read the CURRENT secret on every attempt (copied out under
                // the lock, released before sealing): after a 401 → re-handshake
                // the retry must seal under the REFRESHED secret, or the rebooted
                // prover (new secret) rejects the stale-keyed seal (C4).
                let secret = self.session.lock().unwrap().secret;
                let sealed_hex =
                    seal_witness(w, &self.seal_root, &self.measurement, secret.as_ref())?;
                let body = serde_json::json!({ "sealed": sealed_hex }).to_string();
                let resp = http_post(&self.url, &body, self.timeout_secs, bearer)?;
                parse_prove_resp(&resp)
            },
            |fresh_token, fresh_secret, fresh_not_after| {
                let mut s = self.session.lock().unwrap();
                s.token = Some(fresh_token);
                s.secret = Some(fresh_secret);
                s.not_after = fresh_not_after;
            },
        )
    }
}

/// Test-only fixture builders for the SEC-025-B `prove_and_prepare` tests. Both drive
/// the REAL gateway path — `Gw::boot()` → account ops → `begin_window_settle` — never a
/// hand-built witness (the rollback_journal tests' `sealed_window` shape; underneath,
/// every op flows through the live `Sequencer`/`seal_window`). Each helper ASSERTS its
/// own preconditions, so a fixture that drifts fails loudly here instead of letting a
/// dependent test pass vacuously.
#[cfg(test)]
pub(crate) mod tests_support {
    use crate::withdrawals::Withdrawal;
    use perp_core::engine::BatchOp;
    use perp_core::fixed::QUOTE_SCALE;
    use sequencer::WindowWitness;

    /// A caller-signed account's signing key + its Ethereum address (the registered
    /// signer), so withdrawals go through the FULL SEC-021 authorization path.
    fn signer_key() -> (k256::ecdsa::SigningKey, [u8; 20]) {
        use sha3::{Digest as _, Keccak256};
        let sk = k256::ecdsa::SigningKey::from_slice(&[0x51u8; 32]).unwrap();
        let point = sk.verifying_key().to_encoded_point(false);
        let hash = Keccak256::digest(&point.as_bytes()[1..]);
        let mut signer = [0u8; 20];
        signer.copy_from_slice(&hash[12..]);
        (sk, signer)
    }

    /// A real signed withdrawal: sign the live `withdraw_auth_digest` with the
    /// account's registered signer and apply it (Unbind + Withdraw ops + the
    /// window's incremental withdrawal set).
    fn signed_withdraw(
        gw: &mut crate::Gw,
        sk: &k256::ecdsa::SigningKey,
        key: &[u8; 32],
        owner: &perp_core::PubKey,
        amount: i128,
        auth_nonce: u64,
    ) {
        let to = [7u8; 20];
        let digest =
            crate::withdraw_auth_digest(gw.chain_id, &gw.vault, owner, 0, amount, &to, auth_nonce);
        let (s, recid) = sk.sign_prehash_recoverable(&digest).unwrap();
        let mut sig = [0u8; 65];
        sig[..64].copy_from_slice(&s.to_bytes());
        sig[64] = 27 + recid.to_byte();
        gw.account_withdraw(key, 0, amount, to, auth_nonce, &sig)
            .unwrap();
    }

    /// A REAL sealed window containing at least one `Deposit` op AND at least one
    /// withdrawal, so `prove_and_prepare`'s withdrawal-tree byte-match is genuinely
    /// exercised. Note the pre-state is the FULL boot state (`seal_genesis_baseline`
    /// folds boot funding into the genesis baseline), so `consumed_deposit_count`
    /// starts non-zero too — cumulative vs per-window is distinguishable here as well.
    pub(crate) fn sample_window() -> (WindowWitness, Vec<Withdrawal>) {
        let (sk, signer) = signer_key();
        let mut gw = crate::Gw::boot();
        let (key, owner) = gw.register_account(Some(signer));
        gw.account_deposit(&key, 0, 20_000 * QUOTE_SCALE).unwrap();
        signed_withdraw(&mut gw, &sk, &key, &owner, 5_000 * QUOTE_SCALE, 1);
        let bc = gw.seq.state.next_batch_id;
        let (witness, ww) = gw.begin_window_settle(bc).unwrap().expect("window sealed");
        // fixture preconditions — do NOT weaken; a fixture without them lets the
        // dependent tests pass while exercising nothing
        assert!(
            witness
                .ops
                .iter()
                .any(|o| matches!(o, BatchOp::Deposit { .. })),
            "fixture precondition: sample_window must contain a Deposit op"
        );
        assert!(
            !ww.is_empty(),
            "fixture precondition: sample_window must contain a withdrawal"
        );
        (witness, ww)
    }

    /// A REAL sealed window with NO `Deposit` ops over a pre-state whose
    /// `consumed_deposit_count` is non-zero: window 0 (boot + a deposit) is sealed
    /// away first, then window 1 carries only a withdrawal. This is the fixture that
    /// distinguishes the cumulative `new_deposit_count` from a per-window reading
    /// (which would wrongly submit 0 here).
    pub(crate) fn sample_window_no_deposits() -> (WindowWitness, Vec<Withdrawal>) {
        let (sk, signer) = signer_key();
        let mut gw = crate::Gw::boot();
        let (key, owner) = gw.register_account(Some(signer));
        gw.account_deposit(&key, 0, 20_000 * QUOTE_SCALE).unwrap();
        // seal window 0 (contains the deposit) so the NEXT window's pre-state carries
        // the cumulative count
        let bc0 = gw.seq.state.next_batch_id;
        let _ = gw
            .begin_window_settle(bc0)
            .unwrap()
            .expect("window 0 sealed");
        // window 1: only a withdrawal — no Deposit op enters this window
        signed_withdraw(&mut gw, &sk, &key, &owner, 5_000 * QUOTE_SCALE, 1);
        let bc1 = gw.seq.state.next_batch_id;
        let (witness, ww) = gw
            .begin_window_settle(bc1)
            .unwrap()
            .expect("window 1 sealed");
        // fixture preconditions — do NOT weaken (see sample_window)
        assert!(
            witness.pre_state.consumed_deposit_count > 0,
            "fixture precondition: the pre-state must have consumed deposits"
        );
        assert!(
            witness
                .ops
                .iter()
                .all(|o| !matches!(o, BatchOp::Deposit { .. })),
            "fixture precondition: the window must contain no Deposit ops"
        );
        (witness, ww)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Task 2: parsing the remote /prove response ────────────────────────────

    /// SEC-025-B break 3: `prover-service`'s ProveResp has EIGHT fields and does not
    /// emit `deposits_root` (crates/prover-service/src/main.rs:71-80), while the parser
    /// required it — so every HTTP prove failed at JSON decode before any proof was
    /// examined. The requirement was recorded as a comment instructing the service to
    /// emit it, and never implemented.
    #[test]
    fn parses_a_response_without_deposits_root() {
        let json = r#"{
            "prev_root":"0x1111111111111111111111111111111111111111111111111111111111111111",
            "manifest_hash":"0x2222222222222222222222222222222222222222222222222222222222222222",
            "new_root":"0x3333333333333333333333333333333333333333333333333333333333333333",
            "ordered_root":"0x4444444444444444444444444444444444444444444444444444444444444444",
            "withdrawals_root":"0x5555555555555555555555555555555555555555555555555555555555555555",
            "rejected_root":"0x6666666666666666666666666666666666666666666666666666666666666666",
            "commitment":"0x7777777777777777777777777777777777777777777777777777777777777777",
            "proof":"0xabcd"
        }"#;
        let r = parse_prove_resp(json).expect("today's prover-service shape must parse");
        assert_eq!(r.commitment[0], 0x77);
        assert_eq!(r.proof, vec![0xab, 0xcd]);
        assert_eq!(r.roots.deposits_root, None, "absent field stays absent");
        assert_eq!(
            r.roots.new_root.expect("present roots still parse")[0],
            0x33
        );
    }

    /// Forward-compatible: if the service later emits the 7th word, it parses too.
    #[test]
    fn parses_a_response_with_deposits_root() {
        let json = r#"{
            "prev_root":"0x1111111111111111111111111111111111111111111111111111111111111111",
            "manifest_hash":"0x2222222222222222222222222222222222222222222222222222222222222222",
            "new_root":"0x3333333333333333333333333333333333333333333333333333333333333333",
            "ordered_root":"0x4444444444444444444444444444444444444444444444444444444444444444",
            "withdrawals_root":"0x5555555555555555555555555555555555555555555555555555555555555555",
            "rejected_root":"0x6666666666666666666666666666666666666666666666666666666666666666",
            "deposits_root":"0x8888888888888888888888888888888888888888888888888888888888888888",
            "commitment":"0x7777777777777777777777777777777777777777777777777777777777777777",
            "proof":"0xabcd"
        }"#;
        let r = parse_prove_resp(json).expect("forward-compatible");
        assert_eq!(r.roots.deposits_root.expect("present")[0], 0x88);
    }

    /// A malformed root that IS present must still be rejected — leniency is about
    /// absence, not about accepting garbage.
    #[test]
    fn rejects_a_present_but_malformed_root() {
        let json = r#"{
            "prev_root":"not-hex",
            "manifest_hash":"0x2222222222222222222222222222222222222222222222222222222222222222",
            "new_root":"0x3333333333333333333333333333333333333333333333333333333333333333",
            "ordered_root":"0x4444444444444444444444444444444444444444444444444444444444444444",
            "withdrawals_root":"0x5555555555555555555555555555555555555555555555555555555555555555",
            "rejected_root":"0x6666666666666666666666666666666666666666666666666666666666666666",
            "commitment":"0x7777777777777777777777777777777777777777777777777777777777777777",
            "proof":"0xabcd"
        }"#;
        assert!(
            parse_prove_resp(json).is_err(),
            "garbage must not parse as absent"
        );
    }

    /// The commitment and proof are what Task 3 actually consumes — absent or
    /// malformed, they are a hard parse failure.
    #[test]
    fn rejects_a_response_missing_the_commitment() {
        let json = r#"{"proof":"0xabcd"}"#;
        assert!(parse_prove_resp(json).is_err());
    }

    // ── Task 3: local derivation is the source of truth ───────────────────────

    /// SEC-025-B §1: the gateway derives all seven roots from its OWN replay and requires
    /// the prover's commitment to equal its own. Because the commitment is a keccak over
    /// all seven words, that single comparison covers every root — replacing a check that
    /// only re-hashed the prover's own roots and so proved nothing but self-consistency.
    #[test]
    fn local_derivation_matches_the_mock_prover_on_all_seven_roots() {
        let (witness, ww) = crate::prover_client::tests_support::sample_window();
        let prepared = prove_and_prepare(&MockProverClient, &witness, &ww)
            .expect("mock agrees with local derivation");
        let mut state = witness.pre_state.clone();
        let d = perp_core::commitment::derive_roots(&mut state, &witness.ops, &witness.manifest)
            .expect("replay");
        let o = &prepared.outcome;
        assert_eq!(o.prev_root, d.prev_state_root);
        assert_eq!(o.manifest_hash, d.manifest_hash);
        assert_eq!(o.new_root, d.new_state_root);
        assert_eq!(o.ordered_root, d.ordered_root);
        assert_eq!(o.withdrawals_root, d.withdrawals_root);
        assert_eq!(o.rejected_root, d.rejected_root);
        assert_eq!(o.deposits_root, d.deposits_root);
    }

    /// The cumulative count, not the per-window one. This is the value
    /// `_requireDepositPrefix` pins BEFORE proof verification, so getting it wrong
    /// selects the wrong L1 prefix.
    #[test]
    fn new_deposit_count_is_cumulative_not_per_window() {
        let (witness, ww) = crate::prover_client::tests_support::sample_window();
        let pre_count = witness.pre_state.consumed_deposit_count;
        let n_deposits = witness
            .ops
            .iter()
            .filter(|o| matches!(o, perp_core::engine::BatchOp::Deposit { .. }))
            .count() as u64;
        let prepared = prove_and_prepare(&MockProverClient, &witness, &ww).expect("prove");
        assert_eq!(
            prepared.outcome.new_deposit_count,
            pre_count + n_deposits,
            "post == pre + deposits in window (NOT the per-window count)"
        );
    }

    /// A window with no deposits over a non-zero pre-state must still submit the
    /// pre-state count — the case a per-window reading gets wrong as 0.
    #[test]
    fn zero_deposit_window_submits_the_prestate_count() {
        let (witness, ww) = crate::prover_client::tests_support::sample_window_no_deposits();
        assert!(
            witness.pre_state.consumed_deposit_count > 0,
            "fixture precondition: the pre-state must have consumed deposits, or this \
             test cannot distinguish cumulative from per-window"
        );
        let prepared = prove_and_prepare(&MockProverClient, &witness, &ww).expect("prove");
        assert_eq!(
            prepared.outcome.new_deposit_count,
            witness.pre_state.consumed_deposit_count
        );
    }

    /// A prover whose commitment disagrees with local derivation must be refused
    /// OUTRIGHT — nothing prepared, nothing returned for broadcast.
    #[test]
    fn a_disagreeing_prover_is_refused() {
        struct LyingProver;
        impl ProverClient for LyingProver {
            fn prove(&self, _w: &WindowWitness) -> Result<RemoteProveResp, ProverClientError> {
                Ok(RemoteProveResp {
                    roots: RemoteRoots::default(),
                    commitment: [0xEE; 32],
                    proof: vec![0x01],
                })
            }
        }
        let (witness, ww) = crate::prover_client::tests_support::sample_window();
        let err = prove_and_prepare(&LyingProver, &witness, &ww)
            .expect_err("a commitment that disagrees with local derivation must be refused");
        assert!(
            err.contains("commitment"),
            "error should name the commitment mismatch, got: {err}"
        );
    }

    /// The diagnostic path: when the response DID carry roots, the error names which
    /// one differs rather than only reporting a commitment mismatch.
    #[test]
    fn a_disagreeing_prover_names_the_differing_root() {
        let (witness, ww) = crate::prover_client::tests_support::sample_window();
        let mut state = witness.pre_state.clone();
        let d = perp_core::commitment::derive_roots(&mut state, &witness.ops, &witness.manifest)
            .expect("replay");
        struct WrongNewRoot(perp_core::commitment::DerivedRoots);
        impl ProverClient for WrongNewRoot {
            fn prove(&self, _w: &WindowWitness) -> Result<RemoteProveResp, ProverClientError> {
                Ok(RemoteProveResp {
                    roots: RemoteRoots {
                        prev_root: Some(self.0.prev_state_root),
                        new_root: Some([0xEE; 32]), // the one that differs
                        ..RemoteRoots::default()
                    },
                    commitment: [0xEE; 32],
                    proof: vec![0x01],
                })
            }
        }
        let err = prove_and_prepare(&WrongNewRoot(d), &witness, &ww).expect_err("must refuse");
        assert!(
            err.contains("new_root"),
            "error should name new_root, got: {err}"
        );
    }
}

#[cfg(test)]
mod seal_nonce_tests {
    use super::seal_nonce;

    fn raw_keccak(bytes: &[u8]) -> [u8; 32] {
        use sha3::{Digest as _, Keccak256 as RawKeccak};
        RawKeccak::digest(bytes).into()
    }

    #[test]
    fn nonce_is_not_the_public_plaintext_hash() {
        // The whole point: the clear nonce must NOT equal keccak256(plaintext),
        // or an interceptor could confirm a guessed witness by matching it.
        let root = [0x5Eu8; 32];
        let pt = b"positions/fills/margins for one window";
        assert_ne!(seal_nonce(&root, pt), raw_keccak(pt));
    }

    #[test]
    fn nonce_is_deterministic_for_same_root_and_plaintext() {
        // Rollback/retry safety: an identical re-seal must reproduce the nonce.
        let root = [0x5Eu8; 32];
        let pt = b"same witness bytes";
        assert_eq!(seal_nonce(&root, pt), seal_nonce(&root, pt));
    }

    #[test]
    fn nonce_varies_with_plaintext_and_with_root() {
        let root = [0x5Eu8; 32];
        let other_root = [0x11u8; 32];
        let pt1 = b"witness A";
        let pt2 = b"witness B";
        assert_ne!(
            seal_nonce(&root, pt1),
            seal_nonce(&root, pt2),
            "different plaintext"
        );
        assert_ne!(
            seal_nonce(&root, pt1),
            seal_nonce(&other_root, pt1),
            "different root"
        );
    }
}

#[cfg(test)]
mod prove_curl_tests {
    use super::{prove_curl_args, split_status, ProverClientError};

    #[test]
    fn args_carry_the_transport_hardening_flags_in_pairs() {
        let a = prove_curl_args("http://127.0.0.1:8091/prove", 1800, None);
        // helper: the value immediately following a flag token
        let val = |flag: &str| a.iter().position(|s| s == flag).map(|i| a[i + 1].clone());
        assert_eq!(
            val("--connect-timeout").as_deref(),
            Some("20"),
            "fail fast on a dead prover / down tunnel"
        );
        assert_eq!(
            val("--keepalive-time").as_deref(),
            Some("30"),
            "hold the idle connection open through the long proof"
        );
        assert_eq!(
            val("--max-time").as_deref(),
            Some("1800"),
            "overall wall-clock cap from the env timeout"
        );
        // endpoint is last; body streams on stdin (POST + @-)
        assert_eq!(a.last().unwrap(), "http://127.0.0.1:8091/prove");
        assert!(a.iter().any(|s| s == "--data-binary"));
        assert!(a.iter().any(|s| s == "POST"));
    }

    // ── SEC-020 Task 5: the /prove Authorization bearer + status capture ───────

    /// A flag/value pair is present adjacently in the argv.
    fn has_pair(a: &[String], flag: &str, value: &str) -> bool {
        a.windows(2).any(|w| w[0] == flag && w[1] == value)
    }

    #[test]
    fn bearer_is_attached_when_present() {
        let a = prove_curl_args("http://x/prove", 900, Some("s3cret-token"));
        assert!(
            has_pair(&a, "-H", "Authorization: Bearer s3cret-token"),
            "a present session token must ride the /prove request as a bearer"
        );
        assert_eq!(a.last().unwrap(), "http://x/prove", "endpoint stays last");
    }

    #[test]
    fn no_bearer_header_when_token_absent() {
        // Fail-closed: with no token the gateway must NOT fabricate an Authorization
        // header — the prover then 401s (never an empty bearer that could slip past).
        let a = prove_curl_args("http://x/prove", 900, None);
        assert!(
            !a.iter().any(|s| s.starts_with("Authorization:")),
            "no session token ⇒ no Authorization header"
        );
    }

    #[test]
    fn status_is_captured_via_write_out() {
        // The `-w` template must emit the http_code so a 401 is distinguishable.
        let a = prove_curl_args("http://x/prove", 900, None);
        assert!(
            a.iter().any(|s| s.contains("http_code")),
            "curl -w must capture the HTTP status for gate 401 detection"
        );
        // and we must NOT use --fail (it would collapse 401 into a bare exit code).
        assert!(!a.iter().any(|s| s == "--fail"));
    }

    #[test]
    fn split_status_separates_body_and_code() {
        let raw = format!("{{\"proof\":\"0x00\"}}\n{}200", super::STATUS_SENTINEL);
        let (body, code) = split_status(&raw).unwrap();
        assert_eq!(body, "{\"proof\":\"0x00\"}");
        assert_eq!(code, 200);
        // 401 rides through cleanly for the gate-retry path
        let raw401 = format!(
            "attestation session required\n{}401",
            super::STATUS_SENTINEL
        );
        assert_eq!(split_status(&raw401).unwrap().1, 401);
        // a missing marker is a curl/flag regression, surfaced as an error
        assert!(matches!(
            split_status("no marker here"),
            Err(ProverClientError::Http(_))
        ));
    }
}

#[cfg(test)]
mod reauth_tests {
    use super::*;
    use std::cell::RefCell;

    // SEC-025-B: the reauth seam now carries the RAW remote response (the
    // authoritative ProveOutcome is built only after the local replay).
    fn dummy_outcome() -> RemoteProveResp {
        RemoteProveResp {
            roots: RemoteRoots::default(),
            commitment: [0u8; 32],
            proof: vec![],
        }
    }

    /// A 401 triggers ONE re-handshake, then the retry succeeds. The refreshed
    /// triple is persisted and the fresh token is used on the retry.
    #[test]
    fn re_handshakes_once_and_retries_on_401() {
        let calls = RefCell::new(Vec::<Option<String>>::new());
        let stored = RefCell::new(None::<(String, [u8; 32], u64)>);
        let rehandshake: ReHandshake =
            Box::new(|| Ok(("fresh-token".to_string(), [0xAAu8; 32], 5_000)));
        let out = prove_with_reauth(
            Some("stale-token".to_string()),
            Some(&rehandshake),
            |bearer| {
                calls.borrow_mut().push(bearer.map(str::to_string));
                if calls.borrow().len() == 1 {
                    Err(ProverClientError::Unauthorized) // first attempt: stale ⇒ 401
                } else {
                    Ok(dummy_outcome()) // retry with the fresh token: OK
                }
            },
            |t, s, na| *stored.borrow_mut() = Some((t, s, na)),
        );
        assert!(out.is_ok());
        assert_eq!(
            *calls.borrow(),
            vec![
                Some("stale-token".to_string()),
                Some("fresh-token".to_string())
            ],
            "posts with the stale token, then retries with the refreshed one"
        );
        assert_eq!(
            *stored.borrow(),
            Some(("fresh-token".to_string(), [0xAAu8; 32], 5_000)),
            "the WHOLE triple (token, secret, not_after) is persisted"
        );
    }

    /// A second 401 after the re-handshake is terminal — proving stays closed.
    #[test]
    fn second_401_is_terminal() {
        let n = RefCell::new(0);
        let rehandshake: ReHandshake =
            Box::new(|| Ok(("fresh-token".to_string(), [0xAAu8; 32], 5_000)));
        let out = prove_with_reauth(
            Some("stale".to_string()),
            Some(&rehandshake),
            |_| {
                *n.borrow_mut() += 1;
                Err(ProverClientError::Unauthorized)
            },
            |_, _, _| {},
        );
        assert!(matches!(out, Err(ProverClientError::Unauthorized)));
        assert_eq!(
            *n.borrow(),
            2,
            "one original attempt + one retry, then give up"
        );
    }

    /// With no re-handshake wired, a 401 is terminal after a single attempt (no retry).
    #[test]
    fn no_rehandshake_means_401_is_terminal() {
        let n = RefCell::new(0);
        let out = prove_with_reauth(
            None,
            None,
            |_| {
                *n.borrow_mut() += 1;
                Err(ProverClientError::Unauthorized)
            },
            |_, _, _| panic!("must not store a session without a re-handshake"),
        );
        assert!(matches!(out, Err(ProverClientError::Unauthorized)));
        assert_eq!(*n.borrow(), 1, "no re-handshake ⇒ no retry");
    }

    /// SEC-020 C4 (Phase-2): the 401 re-handshake must refresh the STORED session
    /// secret + not_after, not only the token. A rebooted prover derives a NEW
    /// session secret; if only the token were refreshed the gateway would keep
    /// sealing under the STALE secret — the bearer gate would pass while every
    /// seal failed to open (`SealAuthFailed`), wedging proving until a gateway
    /// restart.
    #[test]
    fn rehandshake_refreshes_the_stored_secret_not_only_the_token() {
        let stale_secret = [0x11u8; 32];
        let fresh_secret = [0x22u8; 32];

        // The client-side session state, shaped exactly as `HttpProverClient`
        // holds it: one lock over (token, secret, not_after).
        let session = std::sync::Mutex::new(SessionState {
            token: Some("stale-token".to_string()),
            secret: Some(stale_secret),
            not_after: 1_000,
        });

        // The re-handshake against the REBOOTED prover yields a whole fresh triple.
        let rehandshake: ReHandshake =
            Box::new(move || Ok(("fresh-token".to_string(), fresh_secret, 2_000)));

        let attempts = RefCell::new(0u32);
        // Snapshot the token OUTSIDE the call (as `prove` does) so no guard is
        // alive while the closures re-lock the session.
        let boot_token = session.lock().unwrap().token.clone();
        let out = prove_with_reauth(
            boot_token,
            Some(&rehandshake),
            |bearer| {
                *attempts.borrow_mut() += 1;
                if *attempts.borrow() == 1 {
                    // Stale session: the rebooted prover's /prove gate 401s.
                    Err(ProverClientError::Unauthorized)
                } else {
                    // The RETRY must observe the refreshed secret — this is what
                    // the re-seal reads, so a stale value here IS the C4 wedge.
                    assert_eq!(
                        session.lock().unwrap().secret,
                        Some(fresh_secret),
                        "retry must seal under the refreshed secret"
                    );
                    assert_eq!(bearer, Some("fresh-token"));
                    Ok(dummy_outcome())
                }
            },
            |t, s, na| {
                let mut g = session.lock().unwrap();
                g.token = Some(t);
                g.secret = Some(s);
                g.not_after = na;
            },
        );
        assert!(out.is_ok());
        let g = session.lock().unwrap();
        assert_eq!(g.token.as_deref(), Some("fresh-token"));
        assert_eq!(
            g.secret,
            Some(fresh_secret),
            "stored secret must be the FRESH one"
        );
        assert_ne!(
            g.secret,
            Some(stale_secret),
            "the stale secret must be gone"
        );
        assert_eq!(
            g.not_after, 2_000,
            "the prover-owned expiry rides the refresh"
        );

        // Seal-key contract (mirrors the prover crate's Task-6 round-trip): a seal
        // keyed by the STORED (post-refresh) secret byte-matches what the rebooted
        // prover (fresh secret) derives, while the stale secret's seal does not —
        // i.e. the stale-keyed seal would fail encrypt-then-MAC auth over there.
        let m = [0xABu8; 32];
        let nonce = [0x03u8; 32];
        let seal = |secret: [u8; 32]| {
            postcard::to_allocvec(
                &prover::SealedWitness::seal(
                    b"window witness",
                    &prover::AttestedSealProvider {
                        session_secret: secret,
                        measurement: m,
                    },
                    m,
                    nonce,
                )
                .expect("seal"),
            )
            .expect("encode")
        };
        let stored = g.secret.expect("refreshed secret present");
        assert_eq!(
            seal(stored),
            seal(fresh_secret),
            "a post-refresh seal opens on the rebooted prover"
        );
        assert_ne!(
            seal(stored),
            seal(stale_secret),
            "a stale-keyed seal would fail auth on the rebooted prover"
        );
    }

    /// A successful first attempt never triggers a re-handshake.
    #[test]
    fn success_does_not_rehandshake() {
        let rehandshake: ReHandshake = Box::new(|| panic!("must not re-handshake on success"));
        let out = prove_with_reauth(
            Some("good".to_string()),
            Some(&rehandshake),
            |_| Ok(dummy_outcome()),
            |_, _, _| panic!("must not store on success"),
        );
        assert!(out.is_ok());
    }
}

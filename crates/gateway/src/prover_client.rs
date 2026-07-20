//! Slice 3b-2a: the gateway's client for turning a sealed window into the six on-chain
//! roots + a proof. `MockProverClient` derives the roots in-process (no network, no
//! confidentiality boundary) and uses the commitment as the proof — accepted by the
//! on-chain MockZkVerifier (proof == commitment). Slice 3b-2b adds `HttpProverClient`
//! (seal → POST /prove → real Groth16 proof); this module's trait is that seam.

use crate::withdrawals::Withdrawal;
use perp_core::commitment::{derive_roots, DerivedRoots};
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
    /// SEC-019: the post-batch deposit hash-chain tip — the 7th commitment word. Carried
    /// from the prover's derived roots (Mock) or its `/prove` response (Http) so the
    /// gateway's independent commitment re-derivation in `prove_and_prepare` includes it
    /// (a 6-word re-derivation would mismatch every settle).
    pub deposits_root: Digest,
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

/// SEC-020 Task 5: re-runs the mutual-attestation handshake with the prover and
/// returns a fresh session token (or an error). Boxed so the attestation
/// machinery stays in `main.rs` while `HttpProverClient` can refresh its token on
/// a 401. `Send + Sync` so the client stays `Send + Sync` behind an `Arc`.
pub type ReHandshake = Box<dyn Fn() -> Result<String, String> + Send + Sync>;

/// Turns a sealed window into its six roots + a proof.
pub trait ProverClient: Send + Sync {
    fn prove(&self, witness: &WindowWitness) -> Result<ProveOutcome, ProverClientError>;
}

/// In-process client: derive the roots locally and use the commitment as the proof.
pub struct MockProverClient;

impl ProverClient for MockProverClient {
    fn prove(&self, w: &WindowWitness) -> Result<ProveOutcome, ProverClientError> {
        let mut state = w.pre_state.clone();
        let d = derive_roots(&mut state, &w.ops, &w.manifest).map_err(ProverClientError::Derive)?;
        let commitment = d.commitment::<Keccak256>();
        Ok(ProveOutcome {
            prev_root: d.prev_state_root,
            manifest_hash: d.manifest_hash,
            new_root: d.new_state_root,
            ordered_root: d.ordered_root,
            withdrawals_root: d.withdrawals_root,
            rejected_root: d.rejected_root,
            deposits_root: d.deposits_root,
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
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct PreparedSettle {
    pub outcome: ProveOutcome,
    pub withdraw_proofs: BTreeMap<[u8; 32], (Digest, Vec<[u8; 32]>)>,
}

/// Prove a sealed window and prepare its claim proofs. Builds the window's withdrawal
/// tree from `ww` (op-application order) and asserts its root byte-matches the prover's
/// derived `withdrawals_root` — the two are the same `merkle_root` over the same
/// `withdrawal_leaf`s, so any divergence is a hard error, never silently published.
pub fn prove_and_prepare(
    client: &dyn ProverClient,
    witness: &WindowWitness,
    ww: &[Withdrawal],
) -> Result<PreparedSettle, String> {
    let outcome = client.prove(witness).map_err(|e| format!("prove: {e:?}"))?;

    // The prover's claimed commitment must be THE commitment of the seven roots it returned
    // — that binding is what the on-chain verifier checks the proof against, so a client
    // that returns mismatched roots/commitment is broken and must never reach settleBatch.
    // (Trivially true for MockProverClient; a real trust-boundary check for 3b-2b's
    // HttpProverClient.)
    let expect = DerivedRoots {
        prev_state_root: outcome.prev_root,
        manifest_hash: outcome.manifest_hash,
        new_state_root: outcome.new_root,
        ordered_root: outcome.ordered_root,
        withdrawals_root: outcome.withdrawals_root,
        rejected_root: outcome.rejected_root,
        deposits_root: outcome.deposits_root,
    }
    .commitment::<Keccak256>();
    if expect != outcome.commitment {
        return Err(format!(
            "commitment mismatch: prover claims {} but its roots commit to {}",
            crate::hex32(&outcome.commitment),
            crate::hex32(&expect)
        ));
    }

    let leaves: Vec<[u8; 32]> = ww.iter().map(|w| w.leaf()).collect();
    let wroot = merkle_root(&leaves);
    if wroot != outcome.withdrawals_root {
        return Err(format!(
            "withdrawals root mismatch: gateway tree {} vs prover {}",
            crate::hex32(&wroot),
            crate::hex32(&outcome.withdrawals_root)
        ));
    }
    let mut withdraw_proofs = BTreeMap::new();
    for (i, w) in ww.iter().enumerate() {
        withdraw_proofs.insert(w.leaf(), (outcome.withdrawals_root, merkle_proof(&leaves, i)));
    }
    Ok(PreparedSettle { outcome, withdraw_proofs })
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

/// Parse the prover-service /prove JSON into a ProveOutcome. The six roots + commitment
/// are 32-byte hex (parse_hex32); the proof is variable-length hex (decode_hex). The
/// returned outcome is validated downstream by prove_and_prepare (commitment cross-check
/// + withdrawal-tree byte-match), so a tampered response is rejected before settleBatch.
pub fn parse_prove_resp(json: &str) -> Result<ProveOutcome, ProverClientError> {
    #[derive(serde::Deserialize)]
    struct Resp {
        prev_root: String,
        manifest_hash: String,
        new_root: String,
        ordered_root: String,
        withdrawals_root: String,
        rejected_root: String,
        // SEC-019: the prover-service must emit the 7th commitment word so the gateway's
        // commitment cross-check in `prove_and_prepare` re-derives the same 7-word digest.
        deposits_root: String,
        commitment: String,
        proof: String,
    }
    let r: Resp =
        serde_json::from_str(json).map_err(|e| ProverClientError::Decode(format!("json: {e}")))?;
    let root = |s: &str, name: &str| -> Result<Digest, ProverClientError> {
        crate::parse_hex32(s).ok_or_else(|| ProverClientError::Decode(format!("bad {name}: {s}")))
    };
    Ok(ProveOutcome {
        prev_root: root(&r.prev_root, "prev_root")?,
        manifest_hash: root(&r.manifest_hash, "manifest_hash")?,
        new_root: root(&r.new_root, "new_root")?,
        ordered_root: root(&r.ordered_root, "ordered_root")?,
        withdrawals_root: root(&r.withdrawals_root, "withdrawals_root")?,
        rejected_root: root(&r.rejected_root, "rejected_root")?,
        deposits_root: root(&r.deposits_root, "deposits_root")?,
        commitment: root(&r.commitment, "commitment")?,
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
        "-s".into(), "-S".into(),
        "--connect-timeout".into(), "20".into(),
        "--keepalive-time".into(), "30".into(),
        "--max-time".into(), timeout_secs.to_string(),
        "-X".into(), "POST".into(),
        "-H".into(), "Content-Type: application/json".into(),
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

/// The real transport: seal the window and POST it to the attested prover-service.
pub struct HttpProverClient {
    url: String,
    seal_root: [u8; 32],
    measurement: Digest,
    timeout_secs: u64,
    /// SEC-020 Task 5: the attestation session token from the boot mutual-attestation
    /// handshake, sent as `Authorization: Bearer <token>` on every `/prove`. `None` ⇒
    /// the handshake refused (Phase-1 prod) ⇒ no bearer is sent and the prover's gate
    /// 401s (fail-closed). `Mutex` for interior mutability so a 401 re-handshake can
    /// refresh the token in place (the trait's `prove` is `&self`). The lock is only
    /// ever held to read/replace the token, never across the long-blocking POST.
    session_token: std::sync::Mutex<Option<String>>,
    /// SEC-020 Task 6: the raw mutual-attestation `session_secret` the attested seal
    /// key rests on (see `AttestedSealProvider`). `Some` ⇒ seal with the attested
    /// provider (Phase-2-active); `None` ⇒ the DEV_INSECURE fallback seals with
    /// `SoftwareSealProvider` keyed on `seal_root`. Never logged/served. Held plainly
    /// (not behind the token `Mutex`): it is fixed for the process lifetime — the
    /// Phase-1 401 re-handshake refreshes only the token, and the attested seal path
    /// is not live until Phase-2 (a Phase-2 rotation must also refresh this secret).
    session_secret: Option<[u8; 32]>,
    /// SEC-020 Task 5: re-runs the mutual-attestation handshake on a 401 (a rotated /
    /// rebooted prover) and yields a fresh token. `None` ⇒ no re-handshake wired
    /// (mock/dev construction) — a 401 is then terminal (still fail-closed).
    rehandshake: Option<ReHandshake>,
}

impl HttpProverClient {
    /// Build from PROVER_URL, matching the prover-service's seal params: PROVER_SEAL_ROOT
    /// (64-hex) resolved FAIL-CLOSED by `prover::resolve_seal_root` (SEC-020: no public
    /// default; unset refuses to boot the settle path, `DEV_INSECURE=1` only outside
    /// production) and the 0xAB.. stand-in measurement; PROVER_TIMEOUT_SECS (default 900
    /// — a real Groth16 proof under qemu takes minutes).
    ///
    /// The client is built token-less; `with_session_token` / `with_rehandshake` inject
    /// the SEC-020 handshake state (main.rs wires them after the boot handshake).
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
            session_token: std::sync::Mutex::new(None),
            session_secret: None,
            rehandshake: None,
        })
    }

    /// SEC-020 Task 5: set the boot-minted session token (`None` ⇒ handshake refused ⇒
    /// fail-closed: no bearer is sent and every `/prove` 401s).
    pub fn with_session_token(mut self, token: Option<String>) -> Self {
        self.session_token = std::sync::Mutex::new(token);
        self
    }

    /// SEC-020 Task 6: set the boot-derived `session_secret` (`None` ⇒ no attested
    /// session ⇒ the DEV_INSECURE `SoftwareSealProvider` seal path). Mirrors the
    /// prover-service's attested-vs-dev provider selection so seal/open round-trips.
    pub fn with_session_secret(mut self, secret: Option<[u8; 32]>) -> Self {
        self.session_secret = secret;
        self
    }

    /// SEC-020 Task 5: wire the re-handshake used to refresh the token on a 401.
    pub fn with_rehandshake(mut self, rehandshake: ReHandshake) -> Self {
        self.rehandshake = Some(rehandshake);
        self
    }
}

/// SEC-020 Task 5: run `post` with the current bearer; on a 401 (a stale session —
/// e.g. the prover rebooted with a new epoch) call `rehandshake` ONCE to mint a fresh
/// token, persist it via `store`, and retry the POST. A second 401, a missing
/// re-handshake, or a re-handshake error is terminal — proving stays closed
/// (fail-closed). Factored out (no I/O of its own) so the retry control flow is
/// unit-testable without a live prover.
fn prove_with_reauth(
    token: Option<String>,
    rehandshake: Option<&ReHandshake>,
    mut post: impl FnMut(Option<&str>) -> Result<ProveOutcome, ProverClientError>,
    store: impl FnOnce(String),
) -> Result<ProveOutcome, ProverClientError> {
    match post(token.as_deref()) {
        Err(ProverClientError::Unauthorized) => {
            let Some(rehandshake) = rehandshake else {
                return Err(ProverClientError::Unauthorized);
            };
            let fresh = rehandshake().map_err(|e| {
                ProverClientError::Http(format!("re-handshake after 401 failed: {e}"))
            })?;
            store(fresh.clone());
            post(Some(&fresh))
        }
        other => other,
    }
}

impl ProverClient for HttpProverClient {
    fn prove(&self, w: &WindowWitness) -> Result<ProveOutcome, ProverClientError> {
        let sealed_hex = seal_witness(
            w,
            &self.seal_root,
            &self.measurement,
            self.session_secret.as_ref(),
        )?;
        let body = serde_json::json!({ "sealed": sealed_hex }).to_string();
        // Snapshot the token (lock released immediately — never held across the
        // multi-minute POST). `None` ⇒ no bearer sent ⇒ the prover 401s (fail-closed).
        let token = self.session_token.lock().unwrap().clone();
        prove_with_reauth(
            token,
            self.rehandshake.as_ref(),
            |bearer| {
                let resp = http_post(&self.url, &body, self.timeout_secs, bearer)?;
                parse_prove_resp(&resp)
            },
            |fresh| *self.session_token.lock().unwrap() = Some(fresh),
        )
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
        assert_ne!(seal_nonce(&root, pt1), seal_nonce(&root, pt2), "different plaintext");
        assert_ne!(seal_nonce(&root, pt1), seal_nonce(&other_root, pt1), "different root");
    }
}

#[cfg(test)]
mod prove_curl_tests {
    use super::{prove_curl_args, split_status, ProverClientError};

    #[test]
    fn args_carry_the_transport_hardening_flags_in_pairs() {
        let a = prove_curl_args("http://127.0.0.1:8091/prove", 1800, None);
        // helper: the value immediately following a flag token
        let val = |flag: &str| {
            a.iter().position(|s| s == flag).map(|i| a[i + 1].clone())
        };
        assert_eq!(val("--connect-timeout").as_deref(), Some("20"), "fail fast on a dead prover / down tunnel");
        assert_eq!(val("--keepalive-time").as_deref(), Some("30"), "hold the idle connection open through the long proof");
        assert_eq!(val("--max-time").as_deref(), Some("1800"), "overall wall-clock cap from the env timeout");
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
        let raw401 = format!("attestation session required\n{}401", super::STATUS_SENTINEL);
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

    fn dummy_outcome() -> ProveOutcome {
        ProveOutcome {
            prev_root: [0u8; 32],
            manifest_hash: [0u8; 32],
            new_root: [0u8; 32],
            ordered_root: [0u8; 32],
            withdrawals_root: [0u8; 32],
            rejected_root: [0u8; 32],
            deposits_root: [0u8; 32],
            commitment: [0u8; 32],
            proof: vec![],
        }
    }

    /// A 401 triggers ONE re-handshake, then the retry succeeds. The refreshed token
    /// is persisted and used on the retry.
    #[test]
    fn re_handshakes_once_and_retries_on_401() {
        let calls = RefCell::new(Vec::<Option<String>>::new());
        let stored = RefCell::new(None::<String>);
        let rehandshake: ReHandshake = Box::new(|| Ok("fresh-token".to_string()));
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
            |t| *stored.borrow_mut() = Some(t),
        );
        assert!(out.is_ok());
        assert_eq!(
            *calls.borrow(),
            vec![Some("stale-token".to_string()), Some("fresh-token".to_string())],
            "posts with the stale token, then retries with the refreshed one"
        );
        assert_eq!(stored.borrow().as_deref(), Some("fresh-token"));
    }

    /// A second 401 after the re-handshake is terminal — proving stays closed.
    #[test]
    fn second_401_is_terminal() {
        let n = RefCell::new(0);
        let rehandshake: ReHandshake = Box::new(|| Ok("fresh-token".to_string()));
        let out = prove_with_reauth(
            Some("stale".to_string()),
            Some(&rehandshake),
            |_| {
                *n.borrow_mut() += 1;
                Err(ProverClientError::Unauthorized)
            },
            |_| {},
        );
        assert!(matches!(out, Err(ProverClientError::Unauthorized)));
        assert_eq!(*n.borrow(), 2, "one original attempt + one retry, then give up");
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
            |_| panic!("must not store a token without a re-handshake"),
        );
        assert!(matches!(out, Err(ProverClientError::Unauthorized)));
        assert_eq!(*n.borrow(), 1, "no re-handshake ⇒ no retry");
    }

    /// A successful first attempt never triggers a re-handshake.
    #[test]
    fn success_does_not_rehandshake() {
        let rehandshake: ReHandshake = Box::new(|| panic!("must not re-handshake on success"));
        let out = prove_with_reauth(
            Some("good".to_string()),
            Some(&rehandshake),
            |_| Ok(dummy_outcome()),
            |_| panic!("must not store on success"),
        );
        assert!(out.is_ok());
    }
}

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
#[derive(Clone, Debug)]
pub struct ProveOutcome {
    pub prev_root: Digest,
    pub manifest_hash: Digest,
    pub new_root: Digest,
    pub ordered_root: Digest,
    pub withdrawals_root: Digest,
    pub rejected_root: Digest,
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
}

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
            commitment,
            proof: commitment.to_vec(),
        })
    }
}

/// The proven outcome plus the per-note claim proofs the gateway serves.
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

    // The prover's claimed commitment must be THE commitment of the six roots it returned
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
/// (same SoftwareSealProvider params) can open it. Plaintext is the postcard-encoded
/// `(pre_state, ops, manifest)` triple; the nonce is the secret-keyed
/// `seal_nonce(root, plaintext)` (content-derived and reuse-proof across rollback
/// re-seals, but keyed with `root` so the clear nonce can't confirm a guessed witness).
/// Returns 0x-prefixed hex of the postcard-encoded SealedWitness.
pub fn seal_witness(
    w: &WindowWitness,
    root: &[u8; 32],
    measurement: &Digest,
) -> Result<String, ProverClientError> {
    let bytes = postcard::to_allocvec(&(&w.pre_state, &w.ops, &w.manifest))
        .map_err(|e| ProverClientError::Decode(format!("witness encode: {e}")))?;
    // Secret-keyed, content-derived nonce (see `seal_nonce`): keyed with `root` so the
    // clear nonce is not a plaintext-confirmation oracle, while identical re-seals still
    // reproduce it (rollback/retry-safe, no two-time pad).
    let nonce = seal_nonce(root, &bytes);
    let provider = prover::SoftwareSealProvider::new(*root, *measurement);
    let sealed = prover::SealedWitness::seal(&bytes, &provider, *measurement, nonce)
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
        commitment: root(&r.commitment, "commitment")?,
        proof: crate::decode_hex(&r.proof)
            .ok_or_else(|| ProverClientError::Decode(format!("bad proof: {}", r.proof)))?,
    })
}

/// POST `body` as application/json to `<url>/prove` via curl (mirrors L1::cast: a
/// subprocess with a wall-clock cap), piping the body on stdin so a large sealed witness
/// never hits an argv limit. The stdin write runs on its own thread to avoid a pipe
/// deadlock when the body exceeds the OS pipe buffer.
fn http_post(url: &str, body: &str, timeout_secs: u64) -> Result<String, ProverClientError> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let endpoint = format!("{}/prove", url.trim_end_matches('/'));
    let mut child = Command::new("curl")
        .args([
            "-s", "-S", "--fail", "--max-time", &timeout_secs.to_string(),
            "-X", "POST", "-H", "Content-Type: application/json",
            "--data-binary", "@-", &endpoint,
        ])
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
    if !out.status.success() {
        return Err(ProverClientError::Http(format!(
            "curl exit {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// The real transport: seal the window and POST it to the attested prover-service.
pub struct HttpProverClient {
    url: String,
    seal_root: [u8; 32],
    measurement: Digest,
    timeout_secs: u64,
}

impl HttpProverClient {
    /// Build from PROVER_URL, matching the prover-service's seal params: PROVER_SEAL_ROOT
    /// (64-hex, default 0x5E..) and the 0xAB.. stand-in measurement; PROVER_TIMEOUT_SECS
    /// (default 900 — a real Groth16 proof under qemu takes minutes).
    pub fn from_env(url: &str) -> Self {
        let seal_root = std::env::var("PROVER_SEAL_ROOT")
            .ok()
            .and_then(|s| crate::parse_hex32(&s))
            .unwrap_or([0x5Eu8; 32]);
        let timeout_secs = std::env::var("PROVER_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(900);
        Self { url: url.to_string(), seal_root, measurement: [0xABu8; 32], timeout_secs }
    }
}

impl ProverClient for HttpProverClient {
    fn prove(&self, w: &WindowWitness) -> Result<ProveOutcome, ProverClientError> {
        let sealed_hex = seal_witness(w, &self.seal_root, &self.measurement)?;
        let body = serde_json::json!({ "sealed": sealed_hex }).to_string();
        let resp = http_post(&self.url, &body, self.timeout_secs)?;
        parse_prove_resp(&resp)
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

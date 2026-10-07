# SEC-020 Phase-2 (local-soundness slice) Implementation Plan


**Goal:** Close SEC-020 Phase-2 findings C1–C5 + constant-time compare with a DH-bound session secret, app-level Azure measurement + vTPM freshness, a `not_after` token TTL, and a re-handshake that refreshes the secret — all TDD-able reboot-free; defer only the live GB10/Azure confirmation to the maintenance window.

**Architecture:** Six tasks. Task 1 lays the pure crypto (DH secret, `not_after` token, constant-time eq) in `crates/attestation`. Task 2 makes `AzureTdxAttestor` verify a full evidence bundle at the **app level** (C1) with **vTPM-extraData freshness** (C2), against the real captured fixture. Task 3 wires the ephemeral-DH handshake across both binaries (C3) with a mock-`Attestor` orchestration test. Tasks 4/5 consume it: the prover `/prove` gate gains `not_after` + constant-time compare (C5), the gateway re-handshake refreshes the secret (C4). Task 6 syncs the deferred-items list into the runbook + ledger.

**Tech Stack:** Rust workspace. `crates/attestation` = package `dark-perp-attestation` (host-buildable, tested in CI). `crates/gateway` (host-buildable). `crates/prover-service` is a **workspace-excluded** standalone crate (`Cargo.toml:25` — pulls SP1/gnark) — it does NOT build in host CI; its logic is covered by scratch/typecheck exactly as SEC-020 Phase-1. `x25519-dalek` v2 (already a workspace dep in `crates/sealed-box`), `perp-core::hash` (Keccak256 + `Domain::KeyDerivation` + `word_u64`), `serde_json` + `hex` (already attestation deps).

## Global Constraints

- **No new workspace dependency.** DH uses `x25519-dalek` v2 (`default-features = false, features = ["static_secrets"]`, mirroring `crates/sealed-box/Cargo.toml:7`); the constant-time compare is hand-rolled (prover-service is a standalone workspace without `subtle`); bundle serialization is `serde_json` with **hex-encoded** binary fields (no base64).
- **Fail-closed everywhere.** Every new `AttestError`/`Result` arm is an error the caller must refuse on — no "verified but degraded" success. Any missing bundle file, malformed field, wrong measurement, wrong challenge, or expired token → error/false, never a partial or defaulted success.
- **`unsafe_code = "forbid"` intact**; `cargo fmt --check` + `clippy` clean.
- **Clean cutover** of the handshake crypto: the OLD nonce-based `session_secret(gw_nonce, pv_nonce, gw_meas, pv_meas)` and `session_token(secret, epoch)` are REPLACED, not kept alongside. Phase-1 mints no real token (prod → `None`; `DEV_INSECURE` → the fixed labeled constant), so no live token breaks.
- **Secrets never logged or served.** `session_secret`, the ephemeral x25519 private key, and the DH shared secret stay in process memory; no `Debug` that prints them, never in a response body or log line.
- **Live-deferred items are documented, not dropped** — Task 6 records each in the runbook §0a + ledger so the window smoke covers them.
- All commands run from `<repo>`.
- Branch: create `feat/sec020-phase2-local` off `main`; commit there, never switch branches.

**Pinned facts (verified against `main` 2026-07-23 — do not re-derive):**
- The real Azure fixture at `crates/attestation/tests/fixtures/azure/` carries the FULL vTPM bundle: `quote.bin`, `collateral.json`, `hcl_report.bin`, `ak_quote_msg.bin`, `ak_quote_sig.bin`, `pcrs.txt`. `tests/vtpm_offline.rs` already drives `verify_azure_vtpm` + `azure_app_measurement` against them, so the C1/C2 verify path is fully testable locally against real bytes.
- `vtpm::verify_azure_vtpm(td, hcl_report, ak_quote_msg, ak_quote_sig, pcr_values: &[[u8;32]]) -> Result<AzureVtpmReport, VtpmError>` (vtpm.rs:193). `AzureVtpmReport.nonce: Vec<u8>` is the AK-extraData freshness value (vtpm.rs:35). `vtpm::azure_app_measurement(td, &vtpm) -> Result<[u8;32], AttestationError>` folds MRTD‖`pcr_digest` (vtpm.rs:261).
- `AZURE_NOW = 1_783_775_325` (midpoint of the fixture collateral window).
- `Domain::KeyDerivation = 13` (perp-core/src/hash.rs:77); `perp_core::hash::word_u64(u64) -> Digest` (:203); `Keccak256::hash_words(Domain, &[[u8;32]]) -> [u8;32]`.
- x25519 pattern (mirror `crates/sealed-box/src/lib.rs:29-30,70-72`): `let sk = StaticSecret::from(bytes); let pk = PublicKey::from(&sk).to_bytes(); let shared = sk.diffie_hellman(&PublicKey::from(peer_bytes)).to_bytes();`
- Current handshake call sites: gateway `prover_handshake` (main.rs:518) + `get_attest` (main.rs:573); prover-service `boot_handshake` (main.rs:229) + `attest` (main.rs:299) + `session_authorized` (main.rs:~90) + `prove` (main.rs:~112). Gateway `HttpProverClient` (prover_client.rs:367): `session_token: Mutex<Option<String>>` (:378), `session_secret: Option<[u8;32]>` (:386, immutable), `ReHandshake = Box<dyn Fn() -> Result<String, String> + Send + Sync>` (:60), `prove_with_reauth` (:452). Gateway re-handshake closure at main.rs:5171.

---

### Task 1: attestation crate — DH-bound secret, `not_after` token, constant-time eq

**Files:**
- Modify: `crates/attestation/Cargo.toml` (add `x25519-dalek`)
- Modify: `crates/attestation/src/handshake.rs` (replace `session_secret`/`session_token`; add DH + `ct_eq`)

**Interfaces:**
- Consumes: `perp_core::hash::{Domain, Hasher, Keccak256, word_u64}`; `x25519_dalek::{StaticSecret, PublicKey}`.
- Produces (later tasks depend on these EXACT signatures):
  - `pub fn ephemeral_keypair(ikm: &[u8; 32]) -> (StaticSecret, [u8; 32])`
  - `pub fn dh_shared(my_secret: &StaticSecret, peer_pub: &[u8; 32]) -> [u8; 32]`
  - `pub fn session_secret(shared: &[u8;32], gw_meas: &Digest, pv_meas: &Digest, gw_ephpub: &[u8;32], pv_ephpub: &[u8;32]) -> Digest`
  - `pub fn session_token(secret: &Digest, not_after_ms: u64) -> String`
  - `pub fn ct_eq(a: &[u8], b: &[u8]) -> bool`
  - `pub const DEV_INSECURE_SESSION_TOKEN` (unchanged)

- [ ] **Step 1: Add the dependency.** In `crates/attestation/Cargo.toml`, under `[dependencies]` after the `hex` line, add:

```toml
# SEC-020 Phase-2 (C3): ephemeral x25519 for the DH-bound session secret — the
# SAME crate/features as crates/sealed-box, so the workspace resolves one copy.
x25519-dalek = { version = "2", default-features = false, features = ["static_secrets"] }
```

- [ ] **Step 2: Write the failing tests.** Replace the entire `#[cfg(test)] mod tests` block at the bottom of `crates/attestation/src/handshake.rs` with:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    // Distinct IKM per party — the ephemeral keys the handshake would draw fresh.
    const GW_IKM: [u8; 32] = [0x11; 32];
    const PV_IKM: [u8; 32] = [0x22; 32];

    #[test]
    fn dh_agrees_from_both_directions() {
        let (gw_sk, gw_pk) = ephemeral_keypair(&GW_IKM);
        let (pv_sk, pv_pk) = ephemeral_keypair(&PV_IKM);
        // Each side computes ECDH with its own secret + the peer's public.
        let shared_gw = dh_shared(&gw_sk, &pv_pk);
        let shared_pv = dh_shared(&pv_sk, &gw_pk);
        assert_eq!(shared_gw, shared_pv, "x25519 ECDH is symmetric");
        assert_ne!(shared_gw, [0u8; 32], "a real shared point, not zero");
    }

    #[test]
    fn secret_is_deterministic_transcript_and_shared_bound() {
        let (gw_sk, gw_pk) = ephemeral_keypair(&GW_IKM);
        let (pv_sk, pv_pk) = ephemeral_keypair(&PV_IKM);
        let shared = dh_shared(&gw_sk, &pv_pk);
        let (m1, m2) = ([3u8; 32], [4u8; 32]);
        let s = session_secret(&shared, &m1, &m2, &gw_pk, &pv_pk);
        // Deterministic.
        assert_eq!(s, session_secret(&shared, &m1, &m2, &gw_pk, &pv_pk));
        // Both sides derive the identical secret (pv computes the same shared).
        let shared_pv = dh_shared(&pv_sk, &gw_pk);
        assert_eq!(s, session_secret(&shared_pv, &m1, &m2, &gw_pk, &pv_pk));
        // Order-bound: swapping the gateway/prover halves changes it.
        assert_ne!(s, session_secret(&shared, &m2, &m1, &pv_pk, &gw_pk));
        // Shared-bound: a different shared secret ⇒ a different session secret.
        assert_ne!(s, session_secret(&[9u8; 32], &m1, &m2, &gw_pk, &pv_pk));
    }

    #[test]
    fn public_transcript_alone_cannot_reproduce_the_secret() {
        // The C3 property: an attacker who sees every PUBLIC value (both ephemeral
        // pubkeys + both measurements) but neither ephemeral SECRET cannot derive
        // the session secret, because it folds the DH `shared` — which needs a
        // private key. We model "public transcript" as the attacker's best guess:
        // hashing the public tuple. It must NOT equal the real secret.
        let (gw_sk, gw_pk) = ephemeral_keypair(&GW_IKM);
        let (_pv_sk, pv_pk) = ephemeral_keypair(&PV_IKM);
        let shared = dh_shared(&gw_sk, &pv_pk);
        let (m1, m2) = ([3u8; 32], [4u8; 32]);
        let real = session_secret(&shared, &m1, &m2, &gw_pk, &pv_pk);
        // The attacker lacks `shared`; substituting anything public (e.g. a zero
        // placeholder, or a pubkey) yields a different secret.
        assert_ne!(real, session_secret(&[0u8; 32], &m1, &m2, &gw_pk, &pv_pk));
        assert_ne!(real, session_secret(&gw_pk, &m1, &m2, &gw_pk, &pv_pk));
    }

    #[test]
    fn token_binds_secret_and_not_after() {
        let s = [7u8; 32];
        assert_eq!(session_token(&s, 1_000), session_token(&s, 1_000)); // deterministic
        assert_ne!(session_token(&s, 1_000), session_token(&s, 2_000)); // not_after-bound
        assert_ne!(session_token(&s, 1_000), session_token(&[8u8; 32], 1_000)); // secret-bound
        assert!(session_token(&s, 1_000).starts_with("0x"));
    }

    #[test]
    fn ct_eq_matches_semantic_equality() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab")); // length mismatch
        assert!(ct_eq(b"", b""));
    }
}
```

- [ ] **Step 3: Run to verify they fail.**

Run: `cargo test -p dark-perp-attestation handshake 2>&1 | tail -20`
Expected: compile errors — `ephemeral_keypair`/`dh_shared`/`ct_eq` undefined and `session_secret`/`session_token` have the old arity.

- [ ] **Step 4: Replace the module body.** Replace everything in `crates/attestation/src/handshake.rs` ABOVE the `#[cfg(test)]` block (the module doc, imports, and the two pure fns) with:

```rust
//! SEC-020 mutual-attestation handshake — the pure transcript math.
//!
//! Phase-2 (C3): each side draws a fresh ephemeral x25519 keypair per handshake
//! and binds its public key into its own attested evidence (the `challenge` the
//! `Attestor` verifies). The session secret folds the x25519 ECDH `shared` point
//! together with the two verified measurements and the two ephemeral pubkeys, so
//! it is NOT reconstructible from the public `/attest` transcript alone — an
//! attacker without an ephemeral private key cannot derive it. `session_token`
//! binds a `not_after` expiry (C5). Pure functions — no I/O, no clock, no env —
//! so both binaries derive byte-identical values from the same transcript.

use crate::Digest;
use perp_core::hash::{word_u64, Domain, Hasher, Keccak256};
use x25519_dalek::{PublicKey, StaticSecret};

/// The fixed session token used ONLY under `DEV_INSECURE` (non-prod): a plain,
/// clearly-named constant — deliberately NOT derived from any quote or secret —
/// so a dev session can never be mistaken for (or forged into) an attested one.
/// Production refuses `DEV_INSECURE` outright, so this value never gates a
/// production `/prove`.
pub const DEV_INSECURE_SESSION_TOKEN: &str = "dev-insecure-session-token-NEVER-production";

/// A fresh ephemeral x25519 keypair from caller-supplied IKM (OS-CSPRNG bytes at
/// the call site). Deterministic in the IKM so the handshake math is unit-testable;
/// `StaticSecret::from` clamps to a valid scalar (mirrors `sealed-box`). Returns
/// the secret + the 32-byte public key (the value bound as the attestation challenge).
pub fn ephemeral_keypair(ikm: &[u8; 32]) -> (StaticSecret, [u8; 32]) {
    let secret = StaticSecret::from(*ikm);
    let public = PublicKey::from(&secret).to_bytes();
    (secret, public)
}

/// The x25519 ECDH shared point between our ephemeral secret and the peer's
/// ephemeral public key. Symmetric: both sides compute the identical value.
pub fn dh_shared(my_secret: &StaticSecret, peer_pub: &[u8; 32]) -> [u8; 32] {
    my_secret.diffie_hellman(&PublicKey::from(*peer_pub)).to_bytes()
}

/// Deterministic session secret from a completed DH mutual-attestation transcript.
///
/// Folds the ECDH `shared` point with both verified measurements and both
/// ephemeral pubkeys. Order-bound: gateway fields first, prover second — both
/// sides MUST call with the same orientation. Reuses `Domain::KeyDerivation` (as
/// `SoftwareSealProvider` does). Because `shared` requires an ephemeral private
/// key, this secret is NOT derivable from the public transcript (C3).
pub fn session_secret(
    shared: &[u8; 32],
    gw_meas: &Digest,
    pv_meas: &Digest,
    gw_ephpub: &[u8; 32],
    pv_ephpub: &[u8; 32],
) -> Digest {
    Keccak256::hash_words(
        Domain::KeyDerivation,
        &[*shared, *gw_meas, *pv_meas, *gw_ephpub, *pv_ephpub],
    )
}

/// Short-lived bearer token the prover checks on `/prove` (hash of the secret + a
/// `not_after` expiry in Unix ms). Rotating/expiring `not_after` invalidates old
/// tokens; the prover's gate rejects a presented token past its `not_after` (C5).
pub fn session_token(secret: &Digest, not_after_ms: u64) -> String {
    let d = Keccak256::hash_words(Domain::KeyDerivation, &[*secret, word_u64(not_after_ms)]);
    format!("0x{}", hex::encode(d))
}

/// Constant-time byte equality for the bearer-token compare (prover `/prove`
/// gate, C5). Length is not secret (the token is fixed-length hex), so a length
/// mismatch short-circuits; equal-length inputs are compared in constant time.
/// Hand-rolled because `prover-service` is a standalone workspace without `subtle`.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
```

- [ ] **Step 5: Export the new symbols.** In `crates/attestation/src/lib.rs`, update the `pub use handshake::{...}` line (currently `session_secret, session_token, DEV_INSECURE_SESSION_TOKEN`) to:

```rust
pub use handshake::{
    ct_eq, dh_shared, ephemeral_keypair, session_secret, session_token,
    DEV_INSECURE_SESSION_TOKEN,
};
```

- [ ] **Step 6: Run to verify pass.**

Run: `cargo test -p dark-perp-attestation handshake && cargo fmt -p dark-perp-attestation --check && cargo clippy -p dark-perp-attestation --all-targets`
Expected: the 5 handshake tests PASS; fmt + clippy clean.

- [ ] **Step 7: Commit.**

```bash
git add crates/attestation/Cargo.toml crates/attestation/src/handshake.rs crates/attestation/src/lib.rs
git commit -m "feat(attestation): SEC-020 C3/C5 — DH-bound session secret + not_after token + constant-time eq"
```

---

### Task 2: attestation crate — bundle-based Azure app-level verify (C1 + C2)

**Files:**
- Modify: `crates/attestation/src/vtpm.rs` (add `pub fn parse_pcrs_txt`)
- Modify: `crates/attestation/src/lib.rs` (`AttestationBundle`; `AzureTdxAttestor::quote`/`verify`; a new `AttestError::VtpmChain` arm)

**Interfaces:**
- Consumes: `vtpm::{verify_azure_vtpm, azure_app_measurement, AzureVtpmReport}`; `verify_tdx_quote`; the real fixture files.
- Produces: `AzureTdxAttestor::quote(challenge) -> Vec<u8>` now returns a serialized `AttestationBundle`; `verify(bundle, expected, challenge) -> Digest` verifies the full chain at the app level with extraData==challenge freshness. `pub fn vtpm::parse_pcrs_txt(&str) -> Result<Vec<[u8;32]>, VtpmError>`. The `Attestor` trait signature is UNCHANGED (`quote(&[u8;32])->Vec<u8>`, `verify(&[u8], &Digest, &[u8;32])->Digest`) — only the byte contents get richer.

- [ ] **Step 1: Write the failing `parse_pcrs_txt` test** in `crates/attestation/src/vtpm.rs` inside its `#[cfg(test)] mod tests`:

```rust
    #[test]
    fn parses_the_fixture_pcrs_txt() {
        let txt = include_str!("../tests/fixtures/azure/pcrs.txt");
        let pcrs = parse_pcrs_txt(txt).expect("fixture pcrs.txt parses");
        assert!(!pcrs.is_empty());
        // Round-trips the real chain: these PCRs satisfy the AK quote's pcrDigest.
        let collateral = crate::Collateral::from_json(include_bytes!(
            "../tests/fixtures/azure/collateral.json"
        ))
        .unwrap();
        let td = crate::verify_tdx_quote(
            include_bytes!("../tests/fixtures/azure/quote.bin"),
            &collateral,
            1_783_775_325,
        )
        .unwrap();
        let report = verify_azure_vtpm(
            &td,
            include_bytes!("../tests/fixtures/azure/hcl_report.bin"),
            include_bytes!("../tests/fixtures/azure/ak_quote_msg.bin"),
            include_bytes!("../tests/fixtures/azure/ak_quote_sig.bin"),
            &pcrs,
        )
        .expect("real vTPM chain verifies with the parsed PCRs");
        assert_eq!(report.pcr_digest.len(), 32);
    }
```

Note: `pcrs.txt` is one hex-encoded 32-byte PCR value per line (the existing `vtpm_offline.rs::pcrs()` decodes each line with `hex::decode_to_slice`). `parse_pcrs_txt` must accept exactly that: for each non-empty trimmed line, decode 64 hex chars → `[u8;32]`; any malformed line → `Err(VtpmError::AttestParse)`.

- [ ] **Step 2: Run to verify it fails.**

Run: `cargo test -p dark-perp-attestation parses_the_fixture_pcrs_txt 2>&1 | tail`
Expected: FAIL — `parse_pcrs_txt` undefined.

- [ ] **Step 3: Implement `parse_pcrs_txt`** in `crates/attestation/src/vtpm.rs` (public, next to `azure_app_measurement`):

```rust
/// Parse a `pcrs.txt` capture — one hex-encoded 32-byte PCR value per non-empty
/// line — into the `pcr_values` slice `verify_azure_vtpm` folds. Strict: a line
/// that is not exactly 64 hex chars is `Err(AttestParse)`, never skipped.
pub fn parse_pcrs_txt(txt: &str) -> Result<Vec<[u8; 32]>, VtpmError> {
    let mut out = Vec::new();
    for line in txt.lines() {
        let h = line.trim();
        if h.is_empty() {
            continue;
        }
        let mut a = [0u8; 32];
        hex::decode_to_slice(h, &mut a).map_err(|_| VtpmError::AttestParse)?;
        out.push(a);
    }
    Ok(out)
}
```

(If `VtpmError` has no `AttestParse` variant, use the closest existing parse-failure arm — check the enum at vtpm.rs and pick the parse variant; do NOT add a new arm unless none fits.)

- [ ] **Step 4: Run to verify pass.**

Run: `cargo test -p dark-perp-attestation parses_the_fixture_pcrs_txt`
Expected: PASS.

- [ ] **Step 5: Write the failing bundle + app-level verify tests** in `crates/attestation/src/lib.rs`'s `#[cfg(test)] mod tests`. Add a helper that assembles a bundle from the fixture files, then the tests:

```rust
    // The five tee-capture files that make an Azure evidence bundle.
    const AZURE_HCL: &[u8] = include_bytes!("../tests/fixtures/azure/hcl_report.bin");
    const AZURE_AK_MSG: &[u8] = include_bytes!("../tests/fixtures/azure/ak_quote_msg.bin");
    const AZURE_AK_SIG: &[u8] = include_bytes!("../tests/fixtures/azure/ak_quote_sig.bin");
    const AZURE_PCRS: &str = include_str!("../tests/fixtures/azure/pcrs.txt");

    /// Serialize the fixture into an AttestationBundle exactly as `quote()` would.
    fn azure_bundle() -> Vec<u8> {
        serde_json::to_vec(&AttestationBundle {
            quote: hex::encode(AZURE_QUOTE),
            hcl_report: hex::encode(AZURE_HCL),
            ak_quote_msg: hex::encode(AZURE_AK_MSG),
            ak_quote_sig: hex::encode(AZURE_AK_SIG),
            pcrs: AZURE_PCRS.to_string(),
        })
        .unwrap()
    }

    /// The app-level measurement + the AK-extraData nonce the fixture carries —
    /// the values a correct verify must key off (NOT the firmware-only fold).
    fn azure_app_expected() -> ([u8; 32], Vec<u8>) {
        let collateral = Collateral::from_json(AZURE_COLLATERAL).unwrap();
        let td = verify_tdx_quote(AZURE_QUOTE, &collateral, AZURE_NOW).unwrap();
        let pcrs = crate::vtpm::parse_pcrs_txt(AZURE_PCRS).unwrap();
        let report =
            crate::vtpm::verify_azure_vtpm(&td, AZURE_HCL, AZURE_AK_MSG, AZURE_AK_SIG, &pcrs)
                .unwrap();
        let m = crate::vtpm::azure_app_measurement(&td, &report).unwrap();
        (m, report.nonce)
    }

    #[test]
    fn azure_verify_accepts_the_bundle_at_app_level_with_matching_challenge() {
        let (expected, extradata) = azure_app_expected();
        // The challenge the peer proves it bound is the AK-extraData value; on a
        // live handshake that is the peer's ephemeral pubkey. Here it is the
        // fixture's captured extraData (32 bytes).
        let mut challenge = [0u8; 32];
        challenge.copy_from_slice(&extradata[..32]);
        let att = AzureTdxAttestor::from_collateral_json(AZURE_COLLATERAL).unwrap();
        let m = att.verify(&azure_bundle(), &expected, &challenge).unwrap();
        assert_eq!(m, expected, "verify returns the APP-level measurement");
    }

    #[test]
    fn azure_verify_rejects_a_firmware_only_expected_measurement() {
        // The C1 regression: the firmware-only enclave_measurement (MRTD‖RTMR0..3)
        // must NOT be what verify accepts — pinning it would let two app binaries
        // on one SKU cross-verify. Passing it as `expected` must MeasurementMismatch.
        let collateral = Collateral::from_json(AZURE_COLLATERAL).unwrap();
        let td = verify_tdx_quote(AZURE_QUOTE, &collateral, AZURE_NOW).unwrap();
        let firmware_only = td.enclave_measurement().unwrap();
        let (app_level, extradata) = azure_app_expected();
        assert_ne!(firmware_only, app_level, "the two measurements differ");
        let mut challenge = [0u8; 32];
        challenge.copy_from_slice(&extradata[..32]);
        let att = AzureTdxAttestor::from_collateral_json(AZURE_COLLATERAL).unwrap();
        assert!(matches!(
            att.verify(&azure_bundle(), &firmware_only, &challenge),
            Err(AttestError::MeasurementMismatch)
        ));
    }

    #[test]
    fn azure_verify_rejects_a_mismatched_challenge() {
        let (expected, _extradata) = azure_app_expected();
        let att = AzureTdxAttestor::from_collateral_json(AZURE_COLLATERAL).unwrap();
        assert!(matches!(
            att.verify(&azure_bundle(), &expected, &[0x55u8; 32]),
            Err(AttestError::NonceMismatch)
        ));
    }

    #[test]
    fn azure_verify_rejects_a_malformed_bundle() {
        let (expected, _e) = azure_app_expected();
        let att = AzureTdxAttestor::from_collateral_json(AZURE_COLLATERAL).unwrap();
        assert!(matches!(
            att.verify(b"not json", &expected, &[0u8; 32]),
            Err(AttestError::Backend(_))
        ));
    }

    #[test]
    fn azure_quote_assembles_the_full_bundle_and_round_trips() {
        let (expected, extradata) = azure_app_expected();
        let mut challenge = [0u8; 32];
        challenge.copy_from_slice(&extradata[..32]);
        let mut att = AzureTdxAttestor::from_collateral_json(AZURE_COLLATERAL).unwrap();
        att.quote_dir = Some(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/azure").into());
        // quote() reads all five files and serializes them; verify() round-trips.
        let bundle = att.quote(&challenge).expect("assembles the bundle");
        assert_eq!(att.verify(&bundle, &expected, &challenge).unwrap(), expected);
    }

    #[test]
    fn azure_quote_without_a_live_source_fails_closed() {
        let mut att = AzureTdxAttestor::from_collateral_json(AZURE_COLLATERAL).unwrap();
        att.quote_dir = None;
        assert!(matches!(att.quote(&[0u8; 32]), Err(AttestError::Backend(_))));
    }
```

Also DELETE the now-obsolete Task-2/Phase-1 tests that assumed a bare `quote.bin` and the firmware-level nonce path: `azure_verify_accepts_fixture_with_pinned_measurement`, `azure_verify_rejects_wrong_measurement`, `azure_verify_rejects_wrong_nonce`, `azure_verify_rejects_a_tampered_quote`, `azure_quote_reads_the_captured_artifacts_and_round_trips` (replaced by the bundle round-trip above). Keep `pinned_now_*` tests. Preserve tamper coverage by adding one bundle-level tamper test:

```rust
    #[test]
    fn azure_verify_rejects_a_tampered_quote_in_the_bundle() {
        let (expected, extradata) = azure_app_expected();
        let mut challenge = [0u8; 32];
        challenge.copy_from_slice(&extradata[..32]);
        let mut b: AttestationBundle = serde_json::from_slice(&azure_bundle()).unwrap();
        let mut q = hex::decode(&b.quote).unwrap();
        q[184] ^= 0x01; // flip a byte inside the signed TD report
        b.quote = hex::encode(q);
        let att = AzureTdxAttestor::from_collateral_json(AZURE_COLLATERAL).unwrap();
        assert!(matches!(
            att.verify(&serde_json::to_vec(&b).unwrap(), &expected, &challenge),
            Err(AttestError::Tdx(AttestationError::Verify(_)))
        ));
    }
```

- [ ] **Step 6: Run to verify they fail.**

Run: `cargo test -p dark-perp-attestation --lib 2>&1 | tail -20`
Expected: compile errors — `AttestationBundle` undefined; `verify` still uses the old single-quote path.

- [ ] **Step 7: Implement `AttestationBundle` + the new quote/verify.** In `crates/attestation/src/lib.rs`:

(a) Add the bundle type (near `AzureTdxAttestor`, with `serde`):

```rust
/// The serialized tee-capture evidence one side sends the other: the TD quote
/// plus the full vTPM chain (HCL report, AK quote msg+sig, PCR list). Binary
/// fields are hex; `pcrs` is the raw `pcrs.txt` text. `quote()` assembles it from
/// `ATTESTATION_DIR`; `verify()` parses + checks the whole chain fail-closed.
#[derive(serde::Serialize, serde::Deserialize)]
struct AttestationBundle {
    quote: String,
    hcl_report: String,
    ak_quote_msg: String,
    ak_quote_sig: String,
    pcrs: String,
}
```

(If `serde` is not yet a dep of `attestation`, it is transitively via `dcap-qvl`/`serde_json`; add `serde = { version = "1", features = ["derive"] }` to `[dependencies]` if the derive is unavailable — check and add only if needed.)

(b) Add a `Backend`-style helper and replace `AzureTdxAttestor::quote`:

```rust
    // `_challenge` (the local ephemeral pubkey) is bound into the AK-extraData by
    // a LIVE `tee-capture` on a real CVM; here we read the STATIC captured bundle,
    // whose extraData is fixed, so the arg is a documented no-op locally. (This is
    // why a real-binary handshake is window-deferred, not asserted in local tests.)
    fn quote(&self, _challenge: &[u8; 32]) -> Result<Vec<u8>, AttestError> {
        let dir = self.quote_dir.as_ref().ok_or_else(|| {
            AttestError::Backend("no live quote source: ATTESTATION_DIR is not set".into())
        })?;
        let rd = |name: &str| -> Result<Vec<u8>, AttestError> {
            std::fs::read(dir.join(name))
                .map_err(|e| AttestError::Backend(format!("read {}/{name}: {e}", dir.display())))
        };
        let bundle = AttestationBundle {
            quote: hex::encode(rd("quote.bin")?),
            hcl_report: hex::encode(rd("hcl_report.bin")?),
            ak_quote_msg: hex::encode(rd("ak_quote_msg.bin")?),
            ak_quote_sig: hex::encode(rd("ak_quote_sig.bin")?),
            pcrs: String::from_utf8(rd("pcrs.txt")?)
                .map_err(|e| AttestError::Backend(format!("pcrs.txt not utf8: {e}")))?,
        };
        serde_json::to_vec(&bundle)
            .map_err(|e| AttestError::Backend(format!("serialize bundle: {e}")))
    }
```

(c) Replace `AzureTdxAttestor::verify` with the app-level, vTPM-chain, freshness-gated path:

```rust
    fn verify(
        &self,
        bundle: &[u8],
        expected: &Digest,
        challenge: &[u8; 32],
    ) -> Result<Digest, AttestError> {
        let b: AttestationBundle = serde_json::from_slice(bundle)
            .map_err(|e| AttestError::Backend(format!("bundle parse: {e}")))?;
        let dec = |h: &str, what: &str| -> Result<Vec<u8>, AttestError> {
            hex::decode(h).map_err(|e| AttestError::Backend(format!("bundle {what}: {e}")))
        };
        let quote = dec(&b.quote, "quote")?;
        let hcl = dec(&b.hcl_report, "hcl_report")?;
        let ak_msg = dec(&b.ak_quote_msg, "ak_quote_msg")?;
        let ak_sig = dec(&b.ak_quote_sig, "ak_quote_sig")?;
        let pcrs = crate::vtpm::parse_pcrs_txt(&b.pcrs)
            .map_err(|e| AttestError::Backend(format!("bundle pcrs: {e:?}")))?;

        // 1. TD quote crypto + TCB gate.
        let td =
            verify_tdx_quote(&quote, &self.collateral, self.now_secs).map_err(AttestError::Tdx)?;
        // 2. Full vTPM chain (HCL binding, AK sig, pcrDigest).
        let report = crate::vtpm::verify_azure_vtpm(&td, &hcl, &ak_msg, &ak_sig, &pcrs)
            .map_err(|e| AttestError::VtpmChain(format!("{e:?}")))?;
        // 3. C1: APP-level measurement (MRTD‖pcr_digest), not the firmware fold.
        let m = crate::vtpm::azure_app_measurement(&td, &report).map_err(AttestError::Tdx)?;
        if &m != expected {
            return Err(AttestError::MeasurementMismatch);
        }
        // 4. C2/C3: the AK-extraData freshness value must equal the caller's
        //    challenge (the peer's ephemeral pubkey on a live handshake).
        if report.nonce.len() != 32 || report.nonce[..] != challenge[..] {
            return Err(AttestError::NonceMismatch);
        }
        Ok(m)
    }
```

(d) Add the `VtpmChain` arm to `AttestError` (fail-closed, carries the chain error string):

```rust
    /// The Azure vTPM chain (HCL binding / AK signature / PCR digest) failed.
    VtpmChain(String),
```

Remove the now-unused `nonce_from_report_data` ONLY if nothing else references it (grep first; the Phase-1 tests that used it are being deleted). If the gateway/prover reference it, leave it.

- [ ] **Step 8: Run to verify pass + lints.**

Run: `cargo test -p dark-perp-attestation && cargo fmt -p dark-perp-attestation --check && cargo clippy -p dark-perp-attestation --all-targets`
Expected: all attestation tests PASS (new bundle tests + the retained `pinned_now_*` + vtpm tests); fmt + clippy clean.

- [ ] **Step 9: Commit.**

```bash
git add crates/attestation/src/lib.rs crates/attestation/src/vtpm.rs crates/attestation/Cargo.toml
git commit -m "feat(attestation): SEC-020 C1/C2 — bundle-based Azure verify at app level with vTPM-extraData freshness"
```

---

### Task 3: handshake orchestration — ephemeral-DH wiring across both binaries (C3)

**Files:**
- Modify: `crates/gateway/src/main.rs` (`prover_handshake`, `get_attest`)
- Modify: `crates/prover-service/src/main.rs` (`boot_handshake`, `attest`)
- Add: an orchestration test in `crates/attestation` (host-buildable) driving both handshake halves with a mock `Attestor`.

**Interfaces:**
- Consumes: Task 1 (`ephemeral_keypair`, `dh_shared`, `session_secret`, `session_token`), Task 2 (bundle-based `Attestor::verify`/`quote`).
- Produces: `/attest` responses now carry `{ bundle, eph_pub, not_after }` (no `nonce`/`epoch`); `prover_handshake`/`boot_handshake` return `(token, secret, not_after)` — Tasks 4/5 consume `not_after` + the refreshed secret.

- [ ] **Step 1: Write the orchestration test** (host-buildable, in `crates/attestation`, e.g. a new `tests/handshake_orchestration.rs`). It proves the DH handshake converges and fails closed, using a mock `Attestor` — no gateway/prover binary, no hardware:

```rust
// A mock Attestor: quote() echoes the challenge into a synthetic "bundle";
// verify() returns the pinned measurement iff the bundle's bound challenge ==
// the expected challenge. This exercises the SAME orchestration both binaries
// run (generate eph key → verify peer → dh_shared → session_secret → token)
// without any TEE evidence.
use dark_perp_attestation::{dh_shared, ephemeral_keypair, session_secret, session_token};

// ... a small MockAttestor whose quote(challenge)=serialize(measurement,challenge)
// and verify(bundle,expected,challenge) checks both fields ...

#[test]
fn both_sides_derive_the_identical_secret_and_token() {
    // gateway + prover each draw an ephemeral key; each "attests" binding its
    // own eph_pub; each verifies the peer's bundle over the peer's eph_pub;
    // both compute session_secret(shared, gw_meas, pv_meas, gw_pub, pv_pub).
    // Assert gw_secret == pv_secret and gw_token == pv_token for a shared not_after.
}

#[test]
fn a_tampered_peer_bundle_fails_closed() { /* verify → Err ⇒ no token */ }

#[test]
fn a_wrong_peer_measurement_fails_closed() { /* MeasurementMismatch ⇒ no token */ }

#[test]
fn a_mismatched_eph_pub_fails_closed() { /* NonceMismatch ⇒ no token */ }
```

Write the `MockAttestor` and fill the test bodies concretely (the implementer composes them from the Task-1 fns; the mock is ~20 lines). The point: assert `session_secret`/`session_token` agreement across the two orientations and fail-closed on each tampered input.

- [ ] **Step 2: Run to verify it fails.**

Run: `cargo test -p dark-perp-attestation --test handshake_orchestration 2>&1 | tail`
Expected: FAIL (test file/mocks not yet present, or assertions unmet).

- [ ] **Step 3: Implement the mock + make the orchestration test pass** (pure attestation-crate code; no binary changes yet). This validates the shared math before touching the binaries.

Run: `cargo test -p dark-perp-attestation --test handshake_orchestration`
Expected: PASS.

**Protocol (both sides symmetric).** Each binary generates ONE ephemeral x25519 keypair at boot/settle-init and binds its OWN `eph_pub` in its `/attest` bundle (freshness = the single-use ephemeral key, so no fetcher-supplied nonce is needed — a replayed `(bundle, eph_pub)` is useless without that pub's private key). `/attest` needs no query param. The **prover owns expiry**: it computes `not_after = now + SESSION_TTL_MS` ONCE at boot, stores it, serves it on `/attest`, and mints its accept-token with it; the gateway reads the prover's advertised `not_after` and mints the identical send-token. The gateway's `/attest` carries only `{ bundle, eph_pub }`.

**Local reality (why the real-binary handshake is NOT asserted locally):** `AzureTdxAttestor::quote` reads the STATIC fixture, whose AK-`extraData` is a captured constant — it cannot bind a fresh `eph_pub` without a live `tee-capture`. So a real gateway↔prover handshake `verify` would `NonceMismatch` locally; that end-to-end is window-deferred. Local coverage is the **mock-Attestor orchestration test** (Steps 1–3), whose `quote` DOES echo the challenge. Do NOT add a passing local real-binary handshake test.

- [ ] **Step 4: Wire the gateway** (`crates/gateway/src/main.rs`). Rewrite `prover_handshake` to the DH flow (reads the prover's advertised `eph_pub` + `not_after`; binds nothing as a query):

```rust
fn prover_handshake(prover_url: &str, gw_sk: &StaticSecret, gw_pub: &[u8; 32]) -> Result<(String, [u8; 32], u64), String> {
    let gw_expected = expected_measurement_env("GATEWAY_EXPECTED_MEASUREMENT")?;
    let pv_expected = expected_measurement_env("PROVER_EXPECTED_MEASUREMENT")?;
    let url = format!("{}/attest", prover_url.trim_end_matches('/'));
    let resp = http_get_json(&url)?;
    let bundle = resp.get("bundle").and_then(|v| v.as_str()).and_then(decode_hex)
        .ok_or("no hex `bundle` in the prover /attest response")?;
    let pv_pub = resp.get("eph_pub").and_then(|v| v.as_str()).and_then(parse_hex32)
        .ok_or("no 32-byte `eph_pub` in the prover /attest response")?;
    let not_after = resp.get("not_after").and_then(|v| v.as_u64())
        .ok_or("no `not_after` in the prover /attest response")?;
    // Phase-1 fail-closed pivot stays: NvidiaCcAttestor::verify is CcNotEnabled today.
    // The challenge is the PROVER's own advertised eph_pub (it must have attested to it).
    let pv_meas = NvidiaCcAttestor::detect()
        .verify(&bundle, &pv_expected, &pv_pub)
        .map_err(|e| format!("prover quote verify: {e:?}"))?;
    let shared = attestation::dh_shared(gw_sk, &pv_pub);
    let secret = session_secret(&shared, &gw_expected, &pv_meas, gw_pub, &pv_pub);
    Ok((session_token(&secret, not_after), secret, not_after))
}
```

- `get_attest`: drop the `?nonce=` query (no `AttestQuery`); serve `{ bundle: att.quote(&app.gw_pub), eph_pub: app.gw_pub }` — NO `not_after` (the gateway does not own expiry). `quote()` ignores the challenge locally (static fixture); on a live CVM it binds `gw_pub`.
- Replace the App's `hs_nonce`/`hs_epoch` fields with the per-boot ephemeral keypair: `gw_eph_secret: StaticSecret`, `gw_pub: [u8; 32]` (generated once at boot via `ephemeral_keypair(&csprng_bytes32())`). Update the App struct + boot wiring (main.rs:5358 area) + the `prover_handshake` call to pass `&app.gw_eph_secret, &app.gw_pub`.
- Add `use attestation::{dh_shared, ephemeral_keypair};` (and `x25519_dalek::StaticSecret` for the signature) to the gateway imports.

- [ ] **Step 5: Wire the prover-service** (`crates/prover-service/src/main.rs`) symmetrically:
- Define `const SESSION_TTL_MS: u64 = 15 * 60 * 1000;` (the prover owns expiry).
- At boot: generate the prover ephemeral keypair `(pv_sk, pv_pub)` and compute `session_not_after = now_ms() + SESSION_TTL_MS` ONCE; store `pv_sk`, `pv_pub`, `session_not_after` on `App`.
- `boot_handshake(pv_sk, pv_pub, not_after) -> Result<(String, [u8;32]), String>`: fetch the gateway `/attest` → read `{ bundle, eph_pub: gw_pub }` → `AzureTdxAttestor::verify(&bundle, &gw_expected, &gw_pub)` → `shared = dh_shared(pv_sk, &gw_pub)` → `secret = session_secret(&shared, &gw_meas, &pv_expected, &gw_pub, pv_pub)` (gateway fields first — SAME orientation as the gateway) → `session_token(&secret, not_after)`. Returns `(token, secret)`; the caller already holds `not_after`.
- `attest` serves `{ bundle: NvidiaCcAttestor::quote(&app.pv_pub) (503 today), eph_pub: app.pv_pub, not_after: app.session_not_after }`. Keep the `DEV_INSECURE` placeholder branch (labeled), now returning the `{bundle-placeholder, eph_pub, not_after}` shape.
- **Orientation caution (must match the gateway):** `session_secret` is called with `(shared, gw_meas, pv_meas, gw_pub, pv_pub)` on BOTH sides — gateway first. The gateway passes `(&gw_expected, &pv_meas, gw_pub, &pv_pub)`; the prover passes `(&gw_meas, &pv_expected, &gw_pub, pv_pub)`. `gw_meas`(prover) is verify-enforced == `gw_expected`(gateway); `pv_meas`(gateway) == `pv_expected`(prover); the two pubs are identical bytes. So both fold the identical tuple.

- [ ] **Step 6: Verify the buildable side + typecheck the excluded side.**

Run: `cargo test -p gateway 2>&1 | tail -15 && cargo build -p gateway`
Then (excluded crate — typecheck only, as Phase-1): `cargo check --manifest-path crates/prover-service/Cargo.toml 2>&1 | tail -15`
Expected: gateway builds + its tests pass; prover-service type-checks. If gateway has handshake unit tests referencing the old `nonce`/`epoch` shape, update them to the `{bundle,eph_pub,not_after}` shape.

- [ ] **Step 7: Commit.**

```bash
git add crates/gateway/src/main.rs crates/prover-service/src/main.rs crates/attestation/tests/handshake_orchestration.rs
git commit -m "feat(gateway,prover-service): SEC-020 C3 — ephemeral-DH mutual-attestation handshake (bundle + eph_pub + not_after)"
```

---

### Task 4: prover `/prove` gate — `not_after` TTL + constant-time compare (C5)

**Files:**
- Modify: `crates/prover-service/src/main.rs` (`App`, `session_authorized`, `prove`)

**Interfaces:**
- Consumes: `attestation::ct_eq`; the `not_after` minted in Task 3's `boot_handshake`.
- Produces: `session_authorized(stored_token, stored_not_after, headers, now_ms) -> bool` — Task 5's gateway side is unaffected (this is prover-local).

- [ ] **Step 1: Write the failing gate tests** in `crates/prover-service/src/main.rs`'s test module (these compile in the scratch/typecheck path; if the crate has no runnable host tests, add them as `#[cfg(test)]` and rely on `cargo check` + the reviewer reading them, per Phase-1 precedent). Cover: valid token + unexpired → true; valid token + expired (`now_ms > not_after`) → false; wrong token (same length) → false via `ct_eq`; empty/absent stored → false; missing bearer → false.

```rust
    fn hdr(bearer: &str) -> axum::http::HeaderMap {
        let mut h = axum::http::HeaderMap::new();
        h.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {bearer}").parse().unwrap(),
        );
        h
    }

    #[test]
    fn gate_accepts_valid_unexpired_and_rejects_expired_or_wrong() {
        let tok = "0xabc123";
        // valid + unexpired
        assert!(session_authorized(Some(tok), 1_000, &hdr(tok), 500));
        // expired
        assert!(!session_authorized(Some(tok), 1_000, &hdr(tok), 1_001));
        // wrong token, same length (constant-time path)
        assert!(!session_authorized(Some(tok), 1_000, &hdr("0xabc124"), 500));
        // absent/empty stored
        assert!(!session_authorized(None, 1_000, &hdr(tok), 500));
        assert!(!session_authorized(Some(""), 1_000, &hdr(tok), 500));
    }
```

- [ ] **Step 2: Run to verify it fails.**

Run: `cargo check --manifest-path crates/prover-service/Cargo.toml 2>&1 | tail`
Expected: FAIL — `session_authorized` has the old arity (no `not_after`/`now_ms`).

- [ ] **Step 3: Implement.** Update `session_authorized` to take `stored_not_after: u64` and `now_ms: u64`, use `attestation::ct_eq` for the compare, and add the expiry check:

```rust
fn session_authorized(
    stored: Option<&str>,
    stored_not_after: u64,
    headers: &axum::http::HeaderMap,
    now_ms: u64,
) -> bool {
    let Some(stored) = stored.filter(|t| !t.is_empty()) else {
        return false;
    };
    let Some(bearer) = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
    else {
        return false;
    };
    // C5: constant-time compare (the token is now a real DH-bound secret) AND
    // reject a token past its advertised not_after.
    attestation::ct_eq(bearer.as_bytes(), stored.as_bytes()) && now_ms <= stored_not_after
}
```

- Store `session_not_after: u64` on `App` alongside `session_token` (set from `boot_handshake`'s third return value). In `prove`, read the real clock (`now_ms`) and pass `app.session_not_after` + `now_ms` to `session_authorized`. Remove the `TODO(SEC-020 C3)` comment (now resolved). For `DEV_INSECURE`, set `session_not_after = u64::MAX` (the fixed dev token never expires in dev).

- [ ] **Step 4: Verify.**

Run: `cargo check --manifest-path crates/prover-service/Cargo.toml && cargo test --manifest-path crates/prover-service/Cargo.toml session_authorized 2>&1 | tail`
(If the crate's heavy deps make `cargo test` impractical in the environment, `cargo check` + the reviewer reading the test is the Phase-1-consistent bar — note which you ran.)
Expected: type-checks; the gate test passes (or compiles under check).

- [ ] **Step 5: Commit.**

```bash
git add crates/prover-service/src/main.rs
git commit -m "feat(prover-service): SEC-020 C5 — not_after token expiry + constant-time bearer compare on /prove"
```

---

### Task 5: gateway re-handshake refreshes the secret + not_after (C4)

**Files:**
- Modify: `crates/gateway/src/prover_client.rs` (`ReHandshake`, `HttpProverClient`, `prove_with_reauth`)
- Modify: `crates/gateway/src/main.rs` (the re-handshake closure ~5171)

**Interfaces:**
- Consumes: Task 3's `prover_handshake(url, ikm) -> (token, secret, not_after)`.
- Produces: a re-handshake that refreshes `session_secret` (fixes the Phase-2 seal/open mismatch).

- [ ] **Step 1: Write the failing test** in `crates/gateway/src/prover_client.rs`'s test module: a re-handshake that returns a NEW `(token, secret, not_after)` must update the client's stored secret (not just the token). Assert via a seal round-trip: seal with the pre-refresh secret fails to open after a refresh to a new secret; seal with the refreshed secret opens. (Reuse the existing seal/open helpers the Phase-1 Task-6 round-trip test uses in `crates/prover/src/lib.rs` — construct a small case here or assert the stored `session_secret` changed after `prove_with_reauth` triggers the closure.)

```rust
    #[test]
    fn rehandshake_refreshes_the_stored_secret_not_only_the_token() {
        // A rehandshake closure returning a fresh (token, secret, not_after).
        // After a forced 401 → reauth, the client's session_secret must equal the
        // fresh secret, and session_token the fresh token.
    }
```

- [ ] **Step 2: Run to verify it fails.**

Run: `cargo test -p gateway rehandshake_refreshes 2>&1 | tail`
Expected: FAIL — `ReHandshake` returns only a `String`; `session_secret` is immutable.

- [ ] **Step 3: Implement.**
- Change `ReHandshake` to `Box<dyn Fn() -> Result<(String, [u8;32], u64), String> + Send + Sync>`.
- Make `HttpProverClient.session_secret` a `Mutex<Option<[u8;32]>>` and add `session_not_after: Mutex<u64>` (or fold into an existing session state struct). Update `with_session_secret` + the seal path (`seal_witness` reads the current secret under the lock).
- In `prove_with_reauth`, on `Unauthorized`: call the closure once, store all three (token, secret, not_after), retry. Still bounded to exactly one retry; a second 401 / closure error ⇒ terminal fail-closed.
- In `main.rs` (~5171) update the closure to `prover_handshake(&url_owned, &fresh_ikm).map(|(t, s, na)| (t, s, na))` — generating a FRESH ephemeral IKM per re-handshake (a new DH exchange), NOT reusing a boot nonce. `dev_insecure` short-circuits to `(DEV_INSECURE_SESSION_TOKEN.to_string(), [0u8;32], u64::MAX)` (secret unused on the dev path).
- Remove the Phase-1 `Task 6` in-code comment noting the secret isn't refreshed (now resolved).

- [ ] **Step 4: Verify.**

Run: `cargo test -p gateway && cargo build -p gateway && cargo clippy -p gateway --all-targets`
Expected: the new test + existing gateway tests PASS; build + clippy clean.

- [ ] **Step 5: Commit.**

```bash
git add crates/gateway/src/prover_client.rs crates/gateway/src/main.rs
git commit -m "feat(gateway): SEC-020 C4 — re-handshake refreshes session_secret + not_after, not only the token"
```

---

### Task 6: sync deferred live-smoke items into runbook + ledger

**Files:**
- Modify: `docs/REDEPLOY-CC-RUNBOOK.md` (§0a)
- Modify: `.superpowers/sdd/progress.md`

**Interfaces:** none (docs).

- [ ] **Step 1: Update the runbook.** In `docs/REDEPLOY-CC-RUNBOOK.md` §0a, replace the sentence describing the Phase-2 package as unbuilt with a crisp done/deferred split: DONE (this branch, local-soundness) = C1 app-level verify path, C2 vTPM-freshness verify path, C3 DH-bound token, C4 re-handshake secret refresh, C5 not_after + constant-time compare — all TDD'd against the captured Azure fixture. DEFERRED to the window smoke (still gate CC-enable): (a) the prover's real NVIDIA CC `measurement()` value, (b) a live fresh Azure capture proving `eph_pub` lands in AK-`extraData`, (c) CC-on end-to-end gateway↔prover DH, (d) `tee-capture`/`capture.sh` emitting the full five-file bundle into `ATTESTATION_DIR`. Update the decision table row 1 accordingly.

- [ ] **Step 2: Append the ledger entry** to `.superpowers/sdd/progress.md` recording the branch, the six tasks, and the deferred list verbatim (so the window smoke covers each).

- [ ] **Step 3: Commit.**

```bash
git add docs/REDEPLOY-CC-RUNBOOK.md .superpowers/sdd/progress.md
git commit -m "docs(sec020): record Phase-2 local-soundness done + the window-smoke deferred list"
```

---

### Final gate (after all tasks)

- [ ] Run the full soundness gate:

```bash
cd <repo>
cargo test -p dark-perp-attestation -p gateway -p prover \
  && cargo check --manifest-path crates/prover-service/Cargo.toml \
  && cargo fmt --check \
  && cargo clippy --workspace --all-targets 2>&1 | tail -5
```

Expected: attestation/gateway/prover tests green; prover-service type-checks; fmt + clippy clean. The C3 public-transcript test, the C1 firmware-only-rejection test, and the C5 expiry test are the load-bearing soundness proofs.

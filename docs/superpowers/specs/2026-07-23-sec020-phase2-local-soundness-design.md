# SEC-020 Phase-2 hardening (local-soundness slice) — design

**Date:** 2026-07-23
**Scope:** `crates/attestation`, `crates/gateway`, `crates/prover-service`, `crates/prover`. No Solidity, no frontend.
**Precedent:** mirrors ZK-001/SEC-019 — merge the locally-TDD-able soundness now; defer the hardware-only confirmation to the GB10/Azure maintenance window (`docs/REDEPLOY-CC-RUNBOOK.md` §0a). This slice IS runbook item 0a: the gate that must merge before GB10 CC-enable.

## Context

SEC-020 Phase-1 (merged) built the attested-prover structure: a mutual-attestation handshake mints a session secret + bearer token, `/prove` is gated on that token, and the seal key is measurement-bound. Six Phase-2 findings were tracked as **Phase-1-inert** (prod mints no token/secret; `DEV_INSECURE` is prod-refused on both binaries) but **must all be fixed before GB10 CC-enable**, because enabling CC makes them live:

- **C1** — `AzureTdxAttestor::verify` pins the firmware-only `enclave_measurement()` (MRTD‖RTMR0..3; RTMRs are zero on Azure CVMs) instead of the app-level `azure_app_measurement` (MRTD‖vTPM `pcr_digest`, `vtpm.rs:261`). Two different app binaries on the same Azure SKU mutually verify. The `AttestedSealProvider` measurement check is also vacuous today (`[0xAB]` stub, `prover-service/src/main.rs:32`).
- **C2** — no per-handshake freshness: `/attest` serves only static `quote.bin`; the TD `report_data` is a per-boot static `SHA-256(runtime_data)`, not the caller's fresh challenge. Fresh challenge must ride the vTPM AK quote `extraData` (`AzureVtpmReport.nonce`, `vtpm.rs:36`), and `/attest` must carry the full tee-capture vTPM bundle.
- **C3** (Critical once tokens mint) — the session token is derivable from the PUBLIC `/attest` transcript (nonces + epoch unauthenticated; measurements are pinned public code identities; no DH/ephemeral contribution). Anyone with network reach to both `/attest` recomputes the bearer token. The prover binding `127.0.0.1:8091` is the only current mitigation.
- **C4** — the gateway 401 re-handshake refreshes the token only, discarding the fresh `session_secret` (`prover_client.rs` `session_secret` immutable). Post-reboot: gateway seals with the stale secret, rebooted prover opens with the new → `SealAuthFailed` → proving wedged until gateway restart.
- **C5** — the session token has no active TTL; `session_authorized` does a bare `bearer == stored` (`prover-service/src/main.rs:108`), non-constant-time, token minted once at boot.

**Key mechanism (Azure):** the TD quote's `report_data` is NOT app-settable — it is `SHA-256(HCL runtime_data)`. The caller's fresh challenge rides in the vTPM AK quote's `extraData` (a caller-supplied `qualifyingData`, 32 bytes, already extracted as `AzureVtpmReport.nonce`). This single channel carries both C2's freshness and C3's DH binding: **the challenge IS the caller's ephemeral x25519 public key** (32 bytes, fits `extraData` directly — no separate hash).

## Decisions (user-approved)

1. **Local-soundness slice now; live smoke deferred.** Build and TDD everything reboot-free; defer to the window: the prover's real NVIDIA CC `measurement()` value, live confirmation that a fresh Azure capture carries `eph_pub` in AK-`extraData`, CC-on end-to-end DH, and the `tee-capture`/`capture.sh` bundle-emission ops artifact.
2. **Session lifetime = `not_after` timestamp + single re-handshake** (C5), not a runtime epoch-rotation loop. The token binds a `not_after` (Unix ms); the prover's `/prove` gate checks expiry against an injected clock; on expiry the gateway's existing C4 re-handshake fetches a fresh token + secret + `not_after`. No background thread. Clocks are assumed within ~minutes (same datacenter).
3. **Clean cutover** of the handshake crypto: the public-transcript `session_secret`/`session_token` are replaced by the DH-bound forms. Safe because Phase-1 mints no real token (prod → None; `DEV_INSECURE` → a fixed labeled constant).
4. **No new workspace dependency.** `x25519-dalek` v2 is already a workspace dep (`crates/sealed-box`); the constant-time compare is hand-rolled (prover-service is a standalone workspace without `subtle`).

## Design

### D1 — DH-bound session secret (C3) · `crates/attestation/src/handshake.rs`

- Ephemeral x25519 per handshake, per side. **The fresh ephemeral pubkey is itself the per-handshake freshness channel — it replaces the Phase-1 per-boot `hs_nonce`** (a new keypair each handshake is anti-replay by construction and is what the attestation binds). Add:
  - `pub fn ephemeral_keypair(ikm: &[u8; 32]) -> (StaticSecret, [u8; 32])` — deterministic from caller-supplied IKM (the caller passes OS-CSPRNG bytes; determinism keeps the fn pure/testable). Returns the secret + the 32-byte public key.
  - `pub fn dh_shared(my_secret: &StaticSecret, peer_pub: &[u8; 32]) -> [u8; 32]` — x25519 ECDH, returns the raw shared point.
  - `pub fn session_secret(shared: &[u8;32], gw_meas, pv_meas, gw_ephpub, pv_ephpub) -> Digest` — `Keccak256(Domain::KeyDerivation, [shared, gw_meas, pv_meas, gw_ephpub, pv_ephpub])`. Order-bound (gateway fields first). The OLD 4-arg (nonce-based) `session_secret` is removed; the per-boot `hs_nonce` field is dropped from the handshake entirely.
- `session_token(secret, not_after_ms) -> String` — binds `not_after` in place of the old free `epoch`: `Keccak256(KeyDerivation, [secret, word_u64(not_after_ms)])`, hex `0x…`. `DEV_INSECURE_SESSION_TOKEN` const unchanged.
- **Tests:** determinism; both-directions agree (gateway computes with (gw_eph_secret, pv_eph_pub); prover with (pv_eph_secret, gw_eph_pub); the two `dh_shared` values are equal by x25519, so the two `session_secret`s are equal); secret changes if any input changes; **public-transcript-attacker cannot derive** (given all public values — nonces, measurements, both eph pubs — but neither eph secret, the secret is not reconstructible: encoded as "secret ≠ any Keccak over the public tuple alone", and a direct check that swapping in a different `shared` changes the secret).

### D2 — Evidence bundle + `Attestor` trait (C1/C2 plumbing) · `crates/attestation/src/lib.rs`

- Trait signature (challenge stays `[u8;32]`; return carries a richer bundle, not bare `quote.bin`):
  ```rust
  fn quote(&self, challenge: &[u8; 32]) -> Result<Vec<u8>, AttestError>;   // returns an AttestationBundle (serialized)
  fn verify(&self, bundle: &[u8], expected: &Digest, challenge: &[u8; 32]) -> Result<Digest, AttestError>;
  ```
  `challenge` = the local ephemeral x25519 pubkey on the `quote` side; = the peer's advertised `eph_pub` on the `verify` side.
- `AttestationBundle` = a small serialized envelope of the tee-capture files: `quote.bin`, `hcl_report.bin`, `ak_quote_msg.bin`, `ak_quote_sig.bin`, `pcrs.txt`. Serialization: `serde_json` (already a dep) with each binary file **hex-encoded** (`hex` is already used pervasively — no base64 dependency). `quote()` reads the five files from `ATTESTATION_DIR`; any missing/unreadable file ⇒ `Backend(..)` fail-closed. A malformed bundle on `verify` ⇒ `Backend(..)`, never a partial-success.
- New `AttestError` arms as needed (e.g. `VtpmChain(String)` for a vTPM-chain failure) — every arm fail-closed, no degraded-success (matches the existing enum posture).

### D3 — App-level measurement verify (C1) · `crates/attestation/src/lib.rs` + `vtpm.rs`

- `AzureTdxAttestor::verify` becomes: parse the bundle → `verify_tdx_quote` (TD quote crypto + TCB gate) → `verify_azure_vtpm` (the full 4-step vTPM chain: HCL `report_data == SHA-256(runtime_data)`, AK extraction, AK RSASSA sig over `TPMS_ATTEST`, `pcrDigest == SHA-256(PCRs)`) → compute `azure_app_measurement` (MRTD‖`pcr_digest`) → require `== expected` else `MeasurementMismatch` → **freshness (D4)**. Single Ok path. `enclave_measurement()` (firmware-only) is no longer the verify anchor (kept for any non-Attestor callers, but the Attestor path uses app-level).
- The prover's advertised `measurement()` (`prover-service/src/main.rs:32`, `[0xAB]` stub) is documented as **live-deferred**: locally it stays a clearly-labeled placeholder the window replaces with the real NVIDIA CC measurement; the `AttestedSealProvider` measurement-binding is thus vacuous until the window (already tracked). This slice does NOT fabricate a real prover measurement.

### D4 — vTPM freshness / DH-binding check (C2/C3) · `crates/attestation/src/lib.rs` + `vtpm.rs`

- After the vTPM chain verifies, require `AzureVtpmReport.nonce == challenge` (the peer's `eph_pub`) else `NonceMismatch`. This is where the caller's fresh ephemeral pubkey is proven bound to the attested evidence.
- **Testing decomposition** (we cannot re-sign the real AK for an arbitrary nonce):
  - Full-chain verify against the **real Azure fixture** with ITS static `extraData` (proves the chain + the equality check fire on real bytes).
  - The freshness/binding comparison as a **pure function over a constructed `AzureVtpmReport`** — assert `nonce == challenge` accepts and any mismatch → `NonceMismatch`. Honest separation, mirroring the existing `report_data` binding tests.

### D5 — `not_after` TTL + constant-time compare (C5) · `handshake.rs` + `prover-service/src/main.rs`

- Token binds `not_after_ms` (D1). **The prover owns expiry** (it enforces the `/prove` gate), so the prover computes `not_after = now + SESSION_TTL_MS` (a named const, default 15 min) and advertises it in `/attest`; the gateway echoes the prover's advertised `not_after` into its token, so both derive the identical token (mirrors Phase-1's prover-advertised epoch). This is the ONLY clock read in the token path, on the prover side.
- `pub fn ct_eq(a: &[u8], b: &[u8]) -> bool` in `attestation` — length-check then constant-time XOR-accumulate over the bytes; dependency-free, shared by both binaries.
- `session_authorized(auth_header, stored_token, stored_not_after, now_ms) -> bool` (prover-service): `None`/empty stored → false (unchanged); strip `Bearer `; `ct_eq(bearer, stored)`; **AND** `now_ms <= stored_not_after`. `now_ms` is injected (a param) so expiry is unit-testable; the caller passes the real clock. An expired token → false → 401.

### D6 — Re-handshake refreshes secret (C4) · `crates/gateway/src/prover_client.rs` + `main.rs`

- `ReHandshake` returns `(token, secret, not_after)` (was `token` only). `HttpProverClient` holds `session_token`, `session_secret`, `session_not_after` all in a `Mutex` (secret was immutable). `prove_with_reauth`: on `Unauthorized`, call the re-handshake once, store all three, retry. Still bounded to exactly one retry, fail-closed on a second 401.
- The gateway's re-handshake closure (`main.rs`) REUSES the gateway's boot ephemeral keypair (`gw_eph_secret`/`gw_pub`) and re-fetches the prover's new `eph_pub` from `/attest`, then redoes the DH and returns the fresh `(token, secret, not_after)`. Reuse is mandatory, not optional: `/attest` advertises the boot `gw_pub` for the whole process lifetime (D7 — no mid-run re-advertise), so a rebooted prover derives its secret from `ECDH(pv_sk_new, gw_pub_boot)`; only re-deriving with the same boot key (against the prover's new `pv_pub`) converges both sides on the identical secret + token so the one bounded retry succeeds and proving recovers. `seal_witness` uses the refreshed secret.

### D7 — Handshake orchestration wiring · `crates/gateway/src/main.rs` + `crates/prover-service/src/main.rs`

- `/attest` response carries `{ bundle, eph_pub (32-byte hex), not_after }` — the per-boot `nonce`/`epoch` fields are removed (`eph_pub` is the freshness challenge; `not_after` replaces the free epoch). The challenge each side puts in its own attestation is its `eph_pub`. `prover_handshake`/`boot_handshake`: generate an ephemeral keypair from OS-CSPRNG IKM → fetch peer `/attest` → `verify(peer_bundle, peer_expected_meas, peer_eph_pub)` → `dh_shared(my_secret, peer_eph_pub)` → `session_secret(shared, gw_meas, pv_meas, gw_ephpub, pv_ephpub)` → `session_token(secret, not_after)`. The prover advertises `not_after` in its `/attest`; the gateway echoes it (D5) so both derive the identical token.
- **Orchestration is unit-tested with a mock `Attestor`** (a test impl returning a synthetic bundle that binds a chosen `eph_pub` and a chosen measurement), driving both handshake fns end-to-end: asserts both sides derive the identical secret + token, and that a tampered peer bundle / wrong measurement / mismatched `eph_pub` each fail closed. No hardware, no `CcNotEnabled` dependency.

## Out of scope / live-deferred (window smoke — tracked, not dropped)

- Prover's real NVIDIA CC `measurement()` value and the CC evidence actually binding `eph_pub` (locally `CcNotEnabled`).
- A live fresh Azure capture proving `eph_pub` lands in AK-`extraData` (fixture is static).
- CC-on end-to-end gateway↔prover DH handshake.
- `tee-capture`/`capture.sh` emitting the full five-file bundle into `ATTESTATION_DIR` (ops artifact for the CVM/GB10).
- The Phase-1 minors M1–M13 (deferred; not part of this gate) except where D1–D7 naturally subsume one.

## Success criteria

- `cargo test -p dark-perp-attestation -p gateway -p prover` green (prover-service via its scratch/stub path, as Phase-1); workspace `cargo test` green; `cargo fmt --check` + `clippy` clean; `unsafe_code = "forbid"` intact.
- No public-transcript-derivable token: a test proves the session secret requires an ephemeral private key (public transcript alone cannot reproduce it).
- `AzureTdxAttestor::verify` accepts the real Azure fixture under the **app-level** measurement and rejects a firmware-only / wrong-measurement / wrong-challenge / tampered bundle.
- Expired token → `/prove` 401; bearer compare is constant-time.
- Re-handshake refreshes the secret (a test shows a post-refresh seal/open round-trip succeeds with the new secret, fails with the stale one).
- Every deferred item above appears verbatim in the runbook §0a / SDD ledger so the window smoke covers it.

# SEC-020 Remediation — Attested Prover Boundary (Phase 1) — Design

**Finding:** SEC-020 [high] — the prover is the "bare server" `ARCHITECTURE.md §10b` forbids:
an unauthenticated HTTP `POST /prove` with no attestation, and the witness seal root
**fails OPEN** to a public constant `[0x5E; 32]` in both `prover-service` and the gateway.
The doc-honesty pass already softened the ROADMAP "attested proving ✅" claim; this design
closes the two **active code** holes (unauthenticated `/prove` + fail-open seal root) and
lays the target mutual-attestation architecture so the real hardware key-release drops in
later without an interface change.

## Scope

- **Phase 1 (this design, reboot-free):** fail-CLOSED seal root, an `Attestor` abstraction,
  a startup **mutual-attestation handshake**, an attestation gate on `/prove`, and a
  fail-closed `SealKeyProvider` selection. Runs on the existing infra. The
  `NvidiaCcAttestor` is present but returns `Err(CcNotEnabled)` until GPU CC mode is on, so
  production proving is fail-closed; an explicit, loud, prod-refused `DEV_INSECURE=1` escape
  keeps dev/testnet proving working until Phase 2.
- **Phase 2 (deferred — hardware):** enable NVIDIA GB10 CC mode on the prover host
  (BIOS/firmware + reboot), deploy the prover there, and back `SealKeyProvider` with real
  CC-measurement-bound key release. **Blocked on a host reboot the operator schedules.**
  Feasibility already confirmed: `nv-attestation-sdk` / `nv-local-gpu-verifier` install and
  run on the GB10 (aarch64); the verifier reports `confidential compute = False` and
  requires CC (or PPCIE) mode — the only remaining gate for Phase 2.

**Topology (confirmed):** the prover runs on a separate NVIDIA GB10 (Grace-Blackwell) GPU
box; the gateway/sequencer runs in an Azure TDX CVM; they talk over the reverse tunnel that
carries `/prove`. Two different TEE stacks → **mutual** attestation (each verifies the
other's quote).

## Non-goals

- No circuit/guest change; no receipt-schema change; no change to `derive_roots`.
- No real hardware key-release in Phase 1 (that is Phase 2, `SealKeyProvider` swap only).
- Does not touch the other findings (FIN-001, SEC-019, ZK-001/ORA-001).

## Current state (grounding)

- `crates/prover/src/lib.rs`:
  - `pub trait SealKeyProvider { fn seal_key(&self, measurement: &Digest, nonce: &Digest) -> Option<[u8;32]>; }`
    — already the correct typed boundary; `None` models the TEE refusing key-release.
  - `SoftwareSealProvider { root: [u8;32], measurement: Digest }` derives the key as
    `Keccak256::hash_words(Domain::KeyDerivation, [root, measurement, nonce])`.
  - `SealedWitness` = encrypt-then-MAC; `ProverError::SealAuthFailed` on tamper/wrong key.
- `crates/prover-service/src/main.rs`:
  - `fn seal_root() -> [u8;32]` returns `[0x5E;32]` unless `PROVER_SEAL_ROOT` is a 32-byte
    hex — **the fail-open default**. `fn measurement() -> Digest` returns `[0xAB;32]` stub.
  - `POST /prove` takes `{ sealed: hex }`, opens → derives → proves → zeroizes; **no caller
    auth / attestation**.
- `crates/attestation/src/lib.rs`: `verify_tdx_quote(...) -> VerifiedAttestation`,
  `enclave_measurement()`, `TcbStatus::is_acceptable()`; `vtpm.rs` verifies the Azure vTPM
  measured-boot (AK-signed `TPMS_ATTEST`, PCR digest, HCL binding).
- `crates/gateway/src/main.rs`: `HttpProverClient` (`PROVER_URL` → seal → `POST /prove`);
  seals with the same fail-open root.

## Design

### 1. Fail-closed seal root

Remove the `[0x5E;32]` default in both `prover-service` and the gateway seal-root reads.
Resolution order → a single helper `resolve_seal_root(prod: bool) -> Result<[u8;32], SealRootError>`:

- `PROVER_SEAL_ROOT` set to 32-byte hex → use it.
- else if `DEV_INSECURE=1` (and `!prod`) → a fixed **dev** root (NOT `0x5E`; a clearly-named
  `DEV_INSECURE_SEAL_ROOT` constant), emit a one-line `WARN` "INSECURE dev seal root — never
  production".
- else → `Err(SealRootError::Unset)` and **refuse to start** (both prover and gateway).

`prod` is the existing gateway prod flag; the prover-service gains a `PROD=1` (default true
in a released binary) so the `DEV_INSECURE` escape is refused there too.

### 2. `Attestor` abstraction (in `crates/attestation`)

```rust
pub trait Attestor {
    /// Produce this host's fresh attestation quote over `nonce` (freshness/anti-replay).
    fn quote(&self, nonce: &[u8; 32]) -> Result<Vec<u8>, AttestError>;
    /// Verify a peer `quote` over `nonce`, requiring its measurement == `expected`.
    /// Returns the verified measurement on success.
    fn verify(&self, quote: &[u8], expected: &Digest, nonce: &[u8; 32])
        -> Result<Digest, AttestError>;
}
```

- `AzureTdxAttestor` — wraps `verify_tdx_quote` + `vtpm.rs`; `quote()` reads the CVM's live
  TD+vTPM quote (as the boot self-attest already does at §5c). Gateway self-attests with this.
- `NvidiaCcAttestor` — wraps `nv-attestation-sdk` local GPU verifier; `quote()` collects GPU
  evidence, `verify()` checks a peer GPU report. **Returns `Err(AttestError::CcNotEnabled)`
  whenever the local `is_cc_enabled()` is false** (today's state) — fail-closed. No behavior
  change is needed when CC is later enabled; the same code starts succeeding (Phase 2).

`expected` measurements are pinned via config (`GATEWAY_EXPECTED_MEASUREMENT`,
`PROVER_EXPECTED_MEASUREMENT`) — env hex, required in prod.

### 3. Mutual-attestation handshake (startup)

Before the prover accepts `/prove` and before the gateway sends any sealed witness:

1. Each side generates a fresh 32-byte nonce and calls the peer's `/attest?nonce=...`
   (new lightweight endpoint on each side) → receives the peer's `quote`.
2. Gateway verifies the prover's quote with `NvidiaCcAttestor::verify(quote, PROVER_EXPECTED, n)`;
   prover verifies the gateway's with `AzureTdxAttestor::verify(quote, GATEWAY_EXPECTED, n)`.
3. On success each derives a shared **session secret** from the transcript
   (`Keccak256::hash_words(Domain::KeyDerivation, [both nonces, both measurements])`) and a
   short-lived **session token**; the prover keys `/prove` acceptance on it.
4. Any failure → the proving path stays **closed** (gateway refuses to submit; prover refuses
   `/prove`). In `DEV_INSECURE` the handshake is skipped with a loud `WARN` and a fixed dev
   session token (prod refuses).

The session secret feeds the seal-key binding (§5) so a witness sealed for this session opens
only inside the attested peer.

### 4. `/prove` attestation gate

`/prove` requires a valid session token (from the handshake) in an `Authorization` header;
missing/invalid → `401`. A stale token (handshake expired) → `401` and the gateway
re-handshakes. This makes the endpoint refuse any unauthenticated / unattested caller.

### 5. `SealKeyProvider` — fail-closed selection

- Keep the trait. Add `AttestedSealProvider { session_secret, measurement }`: derives the
  root from `session_secret` + the verified `measurement` (fail `None` on mismatch). This is
  the Phase-1 provider once the handshake succeeds — the confidentiality now rests on the
  handshake-established secret, not a public constant.
- `SoftwareSealProvider` is constructed ONLY under `DEV_INSECURE` with an explicit non-default
  root; never in prod.
- Phase 2 swaps `AttestedSealProvider`'s secret source for real CC key-release (same trait).

## Error handling / behavior matrix

| Condition | Prod | `DEV_INSECURE=1` (non-prod) |
|---|---|---|
| Seal root unset | refuse start (`SealRootError::Unset`) | dev root + WARN |
| CC not enabled on prover | handshake fails → proving closed | handshake skipped + WARN |
| Gateway/prover measurement mismatch | refuse | (dev token) |
| `/prove` without session token | `401` | dev token accepted |

Production never silently degrades: no attestation ⇒ no proof. This is the intended
fail-closed posture; the operator gets a clear startup error, not a silent public-root seal.

## Components & interfaces (files)

- `crates/attestation/src/lib.rs` — add `Attestor` trait, `AzureTdxAttestor`, `AttestError`
  (incl. `CcNotEnabled`); re-export.
- `crates/attestation/src/nvidia_cc.rs` (new) — `NvidiaCcAttestor` over the nv SDK (FFI or a
  thin subprocess to the local verifier); fail-closed when CC off.
- `crates/prover/src/lib.rs` — `AttestedSealProvider`; keep `SoftwareSealProvider` (dev only).
- `crates/prover-service/src/main.rs` — `resolve_seal_root`, `/attest`, session-token gate on
  `/prove`, refuse-start on unset root; `NvidiaCcAttestor` self-quote.
- `crates/gateway/src/main.rs` (+ `prover_client`) — startup handshake, session token on
  `/prove` calls, `AzureTdxAttestor` self-quote + prover-quote verify, fail-closed seal root.

## Testing (TDD, per repo methodology)

1. `resolve_seal_root`: unset + !dev → `Err(Unset)`; `DEV_INSECURE` → dev root (≠ `0x5E`);
   `PROVER_SEAL_ROOT` hex → that root; prod + `DEV_INSECURE` → refused.
2. `NvidiaCcAttestor::quote/verify` returns `Err(CcNotEnabled)` when `is_cc_enabled()` is
   false (today) — asserted with a stub/injected CC-state.
3. Handshake: matching pinned measurements → session token minted; mismatch → refused; the
   derived session secret is deterministic for a transcript.
4. `/prove`: no/invalid token → `401`; valid token → proves (existing happy path preserved).
5. Seal round-trip under `AttestedSealProvider`: seal(gateway secret) → open(prover secret)
   succeeds; wrong measurement/secret → `SealAuthFailed`.
6. `DEV_INSECURE` path is refused when `PROD=1`.

## Deferred to Phase 2 (tracked)

Enable GB10 CC mode (BIOS/firmware + reboot) → deploy prover in CC mode → confirm the local
verifier now returns evidence → swap `AttestedSealProvider`'s secret source for real
CC-measurement-bound key release. No interface change (the `Attestor`/`SealKeyProvider`
boundaries are stable). A separate runbook will capture the reboot/enable ops steps.

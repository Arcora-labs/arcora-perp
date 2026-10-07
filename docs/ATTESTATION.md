# Real TEE attestation (Milestone C, increments #4–#5)

Turning trust root #1 (the TEE) from a stand-in into real, verified attestation:
verify a genuine Intel **TDX DCAP quote**, extract + bind the enclave measurement
(MRTD), and back measurement-bound key release with a real confidential VM.

## Status

| Increment | State |
|---|---|
| **#4 Offline DCAP verification** | ✅ **Built + tested** — [`crates/attestation`](../crates/attestation) |
| #4 → engine wiring (attested measurement → `EnclaveIdentity` + seal release) | ✅ **Built + tested** — [`crates/e2e/tests/attestation_binding.rs`](../crates/e2e/tests/attestation_binding.rs) |
| #4 on-chain (`IDcapAttestation` + `MockDcapAttestation` + `AttestationRegistry`) | ✅ **Built + tested** — [`contracts/`](../contracts) |
| **#5a Real Azure quote captured + verified offline** | ✅ **Done** — a genuine Azure TDX quote verifies through `crates/attestation` (pinned fixture `tests/fixtures/azure/`) |
| #5b vTPM app-binding (`verify_azure_vtpm` + `azure_app_measurement`) | ✅ **Done** — the full HCL→AK→PCR chain verifies and the measurement folds MRTD ‖ PCR digest |
| **#5c Gateway live-boot on the CVM (its OWN quote)** | ✅ **Done (2026-07-03)** — see below |
| #5d Real TEE key-release (`TeeSealProvider` backed by the vTPM) | ⬜ remaining — `SoftwareSealProvider` is still the stand-in |

### #5c live-boot verification (2026-07-03, Azure DC2es_v6 CVM, westus)

`scripts/tee-capture/capture.sh` captured the six live `ATTESTATION_DIR`
artifacts on the running CVM (HCL report via owner-auth NV read of `0x01400001`,
TD quote via IMDS with the bare `application/json` workaround, **fresh** PCS
collateral — quote verified `UpToDate`, zero advisories). The gateway then booted
against its **own live quote** (no `ATTESTATION_NOW`) and bound the enclave to
`0x422890f6aa4e1e864d9ece858e13bc8f9dd2c24e3d8046127acd451e5faf55bd`. Production
posture verified both ways: with the pinned measurement it serves `/v1`; with a
wrong pin it refuses to start (exit 1). ⚠️ Ops note: the measurement covers the
measured-boot PCRs, so a kernel/bootloader update + reboot **changes it** — after
any reboot, re-run `capture.sh` and consciously re-pin
`ATTESTATION_EXPECTED_MEASUREMENT` (verify the change is a legitimate update, not
a platform swap).

### #5 findings from a REAL Azure TDX confidential VM

A `Standard_DC2es_v6` CVM (Ubuntu 24.04 CVM image) was provisioned, a real TDX
quote captured, and verified offline by our crate. What the live platform showed:

- **Region:** Azure Free-Trial subscriptions reject new-customer deploys in saturated regions (westeurope → `RequestDisallowedByAzure: locationineligible`); **westus** worked. Only westus/westeurope expose `DC*es_v6` to this sub; quota `standardDCEV6Family` = 4 vCPU (offer won't raise it).
- **Quote path:** the direct guest interface is gated off (`/dev/tdx_guest` absent, configfs-tsm `mkdir` → ENXIO even after `modprobe`). Quotes come via the **vTPM/HCL → IMDS** path: `az-tdx-vtpm` reads the TD report from the vTPM, then `POST http://169.254.169.254/acc/tdquote`. ⚠️ `az-tdx-vtpm 0.8.1`'s `send_json` sets `Content-Type: application/json; charset=utf-8` → IMDS returns **415**; a bare `application/json` header fixes it.
- **report_data is NOT app-settable:** it carries the Azure HCL runtime-data hash (32 bytes + zero pad), confirming decision #3 — a key/nonce must bind transitively via the **vTPM AK**, not by writing report_data.
- **All four RTMRs are ZERO:** Azure measures boot into the **vTPM PCRs**, not the TD RTMRs. So on Azure the TD measurement is MRTD (firmware) only; **application identity lives in the vTPM layer**. The MRTD+RTMR fold stays correct for general TDX and harmless here, but on Azure it binds firmware, not the app — #5b must add vTPM-PCR/AK binding for real application identity.
- The captured quote verified **UpToDate** end-to-end (PCK chain → Intel Root CA, TCB) and is pinned as a regression fixture.

### What `crates/attestation` does (verified)

`verify_tdx_quote(quote, collateral, now_secs) -> VerifiedAttestation` verifies a
raw TDX quote against **pinned** collateral (no network), returning the MRTD, the
four RTMRs, the 64-byte report data, and the evaluated TCB status.
`VerifiedAttestation::enclave_measurement()` — the **only public path to a
measurement** — folds **MRTD ‖ RTMR0..3** into the engine's 32-byte `Digest`
(under the `Domain::Measurement` tag), but **only if the TCB is acceptable**
(`UpToDate` / `SwHardeningNeeded`); an out-of-date/revoked platform gets
`Err(TcbRejected)`. Binding the RTMRs (not MRTD alone) is what makes the digest
**application-bound** rather than firmware-generation-bound on the Azure CVM
target. The raw fold helper is `pub(crate)` so the gate cannot be bypassed.

Hermetic tests ([`tests/verify_offline.rs`](../crates/attestation/tests/verify_offline.rs))
against Phala's pinned TDX v4 vector (commit `9bffe30b`), timestamp pinned to the
collateral window:
- verifies the quote + extracts MRTD/RTMR0/report_data == golden (byte-for-byte);
- **rejects a tampered quote** (flips one MRTD byte → ECDSA check fails);
- the measurement is deterministic and bound to **both** MRTD and RTMRs;
- the key-release gate accepts only `UpToDate`/`SwHardeningNeeded`, rejecting
  OutOfDate / Revoked / ConfigurationNeeded / unknown (synthetic + real vectors).

Pure-Rust crypto (`dcap-qvl 0.5.2`, `default-features=false, ["std","rustcrypto","default-x509"]`)
— no `ring`/asm, so it builds clean under workspace `unsafe_code = "forbid"`.

## Decisions

1. **Verify crate:** Phala `dcap-qvl` 0.5.2 (pure-Rust `rustcrypto` backend, MIT). Rejected AGPL `tdx-quote` and C-FFI Intel QVL.
2. **Offline collateral:** vendor pinned vectors + pin the verify timestamp; never `SystemTime::now()`. CI air-gapped from Intel PCS.
3. **Quote acquisition (#5):** Azure vTPM/HCL path (`az-tdx-vtpm`) is primary — Azure GA images fix REPORTDATA to the HCL-runtime-data hash, so the seal key binds transitively via the vTPM AK. Probe `configfs-tsm` for app-settable REPORTDATA but don't design for it.
4. **On-chain:** `IDcapAttestation` interface + a `MockDcapAttestation` for tests (mirrors `MockZkVerifier`); a thin `AutomataDcapAdapter` (deferred to #5) will call the live Automata verifier on **Sepolia `0x27188ABA3a26CBb806eF4C67de9b05D7d792EC10`** and map its Output onto this interface. `AttestationRegistry.sol` (owner-gated) requires verified + acceptable TCB (`{UpToDate, SwHardeningNeeded}`, matching off-chain) + `keccak256(MRTD‖RTMR0..3) == expected`, then binds the enclave signer from report_data — kept OUT of settlement so the byte-locked CrossLayer vectors stay frozen. The on-chain `keccak256(MRTD‖RTMR0..3)` and the off-chain keccak fold are **intentionally distinct encodings** of the same measurement set and must never be unified.
5. **Self-DCAP is the source of truth;** Microsoft Azure Attestation (MAA) is an optional ops cross-check only.
6. **On-chain proof mode:** SP1 Groth16 ZK path (`ZkCoProcessorType.Succinct`, ~493k gas) — deferred, additive, does not touch CrossLayer vectors.

## Azure runbook (USER actions — slowest first)

Subscription is essentially fresh; core RPs (`Microsoft.Compute/Network/Storage/Quota`)
have been **registered**. Region: **westeurope** has Intel TDX (`DC*es_v6`); smallest
is **`Standard_DC2es_v6`** (2 vCPU). (West US 3 is the cheapest GA TDX region if cost > latency.)

1. **[lead time] Request confidential-VM quota.** Default is **0**; regional total is **4 vCPU**. Portal → Quotas → Compute → westeurope → **"Standard DCESv6 Family vCPUs"** → request **8** (covers a `DC4es_v6` + headroom). Usually auto-approves in minutes.
2. **Create the CVM** (Ubuntu 24.04 CVM image, `--security-type ConfidentialVM --enable-vtpm --enable-secure-boot`, `Standard_DC4es_v6`).
3. **On the VM:** install `azguestattestation1` (or `az-tdx-vtpm`), capture a real `quote.bin` + collateral, ship it here to pin as the production golden **MRTD+RTMR0..3** set.
4. **[me]** parse/verify the real Azure quote with `crates/attestation`, extract the Azure measurement set, wire it into `EnclaveIdentity` + the real `TeeSealProvider`.

Cost: `DC2es_v6` ≈ $74/mo, `DC4es_v6` ≈ $148/mo (+ ~$5–10 disk).

## Open questions (confirm against a real Azure quote — deferred to #5)

- **#5b — application identity via the vTPM (the now-primary task).** Since Azure's TD RTMRs are zero and report_data is the HCL hash, the sequencer binary's identity is in the vTPM PCRs and the AK that signs them. `TeeSealProvider` must: verify the vTPM AK is bound to this TD (the AK pub is in the HCL runtime data, whose SHA-256 is the quote's report_data — chain it), read a PCR quote over the measured-boot PCRs, and key release off `MRTD ‖ PCR-set` rather than `MRTD ‖ RTMRs`. The on-chain `enclaveSigner ← reportData[0..20]` binding likewise needs reworking to derive from the AK, not the (HCL-hash) report_data; require `reportData.length == 64` and pin the layout against real output.
- **Live-gate freshness:** the verifier takes a pinned `now_secs` + pinned collateral (correct for hermetic tests / replay-resistance). A live gate must drive `now` from a trusted clock and refresh collateral each `nextUpdate`, and re-check revocation.
- **TCB policy:** `SwHardeningNeeded` is accepted regardless of the outstanding `advisory_ids` set. Decide whether to gate it on an allowlist of known-mitigated advisories.

> Resolved by the real Azure quote (#5a):
> - report_data is **not** app-settable — it is the Azure HCL runtime-data hash. Bind via the vTPM AK (above), not by writing report_data.
> - `/acc/tdquote` returns a **standard TDX v4** quote, offline-verifiable with Intel PCS collateral (status UpToDate).
> - The Azure TD **RTMRs are zero** (vTPM-measured boot) — so on Azure the fold binds firmware (MRTD) only; app identity is the vTPM layer (#5b).
> - The off-chain fold and the on-chain `keccak256(MRTD‖RTMR0..3)` are **intentionally distinct encodings** of the same set — by design, never unified.

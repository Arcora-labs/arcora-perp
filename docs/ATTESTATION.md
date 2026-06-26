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
| **#5 Confidential-VM run + real key release** | ⬜ blocked on Azure provisioning |

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

- **report_data → signer (biggest fork).** Does Azure GA Ubuntu 24.04 CVM expose an app-settable 64-byte REPORTDATA via `configfs-tsm`, or only the HCL-AK-bound hash? If not app-settable, the registry's `reportData[0..20] → enclaveSigner` binds a garbage signer; bind the signer transitively via the vTPM-AK chain instead. The first-20-bytes/left-aligned layout is also currently asserted only against a self-constructed test buffer — pin it against real #5 enclave output and require `reportData.length == 64`.
- Does `/acc/tdquote` return a standard v4 ECDSA-P256 DCAP quote verifiable with Intel PCS collateral, or must collateral come from Azure THIM?
- V4 (TD10) vs V5 (TD15) body emitted by the CVM (off-chain + on-chain decode must agree; `quote_version` is currently the body-variant, not the header version).
- Are the captured RTMR0..3 stable across reboots of the same image (RTMR0 firmware config in particular)? If any legitimately varies, narrow the fold to the stable subset (e.g. RTMR1..3). Pin the real Azure MRTD+RTMR set as the production golden, replacing the Phala sample.
- **Live-gate freshness:** the verifier takes a pinned `now_secs` + pinned collateral (correct for hermetic tests / replay-resistance). A live gate must drive `now` from a trusted clock and refresh collateral each `nextUpdate`, and re-check revocation.
- **TCB policy:** `SwHardeningNeeded` is accepted regardless of the outstanding `advisory_ids` set. Decide whether to gate it on an allowlist of known-mitigated advisories.

> Resolved (no longer open): the off-chain fold and the on-chain `keccak256(MRTD‖RTMR0..3)` are **intentionally distinct encodings of the same measurement set** — this is by design, not a form to be unified.

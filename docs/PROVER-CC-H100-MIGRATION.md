# Prover → CC-capable H100 migration plan

**Written:** 2026-07-24. **Owner:** operator. **Status:** planning (no host provisioned yet).

## Why this exists

GB10 (the GX10 box / DGX Spark) **cannot do Confidential Computing** — NVIDIA
staff confirmed on the official forum: *"Confidential Compute is not supported
on the DGX Spark … This is specific to the GB10."* It is a hardware limitation,
not a driver/toggle. So SEC-020's attested prover — `NvidiaCcAttestor`, the
attested seal, the DH mutual-attestation handshake — can never be exercised on
GX10; there `NvidiaCcAttestor::detect().verify()` always returns `CcNotEnabled`
and the prover stays fail-closed (which is why prod proving is closed today).

The SEC-020 Phase-2 code (C1–C5, merged on `main` at `9969ed4`) is correct and
ready; it just needs a **CC-capable NVIDIA GPU** for the prover half. The Azure
TDX gateway half already works. This plan moves the prover-service onto a CC-H100
and turns the DH handshake from "always refuses" into "completes, both sides
attested," which is what unblocks runbook deferred items (b)/(c)/(d).

## Decision — which CC-H100 host

All viable hosts give a **CPU TEE + NVIDIA GPU CC** envelope (the witness stays
protected in CPU-TEE memory and is processed on the H100 with encrypted VRAM).
The axis that matters is the **attestation model** the prover's `NvidiaCcAttestor`
consumes (it expects NVIDIA GPU attestation — `nv-attestation-sdk` /
`nv-local-gpu-verifier` reporting `confidential compute = True` + a GPU
measurement, with a caller nonce bound into the GPU evidence).

| Host | $/hr | CPU TEE | GPU attestation | Prover code fit | Verdict |
|---|---|---|---|---|---|
| **Phala GPU TEE** | ~$2.38 reserved / $3.08 trial | Intel TDX (same family as the gateway) | H100 NVIDIA CC mode + separate NVIDIA-signed GPU quote | ✅ likely as-is — **confirm the tenant attestation API** (direct `nv-local-gpu-verifier` vs Phala's combined verifier) | **Recommended** — cheapest + arch-aligned, pending the API check |
| **Azure NCC H100 v5** (`Standard_NCC40ads_H100_v5`) | ~$5.60 | AMD SEV-SNP | H100 CC + confidential-GPU driver + NVIDIA attestation (`aka.ms/cgpu-onboarding-steps`) | ✅ reference model, **zero prover code change** | **Safe fallback** — 2× price, GA East US2 / West Europe |
| VoltageGPU | ~$2.75 | Intel TDX | **TEE-IO** (GPU in the CPU TDX trust domain, attested via the TDX quote) | ⚠️ different model → prover attestation-path adaptation likely | Cheapest but needs a code cycle; only if Phala/Azure don't fit |
| AWS Nitro | ~$5.45 | Nitro | **CPU-only, no GPU attestation** | ❌ | Unusable — GPU runs plaintext |

**Recommendation:** start with **Phala** (price + Intel-TDX alignment with the
Azure TDX gateway); keep **Azure NCC H100 v5** as the zero-code-change fallback.
Decide only after the §1 attestation-API check.

## What this unblocks (SEC-020 runbook §0a deferred items)

- **(b)** the prover's real NVIDIA CC `measurement()` — replaces the `[0xAB]`
  stub with the live GPU measurement; the `AttestedSealProvider` measurement
  binding becomes real.
- **(c)** a live GPU-attestation nonce binding the caller's fresh `eph_pub`
  (the GPU-side analogue of the Azure `tpm2_quote -q` freshness).
- **(d)** the CC-on end-to-end gateway↔prover DH handshake completing.

(Deferred item **(a)** — the Azure gateway's `capture.sh -q <eph_pub>` — is
separate; it lives on the Azure TDX CVM, not this host.)

## Steps

**1. Provision + verify the CC-H100 (before touching dark-perp).**
- Provision the chosen host; complete its confidential-GPU driver + attestation
  onboarding.
- Confirm CC is actually on: `nvidia-smi conf-compute -f` reports CC ON (or the
  provider's equivalent), and `nv-attestation-sdk` / `nv-local-gpu-verifier`
  yields `confidential compute = True` + a GPU measurement + a **fresh caller
  nonce echoed in the GPU evidence** (the analogue of a fresh eph_pub binding).
- **Phala decision gate:** verify tenant code can obtain a GPU attestation report
  that (i) carries a caller-supplied nonce and (ii) matches what `NvidiaCcAttestor`
  parses. If Phala only exposes a pre-baked combined verifier without a
  caller-nonce path, either adapt the prover to Phala's API or fall back to Azure.
- Record the GPU measurement → this is the gateway's `PROVER_EXPECTED_MEASUREMENT`.

**2. Build + deploy the prover-service on the CC-H100.**
- `crates/prover-service` is the workspace-EXCLUDED standalone crate (SP1 +
  gnark/Groth16). Build per `docs/PROVING-RUNBOOK.md` (SP1 toolchain; Docker for
  Groth16). A clean-state proof is ~10–14 GB RSS — trivial on the 94 GB H100.
- Set the prover env: `ATTESTATION_DIR` (its live CC evidence source),
  `PROVER_EXPECTED_MEASUREMENT` / `GATEWAY_EXPECTED_MEASUREMENT` (app-level,
  pinned), `PROVER_SEAL_ROOT` + the attested-provider path so
  `AttestedSealProvider` builds from a REAL attested seal — **no `DEV_INSECURE`**
  (prod refuses it). `SESSION_TTL_MS` default (15 min) unless tuned.
- The prover generates its per-boot ephemeral x25519 keypair, computes
  `not_after`, and serves `{ bundle, eph_pub, not_after }` on `/attest` (the code
  is already merged; on a CC host `NvidiaCcAttestor::quote` now returns a real
  bundle instead of `CcNotEnabled`/503).

**3. Wire the gateway (Azure TDX CVM) to the remote prover.**
- Point `PROVER_URL` at the CC-H100. **The prover is no longer `127.0.0.1:8091`**
  — it's a remote host, so the network path is now trust-sensitive. This is
  exactly what C3 (the DH-bound, non-public-transcript session token) and C5
  (constant-time compare + `not_after`) secure: a network attacker cannot
  recompute the bearer token. Put the link on TLS / a private tunnel regardless.
- Pin `PROVER_EXPECTED_MEASUREMENT` = the §1 measurement; keep
  `GATEWAY_EXPECTED_MEASUREMENT` = the gateway's app-level Azure measurement.
- The gateway's boot ephemeral keypair + the (already-merged) C4 boot-key-reuse
  re-handshake handle prover reboots.

**4. SEC-020 smoke (the first time the handshake completes).**
- Gateway↔prover `/attest` exchange: each verifies the peer bundle over the
  peer's advertised `eph_pub`; both `dh_shared` → identical `derive_session`
  secret + token.
- `/prove` without a valid session ⇒ 401; with the DH-bound session token ⇒ 200.
- Drive one real batch: seal → `/prove` → Groth16 → `settleBatch` on Base
  Sepolia. Confirms the guest enforces `deposits_root` + the oracle gate, AND the
  attested seal round-trips under the real measurement (deferred (b)/(c)/(d) all
  exercised).

**5. Retire the dev GPU box from this service.** Stop the un-attested
prover-service there. Do not reboot that host if other workloads depend on it.

## Cost / ops

- The prover need only be **up while proving** (settle windows). Phala's
  per-minute + reserved options and Azure's on-demand both allow spin-up per
  window → cost tracks proving frequency, not wall-clock.
- Always-on ballpark: Phala ~$1.7k–2.2k/mo, Azure ~$4k/mo. Decide by how
  continuous settlement must be for a live testnet vs on-demand.

## Open questions / verification gates (do before committing to a host)

1. **Phala attestation API** — can tenant code get a GPU attestation report with
   a caller-supplied fresh nonce that `NvidiaCcAttestor` parses? (Gate for the
   cheap path; else Azure.)
2. **Fresh-nonce binding on the GPU side** — the live analogue of the Azure
   `tpm2_quote -q <eph_pub>`: the H100 CC evidence must bind the prover's
   `eph_pub` per handshake, or C2/C3 freshness is only structural. Confirm the
   NVIDIA CC attestation supports a per-request nonce (it does via
   `collect_gpu_evidence(nonce)`) and the provider exposes it.
3. **Does `NvidiaCcAttestor`'s current stub `quote()`/`verify()` need the real
   NVIDIA SDK wired in?** Phase-1 built `NvidiaCcAttestor` fail-closed
   (`CcNotEnabled`); turning it live = implementing the real
   `collect_gpu_evidence`/`verify_evidence` against `nv-attestation-sdk` on the CC
   host. That is a **code task** (its own TDD/SDD cycle) once a host is chosen —
   it was correctly deferred as not-locally-testable.

> Item 3 means "provision a CC-H100" is necessary but not sufficient: the
> prover's NVIDIA attestation backend still has to be implemented against the
> real SDK on that host. Budget a focused implementation + on-host smoke, not
> just a VM rental.

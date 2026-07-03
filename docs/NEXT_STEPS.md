# HANDOFF — next steps (continue in a clean session)

Snapshot for resuming the dark-perp work. Repo lives at `~/Desktop/dark-perp`.

## Where things stand (2026-06-26)

Branches:
- **`main`** — Celari UI redesign + real backend gateway. **Pushed to GitHub** (`origin/main`, github.com/Kubudak90/dark-perp).
  - `14d9436` feat(frontend): apply Celari Perp design system
  - `dd42204` feat(gateway): real backend — axum HTTP+WS gateway over the Sequencer engine
- **`feat/real-tee`** — current branch, TEE milestone work (NOT yet pushed/merged).
  - `79b29f6` feat(prover): real authenticated witness sealing (measurement-bound key release)
- Uncommitted (optional to commit): `docs/architecture.html` (the technical doc).

**Live on testnet (2026-06-28) — USDC stack + full deposit/withdraw:** the L1
settlement stack is deployed to **Base Sepolia** (chain 84532) with **USDC**
collateral — `DarkPerpSettlement` `0x0329b356B51944616C47DFfc869F6f8F8e9dB872`,
`CollateralVault` `0xB8941ED1057F7e881dC4534d2435CBF5d395Ffb6`, `MockZkVerifier`
`0x9C13bD8d2E59d89AcA41aCF1DdFd4E8289e54253`, `MockUSDC`
`0x967F498cf759F2CA8a43394a21f6b317A2c0d56c` (deployer 0xe8E5, genesisRoot=0,
enclaveSigner = the real gateway enclave `0x4a62…C569`). Record:
`contracts/deployments/base-sepolia.json`. **The gateway settles on-chain AND drives
real USDC deposit/withdraw** via the opt-in L1 bridge (`crates/gateway/src/l1.rs`):
with `L1_SETTLEMENT/L1_SEQUENCER_KEY/L1_USDC/L1_VAULT` set it keeps the USDC bond
above the 5%-of-TVL floor, advances `currentStateRoot` every 30s, and publishes a
**real cumulative withdrawals root**. The earlier "remaining L1 half" is **done**:
real **deposit** (`POST /v1/accounts/deposit/onchain` verifies a `vault.deposit` tx →
engine credit) and **withdraw** (engine debit → leaf → cumulative root → `vault.claim`
releases USDC). The full deposit → withdraw → claim flow is **verified live on Base
Sepolia**. `withdrawalsRoot` is no longer a `0x0` placeholder.

## Active goal: **Real TEE** (Milestone C) — turn the 3 trust roots from stand-ins into real

Increments (the plan we set):
1. ✅ **Real authenticated sealing** — DONE (`79b29f6`). `SealKeyProvider` trait + `SoftwareSealProvider` (dev stand-in for TDX/Nitro key release) + encrypt-then-MAC `SealedWitness` (`WitnessSealMac` domain, `ProverError::SealAuthFailed` on tamper/wrong-key), zeroize kept. Closed the SECURITY.md "real enclave sealing" prerequisite at the software layer. Files: `crates/prover/src/lib.rs`, `crates/perp-core/src/hash.rs`, callers in `crates/demo`, `crates/e2e`.
2. ⬜ **Order encryption** — client encrypts the order to the enclave's epoch key (X25519/HPKE, or a Keccak-based scheme consistent with the crate); wire `Order.ciphertext_commit` to a real ciphertext; the enclave decrypts inside. **Buildable locally, no cloud.** ← natural NEXT.
3. ⬜ **Encrypted append-only order log** (§2). Buildable locally.
4. ✅ **Attestation verification** — DONE. `crates/attestation` verifies a real Azure TDX DCAP quote (offline, pure-Rust dcap-qvl) + the vTPM measured-boot chain, with real captured fixtures. On-chain `AttestationRegistry` + `MockDcapAttestation`.
5. ✅ **Confidential-VM run + real attest** — **DONE (2026-07-03).** The gateway runs on the real `perp-seq` DC2es_v6 CVM (westus, reused from the #5a capture — it was deallocated, not deleted) and verifies its **OWN live quote** at boot: `scripts/tee-capture/capture.sh` produces the six `ATTESTATION_DIR` artifacts live (fresh PCS collateral, `UpToDate`, zero advisories), and the enclave identity is bound to the live measurement `0x422890f6…faf55bd`. Production posture smoke-tested both ways (correct pin serves `/v1`; wrong pin refuses, exit 1). See `docs/ATTESTATION.md` #5c (including the re-pin-after-reboot ops note). Remaining TEE work: back `SealKeyProvider` with real vTPM key-release (#5d).

## What the user must provide (and when)

| Need | For | When (blocks) | Rough cost |
|---|---|---|---|
| **Azure TDX confidential VM** — quota already sufficient (westeurope DCesv6 = 4 vCPU, DC2es_v6 deployable). Just provision + run; a >4-vCPU headroom increase needs a portal ticket / PAYG upgrade (offer-gated) | this goal (#5) | the "run + attest for real" step | ~$0.10–0.40/hr (DC2es_v6) |
| SP1/Succinct prover-network key **or** a GPU box | later: real ZK (Milestone A) | when we do real proofs | proof: ¢–$ · GPU: ~$1–3/hr |
| Sepolia RPC + deployer key + test ETH | later: L1 deploy (Milestone A/B) | Sepolia deploy | free (faucet) |
| External security audit (ZK + Solidity + Rust) | later: mainnet (Milestone D) | before mainnet | ~$50k–200k+ |

Recommended decisions: TEE platform = **Azure TDX**; prover = SP1 network first; mainnet stance = single-enclave + full protocol-completeness beta (committee fast-follow).

## External trading API (REST + WebSocket) — **core built** (see docs/API.md)

The multi-tenant `/v1` API now exists in the gateway: accounts register (API-key
auth, Phase-0 server custody), deposit, place/cancel orders (Ioc/Fok takers +
Gtc/PostOnly resting makers), and read their own account/positions/orders + public
markets/orderbook/oracle/status — all isolated on the **same shared engine**, demo
preserved. `/v1/ws` streams live public market data AND, after auth, per-account
events (own fills, order finality, ADL). Per-account order **rate limiting** (10/s →
429) is in. Follow-ons that remain: per-IP rate limiting on registration, OpenAPI
spec, caller-signed orders + enclave custody, real deposit/withdraw L1 flows.
Reference: `docs/API.md`. Original gap analysis kept for context:

**The gap.** A real perp DEX needs an external API that market-makers, bots, and
integrations hit **without a browser** — place/cancel orders and read
account/positions/orderbook/fills programmatically. Today that layer does not
exist as a product:
- The frontend "API" tab (`ApiExplorer.tsx`) is an in-browser console that calls
  the `MockDarkPerpClient` — in-memory, no network. A dev/demo tool, not an
  endpoint an external bot can hit.
- The `DarkPerpClient` interface (`frontend/src/api/client.ts`) is the UI↔backend
  TypeScript seam; today only the mock + the demo gateway implement it.
- The `gateway` crate **does** expose HTTP+WS over the real sequencer, **but** it
  is a single-tenant DEMO: one hardcoded user + one market-maker, no auth, no
  per-account isolation, not a public multi-account API.
- The `sequencer` crate holds the real protocol logic (accept_order → signed
  receipt §2, seal_batch, finality, inclusion challenge) as a **library**; the
  `node` crate is just a loop.

**What a real one needs.** A multi-tenant service over the sequencer:
- REST: submit/cancel order, deposit/withdraw intents, read account, positions,
  orderbook, fills, funding, batch/finality status.
- WebSocket: live orderbook, trades, per-account fills + finality transitions,
  oracle/mark updates.
- Per-account **auth** (API key or signed request) and isolation — arbitrary
  accounts, not the demo's fixed two.
- External **order signing**: the order's `ciphertext_commit`/signature is
  produced by the caller; the API verifies + forwards to `accept_order`.
- Rate limits + OpenAPI/asyncapi docs so MMs/bots can integrate.

**Where it plugs in.** Generalize the `gateway` (or a new `api`/`exchange-api`
crate) from the single-user demo into a multi-account service over
`sequencer::Sequencer`; the `DarkPerpClient` interface is the shape to mirror.
This is a genuine missing layer — not yet built.

## Run / test

```bash
# Real backend (Rust engine drives the UI)
cargo run -p gateway                                   # :8080 (PORT overrides)
cd frontend && VITE_API_URL=http://localhost:8080 pnpm dev

# Mock (no backend)
cd frontend && pnpm dev

# Tests
pnpm test                 # frontend 90/90
cargo test -p gateway     # 2/2
cargo test --workspace
```
`frontend/pnpm-workspace.yaml` sets `verifyDepsBeforeRun:false` so `pnpm dev/build/test` don't re-trigger the install-time supply-chain gate.

## Key references

- `docs/ARCHITECTURE.md` (v2, canonical), `docs/ROADMAP.md` (phase status — **Phases 0–2 substantially built/tested**; remaining = real ZK backend, attestation, Proof-v2, Aztec/committee).
- `docs/PROVING.md` — the SP1 guest **already builds** (`cargo prove build`) and `sp1-host` **executed it byte-for-byte equal to native** (cycles=248477); real proof = `.prove().groth16()` + generate the SP1 Solidity verifier + swap `MockZkVerifier`.
- `docs/SECURITY.md` — threat model + production prerequisites + open design items (P3b on-chain rejection-proof path, P6 cumulative withdrawals root, spend-key↔owner binding).
- `docs/DECISIONS.md` — ADRs. `docs/architecture.html` — the standalone technical doc.

## Constraints (carry into every session)

- Commits: the user's account (**Kubudak90**), **NO Claude/AI attribution** anywhere.
- **Never** change the cross-layer public-input vectors (`crates/prover/tests/vectors.rs` ↔ `contracts/test/CrossLayer.t.sol`) or `PublicInputs::commitment` — they are byte-locked to L1.
- `unsafe_code` is forbidden workspace-wide; `perp-core` must keep building `--no-default-features --features serde` (the no_std zkVM-guest config).

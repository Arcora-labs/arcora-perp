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

**Live on testnet (2026-06-27):** the L1 settlement stack is deployed to **Base
Sepolia** (chain 84532) — `DarkPerpSettlement` `0xF82F7676502935c4B86AAD36F405BfF7a3CA65D3`,
`CollateralVault` `0x4b647D3E5c3Ed0FEE209dD9F00feC957b0157E0c`, `MockZkVerifier`
`0x1022801D314258c79556C85973260d4F06C35ACB` (deployer 0xe8E5, genesisRoot=0,
MockZkVerifier — real SP1 verifier before non-testnet). Record:
`contracts/deployments/base-sepolia.json`. The running gateway is **not yet wired**
to settle against these (it's still in-memory) — that wiring is the next L1 step.

## Active goal: **Real TEE** (Milestone C) — turn the 3 trust roots from stand-ins into real

Increments (the plan we set):
1. ✅ **Real authenticated sealing** — DONE (`79b29f6`). `SealKeyProvider` trait + `SoftwareSealProvider` (dev stand-in for TDX/Nitro key release) + encrypt-then-MAC `SealedWitness` (`WitnessSealMac` domain, `ProverError::SealAuthFailed` on tamper/wrong-key), zeroize kept. Closed the SECURITY.md "real enclave sealing" prerequisite at the software layer. Files: `crates/prover/src/lib.rs`, `crates/perp-core/src/hash.rs`, callers in `crates/demo`, `crates/e2e`.
2. ⬜ **Order encryption** — client encrypts the order to the enclave's epoch key (X25519/HPKE, or a Keccak-based scheme consistent with the crate); wire `Order.ciphertext_commit` to a real ciphertext; the enclave decrypts inside. **Buildable locally, no cloud.** ← natural NEXT.
3. ⬜ **Encrypted append-only order log** (§2). Buildable locally.
4. ⬜ **Attestation verification** — verify a real **Azure TDX DCAP quote**, extract + match the measurement (MRTD); Rust verifier module + optional on-chain Solidity verifier (or integrate Automata DCAP). Platform-specific (Azure TDX recommended); writable here, but needs a **real quote sample** (from a TDX VM) to test end-to-end.
5. ⬜ **Confidential-VM run + real attest** — run the sequencer (+ attested prover) inside an **Azure TDX VM**, generate a real quote, verify end-to-end, and back `SealKeyProvider` with real TEE key-release. **Needs the Azure account.**

## What the user must provide (and when)

| Need | For | When (blocks) | Rough cost |
|---|---|---|---|
| **Azure TDX confidential VM** — subscription + TDX region (eastus2 / westeurope) + `Standard_DC*as_v5` or `EC*as_v5` quota | this goal (#5) | the "run + attest for real" step | ~$100–500/mo |
| SP1/Succinct prover-network key **or** a GPU box | later: real ZK (Milestone A) | when we do real proofs | proof: ¢–$ · GPU: ~$1–3/hr |
| Sepolia RPC + deployer key + test ETH | later: L1 deploy (Milestone A/B) | Sepolia deploy | free (faucet) |
| External security audit (ZK + Solidity + Rust) | later: mainnet (Milestone D) | before mainnet | ~$50k–200k+ |

Recommended decisions: TEE platform = **Azure TDX**; prover = SP1 network first; mainnet stance = single-enclave + full protocol-completeness beta (committee fast-follow).

## Queued next: a real external trading API (REST + WebSocket)

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

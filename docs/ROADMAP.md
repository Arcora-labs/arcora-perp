# Roadmap — phases mapped to code

Maps the architecture's build order (§13) to concrete crates/components and marks
what exists. Each phase lists its deliverables and the architecture sections it
discharges.

Legend: ✅ done · 🟡 partial / scaffolding present · ⬜ not started

> Status snapshot: Phases 0–2 are substantially built and tested end-to-end
> (`crates/e2e`), with the L1 layer cross-bound to the Rust core by byte-exact
> vectors. Remaining work is the real ZK backend, attestation, Proof-v2, and the
> Aztec/committee phases — see the per-phase tables.

## Faz 0 — Local / Sepolia ZK perp core (no TEE, no Aztec) — **done**

The deterministic perp core + accounting soundness. Proving is done **in the
open** (a Sepolia testnet has no real positions to protect, §10b "Faz timing").

| Deliverable | Where | Status |
|---|---|---|
| Note tree (commitment / nullifier) | `perp-core::merkle`, `::note`, `::nullifier` | ✅ |
| Margin / leverage / liquidation validity | `perp-core::position`, `::market` | ✅ |
| Funding rate + cumulative index | `perp-core::funding` | ✅ |
| Oracle transcript + sanity bounds (§8) | `perp-core::oracle` | ✅ |
| Deterministic batch state transition | `perp-core::engine`, `::state` | ✅ |
| Proof-v1 invariants as tests (§4) | `perp-core/tests/lifecycle.rs` | ✅ |
| Receipt / manifest / finality types (§2, §3) | `perp-core::order` | ✅ |
| Close-only / forced-exit mode (§6) | `perp-core::state`, `::engine` | 🟡 (mode + close-only; L1 trigger is Faz 2) |
| zkVM guest + proof (SP1/Risc0) over `engine` | `crates/prover` (todo) | ⬜ |
| Solidity verifier + vault skeleton on Sepolia | `contracts/` (todo) | ⬜ |
| `no_std` guest-build guarantee | `cargo build -p perp-core --no-default-features` | ✅ |

**Next concrete steps in Faz 0:** wrap `State::apply_batch` in an SP1 guest, emit a
proof binding `(previous_state_root, batch_manifest_hash, new_state_root)`; stand up
a minimal Solidity verifier + collateral vault on Sepolia; benchmark proving time
per batch size (the §10b memory-envelope data point).

## Faz 1 — TEE order gateway + receipt + preconf

| Deliverable | Where | Status |
|---|---|---|
| In-enclave in-memory CLOB (native match, price-time, order types, STP) | `matcher` | ✅ |
| Signed receipt (ACCEPTED) — secp256k1, L1-verifiable | `sequencer` | ✅ |
| Fill preconf (MATCHED) + finality state machine | `sequencer` | ✅ |
| Encrypted order ingress + enclave key epoch | `gateway::enclave_epoch`, `sealed-box`, `realClient.ts` | ✅ (client seals to the attested enclave epoch key at `GET /v1/enclave/epoch`; the enclave decrypts inside `account_place_order`; depth stays public) |
| Enclave attestation verification (TDX / Nitro) | — | ⬜ (modelled as measurement) |
| Append-only encrypted order log | `gateway::order_log` | ✅ (hash-chained, sealed to the enclave log X25519 key; on-chain manifest anchoring deferred to the ZK-verifier workstream — the log is the prover witness) |

## Faz 2 — ZK settlement + fund safety + confidential proving

| Deliverable | Where | Status |
|---|---|---|
| Ethereum verifier interface + state-root anchoring | `contracts/DarkPerpSettlement` | ✅ |
| Collateral vault + settled-withdrawal claims | `contracts/CollateralVault` | ✅ |
| Forced-exit / close-only L1 module | `DarkPerpSettlement` (liveness→close-only) | ✅ |
| **Encrypted note archive / indexer** | `note-archive` | ✅ (real AEAD — X25519 + HKDF + XChaCha20-Poly1305 via `sealed-box`; the earlier XOR stand-in is gone, and the host cannot read a note without the view key) |
| **Attested confidential prover** (sealed witness → measurement) | `prover` (§10b boundary) | 🟡 (the sealing-boundary abstraction ships — real Groth16 proving + a sealed-witness handshake over `crates/gateway/src/prover_client.rs` — but "attestation" is a stub: a fixed `0xAB` measurement + a public default seal-root `0x5E`, not real TDX/Nitro attestation; see the `⬜` row above, SEC-020) |
| Real SP1/Risc0 verifier + EIP-4844 DA blob | — | ⬜ (see `docs/PROVING.md`) |

## Faz 3 — Fair-sequencing hardening

| Deliverable | Where | Status |
|---|---|---|
| Inclusion timeout detection | `sequencer::inclusion_violations` | ✅ |
| Slashing bond + inclusion challenge/answer/slash | `contracts/DarkPerpSettlement` | ✅ |
| Pre-trade risk (reject unmarginable before matching) | — | ⬜ |
| **Proof-v2** matching determinism (price-time, STP, partial, expiry, order types) | — | ⬜ (matcher is deterministic + tested; ZK proof pending) |

## Faz 4 — private bridge

| Deliverable | Where | Status |
|---|---|---|
| Amount-bucket decomposition (fixed denominations) | `bridge::decompose` | ✅ (model) |
| Batching / mixing + per-denomination anonymity set | `bridge::MixBatch` | ✅ (model) |
| Actual Aztec network integration | — | ⬜ (optional; Ethereum-direct ships first, §15) |

Private deposit/withdraw via padding / batching / relayer + amount-bucket strategy
(§13, §15). The model is Ethereum-direct; the Aztec dependency is lightweight and
isolated to this bridge, and can wait for Alpha/v5 maturity.

## Faz 5 — Committee-of-enclaves

| Deliverable | Where | Status |
|---|---|---|
| Threshold (t-of-n) order-key sharing — no single enclave decrypts an order | `committee::shamir` | ✅ (model) |
| Quorum preconfirmation (t-of-n distinct enclave signatures) | `committee::QuorumCertificate` | ✅ (model) |
| Wire quorum into the sequencer preconf path | — | ⬜ |
| Real distributed key generation + enclave diversity / cross-provider | — | ⬜ |

Addresses confidentiality/integrity single-point-of-failure only (§10, §11) —
*not* a substitute for protocol completeness, which is required in every version.

---

## Non-negotiables carried across all phases (§11 taxonomy)

These are **protocol completeness** items — required in *every* version,
independent of enclave count:

- order-commitment log + slashing (sequencing accountability, §2)
- forced exit / close-only (liveness, §6)
- oracle transcript + sanity bounds (§8)
- encrypted note archive (recovery, §7)
- `MATCHED ≠ SETTLED` finality discipline (§3)

# Roadmap — phases mapped to code

Maps the architecture's build order (§13) to concrete crates/components and marks
what exists. Each phase lists its deliverables and the architecture sections it
discharges.

Legend: ✅ done · 🟡 partial / scaffolding present · ⬜ not started

## Faz 0 — Local / Sepolia ZK perp core (no TEE, no Aztec) — **current**

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

| Deliverable | Notes |
|---|---|
| Enclave attestation verification (TDX / Nitro) | client checks measurement before encrypting (§1) |
| Encrypted order ingress + enclave key epoch | `Order.ciphertext_commit` already in the wire format |
| In-enclave in-memory CLOB (native match) | hot path (§1, §5) |
| Signed receipt (ACCEPTED) + fill preconf (MATCHED) | `Receipt`/`Finality` types exist; add real enclave signing |
| Append-only encrypted order log | feeds the manifest (§2) |

## Faz 2 — ZK settlement + fund safety + confidential proving

| Deliverable | Architecture |
|---|---|
| Ethereum verifier + collateral vault + withdrawal queue | §1, §3 |
| Hard state root anchoring + EIP-4844 DA blob | §1, §3 |
| Forced-exit / close-only L1 module | §6 |
| **Encrypted note archive / indexer** | §7 (mandatory, not "hardening") |
| **Attested confidential prover** (sealed witness → measurement decrypt) | §10b (real position privacy starts here) |

## Faz 3 — Fair-sequencing hardening

Inclusion timeout, slashing bond, batch-non-proving penalty, and **Proof-v2**
(committed-log matching determinism: price-time priority, self-trade prevention,
partial fill, expiry, order types). §2, §4.

## Faz 4 — Aztec private bridge

Private deposit/withdraw + padding / batching / relayer + amount-bucket strategy.
Lightweight dependency, isolated to the bridge. §13, §15.

## Faz 5 — Committee-of-enclaves

Threshold order encryption, quorum preconfirmation, enclave diversity /
cross-provider. Addresses confidentiality/integrity single-point-of-failure only
(§10, §11) — *not* a substitute for protocol completeness, which is required in
every version.

---

## Non-negotiables carried across all phases (§11 taxonomy)

These are **protocol completeness** items — required in *every* version,
independent of enclave count:

- order-commitment log + slashing (sequencing accountability, §2)
- forced exit / close-only (liveness, §6)
- oracle transcript + sanity bounds (§8)
- encrypted note archive (recovery, §7)
- `MATCHED ≠ SETTLED` finality discipline (§3)

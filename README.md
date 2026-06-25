# dark-perp

**A fast + dark perpetual-futures protocol.** Low-latency confidential matching
inside an attested TEE, fund safety from ZK validity proofs on Ethereum,
sequencing accountability from an order-commitment log + slashing, and
liveness/recovery from forced exit + an encrypted note archive.

> Tek cümle: *Attested TEE içinde low-latency confidential CLOB (hız +
> operatör-kör dark), append-only order-commitment log + slashing ile sequencing
> accountability, forced-exit + note archive ile liveness/recovery, attested
> confidential prover ile witness gizliliği, asenkron ZK validity proof ile L1
> vault safety, shielded note state ile public privacy.*

The full architecture (v2, Turkish) lives in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).
The design decisions taken while building are in [`docs/DECISIONS.md`](docs/DECISIONS.md),
and the phased build plan in [`docs/ROADMAP.md`](docs/ROADMAP.md).

## Three trust roots, three layers

The thesis: speed and darkness physically fight; the component that gives both at
practical latency is a TEE — but a TEE **moves** trust, it does not remove it, and
fairness / liveness / recovery are *separate* protocol obligations.

| Root | Provides | Does **not** provide |
|---|---|---|
| **TEE** — low-latency confidential execution | operator-blind matching, native-speed continuous CLOB | liveness, fairness, censorship-resistance, recovery |
| **Protocol** — order-commitment log + forced exit + slashing | sequencing accountability, liveness, fair access | confidentiality, fund validity |
| **ZK** — fund-safety / state-validity root | vault safety, valid state transitions | inclusion / ordering / censorship (on its own) |

If the TEE breaks, funds **cannot be stolen** (ZK protects the vault) — but
confidentiality, fair access, preconfirmation reliability and market integrity
can. We label that honestly rather than calling the enclave an untouchable black
box. See §10 of the architecture.

## Repository status

The protocol is built bottom-up across the [roadmap](docs/ROADMAP.md) phases. What
exists today, end-to-end and tested (79 Rust tests + 16 Solidity tests, all green;
clippy clean):

| Component | Crate / dir | Phase | Arch |
|---|---|---|---|
| Deterministic state-transition core (note tree, risk, Proof-v1 invariants) | [`crates/perp-core`](crates/perp-core) | 0 | §1,§4,§12 |
| Price-time CLOB matcher (IOC/FOK/post-only/GTC, STP) | [`crates/matcher`](crates/matcher) | 1 | §1,§4 |
| Sequencer spine: secp256k1 receipts, manifests, finality, inclusion accountability | [`crates/sequencer`](crates/sequencer) | 1–3 | §2,§3 |
| ZK proving harness + §10b confidential-proving boundary | [`crates/prover`](crates/prover) | 2 | §4,§10b |
| Encrypted note archive + view-key recovery | [`crates/note-archive`](crates/note-archive) | 2 | §7 |
| L1 settlement: root anchoring, liveness/close-only, bond + inclusion slashing, vault | [`contracts/`](contracts) | 2 | §2,§3,§6 |
| Committee-of-enclaves: Shamir t-of-n order keys + quorum preconf | [`crates/committee`](crates/committee) | 5 | §11 |
| Privacy bridge: amount-bucketing + batching/mixing | [`crates/bridge`](crates/bridge) | 4 | §13,§9 |
| End-to-end integration (deposit→match→settle→prove→recover) | [`crates/e2e`](crates/e2e) | — | all |
| Web client skeleton (finality UX), design-ready | [`frontend/`](frontend) | — | §3,§6,§7 |

The Rust core and Solidity contracts are bound by **byte-exact cross-layer
vectors** ([`crates/prover/tests/vectors.rs`](crates/prover/tests/vectors.rs) ↔
[`contracts/test/CrossLayer.t.sol`](contracts/test/CrossLayer.t.sol)): a receipt
signed in Rust recovers on-chain via `ecrecover`, and the proof public-input
commitment matches on both sides.

### [`crates/perp-core`](crates/perp-core) — deterministic state-transition core

Written **once**, run in **two** places: natively in the sequencer (hot path) and
**unchanged inside a zkVM guest** (SP1/Risc0 → RISC-V) where it becomes the
Proof-v1 validity circuit. To make that possible it is `#![no_std]` (with
`alloc`), with **no floats, clocks, randomness, or I/O** — every transition is a
pure function of its inputs.

It implements and tests all six **Proof-v1** invariants (§4):

1. **collateral conservation** — `Σ notes + Σ position collateral + insurance + vault_pool == external_in − external_out`, asserted after every op
2. **valid nullifiers / no double-spend** — append-only nullifier set
3. **post-fill margin sufficiency** — increasing side must meet initial margin at the oracle mark
4. **oracle freshness + confidence + deviation** — transcript sanity gates (§8)
5. **funding correctness** — clamped funding rate + cumulative index
6. **liquidation threshold** — equity vs maintenance margin, offline-safe (§5)

Plus the accountability/recovery scaffolding: signed-receipt + batch-manifest
types (§2), three-layer finality `ACCEPTED / MATCHED / SETTLED` where **only
SETTLED is withdrawable** (§3), and a **close-only / forced-exit** mode (§6).

## Build & test

```bash
cargo test                                       # native: 44 tests (unit + lifecycle)
cargo build -p perp-core --no-default-features   # proves the no_std zkVM-guest build
cargo clippy --all-targets                       # clean
```

## What is intentionally NOT here yet

- **Real ZK backend.** The prover is a documented commitment-based stand-in; the
  SP1/Risc0 swap is specified in [`docs/PROVING.md`](docs/PROVING.md) (the guest is
  already `no_std`). `MockZkVerifier` likewise stands in for the generated Solidity
  verifier.
- **TEE attestation.** Enclave keys/measurements are modelled as values; real
  TDX/Nitro attestation verification is Phase 1 production.
- **Proof-v2 (matching determinism).** The matcher is deterministic and tested,
  but matching fairness is not yet *proven* in ZK — in the interim it is backed by
  receipts + manifest + slashing (§2). Phase 3.
- **Pre-trade risk.** Margin is checked at settlement; rejecting unmarginable
  orders *before* matching is Phase 3 (see `crates/sequencer`).
- **Aztec privacy bridge** (Phase 4) and **committee-of-enclaves** (Phase 5).

See [`docs/ROADMAP.md`](docs/ROADMAP.md) for the full phase map.

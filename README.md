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

## Repository status — Phase 0

This repo is at **Phase 0** of the [roadmap](docs/ROADMAP.md): the *local /
Sepolia ZK perp core* — **no TEE, no Aztec yet**. What exists today:

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

CLOB matching fairness (price-time priority, self-trade prevention, order types)
is **Proof-v2** (§4) — in the interim it is backed by receipts + manifest +
slashing (§2). TEE attestation (Phase 1), L1 verifier + vault + note archive +
confidential prover (Phase 2), fair-sequencing slashing (Phase 3), the Aztec
privacy bridge (Phase 4), and committee-of-enclaves (Phase 5) are later phases.
See [`docs/ROADMAP.md`](docs/ROADMAP.md).

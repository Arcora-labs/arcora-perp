# perp-core

The deterministic state-transition core of dark-perp (Phase 0). One body of logic
that runs **natively** in the sequencer hot path and **unchanged inside a zkVM
guest** as the Proof-v1 validity circuit. `#![no_std]` + `alloc`; no floats,
clocks, randomness, or I/O.

See the [workspace README](../../README.md) and
[`docs/`](../../docs/ARCHITECTURE.md) for the full architecture. Module map:

| Module | Role | Arch ref |
|---|---|---|
| `fixed` | fixed-point scales + checked arithmetic | §12 |
| `hash` | `Hasher` trait + Keccak-256 (Poseidon-swappable) | ADR-0002 |
| `merkle` | append-only commitment tree + proofs | §1, §7 |
| `note` / `nullifier` | shielded collateral, double-spend prevention | §1, §4 |
| `market` | deterministic risk parameters | §12 |
| `position` | margin / PnL / liquidation math | §5, §12 |
| `funding` | clamped funding rate + cumulative index | §4 |
| `oracle` | transcript + sanity gates | §8 |
| `order` | order / receipt / manifest / finality | §2, §3 |
| `state` / `engine` | global state + batch transition | §3, §4 |

```bash
cargo test -p perp-core
cargo build -p perp-core --no-default-features   # zkVM-guest build
```

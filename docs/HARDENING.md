# Adversarial hardening pass

A full-codebase adversarial review — every layer read with a "how does this break?"
lens, real findings fixed with a regression test, correct code verified and left
alone. This consolidates the pass into one reviewable record; each line maps to a
commit on the branch.

Test totals moved **132 → 139 Rust**, **40 → 59 frontend** (31 Solidity unchanged),
all green and CI-enforced (`cargo test --workspace` + `clippy -D warnings` + `fmt`,
`forge test`, `pnpm test` + `pnpm build`; pnpm/CI parity verified locally).

## Frontend — 9 real bugs fixed (the mock was the least battle-tested layer)

| Area | Bug | Fix |
|---|---|---|
| Live oracle | a market that went `live` then lost the feed **froze** on its last price (priceTick skips live markets, pollOracle returned on error) — opposite of the documented "never stalls" | outage demotes live markets back to the internal walk; a dropped instrument demotes alone; reconnect re-anchors. Self-healing, 4 regression tests |
| Liquidation | liq line was a magic `±9%`, inconsistent with the market's `0.05` maintenance ratio **and** with perp-core's `is_liquidatable` | derive the buffer from the margin model (`initial − maintenance = 5%`), single-sourced; `maintenanceMarginRatio` now drives the number it names |
| Close-only (§6) | an oversized *opposite* order (a **flip**) slipped past the close-only gate — it opened fresh exposure on the other side | `isOpening` now treats a zero-cross as opening (matches perp-core `increases_exposure` exactly) |
| Reduce-only | the flag was threaded but **never enforced** — a reduce-only order could still grow/flip | reject any reduce-only order that is "opening" |
| Collateral accounting | opening a position never **deducted margin from the free balance** → equity double-counted margin, "withdrawable" overstated, a withdrawal could drain funds backing a position | lock margin on open/increase, release + realize PnL on reduce/close/flip; buying-power guard; conservation journey test |
| Multi-market | size-input label hard-coded `Size (BTC)` for every market | derive base asset from the symbol (`baseAsset`) |
| Multi-market | positions marked at the **selected** market's price — a BTC position's safety-critical liq health was wrong while ETH was on screen | expose per-market `marks` in state; mark each row/summary by its own market |
| Close-only sim | "Simulate forced exit" was a **one-way trap** — no way back to Normal | add `resumeNormal()` + a "Resume normal" button (toggle) |
| Stats | the user's own position notional was mislabeled "Open interest" (a market-wide metric a single-user mock can't compute) | relabel "Your notional" |

Plus: every brand colour made to derive from a token via `color-mix` (≈20 leaked
`rgba()` literals) so a reskin is a *true* token swap; full `DarkPerpClient` API now
under test (cancel/select/recover were untested); a CI-locked **token-discipline**
test fails the build if any brand colour is hard-coded outside `:root`; and a
`theme.css` drop-slot (imported last, override cascade proven in the built bundle)
where the incoming design lands as one self-contained file.

## Rust — 5 crypto/correctness fixes on the security-sensitive crates

| Crate | Finding | Fix |
|---|---|---|
| bridge | the privacy mixer's Fisher–Yates used `r % (i+1)` — **modulo-biased**, so the shuffle (and thus the mix) wasn't uniform | rejection sampling — every permutation equally likely |
| bridge | mix PRNG reused `Domain::StateRoot` | dedicated `Domain::MixShuffle` |
| note-archive | view-key keystream reused `Domain::Nullifier` | dedicated `Domain::NoteKeystream` |
| prover (§10b) | the opened-witness zeroization was a **dead store the optimizer may elide** — plaintext could linger in prover memory | `core::hint::black_box` barrier (safe, no dep) so the wipe can't be elided |
| prover (§10b) | witness-seal keystream reused `Domain::OracleTranscript` | dedicated `Domain::WitnessSeal` |

Domain separation is now one-domain-one-purpose across the codebase, and a test locks
that **all 12 `Domain` tags hash distinctly** — so a duplicated discriminant or a
hasher that dropped the prefix fails CI.

## Invariants locked into CI (were asserted only at runtime, or not at all)

- **No crossed book** (`best_bid < best_ask`) — added to the matcher fuzzer (300 seeds);
  was only checked at loadbot runtime.
- **Node operating-loop lifecycle** — extracted the loop to a lib; a test drives
  funding → liquidation → conservation every tick.
- **Collateral conservation** (frontend) — a multi-op journey asserts free balance +
  locked margin changes only by deposits/withdrawals/realized PnL.
- **§3 proving-failure rollback** (e2e) — a settled batch stays immutable while a failed
  pending batch reverts state, flips fills MATCHED→ACCEPTED, and keeps recovery intact.
- **Live-oracle fail-safe** (oracle-feed) — a manipulated feed is rejected by the §8
  gate, not silently marked.

## Verified correct (no fix needed)

committee (Shamir GF(256) split/combine + quorum signature aggregation, with full
negative-case coverage), sequencer (`run_maintenance` + `mark_failed` rollback),
perp-core (and confirmed the frontend mock mirrors `increases_exposure` /
`is_liquidatable` exactly), and the Solidity vault/settlement (`claim` and the
challenge game are CEI / replay-safe / canonical-sig-checked; the Merkle leaf paths
are second-preimage-safe by hashing the claimed inputs). The one future risk — the
withdrawals-tree leaf encoding must match `claim` byte-for-byte once wired — is now
pinned in `SECURITY.md`.

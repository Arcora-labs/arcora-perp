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

Domain separation is one-domain-one-purpose, and a test locks that **every `Domain`
tag hashes distinctly** — so a duplicated discriminant or a hasher that dropped the
prefix fails CI. (The continuation pass below finished the sweep and grew the tag
set to 16.)

## Frontend robustness & polish (design-independent, survives any reskin)

Found by asking "what does a production trading frontend need that's missing?" rather
than hunting bugs in existing code — each is themeable/token-driven so the incoming
design inherits it for free:

- **Error boundary** — a single component fault showed a white screen; now a contained,
  token-styled fallback ("a UI fault is not a protocol action — funds/orders unaffected")
  with a reset.
- **`color-scheme: dark`** — native controls (the `<select>`, scrollbars, autofill)
  rendered light-on-dark; declared on `:root`, themeable (a light design sets `light`).
- **`prefers-reduced-motion`** — ~19 animations/transitions always played; now near-instant
  for users with vestibular sensitivity (WCAG).
- **Thousands separators** — `$59575.14` → `$59,575.14` across every price/balance;
  `parseScaled` strips them so display strings (and pasted `1,000`) round-trip. Money
  math stays bigint.
- **Live price in the tab title** — `BTC/USDC 59,575.14 · dark-perp`, so a trader watching
  several tabs sees the price at a glance.
- **`<noscript>` fallback** — a JS-disabled visitor got a blank page; now a clear message.

Plus the design handoff itself: a `theme.css` drop-slot (imported last, override cascade
proven in the built bundle for both a single token and a full light theme), the README
"Token map" contract, and a CI-locked token-discipline test.

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

## Continuation pass — sequencer/matcher correctness + a finished domain sweep

A second sweep on the protocol spine while the frontend awaited its design. Rust
totals moved **139 → 146**, frontend **59 → 83** (component-test infra added:
happy-dom + Testing Library; Explorer / Health / API-console pages). Each finding
landed with a failing-test-first regression.

| Crate | Finding | Fix |
|---|---|---|
| sequencer (§3) | `mark_settled(N)` pruned rollback snapshots for batch N **and every earlier batch** (making them hard) but advanced finality for only batch N — finalizing a height directly stranded earlier batches "hard yet MATCHED", un-withdrawable forever | settle every pending batch ≤ N; prune their order-lists too |
| matcher (§1) | expiry was checked only for the **incoming** order — a good-till-time resting maker could still be hit past its expiry | matching prunes expired makers (with STP); FOK pre-check excludes them so it can't pass then under-fill |
| matcher/sequencer (§8) | an expired maker no taker hit was never reaped → it lingered as `best_bid`/`best_ask`, anchoring the funding mark to a price no taker can reach | `reap_expired(now_ms)`, called before the mark is read each batch |
| frontend Health (§4) | the "collateral conservation" row re-derived `equity` from the same summary that *defines* it — a tautology that could never report MISMATCH | check invariants a bad state can violate: free ≥ 0, no negative position margin, solvency |

**Domain-separation sweep completed.** The earlier pass dedicated the keystream/
shuffle/seal tags; this one found three more cross-purpose reuses of the
*one-domain-one-purpose* rule and closed the last gap:

| Reuse | Purpose | Dedicated tag |
|---|---|---|
| §7 wallet KDF (owner/view/**spend**) under `StateRoot` | seed→key derivation, the most secret in the system | `KeyDerivation` (13) |
| bridge mix-bucket commitment under `NoteCommitment` | could collide with a **spendable** note commitment | `BridgeCommitment` (14) |
| committee Shamir coefficients under `Nullifier` | secret-sharing PRNG sharing the nullifier namespace | `ShamirShare` (15) |
| prover witness commitment under `BatchManifest` | a witness commitment is not a manifest hash | `WitnessCommitment` (16) |

The pairwise-distinct test now locks **all 16 `Domain` tags** hashing distinctly.
Every `hash_words` call site was audited; the only multi-use tag left is
`StateRoot` for `PublicInputs::commitment` / the proof glue, which is deliberate —
it is the cross-layer public commitment the Solidity verifier and the sp1 guest
both recompute, so it must remain a shared constant.

## Verified correct (no fix needed)

committee (Shamir GF(256) split/combine + quorum signature aggregation, with full
negative-case coverage), sequencer (`run_maintenance` + `mark_failed` rollback),
perp-core (and confirmed the frontend mock mirrors `increases_exposure` /
`is_liquidatable` exactly), and the Solidity vault/settlement (`claim` and the
challenge game are CEI / replay-safe / canonical-sig-checked; the Merkle leaf paths
are second-preimage-safe by hashing the claimed inputs). The one future risk — the
withdrawals-tree leaf encoding must match `claim` byte-for-byte once wired — is now
pinned in `SECURITY.md`.

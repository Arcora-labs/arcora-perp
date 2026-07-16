# Design decisions (ADR log)

Decisions taken while building, with the reasoning. Each references the
architecture section(s) in [`ARCHITECTURE.md`](ARCHITECTURE.md) it serves.

## ADR-0001 — Rust as the single state-transition language

**Decision.** The protocol's settlement logic (`perp-core`) is written once in
Rust and run in two places: natively in the sequencer/matcher (§1 hot path) and
**unchanged inside a zkVM guest** (SP1 / Risc0, both RISC-V Rust targets) where it
becomes the Proof-v1 circuit (§4, §10b, §12).

**Why.** §10b's "memory zarfı" point is decisive: the confidential prover runs the
*same* execution it proves, so the cleanest way to guarantee the prover and the
hot path agree is to share the exact same code. Writing the matching/risk core in
a circuit DSL (Noir) up front would (a) duplicate the logic across native + circuit
and risk divergence, and (b) front-load circuit cost before the accounting is even
settled. The roadmap's "SP1-first → hand-optimized Noir/Plonky3" ordering (§10b,
§13) maps directly onto: *Rust core now → port hot circuits to a tighter prover
later*. Rust is also the only mature toolchain available in this environment.

**Consequence.** The crate is `#![no_std]` + `alloc`, with **no floats, no clocks,
no randomness, no I/O** — verified by a `--no-default-features` build in CI/tests.
The "Noir dilini CELARI'den taşı" note (§13 Faz 0) is honored at the *circuit*
boundary in Phase 2, not by writing the core in Noir.

## ADR-0002 — Pluggable hash; Keccak-256 now, Poseidon for the circuit

**Decision.** All commitments, nullifiers, Merkle nodes, manifests, and the state
root go through a `Hasher` trait. Phase 0 instantiates it with Keccak-256.

**Why.** Phase 0's job is *accounting soundness* (§13 Faz 0), not the final proving
circuit. Keccak is audited, ubiquitous, and identical to what the L1 contracts will
hash natively (§13 Faz 2). The note-tree *shape* and the state transition are what
must be correct now; the concrete hash is a parameter the prover phase pins down by
swapping in a ZK-friendly algebraic hash (Poseidon/Poseidon2 over the proving
field) **without touching the state machine**. Domain-separation tags keep
commitments, nullifiers, and nodes in disjoint hash sub-spaces.

## ADR-0003 — Fixed-point integers, never floats

**Decision.** Quote/PnL in micro-USD (`1e6`), price `1e8`, size `1e8`; all `i128`.
Hot multiplications are `checked_*` and reject on overflow rather than wrapping.

**Why.** Determinism across native + zkVM is non-negotiable (§12); floats are
non-deterministic across targets and forbidden in most zkVMs. A silent wrap would
violate collateral conservation — the one invariant the whole system exists to
protect — so overflow is a hard reject.

## ADR-0004 — A `vault_pool` clearing term makes conservation an exact identity

**Decision.** Realized PnL and funding are routed through a single net
clearing-house balance, `vault_pool`. The conservation invariant is:

```
Σ notes + Σ position.collateral + insurance_fund + vault_pool
    == external_in − external_out
```

asserted after **every** operation (`State::conservation_holds`).

**Why.** Without a clearing term, crediting a closing position's realized gain has
no matching debit until the *counterparty* later closes, so `Σ collateral` is not
conserved per-fill. Routing every realized-PnL and funding flow through
`vault_pool` makes conservation an exact integer identity at every step — which is
precisely the form Proof-v1 (§4) needs. With matched long/short fills at one price
the pool stays bounded and nets to zero when all positions close.

## ADR-0005 — Phase-0 fills arrive already matched (matching fairness deferred)

**Decision.** The engine consumes *matched* fills (taker + maker at one price) and
proves **settlement** validity (funding, margin, liquidation, conservation). It
does **not** prove CLOB matching fairness.

**Why.** This is the staged-proof obligation split (§4): proving full
continuous-CLOB fair-matching in ZK up front is "zkVM'e komple borsa" → minutes of
proof. Phase 0 nails settlement; matching fairness is **Proof-v2** (§4), backed in
the interim by receipts + manifest + slashing (§2). The order/receipt/manifest
types already exist so the Phase 1 TEE gateway and Phase 3 slashing have a stable
wire format.

## ADR-0011 — Pre-trade risk closes the match-but-unsettleable gap (Phase 3)

**Decision.** The sequencer runs a **pre-trade risk check** before matching: an
opening/increasing order that, filled in full at the oracle mark, would leave the
trader below initial margin is rejected up front (manifest `rejected`,
`InsufficientMargin`) and never enters the book. Reducing/closing orders always
pass. (`Sequencer::pre_trade_check` + `Position::fits_initial_after`.)

**Why.** Mission 2 left a wrinkle (ADR-0005 follow-up): a fill could match in the
book yet fail settlement on margin, forcing settlement rejects that were either
double-listed or silently dropped. Checking margin *before* matching means an
admitted order is always marginable, so a matched fill never fails to settle —
`ordered`/`rejected` stay disjoint and honest (§2), and `settlement_rejected` is
empty in normal operation. The check uses the conservative oracle mark and the
worst case (full size), matching standard venue pre-trade risk.

## ADR-0006 — Per-operation atomicity

**Decision.** `Fill` and `Unbind` compute their result on copies and commit only
after all margin checks pass; a rejected op leaves state byte-for-byte unchanged.

**Why.** A state-transition function must be all-or-nothing per op, mirroring the
prover's constraint system — otherwise `apply_batch` stopping on an error would
leave a half-applied fill (one leg open, no counterparty), breaking both
conservation and the prover's reproducibility (§4).

## ADR-0007 — Conservative default risk parameters (mainnet-beta stance)

**Decision.** `Market::conservative`: 10× max leverage, 5% maintenance, 1%
liquidation fee, 10s oracle staleness, 1% confidence bound, 2% backup-deviation
bound.

**Why.** §11's mainnet stance: "tek enclave + tam protocol-completeness +
muhafazakâr pozisyon cap'leri" is a defensible mainnet-beta. Tight, explicit,
re-proven bounds (§12) over generous limits — the spec's deterministic-risk-core
principle.

## ADR-0008 — `MATCHED ≠ SETTLED`, encoded in the type system

**Decision.** `Finality { Accepted, Matched, Settled }` with
`is_withdrawable()` true *only* for `Settled`.

**Why.** §3's core principle: "bağlayıcı olan SETTLED'dır; MATCHED iyi-niyet
UX'idir, finansal kesinlik değil." Putting it in the types means the contract and
UI layers can't accidentally treat a soft preconfirmation as withdrawable.

## ADR-0009 — Receipts are secp256k1 (L1-verifiable), not Ed25519

**Decision.** The enclave signs order receipts with **secp256k1 recoverable
signatures** (`k256`), and the receipt carries `(r, s, v)`. The L1 settlement
contract recovers the signer with `ecrecover` and compares against the configured
`enclaveSigner` address.

**Why.** §2 requires the user to *submit the receipt to L1* to trigger
slashing/forced-exit. Ed25519 (the first cut in Mission 2) is not natively
verifiable on Ethereum — there is no cheap precompile — so an Ed25519 receipt
could prove ACCEPTED off-chain but never drive on-chain slashing, silently
breaking the §2 accountability loop. secp256k1 gives **one** signature that
verifies identically off-chain (`SignedReceipt::verify`) and on L1
(`ecrecover`). This was caught by an adversarial cross-layer review and is locked
by a test that signs a receipt in Rust and recovers it on-chain
(`contracts/test/CrossLayer.t.sol::test_real_rust_receipt_passes_ecrecover`).

**Consequence.** The receipt signing *digest* is identical on both sides
(`perp-core::Receipt::signing_digest` ↔ `DarkPerpSettlement.receiptDigest`), and
the public-input commitment likewise (`prover::PublicInputs::commitment` ↔
`DarkPerpSettlement.publicCommitment`). Both are pinned by byte-exact test vectors
(`crates/prover/tests/vectors.rs`) so any divergence fails CI on both sides.

## ADR-0010 — The settlement contract holds no user collateral

**Decision.** `DarkPerpSettlement` anchors roots, runs liveness/close-only, and
the slashing game (custodying only its own sequencer bond + challenge stakes);
**`CollateralVault` holds the user collateral** and releases it only against a
withdrawals root published *by* a settled batch.

**Why.** §0/§10's damage-containment: a compromised or stalled sequencer must be
able to censor or halt but **never steal user funds**. Separating the authority
(settlement — which custodies only its own bond + challenge stakes, never user
collateral) from custody of user funds (vault, settlement-gated) means fund release
is a function
of verified state, not operator action — withdrawals are only ever authorized from
SETTLED state (§3) and survive into forced-exit (§6) against the last settled
root.

# ZK-001 / ORA-001 Remediation — Publisher-Signed Oracle Transcript — Design

**Finding:** ZK-001 / ORA-001 [high] — the oracle/mark price fed into proving is an **unsigned prover-supplied witness**. `OracleTranscript { price, publish_time_ms, confidence, backup_twap }` (`crates/perp-core/src/oracle.rs:20-29`) carries no publisher key or signature, and `validate()` (`oracle.rs:45-85`) checks only price>0, freshness, a confidence ratio, and deviation vs `backup_twap` — but `backup_twap` is **another field on the same prover-supplied struct**, so the deviation gate is trivially satisfiable (`backup_twap ≈ price`). Nothing binds the price to an authenticated source. A malicious prover (or anyone feeding a witness directly to the SP1 guest) can supply **any** price and mark, liquidate, or fund at it — the price is consumed by `op_fill` (margin gate), `op_accrue_funding` (funding), `op_liquidate` (liquidation trigger + close price), and `op_unbind` (margin re-check). The docs already track this (`docs/ARCHITECTURE.md:134-139`).

This design binds every price used in-circuit to a signature from a per-market **publisher key** the prover does not control, verified **inside the circuit** — so the prover can only relay a genuinely-signed price, never fabricate one. Chosen trust model: **self-signing** (an operator-held publisher key, mirroring SEC-019's `GatewaySigner` and `committee::EnclaveSig`). This closes the prover-fabrication hole using the established trust boundary; removing operator trust from the price itself (e.g. Pyth/Wormhole attestations) is a larger, separate epic (Phase 2).

## Scope

- **`perp-core` (circuit):** `OracleTranscript` gains a `signature`; `Market` gains an `oracle_pubkey`; `OracleTranscript::validate()` gains a **fail-closed publisher-signature check** (recover signer, require `== market.oracle_pubkey`) as its first gate; a `Domain::OracleAttest` tag; and `op_accrue_funding`'s separate raw `mark` witness gets a **bounded-deviation** check against the signed price.
- **`oracle-feed` (producer):** an operator-held k256 signing key; `fetch_transcript` signs the transcript digest and attaches the signature.
- **Host (`gateway`/`sequencer`):** the signature rides as a field on `OracleTranscript`, so plumbing is mostly automatic (`set_oracle` just stores it); the operator sets each `Market.oracle_pubkey` at boot to the publisher key's address.
- **No Solidity.** The oracle never touches L1 (`contracts/` has zero `oracle`/`price` references) — this is entirely off-chain-fetch → in-circuit-validate.

**Non-goals / deferred:**
- Removing operator trust from the price (Pyth Hermes / Wormhole guardian attestations verified in-circuit) — a separate, much larger Phase-2 epic (different signature scheme, guardian-set management, expensive multi-ECDSA in-circuit). The `Market.oracle_pubkey` + `validate()` signature-check interface is kept stable so a different signature source can drop in later.
- In-circuit oracle-key **rotation**: `oracle_pubkey` is boot-time operator config via `State::add_market` (baked into the state root), same model as markets themselves; there is no in-circuit `UpdateMarket` op today, so rotation is a boot-config change. Consistent with the existing model; not expanded here.
- The end-to-end **real in-zkVM proof** (does the SP1 guest actually enforce the signature check) is a GB10/SP1 smoke-test — not local. The guest re-runs `perp-core::apply_batch`, so a correct + unit-tested `validate()` is enforced by construction; only proof generation needs the box.

## Current state (grounding)

- `OracleTranscript` (`oracle.rs:20-29`): `{ price:i128, publish_time_ms:u64, confidence:i128, backup_twap:i128 }`. `validate(&market, now_ms) -> Result<i128, OracleError>` (`:45-85`): price>0 → `NonPositivePrice`; freshness vs `market.max_oracle_staleness_ms` → `Stale`; `confidence` vs `market.max_oracle_confidence_ratio` → `LowConfidence`; deviation vs the struct's own `backup_twap` vs `market.max_oracle_deviation_ratio` → `DeviatesFromBackup`. Returns the validated `price`.
- Consumed in four `BatchOp`s (`engine.rs:59-92`): `op_fill:474`, `op_accrue_funding:589` (+ a **separate unvalidated raw `mark:i128`** witness field on `AccrueFunding`, `engine.rs:70-75`, = the sequencer book mid `sequencer/lib.rs:708`), `op_liquidate:609`, `op_unbind:795`. Each calls `oracle.validate(&market, now_ms)?` and uses the returned price directly.
- SP1 guest witness is `(DefaultState, Vec<BatchOp>, BatchManifest)` (`sp1-guest/src/main.rs:25`) → `derive_roots` → `apply_batch` → the same `validate()` path. **A signature check inside `validate()` runs in-circuit with no guest change.**
- Reusable primitive: `committee::EnclaveSig { r:[u8;32], s:[u8;32], v:u8 }` (`committee/src/lib.rs:41-71`) — `sign(key, digest)` + `recover(digest) -> Option<[u8;20]>` via `k256::ecdsa` + keccak eth-address. `committee` pulls **std** k256, so `perp-core` (no_std) cannot depend on it; instead `perp-core` adds `k256 = { default-features = false, features = ["ecdsa"] }` and a small recover mirroring `EnclaveSig::recover`.
- `Market` (`market.rs:18`) has `max_oracle_staleness_ms`, `max_oracle_confidence_ratio`, `max_oracle_deviation_ratio` (RATE_SCALE-scaled); no key field. `State::markets_digest()` (`state.rs:184`) folds markets into `state_root`, so adding a field is a **breaking** state-root change.
- `Domain` enum (`hash.rs:38`): `StateRoot=7`, `KeyDerivation=13`, etc.; a new `OracleAttest` variant needs a free discriminant.
- `oracle-feed::fetch_transcript` (`oracle-feed/src/lib.rs:97-114`): unauthenticated Crypto.com REST; `transcript_from_ticker` builds the struct; no signing.

## Design

### 1. Signed transcript format (`perp-core/src/oracle.rs`)

`OracleTranscript` gains `pub signature: OracleSig` where `OracleSig { r:[u8;32], s:[u8;32], v:u8 }` (identical layout to `committee::EnclaveSig`; recoverable secp256k1 ECDSA). The signed **digest**:

```
oracle_digest(market_id, price, publish_time_ms, confidence, backup_twap)
  = Keccak256::hash_words(Domain::OracleAttest,
      &[ word_u64(market_id), word_i128(price), word_u64(publish_time_ms),
         word_i128(confidence), word_i128(backup_twap) ])
```

(Use the crate's existing `word_u64`/`word_i128` word encoders — grep `fn word_u64`/`word_i128` in `hash.rs`; if `word_i128` is absent, add it mirroring `word_u64`.) The digest binds the **market id** (no cross-market replay), all four price fields, and the publish time (freshness is separately gated). `Domain::OracleAttest` (new discriminant) prevents any cross-preimage / cross-protocol replay.

### 2. Publisher key on the market (`perp-core/src/market.rs`)

`Market` gains `pub oracle_pubkey: [u8; 20]` — the publisher's eth-style address (single key, mirroring `CollateralVault.gatewaySigner`; extendable to an allowlist later without an interface change). It is part of `markets_digest()` → `state_root`, so the proof commits to which key each market trusts. Default/`new` requires a non-zero key (a zero key is fail-closed — see §3).

### 3. Fail-closed signature check in `validate()`

`validate()` gains, as its **FIRST** gate (before price>0/freshness/confidence/deviation):

```
let signer = self.signature.recover(&oracle_digest(market_id, self.price, self.publish_time_ms,
                                                     self.confidence, self.backup_twap))
    .ok_or(OracleError::BadOracleSig)?;          // malformed sig ⇒ reject
if signer != market.oracle_pubkey { return Err(OracleError::WrongOraclePublisher); }
```

`validate` needs the `market_id` in the digest; it already takes `&market`, so thread `market.id` (or pass `market_id` — grep `validate(` call sites and the `Market` id field). New `OracleError` variants: `BadOracleSig`, `WrongOraclePublisher`. **Fail-closed:** no/malformed signature, wrong signer, or a zero `oracle_pubkey` all reject — no price is returned, so no op proceeds. Because `backup_twap` is now inside the signed digest, the existing deviation gate becomes **meaningful** (the trusted publisher attests to the TWAP; it can't be forged to `≈price` by the prover).

### 4. Bounded mark in `op_accrue_funding` (`perp-core/src/engine.rs`)

The `mark: i128` field on `BatchOp::AccrueFunding` is today a completely unvalidated raw witness (the sequencer's book mid) used at `engine.rs:594` `f.accrue(mark, index_price, now_ms)`. After `let index = oracle.validate(...)?` succeeds, constrain `mark` to a governance-set band around the signed index:

```
// |mark - index| * RATE_SCALE <= market.max_mark_deviation_ratio * index   (checked-mul; index>0 here)
if (mark - index).unsigned_abs() ... > market.max_mark_deviation_ratio * index { return Err(EngineError::MarkOutOfBand); }
```

`Market` gains `pub max_mark_deviation_ratio` (RATE_SCALE-scaled; default e.g. `RATE_SCALE/20` = 5%, wider than the oracle-vs-twap band since a real mark-index basis is legitimate). New `EngineError::MarkOutOfBand`. This preserves the real mark-vs-index basis while stopping a prover from setting an arbitrary `mark` to manipulate the funding rate. (Use the crate's checked-mul overflow pattern already in `validate`.)

### 5. Producer signs (`crates/oracle-feed`)

`oracle-feed` gains an operator-held `k256::ecdsa::SigningKey` (env-loaded, e.g. `ORACLE_SIGNER_KEY` hex, like SEC-019's `GATEWAY_SIGNER_KEY`; a dev default for tests). After `transcript_from_ticker` builds the fields, sign `oracle_digest(market_id, ...)` and set `signature`. The signing address (derivable from the key) is what the operator configures as each `Market.oracle_pubkey` at boot; a unit test asserts the produced signature **recovers to that address** under the perp-core recover (round-trip). Add `k256` (with `ecdsa`) to `oracle-feed`'s deps (it is host-side, `std` fine).

### 6. no_std / k256 in the guest

Add to `crates/perp-core/Cargo.toml`: `k256 = { version = "0.13", default-features = false, features = ["ecdsa"] }` and whatever `sha3`/keccak the recover needs consistent with `no_std` (the crate already uses `tiny-keccak`; `EnclaveSig` uses `sha3` for the eth-address keccak — mirror one keccak path, no_std). **The one real build risk is the guest no_std build**; `cargo build -p perp-core --no-default-features` (the documented guest-path proxy, `docs/TESTING.md`) must stay green. If `k256 --no-default-features` needs an RNG/`alloc` feature for verify-only (recover needs none — it's verification, not signing, in the guest), select the minimal feature set; do NOT pull `std`.

### 7. Construction-site churn + synthetic transcripts

`OracleTranscript` and `Market` each gaining a field **breaks every construction site** (like SEC-019's `BatchOp::Deposit`). Fix all in-crate literals. The gateway's **synthetic** non-live-market transcripts (`oracle_of()`, `gateway/main.rs:1126-1133`, a sim/demo path) and any test transcript must now be **signed with a dev key** whose address is the market's `oracle_pubkey` — the honest path is that even sim transcripts go through the real signing helper (so the demo exercises the real check), OR the sim path is `!prod`-gated. Prefer signing sim transcripts with a documented dev key so the check is never bypassed in a shipped build.

## Behavior / edge cases

| Condition | Result |
|---|---|
| Transcript with no/garbage signature | `validate` → `BadOracleSig` (op rejected, in-circuit) |
| Signature valid but signer ≠ `market.oracle_pubkey` | `WrongOraclePublisher` |
| `oracle_pubkey` left zero (misconfig) | recover can't equal zero for a real sig ⇒ every price refused (fail-closed) |
| Signature for market A replayed to market B | digest binds `market_id` ⇒ signer over B's digest ≠ pubkey ⇒ refused |
| Stale (replayed old) signed price | existing freshness gate → `Stale` (signature doesn't bypass it) |
| `mark` far from signed index | `op_accrue_funding` → `MarkOutOfBand` |
| Prover fabricates a price | can't produce a publisher signature ⇒ refused |

## Components & interfaces (files)

- `crates/perp-core/src/hash.rs` — `Domain::OracleAttest`; `word_i128` if absent.
- `crates/perp-core/src/oracle.rs` — `OracleSig`, `OracleTranscript.signature`, `oracle_digest`, the `validate()` signature gate, `OracleError::{BadOracleSig, WrongOraclePublisher}`.
- `crates/perp-core/src/market.rs` — `oracle_pubkey`, `max_mark_deviation_ratio`.
- `crates/perp-core/src/engine.rs` — the `mark` band check + `EngineError::MarkOutOfBand`; thread `market_id` into `validate`.
- `crates/perp-core/Cargo.toml` — `k256` no_std.
- `crates/oracle-feed/src/lib.rs` (+ `Cargo.toml`) — signing key + sign in `fetch_transcript`.
- `crates/gateway`/`crates/sequencer` — construction-site fixes; sign synthetic transcripts / set `oracle_pubkey`.

## Testing (TDD)

Local (`cargo test -p perp-core -p oracle-feed`, `cargo build -p perp-core --no-default-features`):
1. **`oracle_digest` KAT** — pin a known-answer for a fixed `(market_id, price, time, conf, twap)` (a cross-impl anchor if the host ever recomputes it).
2. **`validate` signature gate:** a transcript signed by `market.oracle_pubkey`'s key validates; an unsigned/garbage sig → `BadOracleSig`; a valid sig by a DIFFERENT key → `WrongOraclePublisher`; a signature for a different `market_id` → refused; a zero `oracle_pubkey` → refused. Each asserts NO price is returned (fail-closed) — and mutation-check that deleting the signer comparison makes the wrong-key test go RED.
3. **Existing gates still fire** on a correctly-signed transcript (freshness/confidence/deviation), and `backup_twap` being inside the signed digest is asserted (changing `backup_twap` invalidates the signature).
4. **`op_accrue_funding` mark band:** `mark` within band accrues; `mark` outside → `MarkOutOfBand`; the signed index is what the band is measured against.
5. **oracle-feed round-trip:** `fetch_transcript` (over a canned ticker fixture) produces a transcript whose signature recovers to the signer key's address; feeding it to `validate` with that address as `oracle_pubkey` passes.
6. **no_std build green:** `cargo build -p perp-core --no-default-features`.

Deferred to the GB10/SP1 box (tracked): generate a real proof over a batch with a signed oracle op and confirm the guest enforces `BadOracleSig`/`WrongOraclePublisher` (i.e. k256 recover works inside the zkVM); the redeploy/rollout notes ride with SEC-019's deploy gate (state-root arity changed again — Market gained two fields).

## Deferred to Phase 2 (tracked)

Trust-minimized price source (Pyth Hermes pull updates + in-circuit Wormhole guardian-quorum verification), removing operator trust from the price. The `Market.oracle_pubkey` + `validate()` signature interface stays; only the signature source/scheme and key-set management change. In-circuit oracle-key rotation (an `UpdateMarket` governance op) if boot-config rotation proves insufficient.

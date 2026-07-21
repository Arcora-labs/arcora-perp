# ZK-001 Publisher-Signed Oracle Transcript Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bind every price used in-circuit to a per-market publisher signature verified inside the circuit, so a malicious prover can only relay a genuinely-signed price, never fabricate one — closing ZK-001/ORA-001.

**Architecture:** `OracleTranscript` gains a recoverable-ECDSA `signature` over a `Domain::OracleAttest` digest of `(market_id, price, publish_time_ms, confidence, backup_twap)`; `Market` gains `oracle_pubkey` (the trusted publisher's eth-address, committed via `markets_digest`→`state_root`); `OracleTranscript::validate()` recovers the signer and refuses unless it equals `market.oracle_pubkey`. `oracle-feed` signs with an operator key. The SP1 guest re-runs `perp-core`, so the check is enforced in-circuit for free. Also bounds the separate unvalidated `mark` witness in `op_accrue_funding`.

**Tech Stack:** Rust `perp-core` (no_std, `cargo test` + `cargo build --no-default-features`), `oracle-feed`/`gateway`/`sequencer` (host, `cargo test`). k256 ECDSA (no_std in the guest). No Solidity. Design doc: `docs/superpowers/specs/2026-07-21-zk001-signed-oracle-design.md`.

## Global Constraints

- **Fail-closed signature gate:** `validate()` returns a price ONLY if `signature.recover(oracle_digest(...)) == market.oracle_pubkey`. No/malformed sig ⇒ `BadOracleSig`; wrong signer ⇒ `WrongOraclePublisher`; zero `oracle_pubkey` ⇒ refused (a real sig never recovers to the zero address). This gate runs FIRST, before price>0/freshness/confidence/deviation.
- **Digest binds market + all price fields:** `oracle_digest = Keccak256::hash_words(Domain::OracleAttest, [word_u64(market_id), word_i128(price), word_u64(publish_time_ms), word_i128(confidence), word_i128(backup_twap)])`. Binding `market_id` blocks cross-market replay; binding `backup_twap` makes the existing deviation gate meaningful.
- **no_std / guest:** perp-core stays `no_std`; k256 added with `default-features = false, features = ["ecdsa"]`; `cargo build -p perp-core --no-default-features` MUST stay green (the guest-path proxy). Never pull `std` into perp-core.
- **Recoverable-ECDSA convention** matches `committee::EnclaveSig` and SEC-019: `{r:[u8;32], s:[u8;32], v:u8}`, `v = 27 + recid`, signer = keccak-eth-address of the recovered key. Do not diverge (host and any future L1/committee reuse must interop).
- **Breaking state-root change expected** (Market gains 2 fields → `markets_digest` → `state_root`) — testnet redeploy, no back-compat shims; re-pin any pinned state-root/commitment KAT.
- **Market has `pub id: MarketId` (market.rs:19)** — `validate(&market, now_ms)` already has `market.id`; use it in the digest (no `validate` signature change needed for the id).
- **fmt/build:** `cargo fmt` hunk-scoped (repo not fmt-clean at HEAD); `cargo clippy -p <crate> --all-targets` clean.

---

### Task 1: Crypto foundation — `Domain::OracleAttest`, `word_i128`, `oracle_digest`, `OracleSig` recover (no_std)

**Files:**
- Modify: `crates/perp-core/Cargo.toml` (add k256 no_std)
- Modify: `crates/perp-core/src/hash.rs` (`Domain::OracleAttest`, `word_i128` if absent)
- Modify: `crates/perp-core/src/oracle.rs` (`OracleSig`, `oracle_digest`)
- Test: `crates/perp-core/src/oracle.rs` (`#[cfg(test)]`)

**Interfaces:**
- Produces:
```rust
// hash.rs
pub enum Domain { /* ...existing... */ OracleAttest = <free discriminant> }
pub fn word_i128(v: i128) -> Digest;   // if not already present; mirror word_u64
// oracle.rs
pub struct OracleSig { pub r: [u8;32], pub s: [u8;32], pub v: u8 }
impl OracleSig {
    pub fn sign(key: &k256::ecdsa::SigningKey, digest: &Digest) -> Self;   // host/test convenience
    pub fn recover(&self, digest: &Digest) -> Option<[u8;20]>;             // no_std verify path
}
pub fn oracle_digest(market_id: u64, price: i128, publish_time_ms: u64, confidence: i128, backup_twap: i128) -> Digest;
```
- Consumes: `Keccak256::hash_words`, `Domain`, `word_u64` (existing in `hash.rs`).

- [ ] **Step 1: add k256 no_std + write the failing test**

In `crates/perp-core/Cargo.toml` add under `[dependencies]`: `k256 = { version = "0.13", default-features = false, features = ["ecdsa"] }` (grep how `committee/Cargo.toml` declares k256 and mirror, but with `default-features = false`). Then the test (mirror `committee::EnclaveSig`'s round-trip test — grep `EnclaveSig` tests):
```rust
#[test]
fn oracle_sig_round_trips_and_binds_digest() {
    use k256::ecdsa::SigningKey;
    let key = SigningKey::from_bytes((&[7u8;32]).into()).unwrap();
    let addr = { // eth address of key's verifying key — mirror committee::eth_address
        // ... compute expected signer address ...
    };
    let d = oracle_digest(1, 100_000, 1_700_000_000_000, 500, 100_000);
    let sig = OracleSig::sign(&key, &d);
    assert_eq!(sig.recover(&d), Some(addr));           // recovers to signer
    let d2 = oracle_digest(2, 100_000, 1_700_000_000_000, 500, 100_000); // different market_id
    assert_ne!(sig.recover(&d2), Some(addr));          // sig for market 1 doesn't verify over market 2's digest
    // KAT: pin the digest so a host re-impl can cross-check
    assert_eq!(d, /* KAT hex, filled after first run */ );
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p perp-core oracle_sig_round_trips`
Expected: FAIL — `OracleSig`/`oracle_digest`/`word_i128`/`Domain::OracleAttest` undefined.

- [ ] **Step 3: Implement**

`hash.rs`: add `OracleAttest = <next free discriminant>` to `Domain` (grep the enum for taken values; pick an unused one and add it to any exhaustive match/`ALL` list). Add `word_i128` if absent:
```rust
pub fn word_i128(v: i128) -> Digest { let mut w = [0u8;32]; w[16..].copy_from_slice(&v.to_be_bytes()); w }
```
`oracle.rs`:
```rust
pub struct OracleSig { pub r: [u8;32], pub s: [u8;32], pub v: u8 }
impl OracleSig {
    pub fn sign(key: &k256::ecdsa::SigningKey, digest: &Digest) -> Self {
        let (sig, recid) = key.sign_prehash_recoverable(digest).expect("sign");
        let b = sig.to_bytes(); let (mut r, mut s) = ([0u8;32],[0u8;32]);
        r.copy_from_slice(&b[..32]); s.copy_from_slice(&b[32..]);
        Self { r, s, v: 27 + recid.to_byte() }
    }
    pub fn recover(&self, digest: &Digest) -> Option<[u8;20]> {
        use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
        let mut rs = [0u8;64]; rs[..32].copy_from_slice(&self.r); rs[32..].copy_from_slice(&self.s);
        let sig = Signature::from_slice(&rs).ok()?;
        let recid = self.v.checked_sub(27).and_then(RecoveryId::from_byte)?;
        let vk = VerifyingKey::recover_from_prehash(digest, &sig, recid).ok()?;
        Some(eth_address(&vk))   // mirror committee::eth_address (keccak of uncompressed pubkey[1..], last 20)
    }
}
pub fn oracle_digest(market_id: u64, price: i128, publish_time_ms: u64, confidence: i128, backup_twap: i128) -> Digest {
    Keccak256::hash_words(Domain::OracleAttest, &[
        word_u64(market_id), word_i128(price), word_u64(publish_time_ms), word_i128(confidence), word_i128(backup_twap),
    ])
}
```
Add a private `eth_address(&VerifyingKey) -> [u8;20]` mirroring `committee::eth_address` (keccak256 of the uncompressed point `[1..]`, take `[12..]`); use the no_std keccak already in the crate.

- [ ] **Step 4: Run to verify it passes; pin the KAT + no_std build**

Run: `cargo test -p perp-core oracle_sig_round_trips` (fill the KAT hex from `--nocapture`), then `cargo test -p perp-core`, then **`cargo build -p perp-core --no-default-features`** (the guest path — MUST compile with k256 no_std; if it needs a feature toggle for verify-only, add the minimal one, never `std`). `cargo clippy -p perp-core --all-targets` clean.
Expected: PASS + no_std build clean.

- [ ] **Step 5: Commit**

```bash
git add crates/perp-core/Cargo.toml crates/perp-core/src/hash.rs crates/perp-core/src/oracle.rs
git commit -m "feat(perp-core): ZK-001 oracle signature primitive + digest (no_std k256, Domain::OracleAttest)"
```

---

### Task 2: `Market` publisher key + mark band field

**Files:**
- Modify: `crates/perp-core/src/market.rs` (`oracle_pubkey`, `max_mark_deviation_ratio`, constructors)
- Test: `crates/perp-core/src/market.rs` / `state.rs` (`#[cfg(test)]`)

**Interfaces:**
- Produces: `Market.oracle_pubkey: [u8;20]`, `Market.max_mark_deviation_ratio: i128`; folded into `markets_digest()`.
- Consumes: nothing from Task 1.

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn market_binds_oracle_pubkey_in_digest() {
    let mut s = DefaultState::new(16);
    let mut m = Market::conservative(1); m.oracle_pubkey = [0xAB;20];
    s.add_market(m);
    let r0 = s.markets_digest();
    let mut s2 = DefaultState::new(16);
    let mut m2 = Market::conservative(1); m2.oracle_pubkey = [0xCD;20];
    s2.add_market(m2);
    assert_ne!(s.markets_digest(), s2.markets_digest(), "oracle_pubkey must be in markets_digest");
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p perp-core market_binds_oracle_pubkey`
Expected: FAIL — `oracle_pubkey` field absent.

- [ ] **Step 3: Implement**

Add `pub oracle_pubkey: [u8;20]` and `pub max_mark_deviation_ratio: i128` to `struct Market`. Initialize in EVERY constructor (`conservative`, `with_fees`, any `new`/builder — grep `Market {` and `impl Market`): `oracle_pubkey: [0u8;20]` (a zero default is fail-closed — real deployments set it), `max_mark_deviation_ratio: RATE_SCALE / 20` (5%). In `markets_digest()` (`state.rs:184`), fold BOTH new fields into the per-market hash the same way existing `Market` fields are folded (grep how `markets_digest` serializes a `Market` — mirror it; `oracle_pubkey` as its 20 bytes, `max_mark_deviation_ratio` via the ratio-word encoding siblings use).

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p perp-core` (new + all pre-existing; re-pin any pinned `markets_digest`/`state_root` KAT — report which). `cargo build -p perp-core --no-default-features` green. `cargo clippy -p perp-core --all-targets` clean.

- [ ] **Step 5: Commit**

```bash
git add crates/perp-core/src/market.rs crates/perp-core/src/state.rs
git commit -m "feat(perp-core): ZK-001 Market.oracle_pubkey + max_mark_deviation_ratio (in markets_digest)"
```

---

### Task 3: Signed `OracleTranscript` + fail-closed `validate()` gate

**Files:**
- Modify: `crates/perp-core/src/oracle.rs` (`OracleTranscript.signature`, `validate()` gate, `OracleError` variants)
- Test: `crates/perp-core/src/oracle.rs` (`#[cfg(test)]`)

**Interfaces:**
- Consumes: `OracleSig`/`oracle_digest` (Task 1), `Market.oracle_pubkey` (Task 2).
- Produces: `OracleTranscript { price, publish_time_ms, confidence, backup_twap, signature: OracleSig }`; `validate` unchanged signature (`&self, &Market, u64) -> Result<i128, OracleError>`; `OracleError::{BadOracleSig, WrongOraclePublisher}`.

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn validate_requires_correct_publisher_signature() {
    use k256::ecdsa::SigningKey;
    let key = SigningKey::from_bytes((&[7u8;32]).into()).unwrap();
    let addr = /* eth address of key */;
    let mut mkt = Market::conservative(1); mkt.oracle_pubkey = addr;
    let now = 1_700_000_000_000u64;
    let (price, conf, twap) = (100_000i128, 100i128, 100_000i128);
    let d = oracle_digest(mkt.id, price, now, conf, twap);
    let good = OracleTranscript { price, publish_time_ms: now, confidence: conf, backup_twap: twap, signature: OracleSig::sign(&key, &d) };
    assert_eq!(good.validate(&mkt, now).unwrap(), price);           // signed by the market's key ⇒ OK

    let garbage = OracleTranscript { signature: OracleSig{r:[0;32],s:[0;32],v:27}, ..good.clone() };
    assert!(matches!(garbage.validate(&mkt, now), Err(OracleError::BadOracleSig)));

    let other = SigningKey::from_bytes((&[9u8;32]).into()).unwrap();
    let wrong = OracleTranscript { signature: OracleSig::sign(&other, &d), ..good.clone() };
    assert!(matches!(wrong.validate(&mkt, now), Err(OracleError::WrongOraclePublisher)));

    let mut zmkt = mkt.clone(); zmkt.oracle_pubkey = [0u8;20];
    assert!(good.validate(&zmkt, now).is_err());                    // zero pubkey ⇒ refused

    // backup_twap is signed: tampering it invalidates the sig
    let tampered = OracleTranscript { backup_twap: twap + 1, ..good.clone() };
    assert!(tampered.validate(&mkt, now).is_err());
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p perp-core validate_requires_correct_publisher`
Expected: FAIL — `signature` field / error variants absent.

- [ ] **Step 3: Implement**

Add `pub signature: OracleSig` to `OracleTranscript`. Add `BadOracleSig`, `WrongOraclePublisher` to `OracleError`. In `validate()`, as the FIRST statements (before price>0):
```rust
    let d = oracle_digest(market.id, self.price, self.publish_time_ms, self.confidence, self.backup_twap);
    let signer = self.signature.recover(&d).ok_or(OracleError::BadOracleSig)?;
    if signer != market.oracle_pubkey { return Err(OracleError::WrongOraclePublisher); }
```
Keep the existing price>0/freshness/confidence/deviation gates AFTER, unchanged.

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p perp-core` (fix every in-crate `OracleTranscript { .. }` literal to add `signature` — grep `OracleTranscript {` in perp-core; a test helper that signs with a known key + sets the market's `oracle_pubkey` keeps them DRY). `cargo build -p perp-core --no-default-features` green. `cargo clippy` clean.

- [ ] **Step 5: Commit**

```bash
git add crates/perp-core/src/oracle.rs
git commit -m "fix(perp-core): ZK-001 fail-closed publisher-signature gate in OracleTranscript::validate"
```

---

### Task 4: Bounded `mark` in `op_accrue_funding`

**Files:**
- Modify: `crates/perp-core/src/engine.rs` (`op_accrue_funding` mark band, `EngineError::MarkOutOfBand`)
- Test: `crates/perp-core/src/engine.rs` (`#[cfg(test)]`)

**Interfaces:**
- Consumes: `Market.max_mark_deviation_ratio` (Task 2), the validated `index` price (Task 3).
- Produces: `EngineError::MarkOutOfBand`.

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn accrue_funding_bounds_mark_against_signed_index() {
    // build a signed AccrueFunding op with mark within band ⇒ Ok; mark far outside ⇒ MarkOutOfBand
    // (reuse the Task-3 signing helper; market.max_mark_deviation_ratio default 5%)
    // in-band: mark = index * 101/100 ⇒ Ok
    // out-of-band: mark = index * 2 ⇒ Err(EngineError::MarkOutOfBand)
}
```
(Model the op construction on an existing `op_accrue_funding` test — grep `AccrueFunding` in engine tests.)

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p perp-core accrue_funding_bounds_mark`
Expected: FAIL — no band check / `MarkOutOfBand` undefined.

- [ ] **Step 3: Implement**

Add `MarkOutOfBand` to `EngineError`. In `op_accrue_funding` (`engine.rs:~589`), after `let index = oracle.validate(&market, now_ms)?;` and before `f.accrue(mark, index, now_ms)`:
```rust
    // |mark - index| * RATE_SCALE <= max_mark_deviation_ratio * index  (index>0 here; checked-mul)
    let dev = (mark - index).unsigned_abs();
    let lhs = dev.checked_mul(RATE_SCALE as u128).ok_or(EngineError::Overflow)?;
    let rhs = (market.max_mark_deviation_ratio as u128).checked_mul(index as u128).ok_or(EngineError::Overflow)?;
    if lhs > rhs { return Err(EngineError::MarkOutOfBand); }
```
(Match the exact checked-mul/overflow idiom `oracle::validate` uses for its ratio checks — grep it; adapt types. `index>0` is guaranteed by `validate`.)

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p perp-core`. `cargo build -p perp-core --no-default-features` green. `cargo clippy` clean.

- [ ] **Step 5: Commit**

```bash
git add crates/perp-core/src/engine.rs
git commit -m "fix(perp-core): ZK-001 bound AccrueFunding.mark to a band around the signed index"
```

---

### Task 5: `oracle-feed` signs transcripts

**Files:**
- Modify: `crates/oracle-feed/Cargo.toml` (k256 host), `crates/oracle-feed/src/lib.rs` (signing key + sign in `fetch_transcript`/`transcript_from_ticker`)
- Test: `crates/oracle-feed/src/lib.rs` (`#[cfg(test)]`)

**Interfaces:**
- Consumes: `perp_core::oracle::{OracleSig, oracle_digest}` (Task 1), the market id.
- Produces: signed `OracleTranscript`s; the signer address the operator sets as `Market.oracle_pubkey`.

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn produced_transcript_signature_recovers_to_signer() {
    let key = /* test SigningKey */;
    let addr = /* its eth address */;
    let t = transcript_from_ticker(&canned_ticker(), MARKET_ID, &key);  // new signing param
    let d = perp_core::oracle::oracle_digest(MARKET_ID, t.price, t.publish_time_ms, t.confidence, t.backup_twap);
    assert_eq!(t.signature.recover(&d), Some(addr));
    // and it validates under a market whose oracle_pubkey == addr
    let mut m = Market::conservative(MARKET_ID); m.oracle_pubkey = addr;
    assert!(t.validate(&m, t.publish_time_ms).is_ok());
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p oracle-feed produced_transcript_signature`
Expected: FAIL — no signing param / signature not set.

- [ ] **Step 3: Implement**

Add `k256 = { version = "0.13", features = ["ecdsa"] }` to `oracle-feed/Cargo.toml` (host — `std` fine). `transcript_from_ticker` (and `fetch_transcript`) gain a `signer: &SigningKey` + `market_id: u64`; after building the price fields, compute `d = oracle_digest(market_id, price, publish_time_ms, confidence, backup_twap)` and set `signature: OracleSig::sign(signer, &d)`. Load the key from env (`ORACLE_SIGNER_KEY` hex) with a documented dev default in a `fn signer_from_env()` (mirror SEC-019's `GatewaySigner::from_env`); print the derived address at boot so the operator can set `Market.oracle_pubkey`. Update the crate's existing 11 tests to pass a signer + market id (a shared test helper).

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p oracle-feed`. `cargo clippy -p oracle-feed --all-targets` clean.

- [ ] **Step 5: Commit**

```bash
git add crates/oracle-feed/Cargo.toml crates/oracle-feed/src/lib.rs
git commit -m "feat(oracle-feed): ZK-001 sign oracle transcripts with the operator publisher key"
```

---

### Task 6: Host wiring + construction-site fixes + no_std/workspace green

**Files:**
- Modify: `crates/gateway/src/main.rs` (sign synthetic `oracle_of()` transcripts / set `oracle_pubkey`; feed the signer to `oracle-feed`; set each `Market.oracle_pubkey` at boot), `crates/sequencer/src/lib.rs` + any other crate constructing `OracleTranscript`/`Market` (node/e2e/demo)
- Test: `crates/gateway` (`#[cfg(test)]`)

**Interfaces:**
- Consumes: Tasks 1-5.

- [ ] **Step 1: enumerate the breakage + write a failing test**

Run `cargo build --workspace 2>&1 | head -40` to list every broken `OracleTranscript { .. }` / `Market { .. }` / `validate(` / `AccrueFunding` site. Write a gateway test that a live-market oracle set via the real path validates in-circuit-style (a transcript the gateway produced passes `validate` against the market whose `oracle_pubkey` the gateway configured):
```rust
#[test]
fn gateway_oracle_path_produces_a_validatable_signed_transcript() {
    // set up a market with oracle_pubkey = the gateway's oracle signer address;
    // drive the oracle path (real or apply_real_oracle); assert the stored transcript validate()s
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo build --workspace` (compile errors) then `cargo test -p gateway gateway_oracle_path_produces`
Expected: FAIL (won't compile / no signing wired).

- [ ] **Step 3: Implement**

Thread the oracle signer + market ids through the gateway's oracle fetch (`apply_real_oracle`/the `oracle_feed::fetch_transcript` call at `gateway/main.rs:5856`). For the **synthetic** `oracle_of()` non-live path (`gateway/main.rs:1126-1133`), sign the transcript with the same dev/operator oracle key so it passes `validate` (do NOT leave it unsigned — an unsigned sim transcript would be rejected by the new gate; sign it, or `!prod`-gate the sim path and set a matching `oracle_pubkey`). At boot, set each `Market.oracle_pubkey` to the oracle signer's address (grep `add_market`/`Market::conservative` in `gateway/main.rs:1405`). Fix every remaining broken `OracleTranscript`/`Market` literal across `sequencer`/`node`/`e2e`/`demo` (sign test/seed transcripts with a shared helper + a known key, and set the corresponding `oracle_pubkey`).

- [ ] **Step 4: Run to verify it passes + whole workspace**

Run: `cargo test --workspace` (all green; re-pin any broken state-root/KAT test) then `cargo build -p perp-core --no-default-features` (guest path) then `cargo clippy --workspace --all-targets` clean.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(host): ZK-001 wire oracle signing through gateway/sequencer; sign synthetic transcripts; set Market.oracle_pubkey"
```

---

## Self-Review

**Spec coverage:** §1 signed format → Task 1 (`oracle_digest`/`OracleSig`); §2 publisher key → Task 2; §3 fail-closed `validate` gate → Task 3; §4 bounded mark → Task 4; §5 producer signs → Task 5; §6 no_std/k256 → verified in every task's Step 4 (`--no-default-features`), added in Task 1; §7 construction churn + synthetic-transcript signing → Task 6. ✓

**Placeholder scan:** the `<free discriminant>`, `/* eth address of key */`, `/* KAT hex, filled after first run */`, and "grep how X does it" markers are real "compute/locate this concrete value" instructions, not vague TODOs — each names exactly what to substitute and where it comes from (KAT is pinned in Task 1 Step 4; the eth-address helper mirrors `committee::eth_address`; the Domain discriminant is the next free enum value). The signing/recover code is given in full.

**Type consistency:** `OracleSig{r,s,v}` (== committee shape), `oracle_digest(u64,i128,u64,i128,i128)->Digest`, `Market.oracle_pubkey:[u8;20]` / `max_mark_deviation_ratio:i128`, `OracleTranscript.signature:OracleSig`, `OracleError::{BadOracleSig,WrongOraclePublisher}`, `EngineError::MarkOutOfBand`, `validate(&self,&Market,u64)->Result<i128,OracleError>` (unchanged sig; uses `market.id`) are consistent across tasks. Task 1 is the crypto+no_std risk, front-loaded so a k256-no_std problem surfaces immediately.

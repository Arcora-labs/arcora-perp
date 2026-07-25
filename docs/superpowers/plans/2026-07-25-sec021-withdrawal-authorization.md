# SEC-021 / SEC-021b Withdrawal Authorization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make every withdrawal require a secp256k1 signature from an address the account has proven it controls, and stop a leaked API key from rebinding that address.

**Architecture:** Gateway-only. A withdrawal's *authorizing address* is the registered `signer` for caller-signed accounts, otherwise the bound `deposit_address` (which the account already signed with at bind time). The signature covers a domain-separated, deployment-bound digest carrying every field that moves money, replay-protected by a withdrawal nonce that is separate from the order nonce and committed only after the withdrawal fully succeeds. Separately, rebinding the deposit address now requires a signature from the currently bound address — without this the whole scheme is bypassable with just the API key.

**Tech Stack:** Rust (axum, k256, sha3/Keccak256, serde/postcard), TypeScript/React frontend (raw EIP-1193 `personal_sign`, no ethers/viem).

## Global Constraints

- **Gateway crate only.** No changes to `perp-core`, `sequencer`, or `contracts/`. Touching `perp-core` risks changing the SP1 guest ELF and therefore the deployed vkey (`0x000a2f9b…` on verifier `0x8012F3b3`); GATE-1 already caught one such drift.
- **No new dependencies.** Everything needed (`k256`, `sha3`, `serde_json`) is already in the gateway's `Cargo.toml`.
- **Fail-closed:** every rejection returns `Err` with **no** state mutation and **no** nonce advance.
- **Authorization lives in the engine methods**, not the HTTP handlers — the existing unit tests call `gw.account_withdraw(...)` directly and must be able to observe it.
- **Digest domain prefixes are exact ASCII, no trailing space:** `"dark-perp:withdraw:"`, `"dark-perp:lp-withdraw:"`, `"dark-perp:rebind-deposit:"`. They must not collide with the existing `"dark-perp:bind-deposit:"`.
- **All digest fields are fixed-width big-endian.** No length prefixes, no variable-length fields.
- Run `cargo test -p gateway` after every task; run `cargo clippy --workspace --all-targets -- -D warnings` before each commit.
- Commit message style: `fix(gateway): SEC-021 …` / `fix(gateway): SEC-021b …`, matching the repo's existing subject lines.

## File Structure

| File | Responsibility | Change |
|---|---|---|
| `crates/gateway/src/main.rs` | everything below (single-file crate, follow existing layout) | modify |
| ↳ `eip191_prehash_candidates` (~`:4088`) | shared 3-shape prehash helper | rename from `deposit_bind_prehash_candidates` |
| ↳ `withdraw_auth_digest` / `lp_withdraw_auth_digest` / `rebind_auth_digest` (new, beside `deposit_bind_digest` ~`:4073`) | digest construction | create |
| ↳ `Gw.chain_id` / `Gw.vault` (~`:1091`, beside `prod`) | deployment binding, `#[serde(skip)]` | create |
| ↳ `Account.last_withdraw_nonce` (~`:977`) | withdrawal replay protection | create |
| ↳ `Gw::authorizing_address` (new) | the single authorization rule | create |
| ↳ `Gw::account_set_deposit_address` (`:1676`) | rebind lock | modify |
| ↳ `Gw::account_withdraw` (`:1875`) | signed withdrawal | modify |
| ↳ `Gw::account_lp_withdraw` (new, beside `lp_withdraw` `:2808`) | authorized LP entry point | create |
| ↳ `Gw::lp_withdraw` (`:2808`) | raw engine primitive — **unchanged**, legacy caller keeps working | none |
| ↳ `Gw::v1_account` (`:2467`) | expose binding state to the client | modify |
| ↳ `WithdrawReq` (`:3889`), `LpWithdrawReq` (`:5029`), `DepositAddrReq` (`:3860`) | request schemas | modify |
| `frontend/src/api/realClient.ts` | sign + submit withdrawals | modify |
| `frontend/src/components/AccountPanel.tsx` | wallet-signed withdrawal UI | modify |
| `frontend/src/api/realClient.test.ts` | request-body expectations | modify |
| `docs/API.md`, `docs/SECURITY.md`, `docs/public-site/{api,trading}.html` | documentation | modify |

---

### Task 1: Generalize the EIP-191 prehash helper

Pure rename + doc update, no behavior change. Doing it first keeps every later task calling one shared helper.

**Files:**
- Modify: `crates/gateway/src/main.rs:4082-4124` (the function + its doc comment)
- Modify: `crates/gateway/src/main.rs:1688-1697` (the one call site)
- Modify: `crates/gateway/src/main.rs:3863-3866` (`DepositAddrReq` doc comment referencing the old name)

**Interfaces:**
- Produces: `fn eip191_prehash_candidates(digest: &[u8; 32]) -> [[u8; 32]; 3]`

- [ ] **Step 1: Rename the function and generalize its doc comment**

Replace the doc comment and signature at `main.rs:4082-4088`:

```rust
/// The three prehashes a gateway-local authorization signature may cover, in the
/// order they are tried. SECURITY INVARIANT: every candidate is a deterministic
/// transform of the SAME caller-independent digest — no attacker-chosen message
/// ever enters a preimage — so accepting any of them leaves the authorization
/// semantics unchanged: a valid signature still proves the signer consented to
/// exactly the fields that digest binds. Shared by the deposit-address bind
/// (`deposit_bind_digest`) and by withdrawal authorization (`withdraw_auth_digest`,
/// `lp_withdraw_auth_digest`, `rebind_auth_digest`).
fn eip191_prehash_candidates(digest: &[u8; 32]) -> [[u8; 32]; 3] {
```

Leave the body (the three `raw` / `eip191_raw` / `eip191_hex` candidates) exactly as it is.

- [ ] **Step 2: Update the call site**

At `main.rs:1695`, change `deposit_bind_prehash_candidates(&digest)` to `eip191_prehash_candidates(&digest)`.

- [ ] **Step 3: Update the stale reference in the request-struct doc**

At `main.rs:3866`, change `see \`deposit_bind_prehash_candidates\`` to `see \`eip191_prehash_candidates\``.

- [ ] **Step 4: Verify no references remain**

Run: `rg 'deposit_bind_prehash_candidates' crates/`
Expected: no output.

- [ ] **Step 5: Run the existing tests**

Run: `cargo test -p gateway 2>&1 | tail -5`
Expected: all pass, same count as before the change (the three-shape bind test at `main.rs:7935-8007` must still pass).

- [ ] **Step 6: Commit**

```bash
git add crates/gateway/src/main.rs
git commit -m "refactor(gateway): SEC-021 — generalize deposit_bind_prehash_candidates to eip191_prehash_candidates

Shared by the upcoming withdrawal-authorization digests. Body unchanged;
rename + doc only, so the security invariant it documents now reads as the
general rule rather than a bind-specific one."
```

---

### Task 2: Deployment binding on `Gw` + the three digests

**Files:**
- Modify: `crates/gateway/src/main.rs:1085-1091` (add fields beside `prod`)
- Modify: `crates/gateway/src/main.rs:5608` (boot wiring, beside `gw.prod = prod`)
- Modify: `crates/gateway/src/main.rs:6730` (demo/test constructor)
- Create: three digest functions beside `deposit_bind_digest` (`main.rs:4073-4080`)
- Test: `crates/gateway/src/main.rs` (in the existing `#[cfg(test)] mod` alongside the bind-digest tests)

**Interfaces:**
- Consumes: `eip191_prehash_candidates` (Task 1)
- Produces:
  - `Gw.chain_id: u64`, `Gw.vault: [u8; 20]` (both `#[serde(skip)]`)
  - `fn withdraw_auth_digest(chain_id: u64, vault: &[u8;20], owner: &PubKey, market_id: u64, amount: i128, to: &[u8;20], nonce: u64) -> [u8;32]`
  - `fn lp_withdraw_auth_digest(chain_id: u64, vault: &[u8;20], owner: &PubKey, shares: u128, nonce: u64) -> [u8;32]`
  - `fn rebind_auth_digest(chain_id: u64, vault: &[u8;20], owner: &PubKey, rebind_counter: u64, old_addr: &[u8;20], new_addr: &[u8;20]) -> [u8;32]`

- [ ] **Step 1: Add the deployment-binding fields to `Gw`**

Insert immediately after the `prod` field at `main.rs:1091`:

```rust
    /// SEC-021: the deployment this gateway's withdrawal-authorization signatures are
    /// bound to (L1 chain id + vault address). Mixed into every withdrawal/rebind digest
    /// so a snapshot restored or copied onto a DIFFERENT deployment cannot accept a
    /// signature minted for this one — the signed nonce is not the withdrawal-leaf nonce
    /// (that is the gateway-global `next_withdraw_nonce`), so one authorization could
    /// otherwise become different claim leaves on two deployments. NOT persisted —
    /// recomputed from the environment at boot, exactly like `prod`.
    #[serde(skip)]
    chain_id: u64,
    #[serde(skip)]
    vault: [u8; 20],
```

- [ ] **Step 2: Wire them at boot**

At `main.rs:5608`, immediately after `gw.prod = prod;`, add:

```rust
    // SEC-021: bind withdrawal authorization to this deployment. Same source the
    // deposit-authorization signer uses, so both digests agree on chain id + vault.
    gw.chain_id = gateway_signer.chain_id;
    gw.vault = gateway_signer.vault;
```

`GatewaySigner`'s `chain_id`/`vault` fields (`main.rs:3976-3977`) are private to the module but in the same file, so direct field access compiles. If `gateway_signer` is moved into `App` before this line, move these two assignments above that move.

- [ ] **Step 3: Give `Gw::new`/`boot` a defined default**

Both fields are `#[serde(skip)]`, so a snapshot restore leaves them at `0`/`[0u8; 20]`. That is a *valid* dev identity but must not be reached silently in production, so set them explicitly wherever a `Gw` is constructed. In whichever constructor the crate uses (`Gw::new` — find it with `rg -n 'fn new\(' crates/gateway/src/main.rs` and match the surrounding field-init style), initialize:

```rust
            // SEC-021: overwritten at boot from GatewaySigner. Base Sepolia + zero
            // vault is the same fallback GatewaySigner::from_env uses, so the demo
            // build and unit tests get a coherent (if non-unique) deployment identity.
            chain_id: 84532,
            vault: [0u8; 20],
```

The boot wiring in Step 2 then overwrites both for the real deployment. `boot_restored` (`main.rs:1586-1615`) already re-applies non-persisted config after a restore — verify these two fields are set on that path too, the same way `mkts` is rebuilt at `:1615` and `prod` at `:5608`.

- [ ] **Step 4: Write the failing digest tests**

Add to the test module, beside the existing bind-digest tests:

```rust
#[test]
fn withdraw_auth_digest_binds_every_field() {
    let owner: PubKey = [7u8; 32];
    let to = [0x11u8; 20];
    let vault = [0x22u8; 20];
    let base = withdraw_auth_digest(84532, &vault, &owner, 0, 1_000, &to, 1);

    // Every field must change the digest.
    assert_ne!(base, withdraw_auth_digest(1, &vault, &owner, 0, 1_000, &to, 1));
    assert_ne!(base, withdraw_auth_digest(84532, &[0x33u8; 20], &owner, 0, 1_000, &to, 1));
    assert_ne!(base, withdraw_auth_digest(84532, &vault, &[8u8; 32], 0, 1_000, &to, 1));
    assert_ne!(base, withdraw_auth_digest(84532, &vault, &owner, 1, 1_000, &to, 1));
    assert_ne!(base, withdraw_auth_digest(84532, &vault, &owner, 0, 1_001, &to, 1));
    assert_ne!(base, withdraw_auth_digest(84532, &vault, &owner, 0, 1_000, &[0x44u8; 20], 1));
    assert_ne!(base, withdraw_auth_digest(84532, &vault, &owner, 0, 1_000, &to, 2));

    // Deterministic.
    assert_eq!(base, withdraw_auth_digest(84532, &vault, &owner, 0, 1_000, &to, 1));
}

#[test]
fn withdrawal_digests_are_domain_separated_from_each_other_and_from_bind() {
    let owner: PubKey = [7u8; 32];
    let addr = [0x11u8; 20];
    let vault = [0x22u8; 20];
    let w = withdraw_auth_digest(84532, &vault, &owner, 0, 1_000, &addr, 1);
    let lp = lp_withdraw_auth_digest(84532, &vault, &owner, 1_000, 1);
    let rb = rebind_auth_digest(84532, &vault, &owner, 0, &addr, &[0x33u8; 20]);
    let bind = deposit_bind_digest(&owner, &addr);
    assert_ne!(w, lp);
    assert_ne!(w, rb);
    assert_ne!(lp, rb);
    assert_ne!(w, bind);
    assert_ne!(lp, bind);
    assert_ne!(rb, bind);
}

#[test]
fn rebind_auth_digest_binds_both_addresses_in_order() {
    let owner: PubKey = [7u8; 32];
    let a = [0xAAu8; 20];
    let b = [0xBBu8; 20];
    let vault = [0x22u8; 20];
    // Swapping old/new must NOT produce the same digest — otherwise a signature
    // authorizing A->B would also authorize B->A.
    assert_ne!(
        rebind_auth_digest(84532, &vault, &owner, 0, &a, &b),
        rebind_auth_digest(84532, &vault, &owner, 0, &b, &a)
    );
    // The counter must change the digest, or a rebind authorization would be
    // replayable forever once the account returns to the same bound address.
    assert_ne!(
        rebind_auth_digest(84532, &vault, &owner, 0, &a, &b),
        rebind_auth_digest(84532, &vault, &owner, 1, &a, &b)
    );
}
```

- [ ] **Step 5: Run the tests to verify they fail**

Run: `cargo test -p gateway withdraw_auth_digest 2>&1 | tail -20`
Expected: FAIL — `cannot find function 'withdraw_auth_digest' in this scope`.

- [ ] **Step 6: Implement the three digests**

Insert immediately after `deposit_bind_digest` (`main.rs:4080`):

```rust
/// SEC-021: the digest a withdrawal authorization signature must cover.
/// `keccak256("dark-perp:withdraw:" ‖ chain_id ‖ vault ‖ owner ‖ market_id ‖ amount ‖ to ‖ nonce)`
///
/// Every field is fixed-width big-endian, so the concatenation is unambiguous by
/// construction — there is no variable-length field that could collide under a
/// different field split. `owner` stops a signature being replayed onto a second
/// account registered to the same address; `chain_id`+`vault` stop it being replayed
/// onto another deployment restored from a copied snapshot.
fn withdraw_auth_digest(
    chain_id: u64,
    vault: &[u8; 20],
    owner: &PubKey,
    market_id: u64,
    amount: i128,
    to: &[u8; 20],
    nonce: u64,
) -> [u8; 32] {
    use sha3::{Digest as _, Keccak256 as RawKeccak};
    let mut h = RawKeccak::new();
    h.update(b"dark-perp:withdraw:");
    h.update(chain_id.to_be_bytes());
    h.update(vault);
    h.update(owner);
    h.update(market_id.to_be_bytes());
    h.update(amount.to_be_bytes());
    h.update(to);
    h.update(nonce.to_be_bytes());
    h.finalize().into()
}

/// SEC-021: the digest an LP-withdrawal authorization signature must cover.
/// `keccak256("dark-perp:lp-withdraw:" ‖ chain_id ‖ vault ‖ owner ‖ shares ‖ nonce)`
/// There is no `to`: LP value lands in the account's OWN internal balance, never on L1.
/// The distinct prefix makes a `withdraw` signature unusable here and vice versa.
fn lp_withdraw_auth_digest(
    chain_id: u64,
    vault: &[u8; 20],
    owner: &PubKey,
    shares: u128,
    nonce: u64,
) -> [u8; 32] {
    use sha3::{Digest as _, Keccak256 as RawKeccak};
    let mut h = RawKeccak::new();
    h.update(b"dark-perp:lp-withdraw:");
    h.update(chain_id.to_be_bytes());
    h.update(vault);
    h.update(owner);
    h.update(shares.to_be_bytes());
    h.update(nonce.to_be_bytes());
    h.finalize().into()
}

/// SEC-021b: the digest the CURRENTLY BOUND address must sign to authorize moving an
/// account's deposit-address binding to `new_addr`.
/// `keccak256("dark-perp:rebind-deposit:" ‖ chain_id ‖ vault ‖ owner ‖ rebind_counter ‖ old ‖ new)`
///
/// Binding BOTH addresses (in this order) stops a signature authorizing old→new being
/// reused to authorize old→someone-else, or replayed in reverse.
///
/// `rebind_counter` is the account's monotonic rebind count, and it is what stops a
/// rebind authorization living forever. Without it a signature over (owner, A, B) stays
/// valid ANY time the account's bound address is A — so a user who rotates A→B and later
/// back to B→A hands anyone holding the old signature plus a leaked API key the power to
/// force the binding back to B. That is worst exactly when it matters most: rotating away
/// from a compromised address. The counter increments on every accepted rebind, so each
/// authorization is single-use.
fn rebind_auth_digest(
    chain_id: u64,
    vault: &[u8; 20],
    owner: &PubKey,
    rebind_counter: u64,
    old_addr: &[u8; 20],
    new_addr: &[u8; 20],
) -> [u8; 32] {
    use sha3::{Digest as _, Keccak256 as RawKeccak};
    let mut h = RawKeccak::new();
    h.update(b"dark-perp:rebind-deposit:");
    h.update(chain_id.to_be_bytes());
    h.update(vault);
    h.update(owner);
    h.update(rebind_counter.to_be_bytes());
    h.update(old_addr);
    h.update(new_addr);
    h.finalize().into()
}
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `cargo test -p gateway -- withdraw_auth_digest withdrawal_digests rebind_auth_digest 2>&1 | tail -10`
Expected: 3 passed.

- [ ] **Step 7b: Add known-answer (KAT) tests pinning the exact bytes**

The tests above compare the implementation against itself, so they survive a typo in a prefix, a swap of two same-width fields (`market_id` ↔ `nonce`, `vault` ↔ `to`, `old` ↔ `new`), or little-endian instead of big-endian. A TypeScript client mirrors `withdraw_auth_digest` byte-for-byte in Task 8, so the layout is a cross-component contract and a wrong layout is a **silent** security bug — the gateway would accept a signature over a different field tuple than the one it acts on. There is crate precedent: `gateway_signature_round_trips_and_matches_solidity_digest` (`main.rs:6856`) pins the deposit digest the same way.

Add a KAT asserting fixed vectors for all four digests (including `deposit_bind_digest` as a frozen baseline), and include the negative-amount vector — it pins `i128` two's-complement big-endian, which nothing else covers. Compute each vector from the implementation once, then hard-code it.

Also fold an offset table into each digest's doc comment. **The divergence a TS author is most likely to get wrong:** `GatewaySigner::digest` (`main.rs:4061`) encodes `chain_id` as a **32-byte** word (mirroring Solidity's `abi.encodePacked(uint256)`), while these three encode it as **8 bytes**. Both live in the same file.

- [ ] **Step 7c: Fail closed in production when the vault is unset**

`production_mode()` (`main.rs:5277`) is `l1_enabled || DARKPERP_PROD == "1"`, and `GatewaySigner::from_env` falls back to chain-id `84532` / zero vault when the env vars are absent. So a gateway in production posture without an L1 bridge and without `L1_VAULT` binds every withdrawal digest to `(84532, 0x00…00)` — byte-identical to the unit-test identity and to every other such deployment. The cross-deployment replay protection these fields exist to provide would be vacuous exactly there.

In production posture, refuse to boot when `L1_VAULT` is unset or all-zero, in the style of the existing fail-closed exits at `main.rs:5734` (attestation) and `:5935` (SEC-019 signer). Dev/demo is unaffected.

- [ ] **Step 8: Commit**

```bash
cargo clippy --workspace --all-targets -- -D warnings
git add crates/gateway/src/main.rs
git commit -m "feat(gateway): SEC-021 — deployment-bound withdrawal/rebind authorization digests

Adds withdraw/lp-withdraw/rebind digests beside deposit_bind_digest, each
domain-separated by a distinct ASCII prefix and bound to (chain_id, vault)
so a snapshot copied onto another deployment cannot replay a signature —
the signed nonce is not the withdrawal-leaf nonce, so one authorization
could otherwise become different claim leaves on two chains.

chain_id/vault ride Gw as #[serde(skip)] fields set at boot from
GatewaySigner, matching how `prod` is handled: no snapshot format change."
```

---

### Task 3: `last_withdraw_nonce` + snapshot-compatibility answer

The spec leaves one question open: does adding a trailing `#[serde(default)]` field to `Account` break loading an existing postcard snapshot? **Answer it with a test rather than assuming.** The comment at `main.rs:976` claims `serde(default)` keeps pre-upgrade snapshots loadable; postcard is positional, so this may be false.

**Files:**
- Modify: `crates/gateway/src/main.rs:966-977` (add the field after `last_sealed_nonce`)
- Test: `crates/gateway/src/main.rs` test module

**Interfaces:**
- Produces: `Account.last_withdraw_nonce: u64`, `Account.rebind_counter: u64`

Both fields are added in this task so the snapshot-format question is answered once, for the final field layout — not twice.

- [ ] **Step 1: Write the snapshot round-trip test**

```rust
/// SEC-021: adding `last_withdraw_nonce` must not silently corrupt snapshot
/// loading. postcard is POSITIONAL, so `#[serde(default)]` does not necessarily
/// make an older (shorter) encoding loadable. This test pins the actual behaviour
/// so the deploy runbook states the truth instead of a guess.
#[test]
fn account_snapshot_round_trips_with_withdraw_nonce() {
    let mut a = Account {
        wallet: Wallet::new(&[3u8; 32]),
        orders: vec![],
        nonce: 0,
        deposit_counter: 0,
        last_order_ms: 0,
        orders_this_sec: 0,
        deposit_address: Some([0x11u8; 20]),
        signer: None,
        last_signed_nonce: 0,
        last_sealed_nonce: 0,
        deposit_authorizations: Default::default(),
        last_withdraw_nonce: 42,
        rebind_counter: 3,
    };
    a.nonce = 7;
    let bytes = postcard::to_allocvec(&a).expect("serialize");
    let back: Account = postcard::from_bytes(&bytes).expect("deserialize");
    assert_eq!(back.last_withdraw_nonce, 42);
    assert_eq!(back.rebind_counter, 3);
    assert_eq!(back.nonce, 7);
    assert_eq!(back.deposit_address, Some([0x11u8; 20]));
}
```

If `Wallet::new` has a different constructor in this crate, use whatever the existing tests use to build a `Wallet` (search the test module for `Wallet` construction and copy it verbatim).

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p gateway account_snapshot_round_trips 2>&1 | tail -20`
Expected: FAIL — `struct 'Account' has no field named 'last_withdraw_nonce'`.

- [ ] **Step 3: Add the field**

Insert after the `last_sealed_nonce` field (`main.rs:977`):

```rust
    /// SEC-021: strictly-increasing nonce of the last SUCCESSFULLY COMPLETED signed
    /// withdrawal (account or LP). Deliberately SEPARATE from `last_signed_nonce`
    /// (orders): orders are high-frequency, and a shared counter would let an order
    /// stream racing past nonce N invalidate an already-signed withdrawal in flight.
    /// Committed only after the whole withdrawal succeeds, so a validly signed request
    /// that then fails on insufficient balance stays retryable rather than burning its
    /// nonce. Both withdrawal flows share this one counter — their digests are
    /// domain-separated, so cross-replay is impossible without a second counter.
    /// `serde(default)` is forward-additive struct hygiene; NOTE postcard is positional,
    /// so a cross-version snapshot load still requires a state reset (see the migration
    /// note in the deploy runbook).
    #[serde(default)]
    last_withdraw_nonce: u64,
    /// SEC-021b: how many times this account's deposit-address binding has been moved.
    /// Mixed into `rebind_auth_digest` and incremented on every accepted rebind, so a
    /// rebind authorization is single-use. Without it a signature over (owner, A, B)
    /// would stay valid any time the bound address is A — letting a leaked API key plus
    /// a captured old signature force the binding back to B after the user rotated away
    /// from it. Counts rebinds only; the first-time bind does not increment it.
    #[serde(default)]
    rebind_counter: u64,
```

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p gateway account_snapshot_round_trips 2>&1 | tail -10`
Expected: PASS.

- [ ] **Step 5: Determine and record the OLD-snapshot answer**

Build a byte string for the pre-upgrade `Account` layout (the same fields minus `last_withdraw_nonce`) and attempt to decode it as the new `Account`:

```rust
/// SEC-021 migration fact: can a PRE-upgrade Account encoding still load?
/// postcard is positional and non-self-describing, so a trailing field with
/// `#[serde(default)]` is NOT guaranteed to be optional on the wire. This test
/// RECORDS the real behaviour — whichever way it goes, the deploy runbook must
/// match it.
#[test]
fn pre_upgrade_account_encoding_behaviour_is_pinned() {
    #[derive(serde::Serialize)]
    struct OldAccount {
        wallet: Wallet,
        orders: Vec<GwOrder>,
        nonce: u64,
        deposit_counter: u64,
        last_order_ms: u64,
        orders_this_sec: u32,
        deposit_address: Option<[u8; 20]>,
        signer: Option<[u8; 20]>,
        last_signed_nonce: u64,
        last_sealed_nonce: u64,
        deposit_authorizations: std::collections::BTreeMap<[u8; 32], [u8; 32]>,
    }
    let old = OldAccount {
        wallet: Wallet::new(&[3u8; 32]),
        orders: vec![],
        nonce: 7,
        deposit_counter: 0,
        last_order_ms: 0,
        orders_this_sec: 0,
        deposit_address: Some([0x11u8; 20]),
        signer: None,
        last_signed_nonce: 0,
        last_sealed_nonce: 0,
        deposit_authorizations: Default::default(),
    };
    let bytes = postcard::to_allocvec(&old).expect("serialize old");
    let decoded: Result<Account, _> = postcard::from_bytes(&bytes);
    // Record the answer. If this assert fails, INVERT it and update the runbook —
    // do not "fix" it by changing the field, the point is to know which it is.
    assert!(
        decoded.is_err(),
        "pre-upgrade snapshots DO load; update the runbook to say a wipe is optional"
    );
}
```

Run: `cargo test -p gateway pre_upgrade_account_encoding 2>&1 | tail -20`

Whichever way it lands, keep the test and make its message state the truth. Record the outcome in the commit message — the deploy runbook depends on it.

- [ ] **Step 6: Commit**

```bash
cargo clippy --workspace --all-targets -- -D warnings
git add crates/gateway/src/main.rs
git commit -m "feat(gateway): SEC-021 — Account.last_withdraw_nonce + pinned snapshot behaviour

Separate from last_signed_nonce so a high-frequency order stream cannot
invalidate a signed withdrawal in flight; shared by both withdrawal flows
because their digests are domain-separated.

Also pins what postcard actually does with a pre-upgrade Account encoding
rather than trusting the serde(default) comment — the deploy runbook needs
the real answer, not an assumption."
```

---

### Task 4: SEC-021b — rebind lock

**Do this before the withdrawal work.** Until it lands, any defence built on `deposit_address` is bypassable with the API key alone.

**Files:**
- Modify: `crates/gateway/src/main.rs:3860-3868` (`DepositAddrReq`)
- Modify: `crates/gateway/src/main.rs:1676-1712` (`account_set_deposit_address`)
- Modify: `crates/gateway/src/main.rs:4326-…` (`post_v1_deposit_address` handler)
- Modify: `crates/gateway/src/main.rs:958-961` (the false "Bound once" comment)
- Test: `crates/gateway/src/main.rs` test module

**Interfaces:**
- Consumes: `rebind_auth_digest` (Task 2), `eip191_prehash_candidates` (Task 1), `Account.rebind_counter` (Task 3)
- Produces: `Gw::account_set_deposit_address(&mut self, key: &[u8;32], addr: [u8;20], sig: &[u8;65], current_sig: Option<&[u8;65]>) -> Result<(), String>`

- [ ] **Step 1: Write the failing exploit-chain test**

This is the SEC-021b regression test — it encodes the entire attack.

```rust
/// SEC-021b: an attacker holding ONLY the API key must not be able to move the
/// account's deposit-address binding to an address they control. Before the fix,
/// account_set_deposit_address proved control only of the NEW address and
/// overwrote an existing binding unconditionally — so a leaked key plus the
/// attacker's own signature was enough to redirect every future withdrawal.
#[test]
fn leaked_api_key_alone_cannot_rebind_deposit_address() {
    use k256::ecdsa::SigningKey;
    let mut gw = test_gw();
    let victim_sk = SigningKey::from_slice(&[9u8; 32]).unwrap();
    let victim_eoa = eth_addr(&victim_sk);
    let attacker_sk = SigningKey::from_slice(&[0xA5u8; 32]).unwrap();
    let attacker_eoa = eth_addr(&attacker_sk);

    let (key, owner) = gw.register_account(None);

    // Victim binds their own address — one signature, unchanged flow.
    let bind_sig = sign_digest(&victim_sk, &deposit_bind_digest(&owner, &victim_eoa));
    gw.account_set_deposit_address(&key, victim_eoa, &bind_sig, None)
        .expect("first bind succeeds");

    // Attacker has the API key and their own key. They can sign for their OWN
    // address trivially — that was the whole bypass.
    let attacker_bind_sig =
        sign_digest(&attacker_sk, &deposit_bind_digest(&owner, &attacker_eoa));
    let err = gw
        .account_set_deposit_address(&key, attacker_eoa, &attacker_bind_sig, None)
        .expect_err("rebind without the current address's signature must be refused");
    assert!(err.contains("current"), "unexpected error: {err}");

    // Binding is untouched.
    assert_eq!(gw.accounts.get(&key).unwrap().deposit_address, Some(victim_eoa));

    // A rebind signed by the CURRENT address is allowed (legitimate rotation).
    let rotate_sig = sign_digest(
        &victim_sk,
        &rebind_auth_digest(gw.chain_id, &gw.vault, &owner, 0, &victim_eoa, &attacker_eoa),
    );
    gw.account_set_deposit_address(&key, attacker_eoa, &attacker_bind_sig, Some(&rotate_sig))
        .expect("rebind authorized by the current address succeeds");
    assert_eq!(gw.accounts.get(&key).unwrap().deposit_address, Some(attacker_eoa));
    assert_eq!(gw.accounts.get(&key).unwrap().rebind_counter, 1, "rebind burns the authorization");
}

/// SEC-021b: a rebind authorization is SINGLE-USE. Without the counter in the digest,
/// a signature over (owner, A, B) stays valid any time the bound address is A — so a
/// user who rotates A->B and later back to A hands anyone holding the old signature
/// (plus a leaked API key) the power to force the binding back to B. That is worst
/// exactly when it matters most: rotating away from a compromised address.
#[test]
fn a_rebind_authorization_cannot_be_replayed_after_returning_to_the_old_address() {
    use k256::ecdsa::SigningKey;
    let mut gw = test_gw();
    let a_sk = SigningKey::from_slice(&[9u8; 32]).unwrap();
    let b_sk = SigningKey::from_slice(&[0xB5u8; 32]).unwrap();
    let a = eth_addr(&a_sk);
    let b = eth_addr(&b_sk);
    let (key, owner) = gw.register_account(None);
    let bind_a = sign_digest(&a_sk, &deposit_bind_digest(&owner, &a));
    let bind_b = sign_digest(&b_sk, &deposit_bind_digest(&owner, &b));
    gw.account_set_deposit_address(&key, a, &bind_a, None).unwrap();

    // Rotate A -> B (counter 0), then B -> A (counter 1).
    let a_to_b = sign_digest(&a_sk, &rebind_auth_digest(gw.chain_id, &gw.vault, &owner, 0, &a, &b));
    gw.account_set_deposit_address(&key, b, &bind_b, Some(&a_to_b)).unwrap();
    let b_to_a = sign_digest(&b_sk, &rebind_auth_digest(gw.chain_id, &gw.vault, &owner, 1, &b, &a));
    gw.account_set_deposit_address(&key, a, &bind_a, Some(&b_to_a)).unwrap();
    assert_eq!(gw.accounts.get(&key).unwrap().deposit_address, Some(a));
    assert_eq!(gw.accounts.get(&key).unwrap().rebind_counter, 2);

    // The account is bound to A again — replay the ORIGINAL A->B authorization.
    let err = gw
        .account_set_deposit_address(&key, b, &bind_b, Some(&a_to_b))
        .expect_err("a spent rebind authorization must not work a second time");
    assert!(err.contains("rebind not authorized"), "unexpected error: {err}");
    assert_eq!(gw.accounts.get(&key).unwrap().deposit_address, Some(a), "binding unchanged");
}
```

This test needs three helpers. If they do not already exist in the test module, add them next to it (the existing caller-signed tests at `main.rs:7713-7720` already have a `sign` helper — reuse its body):

```rust
fn sign_digest(sk: &k256::ecdsa::SigningKey, digest: &[u8; 32]) -> [u8; 65] {
    use k256::ecdsa::signature::hazmat::PrehashSigner;
    let (sig, recid) = sk.sign_prehash_recoverable(digest).unwrap();
    let mut s = [0u8; 65];
    s[..64].copy_from_slice(&sig.to_bytes());
    s[64] = 27 + recid.to_byte();
    s
}
```

Reuse the existing `eth_addr` and `test_gw` helpers if present; otherwise mirror how the nearby tests construct a `Gw`.

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p gateway leaked_api_key_alone_cannot_rebind 2>&1 | tail -20`
Expected: FAIL — the method takes 3 arguments, not 4.

- [ ] **Step 3: Add `currentSignature` to the request struct**

Replace `DepositAddrReq` (`main.rs:3860-3868`):

```rust
#[derive(Deserialize)]
struct DepositAddrReq {
    address: String,
    /// secp256k1 signature (65-byte r‖s‖v) proving the caller controls `address`.
    /// Accepted over any of three shapes of `deposit_bind_digest(owner, address)`:
    /// the raw digest, EIP-191 `personal_sign` over its 32 bytes, or EIP-191 over
    /// its "0x<64 hex>" string — see `eip191_prehash_candidates`.
    signature: String,
    /// SEC-021b: REBIND ONLY. When the account already has a bound address, this
    /// must additionally carry that CURRENT address's signature over
    /// `rebind_auth_digest(chain_id, vault, owner, old, new)`. Absent/ignored on a
    /// first-time bind. Without it, a leaked API key alone could redirect the
    /// binding — and therefore every future withdrawal — to an attacker's address.
    #[serde(rename = "currentSignature", default)]
    current_signature: Option<String>,
}
```

- [ ] **Step 4: Implement the rebind lock**

Replace the body of `account_set_deposit_address` (`main.rs:1676-1712`):

```rust
    fn account_set_deposit_address(
        &mut self,
        key: &[u8; 32],
        addr: [u8; 20],
        sig: &[u8; 65],
        current_sig: Option<&[u8; 65]>,
    ) -> Result<(), String> {
        let (owner, bound, rebinds) = {
            let a = self.accounts.get(key).ok_or("Unknown account.")?;
            (a.wallet.owner, a.deposit_address, a.rebind_counter)
        };
        // Proof of control over the address being bound (unchanged). Accept the
        // signature over ANY of the three deterministic shapes of the bind digest
        // (raw / EIP-191 over bytes / EIP-191 over hex string) so both CLI signers
        // and browser-wallet `personal_sign` work — see `eip191_prehash_candidates`
        // for the WHY of each and the security invariant (all shapes commit to the
        // same (owner, addr), so this widens signer ergonomics, never authorization).
        let digest = deposit_bind_digest(&owner, &addr);
        let proven = eip191_prehash_candidates(&digest)
            .iter()
            .any(|prehash| recover_eth_address(prehash, sig) == Some(addr));
        if !proven {
            return Err(
                "deposit-address proof: signature must recover to the address being bound".into(),
            );
        }
        // SEC-021b: a REBIND must additionally be authorized by the address currently
        // bound. Proving control of the NEW address is free for an attacker (it is
        // their own address), so without this a leaked API key alone could redirect
        // the binding and drain every future withdrawal to it.
        if let Some(old) = bound {
            if old == addr {
                return Ok(()); // idempotent re-bind of the same address: no-op
            }
            let cur = current_sig.ok_or(
                "rebinding requires `currentSignature` from the account's current deposit address",
            )?;
            let rebind_digest =
                rebind_auth_digest(self.chain_id, &self.vault, &owner, rebinds, &old, &addr);
            let authorized = eip191_prehash_candidates(&rebind_digest)
                .iter()
                .any(|prehash| recover_eth_address(prehash, cur) == Some(old));
            if !authorized {
                return Err(
                    "rebind not authorized: `currentSignature` must recover to the current deposit address"
                        .into(),
                );
            }
        }
        if self
            .accounts
            .iter()
            .any(|(k, a)| k != key && a.deposit_address == Some(addr))
        {
            return Err("that address is already bound to another account".into());
        }
        let a = self.accounts.get_mut(key).unwrap();
        a.deposit_address = Some(addr);
        if bound.is_some() {
            // SEC-021b: burn the authorization just consumed. Only a REBIND increments —
            // the first-time bind carries no `currentSignature` to invalidate.
            a.rebind_counter += 1;
        }
        Ok(())
    }
```

- [ ] **Step 5: Update the handler**

In `post_v1_deposit_address` (`main.rs:4326-…`), parse the optional second signature and pass it through. Add after the existing `signature` parse:

```rust
    let current_sig = match req.current_signature.as_deref() {
        Some(s) => match parse_hex65(s) {
            Some(v) => Some(v),
            None => {
                return err400("bad `currentSignature` (expected 65-byte 0x hex r‖s‖v)".into())
                    .into_response()
            }
        },
        None => None,
    };
```

and change the call to `account_set_deposit_address(&key, addr, &sig, current_sig.as_ref())`.

- [ ] **Step 6: Fix the false comment**

Replace `main.rs:958-961`:

```rust
    /// The external EOA the account funds from. An on-chain USDC `Deposit(from, amount)`
    /// is credited only when `from` matches this (so one account can't claim another's
    /// deposit). `None` until bound. NOT immutable: it may be REBOUND, but SEC-021b
    /// requires the currently bound address to sign the change — the API key alone is
    /// not sufficient, because proving control of the new address is free for whoever
    /// chose it.
    deposit_address: Option<[u8; 20]>,
```

- [ ] **Step 7: Run the tests**

Run: `cargo test -p gateway 2>&1 | tail -10`
Expected: the new test passes; the existing deposit-address tests (`main.rs:7909-7930`, `:7980-8010`) pass after mechanically adding `None` as the fourth argument at their call sites.

- [ ] **Step 8: Commit**

```bash
cargo clippy --workspace --all-targets -- -D warnings
git add crates/gateway/src/main.rs
git commit -m "fix(gateway): SEC-021b — a rebind now requires the current address's signature

account_set_deposit_address proved control only of the NEW address and
overwrote an existing binding unconditionally, while /v1/accounts/me hands
out the account owner. An attacker with just the API key could therefore
sign deposit_bind_digest(owner, attackerEOA) with their own key, rebind the
victim, and redirect every future withdrawal — defeating any defence built
on the bound address.

A rebind now also requires the CURRENT address's signature over
rebind_auth_digest(chain_id, vault, owner, old, new), which binds both
addresses in order so one authorization cannot be reused or reversed.
First-time binds are unchanged. Also closes the authorize/confirm griefing
window where a rebind could strand a legitimate in-flight deposit, and
corrects the Account comment that claimed the address was 'Bound once'."
```

---

### Task 5: Signed `account_withdraw`

**Files:**
- Modify: `crates/gateway/src/main.rs:3889-3894` (`WithdrawReq`)
- Modify: `crates/gateway/src/main.rs:1875-1934` (`account_withdraw`)
- Create: `Gw::authorizing_address` (beside `account_withdraw`)
- Modify: `crates/gateway/src/main.rs:4465-4499` (`post_v1_withdraw`)
- Modify: existing withdrawal tests that fund unbound accounts (e.g. `main.rs:8870`)
- Test: `crates/gateway/src/main.rs` test module

**Interfaces:**
- Consumes: `withdraw_auth_digest`, `eip191_prehash_candidates`, `Account.last_withdraw_nonce`
- Produces:
  - `Gw::authorizing_address(&self, key: &[u8;32]) -> Result<[u8;20], String>`
  - `Gw::account_withdraw(&mut self, key: &[u8;32], market: u64, amount: i128, to: [u8;20], nonce: u64, sig: &[u8;65]) -> Result<Withdrawal, String>`

- [ ] **Step 1: Write the failing tests**

```rust
/// SEC-021: the regression test for the reported finding. A caller-signed account
/// exists precisely so a leaked API key cannot act — but the withdrawal path never
/// read `acct.signer`, so the key alone could drain funds to any address.
#[test]
fn caller_signed_account_cannot_withdraw_without_a_signature() {
    use k256::ecdsa::SigningKey;
    let mut gw = test_gw();
    let sk = SigningKey::from_slice(&[9u8; 32]).unwrap();
    let (key, _owner) = gw.register_account(Some(eth_addr(&sk)));
    fund_test_account(&mut gw, &key, 10_000);
    let root_before = gw.seq.state.state_root();

    let err = gw
        .account_withdraw(&key, 0, 5_000, [0x66u8; 20], 1, &[0u8; 65])
        .expect_err("unsigned withdrawal must be refused");
    assert!(err.contains("signature"), "unexpected error: {err}");

    assert_eq!(gw.seq.state.state_root(), root_before, "no state mutation");
    assert_eq!(
        gw.accounts.get(&key).unwrap().last_withdraw_nonce,
        0,
        "a rejected withdrawal must not burn its nonce"
    );
}

/// SEC-021: server-custody accounts are authorized by the EOA they already proved
/// they can sign with at bind time, and may only withdraw to that address.
#[test]
fn server_custody_withdrawal_requires_bound_address_signature_and_destination() {
    use k256::ecdsa::SigningKey;
    let mut gw = test_gw();
    let sk = SigningKey::from_slice(&[9u8; 32]).unwrap();
    let eoa = eth_addr(&sk);
    let (key, owner) = gw.register_account(None);
    let bind = sign_digest(&sk, &deposit_bind_digest(&owner, &eoa));
    gw.account_set_deposit_address(&key, eoa, &bind, None).unwrap();
    fund_test_account(&mut gw, &key, 10_000);

    // Wrong destination, even with a valid signature over that destination.
    let elsewhere = [0x66u8; 20];
    let sig_elsewhere = sign_digest(
        &sk,
        &withdraw_auth_digest(gw.chain_id, &gw.vault, &owner, 0, 5_000, &elsewhere, 1),
    );
    let err = gw
        .account_withdraw(&key, 0, 5_000, elsewhere, 1, &sig_elsewhere)
        .expect_err("server-custody withdrawal to a non-bound address must be refused");
    assert!(err.contains("bound deposit address"), "unexpected error: {err}");

    // Correct destination + signature.
    let sig = sign_digest(
        &sk,
        &withdraw_auth_digest(gw.chain_id, &gw.vault, &owner, 0, 5_000, &eoa, 1),
    );
    let w = gw.account_withdraw(&key, 0, 5_000, eoa, 1, &sig).expect("accepted");
    assert_eq!(w.to, eoa);
    assert_eq!(gw.accounts.get(&key).unwrap().last_withdraw_nonce, 1);

    // Replay of the same signed request.
    let err = gw
        .account_withdraw(&key, 0, 5_000, eoa, 1, &sig)
        .expect_err("replay must be refused");
    assert!(err.contains("nonce"), "unexpected error: {err}");
}

/// SEC-021: a validly signed withdrawal that fails on insufficient balance must NOT
/// burn its nonce — otherwise the user's retry of the unchanged signed request would
/// be rejected as a replay, stranding them.
#[test]
fn failed_withdrawal_does_not_burn_its_nonce() {
    use k256::ecdsa::SigningKey;
    let mut gw = test_gw();
    let sk = SigningKey::from_slice(&[9u8; 32]).unwrap();
    let eoa = eth_addr(&sk);
    let (key, owner) = gw.register_account(None);
    let bind = sign_digest(&sk, &deposit_bind_digest(&owner, &eoa));
    gw.account_set_deposit_address(&key, eoa, &bind, None).unwrap();
    fund_test_account(&mut gw, &key, 1_000);

    let sig = sign_digest(
        &sk,
        &withdraw_auth_digest(gw.chain_id, &gw.vault, &owner, 0, 5_000, &eoa, 1),
    );
    let err = gw
        .account_withdraw(&key, 0, 5_000, eoa, 1, &sig)
        .expect_err("over-balance withdrawal fails");
    assert!(err.contains("Not withdrawable"), "unexpected error: {err}");
    assert_eq!(
        gw.accounts.get(&key).unwrap().last_withdraw_nonce,
        0,
        "nonce must survive a post-verification failure"
    );

    // Fund and retry the SAME signed request — it must now succeed.
    fund_test_account(&mut gw, &key, 10_000);
    gw.account_withdraw(&key, 0, 5_000, eoa, 1, &sig)
        .expect("the unchanged signed request is still valid on retry");
}

/// SEC-021: a caller-signed account's registered `signer` takes precedence — a
/// signature from the bound deposit address must NOT authorize its withdrawals,
/// or registering a signer would silently widen authorization instead of
/// narrowing it.
#[test]
fn registered_signer_takes_precedence_over_bound_address() {
    use k256::ecdsa::SigningKey;
    let mut gw = test_gw();
    let signer_sk = SigningKey::from_slice(&[9u8; 32]).unwrap();
    let eoa_sk = SigningKey::from_slice(&[0xE0u8; 32]).unwrap();
    let eoa = eth_addr(&eoa_sk);
    let (key, owner) = gw.register_account(Some(eth_addr(&signer_sk)));
    let bind = sign_digest(&eoa_sk, &deposit_bind_digest(&owner, &eoa));
    gw.account_set_deposit_address(&key, eoa, &bind, None).unwrap();
    fund_test_account(&mut gw, &key, 10_000);

    let digest = withdraw_auth_digest(gw.chain_id, &gw.vault, &owner, 0, 5_000, &eoa, 1);
    // The bound address signs — must be refused, the account registered a signer.
    let err = gw
        .account_withdraw(&key, 0, 5_000, eoa, 1, &sign_digest(&eoa_sk, &digest))
        .expect_err("bound-address signature must not authorize a caller-signed account");
    assert!(err.contains("signature"), "unexpected error: {err}");
    // The registered signer signs — accepted, and `to` is free for caller-signed.
    gw.account_withdraw(&key, 0, 5_000, eoa, 1, &sign_digest(&signer_sk, &digest))
        .expect("registered signer authorizes");
}

/// SEC-021: `owner` in the digest stops a signature being replayed onto a SECOND
/// account registered to the same signer address.
#[test]
fn withdrawal_signature_does_not_replay_across_accounts() {
    use k256::ecdsa::SigningKey;
    let mut gw = test_gw();
    let sk = SigningKey::from_slice(&[9u8; 32]).unwrap();
    let addr = eth_addr(&sk);
    let (key_a, owner_a) = gw.register_account(Some(addr));
    let (key_b, owner_b) = gw.register_account(Some(addr));
    assert_ne!(owner_a, owner_b);
    fund_test_account(&mut gw, &key_a, 10_000);
    fund_test_account(&mut gw, &key_b, 10_000);

    let to = [0x66u8; 20];
    let sig_a = sign_digest(
        &sk,
        &withdraw_auth_digest(gw.chain_id, &gw.vault, &owner_a, 0, 5_000, &to, 1),
    );
    let err = gw
        .account_withdraw(&key_b, 0, 5_000, to, 1, &sig_a)
        .expect_err("account A's signature must not authorize account B");
    assert!(err.contains("signature"), "unexpected error: {err}");
}

/// SEC-021: the signature covers every money-moving field — tampering with any of
/// them after signing must invalidate it.
#[test]
fn tampering_with_a_signed_withdrawal_invalidates_it() {
    use k256::ecdsa::SigningKey;
    let mut gw = test_gw();
    let sk = SigningKey::from_slice(&[9u8; 32]).unwrap();
    let (key, owner) = gw.register_account(Some(eth_addr(&sk)));
    fund_test_account(&mut gw, &key, 100_000);

    let to = [0x66u8; 20];
    let sig = sign_digest(
        &sk,
        &withdraw_auth_digest(gw.chain_id, &gw.vault, &owner, 0, 5_000, &to, 1),
    );
    // Amount tampered.
    assert!(gw.account_withdraw(&key, 0, 9_000, to, 1, &sig).is_err());
    // Destination tampered.
    assert!(gw.account_withdraw(&key, 0, 5_000, [0x77u8; 20], 1, &sig).is_err());
    // Nonce tampered.
    assert!(gw.account_withdraw(&key, 0, 5_000, to, 2, &sig).is_err());
    // Nothing was applied by any of the three.
    assert_eq!(gw.accounts.get(&key).unwrap().last_withdraw_nonce, 0);
    // The untampered request still works.
    gw.account_withdraw(&key, 0, 5_000, to, 1, &sig).expect("untampered request is valid");
}

/// SEC-021: all three EIP-191 prehash shapes authorize a withdrawal, so both CLI
/// signers and browser wallets work. Mirrors the deposit-bind test at main.rs:7935.
#[test]
fn withdrawal_accepts_all_three_prehash_shapes() {
    use k256::ecdsa::SigningKey;
    let sk = SigningKey::from_slice(&[9u8; 32]).unwrap();
    let addr = eth_addr(&sk);
    let to = [0x66u8; 20];

    for shape in 0..3 {
        let mut gw = test_gw();
        let (key, owner) = gw.register_account(Some(addr));
        fund_test_account(&mut gw, &key, 10_000);
        let digest = withdraw_auth_digest(gw.chain_id, &gw.vault, &owner, 0, 5_000, &to, 1);
        let prehash = eip191_prehash_candidates(&digest)[shape];
        let sig = sign_digest(&sk, &prehash);
        gw.account_withdraw(&key, 0, 5_000, to, 1, &sig)
            .unwrap_or_else(|e| panic!("prehash shape {shape} must be accepted: {e}"));
    }
}

/// SEC-021: cross-flow and cross-deployment replay are both closed by the digest.
#[test]
fn withdrawal_signature_does_not_replay_across_deployments() {
    use k256::ecdsa::SigningKey;
    let mut gw = test_gw();
    let sk = SigningKey::from_slice(&[9u8; 32]).unwrap();
    let eoa = eth_addr(&sk);
    let (key, owner) = gw.register_account(None);
    let bind = sign_digest(&sk, &deposit_bind_digest(&owner, &eoa));
    gw.account_set_deposit_address(&key, eoa, &bind, None).unwrap();
    fund_test_account(&mut gw, &key, 10_000);

    // Signed for a DIFFERENT chain id.
    let foreign = sign_digest(
        &sk,
        &withdraw_auth_digest(gw.chain_id + 1, &gw.vault, &owner, 0, 5_000, &eoa, 1),
    );
    let err = gw
        .account_withdraw(&key, 0, 5_000, eoa, 1, &foreign)
        .expect_err("a signature for another deployment must be refused");
    assert!(err.contains("signature"), "unexpected error: {err}");
}
```

`fund_test_account` should credit the account through whatever path the existing withdrawal tests use (search near `main.rs:8870` and reuse it verbatim). **Note:** those existing tests fund *unbound* accounts, so they will now fail — Step 6 fixes them.

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p gateway -- caller_signed_account_cannot_withdraw server_custody_withdrawal failed_withdrawal_does_not_burn withdrawal_signature_does_not_replay 2>&1 | tail -20`
Expected: FAIL — `account_withdraw` takes 4 arguments, not 6.

- [ ] **Step 3: Add the authorizing-address resolver**

Insert immediately before `account_withdraw` (`main.rs:1870`):

```rust
    /// SEC-021: the address whose secp256k1 signature authorizes this account's
    /// withdrawals. A caller-signed account's registered `signer` wins — it is the
    /// explicit opt-in. Otherwise the bound `deposit_address`: the account already
    /// proved it can sign with that key when it bound it, so requiring it again on
    /// the money path costs the user nothing new and leaves no account authorized by
    /// the bearer API key alone. Neither ⇒ no withdrawal is possible.
    fn authorizing_address(&self, key: &[u8; 32]) -> Result<[u8; 20], String> {
        let a = self.accounts.get(key).ok_or("Unknown account.")?;
        a.signer
            .or(a.deposit_address)
            .ok_or_else(|| {
                "no authorizing address: bind a deposit address (POST /v1/accounts/deposit/address) \
                 or register a caller-signed account before withdrawing"
                    .to_string()
            })
    }
```

- [ ] **Step 4: Rewrite `account_withdraw`'s preamble**

Replace the signature and the checks at `main.rs:1875-1893` (leave everything from `let nonce = self.next_withdraw_nonce;` onward untouched **except** the nonce commit added in Step 5):

```rust
    fn account_withdraw(
        &mut self,
        key: &[u8; 32],
        market: u64,
        amount: i128,
        to: [u8; 20],
        auth_nonce: u64,
        sig: &[u8; 65],
    ) -> Result<Withdrawal, String> {
        if amount <= 0 {
            return Err("Amount must be positive.".into());
        }
        if self.mkt(market).is_none() {
            return Err("Unknown market.".into());
        }
        let (wallet, signer, bound, last_nonce) = {
            let a = self.accounts.get(key).ok_or("Unknown account.")?;
            (a.wallet, a.signer, a.deposit_address, a.last_withdraw_nonce)
        };
        // SEC-021: server-custody accounts may only withdraw to the address they
        // bound. The signature already binds `to`, but the rebind path is exactly
        // where this design's first version failed (SEC-021b), so the destination
        // carries a second, independent constraint. Caller-signed accounts are the
        // explicit advanced mode and keep a free destination — they consented to it
        // cryptographically (deposit from a hot wallet, withdraw to a cold one).
        if signer.is_none() {
            match bound {
                Some(b) if b == to => {}
                Some(_) => {
                    return Err(
                        "Withdrawal `to` must equal this account's bound deposit address.".into(),
                    )
                }
                None => {
                    return Err(
                        "Bind a deposit address first (POST /v1/accounts/deposit/address).".into(),
                    )
                }
            }
        }
        // Replay protection: strictly increasing, CHECKED here but COMMITTED only
        // after the withdrawal fully succeeds (see the end of this function).
        if auth_nonce <= last_nonce {
            return Err("withdrawal nonce must strictly increase (replay protection)".into());
        }
        let expected = self.authorizing_address(key)?;
        let digest = withdraw_auth_digest(
            self.chain_id,
            &self.vault,
            &wallet.owner,
            market,
            amount,
            &to,
            auth_nonce,
        );
        let authorized = eip191_prehash_candidates(&digest)
            .iter()
            .any(|prehash| recover_eth_address(prehash, sig) == Some(expected));
        if !authorized {
            return Err(
                "withdrawal signature does not recover to this account's authorizing address"
                    .into(),
            );
        }
        if amount > self.market_free_of(&wallet.owner, market) {
            return Err(
                "Not withdrawable: amount exceeds the SETTLED balance in this market (§3).".into(),
            );
        }
```

- [ ] **Step 5: Commit the nonce last**

At the end of `account_withdraw`, immediately before `Ok(w)` (after `self.window_withdrawals.push(w.clone());`):

```rust
        // SEC-021: commit the authorization nonce ONLY now — the withdrawal is fully
        // applied. Committing at verification time would burn the nonce on a request
        // that then failed the balance check, and the user's retry of the unchanged
        // signed request would be rejected as a replay.
        self.accounts.get_mut(key).unwrap().last_withdraw_nonce = auth_nonce;
```

- [ ] **Step 6: Update the request struct, handler, and existing tests**

`WithdrawReq` (`main.rs:3889`):

```rust
#[derive(Deserialize)]
struct WithdrawReq {
    #[serde(rename = "marketId")]
    market_id: u64,
    amount: String,
    to: String,
    /// SEC-021: strictly-increasing withdrawal-authorization nonce (replay
    /// protection). Required for every account.
    #[serde(default)]
    nonce: Option<u64>,
    /// SEC-021: 65-byte secp256k1 signature (r‖s‖v) over `withdraw_auth_digest`,
    /// recovering to the account's authorizing address (registered `signer`, else
    /// the bound deposit address). Required for every account; accepted over any of
    /// the three shapes in `eip191_prehash_candidates`.
    #[serde(default)]
    signature: Option<String>,
}
```

In `post_v1_withdraw` (`main.rs:4482`), before the call:

```rust
    let nonce = match req.nonce {
        Some(n) => n,
        None => return err400("`nonce` is required".into()).into_response(),
    };
    let sig = match req.signature.as_deref().and_then(parse_hex65) {
        Some(s) => s,
        None => {
            return err400("`signature` is required (65-byte 0x hex r‖s‖v)".into()).into_response()
        }
    };
```

and change the call to `account_withdraw(&key, req.market_id, amount, to, nonce, &sig)`.

Then fix every pre-existing test that calls `account_withdraw` (e.g. `main.rs:8870`): bind a deposit address for the account and sign the withdrawal, using the helpers from Step 1. **Do not** add a non-production exemption — the tests should exercise the real authorization path, and binding in a fixture is two lines.

- [ ] **Step 7: Run the full gateway suite**

Run: `cargo test -p gateway 2>&1 | tail -10`
Expected: all pass.

- [ ] **Step 8: Commit**

```bash
cargo clippy --workspace --all-targets -- -D warnings
git add crates/gateway/src/main.rs
git commit -m "fix(gateway): SEC-021 — every withdrawal now requires a signature

account_withdraw never read acct.signer, so a leaked API key alone could
drain a caller-signed account to an attacker-chosen address — while the
order path enforced a signature on every order. The lowest-value operation
was protected and the highest-value one was not.

Both account types now share one rule: the withdrawal must carry a
secp256k1 signature over withdraw_auth_digest recovering to the account's
authorizing address — the registered signer, else the bound deposit address
the account already proved it can sign with. Server-custody accounts
additionally pin `to` to that bound address.

Enforced in the engine method, not the handler: every existing unit test
calls gw.account_withdraw directly, so a handler-only fix would leave the
regression test unable to observe the hole. The nonce commits only after
the withdrawal fully succeeds, so a signed request that fails the balance
check stays retryable."
```

---

### Task 6: `account_lp_withdraw` wrapper

`lp_withdraw` must keep working for the legacy demo handler, which passes `share_key = gw.user.owner` — not an entry in `accounts` (`main.rs:5044`). A top-level `accounts.get(...)` check inside `lp_withdraw` would break it, and skipping authorization for non-account keys would hollow out the invariant. So authorization goes in a new account-scoped wrapper.

**Files:**
- Create: `Gw::account_lp_withdraw` (beside `lp_withdraw`, `main.rs:2830`)
- Modify: `crates/gateway/src/main.rs:5029-5032` (`LpWithdrawReq`)
- Modify: `crates/gateway/src/main.rs:4561-4587` (`post_v1_lp_withdraw`)
- Test: `crates/gateway/src/main.rs` test module

**Interfaces:**
- Consumes: `lp_withdraw_auth_digest`, `authorizing_address`, `Gw::lp_withdraw` (unchanged)
- Produces: `Gw::account_lp_withdraw(&mut self, key: &[u8;32], shares: u128, auth_nonce: u64, sig: &[u8;65]) -> Result<i128, String>`

- [ ] **Step 1: Write the failing tests**

```rust
/// SEC-021: the /v1 LP withdrawal is authorized like any other withdrawal, and a
/// withdrawal signature cannot be carried across into it.
#[test]
fn account_lp_withdraw_requires_its_own_signature() {
    use k256::ecdsa::SigningKey;
    let mut gw = test_gw();
    let sk = SigningKey::from_slice(&[9u8; 32]).unwrap();
    let eoa = eth_addr(&sk);
    let (key, owner) = gw.register_account(None);
    let bind = sign_digest(&sk, &deposit_bind_digest(&owner, &eoa));
    gw.account_set_deposit_address(&key, eoa, &bind, None).unwrap();
    fund_test_account(&mut gw, &key, 10_000);
    let wallet = gw.accounts.get(&key).unwrap().wallet;
    let shares = gw.lp_deposit(key, &wallet, 5_000).expect("stake");

    // A signature over the ACCOUNT-withdrawal digest must not authorize an LP
    // withdrawal — the two digests are domain-separated.
    let wrong = sign_digest(
        &sk,
        &withdraw_auth_digest(gw.chain_id, &gw.vault, &owner, 0, shares as i128, &eoa, 1),
    );
    let err = gw
        .account_lp_withdraw(&key, shares, 1, &wrong)
        .expect_err("cross-flow signature must be refused");
    assert!(err.contains("signature"), "unexpected error: {err}");

    let sig = sign_digest(
        &sk,
        &lp_withdraw_auth_digest(gw.chain_id, &gw.vault, &owner, shares, 1),
    );
    gw.account_lp_withdraw(&key, shares, 1, &sig).expect("accepted");
    assert_eq!(gw.accounts.get(&key).unwrap().last_withdraw_nonce, 1);
}

/// SEC-021: the legacy demo LP handler calls the raw primitive with a key that is
/// not a registered account. That path must keep working — authorization lives in
/// the wrapper, not in `lp_withdraw`.
#[test]
fn legacy_lp_withdraw_primitive_still_works_for_the_demo_wallet() {
    let mut gw = test_gw();
    let who = gw.user.owner;
    let w = gw.user;
    let shares = gw.lp_deposit(who, &w, 1_000).expect("stake");
    gw.lp_withdraw(&who, &w, shares).expect("legacy primitive is unauthenticated by contract");
}
```

If `lp_deposit`'s signature differs, match it to the call at `main.rs:4549`.

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p gateway -- account_lp_withdraw_requires legacy_lp_withdraw_primitive 2>&1 | tail -20`
Expected: FAIL — no method named `account_lp_withdraw`.

- [ ] **Step 3: Implement the wrapper**

Insert immediately after `lp_withdraw` (`main.rs:2830`):

```rust
    /// SEC-021: the authorized, account-scoped LP withdrawal — the entry point `/v1`
    /// uses. `lp_withdraw` itself stays an unauthenticated engine primitive because
    /// the legacy demo handler calls it with the demo wallet's owner, which is not a
    /// registered account; putting the check there would break that path, and
    /// skipping the check for non-account keys would hollow it out.
    ///
    /// The withdrawer wallet is DERIVED from the account rather than accepted as a
    /// parameter, so a caller cannot pair one account's share key with another
    /// account's wallet.
    fn account_lp_withdraw(
        &mut self,
        key: &[u8; 32],
        shares: u128,
        auth_nonce: u64,
        sig: &[u8; 65],
    ) -> Result<i128, String> {
        let (wallet, last_nonce) = {
            let a = self.accounts.get(key).ok_or("unknown account")?;
            (a.wallet, a.last_withdraw_nonce)
        };
        if auth_nonce <= last_nonce {
            return Err("withdrawal nonce must strictly increase (replay protection)".into());
        }
        let expected = self.authorizing_address(key)?;
        let digest =
            lp_withdraw_auth_digest(self.chain_id, &self.vault, &wallet.owner, shares, auth_nonce);
        let authorized = eip191_prehash_candidates(&digest)
            .iter()
            .any(|prehash| recover_eth_address(prehash, sig) == Some(expected));
        if !authorized {
            return Err(
                "LP withdrawal signature does not recover to this account's authorizing address"
                    .into(),
            );
        }
        let value = self.lp_withdraw(key, &wallet, shares)?;
        // Commit only after success, for the same reason as `account_withdraw`.
        self.accounts.get_mut(key).unwrap().last_withdraw_nonce = auth_nonce;
        Ok(value)
    }
```

- [ ] **Step 4: Update the request struct and handler**

`LpWithdrawReq` (`main.rs:5029`) — note this struct is shared with the legacy demo handler, which ignores the new fields:

```rust
#[derive(Deserialize)]
struct LpWithdrawReq {
    shares: String,
    /// SEC-021: required on `/v1/lp/withdraw`. Ignored by the legacy demo handler,
    /// which is omitted in production (audit DP-010).
    #[serde(default)]
    nonce: Option<u64>,
    #[serde(default)]
    signature: Option<String>,
}
```

Replace the body of `post_v1_lp_withdraw` (`main.rs:4574-4580`):

```rust
    let nonce = match req.nonce {
        Some(n) => n,
        None => return err400("`nonce` is required".into()).into_response(),
    };
    let sig = match req.signature.as_deref().and_then(parse_hex65) {
        Some(s) => s,
        None => {
            return err400("`signature` is required (65-byte 0x hex r‖s‖v)".into()).into_response()
        }
    };
    let r = { app.gw.lock().await.account_lp_withdraw(&key, shares, nonce, &sig) };
```

- [ ] **Step 5: Run the tests**

Run: `cargo test -p gateway 2>&1 | tail -10`
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
cargo clippy --workspace --all-targets -- -D warnings
git add crates/gateway/src/main.rs
git commit -m "fix(gateway): SEC-021 — authorize /v1 LP withdrawals via account_lp_withdraw

lp_withdraw could not simply gain a top-level accounts.get() check: the
legacy demo handler calls it with the demo wallet's owner, which is not a
registered account (main.rs:5044). Authorization therefore lives in a new
account-scoped wrapper that /v1 calls, while the raw primitive stays
unauthenticated by contract for the prod-disabled legacy route.

The wrapper derives the withdrawer wallet from the account instead of
accepting it as a parameter, removing the dual-identity hazard where a
caller could pair one account's share key with another's wallet."
```

---

### Task 7: Expose binding state on `/v1/accounts/me`

The frontend cannot implement the signed-withdrawal flow without this: it persists only `{apiKey, owner}` (`realClient.ts:495`) and has no way to learn the bound address or a valid nonce after a reload.

**Files:**
- Modify: `crates/gateway/src/main.rs:2467-2476` (`v1_account`)
- Modify: `crates/gateway/src/main.rs:4844` region (OpenAPI blob)
- Test: `crates/gateway/src/main.rs` test module

**Interfaces:**
- Produces: `/v1/accounts/me` response gains `depositAddress` (string or null), `callerSigned` (bool), `nextWithdrawNonce` (u64), `rebindCounter` (u64), `chainId` (u64), `vault` (0x-hex string)

`rebindCounter` is needed for the same reason as the others: it is mixed into `rebind_auth_digest`, so a client rotating its deposit address cannot build a valid signature without it. Task 4 documented the derivation rule (0 at creation, +1 per *accepted* rebind, rejected attempts do not count) but left clients to track it themselves — serving it is the friendlier and less error-prone contract.

`chainId` and `vault` are part of the signed digest, so the client must read them from the gateway rather than hardcoding them — a client compiled against the wrong deployment would otherwise produce signatures that are silently rejected.

- [ ] **Step 1: Write the failing test**

```rust
/// SEC-021: the client needs the binding state to build a withdrawal signature.
#[test]
fn v1_account_exposes_withdrawal_authorization_state() {
    use k256::ecdsa::SigningKey;
    let mut gw = test_gw();
    let sk = SigningKey::from_slice(&[9u8; 32]).unwrap();
    let eoa = eth_addr(&sk);
    let (key, owner) = gw.register_account(None);

    let v = gw.v1_account(&key).unwrap();
    assert_eq!(v["depositAddress"], serde_json::Value::Null);
    assert_eq!(v["callerSigned"], false);
    assert_eq!(v["nextWithdrawNonce"], 1);
    // The client cannot build a valid digest without these.
    assert_eq!(v["chainId"], gw.chain_id);
    assert_eq!(v["vault"], hex0x(&gw.vault));

    let bind = sign_digest(&sk, &deposit_bind_digest(&owner, &eoa));
    gw.account_set_deposit_address(&key, eoa, &bind, None).unwrap();
    let v = gw.v1_account(&key).unwrap();
    assert_eq!(v["depositAddress"], hex0x(&eoa));
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p gateway v1_account_exposes 2>&1 | tail -20`
Expected: FAIL — `depositAddress` is `Null` at the second assertion (field absent).

- [ ] **Step 3: Implement**

Replace `v1_account` (`main.rs:2467-2476`):

```rust
    fn v1_account(&self, key: &[u8; 32]) -> Option<serde_json::Value> {
        let a = self.accounts.get(key)?;
        let owner = a.wallet.owner;
        Some(serde_json::json!({
            "owner": hex0x(&owner),
            "settledBalance": self.free_balance_of(&owner).to_string(),
            "positions": self.positions_json_of(&owner),
            "nextNonce": a.nonce,
            // SEC-021: everything the client needs to build a withdrawal signature —
            // which address must sign, which nonce is next, and the deployment the
            // digest is bound to (never hardcode these client-side: a client built
            // against the wrong deployment would sign digests that silently fail).
            "depositAddress": a.deposit_address.map(|d| hex0x(&d)),
            "callerSigned": a.signer.is_some(),
            "nextWithdrawNonce": a.last_withdraw_nonce + 1,
            "rebindCounter": a.rebind_counter,
            "chainId": self.chain_id,
            "vault": hex0x(&self.vault),
        }))
    }
```

- [ ] **Step 4: Update the OpenAPI blob**

In the `/v1/accounts/me` entry near `main.rs:4844`, extend the response summary to mention `depositAddress`, `callerSigned` and `nextWithdrawNonce`, and add `nonce`/`signature` to the withdrawal endpoints' request fields, matching the wording style of the existing `nonce`/`signature` order-field descriptions at `:4833-4834`.

- [ ] **Step 5: Run the tests**

Run: `cargo test -p gateway 2>&1 | tail -10`
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
cargo clippy --workspace --all-targets -- -D warnings
git add crates/gateway/src/main.rs
git commit -m "feat(gateway): SEC-021 — expose depositAddress/callerSigned/nextWithdrawNonce

/v1/accounts/me returned neither the bound address nor a withdrawal nonce,
and the client persists only {apiKey, owner} — so it could not tell bound
from unbound after a reload, nor pick a valid nonce. The signed-withdrawal
flow is unimplementable client-side without these."
```

---

### Task 8: Frontend — wallet-signed withdrawals

**Files:**
- Modify: `frontend/src/api/realClient.ts:722-734` (`requestWithdrawal`)
- Modify: `frontend/src/api/client.ts:103` (interface signature)
- Modify: `frontend/src/api/mockClient.ts:500` (mock impl)
- Modify: `frontend/src/components/AccountPanel.tsx:126` (destination input → bound address + signing)
- Modify: `frontend/src/api/realClient.test.ts:423,428,446,543`

**Interfaces:**
- Consumes: `/v1/accounts/me` fields from Task 7; the existing `personalSign` helper (`frontend/src/api/wallet.ts:248-251`)
- Produces: `requestWithdrawal(amountQuote, to, nonce, signature)`

- [ ] **Step 1: Build the digest client-side**

Add to `realClient.ts`. Reuse `hexToBytes` / `bytesToHex` / `keccak256` from `wallet.ts` (the deposit-bind flow already uses them) — do **not** add a dependency.

```ts
/** Big-endian, zero-left-padded to `width` bytes. */
function beBytes(value: bigint, width: number): Uint8Array {
  const out = new Uint8Array(width);
  let v = value;
  for (let i = width - 1; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  if (v !== 0n) throw new Error(`value does not fit in ${width} bytes`);
  return out;
}

function concatBytes(parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

/**
 * Mirrors crates/gateway/src/main.rs `withdraw_auth_digest`. Field widths are
 * load-bearing — the gateway concatenates fixed-width big-endian fields with no
 * separators, so a wrong width silently produces a different digest:
 * keccak256("dark-perp:withdraw:" ‖ chainId(8) ‖ vault(20) ‖ owner(32)
 *           ‖ marketId(8) ‖ amount(16) ‖ to(20) ‖ nonce(8))
 */
function withdrawAuthDigest(
  chainId: bigint, vault: string, owner: string,
  marketId: bigint, amount: bigint, to: string, nonce: bigint,
): Uint8Array {
  return keccak256(concatBytes([
    new TextEncoder().encode("dark-perp:withdraw:"),
    beBytes(chainId, 8),
    hexToBytes(vault),
    hexToBytes(owner),
    beBytes(marketId, 8),
    beBytes(amount, 16),
    hexToBytes(to),
    beBytes(nonce, 8),
  ]));
}
```

- [ ] **Step 2: Sign and submit**

Replace `requestWithdrawal` (`realClient.ts:722-734`). It now reads the authorization state from `/v1/accounts/me`, signs, and submits — the legacy `/api/withdraw` mirror below it stays as-is (best-effort, prod-disabled).

```ts
async requestWithdrawal(amountQuote: bigint | number | string): Promise<void> {
  const me = await this.getAccount();               // GET /v1/accounts/me
  if (!me.depositAddress) {
    throw new Error("Bind a deposit address before withdrawing.");
  }
  const to = me.depositAddress;
  const amount = BigInt(s(amountQuote));
  const marketId = BigInt(this.clientSelectedMarket);
  const nonce = BigInt(me.nextWithdrawNonce);
  const digest = withdrawAuthDigest(
    BigInt(me.chainId), me.vault, me.owner, marketId, amount, to, nonce,
  );
  // personal_sign returns an EIP-191 signature over the 32 digest bytes — one of
  // the three shapes the gateway accepts (eip191_prehash_candidates).
  const signature = await personalSign("0x" + bytesToHex(digest), to);
  await this.post("/v1/accounts/withdraw", {
    marketId: Number(marketId), amount: s(amountQuote), to,
    nonce: Number(nonce), signature,
  });
}
```

Note the destination is no longer a parameter — it is always the bound address. Update the interface at `client.ts:103` and the mock at `mockClient.ts:500` to match the new one-argument signature.

- [ ] **Step 3: Replace the destination input**

In `AccountPanel.tsx`, delete the free-text `dest` state and its input, and call `client.requestWithdrawal(v)` (`:126`) with the amount only. Render the bound address read-only:

```tsx
{account.depositAddress ? (
  <div className="withdraw-dest">
    <span className="label">Withdrawing to</span>
    <code>{account.depositAddress}</code>
    <p className="hint">
      Funds always return to the address you deposited from.
    </p>
  </div>
) : (
  <p className="hint">
    Bind a deposit address before withdrawing.
  </p>
)}
```

Gate the submit button on `account.depositAddress` being present. Match the surrounding class names and markup conventions in the file rather than copying these verbatim.

- [ ] **Step 4: Update the tests**

At `realClient.test.ts:423,428,446,543`, the asserted body becomes `{ marketId: 0, amount: "5000000", to: TO, nonce: <n>, signature: "0x…" }`. The fetch stub at `:136` must also answer `GET /v1/accounts/me` with `depositAddress`, `nextWithdrawNonce`, `chainId` and `vault`, since `requestWithdrawal` now reads them first. Add one test asserting it throws without submitting when `depositAddress` is null:

```ts
it("refuses to withdraw when no deposit address is bound", async () => {
  stubAccount({ depositAddress: null });
  await expect(client.requestWithdrawal("5000000")).rejects.toThrow(/Bind a deposit address/);
  expect(calls.some((c) => c.url.includes("/v1/accounts/withdraw"))).toBe(false);
});
```

- [ ] **Step 5: Run the frontend tests**

Run: `cd frontend && npm test 2>&1 | tail -15`
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add frontend/
git commit -m "feat(frontend): SEC-021 — withdrawals are wallet-signed to the bound address

The destination was free text and the request carried no signature. It is
now the bound deposit address, shown read-only, with an EIP-191 signature
over the gateway's withdraw_auth_digest — the same personal_sign path the
deposit bind already uses. Also closes the adjacent wrong-address class:
users can no longer mistype a destination."
```

---

### Task 9: Documentation and comment corrections

**Files:**
- Modify: `docs/API.md:40,45,120,134-152,187,196`
- Modify: `docs/SECURITY.md`
- Modify: `docs/public-site/api.html:46,71,127-128`, `docs/public-site/trading.html:112`
- Modify: `crates/gateway/src/main.rs:3939-3941` (inaccurate `ecrecover` comment)

- [ ] **Step 1: Correct the `recover_eth_address` comment**

Replace `main.rs:3939-3941`:

```rust
/// Recover the 20-byte Ethereum address that signed `prehash` with `sig` (r‖s‖v).
/// NOTE: this is deliberately more permissive than the Solidity side on `v` — it
/// accepts 0..3 as well as 27..30, whereas `CollateralVault`/`DarkPerpSettlement`
/// accept only 27/28. That is safe for gateway-local authorization (these signatures
/// never reach a contract), but it is NOT byte-identical to on-chain `ecrecover`.
/// High-`s` (malleable) signatures are rejected inside k256's recovery primitive.
```

- [ ] **Step 2: Document the withdrawal authorization in `docs/API.md`**

Extend the withdrawal section with the signature/nonce requirement for **both** account types, the `to` rule for server-custody accounts, and the rebind rule. Add the digest layout so an API user can reproduce it. Also close the pre-existing gap at `:134-152`: state explicitly that the caller-signed **order** signature is over the **raw** digest with no EIP-191 prefix, whereas withdrawal and bind signatures accept all three shapes in `eip191_prehash_candidates`.

- [ ] **Step 3: Record both findings in `docs/SECURITY.md`**

Add SEC-021 and SEC-021b with their resolutions, matching the format used for SEC-019/ZK-001.

- [ ] **Step 3b: Document the two user-visible consequences of the rebind lock**

Both follow from decisions taken deliberately, and both are surprising enough that users must not discover them live. Cover them in `docs/API.md`, `docs/SECURITY.md`, and the alpha release notes:

1. **There is no recovery path for a lost bound-address key.** The binding can only be moved by a signature from the address currently bound, and the design explicitly rejects a timelocked or operator-mediated rebind. Combined with the server-custody `to` pin, losing that key makes the account's funds permanently unwithdrawable. State it plainly — "keep the key you deposited from" is the whole mitigation.
2. **First bind wins, permanently.** An attacker holding only a leaked API key can bind their own address to an account that has never bound one, and the victim can no longer overwrite it. The account holds no funds in that state (crediting requires `from == bound address`), so this is griefing rather than theft — but the failure mode inverted relative to the old behavior, where the victim could simply rebind.
3. **For a caller-signed account, the registered `signer` is the *only* key that can withdraw** — even if the account has also bound a deposit address. `authorizing_address` gives `signer` precedence, deliberately, so registering a signer narrows authorization rather than widening it. The consequence: losing the signer key strands the funds even though the deposit-address key is perfectly safe. Say so where caller-signed mode is documented, next to the existing note that a caller-signed account's orders need that same key.

- [ ] **Step 4: Update the public site**

Mirror the API.md changes in `docs/public-site/api.html` (`:46`, `:71`, `:127-128`) and `docs/public-site/trading.html` (`:112`).

**Cover the LP endpoint, not just `/v1/accounts/withdraw`.** It is the one most likely to be missed, because no client calls it today — which is exactly why nothing else will catch a stale doc. Two specific defects found in review:

- `docs/public-site/api.html:128` still documents `POST /v1/lp/withdraw` as `{"shares": "…"}`. That body is now a **guaranteed 400**.
- The in-tree OpenAPI blob (`get_v1_openapi`) omits the `/v1/lp/*` paths **entirely**, and still declares `"required": ["marketId","amount","to"]` for `/v1/accounts/withdraw` — which now contradicts the server. Add the LP paths rather than leaving them undocumented.
- `/v1/accounts/deposit/address` in the same blob still does not document `currentSignature`, the rebind parameter Task 4 added — so the blob describes a rebind request that the server now rejects.
- The withdraw `signature` description is terse where it matters: unlike its sibling at `/v1/accounts/deposit/address`, it does not say that **all three** `eip191_prehash_candidates` shapes are accepted (raw digest, EIP-191 over the 32 bytes, EIP-191 over the `"0x…"` hex string). A browser `personal_sign` client reading only the blob would not know it works.

**One cross-endpoint inconsistency worth a documented line rather than a code change:** two endpoints now expose a field named `vault`. `/v1/accounts/me` serves `hex0x(&Gw.vault)` — normalized lowercase `0x` + 40 hex, and **these are the exact bytes hashed into the digests**, so it is the authoritative one for signing. `/v1/accounts/withdrawals` echoes `l1.vault`, the raw unparsed `L1_VAULT` env string, which may be EIP-55 mixed-case. Same env var, same source of truth, but a naive string comparison between the two can mismatch.

- [ ] **Step 5: Verify the docs match the code**

Run: `rg -n 'currentSignature|nextWithdrawNonce|dark-perp:withdraw' docs/ crates/gateway/src/main.rs`
Expected: the field names in the docs match the code exactly.

- [ ] **Step 6: Commit**

```bash
git add docs/ crates/gateway/src/main.rs
git commit -m "docs(sec021): document signed withdrawals, the rebind rule, and the digest layout

Also corrects two false comments found during this work: recover_eth_address
does NOT behave 'exactly as the contract's ecrecover' (it accepts v in 0..3
as well as 27..30, the contracts accept only 27/28), and API.md never stated
that caller-signed ORDER signatures are over the raw digest with no EIP-191
prefix, unlike withdrawal and bind signatures."
```

---

## Pre-rollout checklist (operator, not code)

These cannot be verified from source — the deployed snapshot is the only authority.

- [ ] Inspect live state for accounts with `signer: Some(..)` — caller-signed accounts in the wild would need a client capable of signing withdrawals.
- [ ] Inspect live state for **funded accounts with `deposit_address: None`** — under the new rule they cannot withdraw. In production this set should be empty (crediting already requires a bound address), but confirm rather than assume.
- [ ] **Wipe `state.snap`.** Task 3 settled this by test: a pre-upgrade snapshot does not load correctly — it either fails with `DeserializeUnexpectedEnd` or, when `deposit_authorizations` is non-empty and its key bytes align, decodes *silently into corrupt state* with the authorizations dropped. The wipe is required, not precautionary. Note the live cutover gotcha already on record: stop the process, **then** remove `state.snap`, then start — a restart lets the old process rewrite an old-format snapshot on shutdown.
- [ ] **Propagate that fact to the deploy runbook.** The runbook does not live in this repo, so no commit here can update it; it has to be carried across by hand.
- [ ] This change rides the pending redeploy that the forge-audit remediation (`a413750`) already requires (fresh `Settlement`/`Vault`/`USDC` with 3 new constructor params). Verify `L1_CHAIN_ID` and `L1_VAULT` are set in the gateway environment — `Gw.chain_id`/`Gw.vault` fall back to `84532`/zero, and a zero vault would make signatures portable to any other zero-vault deployment.

## Follow-ups (out of scope, track separately)

- **`deposit_authorize` unbounded growth:** every request inserts into the persisted `deposit_authorizations` map (`main.rs:1752`) with no per-account cap or rate limit (`main.rs:4420`) — a durable memory/snapshot-growth vector. Note the correct framing: the call moves no value, so this is availability, not theft.
- **EIP-712 typed data** for withdrawal signatures, so wallets render "withdraw 2000 USDC to 0x…" instead of a hex blob to blind-sign.

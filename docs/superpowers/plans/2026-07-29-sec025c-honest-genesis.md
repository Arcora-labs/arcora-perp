# SEC-025 025-C — Honest genesis — Implementation Plan


**Goal:** Make a production gateway able to settle against a real vault, by never fabricating a deposit the L1 chain cannot match.

**Architecture:** One invariant — in production, `consumed_deposit_tip` and `consumed_deposit_count` advance only via a real L1 deposit, or arrive in a snapshot whose continuity with the chain has been verified. Enforced by a genesis mode passed *into* `Gw::boot()`, a mode threaded to every unbacked-funding call site, and a boot-time continuity check on every L1-configured boot.

**Source spec:** `docs/superpowers/specs/2026-07-29-sec025c-honest-genesis-design.md`. Read its "Verified at source" and "Cleaning genesis alone is not enough" sections before starting — the first draft of this design enumerated the writers incompletely and proposed a mechanism that did not force the correct mode, and both corrections are what the tasks below encode.

**Tech Stack:** Rust, `axum` router, `postcard` snapshots, foundry (contract side already covered).

## Global Constraints

- **`crates/perp-core` must not be modified.** It compiles into the SP1 guest; a change there moves the vkey. This piece deliberately does not. (`GENESIS_ROOT` *does* move — that is a deployment parameter, not a guest change.)
- **`cargo fmt --all` before every commit.** CI runs `cargo fmt --all -- --check`.
- **`cargo clippy --workspace --all-targets` must be clean.**
- **The gateway crate is bin-only** — `cargo test --bin gateway`, **never** `--lib` (that errors with "no library targets found"; two briefs on the previous branch shipped `--lib` commands).
- Baseline: `cargo test --workspace` = **521 passed / 50 suites**; `cd contracts && forge test` = **85 passed**. Each task should move the Rust count by exactly the tests it adds.
- **Genesis mode keys on `production_mode`** (`l1_enabled || DARKPERP_PROD`), decided in the spec — **not** on `strict_production()`. Any L1-configured deployment gets a markets-only genesis.

## Fixture suspicion is mandatory

Across the two preceding branches, **twelve test fixtures passed while exercising nothing** — every task found one in its own brief. The variants seen: a fee ratio that was zero so the overflow never fired; a `pool_delta` that netted to zero; a transcript signed at the fill price so the band was never tested; a market that panicked in setup; a verify command that could not run; a test that did not compile; and the subtlest — **a fixture where a *rejected* order satisfied every precondition meant to prove an *accepted* one**, so the test went green while validating the opposite arm.

**Assume the fixtures below are wrong.** Before accepting that a test passes, satisfy yourself it reaches the path its name claims and would fail if the behaviour regressed. Where a task says "must fail before the change", verify that literally by stashing. Mutation-test where a task says to.

---

### Task 1: `GenesisMode`, and a production genesis that mints nothing

**Files:**
- Modify: `crates/gateway/src/main.rs` — `Gw::boot` (`:1491-1600`), its single non-test caller (`:6395`)
- Test: `crates/gateway/src/main.rs` (`mod tests`)

**Interfaces:**
- Produces: `pub enum GenesisMode { Demo, Production }` (`Copy`, `PartialEq`); `Gw::boot_with(mode: GenesisMode) -> Self`; `Gw::boot() -> Self` becomes `Self::boot_with(GenesisMode::Demo)`. Tasks 2 and 5 consume both.

**Why a parameter and not a field:** `gw.prod` is assigned at `main.rs:6397`, **two lines after** `Gw::boot()` is called at `:6395`. By then the seven unbacked deposits already exist. The flag physically cannot guard the funding.

**Why `boot()` keeps its signature:** there are ~80 call sites and **exactly one is not a test** (`main.rs:6395`; the test module begins at `:7331`). Changing the signature would churn all of them and bury the real diff.

- [ ] **Step 1: Write the failing tests**

```rust
    /// SEC-025-C: a production genesis must mint nothing. Boot fabricated seven
    /// unbacked deposits (MM + user per market across 3 markets, plus an LP-demo
    /// grant), each folding a sentinel leaf into `consumed_deposit_tip`. Every settle
    /// then submitted `newDepositCount = 7+` against a vault whose `depositCount` is 0,
    /// and `_requireDepositPrefix` reverted BEFORE the proof was verified.
    #[test]
    fn production_genesis_mints_nothing() {
        let gw = Gw::boot_with(GenesisMode::Production);
        let s = &gw.seq.state;
        assert_eq!(s.consumed_deposit_count, 0, "no deposits at genesis");
        assert_eq!(s.consumed_deposit_tip, [0u8; 32], "untouched deposit chain");
        assert_eq!(s.insurance_fund, 0, "no seeded insurance");
        assert_eq!(s.external_in, 0, "no external value asserted");
        assert!(s.notes.is_empty(), "no notes");
        assert!(s.positions.is_empty(), "no positions");
        assert_eq!(s.markets.len(), MARKETS.len(), "markets ARE registered");
    }

    /// The pair a fresh vault expects. `CollateralVault.sol:59` states that
    /// `depositTipAt[0]` is never written and the mapping default `bytes32(0)` IS the
    /// genesis tip, so this is the exact tuple `_requireDepositPrefix(0, 0)` accepts.
    #[test]
    fn production_genesis_matches_a_fresh_vault_prefix() {
        let gw = Gw::boot_with(GenesisMode::Production);
        assert_eq!(
            (gw.seq.state.consumed_deposit_tip, gw.seq.state.consumed_deposit_count),
            ([0u8; 32], 0u64),
        );
    }

    /// The demo path is untouched — explicitly demo-scoped, not a global expectation.
    #[test]
    fn demo_genesis_is_still_funded() {
        let gw = Gw::boot();
        let s = &gw.seq.state;
        assert_eq!(
            s.consumed_deposit_count,
            (MARKETS.len() as u64) * 2 + 1,
            "MM + user per market, plus the LP-demo grant"
        );
        assert!(s.insurance_fund > 0, "demo seeds insurance");
        assert!(!s.notes.is_empty() || !s.positions.is_empty(), "demo has value");
    }

    /// The window must open from genesis with nothing staged, or the first settle's
    /// witness pre-state would not be the deployed GENESIS_ROOT.
    #[test]
    fn production_genesis_leaves_no_staged_ops() {
        let gw = Gw::boot_with(GenesisMode::Production);
        assert!(
            !gw.seq.window_has_pending_manifest(),
            "no manifest content at genesis"
        );
    }
```

`window_has_pending_manifest` was added by 025-B (`crates/sequencer/src/lib.rs`). If `window_ops` needs a similar accessor to assert emptiness and none exists, add one rather than making the field public — and say so in your report.

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test --bin gateway production_genesis`
Expected: FAIL to compile — `GenesisMode` and `boot_with` do not exist.

- [ ] **Step 3: Implement**

Add near `Gw`:

```rust
/// SEC-025-C: what a boot mints at genesis. **Passed into `Gw::boot_with`, never read
/// from `Gw::prod`** — `prod` is assigned two lines after `boot()` returns
/// (`main.rs:6395` then `:6397`), so it cannot guard the funding that happens inside.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GenesisMode {
    /// Registers markets AND funds MM / demo user / LP demo, and seeds insurance.
    /// Those are UNBACKED mints with sentinel L1 fields, so a chain built on this
    /// genesis can never satisfy `_requireDepositPrefix`. Demo and no-L1 dev only.
    Demo,
    /// Markets only. `consumed_deposit_tip` and `consumed_deposit_count` stay at their
    /// `State::new` values, which is exactly the pair a fresh vault's `depositTipAt(0)`
    /// returns — so the first settle's deposit-prefix pin passes.
    Production,
}
```

Change `fn boot() -> Self` to:

```rust
    fn boot() -> Self {
        Self::boot_with(GenesisMode::Demo)
    }

    fn boot_with(mode: GenesisMode) -> Self {
```

and wrap Pass 2 — the `for (i, cfg) in MARKETS.iter().enumerate()` funding loop (`:1553-1578`), the LP-demo `fund` (`:1578`), and the `SeedInsurance` apply (`:1580-1584`) — in `if mode == GenesisMode::Demo { … }`. Leave Pass 1 (market + oracle registration) and `seal_genesis_baseline()` outside it; with no Pass-2 ops the baseline simply folds nothing.

At the single non-test caller (`:6395`), pass the mode derived from `production_mode`:

```rust
        let genesis_mode = if prod {
            GenesisMode::Production
        } else {
            GenesisMode::Demo
        };
```

`prod` is already in scope there (`main.rs:6124`). Note the ordering: `genesis_mode` must be computed **before** `Gw::boot_with(...)`, which is why this works where `gw.prod` does not.

- [ ] **Step 4: Run to verify they pass**

Run: `cargo test --bin gateway genesis`
Expected: PASS (4 tests).

- [ ] **Step 5: Run the whole suite**

Run: `cargo test --workspace`
Expected: PASS at 521 + 4. **Any existing test that assumed a funded genesis and now fails is a finding — report which and why before changing it.** Most tests call `Gw::boot()`, which is unchanged.

- [ ] **Step 6: Format, lint, commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets
git add crates/gateway/src/main.rs
git commit -m "feat(gateway): SEC-025-C — a production genesis mints nothing

Boot fabricated seven unbacked deposits with sentinel L1 fields, so every settle
submitted newDepositCount = 7+ against a fresh vault whose depositCount is 0 and
_requireDepositPrefix reverted before the proof was even verified.

The mode is a PARAMETER of boot, not a field read inside it: gw.prod is assigned
two lines after boot() returns, so it cannot guard the funding. boot() keeps its
signature as boot_with(Demo) — there are ~80 call sites and exactly one is not a
test."
```

---

### Task 2: Thread the mode to every unbacked-funding call site

**Files:**
- Modify: `crates/gateway/src/main.rs` — `fund` (`:4033`), `fund_amount_unbacked` (`:4059`), and all five call sites: `:2386`, `:2911`, `:2930`, `:3060`, `:3419`, `:7512`
- Test: `crates/gateway/src/main.rs` (`mod tests`)

**Interfaces:**
- Consumes: `GenesisMode` (Task 1).
- Produces: `fund_amount_unbacked(..., prod: bool)` and `fund(..., prod: bool)`, both returning `Err` when `prod` is true.

**Why threading, and why through `fund` too.** The first draft added `prod` only to `fund_amount_unbacked`. Review found that forces `fund` to supply *some* boolean but not the *correct* one, because `fund` has no mode input — and **`fund` is not boot-only: `Gw::simulate_adl` calls it twice at runtime** (`:2911`, `:2930`), protected only by `/api/simulate-adl` sitting inside the router's `if !prod` block. That is route-only enforcement, which this design exists to replace.

**The five sites and what each must pass:**

| Site | Passes |
|---|---|
| `:2386` self-service deposit | `self.prod` (it already returns `Err` when `self.prod` — keep that guard *and* pass the flag; belt and braces, and the compiler now records the intent) |
| `:2911`, `:2930` `simulate_adl` | `self.prod` |
| `:3060` LP `pool_transfer` | `self.prod` |
| `:3419` legacy `Gw::deposit` | `self.prod` |
| `:7512` test fixture | `false` |
| Task 1's boot Pass 2 | `false` — it only runs under `GenesisMode::Demo` |

- [ ] **Step 1: Write the failing tests**

```rust
    /// SEC-025-C: unbacked minting must be refused in production AT THE CALL SITE,
    /// not merely unrouted. `/v1/lp/*` was mounted in production and `simulate_adl`
    /// sits behind route-mounting alone — both reach `fund_amount_unbacked` and would
    /// re-corrupt `consumed_deposit_tip` after a clean genesis.
    #[test]
    fn unbacked_funding_is_refused_in_production() {
        let mut gw = Gw::boot_with(GenesisMode::Production);
        let before_root = gw.seq.state.state_root();
        let before_ops = gw.seq.window_op_count();
        let before_archive = gw.archive.len();
        let w = Wallet::from_seed([9u8; 32]);

        let err = fund_amount_unbacked(
            &mut gw.seq,
            &mut gw.archive,
            &w,
            0,
            1_000 * QUOTE_SCALE,
            [0x99u8; 32],
            /* prod */ true,
        )
        .expect_err("production must refuse an unbacked mint");
        assert!(err.contains("production"), "error names the reason: {err}");

        // `state_root()` alone is NOT sufficient here: this fn takes &mut Sequencer and
        // &mut NoteArchive, and state_root() commits only perp_core::State — a buggy
        // rejected call could mutate the sequencer's op log or the archive invisibly.
        assert_eq!(gw.seq.state.state_root(), before_root, "engine state untouched");
        assert_eq!(gw.seq.window_op_count(), before_ops, "no op staged");
        assert_eq!(gw.archive.len(), before_archive, "no archive record");
    }

    /// A production LP transfer is the live corruption path today.
    /// **This test must FAIL at the parent commit.**
    #[test]
    fn a_production_lp_transfer_is_refused() {
        let mut gw = Gw::boot_with(GenesisMode::Production);
        gw.prod = true;
        let before = gw.seq.state.consumed_deposit_count;
        let res = gw.pool_transfer_for_test();
        assert!(res.is_err(), "LP transfer must be refused in production");
        assert_eq!(
            gw.seq.state.consumed_deposit_count, before,
            "the deposit accumulator must not move"
        );
    }

    /// simulate_adl reaches `fund` at runtime and was protected only by route mounting.
    #[test]
    fn a_production_simulate_adl_is_refused() {
        let mut gw = Gw::boot_with(GenesisMode::Production);
        gw.prod = true;
        let before = gw.seq.state.consumed_deposit_count;
        assert!(gw.simulate_adl().is_err(), "refused in production");
        assert_eq!(gw.seq.state.consumed_deposit_count, before);
    }

    /// The legacy demo deposit is protected today only by its route not being mounted.
    /// After this task the method itself refuses, so an internal caller cannot reach it.
    #[test]
    fn legacy_deposit_is_refused_in_production() {
        let mut gw = Gw::boot_with(GenesisMode::Production);
        gw.prod = true;
        let before = gw.seq.state.consumed_deposit_count;
        assert!(
            gw.deposit(1_000 * QUOTE_SCALE).is_err(),
            "the method must refuse, not merely be unrouted"
        );
        assert_eq!(gw.seq.state.consumed_deposit_count, before);
    }

    /// DP-001 regression — self-service was already correctly closed; keep it closed.
    #[test]
    fn self_service_deposit_is_still_refused_in_production() {
        let mut gw = Gw::boot_with(GenesisMode::Production);
        gw.prod = true;
        let before = gw.seq.state.consumed_deposit_count;
        assert!(gw.self_service_deposit_for_test().is_err());
        assert_eq!(gw.seq.state.consumed_deposit_count, before);
    }
```

**You must supply three things this plan does not:** `Sequencer::window_op_count()` (add it next to `window_has_pending_manifest` if absent — do not make the field public), `NoteArchive::len()` (or an equivalent record count), and the two `*_for_test` entry points — or, better, call the real methods directly if they are reachable from the test module. **If a real method is reachable, use it and delete the shim from this plan**; a shim that bypasses the guarded path would be a thirteenth defective fixture.

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test --bin gateway unbacked_funding`
Expected: FAIL to compile (the `prod` parameter does not exist). Then, after adding the parameter but before the guard, the assertions must fail — **confirm you see that second failure**, not only the compile error.

- [ ] **Step 3: Implement**

Add the parameter and the refusal to both functions:

```rust
fn fund_amount_unbacked(
    seq: &mut Sequencer,
    archive: &mut NoteArchive,
    w: &Wallet,
    market: u64,
    amount: i128,
    blind: Digest,
    prod: bool,
) -> Result<(), String> {
    // SEC-025-C: an unbacked mint folds a sentinel leaf into `consumed_deposit_tip`
    // that the on-chain vault chain can never match, so a single one breaks every
    // subsequent settle at `_requireDepositPrefix` — before the proof is verified.
    // Refused HERE rather than at the router, because route-mounting protects one
    // caller and is invisible to the next one added: that is exactly how /v1/lp and
    // simulate_adl came to be reachable while self-service was correctly closed.
    if prod {
        return Err(
            "unbacked funding is refused in production: collateral must enter through a \
             verified L1 deposit (CollateralVault.deposit → account_confirm_deposit)"
                .to_string(),
        );
    }
    let deposit_id = seq.state.consumed_deposit_count;
    fund_amount(
        seq, archive, w, market, amount, blind, [0u8; 20], deposit_id, [0u8; 32],
    )
    .map_err(|e| e.to_string())
}
```

and give `fund` the same `prod: bool`, forwarding it. Then fix all five call sites per the table above — the compiler will find them.

- [ ] **Step 4: Run to verify they pass**

Run: `cargo test --bin gateway production`
Expected: PASS.

- [ ] **Step 5: Mutation-check the two live paths**

Remove the `if prod` guard, re-run `a_production_lp_transfer_is_refused` and `a_production_simulate_adl_is_refused`, and confirm **both fail**. Restore the guard. Record both outputs — these two are the paths that are live today, and a test that passes with the guard removed is testing nothing.

- [ ] **Step 6: Run the whole suite, format, lint, commit**

```bash
cargo test --workspace
cargo fmt --all
cargo clippy --workspace --all-targets
git add crates/gateway/src/main.rs
git commit -m "feat(gateway): SEC-025-C — refuse unbacked minting at every call site

fund_amount_unbacked has five call sites, and the fund wrapper is not boot-only:
simulate_adl calls it twice at runtime behind route-mounting alone, and /v1/lp/*
is mounted in production. Either one re-corrupts consumed_deposit_tip after a
clean genesis and breaks settling again.

The mode threads through fund as well as fund_amount_unbacked, so the compiler
forces the decision at every site — adding the flag to only the inner function
would force callers to pass SOME boolean, not the correct one."
```

---

### Task 3: `/v1/lp/*` is not mounted in production

**Files:**
- Modify: `crates/gateway/src/main.rs` — `build_router` (`:6063`), the `/v1/lp` routes at `:6107-6109`
- Test: `crates/gateway/src/main.rs` (`mod tests`)

**Interfaces:**
- Consumes: nothing. Independent of Tasks 1–2, but the guard added in Task 2 is what makes this defence in depth rather than the only protection.

`/v1/lp`, `/v1/lp/deposit` and `/v1/lp/withdraw` are mounted **outside** the `if !prod` block that begins at `:6071` and covers only the legacy `/api/*` routes. Authentication exists (`:5179`) but no mode gate.

- [ ] **Step 1: Write the failing test**

```rust
    /// SEC-025-C: the LP pool credits via an unbacked mint (`pool_transfer` →
    /// `fund_amount_unbacked`), so it cannot exist in production without breaking
    /// settlement. Task 2 refuses it at the call site; this keeps it off the surface
    /// entirely. **Must fail at the parent commit** — these routes are mounted today.
    #[tokio::test]
    async fn lp_routes_are_absent_in_production() {
        for path in ["/v1/lp", "/v1/lp/deposit", "/v1/lp/withdraw"] {
            let status = router_status_for(/* prod */ true, path).await;
            assert_eq!(
                status,
                axum::http::StatusCode::NOT_FOUND,
                "{path} must not be mounted in production"
            );
        }
    }

    /// …and still present in demo, so this is a posture change, not a deletion.
    #[tokio::test]
    async fn lp_routes_are_present_in_demo() {
        for path in ["/v1/lp", "/v1/lp/deposit", "/v1/lp/withdraw"] {
            let status = router_status_for(/* prod */ false, path).await;
            assert_ne!(
                status,
                axum::http::StatusCode::NOT_FOUND,
                "{path} must remain mounted in demo"
            );
        }
    }
```

**You must supply `router_status_for(prod, path)`** — build the router via `build_router(app, prod)` and issue a request through `tower::ServiceExt::oneshot`. Check whether the test module already has such a helper before writing one; if it does, use it. An unauthenticated request to a mounted-but-authenticated route returns 401, not 404, which is what makes 404-vs-not-404 the right discriminator here — **verify that is actually what happens rather than assuming it**, and if a mounted route returns something else, assert on that instead and say so.

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test --bin gateway lp_routes`
Expected: `lp_routes_are_absent_in_production` FAILS (the routes are mounted).

- [ ] **Step 3: Implement**

Move the three `/v1/lp*` routes out of the unconditional chain into a `if !prod` block, alongside the existing legacy-route block. Keep them in one place with a comment:

```rust
    if !prod {
        // SEC-025-C: the LP pool credits through an UNBACKED mint (`pool_transfer` →
        // `fund_amount_unbacked`), which folds a sentinel leaf the vault chain cannot
        // match — one call breaks every later settle at `_requireDepositPrefix`. Task 2
        // refuses it at the call site; not mounting it in production keeps it off the
        // surface too. Removing this block does NOT re-enable LP in production.
        router = router
            .route("/v1/lp", get(get_v1_lp))
            .route("/v1/lp/deposit", post(post_v1_lp_deposit))
            .route("/v1/lp/withdraw", post(post_v1_lp_withdraw));
    }
```

- [ ] **Step 4: Run to verify both pass, then the suite**

Run: `cargo test --bin gateway lp_routes && cargo test --workspace`
Expected: PASS. **Any existing test that requested a `/v1/lp` route in production mode is a finding — report it.**

- [ ] **Step 5: Format, lint, commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets
git add crates/gateway/src/main.rs
git commit -m "feat(gateway): SEC-025-C — /v1/lp/* is not mounted in production

The three LP routes sat outside the if !prod block, which covers only the legacy
/api/* routes. Authentication existed but no mode gate, so an LP transfer in
production reached an unbacked mint and re-corrupted the deposit accumulator.

Defence in depth: the load-bearing guard is Task 2's call-site refusal, which
survives a routing change."
```

---

### Task 4: Verify L1 continuity on every L1-configured boot

**Files:**
- Modify: `crates/gateway/src/main.rs:6584-6616` (the restored-state continuity block)
- Test: `crates/gateway/src/main.rs` (`mod tests`)

**Interfaces:**
- Consumes: `Gw::last_settled_root` (a `Digest`, initialized to `genesis_root` at `:1618`), `hex32(&Digest) -> String` (`:64`), `L1::current_root() -> Result<String, String>`.

**The gap.** Today the check runs only when `gw.l1_status` is `Some` (`:6588`). But `l1_status` stays `None` until `commit_window_settle` succeeds (`:1098`, `:2252`), while the gateway persists periodically regardless (`:1656`, `:6685`) and restore deserializes the whole `Gw` including its deposit accumulator (`:1669`). **So a snapshot taken before the first successful settle is checked by nothing.** And because `prod` is deliberately not persisted and is overwritten from the environment after restore (`:1122`, `:6397`), a *demo* snapshot carrying unbacked deposits can be restored under production posture.

**Do not compare `state_root()`.** A legitimate pre-first-settle snapshot may hold real pending deposits and correctly differ from the chain. `last_settled_root` is the universal continuity value: initialized to genesis, advanced only after a settle lands (`:2236`).

- [ ] **Step 1: Write the failing tests**

```rust
    /// SEC-025-C: continuity must be checked on EVERY L1-configured boot. A snapshot
    /// taken before the first settle has `l1_status == None`, so neither the old check
    /// nor a fresh-boot-only check covers it — and since `prod` is not persisted, a
    /// DEMO snapshot with unbacked deposits can be restored under production posture.
    /// **Must fail at the parent commit.**
    #[test]
    fn continuity_is_checked_when_l1_status_is_none() {
        // genesis root vs a chain that has advanced past it
        assert!(
            !continuity_ok(&[0x11u8; 32], "0x2222222222222222222222222222222222222222222222222222222222222222"),
            "a mismatch must be refused even with no prior settle"
        );
        assert!(
            continuity_ok(&[0x11u8; 32], &hex32(&[0x11u8; 32])),
            "a match starts"
        );
    }

    /// Hex comparison must not be case-sensitive — `current_root()` returns whatever
    /// the RPC formats, and the existing check used `eq_ignore_ascii_case`.
    #[test]
    fn continuity_comparison_ignores_hex_case() {
        let root = [0xABu8; 32];
        assert!(continuity_ok(&root, &hex32(&root).to_uppercase()));
    }
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test --bin gateway continuity`
Expected: FAIL — `continuity_ok` does not exist.

- [ ] **Step 3: Implement**

Extract the comparison so it is testable without a chain, then widen the guard:

```rust
/// SEC-025-C: does the gateway's last settled root match the chain's currentStateRoot?
/// Split from the boot wiring so it is testable without an RPC. Case-insensitive
/// because `current_root()` returns whatever the node formats.
fn continuity_ok(last_settled_root: &Digest, chain_root: &str) -> bool {
    hex32(last_settled_root).eq_ignore_ascii_case(chain_root)
}
```

Replace the `if let (Some(l1c), Some(st)) = (&l1, gw.l1_status.as_ref())` guard with `if let Some(l1c) = &l1`, and compare `continuity_ok(&gw.last_settled_root, &r)`. Update the refusal message to print `hex32(&gw.last_settled_root)` and the chain root, and say the snapshot may be stale, from a different deployment, **or a demo snapshot booted under production posture**.

**Keep the `Err` arm's fail-closed `exit(1)` exactly as it is** — an unreachable RPC must refuse the boot, not skip the check. This is preserved behaviour rather than new behaviour, so it needs no new test; but it is the single line most likely to be "temporarily" softened during a cutover when a node is flaky, and softening it is precisely how the existing conditional became vacuous. If you find yourself changing that arm, stop and report instead.

- [ ] **Step 4: Run to verify they pass, then the suite**

Run: `cargo test --bin gateway continuity && cargo test --workspace`
Expected: PASS. **Any existing boot test that configures L1 without a matching chain root will now refuse to start — report which, and whether the test's expectation or the fixture is what needs updating.**

- [ ] **Step 5: Format, lint, commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets
git add crates/gateway/src/main.rs
git commit -m "feat(gateway): SEC-025-C — check L1 continuity on every L1 boot

The check ran only when l1_status was Some, but l1_status stays None until the
first settle commits while the gateway persists throughout — so a pre-first-settle
snapshot was checked by nothing. And prod is not persisted and is overwritten from
the environment after restore, so a demo snapshot carrying unbacked deposits could
be restored under production posture.

Compares last_settled_root, not state_root(): a legitimate pre-settle snapshot may
hold real pending deposits and correctly differ from the chain."
```

---

### Task 5: Prove the fifth blocker is closed, end to end

Asserting the constants `(bytes32(0), 0)` proves two constants. It would not catch `main()` still calling demo boot, a sentinel op left staged in the window, or a wrong witness pre-state reaching the prover.

**Files:**
- Test: `crates/gateway/src/main.rs` (`mod tests`)

**Interfaces:**
- Consumes: `Gw::boot_with(GenesisMode::Production)` (Task 1); `prove_and_prepare` / `MockProverClient` / `ProveOutcome.new_deposit_count` (025-B, `crates/gateway/src/prover_client.rs`); `Gw::begin_window_settle` (025-B).

- [ ] **Step 1: Write the failing test**

```rust
    /// SEC-025-C: the row that actually proves the fifth blocker is closed. From a
    /// PRODUCTION boot, seal a window and run the real prove path; the tuple that would
    /// go on-chain must be the zero prefix a fresh vault accepts.
    ///
    /// The contract side is already covered — `contracts/test/DarkPerpSettlement.t.sol`
    /// lands a zero-prefix settle — but nothing connected it to the boot mode, which is
    /// the half that was broken.
    #[test]
    fn a_production_genesis_window_submits_the_zero_prefix() {
        let mut gw = Gw::boot_with(GenesisMode::Production);
        gw.prod = true;

        let (witness, ww) = gw
            .begin_window_settle(0)
            .expect("no desync at genesis")
            .expect("a genesis window is settleable");

        let prepared = prover_client::prove_and_prepare(
            &prover_client::MockProverClient,
            &witness,
            &ww,
        )
        .expect("local derivation agrees with the mock prover");

        assert_eq!(
            prepared.outcome.deposits_root, [0u8; 32],
            "depositsRoot must be the vault's genesis tip"
        );
        assert_eq!(
            prepared.outcome.new_deposit_count, 0,
            "newDepositCount must be 0 — _requireDepositPrefix reads depositTipAt(0)"
        );
    }
```

**Verify the precondition rather than assuming it:** a production genesis has no state change and no manifest content, so `begin_window_settle` may correctly return `None` (025-B's predicate). If it does, this test needs a window with *something* in it — submit one order first, or assert on a window that follows a real confirmed deposit. **Do not weaken the assertions to make it pass; change the fixture and say what you changed.** A test that settles an empty window is not exercising the path a real deployment takes.

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test --bin gateway zero_prefix`
Expected: FAIL — `boot_with` does not exist at the parent commit; after Task 1 it must pass. If it passes at the parent commit, the test is not reaching the production path.

- [ ] **Step 3: Add the invariant enumeration test**

```rust
    /// SEC-025-C's invariant, checked by enumeration rather than by imagining an attack
    /// — the method that made SEC-024's core the one design in this workstream to
    /// survive review intact. `fund_amount` is the ONLY constructor of BatchOp::Deposit
    /// in the gateway, and `op_deposit` is the only writer of the accumulator, so
    /// guarding the unbacked wrapper is sufficient — but a NEW unbacked caller must
    /// break something. This test is that something.
    #[test]
    fn unbacked_funding_has_exactly_the_known_call_sites() {
        let src = include_str!("main.rs");
        let n = src.matches("fund_amount_unbacked(").count();
        assert_eq!(
            n, 7,
            "expected 1 definition + 1 doc mention + 5 call sites; found {n}. \
             If you added an unbacked-funding call site, it MUST pass the production \
             flag — update this count only after confirming the new site is guarded."
        );
    }
```

**Verify the count empirically before committing it** — grep the file and use the real number, with the breakdown in the message. A count that is wrong on day one makes the test noise, and a maintainer will delete it.

- [ ] **Step 4: Run the suite, format, lint, commit**

```bash
cargo test --workspace
cargo fmt --all
cargo clippy --workspace --all-targets
git add crates/gateway/src/main.rs
git commit -m "test(gateway): SEC-025-C — prove the zero prefix end to end

Asserting the constants proves two constants. This boots production, seals a
window, runs the real prove path, and asserts the tuple that would reach
settleBatch is the zero prefix a fresh vault accepts — which is what would have
caught main() still calling demo boot or a sentinel op left staged.

Plus an enumeration guard: a new unbacked-funding call site must break a test."
```

---

## Branch completion

- [ ] `cargo test --workspace` green; `cd contracts && forge test` still **85 passed**; `cargo fmt --all -- --check` and `cargo clippy --workspace --all-targets` clean.
- [ ] Confirm which tests were verified to **fail at the parent commit**: Task 2's LP and `simulate_adl` refusals, Task 3's route absence, Task 4's `l1_status == None` continuity. These are what prove the branch does something.
- [ ] Request an independent review of the branch. **Codex found six defects in this piece's design, four of which changed it — expect it to find more in the implementation.** Verify every finding at source before accepting it.
- [ ] **Do not deploy.** `GENESIS_ROOT` moves, so this needs a fresh `DarkPerpSettlement` deploy and a snapshot wipe. The cutover also needs SEC-024, 025-A and 025-D; **025-B + 025-C is the smallest set that *settles*, not the smallest set that is *safe to launch*** — production starts with zero insurance until 025-A, and nothing gates trading on it until 025-D.
- [ ] **Runbook item for the cutover:** the live testnet loses its funded MM, demo user, LP pool and insurance. Liquidity must be re-established through real deposits (faucet → `CollateralVault.deposit` → `account_confirm_deposit`). If that proves impractical the fallback is a thinner book — **never reintroducing unbacked minting**, which would re-break settling.

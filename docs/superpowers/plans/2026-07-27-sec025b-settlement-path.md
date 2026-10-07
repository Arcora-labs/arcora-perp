# SEC-025 025-B — Finish the SEC-019 settlement path — Implementation Plan


**Goal:** Make the repo settle end-to-end again, so SEC-021, SEC-022 and SEC-026 — merged but undeployable — can reach a chain.

**Architecture:** The gateway stops trusting the prover for anything that reaches L1. It replays its own `WindowWitness` through `perp_core::commitment::derive_roots`, becoming the source of truth for all seven roots and the cumulative deposit count, and calls the prover only for proof bytes. Four independent breaks are closed along the way, plus one latent path deleted.

**Source spec:** `docs/superpowers/specs/2026-07-27-sec025b-settlement-path-design.md` — read its "Correction history" before starting; the first draft of this design was wrong in three structural ways and the corrections are what the tasks below encode.

**Tech Stack:** Rust, `postcard` serde, `axum` (prover-service), `cast`/foundry (L1 calls), SP1 zkVM.

## Global Constraints

- **`cargo fmt --all` before every commit.** CI runs `cargo fmt --all -- --check` (`.github/workflows/ci.yml:19`) and implementers on this workstream have repeatedly missed it.
- **`cargo clippy --workspace --all-targets` must be clean.**
- **`crates/perp-core` must not be modified by any task in this plan.** It compiles into the SP1 guest; a change there moves the vkey. This piece deliberately does not.
- **`crates/sp1-host` and `crates/prover-service` stay `exclude`d from the workspace** (`Cargo.toml:25`). They pull `sp1-sdk` (Groth16, Docker, gnark) and must never enter `cargo build --workspace`.
- **Baseline: `cargo test --workspace` = 502 passed / 50 suites** at the branch point. Each task should move it by exactly the number of tests it adds.
- **A test that passes both before and after a change is not evidence.** Several tasks below name a row that MUST fail at the parent commit; if it does not, the test is wrong, not the code.

## Fixture suspicion is mandatory

The immediately preceding branch (SEC-022) shipped **seven defective test fixtures across six tasks** — every one a test that passed permanently while exercising nothing: a fee cut that was zero, a `pool_delta` that netted to zero, a transcript signed at the fill price, a market that panicked in setup, a fragmentation test that didn't fragment, a unit test green with the code unwired, a taker too small to reach the poisoned quote.

**Assume the fixtures below are wrong too.** Before accepting that a test passes, satisfy yourself it reaches the specific code path its name claims and would fail if the behaviour regressed. Where a task says "must fail before the change", verify that literally by stashing the change. If you find a defect, fix it minimally, comment the reason inline, and report it.

**Known weak spot in this plan, stated up front:** Tasks 3 and 6 ask you to write fixture helpers (`tests_support::sample_window`, `sample_window_no_deposits`, `gw_with_market`, `resting_order`) whose bodies this plan does **not** supply, because the gateway's existing test-support shape was not in the author's context. That is precisely the gap that produced defective fixtures on the previous branch. The mitigation is built into the tests: each one carries **precondition assertions** that fail loudly if the fixture does not have the property the test needs (a pre-state count above zero; a resting order that genuinely does not move the root). Do not delete those assertions to make a test pass — they are the only thing standing between a wrong fixture and a permanently green test that proves nothing.

---

### Task 1: Fix the prover bins, and add the CI check that stops them rotting again

**Files:**
- Modify: `crates/prover-service/src/bin/seal-client.rs:22`
- Modify: `crates/sp1-host/src/main.rs:43`
- Modify: `crates/sp1-host/src/bin/prove.rs:31`
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Produces: two excluded crates that type-check against the live `perp-core`, and a CI job that fails when they stop doing so.

- [ ] **Step 1: Confirm the break exists, so you know the fix is real**

Run: `cargo check --manifest-path crates/sp1-host/Cargo.toml 2>&1 | tail -20`
Expected: FAIL — `missing fields from, deposit_id, deposit_blind in initializer of BatchOp` (or equivalent E0063). If it does **not** fail, stop and report: the premise of this task is gone.

- [ ] **Step 2: Fix all three constructors**

Each of the three sites currently reads:

```rust
BatchOp::Deposit { owner, asset_id: 0, amount, blinding: blind },
```

Replace with the seven-field form. These are demo/smoke harnesses building a toy one-deposit state, so `deposit_id: 0` is correct (nothing has been consumed yet) and the L1 provenance fields are placeholders:

```rust
BatchOp::Deposit {
    owner,
    asset_id: 0,
    amount,
    blinding: blind,
    // SEC-019: demo harness — a toy state whose first deposit is index 0. `from` and
    // `deposit_blind` are placeholders; nothing here is bound to a real L1 event.
    from: [0u8; 20],
    deposit_id: 0,
    deposit_blind: [0u8; 32],
},
```

- [ ] **Step 3: Verify both excluded crates now type-check**

Run:
```bash
cargo check --manifest-path crates/sp1-host/Cargo.toml
cargo check --manifest-path crates/prover-service/Cargo.toml
```
Expected: both PASS. (First run downloads `sp1-sdk`'s dependency tree and is slow.)

- [ ] **Step 4: Add the CI job**

In `.github/workflows/ci.yml`, add a job alongside the existing ones:

```yaml
  excluded-crates-typecheck:
    # crates/sp1-host and crates/prover-service are excluded from the workspace
    # (Cargo.toml) because they pull sp1-sdk — Groth16, Docker, gnark — which must
    # not enter `cargo build --workspace`. That exclusion also means CI never
    # compiled them, so they silently rotted against perp-core: all three of their
    # binaries were still constructing the pre-SEC-019 four-field BatchOp::Deposit
    # and had not compiled since. `cargo check` type-checks against the real
    # perp-core path dependency without linking or proving, which is exactly the
    # coverage needed to catch a changed op shape.
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - run: cargo check --manifest-path crates/sp1-host/Cargo.toml
      - run: cargo check --manifest-path crates/prover-service/Cargo.toml
```

Match the existing jobs' toolchain and cache action versions rather than copying these verbatim if they differ — read the file first.

- [ ] **Step 5: Prove the job has teeth**

Stash the Step 2 fix and re-run the Step 3 commands. Expected: FAIL. Restore the fix. Record both outputs in your report — a CI job that passes at the parent commit is testing nothing, and this is the one item in the plan whose entire purpose is preventing recurrence.

- [ ] **Step 6: Format, lint, commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets
git add crates/prover-service crates/sp1-host .github/workflows/ci.yml
git commit -m "fix(prover): SEC-025-B — the excluded crates have not compiled since SEC-019

All three prover-side binaries still constructed the pre-SEC-019 four-field
BatchOp::Deposit. They are excluded from the workspace so sp1-sdk stays out of
cargo build --workspace, which also meant CI never compiled them and the drift
was invisible until someone built on the prover box.

Adds a cargo check job over both excluded crates. SEC-024 changes BatchOp next,
so without this the same break recurs immediately."
```

---

### Task 2: Parse a `/prove` response that omits `deposits_root`

**Files:**
- Modify: `crates/gateway/src/prover_client.rs:230-262` (`parse_prove_resp`)
- Test: `crates/gateway/src/prover_client.rs` (`mod tests`)

**Interfaces:**
- Produces: `pub struct RemoteProveResp { pub roots: RemoteRoots, pub commitment: Digest, pub proof: Vec<u8> }` where `RemoteRoots` holds `Option<Digest>` per root. `parse_prove_resp(json: &str) -> Result<RemoteProveResp, ProverClientError>`. Task 3 consumes it.

**Why a new type:** the authoritative `ProveOutcome` can only be built *after* Task 3's local replay, but `HttpProverClient::prove` must return something before then. Keeping `ProveOutcome` as the parse target is what forces the current all-or-nothing root parsing.

**Why not `#[serde(default)]` on the existing `String`:** an absent field defaults to `""`, and `parse_hex32("")` returns `None`, so the parse still fails. This was a defect in the first draft of the spec.

- [ ] **Step 1: Write the failing test**

Add to `crates/gateway/src/prover_client.rs`'s `mod tests`:

```rust
    /// SEC-025-B break 3: `prover-service`'s ProveResp has EIGHT fields and does not
    /// emit `deposits_root` (crates/prover-service/src/main.rs:71-80), while the parser
    /// required it — so every HTTP prove failed at JSON decode before any proof was
    /// examined. The requirement was recorded as a comment instructing the service to
    /// emit it, and never implemented.
    #[test]
    fn parses_a_response_without_deposits_root() {
        let json = r#"{
            "prev_root":"0x1111111111111111111111111111111111111111111111111111111111111111",
            "manifest_hash":"0x2222222222222222222222222222222222222222222222222222222222222222",
            "new_root":"0x3333333333333333333333333333333333333333333333333333333333333333",
            "ordered_root":"0x4444444444444444444444444444444444444444444444444444444444444444",
            "withdrawals_root":"0x5555555555555555555555555555555555555555555555555555555555555555",
            "rejected_root":"0x6666666666666666666666666666666666666666666666666666666666666666",
            "commitment":"0x7777777777777777777777777777777777777777777777777777777777777777",
            "proof":"0xabcd"
        }"#;
        let r = parse_prove_resp(json).expect("today's prover-service shape must parse");
        assert_eq!(r.commitment[0], 0x77);
        assert_eq!(r.proof, vec![0xab, 0xcd]);
        assert_eq!(r.roots.deposits_root, None, "absent field stays absent");
        assert_eq!(
            r.roots.new_root.expect("present roots still parse")[0],
            0x33
        );
    }

    /// Forward-compatible: if the service later emits the 7th word, it parses too.
    #[test]
    fn parses_a_response_with_deposits_root() {
        let json = r#"{
            "prev_root":"0x1111111111111111111111111111111111111111111111111111111111111111",
            "manifest_hash":"0x2222222222222222222222222222222222222222222222222222222222222222",
            "new_root":"0x3333333333333333333333333333333333333333333333333333333333333333",
            "ordered_root":"0x4444444444444444444444444444444444444444444444444444444444444444",
            "withdrawals_root":"0x5555555555555555555555555555555555555555555555555555555555555555",
            "rejected_root":"0x6666666666666666666666666666666666666666666666666666666666666666",
            "deposits_root":"0x8888888888888888888888888888888888888888888888888888888888888888",
            "commitment":"0x7777777777777777777777777777777777777777777777777777777777777777",
            "proof":"0xabcd"
        }"#;
        let r = parse_prove_resp(json).expect("forward-compatible");
        assert_eq!(r.roots.deposits_root.expect("present")[0], 0x88);
    }

    /// A malformed root that IS present must still be rejected — leniency is about
    /// absence, not about accepting garbage.
    #[test]
    fn rejects_a_present_but_malformed_root() {
        let json = r#"{
            "prev_root":"not-hex",
            "manifest_hash":"0x2222222222222222222222222222222222222222222222222222222222222222",
            "new_root":"0x3333333333333333333333333333333333333333333333333333333333333333",
            "ordered_root":"0x4444444444444444444444444444444444444444444444444444444444444444",
            "withdrawals_root":"0x5555555555555555555555555555555555555555555555555555555555555555",
            "rejected_root":"0x6666666666666666666666666666666666666666666666666666666666666666",
            "commitment":"0x7777777777777777777777777777777777777777777777777777777777777777",
            "proof":"0xabcd"
        }"#;
        assert!(parse_prove_resp(json).is_err(), "garbage must not parse as absent");
    }

    /// The commitment and proof are what Task 3 actually consumes — absent or
    /// malformed, they are a hard parse failure.
    #[test]
    fn rejects_a_response_missing_the_commitment() {
        let json = r#"{"proof":"0xabcd"}"#;
        assert!(parse_prove_resp(json).is_err());
    }
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p gateway --lib parses_a_response`
Expected: FAIL to compile — `RemoteProveResp` / `r.roots` do not exist.

- [ ] **Step 3: Implement the remote-response type**

Replace `parse_prove_resp` (`prover_client.rs:230-262`) with:

```rust
/// The six roots the prover-service currently emits, plus the 7th it does not yet.
/// Every field is optional: these are DIAGNOSTIC only. Under SEC-025-B the gateway
/// derives its own authoritative roots (see `prove_and_prepare`), so a response that
/// omits a root is not an error — it just yields a less specific message on mismatch.
#[derive(Debug, Default)]
pub struct RemoteRoots {
    pub prev_root: Option<Digest>,
    pub manifest_hash: Option<Digest>,
    pub new_root: Option<Digest>,
    pub ordered_root: Option<Digest>,
    pub withdrawals_root: Option<Digest>,
    pub rejected_root: Option<Digest>,
    pub deposits_root: Option<Digest>,
}

/// What `/prove` actually returns. Distinct from `ProveOutcome`, which is the
/// AUTHORITATIVE post-replay value and cannot be built until the gateway has replayed
/// the witness itself.
#[derive(Debug)]
pub struct RemoteProveResp {
    pub roots: RemoteRoots,
    pub commitment: Digest,
    pub proof: Vec<u8>,
}

pub fn parse_prove_resp(json: &str) -> Result<RemoteProveResp, ProverClientError> {
    #[derive(serde::Deserialize)]
    struct Resp {
        #[serde(default)]
        prev_root: Option<String>,
        #[serde(default)]
        manifest_hash: Option<String>,
        #[serde(default)]
        new_root: Option<String>,
        #[serde(default)]
        ordered_root: Option<String>,
        #[serde(default)]
        withdrawals_root: Option<String>,
        #[serde(default)]
        rejected_root: Option<String>,
        #[serde(default)]
        deposits_root: Option<String>,
        commitment: String,
        proof: String,
    }
    let r: Resp =
        serde_json::from_str(json).map_err(|e| ProverClientError::Decode(format!("json: {e}")))?;

    // An ABSENT root is fine (today's service omits `deposits_root`); a PRESENT but
    // unparseable one is not — leniency is about absence, never about garbage.
    let opt = |s: &Option<String>, name: &str| -> Result<Option<Digest>, ProverClientError> {
        match s {
            None => Ok(None),
            Some(v) => crate::parse_hex32(v)
                .map(Some)
                .ok_or_else(|| ProverClientError::Decode(format!("bad {name}: {v}"))),
        }
    };

    Ok(RemoteProveResp {
        roots: RemoteRoots {
            prev_root: opt(&r.prev_root, "prev_root")?,
            manifest_hash: opt(&r.manifest_hash, "manifest_hash")?,
            new_root: opt(&r.new_root, "new_root")?,
            ordered_root: opt(&r.ordered_root, "ordered_root")?,
            withdrawals_root: opt(&r.withdrawals_root, "withdrawals_root")?,
            rejected_root: opt(&r.rejected_root, "rejected_root")?,
            deposits_root: opt(&r.deposits_root, "deposits_root")?,
        },
        commitment: crate::parse_hex32(&r.commitment)
            .ok_or_else(|| ProverClientError::Decode(format!("bad commitment: {}", r.commitment)))?,
        proof: crate::decode_hex(&r.proof)
            .ok_or_else(|| ProverClientError::Decode(format!("bad proof: {}", r.proof)))?,
    })
}
```

`HttpProverClient::prove` and the `ProverClient` trait change in Task 3, which is where the return type is reconciled. If this task leaves the crate not compiling, that is expected — **fold Task 3 into the same commit rather than committing a broken tree.** (If you prefer to keep them separate, make `HttpProverClient::prove` construct a `ProveOutcome` from the remote roots temporarily and delete that in Task 3 — but say so in your report.)

- [ ] **Step 4: Run to verify they pass**

Run: `cargo test -p gateway --lib parses_a_response && cargo test -p gateway --lib rejects_a_`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit** (see the note in Step 3 about combining with Task 3)

```bash
cargo fmt --all
git add crates/gateway/src/prover_client.rs
git commit -m "fix(gateway): SEC-025-B break 3 — parse a /prove response without deposits_root

parse_prove_resp required a non-optional deposits_root that prover-service never
emits, so every HTTP prove failed at JSON decode before a proof was examined.
serde(default) on the String is not enough — an absent field becomes \"\", which
parse_hex32 rejects. Splits the wire shape into RemoteProveResp with optional
roots; the authoritative ProveOutcome is built after the local replay."
```

---

### Task 3: Local derivation — the gateway becomes the source of truth

This is the core of the piece.

**Files:**
- Modify: `crates/gateway/src/prover_client.rs` (`ProveOutcome`, `ProverClient` trait, `MockProverClient`, `HttpProverClient::prove`, `prove_and_prepare`)
- Modify: `crates/gateway/src/rollback_journal.rs` (`MAGIC`)
- Test: `crates/gateway/src/prover_client.rs` (`mod tests`)

**Interfaces:**
- Consumes: `RemoteProveResp` / `RemoteRoots` (Task 2).
- Produces: `ProveOutcome` gains `pub new_deposit_count: u64`. `ProverClient::prove` returns `Result<RemoteProveResp, ProverClientError>`. `prove_and_prepare(client, witness, ww) -> Result<PreparedSettle, String>` unchanged in signature, changed in behaviour. Task 4 consumes `outcome.new_deposit_count`.

**The property this rests on:** replaying a stored witness is deterministic — `derive_roots` is pure over explicit inputs (`crates/perp-core/src/commitment.rs:53`), `now_ms` is an explicit `BatchOp` field (`engine.rs:57`), state collections are ordered `BTreeMap`s. `crates/sequencer/tests/spine.rs:971` already pins that a replayed window reproduces its live root.

**The count is cumulative.** `op_deposit` requires `deposit_id == consumed_deposit_count` and increments it (`engine.rs:353`, `:385`). A window with zero deposits over a pre-state of five submits **5**, not 0.

- [ ] **Step 1: Write the failing tests**

```rust
    /// SEC-025-B §1: the gateway derives all seven roots from its OWN replay and requires
    /// the prover's commitment to equal its own. Because the commitment is a keccak over
    /// all seven words, that single comparison covers every root — replacing a check that
    /// only re-hashed the prover's own roots and so proved nothing but self-consistency.
    #[test]
    fn local_derivation_matches_the_mock_prover_on_all_seven_roots() {
        let (witness, ww) = crate::prover_client::tests_support::sample_window();
        let prepared = prove_and_prepare(&MockProverClient, &witness, &ww)
            .expect("mock agrees with local derivation");
        let mut state = witness.pre_state.clone();
        let d = perp_core::commitment::derive_roots(&mut state, &witness.ops, &witness.manifest)
            .expect("replay");
        let o = &prepared.outcome;
        assert_eq!(o.prev_root, d.prev_state_root);
        assert_eq!(o.manifest_hash, d.manifest_hash);
        assert_eq!(o.new_root, d.new_state_root);
        assert_eq!(o.ordered_root, d.ordered_root);
        assert_eq!(o.withdrawals_root, d.withdrawals_root);
        assert_eq!(o.rejected_root, d.rejected_root);
        assert_eq!(o.deposits_root, d.deposits_root);
    }

    /// The cumulative count, not the per-window one. This is the value
    /// `_requireDepositPrefix` pins BEFORE proof verification, so getting it wrong
    /// selects the wrong L1 prefix.
    #[test]
    fn new_deposit_count_is_cumulative_not_per_window() {
        let (witness, ww) = crate::prover_client::tests_support::sample_window();
        let pre_count = witness.pre_state.consumed_deposit_count;
        let n_deposits = witness
            .ops
            .iter()
            .filter(|o| matches!(o, perp_core::engine::BatchOp::Deposit { .. }))
            .count() as u64;
        let prepared = prove_and_prepare(&MockProverClient, &witness, &ww).expect("prove");
        assert_eq!(
            prepared.outcome.new_deposit_count,
            pre_count + n_deposits,
            "post == pre + deposits in window (NOT the per-window count)"
        );
    }

    /// A window with no deposits over a non-zero pre-state must still submit the
    /// pre-state count — the case a per-window reading gets wrong as 0.
    #[test]
    fn zero_deposit_window_submits_the_prestate_count() {
        let (witness, ww) = crate::prover_client::tests_support::sample_window_no_deposits();
        assert!(
            witness.pre_state.consumed_deposit_count > 0,
            "fixture precondition: the pre-state must have consumed deposits, or this \
             test cannot distinguish cumulative from per-window"
        );
        let prepared = prove_and_prepare(&MockProverClient, &witness, &ww).expect("prove");
        assert_eq!(
            prepared.outcome.new_deposit_count,
            witness.pre_state.consumed_deposit_count
        );
    }

    /// A prover whose commitment disagrees with local derivation must be refused
    /// OUTRIGHT — nothing prepared, nothing returned for broadcast.
    #[test]
    fn a_disagreeing_prover_is_refused() {
        struct LyingProver;
        impl ProverClient for LyingProver {
            fn prove(&self, _w: &WindowWitness) -> Result<RemoteProveResp, ProverClientError> {
                Ok(RemoteProveResp {
                    roots: RemoteRoots::default(),
                    commitment: [0xEE; 32],
                    proof: vec![0x01],
                })
            }
        }
        let (witness, ww) = crate::prover_client::tests_support::sample_window();
        let err = prove_and_prepare(&LyingProver, &witness, &ww)
            .expect_err("a commitment that disagrees with local derivation must be refused");
        assert!(
            err.contains("commitment"),
            "error should name the commitment mismatch, got: {err}"
        );
    }

    /// The diagnostic path: when the response DID carry roots, the error names which
    /// one differs rather than only reporting a commitment mismatch.
    #[test]
    fn a_disagreeing_prover_names_the_differing_root() {
        let (witness, ww) = crate::prover_client::tests_support::sample_window();
        let mut state = witness.pre_state.clone();
        let d = perp_core::commitment::derive_roots(&mut state, &witness.ops, &witness.manifest)
            .expect("replay");
        struct WrongNewRoot(perp_core::commitment::DerivedRoots);
        impl ProverClient for WrongNewRoot {
            fn prove(&self, _w: &WindowWitness) -> Result<RemoteProveResp, ProverClientError> {
                Ok(RemoteProveResp {
                    roots: RemoteRoots {
                        prev_root: Some(self.0.prev_state_root),
                        new_root: Some([0xEE; 32]), // the one that differs
                        ..RemoteRoots::default()
                    },
                    commitment: [0xEE; 32],
                    proof: vec![0x01],
                })
            }
        }
        let err = prove_and_prepare(&WrongNewRoot(d), &witness, &ww).expect_err("must refuse");
        assert!(
            err.contains("new_root"),
            "error should name new_root, got: {err}"
        );
    }
```

**You must write `tests_support::sample_window()` and `sample_window_no_deposits()`.** They build a `WindowWitness` + `Vec<Withdrawal>` by driving a `Sequencer` (see `crates/sequencer/tests/spine.rs:971` for the shape: `setup()`, `set_oracle`, `seal_batch`, `apply(BatchOp::Deposit{..})`, `seal_window`). `sample_window` must contain at least one deposit **and** at least one withdrawal (so the withdrawal-tree byte-match is exercised); `sample_window_no_deposits` must have a pre-state with `consumed_deposit_count > 0` and no `Deposit` ops in the window — the assertion in that test enforces the precondition, so a fixture that silently fails it will fail loudly rather than pass vacuously.

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p gateway --lib local_derivation`
Expected: FAIL — `new_deposit_count` does not exist; `ProverClient::prove` returns `ProveOutcome`.

- [ ] **Step 3: Implement**

1. Add to `ProveOutcome`:

```rust
    /// SEC-025-B: the POST-replay cumulative `consumed_deposit_count`, which is the
    /// `newDepositCount` argument of the nine-parameter `settleBatch`. Cumulative, not
    /// per-window: a zero-deposit window over a pre-state of five submits five.
    /// `_requireDepositPrefix` pins this to the L1 deposit hash chain BEFORE the proof
    /// is verified, so it is a fund-safety input and is derived locally, never accepted
    /// from the prover.
    pub new_deposit_count: u64,
```

2. Change the trait:

```rust
pub trait ProverClient: Send + Sync {
    /// Returns the prover's RAW response. The gateway derives the authoritative roots
    /// itself in `prove_and_prepare`; a client is trusted only for `proof` bytes.
    fn prove(&self, w: &WindowWitness) -> Result<RemoteProveResp, ProverClientError>;
}
```

3. `MockProverClient::prove` keeps deriving locally but returns the raw shape — it is now a *stand-in for the remote*, not a source of truth:

```rust
impl ProverClient for MockProverClient {
    fn prove(&self, w: &WindowWitness) -> Result<RemoteProveResp, ProverClientError> {
        let mut state = w.pre_state.clone();
        let d = derive_roots(&mut state, &w.ops, &w.manifest).map_err(ProverClientError::Derive)?;
        let commitment = d.commitment::<Keccak256>();
        Ok(RemoteProveResp {
            roots: RemoteRoots {
                prev_root: Some(d.prev_state_root),
                manifest_hash: Some(d.manifest_hash),
                new_root: Some(d.new_state_root),
                ordered_root: Some(d.ordered_root),
                withdrawals_root: Some(d.withdrawals_root),
                rejected_root: Some(d.rejected_root),
                deposits_root: Some(d.deposits_root),
            },
            commitment,
            proof: commitment.to_vec(),
        })
    }
}
```

4. `HttpProverClient::prove` returns `parse_prove_resp(...)`'s value directly.

5. Rewrite `prove_and_prepare`'s head — the local replay becomes the authority:

```rust
pub fn prove_and_prepare(
    client: &dyn ProverClient,
    witness: &WindowWitness,
    ww: &[Withdrawal],
) -> Result<PreparedSettle, String> {
    // SEC-025-B §1 — derive the answer ourselves. `derive_roots` is pure over explicit
    // inputs (no clock: `now_ms` is a stored BatchOp field), so replaying the witness we
    // are about to send is deterministic and reproduces what the prover must derive.
    // This replaces a check that re-hashed the PROVER's own roots and therefore only
    // established that the prover agreed with itself.
    let mut post = witness.pre_state.clone();
    let derived = derive_roots(&mut post, &witness.ops, &witness.manifest)
        .map_err(|e| format!("local replay failed: {e:?}"))?;
    let local_commitment = derived.commitment::<Keccak256>();

    let remote = client.prove(witness).map_err(|e| format!("prove: {e:?}"))?;

    // The commitment is a keccak over all seven roots, so this ONE comparison verifies
    // every root. The per-root loop below exists only to turn "commitment mismatch" into
    // "the prover's new_root differs", which is the difference between a five-minute and
    // a five-hour cutover debug.
    if remote.commitment != local_commitment {
        let mut which = Vec::new();
        for (name, ours, theirs) in [
            ("prev_root", derived.prev_state_root, remote.roots.prev_root),
            ("manifest_hash", derived.manifest_hash, remote.roots.manifest_hash),
            ("new_root", derived.new_state_root, remote.roots.new_root),
            ("ordered_root", derived.ordered_root, remote.roots.ordered_root),
            ("withdrawals_root", derived.withdrawals_root, remote.roots.withdrawals_root),
            ("rejected_root", derived.rejected_root, remote.roots.rejected_root),
            ("deposits_root", derived.deposits_root, remote.roots.deposits_root),
        ] {
            if let Some(t) = theirs {
                if t != ours {
                    which.push(format!("{name} (ours {} vs prover {})", crate::hex32(&ours), crate::hex32(&t)));
                }
            }
        }
        let detail = if which.is_empty() {
            "prover returned no itemised roots to compare".to_string()
        } else {
            which.join(", ")
        };
        return Err(format!(
            "commitment mismatch: ours {} vs prover {} — {detail}",
            crate::hex32(&local_commitment),
            crate::hex32(&remote.commitment)
        ));
    }

    let outcome = ProveOutcome {
        prev_root: derived.prev_state_root,
        manifest_hash: derived.manifest_hash,
        new_root: derived.new_state_root,
        ordered_root: derived.ordered_root,
        withdrawals_root: derived.withdrawals_root,
        rejected_root: derived.rejected_root,
        deposits_root: derived.deposits_root,
        new_deposit_count: post.consumed_deposit_count,
        commitment: local_commitment,
        proof: remote.proof,
    };
```

Keep the existing withdrawal-tree byte-match and `withdraw_proofs` construction below this, comparing against `outcome.withdrawals_root` as before — it is an independent check and stays.

6. Bump the journal magic in `crates/gateway/src/rollback_journal.rs`:

```rust
// SEC-025-B: ProveOutcome gained `new_deposit_count`, and PreparedSettle is journaled,
// so the positional postcard layout changed. SEC-022 already moved this to DPRBJL2 and
// a pre-025-B binary can therefore already have written DPRBJL2 — reusing it would make
// an old journal a silent postcard misparse instead of a versioned rejection.
const MAGIC: &[u8; 8] = b"DPRBJL3\0";
```

- [ ] **Step 4: Run to verify they pass**

Run: `cargo test -p gateway --lib`
Expected: PASS. Fix any other call sites the trait change breaks.

- [ ] **Step 5: Run the whole suite**

Run: `cargo test --workspace`
Expected: PASS, count = baseline + the tests you added.

- [ ] **Step 6: Format, lint, commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets
git add crates/gateway/src
git commit -m "feat(gateway): SEC-025-B §1 — the gateway derives its own settle roots

prove_and_prepare re-hashed the roots the PROVER returned and compared them to the
commitment the PROVER returned — circular, and passed by any broken, stale-vkey or
swapped prover. It now replays the witness itself and requires the prover's
commitment to equal its own; since the commitment is a keccak over all seven roots,
that one comparison covers them all. The prover is reduced to proof bytes.

Also yields newDepositCount (cumulative post-replay consumed_deposit_count) without
trusting the prover for a value _requireDepositPrefix pins before proof verification.

Journal magic to DPRBJL3: PreparedSettle is journaled and ProveOutcome grew a field."
```

---

### Task 4: The nine-parameter selector, and delete the legacy settle path

**Files:**
- Modify: `crates/gateway/src/l1.rs:425-450` (`settle_proved`)
- Delete: `crates/gateway/src/l1.rs:385-419` (`L1::settle`)
- Modify: `crates/gateway/src/main.rs:7285` (the one caller) and its surrounding legacy settle block
- Test: `crates/gateway/src/l1.rs` (`mod tests`)

**Interfaces:**
- Consumes: `ProveOutcome.new_deposit_count` (Task 3).

**Why deletion is safe:** `L1::settle` synthesizes its commitment via `publicCommitment(bytes32 ×6)`, which now takes seven roots, and submits through the seven-parameter `settleBatch`, which now takes nine. It is broken on both arities. Task 5 preserves a prover-free on-chain path via `PROVER_URL=mock`, which runs through the new window path with the correct ABI — so the legacy path is redundant, not merely non-production.

- [ ] **Step 1: Write the failing test**

```rust
    /// SEC-025-B: the encoded selector and argument order must byte-match Solidity's
    /// nine-parameter settleBatch (contracts/src/DarkPerpSettlement.sol:311-321). A
    /// fixed vector, NOT a round-trip through our own encoder — a round-trip would agree
    /// with itself even if both sides were wrong, which is exactly how the seven-param
    /// selector survived undetected.
    #[test]
    fn settle_batch_signature_matches_solidity() {
        assert_eq!(
            SETTLE_BATCH_SIG,
            "settleBatch(bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,uint64,bytes)"
        );
    }

    /// The argument vector must be in Solidity's declared order: six roots, then
    /// depositsRoot, then newDepositCount, then proof.
    #[test]
    fn settle_proved_argument_order_matches_solidity() {
        let out = crate::prover_client::ProveOutcome {
            prev_root: [0x11; 32],
            manifest_hash: [0x22; 32],
            new_root: [0x33; 32],
            ordered_root: [0x44; 32],
            withdrawals_root: [0x55; 32],
            rejected_root: [0x66; 32],
            deposits_root: [0x77; 32],
            new_deposit_count: 42,
            commitment: [0x88; 32],
            proof: vec![0xab, 0xcd],
        };
        let args = settle_proved_args(&out);
        assert_eq!(args.len(), 9);
        assert!(args[0].ends_with("1111"));
        assert!(args[5].ends_with("6666"));
        assert!(args[6].ends_with("7777"), "depositsRoot is 7th");
        assert_eq!(args[7], "42", "newDepositCount is 8th, decimal uint64");
        assert_eq!(args[8], "0xabcd", "proof is 9th");
    }
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p gateway --lib settle_batch_signature`
Expected: FAIL — `SETTLE_BATCH_SIG` and `settle_proved_args` do not exist.

- [ ] **Step 3: Implement**

Extract the signature and argument construction so they are testable without a chain:

```rust
/// The nine-parameter settleBatch signature. Six roots, then SEC-019's depositsRoot and
/// newDepositCount, then the proof. Must byte-match
/// `contracts/src/DarkPerpSettlement.sol:311-321`; the gateway previously sent the
/// seven-parameter form, which does not even resolve to this selector.
pub(crate) const SETTLE_BATCH_SIG: &str =
    "settleBatch(bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,uint64,bytes)";

pub(crate) fn settle_proved_args(out: &crate::prover_client::ProveOutcome) -> Vec<String> {
    let mut proof_hex = String::with_capacity(2 + out.proof.len() * 2);
    proof_hex.push_str("0x");
    for byte in &out.proof {
        proof_hex.push_str(&format!("{byte:02x}"));
    }
    vec![
        crate::hex32(&out.prev_root),
        crate::hex32(&out.manifest_hash),
        crate::hex32(&out.new_root),
        crate::hex32(&out.ordered_root),
        crate::hex32(&out.withdrawals_root),
        crate::hex32(&out.rejected_root),
        crate::hex32(&out.deposits_root),
        out.new_deposit_count.to_string(),
        proof_hex,
    ]
}
```

Rewrite `settle_proved` to use them:

```rust
    pub fn settle_proved(
        &self,
        out: &crate::prover_client::ProveOutcome,
    ) -> Result<String, String> {
        let args = settle_proved_args(out);
        let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        self.send(&self.settlement.clone(), SETTLE_BATCH_SIG, &refs)
    }
```

Then delete `L1::settle` entirely and remove its caller at `main.rs:7285` together with the legacy settle block it sits in. Follow the compiler: remove any now-unused helpers it alone used, but **do not** remove anything the new path still calls.

- [ ] **Step 4: Run to verify they pass**

Run: `cargo test -p gateway --lib settle_`
Expected: PASS.

- [ ] **Step 5: Run the whole suite**

Run: `cargo test --workspace`
Expected: PASS. If a test exercised the legacy settle path, it must be deleted or rewritten against the window path — **report which, and why**, rather than silently dropping coverage.

- [ ] **Step 6: Format, lint, commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets
git add crates/gateway/src
git commit -m "feat(gateway): SEC-025-B — nine-parameter settleBatch; delete the legacy path

The gateway sent a seven-parameter settleBatch to a contract that has taken nine
since SEC-019 — six roots plus depositsRoot and newDepositCount. The selector does
not resolve, so this was not a call that reverted informatively; it was not a call.

The legacy L1::settle is deleted: it synthesises its commitment through a
publicCommitment arity that is also stale, and PROVER_URL=mock now covers its role
through the window path with the correct ABI."
```

---

### Task 5: Refuse a prover-less production boot — without killing the testnet path

**Files:**
- Modify: `crates/gateway/src/main.rs:5843-5856` (`prover_from_str`)
- Test: `crates/gateway/src/main.rs` (`mod tests`)

**The trap this task exists to avoid.** `production_mode(l1_enabled) = l1_enabled || DARKPERP_PROD == "1"` (`main.rs:5829`), and settlement only runs inside `if let Some(l1)` (`main.rs:6760`). So keying the refusal to `prod` would mean: no L1 → dev but **no settlement at all**; L1 → production → mock refused. **No configuration would settle on-chain without a real prover** — which is precisely what a testnet or local anvil needs. The refusal must key on `DARKPERP_PROD=1` alone.

- [ ] **Step 1: Write the failing test**

```rust
    /// SEC-025-B §6: DARKPERP_PROD=1 must refuse a prover-less settle path — but an
    /// L1-configured TESTNET must still be able to run with mock. `production_mode` is
    /// `l1_enabled || DARKPERP_PROD`, so keying this on `prod` would leave no
    /// configuration that settles on-chain without a real prover.
    #[test]
    fn strict_prod_refuses_a_proverless_settle_path() {
        for v in [None, Some(""), Some("mock")] {
            let err = prover_from_str_strict(v, /* prod */ true, /* strict_prod */ true)
                .expect_err("strict production must refuse a prover-less path");
            assert!(
                err.contains("PROVER_URL"),
                "the error must name the variable an operator has to set, got: {err}"
            );
        }
    }

    /// The case the first draft of this design would have broken: an L1-configured
    /// testnet is `production_mode` (because `l1_enabled` implies it) but is NOT strict
    /// production, and must still be able to settle on-chain with the mock prover.
    #[test]
    fn a_testnet_may_still_use_the_mock_prover() {
        let c = prover_from_str_strict(Some("mock"), /* prod */ true, /* strict_prod */ false)
            .expect("mock is allowed outside strict production, even when prod-mode is on");
        assert!(c.is_some(), "mock must yield a client, not the legacy None path");
    }

    /// The legacy None path is gone (Task 4 deleted L1::settle), so an unset PROVER_URL
    /// outside strict production must still produce no client — the caller treats that
    /// as "do not run the settle loop", not as "settle through a deleted path".
    #[test]
    fn unset_prover_url_outside_strict_prod_yields_no_client() {
        let c = prover_from_str_strict(None, false, false).expect("allowed");
        assert!(c.is_none());
    }
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p gateway --lib strict_prod`
Expected: FAIL — `prover_from_str_strict` does not exist.

- [ ] **Step 3: Implement**

Add the strict predicate and thread it through. Keep `prover_from_str`'s existing behaviour for the non-strict case:

```rust
/// SEC-025-B: TRUE production, as opposed to `production_mode`, which is also true for
/// any L1-configured testnet (`l1_enabled || DARKPERP_PROD`). The prover-less settle
/// refusal keys on THIS, so a testnet can still settle on-chain with `PROVER_URL=mock`
/// while a real deployment cannot boot without a real prover.
fn strict_production() -> bool {
    std::env::var("DARKPERP_PROD").ok().as_deref() == Some("1")
}

/// `prover_from_str`, plus the strict-production refusal. Split from the env read so it
/// is testable without mutating process environment.
///
/// `prod` and `strict_prod` are DIFFERENT and both are needed: `prod` is
/// `production_mode` (true for any L1-configured deployment) and is what
/// `HttpProverClient::from_env` uses for its own fail-closed seal-root resolution;
/// `strict_prod` is `DARKPERP_PROD=1` alone and is what gates this refusal. Collapsing
/// them would refuse mock on every testnet.
fn prover_from_str_strict(
    v: Option<&str>,
    prod: bool,
    strict_prod: bool,
) -> Result<Option<std::sync::Arc<dyn prover_client::ProverClient>>, String> {
    if strict_prod && matches!(v, None | Some("") | Some("mock")) {
        return Err(
            "DARKPERP_PROD=1 requires a real prover: set PROVER_URL to the prover-service \
             endpoint. A prover-less settle path cannot produce a proof the on-chain \
             verifier accepts."
                .to_string(),
        );
    }
    prover_from_str(v, prod)
}
```

Route `prover_from_env_attested`'s fallback arm (`main.rs:5902`) through `prover_from_str_strict(other, prod, strict_production())` — note it already has `prod` in scope — and make the boot path surface the `Err` as a refusal to start rather than a warning.

- [ ] **Step 4: Run to verify they pass**

Run: `cargo test -p gateway --lib prover_url && cargo test -p gateway --lib strict_prod && cargo test -p gateway --lib testnet`
Expected: PASS (3 tests).

- [ ] **Step 5: Format, lint, commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets
git add crates/gateway/src/main.rs
git commit -m "feat(gateway): SEC-025-B §6 — refuse a prover-less production boot

Keyed to DARKPERP_PROD=1, deliberately NOT to production_mode: the latter is
l1_enabled || DARKPERP_PROD, and settlement only runs when L1 is configured, so
refusing on production_mode would leave no configuration that settles on-chain
without a real prover — breaking every testnet and local chain."
```

---

### Task 6: Settle windows that carry manifest content but no state change

This closes break 4, the wrongful-slash path.

**Files:**
- Modify: `crates/sequencer/src/lib.rs` (add an accessor near `window_ordered`, `:525-528`)
- Modify: `crates/gateway/src/main.rs:2183-2188` (`begin_window_settle`)
- Test: `crates/gateway/src/main.rs` (`mod tests`)

**Interfaces:**
- Produces: `Sequencer::window_has_pending_manifest(&self) -> bool`.

**The break:** `begin_window_settle` returns `None` purely on `state_root() == last_settled_root`. But an accepted order that rests without crossing is recorded in `ordered` (`crates/matcher/src/lib.rs:126`) and appended to the window (`crates/sequencer/src/lib.rs:1247`) without changing engine state — the book is matcher state, not `State`. Such a window never settles; its hashes never reach the challenge-answer store (`main.rs:2209` populates it only after a settle); and both contract answer paths require a settled batch (`DarkPerpSettlement.sol:508`, `:549`). An honest sequencer is then unable to answer a ripe challenge and is slashed.

- [ ] **Step 1: Write the failing test**

```rust
    /// SEC-025-B break 4: a window holding an accepted-but-unfilled order's hash must
    /// settle even though the engine root did not move. Otherwise its hashes never reach
    /// the challenge-answer store and an honest sequencer cannot answer a ripe inclusion
    /// challenge — a wrongful-slash path reachable by any user resting an order into an
    /// otherwise quiet window.
    #[test]
    fn a_manifest_only_window_still_settles() {
        let mut gw = tests_support::gw_with_market();
        let root_before = gw.seq.state.state_root();

        // A far-from-the-book limit that rests without crossing: no fill, no state change.
        gw.seq.seal_batch(&[tests_support::resting_order(1)], 1_000);

        assert_eq!(
            gw.seq.state.state_root(),
            root_before,
            "fixture precondition: a resting unfilled order must NOT move the engine root, \
             or this test is not exercising break 4"
        );
        assert!(
            gw.seq.window_has_pending_manifest(),
            "fixture precondition: the order must be in the window manifest"
        );

        let out = gw
            .begin_window_settle(gw.seq.state.next_batch_id)
            .expect("no desync");
        assert!(
            out.is_some(),
            "a window carrying manifest content must settle even with an unchanged root"
        );
    }

    /// The predicate must not turn idle ticks into proofs: a window empty in BOTH senses
    /// still returns None.
    #[test]
    fn a_truly_empty_window_still_returns_none() {
        let mut gw = tests_support::gw_with_market();
        assert!(!gw.seq.window_has_pending_manifest());
        let out = gw
            .begin_window_settle(gw.seq.state.next_batch_id)
            .expect("no desync");
        assert!(out.is_none(), "no state change and no manifest content ⇒ nothing to prove");
    }
```

`tests_support::gw_with_market()` and `resting_order(nonce)` must be written. `resting_order` is a `Gtc` limit far from any crossing price (e.g. a buy at half the oracle mark) so it rests rather than fills — the first precondition assert is what proves it.

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p gateway --lib manifest_only_window`
Expected: FAIL — `window_has_pending_manifest` does not exist, and once added, `begin_window_settle` returns `None`. **The second failure is the one that matters; confirm you see it, not just the compile error.**

- [ ] **Step 3: Implement**

Add to `impl Sequencer`, near the window fields:

```rust
    /// SEC-025-B break 4: does the open window carry manifest content that must be
    /// settled even though the engine root has not moved? An accepted order that rests
    /// without crossing lands in `window_ordered` while changing no engine state (the
    /// book is matcher state, not `State`), and a settle is what publishes the ordered/
    /// rejected roots an inclusion challenge is answered from.
    pub fn window_has_pending_manifest(&self) -> bool {
        !self.window_ordered.is_empty() || !self.window_rejected.is_empty()
    }
```

Change `begin_window_settle`'s guard (`main.rs:2183-2185`):

```rust
        // SEC-025-B break 4: a window can carry consensus-relevant manifest content with
        // an UNCHANGED engine root — a resting unfilled order is in `ordered` but moves no
        // state. Settling is what populates the challenge-answer store, and both on-chain
        // answer paths require a settled batch, so a root-only predicate leaves an honest
        // sequencer unable to answer a ripe challenge. Still returns None when the window
        // is empty in both senses, so idle ticks burn no proofs.
        if self.seq.state.state_root() == self.last_settled_root
            && !self.seq.window_has_pending_manifest()
        {
            return Ok(None);
        }
```

- [ ] **Step 4: Run to verify they pass**

Run: `cargo test -p gateway --lib window`
Expected: PASS.

- [ ] **Step 5: Verify the manifest-only settle is actually accepted downstream**

A manifest-only window has `new_root == prev_root`. Confirm by reading `contracts/src/DarkPerpSettlement.sol:326` that the only root check is `prevRoot != currentStateRoot`, so an unchanged new root is accepted. **State in your report what you found** — if the contract does reject it, this task needs a different design and you should stop and report rather than work around it.

- [ ] **Step 6: Run the whole suite**

Run: `cargo test --workspace`
Expected: PASS. Watch for tests that assumed settles only follow state changes.

- [ ] **Step 7: Format, lint, commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets
git add crates/sequencer/src/lib.rs crates/gateway/src/main.rs
git commit -m "fix(gateway): SEC-025-B — settle windows carrying manifest content

begin_window_settle decided 'nothing to prove' purely from state-root movement, but
a resting unfilled order puts its hash in the window manifest without changing engine
state. Such a window never settled, so its hashes never reached the challenge-answer
store, and both contract answer paths require a settled batch — leaving an honest
sequencer unable to answer a ripe inclusion challenge and slashable for it.

Reachable by any user resting an order into a quiet window. Pre-existing; found by
adversarial review of the 025-B design, not by the decomposition's inventory."
```

---

### Task 7: Enforce guest/native parity in the prover-service

**Files:**
- Modify: `crates/prover-service/src/sp1_prover.rs:58-74` (`prove`)

**The gap:** `/prove` returns roots and a commitment derived **natively** (`crates/prover/src/lib.rs:471` → `crates/prover-service/src/main.rs:163`), and the only comparison against the value the **guest** actually committed is a `debug_assert_eq!` — which compiles out of the release builds the prover box uses. A native/guest divergence therefore yields a response whose commitment matches the gateway's local replay (Task 3), while the proof attests a *different* guest commitment: the gateway accepts, and L1 rejects. Soundness survives; liveness fails late, after gas, inside the rollback machinery.

- [ ] **Step 1: Promote the assertion**

Replace the `debug_assert_eq!` at `sp1_prover.rs:63-68` with an unconditional check:

```rust
        // SEC-025-B §2: the guest's committed public value MUST equal the natively derived
        // commitment. This was a debug_assert, which compiles out of the release builds the
        // prover box runs — so a native/guest divergence would return a proof the gateway
        // happily accepts (its local replay matches the NATIVE roots) and L1 then rejects,
        // late and inside the rollback machinery. Fail here instead, naming both values.
        let expected = public.commitment::<Keccak256>();
        if proof.public_values.as_slice() != expected.as_slice() {
            panic!(
                "guest/native divergence: guest committed {} but native derivation gives {} \
                 — the guest ELF and the host perp-core are not the same code",
                hex::encode(proof.public_values.as_slice()),
                hex::encode(expected),
            );
        }
```

If the surrounding function can return an error rather than panicking, prefer that and propagate it as a `/prove` 500 — read the call site in `crates/prover-service/src/main.rs` and follow whichever it uses. **Say which you chose and why in your report.**

- [ ] **Step 2: Verify it compiles**

Run: `cargo check --manifest-path crates/prover-service/Cargo.toml`
Expected: PASS.

- [ ] **Step 3: Note the untested path honestly**

This check cannot be exercised without an SP1 prover, so there is **no automated test for it in this repo**. Do not write a test that mocks the divergence and claims to cover it — that would be an eighth defective fixture. Instead, record in your report that this path is verified only by inspection, and that the runbook step in Task 8 is its operational counterpart.

- [ ] **Step 4: Format, commit**

```bash
cargo fmt --all
git add crates/prover-service/src/sp1_prover.rs
git commit -m "fix(prover-service): SEC-025-B §2 — enforce guest/native parity in release

/prove returns natively derived roots; the only check against the value the guest
actually committed was a debug_assert, compiled out of the release builds the prover
box uses. A divergence would yield a proof the gateway accepts — its local replay
matches the same native roots — and L1 then rejects, late and inside the rollback
machinery. Fail at the prover instead, naming both values."
```

---

### Task 8: Correct the wind-down runbook

**Files:**
- Modify: `docs/FINAL_SETTLE_RUNBOOK.md:52-80`

- [ ] **Step 1: Read the current text and the contract**

Read `docs/FINAL_SETTLE_RUNBOOK.md:52-80` and `contracts/src/DarkPerpSettlement.sol:365-404` (`finalSettle`) plus `:311-321` (`settleBatch`). The runbook documents six roots and the old selector.

- [ ] **Step 2: Correct it**

Update the documented call to the nine-parameter form, including `depositsRoot` and `newDepositCount`, and note that `newDepositCount` is the **cumulative** post-state `consumed_deposit_count`, not a per-window count.

Add a short subsection recording the operational counterpart of Task 7:

```markdown
### Before a cutover: verify guest/native parity

`prover-service` now fails `/prove` if the guest's committed public value differs from
the natively derived commitment (SEC-025-B §2). That check is the continuous defence,
but it only fires once a proof has been produced. Before a cutover, confirm the guest
ELF and the host `perp-core` are the same code by building both from the same commit
and running the `sp1-host` comparison binary — a mismatch here presents as "the prover
disagrees" during settlement, not as a build error.
```

- [ ] **Step 3: Commit**

```bash
git add docs/FINAL_SETTLE_RUNBOOK.md
git commit -m "docs(runbook): SEC-025-B — nine-parameter settleBatch, and a parity pre-check

The wind-down runbook documented six roots and the old selector. It is EXIT-001's
escape hatch, read under duress, so being wrong there is expensive."
```

---

## Branch completion

- [ ] `cargo test --workspace` green; `cargo fmt --all -- --check` clean; `cargo clippy --workspace --all-targets` clean.
- [ ] `cargo check` passes on **both** excluded crates, and failed at the branch point (Task 1, Step 5).
- [ ] Request an independent review of the branch. **Codex found defects in all seven claims it examined in this piece's design; expect it to find more in the implementation.** Verify every finding at source before accepting it.
- [ ] Confirm in the final report which tests were verified to **fail at the parent commit**: Task 1 Step 5, Task 2's no-`deposits_root` parse, Task 6's manifest-only settle. These are the rows that prove the branch does something.
- [ ] **Do not deploy.** This branch joins the cutover bundle (SEC-022 + SEC-024 + SEC-026 + 025-A/B/C/D). It does not itself move the vkey or `GENESIS_ROOT`, but the bundle does, and 025-A/C/D are not written.

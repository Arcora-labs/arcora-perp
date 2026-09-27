# Source-backed protocol coverage

The base is 098e4952; exact current file hashes and command outcomes are in `../checks/*.json`. Counts from overlapping commands must not be added. This review is local engineering evidence, not an external security audit.

## S4-01 accounting

`State::internal_value` counts unspent notes + position collateral + insurance + vault pool + treasury. This equals external deposits minus external withdrawals. A burned withdrawal becomes an external-out claim, so do not add that claim back into engine value. Vault token balance separately includes outstanding claims; reconcile claimed leaves and uncredited deposits rather than comparing it directly to engine collateral.

`lifecycle`, `sec022_fill_band`, `serde_witness`, `a06_wind_down`, and core property suites cover fees/rebates, positive/negative positions, funding, rounding, rejected state equality, overflow, insurance exhaustion, ADL attribution, duplicated historical note commitments, and final close. The added `local_s4` tests show exhausted batch identity rejects before minting; the old implementation panicked after applying a deposit. The last representable transition still succeeds. Core debug and release runs each selected 162 tests with serde enabled, all passed; release explicitly enabled both assertions and overflow checks. This change affects the guest program and requires a new ELF/vkey binding, even though ordinary vectors do not change.

`apply_batch` is documented to stop at the first invalid operation; callers requiring whole-batch rollback use pre-state clones/window rollback. This review does not turn that documented behavior into a new transactional API.

## S4-02 matching

`Book::submit`/`crossable_liquidity` and sequencer settlement replay preserve price/time and order identity. Existing named tests and deterministic property streams cover GTC/IOC/FOK/PostOnly, self-trade, expiry, positive quantities, no overfill, uncrossed books, repeated seeds, FOK depth including self-trade avoidance, reduce-only, risk rejection and rematching. The matcher fuzzer runs 300 deterministic seeds with 60 orders; this is a bounded corpus, not exhaustive proof. Sequencer tests attribute rejection to the offending leg and retain healthy fragmented liquidity.

Gateway execution metadata is checked separately in the final workspace run (A04 cancel, A05 partial fills/history). SETTLED finality is not full execution; current frontend keeps filled/remaining distinct. No ZK fairness claim follows from native determinism.

## S4-04 contracts

96 Foundry tests passed, no skipped tests, seed `0x27`; 11 suites include 256-run fuzz tests and two invariant campaigns of 128000 calls each. New negative controls reject an otherwise valid gateway deposit signature on another vault/chain and preserve token balances/counts; returning to the original domain succeeds. Non-sequencer configuration/bond/settlement calls leave root, batch and bond untouched.

| Authority/binding | Enforcement | Evidence |
|---|---|---|
| Gateway deposit signer | chain, vault, payer, blinded owner, amount; low-s; used digest | CollateralVault tests including new cross-domain control |
| Settlement publisher | onlySettlement and nonzero historical published roots | withdrawal proof/old root/double claim tests |
| Sequencer | setVault once, post/withdraw bond, ordinary settle | new role test plus bond-floor/prefix tests |
| Governance | delayed finalSettle; phase1 once, phase2 repeatable | A06 and non-governance tests |
| Enclave signer | canonical receipt signature and membership | CrossLayer and inclusion/slashing tests |
| Verifier | immutable program key and commitment/proof adapter | SP1ZkVerifier tests use MockSP1Verifier; not a real proof |

Supported collateral is the configured conventional 6-decimal ERC20/USDC contract. Fee-on-transfer/rebasing/adversarial token equivalence is not claimed. Effects precede claim transfer and authorization mark precedes transferFrom; no blanket reentrancy claim for arbitrary tokens. Live deployment code/roles are not inferred from these tests.

## S4-05 witness/prover boundary

Guest decodes `(pre_state, operations, manifest)` and invokes shared `derive_roots`; it commits the full commitment, not caller-provided roots. Native tests cover roots, sealed-witness tampering, mismatched measurements and transition rejection. The service compares returned public bytes with native commitment using an unconditional check. HTTP session expiry/measurement and dev-insecure production guards are distinct gateway/service paths. Excluded host/service compilation and real guest execution are recorded independently; the green main CI excluded job used a stub ELF.

The three SP1 manifests now pin direct versions to 6.0.0 and retain their separate lockfiles. The final lockfiles also resolve every registry sp1-* and slop-* package to 6.0.0; compatible non-SP1 transitive versions are frozen separately. The first unpinned guest build resolved 6.8.1, so its ELF is historical setup evidence only. Any compilation/parity failure remains a gate.

## S4-06 external trust

Oracle fixtures exercise signatures, wrong digest/market, freshness/confidence/deviation, total validation and HTTP decoding. They establish authentic messages from the configured signer, not independent market price truth. Gateway owns that signing capability.

TDX/Azure tests consume frozen quote/collateral/PCR fixtures at pinned times, include bad measurement/challenge/signature/expiry controls, and test app measurement binding. NVIDIA `detect` currently returns CC disabled; even the test-only enabled branch returns a backend error. No live TEE attestation was obtained. Sealed-box and archive suites test encryption, wrong view keys, tamper detection and note recovery; committee/bridge modules are scaffold coverage, not a deployed distributed trust boundary.

## S4-08 CI and dependency integrity

Main CI run 36337867266 was fetched live and all four jobs passed at the exact base. Historical audit reports remain unchanged. A11 omitted general crate changes; its path filter now includes `crates/**` and local verification scripts. A01 now includes workspace Cargo.toml. Main workspace CI uses `--locked`.

A11 previously set TEST profile variables while invoking `--release`. An independent two-assertion Rust crate failed under those original settings and passed under RELEASE variables. `check_release_profile.py` now exercises the workflow's actual settings in CI. GitHub's normal bash runner enables pipefail for tee pipelines; no invented exit-loss finding is asserted.

Rust audit initially found rustls and RSA advisories. A targeted lock update moved rustls to 0.23.45 and webpki to 0.103.15; repeat audit removes that advisory. RSA Marvin remains unpatched upstream. Local `vtpm.rs` uses public-key signature verification, not private RSA decrypt/sign; that narrows this path's exposure but is not grounds to suppress the dependency advisory. Atomic-polyfill unmaintained and spin yanked warnings remain. Frontend production/dev audit outcomes are in the frontend evidence. Branch protection/action immutable-pin policy is a recommendation only; no repository settings were changed.

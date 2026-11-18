# Security audit remediation: verified findings

PRODUCTION RELEASE HOLD. This code has not settled anything on L1. The SP1 guest program key
changed: the guest was rebuilt, re-pinned and re-proven, but no deployed stack uses the new key
yet (see Operational consequences).

Date: 2026-11-17. Base: `bb16693` (the commit audited on 2026-11-16). Head: `ba27fe9`.
Finding texts and per-item review history are kept outside the repository (the audit
worktree notes); the commit range is `git log bb16693..HEAD`.

## Scope

In scope: the findings the audit marked "independently verified" (re-run and not refuted):
PC-1, PC-2, GF-1, SM-4, GF-2, GA-1, SM-1, SM-2, SM-3, GA-2, G1-1, G2-1, G2-2, OR-1, SV-1, and
the verified Low/Info hygiene items IN-10, IN-11, IN-13 (partly, see Hygiene).

Not addressed: the findings the audit supported only with a PoC or a code read (GA-3, GA-4, GA-5,
FE-2, IN-1) and the remaining Low/Info items. They were left unchanged and not made worse on purpose.
The audit's trust model (gateway holds custody and oracle keys; the development prover sees the
plaintext witness) was accepted and not changed.

The fixes were made in three parallel branches (lane-a gateway/persistence, lane-b engine/sequencer,
lane-c admission/oracle/SP1 binding), merged into this branch, then fixed up once more for the G1-1 review.

## Findings

Test names are prefixed `audit_1116_` plus the finding id in lower case (`gf1`, `gf2`, `ga1`, `sm1`,
`sm2`, `sm3`, `ga2`, `g11`, `g2`, `or1`, `sv1`, `pc1`, `pc2`). "Closed" means the lane review
and, where one ran, the final review closed with no open must-fix.

| Finding | What changed | Regression tests | Review |
|---|---|---|---|
| GF-1 + SM-4 | Order log and per-batch hash lists moved out of the snapshot into side logs beside it (`<state>.orderlog`, `<state>.batches`); settled orders' finality and inclusion records pruned; finished order rows share a fixed history budget (50,000 rows, at most 500 per account); orders refused with `503 PERSISTENCE_UNAVAILABLE` after a failed snapshot write; `snapshot_size_high` alert at 75% of the cap; per-client order rate limit; boot checks the whole order log against the snapshot digest | `audit_1116_gf1_*`, `audit_1116_sm4_*` (gateway) | Closed |
| GF-2 | `POST /v1/orders` returns the signed receipt and `l1Challenge` only after a snapshot holding the order is durable; the challenge watcher declares an open challenge for a hash no batch holds as rejected in the open window (new `DPCHRJ1` section) | `audit_1116_gf2_*` | Closed |
| G2-1 + G2-2 | Deposit reads and every other L1 work run without the clock admission permit (permit taken only to apply and persist); next deposit block read with the vault's `depositBlock`; the open window's age is bounded, so timed work stops near the cutoff and new `CLOCK_WINDOW_CLOSING` answers (`503`, `Retry-After`) are sent on every mutating route; a mined registration revert is surfaced and a stale `BadContext` estimate is re-sent; new `deposit_reads_dropped` alert | `audit_1116_g2_*` | Closed |
| PC-1 + PC-2 | `perp-core`: a liquidation closes the other side pro rata at the liquidation price; funding paid out is capped by what the paying side owes; withdrawals are capped at lifetime deposits; initial margin stays in collateral and is not released by unrealised PnL; a liquidatable counterparty pays the 1% penalty. Sequencer cancels the resting orders of every reduced account (reason `ForcedClose`), emits `forcedClose` receipts and WS events. Boot refuses a snapshot whose open window does not replay under the new rules | `audit_1116_pc1_*`, `audit_1116_pc2_*` (perp-core, sequencer, fuzz) | Closed |
| GA-1 + SM-1 (admission) + SM-3 | Open-order caps (64 per account per market, 128 per account); pending orders reserve collateral, and withdrawals and unbinds refuse to release it (`PENDING_MARGIN`); the funding mark no longer counts quotes that cannot trade and cannot be pinned by dust | `audit_1116_ga1_*`, `audit_1116_sm1_*`, `audit_1116_sm3_*` | Closed |
| GA-1 tick + SM-2 | Matcher indexes resting orders by hash and a stream is undoable; sequencer bans an under-collateralised maker's side and caps matching passes at 8, with the last pass settling each fill as it matches; gateway tick updates only the order rows its batch touched | `audit_1116_ga1_*`, `audit_1116_sm2_*` (`tick_scaling_tests`, `order_flood`) | Closed (final review) |
| GA-2 | Withdrawals rate-limited (3 per minute, 10 per open window), minimum raised to 10 USDC, lifetime per-account history quota of 50 operations, exchange-wide reserve for partial withdrawals read from the state only | `audit_1116_ga2_*` | Closed |
| G1-1 | Registration no longer depends on position count; entries below 100 USDC cannot open, grow or flip a position (`BELOW_ENTRY_BALANCE`); dust entries are swept by a notified forced exit and not charged to the history ledger; opening permits share the soft cap and are limited per client group (`OPENING_PERMIT_LIMIT`); a full exit waits for a pending top-up permit (`TOP_UP_PERMIT_OUTSTANDING`); frontend mirrors the minimum | `audit_1116_g11_*` | Final review: partial, 1 must-fix. A fix-up round applied it and a confirm review closed with nothing open. Declined items remain as residuals below |
| OR-1 | A withdrawal from an entry with an open position uses the stored oracle transcript and is refused as `oracle unavailable` when it does not validate; same rule for `pool_transfer` and the demo withdraw; free balance priced from the same transcript | `audit_1116_or1_*` | Closed |
| SV-1 | The SP1 adapter is bound directly to the stateless v6.1.0 verifier; the gateway boot gate pins every hop of the clock route and refuses a router that is not the pinned stateless verifier unless `L1_ACCEPT_SP1_ROUTER_OWNER_TRUST=1` is set; candidate observer and deploy tooling refuse gateway-routed graphs | `audit_1116_sv1_*` (Python local-verification suites, Foundry) | Closed |
| Cross-lane merge | Merge fixes: dust sweeps held to the open-window timed-op gate, fixtures scaled to the entry minimum, optional snapshot section order pinned | `audit_1116_merge_*` | Closed |

### Hygiene (verified Low/Info)

IN-10 (`.gitignore` now covers private keys, keystores, gateway state files), IN-11 (the remaining
crates inherit the workspace lints) and IN-13 (developer home-directory paths removed from docs
and evidence) were handled in separate commits. IN-13 is incomplete: the two
`scripts/local-verification` scripts and the six `guest.elf` binaries still contain the username, paths
were anonymised to `/Users/<dev>` and not made repo-relative, evidence manifests that hash rewritten
files may no longer match (not checked), and `LICENSE` (MIT) still disagrees with the manifest
license (MIT OR Apache-2.0). The commit `3d0470e` has no blank line before its trailers and was not amended.

## Operational consequences

- **The SP1 guest program key changed.** `crates/perp-core` changed (`engine.rs`, `error.rs`,
  `funding.rs`, `hash.rs` with the new `Domain::ForcedClose = 33` appended last, `merkle.rs`,
  `position.rs`, `state.rs`, and with the k256 0.14 upgrade below `Cargo.toml` and `oracle.rs`, plus
  the guest lock). On 2026-11-18 the guest was rebuilt with the cold reviewed recipe (byte-exact
  twice: ELF `151afdba…`, 544,920 bytes; setup key `0x00a64436…`), `REVIEWED_GUEST` and
  `REVIEWED_FIXTURE` were re-pinned, and the reviewed fixture was regenerated with
  `clock-proof --no-prove` (the normal fixture's witness and commitment are unchanged; three case
  witnesses and one negative changed with the liquidation rule). The normal fixture was then proven
  for real on one GPU and `PROOF_FIXTURE` now names that proof, so `proof_status()` reads `PROVEN`;
  27 real-verifier Solidity checks pass on it. The prover service's program table and the `sp1-host`
  binaries name the new ELF. Records: `docs/audits/2026-11-18-guest-reproof/`. An intermediate
  rebuild of the same day (ELF `3c0bbb2a…`, before the k256 upgrade) was superseded on this branch
  and never merged. Before this code can settle on L1 the stack still has to be redeployed with the
  new verifier key (see SV-1 below).
- **Dependency advisories (RustSec, 2026-11-18).** New advisories failed the dependency audit.
  Lock updates within semver: tokio 1.54.1 (RUSTSEC-2026-0386, unsound), quinn-proto 0.11.19,
  quinn-udp 0.5.16, rustix 1.1.6 (RUSTSEC-2026-0523/0524/0538/0486) and hickory-* 0.26.3
  (RUSTSEC-2026-0487..0558, TEE capture). RUSTSEC-2026-0387 (crypto-bigint < 0.7.6: operations meant
  to be constant-time could branch on secret data) reached the gateway's ECDSA signing with its
  custody and oracle keys through k256 0.13, so every crate moved to k256 0.14 (ecdsa 0.17,
  crypto-bigint 0.7.11). ecdsa 0.17's `recover_from_prehash` no longer re-verifies the signature,
  which in 0.16 refused a malleated high-`s` twin; the four production recovery sites
  (`perp-core` oracle signatures in the guest, `committee`, the sequencer's receipts, the gateway's
  `recover_eth_address`) now verify against the recovered key themselves, and regression tests hold
  the twin refused. The frozen `chainlink-oracle` lane keeps its own k256 0.13 lock, unaudited as
  before. SP1 6.1.0 itself still carries crypto-bigint 0.5.5 (`sp1-lib`, `sp1-curves`), so the four
  SP1 locks skip that one advisory, only while `check_sp1_owned_advisories.py` proves no repository
  crate reaches it outside the reviewed SP1 release; it fails once SP1 drops it. The application and
  TEE capture locks are audited with no exception.
- **`crates/perp-core/src/merkle.rs` changed too.** The stable toolchain on CI (1.100) flags
  `clippy::needless_range_loop` in `root` and `prove`. Both functions now carry an `allow` for it and
  their code is unchanged, but the file is pinned guest source. This went in before the guest rebuild
  on purpose, so the rebuilt guest and its pin include it.
- **Snapshot format.** The base snapshot (`DPSNAP10`) and rollback journal (`DPRBJL7`) magics are
  unchanged and everything `bb16693` wrote still loads. Additions: side logs beside the snapshot
  (migrated at boot when `DARKPERP_STATE` is set) and the optional trailing sections `DPHIST1`,
  `DPCHRJ1`, `DPWLIM01` and `DPSWEEP1` (in that order). A snapshot that uses side logs or declarations is refused by the old
  binary, so there is no downgrade. Back up and restore the side logs with the snapshot, and move
  leftover side logs aside before a fresh genesis. Accounts with withdrawals from before the upgrade start the lifetime
  quota at zero.
- **Upgrade hazard for an unsettled window.** Boot replays the open window under the new rules and
  refuses to start if it does not reproduce its root (see the upgrade section of
  `FINAL_SETTLE_RUNBOOK.md`). A sealed but unsettled rollback-journal window cannot be checked at
  boot: resolve it with the old build before upgrading.
- **New API limits and error codes** (details in `docs/API.md`): `PERSISTENCE_UNAVAILABLE` (503),
  `CLOCK_WINDOW_CLOSING` (503 with `Retry-After`), `OPEN_ORDER_LIMIT`, `PENDING_MARGIN`,
  `BELOW_ENTRY_BALANCE`, `TOP_UP_PERMIT_OUTSTANDING`, `OPENING_PERMIT_LIMIT` (429),
  `WITHDRAW_RATE_LIMIT_MINUTE`, `WITHDRAW_RATE_LIMIT_WINDOW`, `WITHDRAW_QUOTA_EXCEEDED`,
  `WITHDRAW_RESERVE_REACHED`, `ACCOUNT_HISTORY_QUOTA`, `oracle unavailable` on withdrawals with a position.
  Order intake is limited to 20 orders/s per client with a burst of 40; the minimum withdrawal is
  10 USDC; entering a position needs 100 USDC of entry balance. Order receipts now wait for a durable snapshot.
  New alerts: `snapshot_size_high`, `withdraw_reserve_near`, `deposit_reads_dropped`.
- **SV-1 needs a redeploy.** The registered Base Sepolia stack still routes through Succinct's shared
  gateway. It must be redeployed with the adapter bound directly to the stateless verifier. The cost
  of direct binding is that a new SP1 verifier version means redeploying the adapter, clock verifier,
  settlement and vault. Boot refuses the old graph unless the owner-trust opt-in is set.

## Not verified

- The guest rebuild, vkey, fixture and proof (2026-11-18) cover the normal fixture only: no case,
  cap or lifecycle witness was proven (all are executed on CPU in CI), the proving GPU was not in
  confidential-computing mode, and no target settlement accepted the proof on a chain.
- No real L1, TEE or live-RPC run. The challenge-watcher loop in `main()` and the real feed poller and
  HTTP route for OR-1 were not exercised end to end; tests call the helpers directly.
- The full suite was run once on the merged branch (2026-11-18, as root, no SP1 toolchain):
  `cargo fmt --all --check` and `cargo clippy --workspace --all-targets --locked -- -D warnings` clean;
  `cargo test --workspace --locked --no-fail-fast` 1777 passed, 1 failed, 135 ignored; `forge test`
  433 passed; `scripts/ops` 111 passed, 2 skipped; `scripts/claim` and `scripts/challenge` passed;
  frontend `pnpm test` 719 passed, 1 skipped; `scripts/local-verification` 16 suites passed and the
  five guest-pinned suites named above failed. The one Rust failure is
  `clock_recovery::tests::a_failed_void_snapshot_or_journal_delete_waits_and_completes_on_the_next_step`:
  chmod-based denial does not work as root, and it fails the same way on `bb16693`. The release-profile
  run (`cargo test --workspace --locked --release`), `cargo audit` and `pnpm build` were not run.
- The interaction of the SM-1 reserve with the entry minimum was not reviewed end to end.
- Proving cost of the liquidation change was reduced by construction and not measured in cycles.

## Residual risks

- **G1-1.** About 133 IPv4 addresses or IPv6 /64 groups can still hold the opening-permit room with
  unfunded permits. Entries can sit around 30 to 65 USDC under the 100 USDC floor, so the soft cap costs
  roughly $30k to $70k, not $106,300. Funding charged across passes while an opener rests is covered
  only up to a shared 2 USDC allowance, and that allowance loosens the entry floor slightly. Client
  groups are runtime-only and are lost on restart. A global rate limit for permits near the cap and
  persisted groups were not done: treating post-restart permits as one group would lock every
  client out.
- **GA-2.** About 80 Sybil accounts can push the state past the 7,968-unit reserve; partial
  withdrawals then stay closed for every account for the life of the deployment (the alert warns first).
  The 50-operation lifetime quota permanently limits active traders; a new account is the way back.
- **GF-1.** The side logs grow on disk without limit and boot reads the whole order log, so restart
  time grows with lifetime order volume. Fail-closed after a failed write is coarse (up to about 30 s of 503s).
- **GF-2.** Every accepted order waits for a snapshot write, and the permit is held while it waits.
- **G2.** A window whose seal stays skipped past `clockSkewMs` is still voided. Deposit reads slower than
  the time admission is open still never apply (visible through `deposit_reads_dropped`).
- **PC-1.** The upgrade check covers the snapshot's open window only. The `NetSizes` cache is correct
  only while `Liquidate` and `SettleAll` are the only ops that change a market's net size.
- **GA-1 / SM-2.** Each matching pass but the last settles on a full state copy (at most 8 per batch);
  fixing that needs a `perp-core` change. A tick still visits every order row, and the history prune
  relies on it: extending the touched-row skip to that loop would break pruning.
- **Durability asymmetry.** The dust sweep's `forcedExit` events wait for a durable snapshot, but
  `forcedClose` and fill events go out at tick time. Pre-existing, unchanged.
- **SV-1.** The four boot-gate runtime templates must be re-pinned whenever the verifier contracts or
  compiler settings change; the Python sync test catches drift only after `forge build`.
- **Not combined.** The `DPHIST1` section was not part of the combined round-trip test.

# Maintenance-window runbook — SEC-019/ZK-001 redeploy + SEC-020 Phase-2 CC enable

**Written:** 2026-07-23. **Owner:** operator. **Status:** pre-window prep not started.

One combined window, because both legs touch the same GX10 (NVIDIA GB10) box: the
Base-Sepolia contract redeploy needs an in-zkVM proof smoke on GX10, and SEC-020
Phase-2 needs a CC-enable reboot of GX10. The box also hosts **Quetzal DEX**
(aggregator/faucet behind the reverse tunnel to box 161) and the operator's
**llama-server** (port 8091 tunnel) — both go down during the reboot, so one
window beats two.

The two legs are **independent**: if CC-enable fails or its gate work isn't done,
the redeploy leg can still run (posture unchanged — the prover keeps working
un-attested exactly as today). Never block the redeploy on CC.

---

## Why this window exists (what's already done)

All four audit soundness findings are merged on `main` and the frontend leg is
merged (`999bdde`): the frontend already emits `deposit(uint256,bytes32,bytes)`
calldata and MUST NOT be published until the new vault is live. The currently
deployed stack (see `contracts/deployments/base-sepolia.json`) is pre-SEC-019:
`DarkPerpSettlement 0x0869…`, `CollateralVault 0x57e9…` (old arity),
`SP1ZkVerifier 0x8012F3b3` (programVKey pinned to the OLD guest), `MockUSDC
0x8a52…`, served at `https://perp.arcoralabs.xyz` (frontend + gateway on the
same Azure TDX CVM).

**Prod refusals are LIVE on the redeployed gateway.** `production_mode()` is
true whenever the L1 bridge is configured (`gateway/src/main.rs:5123`), and the
merged tree refuses prod boot on: the dev enclave seed, the dev oracle signer
key (`ORACLE_SIGNER_KEY` unset → Anvil #1 → exit 1), and an unset
`PROVER_SEAL_ROOT` without attestation (SEC-020 fail-closed provider selection).
Real keys are not optional in this window.

---

## Phase 0 — Pre-window prep (no downtime; days before)

**0a. SEC-020 Phase-2 hardening package — GATES THE CC LEG (new code).**
The Phase-2 gate list (SDD ledger + darkperp memory): C1 app-level
`azure_app_measurement` pinning, C2 per-handshake vTPM freshness, C3 DH-bound
session token, C4 re-handshake refreshes `session_secret`, C5 token TTL, plus
constant-time bearer compare and a real `measurement()` (currently `[0xAB]`
stub). These are inert today ONLY because prod mints no token; enabling CC makes
them live. **Do not enable CC before this package is merged.** Run it as its own
SDD spec→plan→implement cycle. If it isn't done by window day, run the window
with the CC leg dropped (Phase 1 skipped).

**0b. GB10 CC-enable procedure investigation.**
`nvidia-smi conf-compute` is absent on the GB10; the enable path is likely
BIOS/firmware + reboot but **unconfirmed** (2026-07-19 session). Before
scheduling: identify the exact toggle (CC vs PPCIE mode), confirm a rollback
path (disable + reboot restores today's behavior), and verify
`~/nvattest-venv` (`nv-attestation-sdk` + `nv-local-gpu-verifier`) still runs.
If no procedure can be confirmed, drop the CC leg from the window.

**0c. Mint + stage prod keys** (secure storage; these must survive restarts —
a changed `ORACLE_SIGNER_KEY` after genesis = fail-closed oracle outage, see
ZK-001 minors):
- `GATEWAY_SIGNER_KEY` (fresh secp256k1 scalar). Its ADDRESS goes to the vault
  ctor (`GATEWAY_SIGNER` env of `Deploy.s.sol`) — non-zero is enforced.
- `ORACLE_SIGNER_KEY` (fresh scalar). Its address becomes every
  `Market.oracle_pubkey` at genesis.
- Confirm `ENCLAVE_SEED` + `ENCLAVE_SIGNER` stay what the live CVM uses today
  (unchanged enclave, measurement `0x422890f6…faf55bd`).

**0d. Build the new guest + compute the clean prod genesis.**
- SP1 guest rebuild on merged `main` (per `docs/PROVING-RUNBOOK.md`) → record
  the NEW `programVKey`. The old verifier `0x8012F3b3` pins the OLD guest's
  vkey — a NEW `SP1ZkVerifier` must be deployed.
- Compute the CLEAN PROD GENESIS on the merged tree with the real keys from 0c:
  no sentinel deposit leaves (SEC-019 genesis gate — a shipped demo genesis
  bricks the deposit path), `oracle_pubkey` = real signer address (not
  Anvil/0x0), the two new Market fields in `markets_digest`. Record
  `GENESIS_ROOT`.
- Dry-run `contracts/script/Deploy.s.sol` against a local anvil fork with the
  full env set; `forge test` (84) + workspace `cargo test` green on the exact
  commit being shipped.

**0e. Stage the frontend build.** Everything is merged; only
`frontend/src/api/wallet.ts` consts (`COLLATERAL_VAULT`, `MOCK_USDC` if it
changes) + `contracts/deployments/base-sepolia.json` + the `TestnetNotice`
deploy-info line get filled mid-window. Pre-run `pnpm typecheck && pnpm vitest
run` (183) so the only window-day delta is the constants.

**0f. Co-tenant prep (GX10).**
- Quetzal: back up aggregator/faucet state; announce downtime; confirm the
  boot procedure that brought it up on 2026-07-18 is written down (reverse SSH
  tunnel to box 161; Caddy stays untouched).
- llama-server (8091 → azureuser@104.42.53.250): warn its user; it also frees
  ~30 GB during the proof smoke if left down until Phase 2 completes.
- Old dark-perp stack (optional but honest): wind down via
  `docs/FINAL_SETTLE_RUNBOOK.md` (close-only + `finalSettle`) so any old-stack
  balances become claimable instead of stranded. Testnet — operator's call.

---

## Phase 1 — GX10 CC-enable reboot (window start; skippable)

1. Gracefully stop Quetzal aggregator/faucet, llama-server, and the dark-perp
   prover-service on GX10.
2. Enable CC per the 0b procedure; reboot.
3. Verify: `nv-attestation-sdk` local verifier now reports
   `confidential compute = True` and a verifiable GPU quote.
4. Bring Quetzal back up; verify `aggregator.quetzaldex.xyz` /
   `faucet.quetzaldex.xyz` respond through the tunnel. Restart llama-server
   (or defer to after Phase 2 for RAM headroom).
5. **Failure path:** revert the toggle, reboot, confirm Quetzal + prover healthy
   — the window continues with Phase 2 regardless.
6. Only with 0a merged AND step 3 green: flip the prover-service to the
   `NvidiaCcAttestor` path and run the SEC-020 smoke (handshake REFUSED ⇒
   `/attest` 503; `/prove` without token ⇒ 401; with session ⇒ 200).

## Phase 2 — Base-Sepolia redeploy (dark-perp trading paused)

1. Pause the gateway settle loop (breaker/`FIN_ADMIN_KEY` path or stop the
   service); snapshot + archive the CVM's `state.snap` and rollback journal,
   then wipe both (clean genesis boot).
2. Deploy with `Deploy.s.sol` (env from 0c/0d): new `SP1ZkVerifier` (NEW
   programVKey), `DarkPerpSettlement` (`GENESIS_ROOT`, governance, bonds),
   `CollateralVault` (`GATEWAY_SIGNER` = real address). `MockUSDC`: reuse
   `0x8a52…` (keeps user balances + the frontend const) unless the script
   forces a fresh one — decide at dry-run (0d).
3. Repoint the gateway env (addresses, `ORACLE_SIGNER_KEY`,
   `GATEWAY_SIGNER_KEY`, `PROVER_URL`, seal-root config) and boot. The boot
   itself is a test: prod-mode refusals must NOT fire with real keys (if one
   fires, the env is wrong — that's the guard working).
4. **In-zkVM proof smoke on GX10:** drive one real batch through seal → POST
   `/prove` → Groth16 → `settleBatch` on-chain with the new VK. A clean-state
   proof is ~10–14 GB RSS. This also proves the guest now enforces
   `deposits_root` + the oracle signature gate end-to-end.
5. Health: status snapshot shows `settlement_health: HEALTHY`; the
   settle-stall alert (`openWindowId > batchCount`) stays quiet.

## Phase 3 — Frontend release

1. Fill the constants (0e list), update `deployments/base-sepolia.json`
   (addresses, `deployedAt`, deploy block, new `programVKey`), commit + push.
2. `pnpm typecheck && pnpm vitest run` (183) → build → publish to the CVM
   (`perp.arcoralabs.xyz`).
3. E2E smoke with a real wallet: the full 7-step pipeline (chain → mint →
   approve → bind → authorize → deposit → credit) against the NEW vault; then a
   withdraw → claim round-trip; HealthPanel shows the FIN-001 row HEALTHY and
   the attestation card.

## Phase 4 — Post-window

- Watch ntfy alerts + Quetzal health for 24h; confirm GX10 stayed up.
- Update `.superpowers/sdd/progress.md` + operator notes: what shipped, new
  addresses, whether the CC leg ran.
- Rollback note: the OLD stack addresses remain on-chain and archived in the
  deployments file; the old frontend build is the last pre-`999bdde` `main`
  build. Rolling back = repoint gateway env + republish old frontend.

---

## Decision points (settle before scheduling)

| # | Decision | Recommendation |
|---|---|---|
| 1 | CC leg in or out of this window | In ONLY if 0a (Phase-2 hardening) is merged and 0b confirmed a procedure; else redeploy-only window |
| 2 | Wind down the old stack via finalSettle | Yes (honest exit; cheap on testnet) |
| 3 | Reuse `MockUSDC 0x8a52` | Yes, if `Deploy.s.sol` accepts an existing token address at dry-run |
| 4 | llama-server during window | Down until Phase 2 smoke passes (RAM headroom), then restore |

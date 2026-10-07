# Maintenance-window runbook — SEC-019/ZK-001 redeploy + SEC-020 Phase-2 CC enable

**Written:** 2026-07-23. **Owner:** operator. **Status:** pre-window prep not started.

**UPDATE 2026-07-24 — the CC leg no longer touches GX10.** GB10 cannot do
Confidential Computing (NVIDIA-confirmed, §0b), so SEC-020's attested prover
moves to a **CC-capable H100 host** (Phala / Azure NCC H100 v5), NOT a GX10
reboot. The two legs are now cleanly decoupled:
- **CC-prover leg** — provision a CC-H100, deploy the prover there, wire real
  NVIDIA GPU attestation. The current prover workstation stays up.
  No reboot of that host for this leg. Plan: `docs/PROVER-CC-H100-MIGRATION.md`.
- **Redeploy leg** — Azure TDX gateway + Base-Sepolia contracts (new VK / clean
  genesis) + frontend. Its in-zkVM proof smoke runs on whichever prover is live
  (the new CC-H100 once migrated, else GX10 un-attested). Independent of CC.

Neither blocks the other; the redeploy can ship with the prover still un-attested
on GX10 exactly as today, and the CC-prover migration can happen on its own
schedule. Combine them into one window only if convenient.

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

**0a. SEC-020 Phase-2 hardening package — CODE DONE on
`feat/sec020-phase2-local`; four live items below still GATE THE CC LEG.**

DONE on the branch (local-soundness, TDD'd against the captured Azure fixture):
- **C1** — `AzureTdxAttestor::verify` anchors on the APP-level
  `azure_app_measurement` (MRTD‖pcr_digest), not the firmware-only
  `enclave_measurement`; regression-tested that the firmware fold ≠ app fold
  and is rejected.
- **C2** — full vTPM chain verified + AK-extraData freshness gate
  (`nonce == challenge`); `/attest` carries the full evidence bundle (quote +
  hcl_report + ak_quote_msg + ak_quote_sig + pcrs).
- **C3** — DH-bound session secret: ephemeral x25519 per boot,
  `session_secret` folds the ECDH shared point → not derivable from the public
  transcript; proven by the public-transcript-cannot-derive test and the
  mock-Attestor orchestration test (both sides derive the identical
  secret+token).
- **C4** — the 401 re-handshake refreshes `session_secret` + `not_after` (not
  only the token) and REUSES the boot ephemeral keypair, so a rebooted prover
  and the gateway re-derive the identical secret (convergence proven in
  re-review).
- **C5** — `not_after` token TTL enforced on `/prove` (inclusive `<=`) +
  constant-time bearer compare (`ct_eq`).

DEFERRED to the window smoke — each still gates CC-enable and must be
exercised live (none droppable):
- (a) `tee-capture`/`capture.sh` must emit the full five-file bundle into
  `ATTESTATION_DIR` AND pass `tpm2_quote -q <eph_pub>` so the live
  AK-extraData binds the caller's fresh ephemeral pubkey. Today capture.sh
  passes no `-q`, so a live fresh capture has empty extraData → `verify()`
  correctly fails closed `NonceMismatch`. The fixture (extraData = 0xAB×32) is
  unaffected; this is a live-capture wiring task.
- (b) The prover's real NVIDIA CC `measurement()` value — still the `[0xAB]`
  stub; the `AttestedSealProvider` measurement-binding is vacuous until CC is
  enabled and a real GB10 CC measurement replaces it.
- (c) A live fresh Azure capture proving `eph_pub` lands in AK-`extraData`
  (the committed fixture is static, so this can only be confirmed on a live
  CVM).
- (d) CC-on end-to-end gateway↔prover DH handshake — locally the gateway
  handshake fail-closes at `NvidiaCcAttestor` (`CcNotEnabled`) and
  `AzureTdxAttestor::quote` reads the static fixture whose extraData can't
  bind a fresh `eph_pub`, so a real-binary end-to-end handshake cannot pass
  locally; it is a window smoke.

**Do not enable CC before the branch is merged AND (a)–(d) pass live in the
window.** If the branch isn't merged by window day, run the window with the CC
leg dropped (Phase 1 skipped).

**0b. GB10 CANNOT do Confidential Computing — the prover must move to a CC-capable H100 (DECISIVE, 2026-07-24).**
NVIDIA staff on the official developer forum, specifically about the GB10:
*"Confidential Compute is not supported on the DGX Spark … This is specific to
the GB10."* It is a **hardware/product limitation**, not a `nvidia-smi
conf-compute` toggle or a driver/OpenRM issue — the ARM+Blackwell GB10 has no CC
silicon. So the 2026-07-19 `confidential compute = False` was never a missing
toggle; GX10 can **never** report `True`. `nvidia_gpu_tools.py --set-cc-mode=on`
(the real enable path for H100 / datacenter Blackwell) is unsupported on GB10.
→ **There is no "enable CC on GX10" step. The prover-service migrates to a
CC-capable H100 host; the current prover workstation stays as-is for its other
workloads (no reboot for this service).** See the migration plan `docs/PROVER-CC-H100-MIGRATION.md`.
- Provider shortlist (all give real NVIDIA GPU CC attestation the `NvidiaCcAttestor` consumes, except where noted):
  - **Phala GPU TEE** — H100 in NVIDIA CC mode + Intel-TDX CPU (same TEE family as the Azure gateway) + separate NVIDIA-signed GPU quote. **~$2.38/hr reserved, $3.08 trial.** Best price + arch fit; confirm the tenant-facing attestation API (direct `nv-local-gpu-verifier` vs Phala's combined verifier) before committing.
  - **Azure NCC H100 v5** (`Standard_NCC40ads_H100_v5`) — H100 NVL 94GB + confidential-GPU driver + NVIDIA GPU attestation (cgpu onboarding `aka.ms/cgpu-onboarding-steps`), AMD SEV-SNP CPU. **~$5.60/hr**, GA East US2 / West Europe. Safest code-fit (reference model, zero prover code change).
  - **VoltageGPU** — ~$2.75/hr but Intel TDX + **TEE-IO** (GPU inside the CPU TDX trust domain, attested via the TDX quote) — a DIFFERENT model that likely needs prover attestation-path adaptation. Cheapest, least certain.
  - **AWS Nitro** — CPU-side only, no GPU attestation → **unusable** for the prover.
- Sanity-verify on the chosen host: `nvidia-smi conf-compute -f` (or the provider's attestation flow) reports CC ON, and `nv-attestation-sdk`/`nv-local-gpu-verifier` yields `confidential compute = True` + a GPU measurement (→ this becomes `PROVER_EXPECTED_MEASUREMENT`).

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

**0f. Shared-host prep.**
- If the prover workstation runs other workloads, back those up outside this
  repo and schedule their downtime separately. Do not record co-tenant names,
  reverse-SSH tunnels, SSH users, host addresses, or alert topics here.
- Proof smoke needs RAM headroom. Pause non-essential local workloads until
  Phase 2 completes, then restore them (~30 GB was the observed headroom gap).
- Old stack (optional but honest): wind down via
  `docs/FINAL_SETTLE_RUNBOOK.md` (close-only + `finalSettle`) so any old-stack
  balances become claimable instead of stranded. Testnet — operator's call.

---

## Phase 1 — CC-H100 prover provisioning (off-GX10; skippable, can run BEFORE the window)

Full detail: `docs/PROVER-CC-H100-MIGRATION.md`. Window-level steps:

1. Provision the chosen CC-H100 host (§0b: Phala reserved / Azure NCC H100 v5),
   complete the confidential-GPU driver + attestation onboarding. **The current
   prover workstation is not touched — its other workloads keep running.**
2. Verify on the host: `nv-attestation-sdk` / `nv-local-gpu-verifier` reports
   `confidential compute = True` + a verifiable GPU quote → record the real GPU
   measurement as `PROVER_EXPECTED_MEASUREMENT`.
3. Deploy the prover-service on the CC-H100 (SP1/gnark Groth16; ~10–14 GB proof
   RSS fits the 94 GB H100 easily). Set `PROVER_SEAL_ROOT`/attestation env; the
   `AttestedSealProvider` now builds from a REAL attested seal (no `DEV_INSECURE`).
4. Point the Azure TDX gateway's `PROVER_URL` at the new host; run the SEC-020
   smoke — the DH mutual-attestation handshake now COMPLETES (both sides attested)
   instead of fail-closing at `CcNotEnabled`: gateway↔prover `/attest` exchange →
   `/prove` without a valid session ⇒ 401, with the DH-bound session token ⇒ 200,
   and `deferred (b)/(c)/(d)` (real NVIDIA measurement + live `eph_pub` binding +
   CC-on e2e) are exercised for the first time.
5. **Failure path:** the prover stays un-attested on GX10 exactly as today; the
   redeploy leg proceeds regardless. No rollback needed — the CC-H100 is a new
   host, not a mutation of GX10.

> **Deferred item (a) — Azure-gateway-side, separate from the prover host:** the
> gateway's live fresh capture needs `capture.sh` to pass `tpm2_quote -q <eph_pub>`
> so the AK-extraData binds the caller's ephemeral pubkey (else `verify()` fails
> closed `NonceMismatch`). This runs on the Azure TDX CVM, independent of the
> CC-H100 provisioning.

## Phase 2 — Base-Sepolia redeploy (dark-perp trading paused)

1. Pause the gateway settle loop (breaker/`FIN_ADMIN_KEY` path or stop the
   service); snapshot + archive the CVM's `state.snap` and rollback journal,
   then wipe both (clean genesis boot).
   - **The wipe is REQUIRED, not precautionary — SEC-021 broke the snapshot
     format.** The merged tree adds mid-struct `Account` fields (postcard is
     positional), so a pre-upgrade snapshot does not load correctly under the
     new binary: it either fails with `DeserializeUnexpectedEnd` or — when
     `deposit_authorizations` is non-empty and its key bytes happen to align —
     decodes **silently into corrupt state**, dropping the authorizations. A
     decode that succeeds against a shorter pre-upgrade encoding must be read
     as corruption, never compatibility (pinned by
     `pre_upgrade_account_encoding_behaviour_is_pinned` in the gateway
     tests).
   - **Order matters (the 2026-07-09 cutover gotcha):** stop the process,
     **then** remove `state.snap`, then start. A plain restart lets the old
     process rewrite an old-format snapshot on shutdown, and the new binary
     then boots against exactly the bytes you meant to wipe.
2. Deploy with `Deploy.s.sol` (env from 0c/0d): new `SP1ZkVerifier` (NEW
   programVKey), `DarkPerpSettlement` (`GENESIS_ROOT`, governance, bonds),
   `CollateralVault` (`GATEWAY_SIGNER` = real address). `MockUSDC`: reuse
   `0x8a52…` (keeps user balances + the frontend const) unless the script
   forces a fresh one — decide at dry-run (0d).
3. Repoint the gateway env (addresses, `ORACLE_SIGNER_KEY`,
   `GATEWAY_SIGNER_KEY`, `PROVER_URL`, seal-root config) and boot. The boot
   itself is a test: prod-mode refusals must NOT fire with real keys (if one
   fires, the env is wrong — that's the guard working).
   - **Verify `L1_VAULT` is exported in the systemd unit BEFORE starting the
     cutover (step 1), not here.** The SEC-021 production boot gate
     (`vault_binding_ok_for_mode`) calls `exit(1)` when a prod-posture
     gateway boots with `L1_VAULT` unset or all-zero — and, post
     final-review, a set-but-malformed `L1_VAULT`/`L1_CHAIN_ID` also fails
     the boot instead of silently taking the dev fallback. This gate fires
     *after* the old process is stopped and `state.snap` wiped, so an
     unexported `L1_VAULT` discovered here turns the cutover into a hard
     outage instead of a pre-window check. It must be the NEW vault address
     from step 2.
4. **In-zkVM proof smoke on GX10:** drive one real batch through seal → POST
   `/prove` → Groth16 → `settleBatch` on-chain with the new VK. A clean-state
   proof is ~10–14 GB RSS. This also proves the guest now enforces
   `deposits_root` + the oracle signature gate end-to-end.
5. Health: status snapshot shows `settlement_health: HEALTHY`; the
   settle-stall alert (`openWindowId > batchCount`) stays quiet.

## Phase 3 — Frontend release

**The gateway and frontend must ship together (SEC-021).** The old frontend
against the new gateway gets a 400 on every withdrawal (no `nonce`/`signature`
in the request); the new frontend against the old gateway refuses client-side
("gateway too old" — `/v1/accounts/me` lacks the withdrawal-authorization
fields). Both directions fail closed, but withdrawals are down for any window
where the two are split — keep the split inside the maintenance window and
publish this phase immediately after Phase 2's boot check passes.

1. Fill the constants (0e list), update `deployments/base-sepolia.json`
   (addresses, `deployedAt`, deploy block, new `programVKey`), commit + push.
2. `pnpm typecheck && pnpm vitest run` (183) → build → publish to the CVM
   (`perp.arcoralabs.xyz`).
3. E2E smoke with a real wallet: the full 7-step pipeline (chain → mint →
   approve → bind → authorize → deposit → credit) against the NEW vault; then a
   withdraw → claim round-trip; HealthPanel shows the FIN-001 row HEALTHY and
   the attestation card.

## Phase 4 — Post-window

- Watch operator alerts for 24h; confirm the prover host stayed up. Do not
  commit alert topics or webhook URLs.
- Update `.superpowers/sdd/progress.md` + operator notes: what shipped, new
  addresses, whether the CC leg ran.
- Rollback note: the OLD stack addresses remain on-chain and archived in the
  deployments file; the old frontend build is the last pre-`999bdde` `main`
  build. Rolling back = repoint gateway env + republish old frontend.

---

## Decision points (settle before scheduling)

| # | Decision | Recommendation |
|---|---|---|
| 1 | CC leg in or out of this window | In ONLY if the 0a branch (`feat/sec020-phase2-local`, code done) is merged and 0b confirmed a procedure; the 0a deferred items (a)–(d) run IN the window and gate CC-enable; else redeploy-only window |
| 2 | Wind down the old stack via finalSettle | Yes (honest exit; cheap on testnet) |
| 3 | Reuse `MockUSDC 0x8a52` | Yes, if `Deploy.s.sol` accepts an existing token address at dry-run |
| 4 | Other workloads on the prover host | Pause until Phase 2 smoke passes (RAM headroom), then restore |

# Arcora Perp

**A privacy-preserving perpetual futures exchange.** Orders are matched privately inside attested hardware at centralized-exchange speed, then settled publicly under zero-knowledge validity proofs. In the current alpha, the gateway remains a trusted/custodial component: it holds server-custody spend keys and oracle-publisher authority.

*Technical Brief — Testnet Alpha — July 2026 — Arcora Labs*

---

> **Source/status update — 2026-10-09:** The selected product model is a custodial alpha. The gateway holds spending keys and price-publisher authority; the development prover can access plaintext witnesses. PR #31 has real clock-proof evidence for its pinned source, while the July deployment record is older. Live infrastructure and target capacity were not verified by that source proof. In clock mode, all new financial requests (including closes, cancellation, margin changes and withdrawal creation) pause through settlement/recovery. Historical live and timing descriptions below are not fresh deployment evidence.

## 1. Abstract

Arcora Perp is a perpetual futures exchange built as an application-specific rollup. The matching engine runs inside an Intel TDX confidential VM: order terms are encrypted in the trader's browser to an attested enclave key, matched in milliseconds on a price-time-priority book, and acknowledged with an enclave-signed receipt. Trading activity is sealed into windows; each window is re-executed inside the SP1 zkVM, and the resulting Groth16 proof is verified on-chain before the new state root is accepted. Collateral sits in an on-chain vault, and withdrawals from settled state are claimable by anyone via Merkle proofs, permanently.

Today this runs as a public testnet alpha on Base Sepolia at https://perp.arcoralabs.xyz, with real Groth16 proofs verified on-chain for settlement windows. The trust statement in one line: **the proof verifies that a settled transition satisfies the zk guest and its committed inputs; it does not independently prove user intent or external price truth. The alpha gateway still custodies account spend keys and controls the oracle publisher key.**

## 2. The problem

On a transparent perpetual futures DEX, everything is public before and after the trade: pending orders, resting liquidity, position sizes, margin levels, and — computably — every account's liquidation price. That transparency is usually framed as a feature. For the trader it is a persistent information leak that others monetize:

- **Front-running.** Orders visible before execution can be raced, on-chain or by anyone with a privileged view of the mempool or the operator's infrastructure.
- **Copy-trading and position hunting.** Profitable accounts can be identified, tracked, and systematically mirrored or faded. A strategy that is public is a strategy that decays.
- **Liquidation sniping.** When collateral and position size are public, liquidation prices are public. Concentrated liquidation levels invite the price to be pushed into them.
- **Exit telegraphing.** Unwinding a large position on a transparent book announces the unwind before it is complete.

The established alternative is a centralized exchange: the internal order book is private, so most of these leaks disappear. But the price is custodial trust — traders deposit into an opaque balance sheet, solvency is asserted rather than proven, and withdrawal is at the operator's discretion. The industry has repeatedly discovered what that discretion can cost.

The standing trade-off, then, has been *privacy with custodial trust* or *self-custody with full exposure*. Arcora Perp explores a path toward private matching with publicly verifiable settlement. The current alpha has **not** completed that path: collateral is held by on-chain contracts, but the gateway still holds server-custody spend keys, so a live gateway compromise remains a custody risk until key custody is moved behind the intended hardened boundary.

## 3. Design overview

Two technologies each solve half of the problem, and each fails alone.

A **trusted execution environment (TEE)** gives a private, fast order book: the engine runs on real hardware at real speed, and remote attestation proves *which code* is running. But a TEE alone asks users to accept hardware-vendor trust for *balance integrity* — too much to ask when the enclave also controls custody messages.

A **zero-knowledge validity proof** gives integrity without trusting anyone's hardware: a state transition is accepted only if a proof shows it was computed correctly. But proving is orders of magnitude slower than executing, and a naive zk exchange still has to publish its order flow somewhere to be sequenced.

Arcora Perp splits the roles so each technology carries only the load it is good for:

- The **TEE** is responsible for *confidentiality and speed*: private matching, millisecond acknowledgements, and an attested identity that signs receipts.
- The **zk proof** is responsible for *correctness*: every settled state root must be reproduced by re-executing the engine inside a zkVM. Integrity does not rest on the hardware.
- The **L1 contract** is responsible for *custody and escape hatches*: it holds the collateral, enforces state-root continuity, adjudicates challenges, and permits claims against already published withdrawal roots. Creating new exit roots still requires operator/prover service and governance during final wind-down.

The result: a trader experiences CEX-like latency and CEX-like privacy, while the on-chain contract only ever advances to states that carry a validity proof. The pipeline, end to end:

```
 Trader's browser
   seals order terms to the attested enclave key
   wire carries only {epochId, sealed}            ── ciphertext ──▶
                                                                  │
 TDX enclave (matching + sequencing)                              ▼
   decrypt · match on price-time-priority CLOB          milliseconds
   enclave-signed receipt: ACCEPTED → MATCHED (soft finality)
   append ops to the current settlement window
                                                                  │
 SP1 zkVM prover                                                  ▼
   re-execute the full engine transition for the window
   derive all six commitment roots from the replayed ops
   wrap in a Groth16 proof                             ~10–20 minutes
                                                                  │
 Base Sepolia — DarkPerpSettlement.settleBatch                    ▼
   verify Groth16 via SP1ZkVerifier · enforce prev-root continuity
   accept the new state root → orders become SETTLED (hard finality)
                                                                  │
 CollateralVault                                                  ▼
   withdrawals in the settled Merkle root are claimable
   by anyone, permanently: claim(to, amount, nonce, root, proof)
```

## 4. Architecture

### 4.1 The matching enclave

The matching engine and sequencer run inside a confidential VM on Azure (Intel TDX). The enclave's identity is attestation-bound: a DCAP quote pins the code measurement at boot (TCB status UpToDate), and the enclave signing key is sealed to that measurement. The key cannot be exported to, or reproduced by, a machine running different code.

Every accepted order returns an **enclave-signed receipt** in milliseconds — a secp256k1 signature that recovers to the enclave signer address (`0x92173839C6B3b717179ba5505CCE31bD2131EbA0`). The receipt is soft finality with teeth: it is exactly the artifact a user later presents in the on-chain challenge game (§4.4). Order state progresses `ACCEPTED → MATCHED` (filled, soft) `→ SETTLED` (proven on-chain, hard).

Three markets are live — BTC, ETH, and SOL perpetuals (marketId 0/1/2) — on a price-time-priority central limit order book, with oracle marks taken from crypto.com exchange tickers. A gateway-internal **house market maker**, the counterparty of the LP pool, quotes at the validated oracle mark against IOC/FOK market orders and crossing limit orders, so takers always have a counterparty; GTC limit orders rest on the book. Users can stake USDC into the LP pool and hold shares of the market maker's PnL. Risk machinery is the standard perp stack: margin, liquidation, an insurance fund seeded with 25,000 USDC, and auto-deleveraging (ADL) with haircut receipts that third parties cannot link to positions.

### 4.2 Windowed sealing and zk settlement

The sequencer periodically seals accumulated activity into a **window**. For each window, an **SP1 zkVM proof re-executes the entire engine transition** — fills, funding, liquidations, ADL, deposits, and withdrawals — from the previous state root to the new one. The SP1 proof is wrapped into a Groth16 proof and verified on-chain by `SP1ZkVerifier` inside `DarkPerpSettlement.settleBatch`.

Two properties make this binding rather than decorative:

> **Prev-root continuity.** The contract accepts a batch only if its previous root equals the current on-chain root. Combined with the proof requirement, the operator cannot settle any state transition the proof does not attest — there is no operator-asserted path to a new root.

> **Derived, not declared, commitments.** All six commitment roots — state, manifest, ordered, withdrawals, rejected, and the binding commitment — are derived *inside the zk guest* from the replayed operations. The operator does not get to hand the verifier its own claimed outputs; a whole class of "the host lied about the roots" attacks is closed by construction.

### 4.3 Custody and withdrawals

USDC never sits with the operator: it sits in `CollateralVault`. A withdrawal is recorded off-chain, included in that window's **withdrawals Merkle root**, and once the window settles, anyone — the user, a relayer, a stranger — can execute `claim(to, amount, nonce, root, proof)` permissionlessly. Funds can only move to the address bound into the Merkle leaf. Every historically published root remains claimable forever; a later root can never strand an earlier withdrawal.

> **A withdrawal included in a settled window is claimable by anyone, from any address, indefinitely. Executing the claim requires no cooperation from the operator.**

### 4.4 The challenge game

Soft finality is only as good as its enforcement. The operator posts a USDC bond with an on-chain floor of **5% of vault TVL** (`requiredBond()`, `BOND_BPS = 500`); settlement halts if the bond falls below the floor. A user holding an enclave-signed receipt can open an on-chain **inclusion challenge** (posting a 0.01 ETH challenge bond as an anti-grief measure). The sequencer then has a 300-block challenge window to prove, on-chain, that the receipted order was included in a settled window. If it cannot, the operator's bond is slashed — paid out pull-payment style — to the challenger.

This converts the millisecond receipt from a promise into an enforceable claim: silently dropping an acknowledged order costs the operator real collateral.

### 4.5 Liveness and forced exit

If the sequencer stops settling for 7200 blocks (`livenessBlocks`), the contract enters forced-exit/close-only mode. Only withdrawals already included in published roots can be claimed independently with their Merkle data. Account balances and open positions are not withdrawal leaves. New exits need the operator/prover and, for finalSettle/finalExit, governance; the liveness timeout does not remove these dependencies.

### 4.6 Crash safety

Enclave state is persisted as sealed snapshots (encrypt-then-MAC under the enclave seed), and the in-flight settlement window is protected by a sealed **rollback journal** (write-ahead log). A crash or restart mid-settle self-recovers at boot: the sequencer reconciles against the chain and either rolls the window back for re-sealing or rolls forward to match a settlement that already landed. This is not a paper property — a **restart-during-proof drill was executed against the live public testnet**, and the system recovered without manual state surgery.

## 5. Privacy model

### 5.1 Sealed order ingress

Order terms never leave the browser in plaintext. The client fetches the enclave's rotating **X25519 epoch key**, served signed by the attested enclave identity (`GET /v1/enclave/epoch`), and verifies the signature before sealing. Encryption is a sealed box: X25519 ECDH → HKDF-SHA256 → XChaCha20-Poly1305, with wire format `0x01 ‖ epk ‖ nonce24 ‖ ct` over a 51-byte order payload. The HTTP body carries only `{epochId, sealed}` — no plaintext trade terms cross the wire, with TLS layered on top. The AEAD's associated data binds each ciphertext to (epoch ‖ account owner), so a ciphertext cannot be replayed across accounts. In production posture, unsealed orders are refused outright.

### 5.2 Shielded state

Account state lives as **encrypted notes**: the public can observe aggregate book depth, but not per-account balances or positions. The order log itself is stored encrypted, and ADL haircut receipts are unlinkable by third parties to the positions they touched.

### 5.3 What an observer sees — and does not

| Visible to anyone | Hidden from everyone outside the enclave |
|---|---|
| Aggregate order-book depth per market | Order terms in flight (price, size, side, type) |
| Oracle prices, funding, market metadata | Per-account balances, positions, margin |
| Settled window roots + Groth16 proofs on-chain | Any account's liquidation price |
| On-chain deposits and withdrawal claims (ordinary L1 transactions: EOA, vault, amount) | Which account traded inside a window; the link between an ADL haircut and a position |

The honest boundary: entering and exiting the system are public L1 events, as on any rollup — the depositing address, the claim destination, and those amounts are visible on Base Sepolia. Trading data is hidden from public-chain observers, but the custodial gateway and development prover remain inside the privacy trust boundary.

## 6. Security and trust model

This section is written to be checked, not believed. Each guarantee is stated with its mechanism, and the current limitations are enumerated in full. Precision here is the product.

### 6.1 What the zk proof guarantees

A proof rejects transitions that violate the guest program. The alpha gateway still holds spending keys and price-publisher authority, so user intent and external price truth are separate trust assumptions. Only existing withdrawal leaves in published roots support independent claims with their Merkle data; creating new roots requires operator/prover service and governance during final wind-down.

### 6.2 What the TEE guarantees

Matching and ordering run with privacy and integrity attested to Intel TDX hardware. The enclave identity — the receipt-signing key and the order-decryption keys — is sealed to the code measurement, so it is available only to the audited code, not to the operator's host OS or to modified builds.

### 6.3 What signed receipts guarantee

An acknowledged order is a bonded commitment. Through the inclusion-challenge game (§4.4), omitting a receipted order from settlement is a slashable offense, adjudicated on-chain against the operator's 5%-of-TVL bond.

### 6.4 Current limitations (testnet alpha)

1. **The zk prover is not yet TEE-attested.** It currently runs on a development workstation; the witness leaves the sequencer enclave sealed, but the prover machine's attestation measurement is a stub. Consequence, stated plainly: the plaintext window witness is exposed to operator-controlled prover hardware today, so the privacy perimeter currently includes that machine. State *integrity* is unaffected — the chain still accepts nothing without a valid proof. Roadmap fix: attestation-gated witness-key release to an x86_64 TDX prover.
2. **Operator liveness is a single point of failure.** If the sequencer goes down, trading halts. Existing published claims remain available with their Merkle data. New withdrawal roots require the operator/prover and, in final wind-down, governance; the timeout alone does not make every balance independently withdrawable.
3. **Ordering fairness is not yet zk-proven.** The proof attests correct *execution* of the sequenced operations; the *sequencing itself* is enclave-attested only. A matching-fairness proof ("Proof v2") — proving the ordering policy, not just the execution — is on the roadmap.
4. **Clock proving has no accepted latency bound yet.** The old ~10–20 minute observation is not a current capacity guarantee. One proof per window, over a full-state witness, so hard finality lags soft finality by that interval and proving cost grows with total account count. A sparse-witness redesign (proof cost independent of total accounts) is on the roadmap.
5. **No third-party audit yet.** The contracts and engine have been through internal multi-agent adversarial audits — 13 findings were remediated before alpha — but no independent firm has audited the system. Treat it accordingly.

Test coverage must be read from the command results for the reviewed source, across the workspace — engine, sequencer, gateway, and the contracts' own forge suite — including proof-replay merge gates and crash-recovery drills.

## 7. Status today

PR #31 records a real clock proof for a pinned guest and local verifier stack. The July Base Sepolia addresses describe a historical deployment, not verified parity with that guest. The new normal-wallet HTTP lifecycle is tested locally using Anvil and an explicit mock verifier. The same full lifecycle with real clock proofs, target capacity and infrastructure disaster recovery remain release gates.

### 7.1 Historical deployment contracts (Base Sepolia, deployed 2026-07-09)

| Contract | Address |
|---|---|
| DarkPerpSettlement | `0xf5D6Aa9CC96E2ac8AC5564df5E8475bDb13BCDCF` |
| CollateralVault | `0xC3EBc0f7301D5a914b01b8d2a1B5574764330c05` |
| MockUSDC (open mint, 6dp) | `0x9F5365c947eCaBaf62f42EF0Fe92ab909f709bDA` |
| SP1ZkVerifier | `0x8012F3b35B9884f86a3F8f39B79e82eC410E1160` |

SP1 program vkey: `0x000a2f9bc04612ca95b3b26dc65f5dc463bba65ce1dff5eb3725545679bda5ed`, bound in SP1ZkVerifier; proofs verify through the canonical SP1VerifierGateway `0x397A5f7f3dBd538f23DE225B51f532c34448dA9B`. Sequencer/operator: `0xed37B7fc534Cc93D4195b4F11ADc5C14237cd287`. Enclave signer (receipts recover to): `0x92173839C6B3b717179ba5505CCE31bD2131EbA0`. Explorer: https://sepolia.basescan.org.

### 7.2 Try it

All funds are **test funds** — MockUSDC is open-mint, and Base Sepolia ETH is available from public faucets. The app self-provisions a trading account in the browser; orders are sealed client-side automatically. Alpha testers and integrators (the gateway serves a JSON API with an OpenAPI description, and the sealed-order wire format is documented for bot authors) should start here:

- **App:** https://perp.arcoralabs.xyz
- **Docs, quickstart, and API reference:** https://perpdocs.arcoralabs.xyz

Expect alpha behavior: `SETTLED` status lags a proof interval (~10–20 minutes), and contracts may be redeployed during the alpha.

## 8. Roadmap

Sequenced as engineering milestones; each closes a limitation named in §6.4.

1. **TEE-attested prover.** Move proving onto x86_64 TDX hardware with attestation-gated witness-key release, so the sealed witness can only be opened inside a measured prover — closing limitation 1 and completing the privacy perimeter.
2. **Sparse-witness proving.** Rework the proof so its cost depends on the accounts a window touches, not on total accounts — closing limitation 4 and keeping settlement cadence flat as the user base grows.
3. **Matching-fairness proof (Proof v2).** Extend the zk statement from "the sequenced ops were executed correctly" to "the ops were sequenced by the declared policy" — closing limitation 3 and removing the last integrity reliance on the TEE.
4. **Third-party security audit → incentivized testnet → mainnet.** Independent review of contracts, engine, and enclave posture; then a public incentivized testnet; then mainnet.

## 9. Disclaimer

Arcora Perp is testnet alpha software operating exclusively with valueless test assets on Base Sepolia. There is no token, and nothing in this document is an offer, solicitation, or recommendation to buy or sell any security, token, or financial instrument, nor financial, investment, or legal advice. The system has not been audited by a third party; contracts and infrastructure may change or be redeployed without notice, and any data on the testnet may be reset. The software is provided "as is," without warranty of any kind, express or implied. Descriptions of guarantees in this document are descriptions of mechanism design, not promises of future performance.

---

*Arcora Perp — Technical Brief — July 2026*

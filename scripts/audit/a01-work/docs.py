from pathlib import Path
import sys
r=Path(sys.argv[1]);p=r/'docs/API.md';s=p.read_text()
s=s.replace('| POST | `/v1/accounts/deposit/onchain` | ✓ | `{ txHash, marketId }` — credit a real USDC deposit |','''| POST | `/v1/accounts/deposit/authorize` | ✓ | `{ from, amount, marketId, purpose }` — durable permit with explicit routing |
| POST | `/v1/accounts/deposit/route` | ✓ | `{ ownerCommit, from, amount, marketId, purpose }` — explicitly adopt a legacy pending permit |
| POST | `/v1/accounts/deposit/onchain` | ✓ | `{ txHash, marketId }` — optional finalized ingestion accelerator / durable receipt |''')
s=s.replace('`POST /v1/accounts/deposit/authorize { "from": "0x<your EOA>", "amount": "<base units>" }`','`POST /v1/accounts/deposit/authorize { "from": "0x<your EOA>", "amount": "<base units>", "marketId": 0, "purpose": "collateral" }`')
a=s.index('4. `POST /v1/accounts/deposit/onchain');b=s.index('## Trading is gated until launch',a)
s=s[:a]+'''4. **No confirm call is required.** The gateway autonomously consumes finalized
   L1 blocks in deposit-ID order, using the market and purpose recorded at
   authorization. Closing the browser does not interrupt ingestion.
   `POST /v1/accounts/deposit/onchain { "txHash": "0x..", "marketId": 0 }` optionally
   accelerates that same serialized ingester and returns an owned durable receipt.
   It cannot skip earlier deposits, change their market, or divert insurance.

The permit's secret blind and route must be acknowledged by persistent storage
**before** any gateway signature is released. An applied block's engine state,
replay operations, consumed prefix, receipts and remaining permits are saved
in the same snapshot before success is reported. Identity is chain/vault/deposit ID,
not merely transaction hash: multiple accounts can deposit in one transaction.

**Confirm responses:** `200` with `status: "credited"`, `credited`, `depositIds`,
`marketId`, `purpose`, `durability: "confirmed"`; `202` with
`status: "pendingFinalizedIngestion"` (not successful zero credit); `409` for a
market/purpose mismatch or a historical transaction without reconstructible new
receipts; `503` for RPC unavailability, blocked ordering, safety halt or uncertain
durability. Pending / `503` is **not** an instruction to send funds again.

**Legacy permits remain unresolved, not reset.** Snapshot v5 imports retain every
blind, account, nonce, note, replay operation and inherited consumed prefix. No
market or purpose is inferred for blind-only authorizations. The account explicitly
adopts each legacy permit through `/v1/accounts/deposit/route`, supplying all route
fields; insurance additionally requires operator authorization. Routing is then
immutable. A missing or mismatched route at the next L1 deposit stops the stream
with a visible error. Later deposits are never skipped. Do not delete the state,
invent an initial cursor, or fabricate missing historical receipts to bypass this.

**Provider requirements:** `finalized`, historical headers, block-hash
`eth_getLogs`, EIP-1898 hash-pinned `eth_call`, and historical `eth_getCode` before
contract deployment. There is no latest/receipt fallback. Complete log pages are
checked against contract deposit-count/prefix and canonical headers. Transient
errors pause ingestion; a contradiction of a persisted prefix or anchor causes a
durable safety halt. Trading, withdrawals and new settlement are paused while
prefix verification or deposit durability is unresolved. The public state's
`deposit_ingestion` object exposes readiness, dirty state, count/tip, anchor, halt,
last error and unresolved-permit count without exposing secret routes.

RPC remains a trust boundary: consistency checks cannot authenticate a wholly
fabricated chain. A finalized reorg is not automatically rewound; operators must
reconcile trusted chain data and preserved state. v6 is an explicit snapshot format
upgrade; older binaries cannot safely read the new state. Preserve backups and do
not roll back the binary while discarding credits written after upgrade.

'''+s[b:]
a=s.index('`POST /v1/admin/insurance/bootstrap');b=s.index('## Withdrawals + claiming',a)
s=s[:a]+'''The operator first authorizes a fresh one-shot permit with
`POST /v1/accounts/deposit/authorize { "from": "0x<operator>", "amount": "<base units>",
"marketId": 0, "purpose": "insuranceBootstrap" }`.
This requires the operator account's `X-Api-Key`, `X-Admin-Key` matching
`FIN_ADMIN_KEY`, and a bound payer equal to `INSURANCE_OPERATOR_ADDRESS`.
All requirements also apply to explicit legacy insurance-route adoption.

The finalized ingester applies `Deposit` and `FundInsurance` atomically. It never
uses a later confirm request to decide purpose. A bootstrap deposit cannot become
user collateral, even when manual confirm races automatic processing.

`POST /v1/admin/insurance/bootstrap { "txHash": "0x..", "marketId": 0 }` with those
credentials is now an **optional receipt/acceleration endpoint**, not a routing
command. Its `200`, `202`, `409`, `503` meanings match the shared ingester. Repeated
confirmation is idempotent. A separately authorized insurance contribution uses a
fresh permit; do not authorize another contribution because a receipt is pending.

The compile-time insurance minimum remains **10,000 USDC**. Insurance routes record
an explicit existing market ID for audit consistency, but `FundInsurance` targets
the global fund, not a market position. This is a **one-way** transfer to protocol
ownership; there is no operator withdrawal or unfund path.

A pre-v6 `Bootstrap::DepositApplied` record is preserved. After verifying its
inherited L1 prefix, ingestion resumes **only** the recorded `FundInsurance`,
without minting another deposit or crediting collateral. Failed application leaves
the recorded note and state retriable. Bootstrap completion still follows
settlement of the window containing the insurance operation.

These checks are gateway custody policy, not a new ZK guarantee. A compromised
sequencer custodies spend keys and the engine's `FundInsurance` operation does not
prove this API authorization policy. A10 remains open.

'''+s[b:];p.write_text(s)
p=r/'crates/gateway/src/bootstrap.rs';s=p.read_text();a=s.index('/// Whether an operator bootstrap');b=s.index('pub fn amount_meets_floor',a)
p.write_text(s[:a]+'''/// Minimum for an explicit insurance route. A01 production ingestion validates
/// this before atomic Deposit + FundInsurance. The legacy driver is test-only;
/// a v5 half-transfer resumes from its recorded note without a new deposit.
'''+s[b:])

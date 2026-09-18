# Order execution API addendum

Applies to the execution remediation branch on top of PR #2. This supersedes the earlier pre-seal-only cancellation description. The served OpenAPI cancellation summary is updated with the implementation.

### Cancellation and execution (A04 / A05)

`DELETE /v1/orders/:orderId` cancels the caller's queued order or the **live
remaining quantity** in the matcher. Being sealed, partially filled, or previously
`SETTLED` does not prevent cancelling the remaining quote. Already executed fills
and positions are not undone. The order row and its original acceptance receipt
remain in history. Repeating a retained user cancellation is idempotent; an unknown
order or a fully executed order with no resting remainder returns `400`, with
`ORDER_NOT_LIVE` for the latter.

In production, `200` is returned only after the cancellation is included in an
acknowledged durable snapshot. Missing persistence returns `503` before mutation.
An unsuccessful or timed-out write after mutation returns `503` with
`outcome: "DURABILITY_UNKNOWN"`: the cancellation has already been applied in
memory and is **not** undone. Retry the same cancellation to obtain a new durable
acknowledgement; do not interpret this error as proof that the quote remains live.
A cancellation hash enters the window's existing rejection manifest as `Cancelled`.

Order responses now contain a separate `execution` object. Amounts are decimal
strings in the existing size/price scales:

```json
{
  "status": "PARTIALLY_FILLED",
  "remainingSize": "7500000",
  "filledSize": "2500000",
  "avgFillPrice": "100000000000",
  "unsettledSize": "2500000",
  "settledSize": "0",
  "reason": null,
  "available": true,
  "proven": false
}
```

This example represents a 0.1-size order filled for 0.025 with 0.075 still live.
`status` is `PENDING`, `RESTING`, `PARTIALLY_FILLED`, `FILLED`, `CANCELLED`,
`REJECTED`, or `UNKNOWN`. Quantities and volume-weighted average prices accumulate
from successful ledger fills across ticks, including later fills on an older maker.
An IOC may be `CANCELLED` with a nonzero filled quantity and zero remaining quantity.

`finality` remains the monotone receipt axis `ACCEPTED` / `MATCHED` / `SETTLED`.
A previously settled partial order can receive later, not-yet-settled fills;
`execution.unsettledSize` distinguishes that quantity. Do not treat `SETTLED` alone
as saying the whole order has filled or every later fill is settled. This metadata
is native gateway reporting, **not** an independent ZK proof of the order-to-fill
association or matching fairness (`proven: false`).

New snapshots use `DPSNAP6`. The new reader can migrate authenticated v5 snapshots
without resetting balances. Old software fabricated some execution history, so
migrated sealed orders report `available: false`, and historical `filledSize`,
`avgFillPrice`, `settledSize` and `unsettledSize` are `null`. Their real remaining
book quantity is still usable for cancellation. `filledSize` / `avgFillPrice` on
the flat order response are likewise nullable. Clients must display unavailable
history rather than invent zeros. Update gateway and frontend together; older
software cannot read a v6 snapshot. See
[`2026-09-18-execution-remediation.md`](2026-09-18-execution-remediation.md).

## Private WebSocket notifications

One `fill` event represents one actual applied fill; hardening its batch does not create another fill. `execution` events update native lifecycle metadata. The durable cancellation endpoint sends `{ "type": "execution", "orderId": "o1", "status": "CANCELLED" }`; refresh the authenticated order view for complete quantities and receipt fields. These events use the owner-filtered private stream.

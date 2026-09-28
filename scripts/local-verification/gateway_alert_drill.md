# Local operational alert drill

Run from the repository root, using a new output directory:

```sh
python3 scripts/local-verification/gateway_alert_drill.py --output-dir /tmp/arcora-alert-drill-new
```

This runs six tests. Four fault cases drive production event paths and capture real
HTTP POSTs at a disposable `127.0.0.1` collector; two tests check configuration and
bounded/redirect-refusing delivery. No external recipient is configured or contacted.
`result.json` includes exact before/after source hashes, command, actual discovered
test counts, log hash, and the JSON bodies the collector received. A changed source,
missing case, test failure, timeout, or empty test collection fails the drill.

| Event | Controlled fault and production path | Recovery / repeat behavior |
| --- | --- | --- |
| `settlement_held` | `Gw::settle_breaker_failed` crosses the actual breaker threshold; `hold_settlement_for_recovery` handles an unresolved transaction | One active event per episode; the shared actual-success transition recovers and rearms. Admin retry cannot clear an unresolved hold. No real settlement proof is claimed by this transition test. |
| `persistence_failed` | An actual `ENOTDIR` write failure in `write_snapshot` and `final_snapshot` | Failure remains false even when the collector responds 503. An actual successful sealed write recovers and rearms; its bytes are decrypted and restored. Missing queues, ACK timeouts, and journal writes are outside this scoped event. |
| `deposit_halted` | `ingest_once` receives a finalized-anchor mismatch from a controlled source, then persists the halt through the real writer ACK | Repeated ingestion does not refetch or re-alert. The halt survives decrypt/restore. This is terminal until separate operator reconciliation; no automatic recovery event is sent. |

## Runtime configuration

The default sink is one structured `[ops-alert]` JSON line in stderr. Its schema
contains only `schema`, the closed event enum, `transition`, and a numeric `episode`.
RPC URLs, arbitrary error text, accounts, keys, and witness data cannot enter the
notification schema. Existing restricted diagnostic logging is separate.

To additionally send to a local collector, set one explicit address:

```sh
FIN_ALERT_LOCAL_URL=http://127.0.0.1:19090/alerts
```

Only literal `127.0.0.1` or `[::1]`, a nonzero explicit port, HTTP, and `/alerts` are
accepted. Hostnames, userinfo, queries, fragments and redirects are refused. The
transport ignores curl configuration and bypasses proxies for loopback delivery.
It uses a one-second connect timeout and two-second total request timeout, requires
HTTP 2xx, and has one worker with a 32-event bounded queue. Sending is best effort;
a full queue or failed recipient retains the local structured log and never changes
the application durability result. There is one delivery attempt per transition,
not an unbounded retry loop. Process restart resets the runtime episode counter;
persisted deposit halts are announced again after startup configuration.

Existing `FIN_ALERT_NTFY_TOPIC` delivery remains opt-in at `https://ntfy.sh/<topic>`.
Topic characters are restricted to letters, digits, dash and underscore (maximum
128). Its payload is now the same redacted JSON. `FIN_ALERT_LOCAL_URL` and a topic
are mutually exclusive; invalid configuration prevents startup. The drill never
selects this external transport.

This completes the local alarm subpackage only. Real operational owners, external
escalation, the complete alert catalog, and restore/CloseOnly exercises remain in
the original S7-01 acceptance scope.

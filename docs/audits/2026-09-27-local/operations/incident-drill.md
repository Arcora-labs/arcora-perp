# Local incident and release rehearsal boundary

The managed gateway starts with a clean allowlisted environment, only synthetic demo identities, a temporary snapshot and loopback port 0. `runtime/runtime-manifest.json` records the own-process SIGKILL/restart and orderly SIGTERM results. No production snapshot or user process is touched. `checks/live-http-restore-integrated.json` is the final combined-source run when complete.

Observed drill: real HTTP account/order smoke; demo deposit; wait for the periodic authenticated snapshot; record hash; kill the owned process; verify file hash; restart same snapshot; compare owner/balance/position collateral/recovery nonce; stop the owned process. This does not prove durability at a successful recovery/settlement ACK boundary, crash-after-rename, fsync failure, or a power cut.

Incident procedure: preserve snapshot and journal copies and hashes; keep intake paused; determine confirmed versus unknown using durable state and pinned chain observations; never infer rollback from a timeout alone. Use the restore runbook. A browser compromise requires a clean device and current wallet-authorized recovery; closing a tab alone does not revoke credentials. A prover outage requires no resubmission of unknown chain transactions and no dev/mock fallback. CloseOnly on a real chain or key/role rotation requires its own explicit operational authorization.

No notification was sent. No real incident owner, escalation destination or second human operator was supplied. Full failure-injected alarm delivery, CloseOnly/token-flow rehearsal and a runbook executed by another operator remain open. The alert catalog records source defaults rather than invented response-time targets.

Proposed release observation, not executed: assign custodial/sequencer/oracle/prover/security owners; use a reviewed small canary limit; reconcile after every finalized settlement during the first 24 hours; retain daily signed source/state/block reconciliation for seven days. Owners must choose numeric fund/latency limits from measured proving capacity and risk tolerance. No release is authorized by this document.

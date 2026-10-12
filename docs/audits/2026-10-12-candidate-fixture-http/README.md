# Candidate fixture HTTP: software verification and recovery boundary

The existing candidate preparation/handoff specification now has a separate
`cfg(test)` HTTP transport and stateful, caller-owned loopback peer. This closes
the software exchange/recovery test gap. It creates **no production route,
candidate backend, authenticated witness channel or real chain/proof result**.
Candidate submission stays disabled and **PRODUCTION HOLD** remains.

Base main: `29be35c7a66c20563fb83812039eaaf1aa05d80a` (#55).
Code: `a716f0c0fe6305749844d4f16cabbff19541b2d2`.
The later publication commit adds documentation/evidence; publication-head CI
and normal merge observations are delivered separately after they occur.

| Local check | Actual result | Evidence |
| --- | --- | --- |
| Final full gateway | **697 PASS / 0 FAIL / 23 intentional IGNORE**, all 18 new HTTP tests included | `receipts/checks--gateway-final.json` and raw logs |
| Final Python builder/preflight | **25 PASS** | `receipts/checks--new-python-published.json` |
| Final workspace format/Clippy | PASS, warnings denied | `receipts/checks--workspace-format.json`, `receipts/checks--workspace-clippy-final.json` |
| Reviewed provenance | 21 reviewed + 9 candidate runtime + 2 auxiliary sources unchanged | `receipts/checks--pins-final.json` |
| Independent static preservation | 2920 baseline files: 2916 unchanged, only four planned old paths changed; 82 original dirty files unchanged | `receipts/preservation-final.json` |

The four final command receipts bind all **373** covered source files before/after to
`69e339182071f166942be65ced7857f27f401093315ba48b0bea73f5551661e1`.
The final pin receipt records the same source map in a single snapshot.
`artifact-ledger.json` binds retained artifacts and the five code-commit paths.
Root Cargo manifest/lock, guest/core/contract/ELF/vkey and all old candidate
stores/protocols/fixtures are unchanged. Old main executable lines are preserved;
only the four `cfg(test)` hooks were added. A11 has one additive explicit fixture
step; all old steps and timeout/required-check policies are retained.

## Actual behavior under the owned HTTP fixture

The complete original normal/liquidation witnesses and full containers are used.
Native replay and local roots/count/canonical calldata are computed from those
pinned inputs. Responses carry opaque mock proof bytes, fixture observations
and mock settlement effects. They do not authenticate SP1 proofs, DON, finality,
archive provenance, a binary/process or an approved operator.

Each semantic matrix waits for both actual positive native HTTP flows, shared
once per frozen test process. Each refusal has fresh directories, listeners,
remote state and durable lanes. Exact wire bytes, received operation/effect
counts and source/broadcast stages are asserted; the source lease/checkpoints
remain with the old coordinator.

- Normal/liquidation flows reach durable Prepared and terminal mock outcome;
  terminal replay performs no HTTP.
- Lost clock ACK leaves ClockPending. Resume does lookup only; absent reports
  become ReportsPending/Absent/HOLD, not an invented successful registration.
- Lost report ACK can reconcile the actual fixture report effect to Prepared
  without a second registration.
- Lost broadcast ACK keeps the same Pending plan/lane. Resume only looks up the
  recorded effect; Pending/Absent/Unknown/Reorg never trigger rebroadcast.
- ReportsObserved can repeat pure mock proving on Resume; this is explicitly
  distinct from mutation retry or exactly-once proving.
- Constructor/callback/plan mismatches refuse before socket work. Invalid peer
  bytes **after an effect** leave the proper staged cut and stop later actions;
  they cannot establish that the peer performed no effect.

The new packet tests program/target/witness/material/plan bindings, wrong or
replayed exchange identities, response magic/version/operation/scope/digests,
ambiguous headers/content length, transfer/content encoding, redirect, wrong
content type/version, header/body size, truncation/trailing bytes, proof program/
public values/nonempty/canonical/nested-size guards, observation/epoch/anchor,
outcome effect/finality and stalled-peer deadline refusals. Literal IPv4
127.0.0.1/nonzero port, fixed path/content type, coded diagnostics, no ambient
URL/DNS/env/proxy/credentials and one exchange per requested action keep this
fixture boundary separate from production transport. IDs are random-seeded
process counters with no wrap; they are correlation, not signed freshness or
durable/authenticated identity.

## Failed-before, passed-after and performance evidence

Initial compile failed before any test: the new test helper passed a seed value
where the unchanged store decoder requires a reference. Only `&BROADCAST_SEED`
was corrected. The first executed source then passed all 18 tests in **425.37 s**
(438.631 s total).

That version redundantly replayed identical fsync-heavy positive flows before
every variant. Sharing both positive flows behind a process-local OnceLock
barrier preserved every fresh fault fixture, assertion and effect/stage check.
The optimized pre-lint source passed the same 18 tests in **57.04 s** (64.464 s
total). Independent byte comparison reconstructs the previous test file by
reversing only the import/barrier change. These timings measure this test suite,
not proving or production capacity; those receipts have their own source hashes.

Clippy then rejected a manual inclusive range spelling. The equivalent
`RangeInclusive::contains` predicate preserves exactly the same bounds; the
lint was not disabled. The final source passed Clippy/format/Python and the
full **697** gateway tests (including all 18 HTTP tests), in **362.24 s** test
time (366.935 s total). Earlier receipts are historical and do not inherit this
final source hash. Both compile/lint failure logs are retained.

## Remaining gates and preserved history

Production services still declare legacy/DPCLK2; their public preflight rejects
DPCLK3 compatibility. A real candidate backend, sealed/authenticated transport,
approved target/policy/public service inputs, fresh proof/settlement/claim,
actual CC/key release, DON/uptime health, custody, capacity/finality, recovery
operations and independent production acceptance remain open. Live feed
discovery stays user-deferred. This packet made no discovery/RPC/fund/transaction,
new SP1 setup/proof, production service or credential action.

The original 13/7-staged/62 dirty worktree files and their HEAD/status/staged
diff hashes are preserved. #55's three post-merge main runs are now all SUCCESS;
`receipts/main-refresh.json` and its raw log archives record only that prior
base, not this publication's CI. Earlier source/QA/performance receipts remain
unchanged. [Usage/bounds](../../CANDIDATE_FIXTURE_HTTP.md) and
[active acceptance gates](../../ACTIVE_WORK.md).

# Owned diagnostic process-group supervision

PRODUCTION RELEASE HOLD. Candidate submission remains disabled.
Base: PR70 merge `98cded403c3fba045094bda330b61e12aba99d03`.

## Fix and scope

The finite-preparation runner previously killed only its immediate Cargo PID on
its 900-second deadline. PR70 recorded the compiler continuing after that timeout.
The diagnostic runner now launches a new POSIX session/process group, records the
owned group ID, sends TERM and then KILL after a bounded grace when needed, and
collects wait4 only for the direct child. A normally exited leader with leftover
same-group descendants is also cleaned up and cannot produce a success result.

SIGINT and SIGTERM requests are retained while Popen establishes ownership, then
cause cleanup. Original signal handlers are restored. Runtime exceptions and
KeyboardInterrupt use the same cleanup path. The capture adapter writes status
and hashed stdout/stderr logs before re-raising failures/cancellation. A zero exit
cannot hide a deadline, exception, cancellation or incomplete cleanup. Invalid
arguments fail before spawning; existing logs are not overwritten.

The helper is standard-library-only and is invoked by the existing macOS CLI.
wait4 resource units are explicitly recorded; they are not whole-process-tree RSS.
No Rust, guest, contract, dependency lock, protocol, wire, production process,
repository permission or deployment setting changes. The A11 workflow only ADDS
the two Python suites to the existing required dependency-advisories job.

## Actual acceptance at this publication cut

* Assistant Linux container: 10 real-subprocess supervisor tests PASS. Exact
  helper/test hashes were matched after transferring their source to the Mac.
  Coverage includes TERM-ignoring parent/grandchild, escalation, an unrelated
  surviving session, timeout despite graceful zero exit, SIGINT/SIGTERM during
  spawn return, runtime exception/KeyboardInterrupt, early leader exit, missing
  executable, invalid deadlines, output larger than a pipe buffer, and denied
  group inspection being refused rather than called successful.
* Connected Mac: the original 9-test full supervisor run FAILED (five assertion
  failures and three teardown errors), because group signal/probe operations
  returned PermissionError / Operation not permitted. The capture/parser suite
  had nine passes and one error at the same denied group probe. These are NOT
  passes and are preserved verbatim. The targeted permission-refusal test PASS,
  and all three repository-policy tests PASS. Python syntax and diff checks PASS.
* A11 CI now executes all 10 supervisor and all 10 capture/parser tests on Linux.
  Publication is not itself CI acceptance; later job/step logs close that gate.

The first local Linux fixture attempt failed readiness/timeout checks. Fixtures
were changed to launch Python with -S, and fixture startup failures now retain
and clean their own PID. The final Linux tests above are bound to the final source.
No suppressed warning or weakened assertion was used to relabel a failed run.

## Permission and containment limits

The connected Mac's denied group operations were NOT bypassed with per-PID kills,
privilege elevation or permission changes. Those bounded test children expired
normally; targeted readbacks found the previously reported PIDs absent.
This patch reports the permission failure and incomplete cleanup honestly. It
cannot grant OS signal authority. Do not assume complete cleanup in that restricted
Mac execution context until the full suite passes from an authorized environment.

Only descendants remaining in the owned group are covered. A process deliberately
creating another session/group, SIGKILL of the supervisor, or a kernel-uninterruptible
task requires an external supervisor. Adopted zombies may remain visible until the
OS reaps them: tests distinguish stopped execution from reaping, and metadata does
not mark a still-present group as clean. No process-name or system-wide kill is used.
The source is not a security sandbox and is not intended for hostile child code.

## Reproduce

From the repository root with Python 3.11+:

```sh
python3 -m unittest discover -s scripts/local-verification -p test_owned_process.py -v
python3 -m unittest discover -s scripts/local-verification -p test_finite_preparation_profile.py -v
python3 -m unittest discover -s scripts/local-verification -p test_repository_policy.py -v
```

The legacy fixture/CPU parser, actual benchmark inputs, CPU phase definitions,
proof placeholders and default timing/codegen settings are unchanged. No new full
Rust release benchmark, real proof, target/backend, CC, custody or release gate
is claimed. Prior audit packets retain their original bytes and source identities.

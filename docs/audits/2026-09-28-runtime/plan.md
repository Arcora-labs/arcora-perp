# Runtime/reconciliation continuation — 28 September 2026

Base checkout and earlier changes preserved. This pass focuses on S4-07 accepted HTTP/WS/background drain, S6-02 actual SIGKILL at atomic persistence boundaries, prover SIGTERM with accepted/cancelled worker, and S2-03 known-transaction status reconciliation UI. Separate file ownership prevents concurrent overwrites.

Acceptance: actual tests must demonstrate no lost acknowledged state, no duplicate wallet send, no premature release of running worker capacity, and no clean shutdown claim before admitted work ends. Crash tests use only owned temporary subprocesses and cfg(test)-only checkpoints. No proof or native/guest parity result is inferred from these tests. Existing A06 execution restriction remains unchanged and is not worked around.

Evidence lives in this directory; prior continuation evidence remains historical with its own source identity. Original Desktop checkout remains untouched. No deployment, live chain mutation, external message or user credential use is part of this pass.

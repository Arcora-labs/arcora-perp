# Required CI correction

First PR66 head243a2ea failed release regression: full gateway765PASS/1FAIL/24IGNORE.
The mint-site enumeration expected9 but found11 because two constructors were added
in a cfg(test) candidate codec fixture. This first CI result is rejected and retained.

Only the existing main.rs test is updated. Journal production must contain0 mint
constructors, its explicit cfg(test) section2, global source count11. Other funnel
counts7/3/2 remain. Restoring only that test restores entire main.rs BASE bytes;
no production logic/guard, workflow, custody model or repository protection change.
Journal source5c8f is unchanged from the initial functional implementation.

Current source380/927cfb188e76f7043ba620f96e42e7ce46c3e3af3168f18c59a2d4ea5a36b679.
Fresh checks bound both source files: targeted guard1PASS; fullgateway766PASS/0FAIL/
24IGNORE; format and gateway all-target Clippy-DwarningsPASS. The full log includes
newcandidate3/journal12 and all five retention tests. Native mocks and loopbacks
are not fresh proof/live backend/release acceptance or a CPU/RSS benchmark.

Original36mapped+README/ledger38 core files and originals remain byteexact. This
supplement has its own ledger; current physical closure is the UNION of both groups.
Original three zero-test filters remain historical/unaccepted. Baseline-v2 keeps
5564 original inputs and100 initial-revision records, two source exceptions and
append-only ACTIVE prefixes. Existing21compiledgoldens/32pins/8locks/9program
artifacts/82 other dirty bodies remain protected. NewheadCI/normalmerge/main PENDING
at this historical cut. Production HOLD and candidate submission disabled.

# Offline Prepared handoff and candidate identity: final software packet

Base main: `f9a0f2f59ffae651163fc10a43a995054a07ebcc` (merged #52).
Initial handoff code: `995d204`.
Final code: `c9ce9ce51faf78bb8d3f031f612a5d4335dc2a8e`.
The enclosing publication adds documentation and evidence to that code.
**PRODUCTION RELEASE HOLD**. Publication-head CI and merge require their own
GitHub readback; this local packet does not claim a later head has passed.

## Owned Prepared cut and fixed broadcast lane

The new `cfg(test)` `HandoffCoordinator` owns its registration coordinator and
broadcast store. It accepts no externally injected raw source/store or alternate
broadcast pathname. A broadcast lane is derived from the existing physical-source
registration lock identity, independent of request, proof, bridge, sender or nonce.
Changing an attempt's inputs cannot silently select a new store for that source.

`lease_prepared` acquires the source lease, authenticates its binding and requires
the original canonical Prepared record. Its immutable snapshot remains held
while the coordinator takes the broadcast lease second. Both nonblocking leases
stay held through callbacks, writes, readback and the returned outcome. Source,
binding, lock inode and broadcast record are checked before and after callbacks,
including callbacks that return an error. Neither a raw store nor a refreshed
Prepared cut escapes from this interface.

The original dispatcher body is shared through small read/checkpoint interfaces;
its callback schedule, watermark rules and validators are preserved. Existing
preparation `run_prepared` and `attach_existing` bodies remain byte-exact.
[Static comparisons](checks/legacy-seams-comparison.json) record these boundaries.
No DPCINT3/4, DPCREG1 or DPCBTX1 framing, previous fixture/golden builder, reviewed
guest or candidate runtime pin was changed.

Both frozen #50 normal/liquidation flows prepare and pass the exact plan to the
dispatcher. Fresh uses its original recheck/broadcast/lookup schedule; durable
Pending resumes by lookup alone, and terminal records use zero callbacks.
Substitution, mismatched attempts, receipt/anchor/epoch/finality refusals and
Pending/Outcome write, rename and directory-sync failures retain HOLD behavior.

Two actual independent-process tests kill only the fixture-owned process with
SIGKILL inside Broadcast or Lookup. A contender is Busy with zero callbacks;
the successor resumes the original Pending by lookup only. Tests also check the
second lease, exact Prepared/binding bytes, stable device/inode/owner identities,
sender/nonce/attempt and the single mock-broadcast marker.

This is cooperative local coordination for the same owned physical source and
lane. Alternate copies/paths, legacy writers, hostile filesystem changes, physical
power loss, RPC consensus and chain exactly-once remain outside its guarantee.
Legacy writers must be stopped before adoption. The saved Prepared anchor is the
restart baseline; the most recent observed tip is not persisted across restarts.
Transport and transaction identities remain explicitly mock, and these modules
are not production-wired.

## Offline candidate identity

The new [identity guide](../../CHAINLINK_CANDIDATE_IDENTITY.md) and CLI bind the
committed candidate ELF/metadata, historical measured key, 21 reviewed pins,
nine candidate runtime pins and two separately pinned existing test-only modules.
The separate `arcora-chainlink-candidate-offline/v1` schema always preserves HOLD
and disabled submission. The reviewed v2 manifest schema and guards are unchanged.

Explicit public configuration and seven existing compiler artifacts are checked
against local source/compiler/template identities. Credentials and dotenv paths
are excluded without reading their contents. The manifest is a local checksum
binding, not a signature, target observation or trusted compiler attestation.
It refuses unknown fields, unsafe paths, malformed/deep/oversize JSON, changed
source/artifact/key identities, forged scope and output replacement.

The 19 unit tests copy the real committed ELF/metadata and unchanged 21/9/2 pins,
but use synthetic compiler artifacts/configurations and mocked Keccak, dependency
guard and ancestry interfaces. They establish parser/software behavior only.

Separately, the real CLI created and validated [this demonstration manifest](identity-demo/manifest.json)
using seven actual local compiler artifacts and a 353-file source inventory.
The upstream SP1 contracts were compiled with Solc 0.8.20; app artifacts were
already present and their compiler/source/template bindings were validated.
All addresses, expected runtime hashes and policy values in the public demo are
**synthetic declarations**, never observed deployment or approved policy.
[Demo summary](checks/candidate-identity-real-demo.json) distinguishes those inputs
from the actual artifacts. Forged PASS/enabled scope and output-clobber attempts
returned the expected refusal (exit 1), and the original manifest hash remained
`9fe92b08aed519109397f82584a2cd9294409328a88a101d30e330bfa2d46d47`.
Validation also passed after the code-only commit advanced without covered-byte
changes. No guest build, setup, proof, chain observation or transaction occurred.

## Local results and repair history

| Check | Actual result and source boundary |
|---|---|
| Final handoff focus, Rust 1.99 | **17 PASS / 0 FAIL / 1 ignored owned child helper**; 15 semantic + two real-process tests; final 40-source fingerprints |
| Full gateway, Rust 1.99 | **673 PASS / 0 FAIL / 23 intentional IGNORE** at `995d204`, before four lint-only `inspect_err` changes; historical full-run evidence |
| Final workspace Clippy | Rust 1.99, `-D warnings`, PASS; final 40-source fingerprints |
| Final format | PASS; final 50-source fingerprints |
| Existing Python guards | **47 PASS**; final 50-source fingerprints |
| New candidate identity units | **19 PASS**; final 50-source fingerprints |
| Reviewed v2 manifest units | **36 run, OK, one optional Anvil skip locally**; final 50-source fingerprints |
| Release/candidate lock and pins | PASS; **21 reviewed / 9 candidate runtime unchanged**, final 50-source fingerprints |
| Actual CLI demo | Create/validate PASS; forged-scope and clobber expected refusals; final 50-source fingerprints |

The full local 673 run is not labelled as execution of the later `c9ce9ce` source.
Current focused tests and Clippy cover that final Rust code. A fresh complete
Linux publication-head workspace run remains mandatory before normal merge.
No local full Foundry or SP1 CPU replay was rerun for this host-only packet;
the frozen #50 corpus and previous evidence remain unchanged. Publication CI
has separate existing Foundry and real CPU gates.

The initial focus failed **16/1/1**: only the new changed-proof helper encoded
the old DPCINT4 field lengths in the wrong order/endianness. Repair 1 fixed that
new helper to the existing codec and additionally proved authenticated load and
semantic validity before the unchanged PlanMismatch assertion. An older frozen
broadcast negative helper has the same framing problem; its historical result
establishes frame refusal, not the intended semantic mutation. It was preserved;
the new valid-record test supplies the semantic changed-proof coverage.

Initial Clippy 1.99 rejected four new pass-through `map_err` sites. Repair 2
uses `inspect_err` while retaining typed fault reporting and all assertions.
[Handoff repair history](checks/repair-history.json) preserves both failures and
the passed-after records. Rust/Cargo/Clippy 1.99 were selected with the actual
child-tool PATH, not just a rustup wrapper.

Candidate repair 1 fixed an owned fixture's missing Cargo.lock and added an
explicit 64-level JSON bound. Its initial/first-pass tool excerpts are explicitly
labelled reconstructed text, not raw stdout. Candidate repair 2 followed an
actual CLI refusal of the real source layout: two existing `cfg(test)` modules
needed distinct fixed hash pins. Runtime nine/reviewed 21 pins and unknown-file
refusal remain unchanged. [Candidate histories](checks/candidate-identity-repair2-history.json)
link the actual final logs and failed real CLI receipt.

## Preservation and publication boundary

The fresh [preservation receipt](checks/preservation-publication.json) hashes
2,548 base tracked files and allows only seven planned existing changes:
two Rust seams, six test-module wire lines in main, ACTIVE_WORK, SECURITY,
one new candidate unittest-discovery command in A11, and raw-log attributes.
The main CI workspace workflow, previous packets, corpus and all old guards and
assertions remain byte-exact. Three original checkouts retain their complete
**13 / 7 / 62** dirty-file states, heads and staged diff; none was reset or cleaned.

[Verification ledger](verification.json) binds the published receipts, raw
stdout/stderr and their combined logs, payloads, histories, demo and 50 final
source fingerprints. Combined logs are stdout followed by stderr, not interleaved
streams. Original absolute command/capture paths identify the local run; copied
packet paths and hashes identify the public evidence.

[Repository policy observation](checks/ruleset-observation-public.json) records
live main review=0/last-push approval=false versus the recommended template's
review=1/last-push=true. Eleven required contexts differ from the 19 observed
successful contexts on #52. No repository policy was changed. SECURITY now
recognizes implemented on-chain rejection membership/refund behavior while
keeping rejection-reason legitimacy, matching fairness and independent review open.

Real proof, service/deployment/vkey/runtime acceptance, live DON/uptime and
approved feeds/economics, NVIDIA CC/key release, custody/exit availability,
capacity/finality and operational RTO/RPO remain open. Feed discovery remains
user-deferred. These gates are tracked in [ACTIVE_WORK](../../ACTIVE_WORK.md).

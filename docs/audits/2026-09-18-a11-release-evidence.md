# A11 release evidence and deployment gate — 2026-09-18

Base: `main@21d31ff1396db07df99384b0b6a43dbbe60d626b`.

A11 is a release-evidence finding, not something that can honestly be closed by making
ordinary unit tests green. This gate separates four claims that had previously been
blurred together:

1. host/workspace regression safety;
2. current dependency advisory state;
3. current guest source identity;
4. a real SP1 ELF/vkey/proof and its live deployed verifier binding.

The first three can be measured in ordinary CI. The fourth **cannot** be inferred from
the excluded-crate typecheck, old July deployment JSON, or historical proof logs.

## Mandatory release gate

Before any deployment carrying the A06 guest semantics:

- build the current `crates/sp1-guest` with the pinned SP1 toolchain;
- record ELF SHA-256 and the complete toolchain/dependency identity;
- execute native and guest on the same witness and require byte-identical public output;
- derive the program vkey from that exact ELF;
- generate a real Groth16 proof and verify it through the intended verifier path;
- compare the derived vkey with the verifier/deployment target;
- query the target chain through pinned/redundant RPC evidence and record chain id,
  contract code hashes, verifier address, vkey and settlement/vault addresses;
- perform the crash/restart and L1 finality/reorg operational drill against the release
  candidate;
- preserve all commands, exit codes and hashes as an immutable release artifact.

A mismatch is a **deployment blocker**, not a warning.

## Why the existing deployment record is insufficient

`contracts/deployments/base-sepolia.json` records a July program vkey and verifier.
A06 later changed guest-visible transition semantics by adding the proof-bound wind-down
phases. Therefore the repository must not claim that the July vkey proves the current
guest until the current ELF is rebuilt and the vkey is re-derived. The A11 CI records
the old deployment pin only as comparison input and labels it `deploymentRecordOnly`.

## Dependency policy

`cargo audit` and `pnpm audit --prod` run against the current lockfiles. A non-zero
result fails the dependency job and the JSON output is uploaded even on failure. Findings
must be triaged by advisory, dependency path, reachability and fixed version; this change
does not blindly upgrade cryptographic/prover dependencies.

## What this PR does not do

It does not deploy, send live transactions, rotate verifier/vkey state, or claim a real
SP1 proof was produced. It also does not replace an independent external audit. Those
facts are deliberately represented as blockers rather than converted into green
checkboxes by a stub ELF.

# Next A4 packet: exact native witness to local mock-contract bridge

11 October 2026. Design inspection only. No bridge implementation, native/CPU rerun,
proof generation, credential discovery or deployment is claimed here.
**PRODUCTION RELEASE HOLD.** This follows the staged registration recovery packet.

The merged #48 corpus supplies original PUBLIC synthetic full reports and proves
native/CPU equality. Its contract tests use R=1/N=2 fixture roots. Replacing these
roots alone cannot reproduce the complete native commitment: the corpus has
synthetic clock/settlement/wrapper/proxy addresses, and its normal atMs=2,001,100
differs from the EVM seconds timestamp projection 2,001,000. Preserve that original
corpus. A separate bridge must derive a fresh canonical witness in an explicitly
owned local contract context rather than retimestamp a pending request.

Both source fixtures also retain demo genesis deposits: eight sentinel deposits
plus account_deposit produce consumedDepositCount=9 and a nonzero consumed tip.
The later lifecycle batch has no Deposit operation, but its native depositsRoot
still commits that tip. A no-vault settlement requires zero prefix and rejects
this native root before the verifier. Zeroing it would change the commitment.
Count is not itself in publicCommitment; no-vault prefix is zero at every count,
so no contract-side count rejection can be claimed from that path.

## Smallest complete local scope

Phase-0 actual gateway normal and liquidation batches, real local clock/oracle/
settlement wrapper code, and explicit mock DON/SP1/uptime. No public chain or
production service route. An explicit mock prefix vault must accept only the
exported (count=9, consumed tip), reject other prefixes and capture published
withdrawals. This is a mock ledger bridge; it supplies no actual backed deposits
or fund claims. Wind-down, actual CollateralVault/USDC custody and real DON/proofs
remain separate acceptance steps.

Inputs must pin original witness/SHA and archive material, actual local chain and
clock/settlement/wrapper/proxy addresses, code hashes, exact clock registered atMs,
max window/skew and original healthy uint80 uptime round/startedAt with grace.
The derived fixture must record its provenance and a new exact witness SHA.
Changing wrapper/proxy addresses leaves Policy::hash unchanged but changes the
host policy binding/archive identity. Rearchive the original full containers under
that explicit new policy; never relabel old archive refs or mutate Pending/Prepared.
Use the actual registered anchoredAtMs=block.timestamp*1000; do not round
first_ms/last_ms or evidence now_ms. The normal last_ms=2,001,100 can remain
unchanged under the explicit 2-second skew with atMs=2,001,000.

Export all seven DerivedRoots, phase, post consumedDepositCount and baseCommitment;
actual ClockContext/receipt/clockCommitment; policy/full input/body evidence hashes;
and complete native candidate commitment. CandidateOutput itself exports only
commitment/clock_commitment/policy_hash/evidence_hash. Derive roots/phase from a
mutable clone of witness.clock.0 and take the post deposit count from that same
mutated clone. Initialize the real settlement with
that exported prevRoot and wire the explicitly labelled mock prefix vault before
settlement. Register the exact full report containers in order. The
mock inner verifier must accept exactly the new native commitment, then the real
settlement entrypoint must advance to the exact exported post-root and other
exported public fields. Compare clock receipt, full ABI input hash, body evidence
hash and bound native public commitment byte for byte.
Assert the new root, batch counter, batches[id] manifest/ordered/rejected fields
and captured withdrawal publication. Deposit count is an exported post-state
value and a mock prefix-gate input; settlement has no stored post-deposit-count
field. Phase 0 adds no phase word to the seven-root base commitment.

## Acceptance and boundary

Require positive normal and liquidation cases and rejection of mismatched target,
clock timestamp/receipt, report-container input, reordered evidence, public roots,
consumed-deposit count through the mock vault prefix gate, response/vkey and
changed uptime epoch without settlement state mutation. Distinguish mock prefix
or adapter preflight refusals from actual CollateralVault custody acceptance.
The existing MockZkVerifier has no vkey or response DTO binding: those negatives
belong to host adapter preflight unless the harness includes real SP1ZkVerifier
with an explicit mock ISP1Verifier that pins programVKey and publicValues.
Full report-container inputHash is not itself the native public commitment.
The adapter must pin exact full bytes before first registration: a permissive DON
mock can accept a same-body signature sibling initially. Onchain replacement
rejection only establishes immutability after the original registration exists.
The derived witnesses need native execution plus pinned SP1 CPU
execution; unchanged candidate/core/guest source pins are insufficient to call a
new witness executed.

The local host-to-EVM adapter or explicitly opted-in Foundry FFI must use owned
paths, bounded data and a disposable localhost chain/ports; preserve existing
services. A mock proof proves only integration of public values. Approved guest/key
provenance, real SP1 proof and DON verifier, service/transport/deployment identity,
public-chain finality/reorg and actual custody/exit/claim acceptance stay open.

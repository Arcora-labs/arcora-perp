# S6-03 deployment RPC corroboration

The deployment reader now accepts an optional `--witness-rpc` anonymous public URL.
The fixed acceptance is: both endpoint hosts must be distinct; both must report the
configured chain; the witness must have finalized the primary anchor; its historical
header must match the exact primary block number and 32-byte hash. Both endpoints
must return identical contract code and all 15 ABI getter words at that hash using
EIP-1898 `{blockHash, requireCanonical: true}`. Both canonical headers are rechecked
after all reads. The witness may be ahead, but every contract read still uses the
primary anchor. An unavailable, malformed, lagging or disagreeing witness blocks
with a nonzero exit; there is no latest fallback, quorum downgrade or automatic retry.

Single-endpoint use remains an observation and explicitly reports
`rpc_agreement.status = NOT_REQUESTED`. Even `OBSERVED` + `AGREED` means the responses
were collected and agreed; check `configured_bindings_match` and
`vkey_matches_local` separately. Source/bytecode equivalence is still `NOT_PROVEN`.
The gateway runtime remains a single-provider reader. This audit option does not add
runtime quorum, prove independent RPC operators, or satisfy the full funds/reorg
matrix and S6-01 dependencies. **S6-03 remains PARTIAL; release remains HOLD.**

## Fresh public endpoint observation

At **2026-09-28T12:44:39.488583Z**, the configured public
`https://sepolia.base.org` endpoint returned **HTTP 403** on the first `eth_chainId`
request. Exactly one attempt was made. No witness was configured or contacted,
no alternate access path was tried, and no wallet, credential or chain-write method
was used. No current block, contract code, role or vkey equivalence was established.

- [Exact observation](initial-observation-checks/deployment-observation.json)
- [Exact command output](initial-observation-checks/deployment-refresh.log)
- [Source identity at that attempt](initial-observation-checks/verification.json)

This observation predates the final offline robustness fixes below. Its original
source hashes and logs are preserved, rather than relabelled as a final-source live
run. No second public request was made. The copied logs contain only anonymous
public endpoint/configuration data; no environment secrets were read.

## Validation and focused review

[Final verification](verification.json) binds both changed Python files and the
unchanged deployment config to exact SHA-256 hashes. **29 unit tests passed** both
normally and with `python3 -O`; syntax compilation and scoped `git diff --check`
also passed. These are controlled offline JSON-RPC fixtures, not live corroboration.

The review checked:

- JSON-RPC version and exact integer request ID; all RPC error codes fail closed,
  including responses that also contain a result. Error codes are never retried or
  treated as empty deployment state.
- Exact block height/hash, finalized-lag rejection, EIP-1898 code/getter pins,
  conflicting finalized/historical headers and either endpoint changing after reads.
- Full byte comparison of nonempty code; malformed hex and wrong ABI word sizes
  fail closed. Responses are bounded to 1 MiB before JSON parsing/logging/hashing;
  runtime hashes and byte lengths describe observed code, not compiled equivalence.
- Explicit empty/invalid witness arguments cannot disable corroboration. Same-host
  case/path/trailing-dot aliases are rejected. URL userinfo/query/fragment inputs are
  rejected and URL paths are not logged. Saved records retain only validated
  method-bound results or endpoint/method/numeric error-code metadata. Raw provider
  error/debug fields, malformed echoes and external exception text are not retained
  in records, getter errors, blockers or stdout. Different hosts are not proof of
  different operators; DNS/provider/redirect independence is outside this observation.
- Nonzero ABI address padding cannot match a configured address. A matching response
  alone still does not mean the configured contract binding or local vkey matched.

Two concrete existing reader gaps were also covered: a historical header with the
same hash but the wrong height is blocked, and a short required ABI word yields a
non-successful observation. Review found and corrected explicit-empty-witness and
same-host trailing-dot edge cases before final verification.

Independent review then found that a provider could reflect a URL path token through
its error text, or that an invalid URL port could echo the supplied value. Four new
redaction regressions reproduced **nine failing subcases** before the correction
([before evidence](redaction-before.json)); all now pass in both normal and optimized
runs. They inspect the complete saved result and captured stdout, including raw RPC
records, contract getter errors and blocker text. Only a synthetic fixture token was
used. The public endpoint was not queried again.

Only `scripts/local-verification/read_deployment.py`, its existing test file, and
this dedicated evidence directory were changed in this lane. The repository has no
additional local AGENTS instructions for these paths beyond the global instructions.
No root task contract/status files, gateway/frontend code, or original Desktop work
were edited. No commit or merge was performed by this lane.

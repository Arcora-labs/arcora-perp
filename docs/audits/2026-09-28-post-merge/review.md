# Review and execution boundaries

The runtime RPC author independently reviewed RSA/ring, the vendor patch and CI
guard. The archive was compared with the prior registry checksum, not merely the
new provenance map: 29 upstream files and 20 Rust sources match. The alternative
rustcrypto graph still exposes RSA. Ring receives the original message once;
algorithm, modulus/exponent policy and strict TPM envelope checks were inspected.
No blocking defect remained in that review.

Root independently reviewed RPC recovery and found endpoint-to-endpoint chain
agreement did not bind the startup chain. The author corrected it and added unit
and actual-cast rejection of two endpoints agreeing on the same wrong chain.
Hash-pinned reads, finalized/canonical rechecks, read-only transport and error
redaction were inspected and exercised in the loopback matrix.

Root reviewed host helper/main/prove and the actual artifacts. Exactly the same
witness bytes are replayed natively and supplied to the guest. Actual negative
logs show ManifestMismatch/BadSpendKey, exit1 and no public output. All artifact
hashes, commitment and ELF copies were recomputed. Prove uses CPU Groth16, rejects
empty/non-Groth16/divergent payloads and requires SDK verification before success.
It was compiled but not executed. An additional requested subagent review ended
at its usage limit without a result and is not counted as completed review; root
completed the source/evidence review directly.

All 15 original criterion arrays and dependency lists match the original baseline.
Seven original tasks remain open. New ordinary evidence does not close combined
A06, real proof, funds or operations criteria. Current source/ELF/vkey replace
the old release identity; no existing deployment match is inferred. LRU warnings
remain visible and unsuppressed.

## Failed and intermediate attempts

1. Ring-only selection removed active RSA but Cargo retained the weak optional
   lock entry. The published release had the same behavior. A manifest-only
   vendor correction plus rustcrypto counterfactual resolved it without audit
   ignores or manual lock editing.
2. TEE's separate audit revealed crossbeam-epoch/rustls advisories. Compatible
   patch updates, audit and consumer check passed. LRU fixes exceed SP1's
   compatible dependency range and were not silently forced or suppressed.
3. SP1 top-level exact pins allowed newer transitive releases. Cargo aligned the
   complete family with temporary exact constraints, then removed those extra
   direct constraints. An offline guest attempt pinning only mismatched packages
   conflicted; complete-family constraints with available metadata resolved it.
4. The first guest build selected Homebrew rustc with no Succinct target. Correct
   rustup PATH ordering fixed it. A second clean-target build matched byte-for-byte;
   no target/compiler check was disabled.
5. The reused prover target pointed at an old ELF. That test run is excluded from
   new-artifact acceptance. The verified ELF was copied to the actual SP1_ELF
   target and the service recompiled/retested; build/dependency/binary hashes are
   retained in rsa/prover-elf-binding.json.
6. A URL parser test caught an out-of-range port; explicit u16 parsing fixed it.
   Root's separate expected-chain finding was corrected as described above.
7. Git's text-only diff check flags an unchanged upstream README Markdown
   `=======` heading and ASN.1 DER bytes. Those files were excluded from that
   whitespace check while mandatory provenance checking remained; upstream bytes
   were not rewritten to manufacture a passing check.

The previous A06 review refusal was not retried, rephrased or delegated around.
Ordinary witnesses contain no wind-down operation. Desktop state, shared chain
and credentials were preserved. New PR review and publication remain separate
from the explicitly authorized PR23 merge.

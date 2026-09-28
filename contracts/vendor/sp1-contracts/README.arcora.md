# Pinned local SP1 verifier

These eight upstream files are copied byte for byte from the official repositories
and commits in `PROVENANCE.json`. The SP1 v6.1.0 tag resolves to
`2ac5ecbbe473421a963d67e55f182e9a36576f7c`. The gateway's OpenZeppelin dependency
is the upstream repository's locked v5.0.2 submodule,
`dbb6104ce834628e473d2173bbc9d47f81a9eec3`.

All source license headers and OpenZeppelin's LICENSE are preserved. The selected
SP1 commit does not contain a standalone LICENSE; its Solidity files declare MIT
in their SPDX headers. There are no local changes to these upstream files.

The generated Groth16 verifier requires exact Solidity 0.8.20. The local Foundry
project compiles it separately from Arcora's Solidity 0.8.24 contracts; the
integration tests deploy the resulting creation bytecode into a fresh local test
EVM. This does not change Arcora's compiler or deploy a production contract.

The upstream repository's bundled positive fixtures target older verifier
versions, so none are used as v6.1.0 or Arcora proof evidence. See
`../../integration/README.md` for the real artifact gate.

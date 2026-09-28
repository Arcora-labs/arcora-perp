# Ordinary SP1 6.1.0 execution

The actual local CPU executor ran an ordinary synthetic Deposit/Withdraw witness
and two negative witnesses. This is execution evidence, not proof production.

- Witness SHA-256: `0f6f5c96dd9e195f32c63d3c2a72cefe4ef2bdc821fda52485d7fc03c4592dc7`, 956 bytes.
- Native and guest public bytes: `dba12bfa8b5b7c54bd7035e2fdc92615c9b1f653d16b2230f3a5da7a4ff57abd`.
- Positive guest: exit 0, 449,957 cycles.
- Bad manifest: ManifestMismatch, guest exit 1, 115,694 cycles, zero public bytes.
- Unauthorized withdrawal: BadSpendKey, guest exit 1, 156,555 cycles, zero public bytes.
- ELF SHA-256: `82938f5db13d7da2cc48fc18e36ba6a5e6d5f0736154ae9e105b33b8717918d7`.
- Setup-only vkey: `0x00ab0d3f8dbcadb423593ef582e637e864ef538537f43e433a8f1466aaa2dfcf`.

See [artifact manifest](run-6.1.0/manifest.json), [executor log](../checks/normal-guest-parity.log),
[command/source record](../checks/normal-guest-parity.json), [host tests](../checks/normal-host-tests.json)
and [vkey setup](../checks/normal-vkey.log).

Each witness is serialized once, deserialized from those bytes for native replay,
and passed with SP1Stdin.write_vec. Negatives require the expected native error,
actual guest panic exit and empty public output; infrastructure failures cannot
satisfy them. Retained witnesses contain public deterministic test keys, no user
credentials or observed L1 deposits.

Five host unit tests cover the normal commitment, invalid witness reasons, CLI
ambiguity, artifact hashes/no overwrite and empty mock-shaped/divergent proof
payload rejection. The prove main compiled but did not run. It uses CPU Groth16,
compares public bytes with native replay, and calls the SDK verifier before
successful proof output/manifest. Seven roots and consumed deposit count are
emitted. Static/type/unit checks do not establish a real proof or target-contract
acceptance. No A06 input is constructed and the held draft is unchanged.

Root recomputed all five artifact hashes and compared the public bytes and ELF
with the fresh independent build and service consumer. Source→ELF→vkey→witness
is bound in release-manifest.json; the proof segment remains absent. S5-02's
combined normal plus A06 phase 1/2 acceptance stays BLOCKED.

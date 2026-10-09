# Synthetic clock-v2 recursion fixture

This compressed file is the actual final recursive witness produced by SP1 6.1.0
for the public, synthetic `clock-proof` example. It contains no production data,
user credentials, or private user transactions. The example uses public fixture
keys. Decompressed SHA256: `607d17f7b7adad2c8ff7b9a7d564c99027157b3d3e367822e9517e2c402aae94`.

The source guest ELF SHA256 is
`df59a19b310258b4d01d0d5e3cfa31bb7de9ca2f4ea7c2302cf76650c79967c5`;
the public commitment is
`0x4fc574af6cf22bc0aaf7a4d72532aabc2a7db8f2cda8d3872c47cf07b18f139e`.

The isolated CI job completes only the final Groth16 wrapping with a pinned
upstream image and circuit. It is NOT a proof-acceptance assertion by itself.
`finish-clock-wrapper` must verify the result with the real SDK, then
`verify_clock_proof.py` must verify it in the real local EVM target. Do not
substitute this fixture for new-guest execution or full lifecycle validation.

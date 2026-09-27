# Parser negative controls and finite mutation campaign

Four source-level regressions were first executed against unchanged baseline parser functions. `parser-before.log` selected five tests: one disk-resource test passed and four **runtime assertions** failed. The same five tests all passed in `parser-after.log` after the narrow changes.

1. A `DPRECOV1` byte sequence inside an execution record was mistaken for a trailer boundary, rejecting an otherwise valid authenticated V8 payload. Consumption now uses postcard's typed boundary.
2. A recovery extension with incomplete/orphan rows mutated caller-owned nonce fields before reporting an error. Complete row validation now precedes every assignment.
3. An execution extension with an orphan row mutated caller-owned execution metadata before reporting an error. Complete row validation now precedes every assignment.
4. Passing legacy extension absence to a gateway with an already established recovery generation reset it to zero. Genuine legacy deserialization still starts at zero; direct downgrade is now refused.

The complete gateway boot path originally decoded into a private object, so helper atomicity failures were not a demonstrated partially published live gateway. They are reproducible internal API hazards fixed without changing the wire format. The tests contain synthetic accounts only.

`fuzz-manifest.json` records the completed deterministic mutation campaign. The inner target seals each mutated payload using a test fixture key, verifies it with production `snapshot::open`, then calls the production restore path; this is not an authentication bypass. The outer target mutates authenticated envelopes and verifies rejection. The corpus contains malformed synthetic plaintexts and hashes; no actual user snapshot was fuzzed. Accepted random single-byte mutations are allowed only when typed decoding and a stable subsequent restore succeed. Finite samples do not prove all possible inputs safe; no libFuzzer/sanitizer campaign or whole-process RSS guarantee is claimed.

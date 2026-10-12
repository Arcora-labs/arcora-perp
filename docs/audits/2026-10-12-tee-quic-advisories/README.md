# TEE capture QUIC lock advisories — separate local repair

The first PR59 head `c8b05a0805990199aeeb80fc784c8f4f2b546920` failed
`dependency advisories`, run 38289981910 / job 114947462808. The first four
workspace/host/guest/prover locks had zero vulnerabilities; the standalone
TEE capture lock had five `quinn-proto 0.11.15` advisories
(RUSTSEC-2026-0338 through 0342). Its failed raw log and audit JSON are retained.

Lock-only commit `91ba25118105d75abc3d7512cacf32e1b14eb5dc` changes
`scripts/tee-capture/Cargo.lock` to `quinn-proto 0.11.19` and `quinn-udp 0.5.16`.
Stopping at proto 0.11.18 would leave two additional upstream issues open:
[MAX_STREAM_DATA](https://github.com/quinn-rs/quinn/security/advisories/GHSA-53rm-773f-4q8c)
and [Retry token](https://github.com/quinn-rs/quinn/security/advisories/GHSA-wppq-2f6r-wfvm).
The UDP patch covers
[truncated datagram spin](https://github.com/quinn-rs/quinn/security/advisories/GHSA-6pp4-4cxf-xf88).

| Actual local validation | Result |
| --- | --- |
| Locked default TEE capture tool typecheck, Rust 1.99.0 | PASS; 451.940 seconds |
| Root-owned cargo audit, deny unsound, no ignores | PASS; zero vulnerabilities; 57.691 seconds |
| Separate audit already started before task division | PASS; zero vulnerabilities; 55.290 seconds; independent readback only |
| Audit database | Same failed-CI commit `57dcc0f2192e025138907a495c1ac9a7e1e3e123`, 1307 advisories |
| Existing informational warning | One yanked chacha20 warning; retained, no waiver |
| Final capture lock SHA256 | `01cbc51c6253c2c1f6a883e825635197e7942ab55762ee7d3475e4103d36fd6e` |

The lock has 274 -> 259 package records. All 256 common package versions,
checksums and non-edge metadata are unchanged; 245 raw records are identical.
Of 11 raw common-record differences, six only shorten qualified dependency names.
Five resolved edge changes remain: quinn selects the new proto/UDP; wasm edges
move from getrandom 0.3 to 0.4; rustls-platform-verifier and winapi-util select
existing compatible windows-sys 0.52.0 instead of 0.61.2. The explicit delta is
retained. No claim that all other dependency edges remained identical is made.

The original 378-file curl map is still
`8eddb300301a51cb4122c78a658db326013d61bdfcae2ac5ffa6e5844d8ec3b5`;
it excludes the independent TEE capture manifest and lock. Root/prover-service
Cargo files and reviewed/candidate program artifacts remain unchanged.
The default tool was typechecked, while QUIC was audited as a lock inventory
dependency; this is not HTTP/3 integration evidence. No capture.sh or capture
binary ran, and no quote, fresh collateral, TEE/key release, proof or backend
acceptance is claimed. **PRODUCTION RELEASE HOLD.**

The [ledger](artifact-ledger.json) binds 25 exact copied public records; this
README and the ledger itself are explanatory metadata outside that file map.
The next publication head must pass fresh registered CI before normal merge.

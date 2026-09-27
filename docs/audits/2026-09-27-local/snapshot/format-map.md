# Snapshot framing and operational bounds

Base: `098e4952c189f92e4293ed7d49f81222b626e406`. Framing/atomicity negative controls: four actual assertion failures before correction, then all five selected parser/disk tests passed. Historical/property evidence is recorded separately in the manifests.

| Envelope | Authenticated plaintext | Historical behavior |
|---|---|---|
| DPSNAP5 NUL | postcard `(Gw, market dynamics)` | A01 routing absent: preserve consumed prefix and secrets, require explicit permit reconciliation. |
| DPSNAP6 NUL | A01 prefix + postcard `(Gw, market dynamics, DepositState)` | Execution history absent; sealed legacy orders report unavailable history. |
| DPSNAP7 NUL | A05 prefix + complete V6 payload + `DPEXEC2 NUL` + postcard execution rows | Recovery absent in this historical format; migration initializes its previously nonexistent generation at zero. |
| DPSNAP8 NUL | A07 prefix + complete V6 payload + execution extension + `DPRECOV1` + postcard recovery rows | Recovery generation required and preserved; missing/duplicate/orphan rows fail. |

Every envelope has an 8-byte magic, 32-byte nonce, 32-byte tag, then ciphertext. V7/V8 tags additionally bind the version. V5/V6 share the historical tag calculation; the authenticated inner positional prefix is their schema discriminator. Old formats below V5 are refused. This patch does not alter any serialized layout or cryptographic primitive.

The V8 boundary must come from postcard consumption of the typed execution sequence; searching for `DPRECOV1` inside its raw bytes is ambiguous because digests and strings may contain those bytes. The fixed parser consumes precisely one execution extension and requires the recovery marker at the immediately following boundary. The standalone extension restore APIs validate duplicate, missing, orphan, and invalid rows completely before changing caller-owned state. Full gateway restore constructs a private `Gw` and publishes it only after all decoding/validation succeeds.

## Resource policy

The explicit operational cap is **64 MiB of snapshot/journal plaintext**, plus the 72-byte envelope. `open` refuses oversized input before MAC word allocation or decryption; `read_file` checks descriptor size then bounds the actual read to cap plus one byte (including concurrent growth). `boot_restored` separately bounds direct plaintext input. Atomic writes reject oversized bytes before opening a temporary file or touching the durable destination. Existing oversized files are preserved and refused with an offline reconciliation message. This is a deployment capacity policy, not a wire version migration; operators needing larger state must review limits with memory measurements before changing the cap.

Postcard schemas contain nested fixed-depth structures, vectors/maps/strings; they have no recursively nested user-defined schema. Sequence decoding consumes actual input bytes and postcard varint decoding rejects overflow. Recovery and execution row counts are checked against complete account/order inventories before their vector allocation; execution inventory addition uses checked arithmetic. Every decoded row is then validated against the same complete inventory before mutation. The cap bounds bytes, not an exact process-RSS ceiling: in-memory map objects and temporary ciphertext/MAC/decode buffers cost more than the input. Deterministic fuzz evidence is finite and does not prove all inputs safe.

## Safe reconciliation

An unsupported/corrupt/oversized file remains untouched. Keep both snapshot and rollback journal, their hashes, matching enclave seed in secure storage, and the original binary/source identifier. Work only on copies. Recover the correct authenticated backup or replay a separately validated, version-aware offline migration; reconcile native root, L1 prefix and pending withdrawals before resuming. Never delete/reset state or recovery generation to force boot. Unknown legacy execution remains unavailable; unknown A01 permit destinations require explicit authorizer-approved routing, not guessed credit.

An authenticated **older complete snapshot** is not distinguishable from the latest one without an independent trusted monotonic checkpoint. This patch preserves the nonce present in each supported file and prevents a restore helper from overwriting an established larger generation; it does not invent whole-file rollback protection. Backup selection and journal/chain reconciliation remain S6 obligations. The marker reproducer uses a deliberately crafted authenticated payload; it does not establish an unauthenticated remote exploit.

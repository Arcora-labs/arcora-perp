# Frozen v10 snapshot fixture

A public synthetic file written by the current snapshot writer: the `DPSNAP10`
envelope around the v10 gateway payload. Every key is a public test value. The
envelope is sealed under `[0xC3; 32]`, and the withdrawal and recovery
authorizer is the secp256k1 key `[0x51; 32]`. No user state, credentials, chain
data or funds are involved.

| File | Content |
| --- | --- |
| `sealed.bin` | The envelope, as `snapshot::seal` writes it |
| `plain.bin` | The payload `sealed.bin` authenticates to (`Gw::snapshot_plain`) |
| `state.bin` | Postcard of the restored engine state |
| `accounts.bin` | Postcard of the restored accounts |
| `withdrawals.bin` | Postcard of the pending withdrawals |
| `deposits.bin` | Postcard of the deposit ledger |
| `root.txt` | The engine state root |
| `meta.json` | Counts and the keys the tests use |
| `malformed/` | The fixed malformed corpus (see below) |

The state has two accounts and a bound wind-down recipient (`0x77…77`). The
first account has a filled order and a resting order, demo collateral, a routed
L1 deposit credited through the ingestion path, and one permit still
outstanding. The second has demo collateral and a signed pending withdrawal.
Their recovery generations are 3 and 7. Every payload layer is populated: the
header, the wind-down flag, the positional body with the deposit ledger, the
execution extension and the recovery extension.

## Readers

All readers are in `crates/gateway/src/snapshot_s3_tests.rs`:

- `s3_v10_frozen_writer_restores_exactly` opens `sealed.bin` and checks that it
  authenticates to `plain.bin`. The restored state must re-encode to the same
  bytes and match every other file. It then replays the open window natively and
  performs exactly one recovery at the recorded generation.
- `s3_v10_malformed_corpus_is_exact_and_refused` checks that `malformed/`
  equals its derivation from `sealed.bin` and `plain.bin`, with no case missing,
  added or changed. Each case must be refused at its own layer, with the
  expected error.
- `s3_authenticated_parser_mutation_budget` and
  `s3_envelope_mutations_wrong_seed_and_versions_are_rejected` start from this
  file.

## Malformed corpus

`sealed-*` files are envelopes that `snapshot::open` refuses:

- truncations, which fail as too short below 72 bytes;
- each magic byte flipped, and the v5 to v9 magics, refused by magic;
- a trailing byte and a flipped nonce, tag or ciphertext byte, which fail
  authentication.

Every other file is a payload that a genuine writer could seal and that
`Gw::boot_restored` refuses after authentication:

- truncations;
- oversized counts;
- duplicate, unknown and reordered extensions;
- a trailing byte;
- each payload header byte flipped, and an invalid wind-down flag;
- the v6 to v9 headers, a later header, no header, or the rollback journal
  magic in place of the current header.

## Regenerate

A new fixture is a deliberate re-pin. From the repository root, with
`TEE_BACKEND`, `ENCLAVE_SEED` and `ORACLE_SIGNER_KEY` unset:

    ARCORA_SNAPSHOT_V10_EXPORT=<new absolute directory> \
      cargo test -p gateway --bin gateway --locked \
      account_recovery::snapshot_s3_tests::export_v10_snapshot_fixture \
      -- --ignored --exact --nocapture

The export does not reproduce the committed bytes. Account keys, timestamps,
the order-log and note-archive sealing randomness and the envelope nonce are
fresh on every run, so the committed files are the fixture. If you replace them,
update the list below.

The corpus can be recaptured on its own from the committed files:

    S3_CAPTURE_CORPUS=<new absolute directory> \
      cargo test -p gateway --bin gateway --locked \
      s3_authenticated_parser_mutation_budget

It depends only on `sealed.bin` and `plain.bin`, so a recapture reproduces it
byte for byte.

The source was the working tree on top of commit
`8820eb58490788aea2dfac2ef831155a364d2153`.

## SHA-256

    eda94f0a71cfa740e7dec17a59aa3a85d969ba16d33a4a639f11b2bdc698a485  sealed.bin
    1dc262ab51a0746d7cd1a85a25407e4d4b67250be302c37e3f6a90cbe9959624  plain.bin
    89486dcbb3f5d7e8a9b73c6979cbb6e85401bce1f2bc6791ab8012f6a867eeaa  state.bin
    a9f00894795775f71251d7acb4d7b45623b007cd081ff9644575335ff39b828f  accounts.bin
    1d5ae560dfe74f779e31031199bc307c983dac1c89513ee5fc1a28157501bab8  withdrawals.bin
    2f32b3f3a8bafe1fb3da5275b6bc253a4537a76b6a0cf28d367b5f78930a9ea6  deposits.bin
    fc8504d417baafb7cf5e1c8c13844a1e684f31cdc802129f19100311beff0ab5  root.txt
    06ef975ce4ce251f4378f46bf5b974a14247a71d0a9853dee119f0d0b19a137d  meta.json

The corpus is not listed. Its test ties it byte for byte to `sealed.bin` and
`plain.bin`.

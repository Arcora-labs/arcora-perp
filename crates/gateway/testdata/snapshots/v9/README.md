# Frozen v9 refusal fixture

Two genuine `DPSNAP9` files from the v9 writer. They are the public synthetic
paired-recovery pair that commit `27023614509acf5c676433b72f50a46678d76622`
added under `crates/gateway/tests/fixtures/paired-recovery/`:

- `state.snapshot` is a snapshot;
- `state.snapshot.rollback` is its rollback journal, whose sealed body starts
  with `DPRBJL5`.

Both are sealed under the public test key `[0x65; 32]`. Nothing here is user or
production data.

They are kept only as refusal inputs, like `v5` to `v8`:

- `s3_historical_writers_are_refused` checks that `snapshot::open` and
  `rollback_journal::open` refuse both files by their envelope magic.
- `snapshot::tests::frozen_earlier_payloads_are_refused_by_their_headers_too`
  first authenticates and decrypts each file test-side, under its own version.
  It then checks that the snapshot payload is refused by its header and the
  journal body by its magic.

No reader decodes them.

## SHA-256

    a1d0036155f3cd37a2f65f45fe909a57918f2d2087423c0722da525db04ab73e  state.snapshot
    055c42499b46300e23f8ce5cd25d7d890e63d49d507f3d17db9c03622cc5ac18  state.snapshot.rollback

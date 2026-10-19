# Frozen seal-window baseline

The 21 `.bin` files are complete postcard outputs of the two fixed Sequencer
traces in `crates/gateway/src/prover_client/window_ownership_tests.rs`: the
`normal` trace (10 rows) and the `rollback` trace (11 rows). Each file is named
`{case}-{index:02}-{row}.bin`. The `*_seq` rows are serialized `Sequencer`s; the
`*_witness`, `*_legacy` and `*_clocked` rows are the window witness, its legacy
tuple and its clock-bound wire frame.

The ignored `export_seal_window_baseline` test wrote them from the source at
commit `8820eb58490788aea2dfac2ef831155a364d2153`; only the exporter and the test
paths that read this directory were added on top. Inputs are fixed: a seeded
enclave identity, two funded test accounts, deterministic oracle publisher
signatures and fixed timestamps. No gateway boot, wall clock, network, backend,
proof or real funds are involved. The exporter runs each trace twice and refuses
to write unless both runs give the same bytes.

Readers: `window_ownership_tests` compares all 21 files byte for byte;
`cpu_profile_tests` loads `normal-00/01` and `rollback-06/07`;
`finite_profile_tests` (and through it `merkle_reuse_tests`) and
`roots_carry_tests` start from `normal-00`;
`scripts/local-verification/finite_preparation_profile.py` hashes `normal-00`
into its source identity. The earlier baseline under
`docs/audits/2026-10-14-seal-window-ownership/` is historical evidence for its
own change and is no longer read by tests.

## Regenerate

From the repository root:

    ARCORA_SEAL_WINDOW_EXPORT_DIR="$PWD/crates/gateway/testdata/seal-window-pkg3" \
      cargo test -p gateway --bin gateway --locked \
      prover_client::window_ownership_tests::export_seal_window_baseline \
      -- --ignored --exact --nocapture

The directory must be an absolute path. Existing files are overwritten and a
`SEAL_WINDOW_BASELINE` JSON line lists each file's length and SHA-256. Without
the variable nothing is written. A change here is a deliberate re-pin: review
the diff, update the commit above and the list below, then rerun the readers.

## SHA-256

    9261465dd77569800656b740af033d0fde975e94256ba544d0b780a046381cc2  normal-00-before_first_seal_seq.bin
    12549b9aa019f7c5016b61e62f63ac20ab83fe898625a7078efb90bc30957564  normal-01-first_witness.bin
    7c03e5f25b5291de4b54456c3a2d433d40b8d632e62d181d98835bd448e71cf2  normal-02-first_legacy.bin
    76d2e3c47a117d557f119753f0f274c1bb6ad1948c2842496ded0479acf4a7eb  normal-03-first_clocked.bin
    447e8a33a51afac5e13c2014c3110a07a9bfbe713fca47ddeee4c31433d983ce  normal-04-after_first_seal_seq.bin
    9cd78f833746809b317b2e930b75870b9e9da79bc264694348ffa2c9b1c3eaa1  normal-05-live_mutated_seq.bin
    ca22a5a52f9a5b7374d7c318660f4a3715e1877eb03f54fde5d8ac7c32d846bf  normal-06-second_witness.bin
    696c54110168f5ae1135416a7108a83b75342e758a14e0b4d0e01d2c2ce352d7  normal-07-second_legacy.bin
    5ac2bcebf8b3f91786da52305a8a5e515303016622ce7d7c61dae39db6cc841c  normal-08-second_clocked.bin
    c70c8e978da5f39e0bd13b2b707380337a6c2e25b4975d6e0dcb84838226bc38  normal-09-after_second_seal_seq.bin
    9261465dd77569800656b740af033d0fde975e94256ba544d0b780a046381cc2  rollback-00-before_first_seal_seq.bin
    12549b9aa019f7c5016b61e62f63ac20ab83fe898625a7078efb90bc30957564  rollback-01-first_witness.bin
    7c03e5f25b5291de4b54456c3a2d433d40b8d632e62d181d98835bd448e71cf2  rollback-02-first_legacy.bin
    76d2e3c47a117d557f119753f0f274c1bb6ad1948c2842496ded0479acf4a7eb  rollback-03-first_clocked.bin
    447e8a33a51afac5e13c2014c3110a07a9bfbe713fca47ddeee4c31433d983ce  rollback-04-after_first_seal_seq.bin
    0f4fe9d2eb937df2fb70bf483c7077f14b1de1457996817309258cc01636ffc3  rollback-05-intervening_seq.bin
    93ca844d80ba95addc46319b948a810f49a202561bd5765f6dca9f306e73f11d  rollback-06-after_rollback_seq.bin
    895d9080d0527b1538cb221305bb8c3d5644896ad6dccf9a31d85dc4d67f7531  rollback-07-resealed_witness.bin
    03355c330760555525abe1110c6a49748e74ad7d4a81d7c4b879a7c7ce18d997  rollback-08-resealed_legacy.bin
    ce6a64ab47a27400ef4544e264d310aab8d9f45b07f0ce0a8102d51388c1a346  rollback-09-resealed_clocked.bin
    33e87f2719281566898ada5a5e9fade7ca2b5618fa8e6cd21a1fad3ebdf07e29  rollback-10-after_reseal_seq.bin

The `normal` and `rollback` rows 00-04 are identical because both traces share
the first window before they diverge.

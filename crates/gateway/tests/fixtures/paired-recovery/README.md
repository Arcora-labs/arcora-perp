# Public synthetic paired recovery fixture

Generated on ARM64 macOS by the ignored `export_paired_recovery_fixture` test.
Only fresh test accounts and synthetic L1 receipt pages are present. No user
snapshot, real credentials, mainnet/testnet transaction or real funds were read.
The sealing key is deliberately public: `[0x65; 32]` in the test source.

`state.snapshot` contains three consumed test deposits, their receipt ledger,
domain/count/tip/anchor and one signed withdrawal whose first window is in flight.
`state.snapshot.rollback` carries that window's genuine stage-1 rollback witness
and drained withdrawal leaf. One deposit arrived after the window was sealed.
`checkpoint.json` binds the exact files and their synthetic cursor. Neither its
hashes nor its producer fields are a production backup signature or attestation.

The ordinary `public_macos_pair_restores_with_identical_cursor_and_recovery_semantics`
test opens these files with production serializers and checks HOLD, rollback with
persist-before-delete, replay count, roll-forward claim retention and idempotence.
L1 values and the inner proof are explicit test stand-ins. CI's Linux runner tests
portability; it does not relocate or unlock a production gateway.

Both files are DPSNAP10 sealed envelopes; the rollback file carries the
current rollback-journal format. Each export draws a
fresh seal nonce, fresh test account keys and fresh archive randomness, so a
re-export never reproduces these bytes; the committed files are the fixture. The
earlier DPSNAP9 pair is kept as a refusal input in `testdata/snapshots/v9/`.

    27628b3a43f7044fba161e33d09a3e10b7fb0a456944472c8ea2ffdaa5766905  state.snapshot
    2b8cf07e9451738eaa9a2cf4b9a36d92e5fa19916b0a2ad72dcd16e5d5d19700  state.snapshot.rollback
    a176acaea31300978ca29966404b34f488bd44e57e790edf2f81856f1497a786  checkpoint.json

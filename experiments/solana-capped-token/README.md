# solana-capped-token — Capped SPL Token Mint Controller (Experiment)

Native Solana program (no Anchor) that wraps the standard SPL Token program and
enforces a **hard supply cap** on a mint. A config PDA, derived from the mint,
holds mint authority; only the recorded admin can mint (up to the cap) or
permanently revoke minting.

This is a self-contained experiment: it has its own `[workspace]` table and is
not part of the root workspace.

## Architecture

```
user tx (signed by admin)
        │
        ▼
┌─────────────────────────┐         CPI (invoke_signed, PDA seeds)
│ solana-capped-token     │ ──────────────────────────────────────► ┌────────────┐
│  config PDA [b"config", │   spl_token::instruction::mint_to     │ SPL Token  │
│  mint] stores:          │   spl_token::instruction::set_authority│  program   │
│  admin, mint,           │                                        └────────────┘
│  maximum_supply,        │
│  amount_minted, bump    │
└─────────────────────────┘
```

### Instructions (hand-rolled 1-byte tag + LE payload serialization)

- `InitializeConfig { maximum_supply: u64 }` — accounts: `[admin signer, mint,
  config PDA, rent sysvar]`. Validates the mint is owned by `spl_token::ID` and
  that its mint authority equals the config PDA, then writes the config.
  Admin = the initializer signer. Requires the PDA account to be pre-funded,
  rent-exempt, and empty.
- `Mint { amount: u64 }` — accounts: `[admin signer, config PDA, mint,
  destination token account, SPL Token program]`. Checks signer == config.admin,
  mint == config.mint, destination is an SPL token account of that mint, and
  `amount_minted.checked_add(amount) <= maximum_supply`, then CPI `mint_to`
  with the config PDA signer seeds.
- `Revoke` — accounts: `[admin signer, config PDA, mint, SPL Token program]`.
  CPI `set_authority(MintTokens -> None)` signed by the config PDA. After this,
  all mints fail.

### Security properties

- All token accounts and the mint are validated as owned by `spl_token::ID`
  (hardcoded; the CPI target is always `spl_token::ID`, never a passed-in
  program id for the CPI itself — the account is checked against the constant).
- Admin signatures are required and compared to the stored admin pubkey.
- PDA derivation and program ownership of the config account are enforced.
- All arithmetic uses `checked_add`; overflow and cap breaches abort.
- No upgrade authority, no owner backdoor, no way to change admin or cap after
  init; `Revoke` is one-way.

## Trust assumptions

- The config PDA account must be created (pre-funded, rent-exempt, zeroed,
  owned by this program) before `InitializeConfig`; initialization asserts the
  mint authority is already the PDA, so setup order matters and is shown in the
  tests.
- The admin key is a plain signer; if compromised, the attacker can mint up to
  the remaining cap (but not beyond it) and can revoke minting.
- `amount_minted` only tracks amounts minted through this program. If mint
  authority were ever held by another program as well, the on-chain SPL supply
  could diverge from `amount_minted`; in this design the PDA is the sole
  authority, so the two stay in sync.
- The program has no upgrade path in this experiment (it is a native processor
  registered via `program_test.add_program`, not a deployed upgradeable
  binary).

## Out of scope

Token metadata, symbol/name, logos, and liquidity/pool integration are
explicitly out of scope. This program controls only minting and the supply cap.

## Educational disclaimer

This code is an experiment for learning and review. It has not been audited and
must not be used to secure real funds.

## Building and testing

No SBF toolchain is required: tests run natively via `solana-program-test`
with `program_test.add_program(..., processor!(process_instruction))`, which
registers the processor directly.

```sh
cargo fmt
cargo test
cargo clippy --all-targets --all-features -- -D warnings
```

## Pinned dependencies

- `solana-program = 2.3.0` / `solana-sdk = 2.3.1` / `solana-program-test = 2.3.13`
- `spl-token = 6.0.0` (4.x could not resolve against the solana 2.3 dependency
  graph on this toolchain due to a `curve25519-dalek` version conflict; 6.0.0
  keeps the same classic SPL Token instruction/state API)
- `tokio 1.x` (`rt`, `rt-multi-thread`, `macros`)

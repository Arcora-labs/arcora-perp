//! The deployed genesis and its wind-down recipient.
//!
//! A production stack starts from a markets-only genesis: every configured market
//! with its trusted oracle publisher, the wind-down recipient, and nothing else (no
//! deposit, note or position). Its state root is the `GENESIS_ROOT` the L1 settlement
//! is constructed with. The recipient is a word of that root, so it is fixed for the
//! life of a deployment: the final wind-down (`SettleAll`) pays the protocol's
//! remaining reserves (clearing pool, insurance fund and treasury, after every
//! deficit is covered) to it as one phase-1 withdrawal leaf.
//!
//! `--print-genesis-root` computes that root from the oracle publisher address and
//! the recipient alone, so it can run on a machine that holds neither the oracle key
//! nor any other operator secret.
use super::*;
use perp_core::state::{State, TREE_DEPTH};

/// The environment variable that names the wind-down recipient.
pub(crate) const RECIPIENT_VAR: &str = "WIND_DOWN_RECIPIENT";

const USAGE: &str = "[genesis] usage: gateway --print-genesis-root [--oracle-address 0x<40 hex>]";

/// One genesis market: the shared fee schedule, with the market's trusted oracle
/// publisher pinned to `oracle` (ZK-001). Boot and `--print-genesis-root` both build
/// their markets here, so the two cannot drift apart.
pub(crate) fn genesis_market(cfg: &MarketCfg, oracle: [u8; 20]) -> Market {
    let mut market =
        Market::with_fees_treasury(cfg.id, TAKER_FEE_BPS, MAKER_REBATE_BPS, TREASURY_FEE_BPS);
    market.oracle_pubkey = oracle;
    market
}

/// The production genesis state root: a depth-`TREE_DEPTH` tree, every configured
/// market pinned to `oracle`, and `recipient` bound in. This is the root a
/// production boot (`GenesisMode::Production`) starts from.
pub(crate) fn production_genesis_root(oracle: [u8; 20], recipient: [u8; 20]) -> Digest {
    let mut state = State::<Keccak256>::new(TREE_DEPTH);
    for cfg in MARKETS {
        state.add_market(genesis_market(cfg, oracle));
    }
    state.set_wind_down_recipient(recipient);
    state.state_root()
}

/// The raw value of `name`: `None` when unset or empty (an empty value, as in
/// `deploy/env/gateway.env.example`, means unset), `Err` when not valid text.
pub(crate) fn env_value(name: &str) -> Result<Option<String>, String> {
    match std::env::var(name) {
        Ok(value) if value.is_empty() => Ok(None),
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(format!("{name} is not valid text")),
    }
}

/// A configured recipient: `None` when unset; otherwise a nonzero 20-byte address.
/// A set but malformed or zero value is always an error, never "unset".
pub(crate) fn parse_recipient(raw: Option<&str>) -> Result<Option<[u8; 20]>, String> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let address = parse_addr20_hex(raw)
        .ok_or_else(|| format!("{RECIPIENT_VAR} must be a 20-byte hex address (0x + 40 hex)"))?;
    if address == [0; 20] {
        return Err(format!("{RECIPIENT_VAR} must be a nonzero address"));
    }
    Ok(Some(address))
}

/// Whether `address` is one of the default Anvil accounts, whose keys are public.
pub(crate) fn is_public_dev_address(address: &[u8; 20]) -> bool {
    PUBLIC_DEV_ADDRESSES.contains(&hex0x(address).as_str())
}

/// The recipient a boot binds into a fresh genesis, and checks a restored state
/// against. `required` is the production posture with real proofs
/// (`L1_ALLOW_MOCK_PROOF` not set to 1): the recipient must then be set, must not be
/// a public development account, and in every mode it must differ from each operator
/// key in `operators` (role name, address). Unset outside that posture means zero,
/// which only tests and demos use: the wind-down then leaves the reserves in place.
pub(crate) fn boot_recipient(
    raw: Option<&str>,
    required: bool,
    operators: &[(&str, [u8; 20])],
) -> Result<[u8; 20], String> {
    let Some(recipient) = parse_recipient(raw)? else {
        return if required {
            Err(format!(
                "{RECIPIENT_VAR} must be set in production: the cold address the final \
                 wind-down pays the remaining reserves to. It is bound into the genesis \
                 root, so use the value the settlement was deployed with \
                 (gateway --print-genesis-root)"
            ))
        } else {
            Ok([0; 20])
        };
    };
    for (role, address) in operators {
        if recipient == *address {
            return Err(format!(
                "{RECIPIENT_VAR} must differ from the {role} address: the recipient is a \
                 cold address independent of every operator key"
            ));
        }
    }
    if required && is_public_dev_address(&recipient) {
        return Err(format!(
            "{RECIPIENT_VAR} is a default Anvil account, whose key is public"
        ));
    }
    Ok(recipient)
}

/// A restored state keeps the recipient its genesis bound: it is a state-root word
/// and no op changes it. A configured recipient must therefore equal the bound one;
/// an unconfigured one accepts whatever the state holds.
pub(crate) fn check_restored_recipient(
    configured: [u8; 20],
    bound: [u8; 20],
) -> Result<(), String> {
    if configured != [0; 20] && configured != bound {
        return Err(format!(
            "{RECIPIENT_VAR} {} differs from the recipient {} bound in the restored state; \
             the recipient is fixed for the life of a deployment",
            hex0x(&configured),
            hex0x(&bound)
        ));
    }
    Ok(())
}

/// The oracle publisher the genesis pins: the address passed with
/// `--oracle-address`, or the address of `ORACLE_SIGNER_KEY`. Public development
/// keys and addresses are refused either way, since their root would pin a publisher
/// anyone can sign as. With `--oracle-address`, a key that is also configured must
/// sign as that address.
fn genesis_oracle(address: Option<&str>) -> Result<[u8; 20], String> {
    let Some(raw) = address else {
        return match oracle_feed::signer_from_env_checked() {
            Ok((signer, is_default)) if !oracle_signer_is_public(&signer, is_default) => {
                Ok(oracle_feed::signer_address(&signer))
            }
            Ok((_, true)) => Err(
                "set ORACLE_SIGNER_KEY to the operator's oracle publisher key, or pass the \
                 publisher's address with --oracle-address"
                    .into(),
            ),
            Ok((_, false)) => Err(
                "ORACLE_SIGNER_KEY is a public development key (a default Anvil account); \
                 set it to the operator's secret oracle publisher key"
                    .into(),
            ),
            Err(error) => Err(error),
        };
    };
    let oracle = parse_addr20_hex(raw)
        .ok_or("--oracle-address must be a 20-byte hex address (0x + 40 hex)")?;
    if oracle == [0; 20] {
        return Err("--oracle-address must be a nonzero address".into());
    }
    if is_public_dev_address(&oracle) {
        return Err(
            "--oracle-address is a default Anvil account, whose key is public; use the \
             deployment's own oracle publisher address"
                .into(),
        );
    }
    if std::env::var_os("ORACLE_SIGNER_KEY").is_some() {
        let (signer, _) = oracle_feed::signer_from_env_checked()?;
        if oracle_feed::signer_address(&signer) != oracle {
            return Err("ORACLE_SIGNER_KEY does not sign as --oracle-address".into());
        }
    }
    Ok(oracle)
}

/// The recipient `--print-genesis-root` binds: always required, nonzero, not a
/// public development account and distinct from the oracle publisher.
fn genesis_recipient(raw: Option<&str>, oracle: [u8; 20]) -> Result<[u8; 20], String> {
    if raw.is_none() {
        return Err(format!(
            "set {RECIPIENT_VAR} to the deployment's wind-down recipient: a cold address \
             independent of governance, the sequencer, the enclave signer and the gateway \
             signer"
        ));
    }
    boot_recipient(raw, true, &[("oracle signer", oracle)])
}

/// `--print-genesis-root [--oracle-address ADDR]`: print the production genesis root
/// for the configured oracle publisher and `WIND_DOWN_RECIPIENT`, together with both
/// addresses, and exit. Runs before any L1, attestation, prover, listener or
/// state-file access, and reads no key other than an optional `ORACLE_SIGNER_KEY`.
/// Returns the process exit code.
pub(crate) fn print_genesis_root() -> i32 {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let oracle_address = match args.as_slice() {
        [mode] if mode == "--print-genesis-root" => None,
        [mode, flag, address] if mode == "--print-genesis-root" && flag == "--oracle-address" => {
            Some(address.as_str())
        }
        _ => {
            eprintln!("{USAGE}");
            return 2;
        }
    };
    let oracle = match genesis_oracle(oracle_address) {
        Ok(oracle) => oracle,
        Err(error) => {
            eprintln!("[genesis] REFUSING: {error}");
            return 2;
        }
    };
    let recipient =
        match env_value(RECIPIENT_VAR).and_then(|raw| genesis_recipient(raw.as_deref(), oracle)) {
            Ok(recipient) => recipient,
            Err(error) => {
                eprintln!("[genesis] REFUSING: {error}");
                return 2;
            }
        };
    let root = production_genesis_root(oracle, recipient);
    println!("GENESIS_ROOT={}", hex32(&root));
    println!("{RECIPIENT_VAR}={}", hex0x(&recipient));
    println!("ORACLE_SIGNER_ADDRESS={}", hex0x(&oracle));
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    const RECIPIENT: [u8; 20] = [0xC0; 20];

    #[test]
    fn production_boot_starts_from_the_printed_genesis_root() {
        let oracle = oracle_feed::signer_address(&boot_oracle_signer());
        let gw = Gw::boot_genesis(GenesisMode::Production, RECIPIENT);
        assert_eq!(gw.seq.state.wind_down_recipient, RECIPIENT);
        assert_eq!(gw.seq.state.tree.depth(), TREE_DEPTH);
        assert_eq!(
            gw.last_settled_root,
            production_genesis_root(oracle, RECIPIENT)
        );
        assert_eq!(
            gw.seq.window_baseline().state_root(),
            gw.last_settled_root,
            "window 0 opens from the genesis the settlement pins"
        );
    }

    #[test]
    fn the_genesis_root_binds_the_recipient_and_the_oracle_publisher() {
        let oracle = [0x0A; 20];
        let root = production_genesis_root(oracle, RECIPIENT);
        assert_ne!(root, production_genesis_root(oracle, [0xC1; 20]));
        assert_ne!(root, production_genesis_root([0x0B; 20], RECIPIENT));
        assert_ne!(root, production_genesis_root(oracle, [0; 20]));
        assert_eq!(root, production_genesis_root(oracle, RECIPIENT));
    }

    #[test]
    fn a_demo_genesis_binds_the_recipient_before_its_boot_funding() {
        let gw = Gw::boot_genesis(GenesisMode::Demo, RECIPIENT);
        assert_eq!(gw.seq.state.wind_down_recipient, RECIPIENT);
        assert_eq!(gw.seq.window_baseline().wind_down_recipient, RECIPIENT);
        assert_eq!(Gw::boot().seq.state.wind_down_recipient, [0; 20]);
    }

    #[test]
    fn recipient_parsing_is_strict() {
        assert_eq!(parse_recipient(None), Ok(None));
        assert_eq!(
            parse_recipient(Some(&hex0x(&RECIPIENT))),
            Ok(Some(RECIPIENT))
        );
        for bad in [
            "0x",
            "0x1234",
            "zz",
            &hex0x(&[0; 20]),
            &format!("{}00", hex0x(&RECIPIENT)),
        ] {
            assert!(parse_recipient(Some(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn boot_recipient_policy() {
        let operators = [
            ("enclave signer", [0x11; 20]),
            ("gateway signer", [0x22; 20]),
        ];
        // Production with real proofs: required, distinct and not a public account.
        assert!(boot_recipient(None, true, &operators)
            .unwrap_err()
            .contains("must be set"));
        assert_eq!(
            boot_recipient(Some(&hex0x(&RECIPIENT)), true, &operators),
            Ok(RECIPIENT)
        );
        for (role, address) in operators {
            let error = boot_recipient(Some(&hex0x(&address)), true, &operators).unwrap_err();
            assert!(error.contains(role), "{error}");
            // Distinctness holds in every mode.
            assert!(boot_recipient(Some(&hex0x(&address)), false, &operators).is_err());
        }
        let anvil = PUBLIC_DEV_ADDRESSES[0];
        assert!(boot_recipient(Some(anvil), true, &operators)
            .unwrap_err()
            .contains("Anvil"));
        // Outside that posture an unset recipient is zero (tests and demos).
        assert_eq!(boot_recipient(None, false, &operators), Ok([0; 20]));
        assert_eq!(
            boot_recipient(Some(anvil), false, &operators),
            Ok(parse_addr20_hex(anvil).unwrap())
        );
        assert!(boot_recipient(Some(&hex0x(&[0; 20])), false, &operators).is_err());
    }

    #[test]
    fn a_restored_state_keeps_its_bound_recipient() {
        assert!(check_restored_recipient([0; 20], RECIPIENT).is_ok());
        assert!(check_restored_recipient([0; 20], [0; 20]).is_ok());
        assert!(check_restored_recipient(RECIPIENT, RECIPIENT).is_ok());
        assert!(check_restored_recipient(RECIPIENT, [0; 20]).is_err());
        assert!(check_restored_recipient(RECIPIENT, [0xC1; 20]).is_err());
    }

    #[test]
    fn the_printed_recipient_differs_from_the_oracle_publisher() {
        let oracle = [0x0A; 20];
        assert!(genesis_recipient(None, oracle).is_err());
        assert_eq!(
            genesis_recipient(Some(&hex0x(&RECIPIENT)), oracle),
            Ok(RECIPIENT)
        );
        assert!(genesis_recipient(Some(&hex0x(&oracle)), oracle).is_err());
        assert!(genesis_recipient(Some(PUBLIC_DEV_ADDRESSES[3]), oracle).is_err());
    }
}

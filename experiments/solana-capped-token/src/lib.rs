//! Capped SPL token mint controller — experimental native Solana program.
//!
//! A config PDA (seeds `[b"config", mint]`) holds a mint authority over an
//! SPL Token mint and enforces a hard supply cap. Admin (recorded at init)
//! is the only signer allowed to mint or revoke.

use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint::ProgramResult,
    msg,
    program::invoke_signed,
    program_error::ProgramError,
    program_option::COption,
    program_pack::Pack,
    pubkey::Pubkey,
    sysvar::Sysvar,
};

solana_program::declare_id!("CapToK1111111111111111111111111111111111111");

/// Seeds for the config PDA.
pub const CONFIG_SEED: &[u8] = b"config";

/// Serialized config account layout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    pub admin: Pubkey,
    pub mint: Pubkey,
    pub maximum_supply: u64,
    pub amount_minted: u64,
    pub bump: u8,
}

impl Config {
    pub const LEN: usize = 32 + 32 + 8 + 8 + 1;

    pub fn serialize(&self, dst: &mut [u8]) -> Result<(), ProgramError> {
        if dst.len() < Self::LEN {
            return Err(ProgramError::AccountDataTooSmall);
        }
        dst[0..32].copy_from_slice(self.admin.as_ref());
        dst[32..64].copy_from_slice(self.mint.as_ref());
        dst[64..72].copy_from_slice(&self.maximum_supply.to_le_bytes());
        dst[72..80].copy_from_slice(&self.amount_minted.to_le_bytes());
        dst[80] = self.bump;
        Ok(())
    }

    pub fn deserialize(src: &[u8]) -> Result<Self, ProgramError> {
        if src.len() < Self::LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        let admin = Pubkey::try_from(&src[0..32]).map_err(|_| ProgramError::InvalidAccountData)?;
        let mint = Pubkey::try_from(&src[32..64]).map_err(|_| ProgramError::InvalidAccountData)?;
        let maximum_supply = u64::from_le_bytes(src[64..72].try_into().unwrap());
        let amount_minted = u64::from_le_bytes(src[72..80].try_into().unwrap());
        let bump = src[80];
        Ok(Config {
            admin,
            mint,
            maximum_supply,
            amount_minted,
            bump,
        })
    }
}

/// Program instructions (hand-rolled serialization).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CappedTokenInstruction {
    /// Initialize the config PDA. Accounts: [signer admin, mint (SPL), config PDA, rent sysvar].
    InitializeConfig { maximum_supply: u64 },
    /// Mint tokens up to the cap. Accounts: [signer admin, config PDA, mint, destination token account, SPL Token program].
    Mint { amount: u64 },
    /// Permanently revoke mint authority. Accounts: [signer admin, config PDA, mint, SPL Token program].
    Revoke,
}

pub const TAG_INIT: u8 = 0;
pub const TAG_MINT: u8 = 1;
pub const TAG_REVOKE: u8 = 2;

pub fn serialize_initialize(maximum_supply: u64) -> Vec<u8> {
    let mut out = vec![TAG_INIT];
    out.extend_from_slice(&maximum_supply.to_le_bytes());
    out
}

pub fn serialize_mint(amount: u64) -> Vec<u8> {
    let mut out = vec![TAG_MINT];
    out.extend_from_slice(&amount.to_le_bytes());
    out
}

pub fn serialize_revoke() -> Vec<u8> {
    vec![TAG_REVOKE]
}

pub fn deserialize_instruction(data: &[u8]) -> Result<CappedTokenInstruction, ProgramError> {
    let (&tag, rest) = data
        .split_first()
        .ok_or(ProgramError::InvalidInstructionData)?;
    match tag {
        TAG_INIT => {
            let bytes: [u8; 8] = rest
                .try_into()
                .map_err(|_| ProgramError::InvalidInstructionData)?;
            Ok(CappedTokenInstruction::InitializeConfig {
                maximum_supply: u64::from_le_bytes(bytes),
            })
        }
        TAG_MINT => {
            let bytes: [u8; 8] = rest
                .try_into()
                .map_err(|_| ProgramError::InvalidInstructionData)?;
            Ok(CappedTokenInstruction::Mint {
                amount: u64::from_le_bytes(bytes),
            })
        }
        TAG_REVOKE if rest.is_empty() => Ok(CappedTokenInstruction::Revoke),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

/// Derive the config PDA for a mint.
pub fn derive_config_pda(mint: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[CONFIG_SEED, mint.as_ref()], &id())
}

fn signer_seeds<'a>(mint: &'a Pubkey, bump: &'a [u8; 1]) -> [&'a [u8]; 3] {
    [CONFIG_SEED, mint.as_ref(), bump]
}

/// Load and validate an SPL Token mint account: owned by spl_token, parsed.
fn load_token_mint(account: &AccountInfo) -> Result<spl_token::state::Mint, ProgramError> {
    if account.owner != &spl_token::ID {
        return Err(ProgramError::IllegalOwner);
    }
    spl_token::state::Mint::unpack(&account.data.borrow())
        .map_err(|_| ProgramError::InvalidAccountData)
}

/// Load and validate an SPL Token account whose mint matches `expected_mint`.
fn load_token_account(
    account: &AccountInfo,
    expected_mint: &Pubkey,
) -> Result<spl_token::state::Account, ProgramError> {
    if account.owner != &spl_token::ID {
        return Err(ProgramError::IllegalOwner);
    }
    let token_account = spl_token::state::Account::unpack(&account.data.borrow())
        .map_err(|_| ProgramError::InvalidAccountData)?;
    if &token_account.mint != expected_mint {
        msg!("Token account mint mismatch");
        return Err(ProgramError::InvalidArgument);
    }
    Ok(token_account)
}

fn process_initialize_config(accounts: &[AccountInfo], maximum_supply: u64) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let admin = next_account_info(account_info_iter)?;
    let mint_account = next_account_info(account_info_iter)?;
    let config_account = next_account_info(account_info_iter)?;
    let rent_sysvar = next_account_info(account_info_iter)?;

    if !admin.is_signer {
        msg!("Admin must sign");
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Validate the mint account before initializing.
    let mint = load_token_mint(mint_account)?;

    // Config PDA must match derivation and be owned by this program.
    let (config_pda, bump) = derive_config_pda(mint_account.key);
    if config_account.key != &config_pda {
        msg!("Config account is not the derived PDA");
        return Err(ProgramError::InvalidSeeds);
    }
    if config_account.owner != &id() {
        msg!("Config account not owned by this program");
        return Err(ProgramError::IllegalOwner);
    }

    // The config PDA must already be the mint authority.
    match mint.mint_authority {
        COption::Some(authority) if authority == config_pda => {}
        _ => {
            msg!("Mint authority must be the config PDA");
            return Err(ProgramError::InvalidArgument);
        }
    }

    let rent = solana_program::rent::Rent::from_account_info(rent_sysvar)?;
    if !rent.is_exempt(config_account.lamports(), Config::LEN) {
        msg!("Config account not rent exempt");
        return Err(ProgramError::AccountNotRentExempt);
    }

    if config_account.data_len() < Config::LEN
        || config_account.data.borrow()[..Config::LEN]
            .iter()
            .any(|&b| b != 0)
    {
        msg!("Config account not empty");
        return Err(ProgramError::AccountAlreadyInitialized);
    }

    let config = Config {
        admin: *admin.key,
        mint: *mint_account.key,
        maximum_supply,
        amount_minted: 0,
        bump,
    };
    config.serialize(&mut config_account.data.borrow_mut())?;
    msg!("Initialized config: cap {}", maximum_supply);
    Ok(())
}

fn process_mint(accounts: &[AccountInfo], amount: u64) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let admin = next_account_info(account_info_iter)?;
    let config_account = next_account_info(account_info_iter)?;
    let mint_account = next_account_info(account_info_iter)?;
    let destination_account = next_account_info(account_info_iter)?;
    let token_program = next_account_info(account_info_iter)?;

    if token_program.key != &spl_token::ID {
        msg!("Invalid token program");
        return Err(ProgramError::IncorrectProgramId);
    }

    if !admin.is_signer {
        msg!("Admin must sign");
        return Err(ProgramError::MissingRequiredSignature);
    }

    if config_account.owner != &id() {
        msg!("Config not owned by this program");
        return Err(ProgramError::IllegalOwner);
    }
    let mut config = Config::deserialize(&config_account.data.borrow())?;
    if &config.admin != admin.key {
        msg!("Signer is not the admin");
        return Err(ProgramError::Custom(1));
    }

    // Mint account must match config and be a valid SPL mint.
    if mint_account.key != &config.mint {
        msg!("Mint does not match config");
        return Err(ProgramError::InvalidArgument);
    }
    load_token_mint(mint_account)?;

    // Destination token account must belong to this mint.
    load_token_account(destination_account, mint_account.key)?;

    // Enforce the cap with checked arithmetic.
    let new_total = config
        .amount_minted
        .checked_add(amount)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    if new_total > config.maximum_supply {
        msg!("Supply cap exceeded");
        return Err(ProgramError::Custom(2));
    }

    let bump = [config.bump];
    let seeds = signer_seeds(&config.mint, &bump);
    invoke_signed(
        &spl_token::instruction::mint_to(
            &spl_token::ID,
            mint_account.key,
            destination_account.key,
            config_account.key,
            &[],
            amount,
        )?,
        &[
            mint_account.clone(),
            destination_account.clone(),
            config_account.clone(),
        ],
        &[&seeds],
    )?;

    config.amount_minted = new_total;
    config.serialize(&mut config_account.data.borrow_mut())?;
    Ok(())
}

fn process_revoke(accounts: &[AccountInfo]) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let admin = next_account_info(account_info_iter)?;
    let config_account = next_account_info(account_info_iter)?;
    let mint_account = next_account_info(account_info_iter)?;
    let token_program = next_account_info(account_info_iter)?;

    if token_program.key != &spl_token::ID {
        msg!("Invalid token program");
        return Err(ProgramError::IncorrectProgramId);
    }

    if !admin.is_signer {
        msg!("Admin must sign");
        return Err(ProgramError::MissingRequiredSignature);
    }

    if config_account.owner != &id() {
        msg!("Config not owned by this program");
        return Err(ProgramError::IllegalOwner);
    }
    let config = Config::deserialize(&config_account.data.borrow())?;
    if &config.admin != admin.key {
        msg!("Signer is not the admin");
        return Err(ProgramError::Custom(1));
    }

    if mint_account.key != &config.mint {
        msg!("Mint does not match config");
        return Err(ProgramError::InvalidArgument);
    }
    load_token_mint(mint_account)?;

    let bump = [config.bump];
    let seeds = signer_seeds(&config.mint, &bump);
    invoke_signed(
        &spl_token::instruction::set_authority(
            &spl_token::ID,
            mint_account.key,
            None,
            spl_token::instruction::AuthorityType::MintTokens,
            config_account.key,
            &[],
        )?,
        &[mint_account.clone(), config_account.clone()],
        &[&seeds],
    )?;

    msg!("Mint authority revoked");
    Ok(())
}

pub fn process_instruction(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    match deserialize_instruction(instruction_data)? {
        CappedTokenInstruction::InitializeConfig { maximum_supply } => {
            process_initialize_config(accounts, maximum_supply)
        }
        CappedTokenInstruction::Mint { amount } => process_mint(accounts, amount),
        CappedTokenInstruction::Revoke => process_revoke(accounts),
    }
}

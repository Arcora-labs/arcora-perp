//! Integration tests for the capped SPL token mint controller using
//! solana-program-test with a native processor (no SBF build required).

use solana_capped_token::{
    derive_config_pda, serialize_initialize, serialize_mint, serialize_revoke, Config,
};
use solana_program::program_pack::Pack;
use solana_program::pubkey::Pubkey;
use solana_program_test::{processor, BanksClient, ProgramTest};
use solana_sdk::{
    account::Account,
    signature::{Keypair, Signer},
    transaction::Transaction,
};

struct Env {
    banks_client: BanksClient,
    payer: Keypair,
    admin: Keypair,
    mint: Pubkey,
    config_pda: Pubkey,
    destination: Pubkey,
}

async fn setup(cap: u64) -> Env {
    let mut pt = ProgramTest::new(
        "solana_capped_token",
        solana_capped_token::id(),
        processor!(solana_capped_token::process_instruction),
    );
    // SPL Token program must exist on-chain for CPIs to land.
    pt.add_program(
        "spl_token",
        spl_token::ID,
        processor!(spl_token::processor::Processor::process),
    );

    let admin = Keypair::new();
    let mint = Keypair::new();
    let (config_pda, _bump) = derive_config_pda(&mint.pubkey());

    let rent = solana_sdk::rent::Rent::default();
    pt.add_account(
        config_pda,
        Account {
            lamports: rent.minimum_balance(Config::LEN),
            owner: solana_capped_token::id(),
            data: vec![0u8; Config::LEN],
            executable: false,
            rent_epoch: 0,
        },
    );
    pt.add_account(
        admin.pubkey(),
        Account {
            lamports: 10_000_000_000,
            ..Account::default()
        },
    );

    let (banks_client, payer, recent_blockhash) = pt.start().await;

    // Create the SPL mint with mint_authority = config PDA.
    let create_mint_ix = solana_sdk::system_instruction::create_account(
        &payer.pubkey(),
        &mint.pubkey(),
        rent.minimum_balance(spl_token::state::Mint::LEN),
        spl_token::state::Mint::LEN as u64,
        &spl_token::ID,
    );
    let init_mint_ix = spl_token::instruction::initialize_mint(
        &spl_token::ID,
        &mint.pubkey(),
        &config_pda,
        None,
        6,
    )
    .unwrap();
    let mut tx =
        Transaction::new_with_payer(&[create_mint_ix, init_mint_ix], Some(&payer.pubkey()));
    tx.sign(&[&payer, &mint], recent_blockhash);
    banks_client.process_transaction(tx).await.unwrap();

    // Destination token account owned by admin.
    let destination = Keypair::new();
    let create_dst_ix = solana_sdk::system_instruction::create_account(
        &payer.pubkey(),
        &destination.pubkey(),
        rent.minimum_balance(spl_token::state::Account::LEN),
        spl_token::state::Account::LEN as u64,
        &spl_token::ID,
    );
    let init_dst_ix = spl_token::instruction::initialize_account(
        &spl_token::ID,
        &destination.pubkey(),
        &mint.pubkey(),
        &admin.pubkey(),
    )
    .unwrap();
    let recent_blockhash = banks_client.get_latest_blockhash().await.unwrap();
    let mut tx = Transaction::new_with_payer(&[create_dst_ix, init_dst_ix], Some(&payer.pubkey()));
    tx.sign(&[&payer, &destination], recent_blockhash);
    banks_client.process_transaction(tx).await.unwrap();

    let env = Env {
        banks_client,
        payer,
        admin,
        mint: mint.pubkey(),
        config_pda,
        destination: destination.pubkey(),
    };
    initialize(&env, cap).await;
    env
}

async fn initialize(env: &Env, cap: u64) {
    let ix = solana_program::instruction::Instruction {
        program_id: solana_capped_token::id(),
        accounts: vec![
            solana_program::instruction::AccountMeta::new_readonly(env.admin.pubkey(), true),
            solana_program::instruction::AccountMeta::new_readonly(env.mint, false),
            solana_program::instruction::AccountMeta::new(env.config_pda, false),
            solana_program::instruction::AccountMeta::new_readonly(
                solana_program::sysvar::rent::ID,
                false,
            ),
        ],
        data: serialize_initialize(cap),
    };
    let recent_blockhash = env.banks_client.get_latest_blockhash().await.unwrap();
    let mut tx = Transaction::new_with_payer(&[ix], Some(&env.payer.pubkey()));
    tx.sign(&[&env.payer, &env.admin], recent_blockhash);
    env.banks_client.process_transaction(tx).await.unwrap();
}

fn mint_ix(
    env: &Env,
    signer: &Pubkey,
    destination: &Pubkey,
    amount: u64,
) -> solana_program::instruction::Instruction {
    solana_program::instruction::Instruction {
        program_id: solana_capped_token::id(),
        accounts: vec![
            solana_program::instruction::AccountMeta::new_readonly(*signer, true),
            solana_program::instruction::AccountMeta::new(env.config_pda, false),
            solana_program::instruction::AccountMeta::new(env.mint, false),
            solana_program::instruction::AccountMeta::new(*destination, false),
            solana_program::instruction::AccountMeta::new_readonly(spl_token::ID, false),
        ],
        data: serialize_mint(amount),
    }
}

fn revoke_ix(env: &Env, signer: &Pubkey) -> solana_program::instruction::Instruction {
    solana_program::instruction::Instruction {
        program_id: solana_capped_token::id(),
        accounts: vec![
            solana_program::instruction::AccountMeta::new_readonly(*signer, true),
            solana_program::instruction::AccountMeta::new(env.config_pda, false),
            solana_program::instruction::AccountMeta::new(env.mint, false),
            solana_program::instruction::AccountMeta::new_readonly(spl_token::ID, false),
        ],
        data: serialize_revoke(),
    }
}

async fn fetch_config(env: &Env) -> Config {
    let account = env
        .banks_client
        .get_account(env.config_pda)
        .await
        .unwrap()
        .unwrap();
    Config::deserialize(&account.data).unwrap()
}

async fn token_balance(env: &Env) -> u64 {
    let account = env
        .banks_client
        .get_account(env.destination)
        .await
        .unwrap()
        .unwrap();
    spl_token::state::Account::unpack(&account.data)
        .unwrap()
        .amount
}

async fn send(env: &Env, ixs: &[solana_program::instruction::Instruction], signers: &[&Keypair]) {
    let recent_blockhash = env.banks_client.get_latest_blockhash().await.unwrap();
    let mut tx = Transaction::new_with_payer(ixs, Some(&env.payer.pubkey()));
    let mut all = vec![&env.payer];
    all.extend_from_slice(signers);
    tx.sign(&all, recent_blockhash);
    env.banks_client.process_transaction(tx).await.unwrap();
}

#[tokio::test]
async fn initialize_config_success() {
    let env = setup(1_000_000).await;
    let config = fetch_config(&env).await;
    assert_eq!(config.admin, env.admin.pubkey());
    assert_eq!(config.mint, env.mint);
    assert_eq!(config.maximum_supply, 1_000_000);
    assert_eq!(config.amount_minted, 0);
    assert_eq!(config.bump, derive_config_pda(&env.mint).1);
}

#[tokio::test]
async fn authorized_mint_increments_amount_minted() {
    let env = setup(1_000_000).await;
    send(
        &env,
        &[mint_ix(
            &env,
            &env.admin.pubkey(),
            &env.destination,
            400_000,
        )],
        &[&env.admin],
    )
    .await;
    assert_eq!(token_balance(&env).await, 400_000);
    assert_eq!(fetch_config(&env).await.amount_minted, 400_000);

    send(
        &env,
        &[mint_ix(
            &env,
            &env.admin.pubkey(),
            &env.destination,
            100_000,
        )],
        &[&env.admin],
    )
    .await;
    assert_eq!(token_balance(&env).await, 500_000);
    assert_eq!(fetch_config(&env).await.amount_minted, 500_000);
}

#[tokio::test]
async fn unauthorized_signer_cannot_mint() {
    let env = setup(1_000_000).await;
    let attacker = Keypair::new();
    let recent_blockhash = env.banks_client.get_latest_blockhash().await.unwrap();
    let mut tx = Transaction::new_with_payer(
        &[mint_ix(&env, &attacker.pubkey(), &env.destination, 1)],
        Some(&env.payer.pubkey()),
    );
    // Attacker signs as "admin"; payer pays fees.
    tx.sign(&[&env.payer, &attacker], recent_blockhash);
    let err = env.banks_client.process_transaction(tx).await.unwrap_err();
    assert!(
        err.to_string().contains("custom program error"),
        "unexpected: {err}"
    );
    assert_eq!(token_balance(&env).await, 0);
}

#[tokio::test]
async fn mint_exactly_to_cap_ok() {
    let env = setup(1_000_000).await;
    send(
        &env,
        &[mint_ix(
            &env,
            &env.admin.pubkey(),
            &env.destination,
            1_000_000,
        )],
        &[&env.admin],
    )
    .await;
    assert_eq!(token_balance(&env).await, 1_000_000);
    assert_eq!(fetch_config(&env).await.amount_minted, 1_000_000);
}

#[tokio::test]
async fn mint_above_cap_fails() {
    let env = setup(1_000_000).await;
    let recent_blockhash = env.banks_client.get_latest_blockhash().await.unwrap();
    let mut tx = Transaction::new_with_payer(
        &[mint_ix(
            &env,
            &env.admin.pubkey(),
            &env.destination,
            1_000_001,
        )],
        Some(&env.payer.pubkey()),
    );
    tx.sign(&[&env.payer, &env.admin], recent_blockhash);
    assert!(env.banks_client.process_transaction(tx).await.is_err());
    assert_eq!(token_balance(&env).await, 0);
}

#[tokio::test]
async fn cumulative_mint_cannot_exceed_cap() {
    let env = setup(100).await;
    send(
        &env,
        &[mint_ix(&env, &env.admin.pubkey(), &env.destination, 60)],
        &[&env.admin],
    )
    .await;
    let recent_blockhash = env.banks_client.get_latest_blockhash().await.unwrap();
    let mut tx = Transaction::new_with_payer(
        &[mint_ix(&env, &env.admin.pubkey(), &env.destination, 41)],
        Some(&env.payer.pubkey()),
    );
    tx.sign(&[&env.payer, &env.admin], recent_blockhash);
    assert!(env.banks_client.process_transaction(tx).await.is_err());
    assert_eq!(token_balance(&env).await, 60);
    assert_eq!(fetch_config(&env).await.amount_minted, 60);
}

#[tokio::test]
async fn overflow_amount_rejected() {
    let env = setup(u64::MAX).await;
    // amount that overflows u64 when added to amount_minted=0 is impossible,
    // so mint MAX first (exactly at cap), then minting 1 more must fail both
    // cap and overflow paths.
    send(
        &env,
        &[mint_ix(
            &env,
            &env.admin.pubkey(),
            &env.destination,
            u64::MAX,
        )],
        &[&env.admin],
    )
    .await;
    assert_eq!(token_balance(&env).await, u64::MAX);
    let recent_blockhash = env.banks_client.get_latest_blockhash().await.unwrap();
    let mut tx = Transaction::new_with_payer(
        &[mint_ix(&env, &env.admin.pubkey(), &env.destination, 1)],
        Some(&env.payer.pubkey()),
    );
    tx.sign(&[&env.payer, &env.admin], recent_blockhash);
    assert!(env.banks_client.process_transaction(tx).await.is_err());
}

#[tokio::test]
async fn wrong_mint_fails() {
    let env = setup(1_000_000).await;
    let other_mint = Pubkey::new_unique();
    let mut ix = mint_ix(&env, &env.admin.pubkey(), &env.destination, 10);
    // Corrupt the mint account to point at a mint that does not match config.
    ix.accounts[2] = solana_program::instruction::AccountMeta::new(other_mint, false);
    let recent_blockhash = env.banks_client.get_latest_blockhash().await.unwrap();
    let mut tx = Transaction::new_with_payer(&[ix], Some(&env.payer.pubkey()));
    tx.sign(&[&env.payer, &env.admin], recent_blockhash);
    assert!(env.banks_client.process_transaction(tx).await.is_err());
}

#[tokio::test]
async fn wrong_destination_mint_fails() {
    let env = setup(1_000_000).await;
    // Pass a non-SPL-token account (the admin's system-owned account) as the
    // destination: the SPL Token owner check must reject it.
    let mut ix = mint_ix(&env, &env.admin.pubkey(), &env.admin.pubkey(), 10);
    ix.accounts[3] = solana_program::instruction::AccountMeta::new(env.admin.pubkey(), false);
    let recent_blockhash = env.banks_client.get_latest_blockhash().await.unwrap();
    let mut tx = Transaction::new_with_payer(&[ix], Some(&env.payer.pubkey()));
    tx.sign(&[&env.payer, &env.admin], recent_blockhash);
    assert!(env.banks_client.process_transaction(tx).await.is_err());
}

#[tokio::test]
async fn revoke_succeeds_for_admin() {
    let env = setup(1_000_000).await;
    send(&env, &[revoke_ix(&env, &env.admin.pubkey())], &[&env.admin]).await;
    // Mint authority is now None.
    let mint_acct = env
        .banks_client
        .get_account(env.mint)
        .await
        .unwrap()
        .unwrap();
    let mint = spl_token::state::Mint::unpack(&mint_acct.data).unwrap();
    assert_eq!(
        mint.mint_authority,
        solana_program::program_option::COption::None
    );
}

#[tokio::test]
async fn mint_after_revoke_fails() {
    let env = setup(1_000_000).await;
    send(&env, &[revoke_ix(&env, &env.admin.pubkey())], &[&env.admin]).await;
    let recent_blockhash = env.banks_client.get_latest_blockhash().await.unwrap();
    let mut tx = Transaction::new_with_payer(
        &[mint_ix(&env, &env.admin.pubkey(), &env.destination, 10)],
        Some(&env.payer.pubkey()),
    );
    tx.sign(&[&env.payer, &env.admin], recent_blockhash);
    assert!(env.banks_client.process_transaction(tx).await.is_err());
    assert_eq!(token_balance(&env).await, 0);
}

#[tokio::test]
async fn non_admin_cannot_revoke() {
    let env = setup(1_000_000).await;
    let attacker = Keypair::new();
    let recent_blockhash = env.banks_client.get_latest_blockhash().await.unwrap();
    let mut tx = Transaction::new_with_payer(
        &[revoke_ix(&env, &attacker.pubkey())],
        Some(&env.payer.pubkey()),
    );
    tx.sign(&[&env.payer, &attacker], recent_blockhash);
    assert!(env.banks_client.process_transaction(tx).await.is_err());
    // Authority still held by config PDA.
    let mint_acct = env
        .banks_client
        .get_account(env.mint)
        .await
        .unwrap()
        .unwrap();
    let mint = spl_token::state::Mint::unpack(&mint_acct.data).unwrap();
    assert_eq!(
        mint.mint_authority,
        solana_program::program_option::COption::Some(env.config_pda)
    );
}

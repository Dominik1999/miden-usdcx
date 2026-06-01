use std::sync::Arc;

use miden_protocol::assembly::DefaultSourceManager;
use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::note::NoteType;
use miden_protocol::transaction::RawOutputNote;
use miden_protocol::{Felt, Word};
use miden_standards::code_builder::CodeBuilder;
use miden_protocol::crypto::rand::RandomCoin;
use miden_testing::MockChain;
use usdcx_faucet::burn_note::UsdcxBurnNote;
use usdcx_faucet::deposit_intent::{bytes32_to_felts, felts_to_bytes32};

use crate::helpers::*;

// HELPERS
// ================================================================================================

/// Creates a tx script that mints fungible tokens via mint_and_send.
fn create_mint_tx_script_code(
    faucet_id_prefix: Felt,
    faucet_id_suffix: Felt,
    amount: u64,
    tag: u32,
    note_type: NoteType,
    recipient: Word,
) -> String {
    format!(
        r#"
        begin
            push.{recipient}
            push.{note_type}
            push.{tag}
            push.{amount}
            push.{faucet_id_prefix}
            push.{faucet_id_suffix}
            push.1
            exec.::miden::protocol::asset::create_fungible_asset
            call.::miden::standards::faucets::fungible::mint_and_send
            dropw dropw dropw dropw
        end
        "#,
        recipient = recipient,
        note_type = note_type as u8,
        tag = tag,
        amount = amount,
        faucet_id_prefix = faucet_id_prefix,
        faucet_id_suffix = faucet_id_suffix,
    )
}

/// Default destination domain for tests (Ethereum = 0).
const TEST_DESTINATION_DOMAIN: u32 = 0;

/// Default destination recipient for tests (a mock Ethereum address padded to 32 bytes).
const TEST_DESTINATION_RECIPIENT: [u8; 32] = [
    0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
];

/// Creates a USDCx burn note with destination data in storage.
fn create_burn_note(
    sender: miden_protocol::account::AccountId,
    faucet_id: miden_protocol::account::AccountId,
    amount: u64,
    rng_seed: u64,
) -> anyhow::Result<miden_protocol::note::Note> {
    let asset = Asset::Fungible(FungibleAsset::new(faucet_id, amount)?);
    let seed_word = Word::new([
        Felt::new_unchecked(rng_seed),
        Felt::new_unchecked(rng_seed + 1),
        Felt::new_unchecked(rng_seed + 2),
        Felt::new_unchecked(rng_seed + 3),
    ]);
    let mut rng = RandomCoin::new(seed_word);
    let note = UsdcxBurnNote::create(
        sender,
        faucet_id,
        asset,
        TEST_DESTINATION_DOMAIN,
        &TEST_DESTINATION_RECIPIENT,
        &mut rng,
    )?;
    Ok(note)
}

/// Performs a mint transaction, committing it to the chain.
async fn mint_tokens(
    mock_chain: &mut MockChain,
    faucet: &miden_protocol::account::Account,
    attester_sk: &miden_protocol::account::auth::AuthSecretKey,
    amount: u64,
    nonce: Word,
) -> anyhow::Result<()> {
    let recipient = Word::from([10u32, 20, 30, 40]);
    let intent = test_deposit_intent(faucet.id(), amount, 0, nonce);
    let advice = attestation_advice(attester_sk, &intent, 0);

    let source_manager = Arc::new(DefaultSourceManager::default());
    let tx_script_code = create_mint_tx_script_code(
        faucet.id().prefix().as_felt(),
        faucet.id().suffix(),
        amount,
        0,
        NoteType::Private,
        recipient,
    );
    let tx_script = CodeBuilder::with_source_manager(source_manager.clone())
        .compile_tx_script(tx_script_code)?;

    let tx_context = mock_chain
        .build_tx_context(faucet.id(), &[], &[])?
        .tx_script(tx_script)
        .with_source_manager(source_manager)
        .extend_advice_inputs(advice)
        .build()?;

    let executed = tx_context.execute().await?;
    mock_chain.add_pending_executed_transaction(&executed)?;
    mock_chain.prove_next_block()?;

    Ok(())
}

// TESTS
// ================================================================================================

/// Verifies that burning tokens above the minimum burn size succeeds.
///
/// Flow: mint tokens via attestation, create a burn note with the minted asset,
/// have the faucet consume it via receive_and_burn.
#[tokio::test]
async fn burn_above_min_succeeds() -> anyhow::Result<()> {
    let attester_sk = make_attester_keypair(42);
    let pk_comm = attester_pk_comm(&attester_sk);

    let owner_id = test_owner_id();
    let faucet = create_test_usdcx_faucet_existing_with_attesters(owner_id, vec![pk_comm])?;

    // Create the burn note upfront (before building the chain)
    let burn_amount: u64 = 5_000;
    let burn_note = create_burn_note(owner_id, faucet.id(), burn_amount, 600)?;

    let mut builder = MockChain::builder();
    builder.add_account(faucet.clone())?;
    builder.add_output_note(RawOutputNote::Full(burn_note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    // Step 1: Mint tokens to create supply (must happen before burn)
    let mint_amount: u64 = 100_000;
    let nonce = Word::new([
        Felt::new_unchecked(1),
        Felt::new_unchecked(2),
        Felt::new_unchecked(3),
        Felt::new_unchecked(4),
    ]);
    mint_tokens(&mut mock_chain, &faucet, &attester_sk, mint_amount, nonce).await?;

    // Step 2: Faucet consumes the burn note
    let sm = test_source_manager();
    let burn_tx = mock_chain
        .build_tx_context(faucet.id(), &[burn_note.id()], &[])?
        .with_source_manager(sm)
        .build()?;
    let burn_executed = burn_tx.execute().await?;

    mock_chain.add_pending_executed_transaction(&burn_executed)?;
    mock_chain.prove_next_block()?;

    Ok(())
}

/// Verifies that burning tokens below the minimum burn size fails.
#[tokio::test]
async fn burn_below_min_fails() -> anyhow::Result<()> {
    let attester_sk = make_attester_keypair(42);
    let pk_comm = attester_pk_comm(&attester_sk);

    let owner_id = test_owner_id();
    let faucet = create_test_usdcx_faucet_existing_with_attesters(owner_id, vec![pk_comm])?;

    // Create the burn note upfront with amount < min_burn_size (1000)
    let burn_amount: u64 = 500;
    let burn_note = create_burn_note(owner_id, faucet.id(), burn_amount, 601)?;

    let mut builder = MockChain::builder();
    builder.add_account(faucet.clone())?;
    builder.add_output_note(RawOutputNote::Full(burn_note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    // Mint tokens to create supply
    let mint_amount: u64 = 100_000;
    let nonce = Word::new([
        Felt::new_unchecked(1),
        Felt::new_unchecked(2),
        Felt::new_unchecked(3),
        Felt::new_unchecked(4),
    ]);
    mint_tokens(&mut mock_chain, &faucet, &attester_sk, mint_amount, nonce).await?;

    // Attempt burn - should fail
    let sm = test_source_manager();
    let burn_tx = mock_chain
        .build_tx_context(faucet.id(), &[burn_note.id()], &[])?
        .with_source_manager(sm)
        .build()?;
    let result = burn_tx.execute().await;

    assert!(result.is_err(), "expected burn to fail for amount below min_burn_size");
    let err_str = format!("{}", result.unwrap_err());
    assert!(
        err_str.contains("burn") || err_str.contains("assertion failed") || err_str.contains("min"),
        "expected burn-size-related error, got: {err_str}"
    );

    Ok(())
}

/// Verifies that updating the minimum burn size is enforced on subsequent burns.
///
/// Flow:
/// 1. Set min_burn_size to 5000
/// 2. Burn 3000 should fail
/// 3. Set min_burn_size to 2000
/// 4. Burn 3000 should succeed
#[tokio::test]
async fn burn_min_size_update_enforced() -> anyhow::Result<()> {
    let attester_sk = make_attester_keypair(42);
    let pk_comm = attester_pk_comm(&attester_sk);

    let owner_id = test_owner_id();
    let faucet = create_test_usdcx_faucet_existing_with_attesters(owner_id, vec![pk_comm])?;

    // Pre-create all notes we'll need
    let source_manager = test_source_manager();
    let mut rng1 = test_rng(700);
    let set_min_5000_note = create_set_min_burn_size_note(
        owner_id, 5_000, &mut rng1, Arc::clone(&source_manager),
    )?;

    let burn_3000_fail_note = create_burn_note(owner_id, faucet.id(), 3_000, 701)?;

    let mut rng3 = test_rng(702);
    let set_min_2000_note = create_set_min_burn_size_note(
        owner_id, 2_000, &mut rng3, Arc::clone(&source_manager),
    )?;

    let burn_3000_ok_note = create_burn_note(owner_id, faucet.id(), 3_000, 703)?;

    let mut builder = MockChain::builder();
    builder.add_account(faucet.clone())?;
    builder.add_output_note(RawOutputNote::Full(set_min_5000_note.clone()));
    builder.add_output_note(RawOutputNote::Full(burn_3000_fail_note.clone()));
    builder.add_output_note(RawOutputNote::Full(set_min_2000_note.clone()));
    builder.add_output_note(RawOutputNote::Full(burn_3000_ok_note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    // Step 1: Mint tokens to create supply
    let nonce = Word::new([
        Felt::new_unchecked(1),
        Felt::new_unchecked(2),
        Felt::new_unchecked(3),
        Felt::new_unchecked(4),
    ]);
    mint_tokens(&mut mock_chain, &faucet, &attester_sk, 100_000, nonce).await?;

    // Step 2: Set min_burn_size to 5000
    let sm2 = test_source_manager();
    let set_min_tx = mock_chain
        .build_tx_context(faucet.id(), &[set_min_5000_note.id()], &[])?
        .with_source_manager(Arc::clone(&sm2))
        .build()?;
    let set_min_executed = set_min_tx.execute().await?;
    mock_chain.add_pending_executed_transaction(&set_min_executed)?;
    mock_chain.prove_next_block()?;

    // Step 3: Burn 3000 should fail (below new min of 5000)
    let sm3 = test_source_manager();
    let burn_tx_fail = mock_chain
        .build_tx_context(faucet.id(), &[burn_3000_fail_note.id()], &[])?
        .with_source_manager(sm3)
        .build()?;
    let result = burn_tx_fail.execute().await;
    assert!(result.is_err(), "burn of 3000 should fail with min_burn_size=5000");

    // Step 4: Set min_burn_size to 2000
    let sm4 = test_source_manager();
    let set_min_tx2 = mock_chain
        .build_tx_context(faucet.id(), &[set_min_2000_note.id()], &[])?
        .with_source_manager(Arc::clone(&sm4))
        .build()?;
    let set_min_executed2 = set_min_tx2.execute().await?;
    mock_chain.add_pending_executed_transaction(&set_min_executed2)?;
    mock_chain.prove_next_block()?;

    // Step 5: Burn 3000 should now succeed (above new min of 2000)
    let sm5 = test_source_manager();
    let burn_tx_ok = mock_chain
        .build_tx_context(faucet.id(), &[burn_3000_ok_note.id()], &[])?
        .with_source_manager(sm5)
        .build()?;
    let burn_executed = burn_tx_ok.execute().await?;
    mock_chain.add_pending_executed_transaction(&burn_executed)?;
    mock_chain.prove_next_block()?;

    Ok(())
}

/// Verifies that burning is rejected when the faucet is paused.
#[tokio::test]
async fn burn_while_paused_fails() -> anyhow::Result<()> {
    let attester_sk = make_attester_keypair(42);
    let pk_comm = attester_pk_comm(&attester_sk);

    let owner_id = test_owner_id();
    let faucet = create_test_usdcx_faucet_existing_with_attesters(owner_id, vec![pk_comm])?;

    // Pre-create all notes
    let source_manager = test_source_manager();
    let mut rng = test_rng(800);
    let pause_note = create_pause_note(owner_id, &mut rng, Arc::clone(&source_manager))?;

    let burn_note = create_burn_note(owner_id, faucet.id(), 5_000, 801)?;

    let mut builder = MockChain::builder();
    builder.add_account(faucet.clone())?;
    builder.add_output_note(RawOutputNote::Full(pause_note.clone()));
    builder.add_output_note(RawOutputNote::Full(burn_note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    // Step 1: Mint tokens to create supply
    let nonce = Word::new([
        Felt::new_unchecked(1),
        Felt::new_unchecked(2),
        Felt::new_unchecked(3),
        Felt::new_unchecked(4),
    ]);
    mint_tokens(&mut mock_chain, &faucet, &attester_sk, 100_000, nonce).await?;

    // Step 2: Pause the faucet
    let sm2 = test_source_manager();
    let pause_tx = mock_chain
        .build_tx_context(faucet.id(), &[pause_note.id()], &[])?
        .with_source_manager(sm2)
        .build()?;
    let pause_executed = pause_tx.execute().await?;
    mock_chain.add_pending_executed_transaction(&pause_executed)?;
    mock_chain.prove_next_block()?;

    // Step 3: Attempt burn while paused
    let sm3 = test_source_manager();
    let burn_tx = mock_chain
        .build_tx_context(faucet.id(), &[burn_note.id()], &[])?
        .with_source_manager(sm3)
        .build()?;
    let result = burn_tx.execute().await;

    assert!(result.is_err(), "expected burn to fail when faucet is paused");
    let err_str = format!("{}", result.unwrap_err());
    assert!(
        err_str.contains("paused") || err_str.contains("assertion failed"),
        "expected pause-related error, got: {err_str}"
    );

    Ok(())
}

// USDCX BURN NOTE STORAGE TESTS
// ================================================================================================

/// Verifies that UsdcxBurnNote stores destination_domain and destination_recipient
/// in the note's public storage, and the values can be read back correctly.
#[tokio::test]
async fn burn_note_contains_destination_storage() -> anyhow::Result<()> {
    let owner_id = test_owner_id();
    let faucet = create_test_usdcx_faucet_existing(owner_id)?;
    let faucet_id = faucet.id();

    let amount: u64 = 10_000;
    let destination_domain: u32 = 0; // Ethereum
    let destination_recipient: [u8; 32] = [
        0x74, 0x2d, 0x35, 0xCc, 0x66, 0x34, 0xC0, 0x53,
        0x29, 0x25, 0xa3, 0xb8, 0x44, 0xBc, 0x9e, 0x75,
        0x95, 0xf2, 0xbD, 0x1e, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    let asset = Asset::Fungible(FungibleAsset::new(faucet_id, amount)?);
    let seed = Word::new([
        Felt::new_unchecked(900),
        Felt::new_unchecked(901),
        Felt::new_unchecked(902),
        Felt::new_unchecked(903),
    ]);
    let mut rng = RandomCoin::new(seed);

    let note = UsdcxBurnNote::create(
        owner_id,
        faucet_id,
        asset,
        destination_domain,
        &destination_recipient,
        &mut rng,
    )?;

    // Verify note is public
    assert_eq!(note.metadata().note_type(), NoteType::Public);

    // Verify storage has 9 items
    let storage = note.recipient().storage();
    assert_eq!(usize::from(storage.num_items()), UsdcxBurnNote::NUM_STORAGE_ITEMS);

    // Verify destination_domain (first felt)
    let stored_domain = storage.items()[0].as_canonical_u64() as u32;
    assert_eq!(stored_domain, destination_domain);

    // Verify destination_recipient (felts 1-8)
    let stored_recipient_felts: [Felt; 8] = storage.items()[1..9].try_into().unwrap();
    let stored_recipient = felts_to_bytes32(&stored_recipient_felts);
    assert_eq!(stored_recipient, destination_recipient);

    Ok(())
}

/// Verifies that burn notes with different destination domains are distinct.
#[tokio::test]
async fn burn_note_different_destinations() -> anyhow::Result<()> {
    let owner_id = test_owner_id();
    let faucet = create_test_usdcx_faucet_existing(owner_id)?;
    let faucet_id = faucet.id();

    let amount: u64 = 5_000;
    let recipient = [0xABu8; 32];

    let asset_eth = Asset::Fungible(FungibleAsset::new(faucet_id, amount)?);
    let asset_arb = Asset::Fungible(FungibleAsset::new(faucet_id, amount)?);

    let seed1 = Word::new([Felt::new_unchecked(1000), Felt::new_unchecked(1001), Felt::new_unchecked(1002), Felt::new_unchecked(1003)]);
    let seed2 = Word::new([Felt::new_unchecked(2000), Felt::new_unchecked(2001), Felt::new_unchecked(2002), Felt::new_unchecked(2003)]);

    let note_ethereum = UsdcxBurnNote::create(owner_id, faucet_id, asset_eth, 0, &recipient, &mut RandomCoin::new(seed1))?;
    let note_arbitrum = UsdcxBurnNote::create(owner_id, faucet_id, asset_arb, 3, &recipient, &mut RandomCoin::new(seed2))?;

    // Different domain IDs in storage
    let eth_domain = note_ethereum.recipient().storage().items()[0].as_canonical_u64() as u32;
    let arb_domain = note_arbitrum.recipient().storage().items()[0].as_canonical_u64() as u32;
    assert_eq!(eth_domain, 0);
    assert_eq!(arb_domain, 3);

    // Same recipient in both
    let eth_recipient_felts: [Felt; 8] = note_ethereum.recipient().storage().items()[1..9].try_into().unwrap();
    let arb_recipient_felts: [Felt; 8] = note_arbitrum.recipient().storage().items()[1..9].try_into().unwrap();
    assert_eq!(felts_to_bytes32(&eth_recipient_felts), recipient);
    assert_eq!(felts_to_bytes32(&arb_recipient_felts), recipient);

    Ok(())
}

/// Verifies that a burn note with real destination data can be consumed by the faucet.
#[tokio::test]
async fn burn_with_destination_storage_succeeds() -> anyhow::Result<()> {
    let attester_sk = make_attester_keypair(42);
    let pk_comm = attester_pk_comm(&attester_sk);
    let owner_id = test_owner_id();
    let faucet = create_test_usdcx_faucet_existing_with_attesters(owner_id, vec![pk_comm])?;

    // Create burn note with specific destination
    let destination_domain: u32 = 0;
    let destination_recipient: [u8; 32] = [
        0x74, 0x2d, 0x35, 0xCc, 0x66, 0x34, 0xC0, 0x53,
        0x29, 0x25, 0xa3, 0xb8, 0x44, 0xBc, 0x9e, 0x75,
        0x95, 0xf2, 0xbD, 0x1e, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let burn_amount: u64 = 5_000;
    let asset = Asset::Fungible(FungibleAsset::new(faucet.id(), burn_amount)?);
    let seed = Word::new([Felt::new_unchecked(800), Felt::new_unchecked(801), Felt::new_unchecked(802), Felt::new_unchecked(803)]);
    let burn_note = UsdcxBurnNote::create(
        owner_id, faucet.id(), asset, destination_domain, &destination_recipient, &mut RandomCoin::new(seed),
    )?;

    let mut builder = MockChain::builder();
    builder.add_account(faucet.clone())?;
    builder.add_output_note(RawOutputNote::Full(burn_note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    // Step 1: Mint tokens to create supply
    let nonce = Word::new([Felt::new_unchecked(50), Felt::new_unchecked(51), Felt::new_unchecked(52), Felt::new_unchecked(53)]);
    mint_tokens(&mut mock_chain, &faucet, &attester_sk, 100_000, nonce).await?;

    // Step 2: Burn with destination-bearing note
    let sm = test_source_manager();
    let burn_tx = mock_chain
        .build_tx_context(faucet.id(), &[burn_note.id()], &[])?
        .with_source_manager(sm)
        .build()?;
    let executed = burn_tx.execute().await?;

    // Burn succeeded
    mock_chain.add_pending_executed_transaction(&executed)?;
    mock_chain.prove_next_block()?;

    Ok(())
}

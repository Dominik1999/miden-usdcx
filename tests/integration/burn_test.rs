use std::sync::Arc;

use miden_protocol::assembly::DefaultSourceManager;
use miden_protocol::asset::{Asset, FungibleAsset};
use miden_protocol::note::{NoteAttachments, NoteType};
use miden_protocol::transaction::RawOutputNote;
use miden_protocol::{Felt, Word};
use miden_standards::code_builder::CodeBuilder;
use miden_protocol::crypto::rand::RandomCoin;
use miden_standards::note::BurnNote;
use miden_testing::MockChain;

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

/// Creates a burn note using the standard BurnNote from miden-standards.
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
    let note = BurnNote::create(
        sender,
        faucet_id,
        asset,
        NoteAttachments::default(),
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

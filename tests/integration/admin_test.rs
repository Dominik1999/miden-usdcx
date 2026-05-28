use std::sync::Arc;

use miden_protocol::transaction::RawOutputNote;
use miden_protocol::{Felt, ZERO, Word};
use miden_testing::MockChain;
use usdcx_faucet::attester_registry::ATTESTER_ACTIVE;

use crate::helpers::*;

/// Verifies that the faucet owner can add a new attester to the registry.
#[tokio::test]
async fn owner_can_add_attester() -> anyhow::Result<()> {
    let owner_id = test_owner_id();
    let faucet = create_test_usdcx_faucet_existing(owner_id)?;
    let new_attester = mock_attester_pk_comm(1);

    let mut builder = MockChain::builder();
    builder.add_account(faucet.clone())?;

    let source_manager = test_source_manager();
    let mut rng = test_rng(100);
    let note = create_add_attester_note(owner_id, new_attester, &mut rng, Arc::clone(&source_manager))?;

    builder.add_output_note(RawOutputNote::Full(note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let tx = mock_chain
        .build_tx_context(faucet.id(), &[note.id()], &[])?
        .with_source_manager(source_manager)
        .build()?;
    let executed = tx.execute().await?;

    // Apply delta and verify the new attester is in storage
    let mut updated = faucet.clone();
    updated.apply_delta(executed.account_delta())?;

    let status = read_attester_status(&updated, new_attester)?;
    assert_eq!(status, ATTESTER_ACTIVE, "new attester should be active");

    Ok(())
}

/// Verifies that the faucet owner can remove an attester from the registry.
#[tokio::test]
async fn owner_can_remove_attester() -> anyhow::Result<()> {
    let owner_id = test_owner_id();
    let faucet = create_test_usdcx_faucet_existing(owner_id)?;
    let initial_attester = mock_attester_pk_comm(0);

    let mut builder = MockChain::builder();
    builder.add_account(faucet.clone())?;

    let source_manager = test_source_manager();
    let mut rng = test_rng(200);
    let note = create_remove_attester_note(owner_id, initial_attester, &mut rng, Arc::clone(&source_manager))?;

    builder.add_output_note(RawOutputNote::Full(note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let tx = mock_chain
        .build_tx_context(faucet.id(), &[note.id()], &[])?
        .with_source_manager(source_manager)
        .build()?;
    let executed = tx.execute().await?;

    // Apply delta and verify the attester is removed (zero word)
    let mut updated = faucet.clone();
    updated.apply_delta(executed.account_delta())?;

    let status = read_attester_status(&updated, initial_attester)?;
    let zero_word = Word::new([ZERO, ZERO, ZERO, ZERO]);
    assert_eq!(status, zero_word, "removed attester should have zero value");

    Ok(())
}

/// Verifies that a non-owner cannot add an attester (assert_sender_is_owner fails).
#[tokio::test]
async fn non_owner_cannot_add_attester() -> anyhow::Result<()> {
    use miden_protocol::testing::account_id::AccountIdBuilder;

    let owner_id = test_owner_id();
    let non_owner = AccountIdBuilder::new().build_with_seed([99; 32]);
    let faucet = create_test_usdcx_faucet_existing(owner_id)?;
    let new_attester = mock_attester_pk_comm(5);

    let mut builder = MockChain::builder();
    builder.add_account(faucet.clone())?;

    let source_manager = test_source_manager();
    let mut rng = test_rng(300);
    // Send the note from non_owner - should fail the owner check
    let note = create_add_attester_note(non_owner, new_attester, &mut rng, Arc::clone(&source_manager))?;

    builder.add_output_note(RawOutputNote::Full(note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let tx = mock_chain
        .build_tx_context(faucet.id(), &[note.id()], &[])?
        .with_source_manager(source_manager)
        .build()?;
    let result = tx.execute().await;

    // The transaction should fail because the note sender is not the owner.
    // The error manifests as a FailedAssertion from assert_sender_is_owner.
    assert!(result.is_err(), "expected transaction to fail for non-owner");
    let err_str = format!("{}", result.unwrap_err());
    assert!(
        err_str.contains("assertion failed"),
        "expected assertion failure error, got: {err_str}"
    );

    Ok(())
}

/// Verifies that the owner can update the minimum burn size.
#[tokio::test]
async fn owner_can_set_min_burn_size() -> anyhow::Result<()> {
    let owner_id = test_owner_id();
    let faucet = create_test_usdcx_faucet_existing(owner_id)?;
    let new_min_burn_size = 5_000u64;

    let mut builder = MockChain::builder();
    builder.add_account(faucet.clone())?;

    let source_manager = test_source_manager();
    let mut rng = test_rng(400);
    let note = create_set_min_burn_size_note(owner_id, new_min_burn_size, &mut rng, Arc::clone(&source_manager))?;

    builder.add_output_note(RawOutputNote::Full(note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let tx = mock_chain
        .build_tx_context(faucet.id(), &[note.id()], &[])?
        .with_source_manager(source_manager)
        .build()?;
    let executed = tx.execute().await?;

    // Apply delta and verify
    let mut updated = faucet.clone();
    updated.apply_delta(executed.account_delta())?;

    let config = read_domain_config(&updated)?;
    assert_eq!(config.min_burn_size, new_min_burn_size);
    // domain_id should be unchanged
    assert_eq!(config.domain_id, TEST_DOMAIN_ID);

    Ok(())
}

/// Verifies the full two-step ownership transfer flow:
/// 1. Alice (current owner) nominates Bob via `transfer_ownership`
/// 2. Bob accepts via `accept_ownership`
/// 3. Bob is now the owner (can perform admin operations)
/// 4. Alice is no longer the owner (admin operations fail)
#[tokio::test]
async fn ownership_transfer_two_step() -> anyhow::Result<()> {
    use miden_protocol::testing::account_id::AccountIdBuilder;

    let alice_id = test_owner_id(); // current owner
    let bob_id = AccountIdBuilder::new().build_with_seed([42; 32]);
    let faucet = create_test_usdcx_faucet_existing(alice_id)?;

    // Pre-create all notes
    let source_manager = test_source_manager();
    let mut rng1 = test_rng(2000);
    let transfer_note = create_transfer_ownership_note(
        alice_id,
        bob_id,
        &mut rng1,
        Arc::clone(&source_manager),
    )?;

    let mut rng2 = test_rng(2001);
    let accept_note = create_accept_ownership_note(
        bob_id,
        &mut rng2,
        Arc::clone(&source_manager),
    )?;

    // Create a note from Bob to add an attester (proving Bob is the new owner)
    let new_attester = mock_attester_pk_comm(5);
    let mut rng3 = test_rng(2002);
    let bob_admin_note = create_add_attester_note(
        bob_id,
        new_attester,
        &mut rng3,
        Arc::clone(&source_manager),
    )?;

    // Create a note from Alice to add an attester (should fail after transfer)
    let another_attester = mock_attester_pk_comm(6);
    let mut rng4 = test_rng(2003);
    let alice_admin_note = create_add_attester_note(
        alice_id,
        another_attester,
        &mut rng4,
        Arc::clone(&source_manager),
    )?;

    let mut builder = MockChain::builder();
    builder.add_account(faucet.clone())?;
    builder.add_output_note(RawOutputNote::Full(transfer_note.clone()));
    builder.add_output_note(RawOutputNote::Full(accept_note.clone()));
    builder.add_output_note(RawOutputNote::Full(bob_admin_note.clone()));
    builder.add_output_note(RawOutputNote::Full(alice_admin_note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    // Step 1: Alice nominates Bob
    let sm1 = test_source_manager();
    let transfer_tx = mock_chain
        .build_tx_context(faucet.id(), &[transfer_note.id()], &[])?
        .with_source_manager(sm1)
        .build()?;
    let transfer_executed = transfer_tx.execute().await?;
    mock_chain.add_pending_executed_transaction(&transfer_executed)?;
    mock_chain.prove_next_block()?;

    // Step 2: Bob accepts ownership
    let sm2 = test_source_manager();
    let accept_tx = mock_chain
        .build_tx_context(faucet.id(), &[accept_note.id()], &[])?
        .with_source_manager(sm2)
        .build()?;
    let accept_executed = accept_tx.execute().await?;
    mock_chain.add_pending_executed_transaction(&accept_executed)?;
    mock_chain.prove_next_block()?;

    // Step 3: Bob can perform admin operations (add attester)
    let sm3 = test_source_manager();
    let bob_tx = mock_chain
        .build_tx_context(faucet.id(), &[bob_admin_note.id()], &[])?
        .with_source_manager(sm3)
        .build()?;
    let bob_executed = bob_tx.execute().await?;
    mock_chain.add_pending_executed_transaction(&bob_executed)?;
    mock_chain.prove_next_block()?;

    // Step 4: Alice can no longer perform admin operations
    let sm4 = test_source_manager();
    let alice_tx = mock_chain
        .build_tx_context(faucet.id(), &[alice_admin_note.id()], &[])?
        .with_source_manager(sm4)
        .build()?;
    let result = alice_tx.execute().await;
    assert!(result.is_err(), "Alice should no longer be owner after transfer");
    let err_str = format!("{}", result.unwrap_err());
    assert!(
        err_str.contains("assertion failed"),
        "expected assertion failure for non-owner, got: {err_str}"
    );

    Ok(())
}

/// Verifies the full pause/unpause cycle:
/// 1. Pause the faucet - mint should fail
/// 2. Unpause the faucet - mint should succeed again
#[tokio::test]
async fn pause_unpause_cycle() -> anyhow::Result<()> {
    use miden_protocol::assembly::DefaultSourceManager;
    use miden_protocol::note::NoteType;
    use miden_standards::code_builder::CodeBuilder;

    let attester_sk = make_attester_keypair(42);
    let pk_comm = attester_pk_comm(&attester_sk);

    let owner_id = test_owner_id();
    let faucet = create_test_usdcx_faucet_existing_with_attesters(owner_id, vec![pk_comm])?;

    // Pre-create all notes before building the chain
    let source_manager = test_source_manager();
    let mut rng = test_rng(900);
    let pause_note = create_pause_note(owner_id, &mut rng, Arc::clone(&source_manager))?;

    let mut rng2 = test_rng(901);
    let unpause_note = create_unpause_note(owner_id, &mut rng2, Arc::clone(&source_manager))?;

    let mut builder = MockChain::builder();
    builder.add_account(faucet.clone())?;
    builder.add_output_note(RawOutputNote::Full(pause_note.clone()));
    builder.add_output_note(RawOutputNote::Full(unpause_note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    // Helper to attempt a mint transaction (returns true if successful)
    async fn try_mint(
        mock_chain: &MockChain,
        faucet: &miden_protocol::account::Account,
        attester_sk: &miden_protocol::account::auth::AuthSecretKey,
        nonce_seed: u64,
    ) -> anyhow::Result<bool> {
        let amount: u64 = 100_000;
        let recipient = Word::from([10u32, 20, 30, 40]);
        let nonce = Word::new([
            Felt::new_unchecked(nonce_seed),
            Felt::new_unchecked(nonce_seed + 1),
            Felt::new_unchecked(nonce_seed + 2),
            Felt::new_unchecked(nonce_seed + 3),
        ]);

        let advice = attestation_advice(attester_sk, nonce, amount, TEST_DOMAIN_ID);
        let source_manager = Arc::new(DefaultSourceManager::default());
        let tx_script_code = format!(
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
            note_type = NoteType::Private as u8,
            tag = 0,
            amount = amount,
            faucet_id_prefix = faucet.id().prefix().as_felt(),
            faucet_id_suffix = faucet.id().suffix(),
        );
        let tx_script = CodeBuilder::with_source_manager(source_manager.clone())
            .compile_tx_script(tx_script_code)?;

        let tx_context = mock_chain
            .build_tx_context(faucet.id(), &[], &[])?
            .tx_script(tx_script)
            .with_source_manager(source_manager)
            .extend_advice_inputs(advice)
            .build()?;

        match tx_context.execute().await {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    // Step 1: Pause the faucet
    let sm1 = test_source_manager();
    let pause_tx = mock_chain
        .build_tx_context(faucet.id(), &[pause_note.id()], &[])?
        .with_source_manager(sm1)
        .build()?;
    let pause_executed = pause_tx.execute().await?;
    mock_chain.add_pending_executed_transaction(&pause_executed)?;
    mock_chain.prove_next_block()?;

    // Step 2: Verify mint fails while paused
    let mint_result = try_mint(&mock_chain, &faucet, &attester_sk, 100).await?;
    assert!(!mint_result, "mint should fail while faucet is paused");

    // Step 3: Unpause the faucet
    let sm2 = test_source_manager();
    let unpause_tx = mock_chain
        .build_tx_context(faucet.id(), &[unpause_note.id()], &[])?
        .with_source_manager(sm2)
        .build()?;
    let unpause_executed = unpause_tx.execute().await?;
    mock_chain.add_pending_executed_transaction(&unpause_executed)?;
    mock_chain.prove_next_block()?;

    // Step 4: Verify mint succeeds after unpause
    let mint_result = try_mint(&mock_chain, &faucet, &attester_sk, 200).await?;
    assert!(mint_result, "mint should succeed after faucet is unpaused");

    Ok(())
}

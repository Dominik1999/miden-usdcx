use std::sync::Arc;

use miden_protocol::transaction::RawOutputNote;
use miden_protocol::{ZERO, Word};
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

#[tokio::test]
#[ignore = "requires full Ownable2Step integration with ownership transfer notes"]
async fn ownership_transfer_two_step() -> anyhow::Result<()> {
    todo!("Implement two-step ownership transfer test")
}

#[tokio::test]
#[ignore = "requires PausableManager integration with pause/unpause notes"]
async fn pause_unpause_cycle() -> anyhow::Result<()> {
    todo!("Implement pause/unpause cycle test")
}

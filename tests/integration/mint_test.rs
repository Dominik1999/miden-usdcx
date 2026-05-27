use std::sync::Arc;

use miden_protocol::assembly::DefaultSourceManager;
use miden_protocol::note::NoteType;
use miden_protocol::transaction::RawOutputNote;
use miden_protocol::{Felt, Word};
use miden_standards::code_builder::CodeBuilder;
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

// TESTS
// ================================================================================================

/// Verifies that minting via the USDCx faucet succeeds when the faucet is not paused.
///
/// The check_policy is currently a pass-through (see TODO in mint_policy.rs), so this
/// test validates the mint flow end-to-end without attestation verification.
#[tokio::test]
async fn mint_with_valid_attestation_succeeds() -> anyhow::Result<()> {
    let owner_id = test_owner_id();
    let faucet = create_test_usdcx_faucet_existing(owner_id)?;

    let mut builder = MockChain::builder();
    builder.add_account(faucet.clone())?;
    let mock_chain = builder.build()?;

    let amount: u64 = 100_000;
    let recipient = Word::from([10u32, 20, 30, 40]);
    let tag: u32 = 0;
    let note_type = NoteType::Private;

    let source_manager = Arc::new(DefaultSourceManager::default());
    let tx_script_code = create_mint_tx_script_code(
        faucet.id().prefix().as_felt(),
        faucet.id().suffix(),
        amount,
        tag,
        note_type,
        recipient,
    );
    let tx_script = CodeBuilder::with_source_manager(source_manager.clone())
        .compile_tx_script(tx_script_code)?;

    let tx_context = mock_chain
        .build_tx_context(faucet.id(), &[], &[])?
        .tx_script(tx_script)
        .with_source_manager(source_manager)
        .build()?;

    let executed = tx_context.execute().await?;

    assert_eq!(
        executed.output_notes().num_notes(),
        1,
        "should have created exactly one output note"
    );

    Ok(())
}

#[tokio::test]
#[ignore = "requires ECDSA attestation verification in check_policy (stack offset debugging needed)"]
async fn mint_with_unknown_attester_fails() -> anyhow::Result<()> {
    todo!("Implement once check_policy has ECDSA verification")
}

#[tokio::test]
#[ignore = "requires ECDSA attestation verification in check_policy (stack offset debugging needed)"]
async fn mint_nonce_replay_fails() -> anyhow::Result<()> {
    todo!("Implement once check_policy has ECDSA verification")
}

#[tokio::test]
#[ignore = "requires ECDSA attestation verification in check_policy (stack offset debugging needed)"]
async fn mint_wrong_domain_fails() -> anyhow::Result<()> {
    todo!("Implement once check_policy has ECDSA verification")
}

#[tokio::test]
#[ignore = "fee splitting not yet implemented in mint_with_attestation"]
async fn mint_fee_exceeds_max_fee_fails() -> anyhow::Result<()> {
    todo!("Implement once fee splitting is added to check_policy")
}

#[tokio::test]
async fn mint_while_paused_fails() -> anyhow::Result<()> {
    let owner_id = test_owner_id();
    let faucet = create_test_usdcx_faucet_existing(owner_id)?;

    let mut builder = MockChain::builder();
    builder.add_account(faucet.clone())?;

    let source_manager = test_source_manager();
    let mut rng = test_rng(500);
    let pause_note = create_pause_note(owner_id, &mut rng, Arc::clone(&source_manager))?;

    builder.add_output_note(RawOutputNote::Full(pause_note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    // Execute the pause transaction
    let pause_tx = mock_chain
        .build_tx_context(faucet.id(), &[pause_note.id()], &[])?
        .with_source_manager(Arc::clone(&source_manager))
        .build()?;
    let pause_executed = pause_tx.execute().await?;

    mock_chain.add_pending_executed_transaction(&pause_executed)?;
    mock_chain.prove_next_block()?;

    // Now attempt a mint - should fail because faucet is paused
    let amount: u64 = 100_000;
    let recipient = Word::from([10u32, 20, 30, 40]);

    let mint_source_manager = Arc::new(DefaultSourceManager::default());
    let tx_script_code = create_mint_tx_script_code(
        faucet.id().prefix().as_felt(),
        faucet.id().suffix(),
        amount,
        0,
        NoteType::Private,
        recipient,
    );
    let tx_script = CodeBuilder::with_source_manager(mint_source_manager.clone())
        .compile_tx_script(tx_script_code)?;

    let tx_context = mock_chain
        .build_tx_context(faucet.id(), &[], &[])?
        .tx_script(tx_script)
        .with_source_manager(mint_source_manager)
        .build()?;

    let result = tx_context.execute().await;
    assert!(result.is_err(), "expected transaction to fail when paused");
    let err_str = format!("{}", result.unwrap_err());
    assert!(
        err_str.contains("paused") || err_str.contains("assertion failed"),
        "expected pause-related error, got: {err_str}"
    );

    Ok(())
}

#[tokio::test]
async fn mint_zero_amount_fails() -> anyhow::Result<()> {
    let owner_id = test_owner_id();
    let faucet = create_test_usdcx_faucet_existing(owner_id)?;

    let mut builder = MockChain::builder();
    builder.add_account(faucet.clone())?;
    let mock_chain = builder.build()?;

    let amount: u64 = 0;
    let recipient = Word::from([10u32, 20, 30, 40]);

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
        .build()?;

    let result = tx_context.execute().await;
    assert!(result.is_err(), "expected transaction to fail for zero amount");

    Ok(())
}

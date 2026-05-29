use std::sync::Arc;

use miden_protocol::assembly::DefaultSourceManager;
use miden_protocol::note::NoteType;
use miden_protocol::testing::account_id::AccountIdBuilder;
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

/// Attempts a mint transaction. Returns Ok(true) if successful, Ok(false) if it failed.
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

    let advice = attestation_advice(attester_sk, nonce, amount, TEST_DOMAIN_ID, 0, 0);
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

    match tx_context.execute().await {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

// TESTS
// ================================================================================================

/// Verifies that minting is rejected when the faucet's own account is on the blocklist.
///
/// The BasicBlocklist send policy calls `native_account::get_id` during `mint_and_send`
/// (on_before_asset_added_to_note callback). When minting, the native account is the
/// faucet itself, so blocking the faucet's ID causes the send policy to reject.
#[tokio::test]
async fn blocked_account_transfer_rejected() -> anyhow::Result<()> {
    let attester_sk = make_attester_keypair(42);
    let pk_comm = attester_pk_comm(&attester_sk);

    let owner_id = test_owner_id();

    // Build the faucet first to know its ID, then rebuild with it blocked.
    // We use a two-pass approach: create it once to get the ID, then create
    // with that ID in the blocklist.
    let probe_faucet = create_test_usdcx_faucet_existing_with_attesters(owner_id, vec![pk_comm])?;
    let faucet_id = probe_faucet.id();

    // Create faucet with its own ID in the initial blocklist
    let faucet = create_test_usdcx_faucet_existing_with_blocklist(
        owner_id,
        vec![pk_comm],
        vec![faucet_id],
    )?;
    assert_eq!(faucet.id(), faucet_id, "faucet ID should be deterministic");

    let mut builder = MockChain::builder();
    builder.add_account(faucet.clone())?;
    let mock_chain = builder.build()?;

    // Attempt to mint - should fail because the faucet is blocked on itself (send policy)
    let mint_result = try_mint(&mock_chain, &faucet, &attester_sk, 100).await?;
    assert!(!mint_result, "mint should fail when faucet is on its own blocklist (send policy rejects)");

    Ok(())
}

/// Verifies that unblocking the faucet allows minting again.
///
/// 1. Create faucet with its own ID blocked
/// 2. Owner unblocks the faucet
/// 3. Mint should now succeed
#[tokio::test]
async fn unblocked_account_transfer_succeeds() -> anyhow::Result<()> {
    let attester_sk = make_attester_keypair(42);
    let pk_comm = attester_pk_comm(&attester_sk);

    let owner_id = test_owner_id();

    // Create faucet to get deterministic ID
    let probe_faucet = create_test_usdcx_faucet_existing_with_attesters(owner_id, vec![pk_comm])?;
    let faucet_id = probe_faucet.id();

    // Create faucet with its own ID blocked
    let faucet = create_test_usdcx_faucet_existing_with_blocklist(
        owner_id,
        vec![pk_comm],
        vec![faucet_id],
    )?;

    // Pre-create the unblock note
    let source_manager = test_source_manager();
    let mut rng = test_rng(1100);
    let unblock_note = create_unblock_account_note(
        owner_id,
        faucet_id,
        &mut rng,
        Arc::clone(&source_manager),
    )?;

    let mut builder = MockChain::builder();
    builder.add_account(faucet.clone())?;
    builder.add_output_note(RawOutputNote::Full(unblock_note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    // Verify mint fails while blocked
    let mint_result = try_mint(&mock_chain, &faucet, &attester_sk, 100).await?;
    assert!(!mint_result, "mint should fail while faucet is blocked");

    // Unblock the faucet
    let sm = test_source_manager();
    let unblock_tx = mock_chain
        .build_tx_context(faucet.id(), &[unblock_note.id()], &[])?
        .with_source_manager(sm)
        .build()?;
    let unblock_executed = unblock_tx.execute().await?;
    mock_chain.add_pending_executed_transaction(&unblock_executed)?;
    mock_chain.prove_next_block()?;

    // Mint should succeed after unblocking
    let mint_result = try_mint(&mock_chain, &faucet, &attester_sk, 200).await?;
    assert!(mint_result, "mint should succeed after unblocking the faucet");

    Ok(())
}

/// Verifies that a non-owner cannot call block_account (authorization fails).
#[tokio::test]
async fn non_owner_blocklist_fails() -> anyhow::Result<()> {
    let owner_id = test_owner_id();
    let non_owner = AccountIdBuilder::new().build_with_seed([99; 32]);
    let faucet = create_test_usdcx_faucet_existing(owner_id)?;
    let target = AccountIdBuilder::new().build_with_seed([50; 32]);

    let mut builder = MockChain::builder();
    builder.add_account(faucet.clone())?;

    let source_manager = test_source_manager();
    let mut rng = test_rng(1200);
    // Send the block_account note from non_owner - should fail the owner check
    let note = create_block_account_note(non_owner, target, &mut rng, Arc::clone(&source_manager))?;

    builder.add_output_note(RawOutputNote::Full(note.clone()));
    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    let tx = mock_chain
        .build_tx_context(faucet.id(), &[note.id()], &[])?
        .with_source_manager(source_manager)
        .build()?;
    let result = tx.execute().await;

    assert!(result.is_err(), "expected transaction to fail for non-owner blocklist admin");
    let err_str = format!("{}", result.unwrap_err());
    assert!(
        err_str.contains("assertion failed"),
        "expected assertion failure error, got: {err_str}"
    );

    Ok(())
}

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

/// Verifies that minting succeeds with a valid Falcon512 attestation.
///
/// The check_policy verifies:
/// 1. The attester PK_COMM is in the approved registry
/// 2. The nonce has not been used before
/// 3. The Falcon512 signature over merge(NONCE, [amount, domain_id, 0, 0]) is valid
#[tokio::test]
async fn mint_with_valid_attestation_succeeds() -> anyhow::Result<()> {
    // Generate a real attester key pair
    let attester_sk = make_attester_keypair(42);
    let pk_comm = attester_pk_comm(&attester_sk);

    // Create faucet with this attester registered
    let owner_id = test_owner_id();
    let faucet = create_test_usdcx_faucet_existing_with_attesters(owner_id, vec![pk_comm])?;

    let mut builder = MockChain::builder();
    builder.add_account(faucet.clone())?;
    let mock_chain = builder.build()?;

    let amount: u64 = 100_000;
    let recipient = Word::from([10u32, 20, 30, 40]);
    let tag: u32 = 0;
    let note_type = NoteType::Private;
    let nonce = Word::new([
        Felt::new_unchecked(1),
        Felt::new_unchecked(2),
        Felt::new_unchecked(3),
        Felt::new_unchecked(4),
    ]);

    // Build advice inputs with the attestation signature
    let advice = attestation_advice(&attester_sk, nonce, amount, TEST_DOMAIN_ID);

    // Verify PK_COMM is in the faucet storage
    debug_assert_eq!(
        read_attester_status(&faucet, pk_comm).unwrap(),
        usdcx_faucet::attester_registry::ATTESTER_ACTIVE,
    );

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
        .extend_advice_inputs(advice)
        .build()?;

    let executed = tx_context.execute().await?;

    assert_eq!(
        executed.output_notes().num_notes(),
        1,
        "should have created exactly one output note"
    );

    Ok(())
}

/// Verifies that minting fails when the attester PK_COMM is not in the registry.
#[tokio::test]
async fn mint_with_unknown_attester_fails() -> anyhow::Result<()> {
    // Generate two different attester key pairs
    let registered_sk = make_attester_keypair(42);
    let registered_pk = attester_pk_comm(&registered_sk);

    let unknown_sk = make_attester_keypair(99); // different key, not registered

    // Create faucet with only the first attester registered
    let owner_id = test_owner_id();
    let faucet = create_test_usdcx_faucet_existing_with_attesters(owner_id, vec![registered_pk])?;

    let mut builder = MockChain::builder();
    builder.add_account(faucet.clone())?;
    let mock_chain = builder.build()?;

    let amount: u64 = 100_000;
    let recipient = Word::from([10u32, 20, 30, 40]);
    let nonce = Word::new([
        Felt::new_unchecked(1),
        Felt::new_unchecked(2),
        Felt::new_unchecked(3),
        Felt::new_unchecked(4),
    ]);

    // Sign with the unknown attester (not in registry)
    let advice = attestation_advice(&unknown_sk, nonce, amount, TEST_DOMAIN_ID);

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

    let result = tx_context.execute().await;
    assert!(result.is_err(), "expected transaction to fail for unknown attester");
    let err_str = format!("{}", result.unwrap_err());
    assert!(
        err_str.contains("attester") || err_str.contains("assertion failed"),
        "expected attester-related error, got: {err_str}"
    );

    Ok(())
}

/// Verifies that replaying a nonce fails on the second mint attempt.
#[tokio::test]
async fn mint_nonce_replay_fails() -> anyhow::Result<()> {
    let attester_sk = make_attester_keypair(42);
    let pk_comm = attester_pk_comm(&attester_sk);

    let owner_id = test_owner_id();
    let faucet = create_test_usdcx_faucet_existing_with_attesters(owner_id, vec![pk_comm])?;

    let mut builder = MockChain::builder();
    builder.add_account(faucet.clone())?;
    let mut mock_chain = builder.build()?;

    let amount: u64 = 100_000;
    let recipient = Word::from([10u32, 20, 30, 40]);
    let nonce = Word::new([
        Felt::new_unchecked(10),
        Felt::new_unchecked(20),
        Felt::new_unchecked(30),
        Felt::new_unchecked(40),
    ]);

    // First mint should succeed
    let advice1 = attestation_advice(&attester_sk, nonce, amount, TEST_DOMAIN_ID);
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
        .extend_advice_inputs(advice1)
        .build()?;

    let executed = tx_context.execute().await?;
    mock_chain.add_pending_executed_transaction(&executed)?;
    mock_chain.prove_next_block()?;

    // Second mint with the same nonce should fail
    let advice2 = attestation_advice(&attester_sk, nonce, amount, TEST_DOMAIN_ID);
    let source_manager2 = Arc::new(DefaultSourceManager::default());
    let tx_script_code2 = create_mint_tx_script_code(
        faucet.id().prefix().as_felt(),
        faucet.id().suffix(),
        amount,
        0,
        NoteType::Private,
        recipient,
    );
    let tx_script2 = CodeBuilder::with_source_manager(source_manager2.clone())
        .compile_tx_script(tx_script_code2)?;

    let tx_context2 = mock_chain
        .build_tx_context(faucet.id(), &[], &[])?
        .tx_script(tx_script2)
        .with_source_manager(source_manager2)
        .extend_advice_inputs(advice2)
        .build()?;

    let result = tx_context2.execute().await;
    assert!(result.is_err(), "expected transaction to fail for replayed nonce");
    let err_str = format!("{}", result.unwrap_err());
    assert!(
        err_str.contains("nonce") || err_str.contains("assertion failed"),
        "expected nonce-related error, got: {err_str}"
    );

    Ok(())
}

#[tokio::test]
#[ignore = "domain mismatch causes signature verification failure, not a distinct error"]
async fn mint_wrong_domain_fails() -> anyhow::Result<()> {
    todo!("Implement if distinct domain-mismatch error is added to check_policy")
}

#[tokio::test]
#[ignore = "fee splitting not yet implemented in mint_with_attestation"]
async fn mint_fee_exceeds_max_fee_fails() -> anyhow::Result<()> {
    todo!("Implement once fee splitting is added to check_policy")
}

#[tokio::test]
async fn mint_while_paused_fails() -> anyhow::Result<()> {
    // Use a real attester so the faucet can be created, but the pause should
    // prevent execution before check_policy is even reached.
    let attester_sk = make_attester_keypair(42);
    let pk_comm = attester_pk_comm(&attester_sk);

    let owner_id = test_owner_id();
    let faucet = create_test_usdcx_faucet_existing_with_attesters(owner_id, vec![pk_comm])?;

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
    let nonce = Word::new([
        Felt::new_unchecked(1),
        Felt::new_unchecked(2),
        Felt::new_unchecked(3),
        Felt::new_unchecked(4),
    ]);

    let advice = attestation_advice(&attester_sk, nonce, amount, TEST_DOMAIN_ID);

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
        .extend_advice_inputs(advice)
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

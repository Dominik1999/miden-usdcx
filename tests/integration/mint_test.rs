use std::sync::Arc;

use miden_protocol::account::AccountId;
use miden_protocol::assembly::DefaultSourceManager;
use miden_protocol::note::{NoteTag, NoteType};
use miden_protocol::transaction::RawOutputNote;
use miden_protocol::{Felt, Word};
use miden_standards::code_builder::CodeBuilder;
use miden_testing::MockChain;

use crate::helpers::*;

// HELPERS
// ================================================================================================

/// Creates a tx script that mints fungible tokens via mint_and_send.
///
/// The minted tokens are sent as a standard P2ID note to the recipient.
/// The `tag` should be `NoteTag::with_account_target(recipient_account_id)`
/// so the recipient's Miden client can discover the note during sync.
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

/// Computes the note tag for a mint output note targeting a specific recipient.
///
/// Uses `NoteTag::with_account_target` so the recipient's client can discover
/// the note during sync. This is the standard P2ID note tag scheme.
fn mint_note_tag(recipient_id: AccountId) -> u32 {
    NoteTag::with_account_target(recipient_id).as_u32()
}

// TESTS
// ================================================================================================

/// Verifies that minting succeeds with a valid ECDSA secp256k1 attestation.
///
/// The minted tokens are sent as a standard P2ID note to the recipient, tagged
/// with `NoteTag::with_account_target(recipient_id)` so the recipient's client
/// can discover the note during sync.
///
/// The check_policy verifies:
/// 1. The attester PK_COMM is in the approved registry
/// 2. The nonce has not been used before
/// 3. The ECDSA secp256k1 signature over merge(NONCE, [amount, domain_id, 0, 0]) is valid
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

    // Create a real recipient wallet so we can compute the correct note tag
    let recipient_wallet = builder.add_existing_wallet(miden_testing::Auth::Noop)?;

    let mock_chain = builder.build()?;

    let amount: u64 = 100_000;
    let recipient = Word::from([10u32, 20, 30, 40]);
    // Tag the mint note with the recipient's account ID for P2ID discovery
    let tag: u32 = mint_note_tag(recipient_wallet.id());
    let note_type = NoteType::Private;
    let nonce = Word::new([
        Felt::new_unchecked(1),
        Felt::new_unchecked(2),
        Felt::new_unchecked(3),
        Felt::new_unchecked(4),
    ]);

    // Build advice inputs with the attestation signature
    let advice = attestation_advice(&attester_sk, nonce, amount, TEST_DOMAIN_ID, 0, 0);

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
        "should have created exactly one P2ID output note for the recipient"
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
    let advice = attestation_advice(&unknown_sk, nonce, amount, TEST_DOMAIN_ID, 0, 0);

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
    let advice1 = attestation_advice(&attester_sk, nonce, amount, TEST_DOMAIN_ID, 0, 0);
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
    let advice2 = attestation_advice(&attester_sk, nonce, amount, TEST_DOMAIN_ID, 0, 0);
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

/// Verifies that minting with a wrong domain ID fails.
///
/// The domain_id is part of the signed message: `merge(NONCE, [amount, domain_id, 0, 0])`.
/// When the domain_id differs between signature and faucet config, the ECDSA signature
/// verification fails (the message doesn't match). This manifests as an assertion failure
/// rather than a distinct "wrong domain" error.
#[tokio::test]
async fn mint_wrong_domain_fails() -> anyhow::Result<()> {
    let attester_sk = make_attester_keypair(42);
    let pk_comm = attester_pk_comm(&attester_sk);

    let owner_id = test_owner_id();
    let faucet = create_test_usdcx_faucet_existing_with_attesters(owner_id, vec![pk_comm])?;

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

    // Sign with a WRONG domain_id (12345 instead of TEST_DOMAIN_ID=99999)
    let wrong_domain: u32 = 12345;
    let advice = attestation_advice(&attester_sk, nonce, amount, wrong_domain, 0, 0);

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
    assert!(
        result.is_err(),
        "expected transaction to fail when domain_id in signature doesn't match faucet config"
    );

    Ok(())
}

/// Verifies that minting fails when fee_amount exceeds max_fee.
///
/// The signed message includes max_fee. The relayer passes fee_amount in the
/// advice data. check_policy asserts fee_amount <= max_fee (MINT-PRE-9).
#[tokio::test]
async fn mint_fee_exceeds_max_fee_fails() -> anyhow::Result<()> {
    let attester_sk = make_attester_keypair(42);
    let pk_comm = attester_pk_comm(&attester_sk);

    let owner_id = test_owner_id();
    let faucet = create_test_usdcx_faucet_existing_with_attesters(owner_id, vec![pk_comm])?;

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

    // max_fee = 50, but fee_amount = 100 (exceeds max_fee)
    let max_fee: u64 = 50;
    let fee_amount: u64 = 100;
    let advice = attestation_advice(&attester_sk, nonce, amount, TEST_DOMAIN_ID, max_fee, fee_amount);

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
    assert!(
        result.is_err(),
        "expected transaction to fail when fee_amount exceeds max_fee"
    );

    Ok(())
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

    let advice = attestation_advice(&attester_sk, nonce, amount, TEST_DOMAIN_ID, 0, 0);

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

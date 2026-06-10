use std::sync::Arc;

use miden_protocol::asset::{Asset, AssetCallbackFlag, FungibleAsset};
use miden_protocol::assembly::DefaultSourceManager;
use miden_protocol::assembly::mast::error_code_from_msg;
use miden_protocol::crypto::rand::RandomCoin;
use miden_protocol::note::{NoteAttachments, NoteType};
use miden_protocol::testing::account_id::AccountIdBuilder;
use miden_protocol::transaction::RawOutputNote;
use miden_protocol::{Felt, Word};
use miden_standards::code_builder::CodeBuilder;
use miden_standards::note::P2idNote;
use miden_testing::{Auth, MockChain};

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

/// Builds a tx script for a BasicWallet to send a fungible asset to a recipient by creating an
/// output note and moving the asset from the wallet's vault into it.
///
/// `move_asset_to_note` removes the asset from the executing (native) account's vault and adds it
/// to the output note. The add-to-note step triggers the faucet's `on_before_asset_added_to_note`
/// send policy callback, which is what the blocklist enforces against the *sender*.
fn create_send_asset_tx_script_code(
    recipient: Word,
    note_type: NoteType,
    tag: u32,
    asset: Asset,
) -> String {
    format!(
        r#"
        begin
            push.{recipient}
            push.{note_type}
            push.{tag}
            exec.::miden::protocol::output_note::create
            # => [note_idx]

            push.{asset_value}
            push.{asset_key}
            call.::miden::standards::wallets::basic::move_asset_to_note
            dropw dropw dropw dropw
        end
        "#,
        recipient = recipient,
        note_type = note_type as u8,
        tag = tag,
        asset_value = asset.to_value_word(),
        asset_key = asset.to_key_word(),
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

/// END-TO-END: a blocked sender cannot transfer USDCx to a third party.
///
/// This is the real-world flow the faucet's blocklist is meant to gate (not just minting):
///   1. The faucet issues USDCx to Alice (a normal wallet). Alice consumes the note — the
///      *receive* policy passes because Alice is not blocked yet.
///   2. The owner blocks Alice on the faucet.
///   3. Alice tries to send USDCx to Bob via her own wallet (`move_asset_to_note`). Moving the
///      asset into the output note fires the faucet's `on_before_asset_added_to_note` *send*
///      policy callback, which reads Alice (the native/executing account) and finds her blocked.
///
/// The faucet's mint here is simulated with a faucet-issued P2ID note carrying a callback-enabled
/// asset (the same approach used by the canonical miden-standards blocklist tests), so the test
/// stays focused on the transfer policy rather than the attestation machinery.
#[tokio::test]
async fn blocked_sender_cannot_send_to_recipient() -> anyhow::Result<()> {
    let owner_id = test_owner_id();
    let amount: u64 = 100;

    let mut builder = MockChain::builder();
    let alice = builder.add_existing_wallet(Auth::IncrNonce)?;
    let bob = builder.add_existing_wallet(Auth::IncrNonce)?;

    // Faucet with the blocklist send/receive policies, no accounts blocked initially.
    let faucet =
        create_test_usdcx_faucet_existing_with_blocklist(owner_id, vec![mock_attester_pk_comm(0)], vec![])?;
    builder.add_account(faucet.clone())?;

    // The faucet issues USDCx to Alice via a callback-enabled P2ID note.
    let mint_asset = FungibleAsset::new(faucet.id(), amount)?.with_callbacks(AssetCallbackFlag::Enabled);
    let mint_note = builder.add_p2id_note(
        faucet.id(),
        alice.id(),
        &[Asset::Fungible(mint_asset)],
        NoteType::Public,
    )?;

    // Owner-authored note that blocks Alice.
    let mut rng = test_rng(2100);
    let block_note = create_block_account_note(owner_id, alice.id(), &mut rng, test_source_manager())?;
    builder.add_output_note(RawOutputNote::Full(block_note.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    // 1. Alice receives the minted USDCx (receive policy passes — not blocked yet).
    let faucet_inputs = mock_chain.get_foreign_account_inputs(faucet.id())?;
    let recv = mock_chain
        .build_tx_context(alice.id(), &[mint_note.id()], &[])?
        .foreign_accounts(vec![faucet_inputs])
        .build()?
        .execute()
        .await?;
    mock_chain.add_pending_executed_transaction(&recv)?;
    mock_chain.prove_next_block()?;

    // 2. Owner blocks Alice (faucet consumes the block note).
    let block_tx = mock_chain
        .build_tx_context(faucet.id(), &[block_note.id()], &[])?
        .with_source_manager(test_source_manager())
        .build()?
        .execute()
        .await?;
    mock_chain.add_pending_executed_transaction(&block_tx)?;
    mock_chain.prove_next_block()?;

    // 3. Alice tries to send USDCx to Bob — the send policy must reject because Alice is blocked.
    let send_asset = FungibleAsset::new(faucet.id(), amount)?.with_callbacks(AssetCallbackFlag::Enabled);
    let mut coin = RandomCoin::new(Word::from([3u32, 1, 4, 1]));
    let bob_note = P2idNote::create(
        alice.id(),
        bob.id(),
        vec![Asset::Fungible(send_asset)],
        NoteType::Public,
        NoteAttachments::default(),
        &mut coin,
    )?;

    let sm = test_source_manager();
    let send_code = create_send_asset_tx_script_code(
        bob_note.recipient().digest(),
        NoteType::Public,
        u32::from(bob_note.metadata().tag()),
        Asset::Fungible(send_asset),
    );
    let send_script = CodeBuilder::with_source_manager(sm.clone()).compile_tx_script(send_code)?;

    let faucet_inputs = mock_chain.get_foreign_account_inputs(faucet.id())?;
    let result = mock_chain
        .build_tx_context(alice.id(), &[], &[])?
        .tx_script(send_script)
        .with_source_manager(sm)
        .foreign_accounts(vec![faucet_inputs])
        // Provide the public output note's details so `output_note::create` succeeds and execution
        // reaches `move_asset_to_note`, where the send-policy blocklist callback fires.
        .extend_expected_output_notes(vec![RawOutputNote::Full(bob_note.clone())])
        .build()?
        .execute()
        .await;

    assert!(
        result.is_err(),
        "blocked sender Alice must not be able to transfer USDCx to Bob"
    );
    // The failing assertion is the blocklist's `ERR_ACCOUNT_IS_BLOCKED` ("account is blocked").
    // Miden compiles `assert.err="..."` strings to a Blake3-derived felt code, so we match on the
    // code derived from that exact message rather than on the (absent) literal string — this
    // proves the transaction failed in the send-policy blocklist check and not somewhere else.
    let err_str = format!("{}", result.unwrap_err());
    let blocked_code = error_code_from_msg("account is blocked");
    assert!(
        err_str.contains(&blocked_code.to_string()),
        "expected failure with the blocklist code {blocked_code} (\"account is blocked\"), got: {err_str}"
    );

    Ok(())
}

/// END-TO-END (positive control): when the sender is NOT blocked, the full Alice -> Bob transfer
/// succeeds and Bob actually receives the asset.
///
/// Mirrors [`blocked_sender_cannot_send_to_recipient`] but never blocks Alice. This proves the
/// blocklist is not blanket-rejecting transfers and exercises both transfer callbacks on the
/// happy path: Alice's send (`on_before_asset_added_to_note`) and Bob's receive
/// (`on_before_asset_added_to_account`).
#[tokio::test]
async fn unblocked_sender_can_send_to_recipient_end_to_end() -> anyhow::Result<()> {
    let owner_id = test_owner_id();
    let amount: u64 = 100;

    let mut builder = MockChain::builder();
    let alice = builder.add_existing_wallet(Auth::IncrNonce)?;
    let bob = builder.add_existing_wallet(Auth::IncrNonce)?;

    let faucet =
        create_test_usdcx_faucet_existing_with_blocklist(owner_id, vec![mock_attester_pk_comm(0)], vec![])?;
    builder.add_account(faucet.clone())?;

    let mint_asset = FungibleAsset::new(faucet.id(), amount)?.with_callbacks(AssetCallbackFlag::Enabled);
    let mint_note = builder.add_p2id_note(
        faucet.id(),
        alice.id(),
        &[Asset::Fungible(mint_asset)],
        NoteType::Public,
    )?;

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    // Alice receives the minted USDCx.
    let faucet_inputs = mock_chain.get_foreign_account_inputs(faucet.id())?;
    let recv = mock_chain
        .build_tx_context(alice.id(), &[mint_note.id()], &[])?
        .foreign_accounts(vec![faucet_inputs])
        .build()?
        .execute()
        .await?;
    mock_chain.add_pending_executed_transaction(&recv)?;
    mock_chain.prove_next_block()?;

    // Alice sends the USDCx to Bob.
    let send_asset = FungibleAsset::new(faucet.id(), amount)?.with_callbacks(AssetCallbackFlag::Enabled);
    let mut coin = RandomCoin::new(Word::from([2u32, 7, 1, 8]));
    let bob_note = P2idNote::create(
        alice.id(),
        bob.id(),
        vec![Asset::Fungible(send_asset)],
        NoteType::Public,
        NoteAttachments::default(),
        &mut coin,
    )?;

    let sm = test_source_manager();
    let send_code = create_send_asset_tx_script_code(
        bob_note.recipient().digest(),
        NoteType::Public,
        u32::from(bob_note.metadata().tag()),
        Asset::Fungible(send_asset),
    );
    let send_script = CodeBuilder::with_source_manager(sm.clone()).compile_tx_script(send_code)?;

    let faucet_inputs = mock_chain.get_foreign_account_inputs(faucet.id())?;
    let send_tx = mock_chain
        .build_tx_context(alice.id(), &[], &[])?
        .tx_script(send_script)
        .with_source_manager(sm)
        .foreign_accounts(vec![faucet_inputs])
        .extend_expected_output_notes(vec![RawOutputNote::Full(bob_note.clone())])
        .build()?
        .execute()
        .await?;

    assert_eq!(
        send_tx.output_notes().num_notes(),
        1,
        "Alice's transfer should produce exactly one output note for Bob"
    );
    mock_chain.add_pending_executed_transaction(&send_tx)?;
    mock_chain.prove_next_block()?;

    // Bob consumes the note (receive policy passes — Bob is not blocked).
    let faucet_inputs = mock_chain.get_foreign_account_inputs(faucet.id())?;
    let bob_recv = mock_chain
        .build_tx_context(bob.id(), &[bob_note.id()], &[])?
        .foreign_accounts(vec![faucet_inputs])
        .build()?
        .execute()
        .await?;
    mock_chain.add_pending_executed_transaction(&bob_recv)?;
    mock_chain.prove_next_block()?;

    // Bob's committed vault now holds the transferred USDCx. NOTE: the asset's vault key includes
    // its callback flag, so we must query with the same `AssetCallbackFlag::Enabled` the asset
    // carries — querying with the default (disabled) flag is a different key and reads 0.
    let bob_committed = mock_chain.committed_account(bob.id())?;
    let usdcx_key = FungibleAsset::new(faucet.id(), amount)?
        .with_callbacks(AssetCallbackFlag::Enabled)
        .vault_key();
    let balance = bob_committed
        .vault()
        .get_balance(usdcx_key)
        .expect("Bob should hold a USDCx balance");
    assert_eq!(
        balance.as_u64(),
        amount,
        "Bob should have received the full transferred amount"
    );

    Ok(())
}

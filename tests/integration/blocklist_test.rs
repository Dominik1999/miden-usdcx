use std::sync::Arc;

use miden_protocol::asset::{Asset, AssetCallbackFlag, FungibleAsset};
use miden_protocol::assembly::mast::error_code_from_msg;
use miden_protocol::crypto::rand::RandomCoin;
use miden_protocol::note::{NoteAttachments, NoteType};
use miden_protocol::testing::account_id::AccountIdBuilder;
use miden_protocol::transaction::RawOutputNote;
use miden_protocol::Word;
use miden_standards::code_builder::CodeBuilder;
use miden_standards::note::P2idNote;
use miden_testing::{Auth, MockChain};

use crate::helpers::*;

// HELPERS
// ================================================================================================

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

// TESTS
// ================================================================================================

/// END-TO-END (admin round-trip): blocking a real account stops its transfers, and unblocking
/// restores them.
///
/// The blocklist is keyed by account ID and the `check_policy` MASM reads `native_account::get_id`
/// — the account executing the transaction. So a block on Alice takes effect whenever Alice is the
/// acting account (here, when she sends). Note that you cannot block a note from being *addressed*
/// to an account — at send time the MASM only sees the opaque recipient digest — you can only stop
/// the blocked account from moving value itself.
///
///   1. The faucet issues USDCx to Alice; she consumes it (unblocked → receive passes).
///   2. Owner blocks Alice → her transfer to Bob fails in the send-policy blocklist check.
///   3. Owner unblocks Alice → the same transfer now succeeds.
#[tokio::test]
async fn blocked_then_unblocked_sender_can_transfer() -> anyhow::Result<()> {
    let owner_id = test_owner_id();
    let amount: u64 = 100;

    let mut builder = MockChain::builder();
    let alice = builder.add_existing_wallet(Auth::IncrNonce)?;
    let bob = builder.add_existing_wallet(Auth::IncrNonce)?;

    let faucet =
        create_test_usdcx_faucet_existing_with_blocklist(owner_id, vec![mock_attester_pk_comm(0)], vec![])?;
    builder.add_account(faucet.clone())?;

    // Faucet issues USDCx to Alice.
    let mint_asset = FungibleAsset::new(faucet.id(), amount)?.with_callbacks(AssetCallbackFlag::Enabled);
    let mint_note = builder.add_p2id_note(
        faucet.id(),
        alice.id(),
        &[Asset::Fungible(mint_asset)],
        NoteType::Public,
    )?;

    // Owner-authored notes to block then unblock Alice.
    let mut rng = test_rng(3100);
    let block_note = create_block_account_note(owner_id, alice.id(), &mut rng, test_source_manager())?;
    let unblock_note = create_unblock_account_note(owner_id, alice.id(), &mut rng, test_source_manager())?;
    builder.add_output_note(RawOutputNote::Full(block_note.clone()));
    builder.add_output_note(RawOutputNote::Full(unblock_note.clone()));

    let mut mock_chain = builder.build()?;
    mock_chain.prove_next_block()?;

    // 1. Alice receives the minted USDCx (not blocked yet).
    let faucet_inputs = mock_chain.get_foreign_account_inputs(faucet.id())?;
    let recv = mock_chain
        .build_tx_context(alice.id(), &[mint_note.id()], &[])?
        .foreign_accounts(vec![faucet_inputs])
        .build()?
        .execute()
        .await?;
    mock_chain.add_pending_executed_transaction(&recv)?;
    mock_chain.prove_next_block()?;

    // The output note Alice will (try to) send to Bob — reused for both the blocked and unblocked
    // attempt (the blocked attempt aborts before creating it, so there is no collision).
    let send_asset = FungibleAsset::new(faucet.id(), amount)?.with_callbacks(AssetCallbackFlag::Enabled);
    let mut coin = RandomCoin::new(Word::from([8u32, 0, 0, 8]));
    let bob_note = P2idNote::create(
        alice.id(),
        bob.id(),
        vec![Asset::Fungible(send_asset)],
        NoteType::Public,
        NoteAttachments::default(),
        &mut coin,
    )?;
    let send_code = create_send_asset_tx_script_code(
        bob_note.recipient().digest(),
        NoteType::Public,
        u32::from(bob_note.metadata().tag()),
        Asset::Fungible(send_asset),
    );

    // 2. Owner blocks Alice; her transfer to Bob must now fail in the send policy.
    let block_tx = mock_chain
        .build_tx_context(faucet.id(), &[block_note.id()], &[])?
        .with_source_manager(test_source_manager())
        .build()?
        .execute()
        .await?;
    mock_chain.add_pending_executed_transaction(&block_tx)?;
    mock_chain.prove_next_block()?;

    let sm = test_source_manager();
    let send_script = CodeBuilder::with_source_manager(sm.clone()).compile_tx_script(send_code.clone())?;
    let faucet_inputs = mock_chain.get_foreign_account_inputs(faucet.id())?;
    let blocked_result = mock_chain
        .build_tx_context(alice.id(), &[], &[])?
        .tx_script(send_script)
        .with_source_manager(sm)
        .foreign_accounts(vec![faucet_inputs])
        .extend_expected_output_notes(vec![RawOutputNote::Full(bob_note.clone())])
        .build()?
        .execute()
        .await;

    assert!(blocked_result.is_err(), "blocked Alice must not be able to transfer to Bob");
    let blocked_code = error_code_from_msg("account is blocked");
    assert!(
        format!("{}", blocked_result.unwrap_err()).contains(&blocked_code.to_string()),
        "expected the transfer to fail with the blocklist code while Alice is blocked"
    );

    // 3. Owner unblocks Alice; the same transfer now succeeds.
    let unblock_tx = mock_chain
        .build_tx_context(faucet.id(), &[unblock_note.id()], &[])?
        .with_source_manager(test_source_manager())
        .build()?
        .execute()
        .await?;
    mock_chain.add_pending_executed_transaction(&unblock_tx)?;
    mock_chain.prove_next_block()?;

    let sm = test_source_manager();
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
        "after unblocking, Alice's transfer to Bob should succeed and produce one output note"
    );

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

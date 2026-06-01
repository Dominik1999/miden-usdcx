// Shared test helpers for USDCx integration tests.

use std::sync::Arc;

use miden_protocol::account::{
    Account, AccountBuilder, AccountId, AccountType, StorageSlotName,
};
use miden_protocol::account::auth::AuthSecretKey;
use miden_protocol::assembly::Library;
use miden_protocol::assembly::DefaultSourceManager;
use miden_protocol::assembly::debuginfo::SourceManagerSync;
use miden_protocol::asset::AssetAmount;
use miden_protocol::note::Note;
use miden_protocol::testing::account_id::AccountIdBuilder;
use miden_protocol::vm::AdviceInputs;
use miden_protocol::{Felt, Hasher, Word, ZERO};
use miden_standards::account::access::{AccessControl, PausableManager};
use miden_standards::account::auth::NoAuth;
use miden_standards::account::faucets::{FungibleFaucet, TokenName};
use miden_standards::account::policies::{
    BlocklistOwnerControlled, BurnPolicyConfig, MintPolicyConfig,
    PolicyRegistration, TokenPolicyManager, TransferPolicy,
};
use miden_standards::testing::note::NoteBuilder;
use miden_testing::MockChain;
use rand::SeedableRng;
use rand::rngs::SmallRng;
use rand_chacha::ChaCha20Rng;
use usdcx_faucet::burn_policy::UsdcxBurnPolicy;
use usdcx_faucet::deposit_intent::DepositIntent;
use usdcx_faucet::domain_config::DomainConfig;
use usdcx_faucet::mint_policy::UsdcxMintPolicy;
use usdcx_faucet::attester_registry::AttesterRegistry;
use usdcx_faucet::nonce_registry::NonceRegistry;

// CONSTANTS
// ================================================================================================

pub const TEST_DOMAIN_ID: u32 = 99999;
pub const TEST_MIN_BURN_SIZE: u64 = 1_000;
pub const TEST_MAX_SUPPLY: u64 = 1_000_000_000_000;

// HELPERS
// ================================================================================================

/// Creates a deterministic `PK_COMM` word for testing, keyed by `index`.
///
/// NOTE: This creates a fake PK_COMM that does NOT correspond to a real key pair.
/// Use `make_attester_keypair` + `attester_pk_comm` for real attestation tests.
pub fn mock_attester_pk_comm(index: u8) -> Word {
    Word::new([
        Felt::new_unchecked(index as u64 + 1),
        Felt::new_unchecked(index as u64 + 2),
        Felt::new_unchecked(index as u64 + 3),
        ZERO,
    ])
}

// ATTESTATION HELPERS
// ================================================================================================

/// Generates a deterministic ECDSA secp256k1 attester key pair from a seed.
pub fn make_attester_keypair(seed: u64) -> AuthSecretKey {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    AuthSecretKey::new_ecdsa_k256_keccak_with_rng(&mut rng)
}

/// Extracts the public key commitment (Word) from an attester secret key.
pub fn attester_pk_comm(sk: &AuthSecretKey) -> Word {
    sk.public_key().to_commitment().into()
}

/// Computes the deposit message hash: Poseidon2::hash_elements over all 39 depositIntent felts.
///
/// This must match the MASM computation in check_policy exactly.
pub fn deposit_message(intent: &DepositIntent) -> Word {
    intent.message_hash()
}

/// Creates a test `DepositIntent` with sensible defaults.
///
/// The `nonce_bytes` are constructed from a `Word` by encoding each felt as a u32
/// in the first 16 bytes (leaving the rest zeroed). This matches the common test
/// pattern of using a Word as a nonce.
pub fn test_deposit_intent(
    faucet_id: AccountId,
    amount: u64,
    max_fee: u64,
    nonce: Word,
) -> DepositIntent {
    // Convert Word nonce to bytes32 (first 4 felts as u32 LE in first 16 bytes)
    let mut nonce_bytes = [0u8; 32];
    for i in 0..4 {
        let val = nonce[i].as_canonical_u64() as u32;
        nonce_bytes[i * 4..i * 4 + 4].copy_from_slice(&val.to_le_bytes());
    }

    // Non-zero local_token and local_depositor (required by validation)
    let mut local_token = [0u8; 32];
    local_token[0] = 0xAA; // USDC contract on Ethereum (placeholder)

    let mut local_depositor = [0u8; 32];
    local_depositor[0] = 0xBB; // depositor on Ethereum (placeholder)

    let mut remote_recipient = [0u8; 32];
    remote_recipient[0] = 0xCC; // recipient on Miden (placeholder)

    DepositIntent::new(
        nonce_bytes,
        amount,
        max_fee,
        TEST_DOMAIN_ID,
        faucet_id,
        remote_recipient,
        local_token,
        local_depositor,
    )
}

/// Creates a test `DepositIntent` with a custom domain ID (for negative tests).
pub fn test_deposit_intent_with_domain(
    faucet_id: AccountId,
    amount: u64,
    max_fee: u64,
    nonce: Word,
    domain_id: u32,
) -> DepositIntent {
    let mut intent = test_deposit_intent(faucet_id, amount, max_fee, nonce);
    intent.remote_domain = domain_id;
    intent
}

/// The well-known advice map key for attestation data (PK_COMM + NONCE).
/// Must match `ATTESTATION_DATA_KEY` in the MASM.
pub const ATTESTATION_DATA_KEY: Word = Word::new([
    Felt::new_unchecked(3735928559),
    Felt::new_unchecked(3405691582),
    Felt::new_unchecked(3735928559),
    Felt::new_unchecked(3405691582),
]);

/// Builds advice inputs for attestation verification in check_policy.
///
/// The advice map carries:
/// - `ATTESTATION_DATA_KEY` -> [PK_COMM(4), DEPOSIT_INTENT(39), fee_amount, 0, 0, 0,
///                               NONCE_KEY(4), max_fee, 0, 0, 0, MESSAGE(4)]
/// - `merge(PK_COMM, MESSAGE)` -> prepared ECDSA secp256k1 signature
///
/// The check_policy reads from advice stack in this order:
///   1. PK_COMM (4 felts)
///   2. depositIntent fields in 10 word-sized chunks (40 felts, last padded with 0)
///   3. fee_amount word [fee_amount, 0, 0, 0]
///   4. NONCE_KEY word (Poseidon2 hash of nonce bytes32)
///   5. max_fee word [max_fee, 0, 0, 0]
///   6. MESSAGE word (Poseidon2 hash of all 39 intent felts)
pub fn attestation_advice(
    attester_sk: &AuthSecretKey,
    intent: &DepositIntent,
    fee_amount: u64,
) -> AdviceInputs {
    let pk_comm = attester_pk_comm(attester_sk);
    let message = deposit_message(intent);
    let nonce_key = intent.nonce_key();

    // Sign the message
    let sig = attester_sk.sign(message);
    let prepared = sig.to_prepared_signature(message);

    // Compute the advice map key for the signature: merge(PK_COMM, MESSAGE)
    let sig_key = Hasher::merge(&[pk_comm, message]);

    // Build the attestation data matching the check_policy read order:
    // [PK_COMM(4), DEPOSIT_INTENT(39) padded to 40, fee_amount word(4),
    //  NONCE_KEY(4), max_fee word(4), MESSAGE(4)]
    let mut attestation_data: Vec<Felt> = Vec::new();

    // PK_COMM (4 felts)
    attestation_data.extend(pk_comm.as_elements());

    // DEPOSIT_INTENT (39 felts) + 1 padding zero = 40 felts (10 words)
    attestation_data.extend(intent.to_advice_felts());
    attestation_data.push(ZERO); // pad to 40

    // fee_amount word [fee_amount, 0, 0, 0]
    attestation_data.push(Felt::new_unchecked(fee_amount));
    attestation_data.push(ZERO);
    attestation_data.push(ZERO);
    attestation_data.push(ZERO);

    // NONCE_KEY (4 felts)
    attestation_data.extend(nonce_key.as_elements());

    // max_fee word [max_fee, 0, 0, 0]
    attestation_data.push(Felt::new_unchecked(intent.max_fee));
    attestation_data.push(ZERO);
    attestation_data.push(ZERO);
    attestation_data.push(ZERO);

    // MESSAGE (4 felts)
    attestation_data.extend(message.as_elements());

    AdviceInputs::default()
        .with_map([
            (ATTESTATION_DATA_KEY, attestation_data),
            (sig_key, prepared),
        ])
}

/// Creates a USDCx faucet as an "existing" account suitable for MockChain.
///
/// Unlike `create_usdcx_faucet` (which produces a "new" account with seed),
/// this builds the account with `build_existing()` so it can be added to
/// MockChainBuilder via `add_account()`.
pub fn create_test_usdcx_faucet_existing(
    owner_id: AccountId,
) -> anyhow::Result<Account> {
    let token_name = TokenName::new("USDCx")?;
    let token_symbol = miden_protocol::asset::TokenSymbol::new("USDCX")?;

    let faucet = FungibleFaucet::builder()
        .name(token_name)
        .symbol(token_symbol)
        .decimals(6)
        .max_supply(AssetAmount::try_from(TEST_MAX_SUPPLY)?)
        .build()?;

    let attester_registry = AttesterRegistry::new(vec![mock_attester_pk_comm(0)])
        .expect("at least one attester is required");
    let nonce_registry = NonceRegistry::new();
    let domain_config = DomainConfig::new(TEST_DOMAIN_ID, TEST_MIN_BURN_SIZE);
    let mint_policy = UsdcxMintPolicy::new(attester_registry, nonce_registry, domain_config);
    let burn_policy = UsdcxBurnPolicy::new();

    let token_policy_manager = TokenPolicyManager::new()
        .with_mint_policy(
            MintPolicyConfig::Custom(UsdcxMintPolicy::check_policy_root().as_word()),
            PolicyRegistration::Active,
        )?
        .with_burn_policy(
            BurnPolicyConfig::Custom(UsdcxBurnPolicy::check_policy_root().as_word()),
            PolicyRegistration::Active,
        )?
        .with_send_policy(TransferPolicy::Blocklist, PolicyRegistration::Active)?
        .with_receive_policy(TransferPolicy::Blocklist, PolicyRegistration::Active)?;

    let access_control = AccessControl::Ownable2Step { owner: owner_id };

    let account = AccountBuilder::new([0u8; 32])
        .account_type(AccountType::Public)
        .with_auth_component(NoAuth::new())
        .with_component(faucet)
        .with_components(access_control)
        .with_components(token_policy_manager)
        .with_component(PausableManager)
        .with_component(mint_policy)
        .with_component(burn_policy)
        .with_component(BlocklistOwnerControlled)
        .build_existing()?;

    Ok(account)
}

/// Creates a deterministic owner account ID for tests.
pub fn test_owner_id() -> AccountId {
    AccountIdBuilder::new().build_with_seed([1; 32])
}

/// Creates a shared source manager for compiling note scripts.
pub fn test_source_manager() -> Arc<dyn SourceManagerSync> {
    Arc::new(DefaultSourceManager::default())
}

/// Creates a deterministic RNG for note building.
pub fn test_rng(seed: u64) -> SmallRng {
    SmallRng::seed_from_u64(seed)
}

/// Returns the compiled MASM library for the USDCx mint policy component.
///
/// This is needed for note scripts that call mint policy procedures (e.g.
/// add_attester, remove_attester) via dynamic linking.
pub fn mint_policy_library() -> Library {
    UsdcxMintPolicy::code().as_library().clone()
}

/// Returns the compiled MASM library for the USDCx burn policy component.
pub fn burn_policy_library() -> Library {
    UsdcxBurnPolicy::code().as_library().clone()
}

/// Sets up a MockChain with a USDCx faucet.
///
/// Returns (mock_chain, faucet, owner_id).
pub fn setup_faucet_chain() -> anyhow::Result<(MockChain, Account, AccountId)> {
    let owner_id = test_owner_id();
    let faucet = create_test_usdcx_faucet_existing(owner_id)?;

    let mut builder = MockChain::builder();
    builder.add_account(faucet.clone())?;

    let mock_chain = builder.build()?;
    Ok((mock_chain, faucet, owner_id))
}

/// Creates a note that calls `add_attester` on the faucet with the given PK_COMM.
///
/// The note sender must be the faucet owner for the call to succeed.
pub fn create_add_attester_note(
    sender: AccountId,
    pk_comm: Word,
    rng: &mut SmallRng,
    source_manager: Arc<dyn SourceManagerSync>,
) -> anyhow::Result<Note> {
    let script = format!(
        r#"
        use usdcx::components::mint_policy->faucet_account
        @note_script
        pub proc main
            repeat.12 push.0 end
            push.{pk3}
            push.{pk2}
            push.{pk1}
            push.{pk0}
            call.faucet_account::add_attester
            dropw dropw dropw dropw
        end
    "#,
        pk0 = pk_comm[0].as_canonical_u64(),
        pk1 = pk_comm[1].as_canonical_u64(),
        pk2 = pk_comm[2].as_canonical_u64(),
        pk3 = pk_comm[3].as_canonical_u64(),
    );

    let note = NoteBuilder::new(sender, &mut *rng)
        .source_manager(source_manager)
        .dynamically_linked_libraries([mint_policy_library()])
        .code(script)
        .build()?;

    Ok(note)
}

/// Creates a note that calls `remove_attester` on the faucet with the given PK_COMM.
///
/// The note sender must be the faucet owner for the call to succeed.
pub fn create_remove_attester_note(
    sender: AccountId,
    pk_comm: Word,
    rng: &mut SmallRng,
    source_manager: Arc<dyn SourceManagerSync>,
) -> anyhow::Result<Note> {
    let script = format!(
        r#"
        use usdcx::components::mint_policy->faucet_account
        @note_script
        pub proc main
            repeat.12 push.0 end
            push.{pk3}
            push.{pk2}
            push.{pk1}
            push.{pk0}
            call.faucet_account::remove_attester
            dropw dropw dropw dropw
        end
    "#,
        pk0 = pk_comm[0].as_canonical_u64(),
        pk1 = pk_comm[1].as_canonical_u64(),
        pk2 = pk_comm[2].as_canonical_u64(),
        pk3 = pk_comm[3].as_canonical_u64(),
    );

    let note = NoteBuilder::new(sender, &mut *rng)
        .source_manager(source_manager)
        .dynamically_linked_libraries([mint_policy_library()])
        .code(script)
        .build()?;

    Ok(note)
}

/// Creates a note that calls `set_min_burn_size` on the faucet with the given value.
///
/// The note sender must be the faucet owner for the call to succeed.
pub fn create_set_min_burn_size_note(
    sender: AccountId,
    new_min_burn_size: u64,
    rng: &mut SmallRng,
    source_manager: Arc<dyn SourceManagerSync>,
) -> anyhow::Result<Note> {
    let script = format!(
        r#"
        use usdcx::components::burn_policy->faucet_account
        @note_script
        pub proc main
            repeat.15 push.0 end
            push.{new_min_burn_size}
            call.faucet_account::set_min_burn_size
            dropw dropw dropw dropw
        end
    "#,
        new_min_burn_size = new_min_burn_size,
    );

    let note = NoteBuilder::new(sender, &mut *rng)
        .source_manager(source_manager)
        .dynamically_linked_libraries([burn_policy_library()])
        .code(script)
        .build()?;

    Ok(note)
}

/// Reads the domain config from the faucet's storage.
pub fn read_domain_config(faucet: &Account) -> anyhow::Result<DomainConfig> {
    let slot_name = StorageSlotName::new("usdcx::domain_config")?;
    let word = faucet.storage().get_item(&slot_name)?;
    Ok(DomainConfig::from_word(word))
}

/// Reads the attester status (active or not) from the faucet's storage map.
pub fn read_attester_status(faucet: &Account, pk_comm: Word) -> anyhow::Result<Word> {
    let slot_name = StorageSlotName::new("usdcx::attesters")?;
    let value = faucet.storage().get_map_item(&slot_name, pk_comm)?;
    Ok(value)
}

/// Creates a USDCx faucet with a custom set of attester PK_COMMitments.
#[allow(dead_code)]
///
/// Similar to `create_test_usdcx_faucet_existing` but allows specifying which
/// attester public key commitments to register.
pub fn create_test_usdcx_faucet_existing_with_attesters(
    owner_id: AccountId,
    attesters: Vec<Word>,
) -> anyhow::Result<Account> {
    let token_name = TokenName::new("USDCx")?;
    let token_symbol = miden_protocol::asset::TokenSymbol::new("USDCX")?;

    let faucet = FungibleFaucet::builder()
        .name(token_name)
        .symbol(token_symbol)
        .decimals(6)
        .max_supply(AssetAmount::try_from(TEST_MAX_SUPPLY)?)
        .build()?;

    let attester_registry = AttesterRegistry::new(attesters)
        .expect("at least one attester is required");
    let nonce_registry = NonceRegistry::new();
    let domain_config = DomainConfig::new(TEST_DOMAIN_ID, TEST_MIN_BURN_SIZE);
    let mint_policy = UsdcxMintPolicy::new(attester_registry, nonce_registry, domain_config);
    let burn_policy = UsdcxBurnPolicy::new();

    let token_policy_manager = TokenPolicyManager::new()
        .with_mint_policy(
            MintPolicyConfig::Custom(UsdcxMintPolicy::check_policy_root().as_word()),
            PolicyRegistration::Active,
        )?
        .with_burn_policy(
            BurnPolicyConfig::Custom(UsdcxBurnPolicy::check_policy_root().as_word()),
            PolicyRegistration::Active,
        )?
        .with_send_policy(TransferPolicy::Blocklist, PolicyRegistration::Active)?
        .with_receive_policy(TransferPolicy::Blocklist, PolicyRegistration::Active)?;

    let access_control = AccessControl::Ownable2Step { owner: owner_id };

    let account = AccountBuilder::new([0u8; 32])
        .account_type(AccountType::Public)
        .with_auth_component(NoAuth::new())
        .with_component(faucet)
        .with_components(access_control)
        .with_components(token_policy_manager)
        .with_component(PausableManager)
        .with_component(mint_policy)
        .with_component(burn_policy)
        .with_component(BlocklistOwnerControlled)
        .build_existing()?;

    Ok(account)
}

/// Returns the compiled MASM library for the PausableManager component.
pub fn pausable_manager_library() -> Library {
    PausableManager::code().as_library().clone()
}

/// Returns the compiled MASM library for the BlocklistOwnerControlled component.
pub fn blocklist_owner_controlled_library() -> Library {
    BlocklistOwnerControlled::code().as_library().clone()
}

/// Returns the compiled MASM library for the Ownable2Step component.
pub fn ownable2step_library() -> Library {
    use miden_standards::account::access::Ownable2Step;
    Ownable2Step::code().as_library().clone()
}

/// Creates a USDCx faucet with initial blocked accounts in the blocklist.
///
/// This replaces the default empty `BasicBlocklist` with one seeded with blocked accounts.
#[allow(dead_code)]
pub fn create_test_usdcx_faucet_existing_with_blocklist(
    owner_id: AccountId,
    attesters: Vec<Word>,
    blocked_accounts: Vec<AccountId>,
) -> anyhow::Result<Account> {
    use miden_standards::account::policies::BasicBlocklist;

    let token_name = TokenName::new("USDCx")?;
    let token_symbol = miden_protocol::asset::TokenSymbol::new("USDCX")?;

    let faucet = FungibleFaucet::builder()
        .name(token_name)
        .symbol(token_symbol)
        .decimals(6)
        .max_supply(AssetAmount::try_from(TEST_MAX_SUPPLY)?)
        .build()?;

    let attester_registry = AttesterRegistry::new(attesters)
        .expect("at least one attester is required");
    let nonce_registry = NonceRegistry::new();
    let domain_config = DomainConfig::new(TEST_DOMAIN_ID, TEST_MIN_BURN_SIZE);
    let mint_policy = UsdcxMintPolicy::new(attester_registry, nonce_registry, domain_config);
    let burn_policy = UsdcxBurnPolicy::new();

    // Use Custom transfer policy + explicit BasicBlocklist with initial blocked accounts.
    // This avoids the default empty BasicBlocklist that TransferPolicy::Blocklist creates.
    let blocklist_root = BasicBlocklist::root();
    let token_policy_manager = TokenPolicyManager::new()
        .with_mint_policy(
            MintPolicyConfig::Custom(UsdcxMintPolicy::check_policy_root().as_word()),
            PolicyRegistration::Active,
        )?
        .with_burn_policy(
            BurnPolicyConfig::Custom(UsdcxBurnPolicy::check_policy_root().as_word()),
            PolicyRegistration::Active,
        )?
        .with_send_policy(TransferPolicy::Custom(blocklist_root), PolicyRegistration::Active)?
        .with_receive_policy(TransferPolicy::Custom(blocklist_root), PolicyRegistration::Active)?;

    let access_control = AccessControl::Ownable2Step { owner: owner_id };
    let blocklist = BasicBlocklist::with_blocked_accounts(blocked_accounts);

    let account = AccountBuilder::new([0u8; 32])
        .account_type(AccountType::Public)
        .with_auth_component(NoAuth::new())
        .with_component(faucet)
        .with_components(access_control)
        .with_components(token_policy_manager)
        .with_component(PausableManager)
        .with_component(mint_policy)
        .with_component(burn_policy)
        .with_component(blocklist)
        .with_component(BlocklistOwnerControlled)
        .build_existing()?;

    Ok(account)
}

/// Creates a note that calls `block_account` on the faucet via BlocklistOwnerControlled.
///
/// The note sender must be the faucet owner for the call to succeed.
pub fn create_block_account_note(
    sender: AccountId,
    target_account: AccountId,
    rng: &mut SmallRng,
    source_manager: Arc<dyn SourceManagerSync>,
) -> anyhow::Result<Note> {
    let script = format!(
        r#"
        use miden::standards::components::faucets::policies::transfer::blocklist::owner_controlled->faucet_account
        @note_script
        pub proc main
            repeat.14 push.0 end
            push.{target_prefix}
            push.{target_suffix}
            call.faucet_account::block_account
            dropw dropw dropw dropw
        end
    "#,
        target_suffix = target_account.suffix(),
        target_prefix = target_account.prefix().as_felt(),
    );

    let note = NoteBuilder::new(sender, &mut *rng)
        .source_manager(source_manager)
        .dynamically_linked_libraries([blocklist_owner_controlled_library()])
        .code(script)
        .build()?;

    Ok(note)
}

/// Creates a note that calls `unblock_account` on the faucet via BlocklistOwnerControlled.
///
/// The note sender must be the faucet owner for the call to succeed.
pub fn create_unblock_account_note(
    sender: AccountId,
    target_account: AccountId,
    rng: &mut SmallRng,
    source_manager: Arc<dyn SourceManagerSync>,
) -> anyhow::Result<Note> {
    let script = format!(
        r#"
        use miden::standards::components::faucets::policies::transfer::blocklist::owner_controlled->faucet_account
        @note_script
        pub proc main
            repeat.14 push.0 end
            push.{target_prefix}
            push.{target_suffix}
            call.faucet_account::unblock_account
            dropw dropw dropw dropw
        end
    "#,
        target_suffix = target_account.suffix(),
        target_prefix = target_account.prefix().as_felt(),
    );

    let note = NoteBuilder::new(sender, &mut *rng)
        .source_manager(source_manager)
        .dynamically_linked_libraries([blocklist_owner_controlled_library()])
        .code(script)
        .build()?;

    Ok(note)
}

/// Creates a note that calls `transfer_ownership` on the faucet via Ownable2Step.
///
/// The note sender must be the current owner for the call to succeed.
pub fn create_transfer_ownership_note(
    sender: AccountId,
    new_owner: AccountId,
    rng: &mut SmallRng,
    source_manager: Arc<dyn SourceManagerSync>,
) -> anyhow::Result<Note> {
    let script = format!(
        r#"
        use miden::standards::access::ownable2step->faucet_account
        @note_script
        pub proc main
            repeat.14 push.0 end
            push.{new_owner_prefix}
            push.{new_owner_suffix}
            call.faucet_account::transfer_ownership
            dropw dropw dropw dropw
        end
    "#,
        new_owner_suffix = new_owner.suffix(),
        new_owner_prefix = new_owner.prefix().as_felt(),
    );

    let note = NoteBuilder::new(sender, &mut *rng)
        .source_manager(source_manager)
        .dynamically_linked_libraries([ownable2step_library()])
        .code(script)
        .build()?;

    Ok(note)
}

/// Creates a note that calls `accept_ownership` on the faucet via Ownable2Step.
///
/// The note sender must be the nominated owner for the call to succeed.
pub fn create_accept_ownership_note(
    sender: AccountId,
    rng: &mut SmallRng,
    source_manager: Arc<dyn SourceManagerSync>,
) -> anyhow::Result<Note> {
    let script = r#"
        use miden::standards::access::ownable2step->faucet_account
        @note_script
        pub proc main
            padw padw padw padw
            call.faucet_account::accept_ownership
            dropw dropw dropw dropw
        end
    "#;

    let note = NoteBuilder::new(sender, &mut *rng)
        .source_manager(source_manager)
        .dynamically_linked_libraries([ownable2step_library()])
        .code(script)
        .build()?;

    Ok(note)
}

/// Creates a note that calls `pause` on the faucet.
///
/// The note sender must be the faucet owner for the call to succeed.
pub fn create_pause_note(
    sender: AccountId,
    rng: &mut SmallRng,
    source_manager: Arc<dyn SourceManagerSync>,
) -> anyhow::Result<Note> {
    let script = r#"
        use miden::standards::components::access::pausable::manager->faucet_account
        @note_script
        pub proc main
            padw padw padw padw
            call.faucet_account::pause
            dropw dropw dropw dropw
        end
    "#;

    let note = NoteBuilder::new(sender, &mut *rng)
        .source_manager(source_manager)
        .dynamically_linked_libraries([pausable_manager_library()])
        .code(script)
        .build()?;

    Ok(note)
}

/// Creates a note that calls `unpause` on the faucet.
///
/// The note sender must be the faucet owner for the call to succeed.
pub fn create_unpause_note(
    sender: AccountId,
    rng: &mut SmallRng,
    source_manager: Arc<dyn SourceManagerSync>,
) -> anyhow::Result<Note> {
    let script = r#"
        use miden::standards::components::access::pausable::manager->faucet_account
        @note_script
        pub proc main
            padw padw padw padw
            call.faucet_account::unpause
            dropw dropw dropw dropw
        end
    "#;

    let note = NoteBuilder::new(sender, &mut *rng)
        .source_manager(source_manager)
        .dynamically_linked_libraries([pausable_manager_library()])
        .code(script)
        .build()?;

    Ok(note)
}

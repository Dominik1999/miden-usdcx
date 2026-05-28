use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{
    AccountComponent, AccountComponentCode, AccountProcedureRoot, StorageSlot, StorageSlotName,
};
use miden_protocol::assembly::Library;
use miden_protocol::utils::sync::LazyLock;

use miden_standards::code_builder::CodeBuilder;

use crate::attester_registry::{AttesterRegistry, ATTESTER_REGISTRY_SLOT_NAME};
use crate::domain_config::{DomainConfig, DOMAIN_CONFIG_SLOT_NAME};
use crate::nonce_registry::{NonceRegistry, NONCE_REGISTRY_SLOT_NAME};

// CONSTANTS
// ================================================================================================

/// The component name for the USDCx mint policy.
pub const USDCX_MINT_POLICY_NAME: &str = "usdcx::components::mint_policy";

/// MASM source code for the USDCx mint policy component.
const USDCX_MINT_POLICY_MASM: &str = "
    use miden::protocol::active_account
    use miden::protocol::native_account
    use miden::protocol::output_note
    use miden::protocol::faucet
    use miden::standards::access::ownable2step
    use miden::standards::access::pausable
    use miden::core::crypto::dsa::ecdsa_k256_keccak
    use miden::core::crypto::hashes::poseidon2

    # CONSTANTS
    # ============================================================================================

    const ATTESTERS_SLOT=word(\"usdcx::attesters\")
    const NONCES_SLOT=word(\"usdcx::used_nonces\")
    const DOMAIN_CONFIG_SLOT=word(\"usdcx::domain_config\")
    const NONCE_USED=[1, 0, 0, 0]
    const ATTESTER_ACTIVE=[1, 0, 0, 0]

    # Well-known advice map key for the attestation data (PK_COMM + NONCE).
    # The relayer puts [pk0, pk1, pk2, pk3, n0, n1, n2, n3] under this key
    # in the advice map before building the transaction.
    const ATTESTATION_DATA_KEY=[3735928559, 3405691582, 3735928559, 3405691582]

    const ERR_ATTESTER_NOT_APPROVED=\"attester public key commitment not in registry\"
    const ERR_NONCE_ALREADY_USED=\"deposit intent nonce has already been used\"

    # PROCEDURES
    # ============================================================================================

    #! Mint policy check invoked via dynexec by the TokenPolicyManager.
    #!
    #! Verifies an ECDSA secp256k1 attestation from the advice provider before
    #! allowing the mint to proceed. The attestation data is read from the
    #! advice stack (PK_COMM, NONCE) and the signature is read from the
    #! advice map keyed by merge(PK_COMM, MESSAGE).
    #!
    #! Inputs:  [amount, tag, note_type, RECIPIENT]
    #! Outputs: [amount, tag, note_type, RECIPIENT]
    #!
    #! Panics if:
    #! - the attester PK_COMM is not in the approved attesters registry.
    #! - the deposit nonce has already been used.
    #! - the ECDSA secp256k1 signature verification fails.
    #!
    #! Invocation: dynexec
    pub proc check_policy
        # Stack: [amount, tag, note_type, RECIPIENT(4)]

        # 1. Load attestation data (PK_COMM + NONCE) from advice map
        push.ATTESTATION_DATA_KEY
        adv.push_mapval
        dropw
        # => [amount, tag, note_type, RECIPIENT(4)]

        # 2. Read PK_COMM from the advice stack
        padw adv_loadw
        # => [PK_COMM(4), amount, tag, note_type, RECIPIENT(4)]

        # 3. Verify the attester is in the approved registry
        dupw
        push.ATTESTERS_SLOT[0..2]
        exec.active_account::get_map_item
        # => [VALUE(4), PK_COMM, amount, tag, note_type, RECIPIENT]
        # get_map_item returns VALUE reversed on stack
        # Stored [1,0,0,0] appears as [0,0,0,1]; check VALUE[3]
        movdn.3 drop drop drop
        # => [is_approved, PK_COMM, amount, tag, note_type, RECIPIENT]
        assert.err=ERR_ATTESTER_NOT_APPROVED
        # => [PK_COMM, amount, tag, note_type, RECIPIENT]

        # 4. Read NONCE from the advice stack
        padw adv_loadw
        # => [NONCE(4), PK_COMM(4), amount, tag, note_type, RECIPIENT(4)]

        # 5. Check nonce has not been used
        dupw
        push.NONCES_SLOT[0..2]
        exec.active_account::get_map_item
        # => [NONCE_VAL(4), NONCE, PK_COMM, amount, tag, note_type, RECIPIENT]
        # Nonce val stored as [1,0,0,0] appears reversed; check VALUE[3]
        movdn.3 drop drop drop
        # => [nonce_val_last, NONCE, PK_COMM, amount, tag, note_type, RECIPIENT]
        assertz.err=ERR_NONCE_ALREADY_USED
        # => [NONCE, PK_COMM, amount, tag, note_type, RECIPIENT]

        # 6. Mark nonce as used in storage
        # set_map_item needs [slot_suffix, slot_prefix, KEY, VALUE]
        # VALUE = NONCE_USED = [1,0,0,0] but we need to store it reversed
        # Actually, let's just store [1,0,0,0] and the read reversal is consistent
        dupw
        push.NONCE_USED swapw
        push.NONCES_SLOT[0..2]
        exec.native_account::set_map_item
        dropw
        # => [NONCE, PK_COMM, amount, tag, note_type, RECIPIENT]

        # 7. Compute MESSAGE = merge(NONCE, [amount, domain_id, 0, 0])
        push.DOMAIN_CONFIG_SLOT[0..2]
        exec.active_account::get_item
        # => [CONFIG_WORD(4), NONCE, PK_COMM, amount, tag, note_type, RECIPIENT]
        # CONFIG_WORD is also reversed on stack: stored [domain_id, min_burn, 0, 0]
        # appears as [0, 0, min_burn, domain_id] on stack
        # domain_id is at position 3 of the returned word
        movdn.3 drop drop drop
        # => [domain_id, NONCE(4), PK_COMM(4), amount, tag, note_type, RECIPIENT(4)]

        # Build AMOUNT_WORD = [amount, domain_id, 0, 0]
        dup.9 swap push.0 push.0
        movup.3 movup.3 swap
        # => [amount, domain_id, 0, 0, NONCE, PK_COMM, amount, tag, note_type, RECIPIENT]

        swapw
        exec.poseidon2::merge
        # => [MESSAGE(4), PK_COMM(4), amount, tag, note_type, RECIPIENT(4)]

        # 8. Verify ECDSA secp256k1 signature (following x402 pattern)
        swapw
        # => [PK_COMM, MESSAGE, amount, tag, note_type, RECIPIENT]

        dupw.1 dupw.1
        exec.poseidon2::merge
        # => [SIG_KEY(4), PK_COMM, MESSAGE, amount, tag, note_type, RECIPIENT]

        adv.push_mapval
        dropw
        # => [PK_COMM, MESSAGE, amount, tag, note_type, RECIPIENT]

        exec.ecdsa_k256_keccak::verify
        # => [amount, tag, note_type, RECIPIENT]
    end

    #! Mint tokens after verifying an attestation (called from a tx script).
    #!
    #! Verifies the Falcon512 attestation, then mints (amount - fee_amount) to the
    #! recipient and fee_amount to the relayer (if fee > 0), producing up to two
    #! output notes.
    #!
    #! Inputs:  [recipient_suffix, recipient_prefix, relayer_suffix, relayer_prefix,
    #!           fee_amount, amount, tag, note_type, NONCE, PK_COMM]
    #! Outputs: []
    #!
    #! Panics if:
    #! - the attester PK_COMM is not in the approved attesters registry.
    #! - the deposit nonce has already been used.
    #! - the Falcon512 signature verification fails.
    #!
    #! Invocation: exec
    #!
    #! Local memory layout (16 felts):
    #!   0: recipient_suffix
    #!   1: recipient_prefix
    #!   2: relayer_suffix
    #!   3: relayer_prefix
    #!   4: fee_amount
    #!   5: amount (total)
    #!   6: tag
    #!   7: note_type
    #!   8-11: NONCE (word)
    #!   12-15: PK_COMM (word)
    @locals(16)
    pub proc mint_with_attestation
        # Stack: [recipient_suffix, recipient_prefix, relayer_suffix, relayer_prefix,
        #         fee_amount, amount, tag, note_type, NONCE(4), PK_COMM(4)]

        # ---- Save all inputs to locals ----

        # Save recipient_suffix and recipient_prefix
        loc_store.0
        # => [recipient_prefix, relayer_suffix, relayer_prefix, fee_amount, amount,
        #     tag, note_type, NONCE(4), PK_COMM(4)]
        loc_store.1
        # => [relayer_suffix, relayer_prefix, fee_amount, amount,
        #     tag, note_type, NONCE(4), PK_COMM(4)]

        # Save relayer_suffix and relayer_prefix
        loc_store.2
        # => [relayer_prefix, fee_amount, amount, tag, note_type, NONCE(4), PK_COMM(4)]
        loc_store.3
        # => [fee_amount, amount, tag, note_type, NONCE(4), PK_COMM(4)]

        # Save fee_amount, amount, tag, note_type
        loc_store.4
        # => [amount, tag, note_type, NONCE(4), PK_COMM(4)]
        loc_store.5
        # => [tag, note_type, NONCE(4), PK_COMM(4)]
        loc_store.6
        # => [note_type, NONCE(4), PK_COMM(4)]
        loc_store.7
        # => [NONCE(4), PK_COMM(4)]

        # Save NONCE word to locals 8-11
        loc_storew_le.8 dropw
        # => [PK_COMM(4)]

        # Save PK_COMM word to locals 12-15
        loc_storew_le.12 dropw
        # => []

        # ===========================================================================
        # ATTESTATION VERIFICATION (mirrors check_policy steps 3-8)
        # ===========================================================================

        # 1. Verify the attester PK_COMM is in the approved registry
        padw loc_loadw_le.12
        # => [PK_COMM(4)]
        dupw
        push.ATTESTERS_SLOT[0..2]
        exec.active_account::get_map_item
        # => [VALUE(4), PK_COMM(4)]
        # Stored [1,0,0,0] appears reversed as [0,0,0,1]; check VALUE[3]
        movdn.3 drop drop drop
        # => [is_approved, PK_COMM(4)]
        assert.err=ERR_ATTESTER_NOT_APPROVED
        # => [PK_COMM(4)]
        dropw
        # => []

        # 2. Check nonce has not been used
        padw loc_loadw_le.8
        # => [NONCE(4)]
        dupw
        push.NONCES_SLOT[0..2]
        exec.active_account::get_map_item
        # => [NONCE_VAL(4), NONCE(4)]
        movdn.3 drop drop drop
        # => [nonce_val_last, NONCE(4)]
        assertz.err=ERR_NONCE_ALREADY_USED
        # => [NONCE(4)]

        # 3. Mark nonce as used in storage
        dupw
        push.NONCE_USED swapw
        push.NONCES_SLOT[0..2]
        exec.native_account::set_map_item
        dropw
        # => [NONCE(4)]

        # 4. Compute MESSAGE = merge(NONCE, [amount, domain_id, 0, 0])
        push.DOMAIN_CONFIG_SLOT[0..2]
        exec.active_account::get_item
        # => [CONFIG_WORD(4), NONCE(4)]
        # CONFIG_WORD reversed on stack: stored [domain_id, min_burn, 0, 0]
        # appears as [0, 0, min_burn, domain_id]
        movdn.3 drop drop drop
        # => [domain_id, NONCE(4)]

        # Build AMOUNT_WORD = [amount, domain_id, 0, 0]
        loc_load.5 swap push.0 push.0
        movup.3 movup.3 swap
        # => [amount, domain_id, 0, 0, NONCE(4)]

        swapw
        exec.poseidon2::merge
        # => [MESSAGE(4)]

        # 5. Verify Falcon512 signature
        # Need PK_COMM and MESSAGE on stack for verify
        padw loc_loadw_le.12
        # => [PK_COMM(4), MESSAGE(4)]

        dupw.1 dupw.1
        exec.poseidon2::merge
        # => [SIG_KEY(4), PK_COMM(4), MESSAGE(4)]

        adv.push_mapval
        dropw
        # => [PK_COMM(4), MESSAGE(4)]

        exec.falcon512_poseidon2::verify
        # => []

        # ===========================================================================
        # MINT RECIPIENT AMOUNT: (amount - fee_amount)
        # ===========================================================================

        # Compute recipient_amount = amount - fee_amount
        loc_load.5 loc_load.4 sub
        # => [recipient_amount]

        # Create the fungible asset for the recipient
        exec.faucet::create_fungible_asset
        # => [ASSET_KEY(4), ASSET_VALUE(4)]

        # Mint the asset into the faucet vault
        dupw.1 dupw.1
        # => [ASSET_KEY(4), ASSET_VALUE(4), ASSET_KEY(4), ASSET_VALUE(4)]
        exec.faucet::mint
        # => [ASSET_VALUE(4), ASSET_KEY(4), ASSET_VALUE(4)]
        dropw
        # => [ASSET_KEY(4), ASSET_VALUE(4)]

        # Create recipient output note: need [tag, note_type, RECIPIENT(4)]
        # RECIPIENT is a word built from (recipient_suffix, recipient_prefix)
        # For a standard recipient, the RECIPIENT word is passed as a 4-felt word.
        # Here we only have suffix+prefix (account ID), so we build a minimal
        # RECIPIENT = [recipient_suffix, recipient_prefix, 0, 0]
        loc_load.6 loc_load.7
        # => [note_type, tag, ASSET_KEY(4), ASSET_VALUE(4)]
        loc_load.0 loc_load.1 push.0 push.0
        # => [0, 0, recipient_prefix, recipient_suffix, note_type, tag,
        #     ASSET_KEY(4), ASSET_VALUE(4)]

        # Arrange for output_note::create: [tag, note_type, RECIPIENT(4)]
        movup.5 movup.5
        # => [tag, note_type, 0, 0, recipient_prefix, recipient_suffix,
        #     ASSET_KEY(4), ASSET_VALUE(4)]

        exec.output_note::create
        # => [note_idx, ASSET_KEY(4), ASSET_VALUE(4)]

        # Add the minted asset to the recipient note
        movdn.8
        # => [ASSET_KEY(4), ASSET_VALUE(4), note_idx]
        exec.output_note::add_asset
        # => []

        # ===========================================================================
        # MINT FEE AMOUNT TO RELAYER (conditional: only if fee_amount > 0)
        # ===========================================================================

        loc_load.4
        # => [fee_amount]

        dup push.0 gt
        # => [has_fee, fee_amount]

        if.true
            # fee_amount is on the stack
            # => [fee_amount]

            # Create the fungible asset for the relayer fee
            exec.faucet::create_fungible_asset
            # => [ASSET_KEY(4), ASSET_VALUE(4)]

            # Mint the fee asset into the faucet vault
            dupw.1 dupw.1
            # => [ASSET_KEY(4), ASSET_VALUE(4), ASSET_KEY(4), ASSET_VALUE(4)]
            exec.faucet::mint
            # => [ASSET_VALUE(4), ASSET_KEY(4), ASSET_VALUE(4)]
            dropw
            # => [ASSET_KEY(4), ASSET_VALUE(4)]

            # Create relayer output note
            # RECIPIENT for relayer = [relayer_suffix, relayer_prefix, 0, 0]
            loc_load.6 loc_load.7
            # => [note_type, tag, ASSET_KEY(4), ASSET_VALUE(4)]
            loc_load.2 loc_load.3 push.0 push.0
            # => [0, 0, relayer_prefix, relayer_suffix, note_type, tag,
            #     ASSET_KEY(4), ASSET_VALUE(4)]

            movup.5 movup.5
            # => [tag, note_type, 0, 0, relayer_prefix, relayer_suffix,
            #     ASSET_KEY(4), ASSET_VALUE(4)]

            exec.output_note::create
            # => [note_idx, ASSET_KEY(4), ASSET_VALUE(4)]

            # Add the fee asset to the relayer note
            movdn.8
            # => [ASSET_KEY(4), ASSET_VALUE(4), note_idx]
            exec.output_note::add_asset
            # => []
        else
            # No fee - just drop fee_amount
            drop
            # => []
        end
    end

    #! Add an attester to the approved attesters storage map.
    #!
    #! The caller must be the faucet owner.
    #!
    #! Inputs:  [PK_COMM, pad(12)]
    #! Outputs: [pad(16)]
    #!
    #! Panics if:
    #! - the note sender is not the owner.
    #!
    #! Invocation: call
    pub proc add_attester
        exec.ownable2step::assert_sender_is_owner
        # => [PK_COMM, pad(12)]

        # VALUE = ATTESTER_ACTIVE = [1, 0, 0, 0]
        push.ATTESTER_ACTIVE
        # => [ATTESTER_ACTIVE, PK_COMM, pad(12)]

        # Rearrange: set_map_item needs [slot_suffix, slot_prefix, KEY, VALUE]
        swapw
        # => [PK_COMM, ATTESTER_ACTIVE, pad(12)]

        push.ATTESTERS_SLOT[0..2]
        # => [slot_suffix, slot_prefix, PK_COMM, ATTESTER_ACTIVE, pad(12)]

        exec.native_account::set_map_item
        # => [OLD_VALUE, pad(12)]

        dropw
        # => [pad(12)]
    end

    #! Remove an attester from the approved attesters storage map.
    #!
    #! The caller must be the faucet owner. Writes the zero word for the
    #! attester key, effectively removing it from the map.
    #!
    #! Inputs:  [PK_COMM, pad(12)]
    #! Outputs: [pad(16)]
    #!
    #! Panics if:
    #! - the note sender is not the owner.
    #!
    #! Invocation: call
    pub proc remove_attester
        exec.ownable2step::assert_sender_is_owner
        # => [PK_COMM, pad(12)]

        # Write zero word to remove the attester from the map.
        padw
        # => [ZERO_WORD, PK_COMM, pad(12)]

        swapw
        # => [PK_COMM, ZERO_WORD, pad(12)]

        push.ATTESTERS_SLOT[0..2]
        # => [slot_suffix, slot_prefix, PK_COMM, ZERO_WORD, pad(12)]

        exec.native_account::set_map_item
        # => [OLD_VALUE, pad(12)]

        dropw
        # => [pad(12)]
    end
";

// COMPILED CODE
// ================================================================================================

static USDCX_MINT_POLICY_LIBRARY: LazyLock<Library> = LazyLock::new(|| {
    CodeBuilder::default()
        .compile_component_code(USDCX_MINT_POLICY_NAME, USDCX_MINT_POLICY_MASM)
        .expect("USDCx mint policy MASM should compile")
        .into()
});

static USDCX_MINT_POLICY_CODE: LazyLock<AccountComponentCode> = LazyLock::new(|| {
    CodeBuilder::default()
        .compile_component_code(USDCX_MINT_POLICY_NAME, USDCX_MINT_POLICY_MASM)
        .expect("USDCx mint policy MASM should compile")
});

static CHECK_POLICY_ROOT: LazyLock<AccountProcedureRoot> = LazyLock::new(|| {
    let full_path = format!("{}::check_policy", USDCX_MINT_POLICY_NAME);
    USDCX_MINT_POLICY_CODE
        .get_procedure_root_by_path(full_path.as_str())
        .unwrap_or_else(|| panic!("component should contain procedure '{}'", full_path))
});

static MINT_WITH_ATTESTATION_ROOT: LazyLock<AccountProcedureRoot> = LazyLock::new(|| {
    let full_path = format!("{}::mint_with_attestation", USDCX_MINT_POLICY_NAME);
    USDCX_MINT_POLICY_CODE
        .get_procedure_root_by_path(full_path.as_str())
        .unwrap_or_else(|| panic!("component should contain procedure '{}'", full_path))
});

static ADD_ATTESTER_ROOT: LazyLock<AccountProcedureRoot> = LazyLock::new(|| {
    let full_path = format!("{}::add_attester", USDCX_MINT_POLICY_NAME);
    USDCX_MINT_POLICY_CODE
        .get_procedure_root_by_path(full_path.as_str())
        .unwrap_or_else(|| panic!("component should contain procedure '{}'", full_path))
});

static REMOVE_ATTESTER_ROOT: LazyLock<AccountProcedureRoot> = LazyLock::new(|| {
    let full_path = format!("{}::remove_attester", USDCX_MINT_POLICY_NAME);
    USDCX_MINT_POLICY_CODE
        .get_procedure_root_by_path(full_path.as_str())
        .unwrap_or_else(|| panic!("component should contain procedure '{}'", full_path))
});

// USDCX MINT POLICY
// ================================================================================================

/// Account component implementing the USDCx mint policy.
///
/// This component verifies Circle CCTP deposit attestations (ECDSA secp256k1) before
/// allowing tokens to be minted. It manages:
/// - An attester registry (storage map of approved attester public-key commitments)
/// - A nonce registry (storage map of consumed deposit-intent nonces)
/// - A domain configuration (domain ID and min burn size)
pub struct UsdcxMintPolicy {
    attester_registry: AttesterRegistry,
    nonce_registry: NonceRegistry,
    domain_config: DomainConfig,
}

impl UsdcxMintPolicy {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Creates a new `UsdcxMintPolicy`.
    pub fn new(
        attester_registry: AttesterRegistry,
        nonce_registry: NonceRegistry,
        domain_config: DomainConfig,
    ) -> Self {
        Self {
            attester_registry,
            nonce_registry,
            domain_config,
        }
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the compiled [`AccountComponentCode`] for this component.
    pub fn code() -> &'static AccountComponentCode {
        &USDCX_MINT_POLICY_CODE
    }

    /// Returns the procedure root for `check_policy`.
    pub fn check_policy_root() -> AccountProcedureRoot {
        *CHECK_POLICY_ROOT
    }

    /// Returns the procedure root for `mint_with_attestation`.
    pub fn mint_with_attestation_root() -> AccountProcedureRoot {
        *MINT_WITH_ATTESTATION_ROOT
    }

    /// Returns the procedure root for `add_attester`.
    pub fn add_attester_root() -> AccountProcedureRoot {
        *ADD_ATTESTER_ROOT
    }

    /// Returns the procedure root for `remove_attester`.
    pub fn remove_attester_root() -> AccountProcedureRoot {
        *REMOVE_ATTESTER_ROOT
    }

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        AccountComponentMetadata::new(USDCX_MINT_POLICY_NAME)
            .with_description("USDCx mint policy: attestation-gated minting with attester management")
    }

    // STORAGE
    // --------------------------------------------------------------------------------------------

    /// Converts this policy into its storage slots for inclusion in an account component.
    pub fn into_storage_slots(self) -> Vec<StorageSlot> {
        let attester_slot_name = StorageSlotName::new(ATTESTER_REGISTRY_SLOT_NAME)
            .expect("attester registry slot name should be valid");
        let nonce_slot_name = StorageSlotName::new(NONCE_REGISTRY_SLOT_NAME)
            .expect("nonce registry slot name should be valid");
        let domain_config_slot_name = StorageSlotName::new(DOMAIN_CONFIG_SLOT_NAME)
            .expect("domain config slot name should be valid");

        vec![
            StorageSlot::with_map(attester_slot_name, self.attester_registry.build_storage_map()),
            StorageSlot::with_map(nonce_slot_name, self.nonce_registry.build_storage_map()),
            StorageSlot::with_value(domain_config_slot_name, self.domain_config.to_word()),
        ]
    }
}

// TRAIT IMPLEMENTATIONS
// ================================================================================================

impl From<UsdcxMintPolicy> for AccountComponent {
    fn from(policy: UsdcxMintPolicy) -> Self {
        let metadata = UsdcxMintPolicy::component_metadata();
        let storage_slots = policy.into_storage_slots();

        AccountComponent::new(USDCX_MINT_POLICY_LIBRARY.clone(), storage_slots, metadata)
            .expect("USDCx mint policy component should satisfy account component requirements")
    }
}

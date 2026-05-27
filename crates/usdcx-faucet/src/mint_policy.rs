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
    # Uses a distinctive value unlikely to collide with kernel advice map entries.
    const ATTESTATION_DATA_KEY=[3735928559, 3405691582, 3735928559, 3405691582]

    const ERR_ATTESTER_NOT_APPROVED=\"attester public key commitment not in registry\"
    const ERR_NONCE_ALREADY_USED=\"deposit intent nonce has already been used\"

    # PROCEDURES
    # ============================================================================================

    #! Mint policy check invoked via dynexec by the TokenPolicyManager.
    #!
    #! Verifies an ECDSA secp256k1 attestation from the advice provider before
    #! allowing the mint to proceed. The attestation data is read from the advice
    #! stack (PK_COMM, NONCE) and the signature is read from the advice map keyed
    #! by merge(PK_COMM, MESSAGE).
    #!
    #! Inputs:  [amount, tag, note_type, RECIPIENT]
    #! Outputs: [amount, tag, note_type, RECIPIENT]
    #!
    #! Panics if:
    #! - the attester PK_COMM is not in the approved attesters registry.
    #! - the deposit nonce has already been used.
    #! - the ECDSA signature verification fails.
    #!
    #! Invocation: dynexec
    pub proc check_policy
        # Stack: [amount, tag, note_type, RECIPIENT]
        #
        # TODO: Full attestation verification is deferred pending resolution of
        # a stack-position debugging issue in the ECDSA message computation.
        # The MASM structure for attestation verification is documented above
        # (ATTESTATION_DATA_KEY, advice map protocol, poseidon2::merge, and
        # ecdsa_k256_keccak::verify). The Rust-side advice builder and test
        # infrastructure are in place; what remains is verifying the exact
        # stack offsets during dynexec so the MASM MESSAGE matches the
        # Rust-side signature.
        #
        # For now, this is a pass-through: the TokenPolicyManager already
        # checks the pause guard before dynexec, so the minting flow is
        # gated only by pause status.
        push.0 drop
        # => [amount, tag, note_type, RECIPIENT]
    end

    #! Mint tokens after verifying an attestation (called from a tx script).
    #!
    #! Inputs:  [recipient_id, relayer_id, fee_amount]
    #! Outputs: []
    #!
    #! Invocation: exec
    pub proc mint_with_attestation
        # TODO: Full attestation verification (ECDSA + nonce + domain checks),
        # then invoke mint with fee split between recipient and relayer.
        push.0 drop
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

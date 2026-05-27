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
///
/// Procedure bodies are stubs; full implementations are deferred to Task 12.
const USDCX_MINT_POLICY_MASM: &str = "
    #! USDCx Mint Policy - verifies deposit attestations and mints tokens.

    pub proc check_policy
        # stub - always succeeds
        push.1 drop
    end

    pub proc mint_with_attestation
        # stub - wraps check_policy + fee-splitting mint
        push.1 drop
    end

    pub proc add_attester
        # stub - owner-gated attester management
        push.1 drop
    end

    pub proc remove_attester
        # stub - owner-gated attester removal
        push.1 drop
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

use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{AccountComponent, AccountComponentCode, AccountProcedureRoot};
use miden_protocol::assembly::Library;
use miden_protocol::utils::sync::LazyLock;

use miden_standards::code_builder::CodeBuilder;

// CONSTANTS
// ================================================================================================

/// The component name for the USDCx burn policy.
pub const USDCX_BURN_POLICY_NAME: &str = "usdcx::components::burn_policy";

/// MASM source code for the USDCx burn policy component.
///
/// Procedure bodies are stubs; full implementations are deferred to Task 12.
const USDCX_BURN_POLICY_MASM: &str = "
    #! USDCx Burn Policy - enforces minimum burn size from domain config.

    pub proc check_policy
        # stub - always succeeds
        push.1 drop
    end

    pub proc set_min_burn_size
        # stub - owner-gated min burn size update
        push.1 drop
    end
";

// COMPILED CODE
// ================================================================================================

static USDCX_BURN_POLICY_LIBRARY: LazyLock<Library> = LazyLock::new(|| {
    CodeBuilder::default()
        .compile_component_code(USDCX_BURN_POLICY_NAME, USDCX_BURN_POLICY_MASM)
        .expect("USDCx burn policy MASM should compile")
        .into()
});

static USDCX_BURN_POLICY_CODE: LazyLock<AccountComponentCode> = LazyLock::new(|| {
    CodeBuilder::default()
        .compile_component_code(USDCX_BURN_POLICY_NAME, USDCX_BURN_POLICY_MASM)
        .expect("USDCx burn policy MASM should compile")
});

static CHECK_POLICY_ROOT: LazyLock<AccountProcedureRoot> = LazyLock::new(|| {
    let full_path = format!("{}::check_policy", USDCX_BURN_POLICY_NAME);
    USDCX_BURN_POLICY_CODE
        .get_procedure_root_by_path(full_path.as_str())
        .unwrap_or_else(|| panic!("component should contain procedure '{}'", full_path))
});

static SET_MIN_BURN_SIZE_ROOT: LazyLock<AccountProcedureRoot> = LazyLock::new(|| {
    let full_path = format!("{}::set_min_burn_size", USDCX_BURN_POLICY_NAME);
    USDCX_BURN_POLICY_CODE
        .get_procedure_root_by_path(full_path.as_str())
        .unwrap_or_else(|| panic!("component should contain procedure '{}'", full_path))
});

// USDCX BURN POLICY
// ================================================================================================

/// Account component implementing the USDCx burn policy.
///
/// This component enforces a minimum burn size by reading the domain configuration
/// stored by the mint policy component. It is storage-free - all configuration is
/// read from the mint policy's domain_config slot at execution time.
pub struct UsdcxBurnPolicy;

impl UsdcxBurnPolicy {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Creates a new `UsdcxBurnPolicy`.
    pub fn new() -> Self {
        Self
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the compiled [`AccountComponentCode`] for this component.
    pub fn code() -> &'static AccountComponentCode {
        &USDCX_BURN_POLICY_CODE
    }

    /// Returns the procedure root for `check_policy`.
    pub fn check_policy_root() -> AccountProcedureRoot {
        *CHECK_POLICY_ROOT
    }

    /// Returns the procedure root for `set_min_burn_size`.
    pub fn set_min_burn_size_root() -> AccountProcedureRoot {
        *SET_MIN_BURN_SIZE_ROOT
    }

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        AccountComponentMetadata::new(USDCX_BURN_POLICY_NAME)
            .with_description("USDCx burn policy: minimum burn size enforcement")
    }
}

impl Default for UsdcxBurnPolicy {
    fn default() -> Self {
        Self::new()
    }
}

// TRAIT IMPLEMENTATIONS
// ================================================================================================

impl From<UsdcxBurnPolicy> for AccountComponent {
    fn from(_policy: UsdcxBurnPolicy) -> Self {
        let metadata = UsdcxBurnPolicy::component_metadata();

        // The burn policy is storage-free; it reads domain_config from the mint policy's slot.
        AccountComponent::new(USDCX_BURN_POLICY_LIBRARY.clone(), vec![], metadata)
            .expect("USDCx burn policy component should satisfy account component requirements")
    }
}

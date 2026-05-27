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
    use miden::protocol::active_account
    use miden::protocol::native_account
    use miden::standards::access::ownable2step

    # CONSTANTS
    # ============================================================================================

    const DOMAIN_CONFIG_SLOT=word(\"usdcx::domain_config\")
    const ERR_BELOW_MIN_BURN_SIZE=\"burn amount is below minimum burn size\"

    # PROCEDURES
    # ============================================================================================

    #! Burn policy check invoked via dynexec by the TokenPolicyManager.
    #!
    #! Reads the minimum burn size from the domain config slot and asserts
    #! that the burn amount is at least that large.
    #!
    #! Inputs:  [ASSET_KEY, ASSET_VALUE]
    #! Outputs: []
    #!
    #! Panics if:
    #! - the burn amount is below the configured minimum burn size.
    #!
    #! Invocation: dynexec
    pub proc check_policy
        # Drop ASSET_KEY (top 4 elements), leaving ASSET_VALUE
        dropw
        # => [amount, 0, 0, 0]

        # Keep amount, discard padding
        movdn.3 drop drop drop
        # => [amount]

        # Read domain_config: [domain_id, min_burn_size, 0, 0]
        push.DOMAIN_CONFIG_SLOT[0..2]
        exec.active_account::get_item
        # => [domain_id, min_burn_size, 0, 0, amount]

        # Extract min_burn_size
        swap drop
        # => [min_burn_size, 0, 0, amount]

        movdn.2 drop drop
        # => [min_burn_size, amount]

        # Assert amount >= min_burn_size (i.e. min_burn_size <= amount)
        u32assert2 u32lte
        # => [min_burn_size <= amount]

        assert.err=ERR_BELOW_MIN_BURN_SIZE
        # => []
    end

    #! Update the minimum burn size in the domain config.
    #!
    #! The caller must be the faucet owner. Reads the current domain config,
    #! replaces the min_burn_size field, and writes the updated word back.
    #!
    #! Inputs:  [new_min_burn_size, pad(15)]
    #! Outputs: [pad(16)]
    #!
    #! Panics if:
    #! - the note sender is not the owner.
    #!
    #! Invocation: call
    pub proc set_min_burn_size
        exec.ownable2step::assert_sender_is_owner
        # => [new_min_burn_size, pad(15)]

        # Read current domain_config: [domain_id, old_min_burn_size, 0, 0]
        push.DOMAIN_CONFIG_SLOT[0..2]
        exec.active_account::get_item
        # => [domain_id, old_min_burn_size, 0, 0, new_min_burn_size, pad(15)]

        # Rearrange: swap new_min_burn_size into position 1, keep old_min_burn_size
        # for stack depth preservation.
        movup.4
        # => [new_min_burn_size, domain_id, old_min_burn_size, 0, 0, pad(15)]

        swap
        # => [domain_id, new_min_burn_size, old_min_burn_size, 0, 0, pad(15)]

        # Move old_min_burn_size past the word boundary
        movup.2
        # => [old_min_burn_size, domain_id, new_min_burn_size, 0, 0, pad(15)]

        movdn.4
        # => [domain_id, new_min_burn_size, 0, 0, old_min_burn_size, pad(15)]

        # Write updated config word [domain_id, new_min_burn_size, 0, 0]
        push.DOMAIN_CONFIG_SLOT[0..2]
        # => [slot_s, slot_p, domain_id, new_min_burn_size, 0, 0, old_min_burn_size, pad(15)]

        exec.native_account::set_item
        # => [OLD_VALUE, old_min_burn_size, pad(15)]

        dropw
        # => [old_min_burn_size, pad(15)] = pad(16)
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

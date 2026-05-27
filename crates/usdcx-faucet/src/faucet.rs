use miden_protocol::account::{Account, AccountBuilder, AccountId, AccountType};
use miden_protocol::asset::AssetAmount;
use thiserror::Error;

use miden_standards::account::access::{AccessControl, PausableManager};
use miden_standards::account::faucets::{FungibleFaucet, FungibleFaucetError, TokenName};
use miden_standards::account::policies::{
    BlocklistOwnerControlled, BurnPolicyConfig, MintPolicyConfig, PolicyRegistration,
    TokenPolicyManager, TokenPolicyManagerError, TransferPolicy,
};
use miden_standards::AuthMethod;

use crate::attester_registry::AttesterRegistry;
use crate::burn_policy::UsdcxBurnPolicy;
use crate::domain_config::DomainConfig;
use crate::mint_policy::UsdcxMintPolicy;
use crate::nonce_registry::NonceRegistry;

// CONSTANTS
// ================================================================================================

/// Token name for USDCx.
const USDCX_TOKEN_NAME: &str = "USDCx";

/// Token symbol for USDCx.
const USDCX_TOKEN_SYMBOL: &str = "USDCX";

/// Number of decimals for USDCx (matching USDC's 6 decimals).
const USDCX_DECIMALS: u8 = 6;

// ERRORS
// ================================================================================================

/// Errors that can occur when creating a USDCx faucet account.
#[derive(Debug, Error)]
pub enum UsdcxFaucetError {
    #[error("fungible faucet error")]
    FungibleFaucet(#[from] FungibleFaucetError),

    #[error("token policy manager error")]
    TokenPolicyManager(#[from] TokenPolicyManagerError),

    #[error("account builder error")]
    AccountBuilder(#[from] miden_protocol::errors::AccountError),
}

// CONFIG
// ================================================================================================

/// Configuration for creating a USDCx faucet account.
pub struct UsdcxFaucetConfig {
    /// Random seed used to derive the account ID.
    pub init_seed: [u8; 32],
    /// Maximum supply of USDCx tokens (in base units, i.e. 10^6 = 1 USDC).
    pub max_supply: u64,
    /// The account ID of the faucet owner (for Ownable2Step access control).
    pub owner: AccountId,
    /// Authentication method for the faucet account.
    pub auth_method: AuthMethod,
    /// Circle CCTP domain ID for this chain.
    pub domain_id: u32,
    /// Minimum burn size in base units.
    pub min_burn_size: u64,
    /// Initial set of attester public-key commitments.
    pub initial_attesters: Vec<miden_protocol::Word>,
}

// FACTORY
// ================================================================================================

/// Creates a fully composed USDCx faucet account.
///
/// The account is assembled from the following components:
/// - `FungibleFaucet` - standard fungible token with name "USDCx", symbol "USDCX", 6 decimals
/// - `Ownable2Step` + `Authority::OwnerControlled` - single-owner access control
/// - `PausableManager` - pause/unpause administration
/// - `TokenPolicyManager` with:
///   - Mint policy: custom `UsdcxMintPolicy` (attestation-gated minting)
///   - Burn policy: custom `UsdcxBurnPolicy` (minimum burn size enforcement)
///   - Send policy: `TransferPolicy::Blocklist` (blocklist-based send filtering)
///   - Receive policy: `TransferPolicy::Blocklist` (blocklist-based receive filtering)
/// - `BasicBlocklist` - per-faucet blocklist storage (initially empty)
/// - `BlocklistOwnerControlled` - owner-gated blocklist administration
/// - `UsdcxMintPolicy` - attestation verification and attester/nonce management
/// - `UsdcxBurnPolicy` - minimum burn size enforcement
pub fn create_usdcx_faucet(config: UsdcxFaucetConfig) -> Result<Account, UsdcxFaucetError> {
    let token_name =
        TokenName::new(USDCX_TOKEN_NAME).expect("USDCx token name should be valid");
    let token_symbol = miden_protocol::asset::TokenSymbol::new(USDCX_TOKEN_SYMBOL)
        .expect("USDCX token symbol should be valid");

    // Build the FungibleFaucet component.
    let faucet = FungibleFaucet::builder()
        .name(token_name)
        .symbol(token_symbol)
        .decimals(USDCX_DECIMALS)
        .max_supply(AssetAmount::try_from(config.max_supply).expect("max_supply should be valid"))
        .build()?;

    // Build the custom mint policy component.
    let attester_registry = AttesterRegistry::new(config.initial_attesters)
        .expect("at least one attester is required");
    let nonce_registry = NonceRegistry::new();
    let domain_config = DomainConfig::new(config.domain_id, config.min_burn_size);
    let mint_policy = UsdcxMintPolicy::new(attester_registry, nonce_registry, domain_config);

    // Build the custom burn policy component.
    let burn_policy = UsdcxBurnPolicy::new();

    // Build the token policy manager with custom mint/burn and blocklist-based transfer policies.
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

    // Access control: Ownable2Step with owner-controlled authority.
    let access_control = AccessControl::Ownable2Step { owner: config.owner };

    // Build the auth component based on the provided auth method, then compose the account.
    // We follow the same pattern as create_fungible_faucet but add our custom components.
    let account = AccountBuilder::new(config.init_seed)
        .account_type(AccountType::Public)
        .with_auth_component(build_auth_component(&access_control, config.auth_method)?)
        .with_component(faucet)
        .with_components(access_control)
        .with_components(token_policy_manager)
        .with_component(PausableManager)
        .with_component(mint_policy)
        .with_component(burn_policy)
        .with_component(BlocklistOwnerControlled)
        .build()?;

    Ok(account)
}

/// Builds the account-level auth component for the given access control and auth method.
///
/// For USDCx, we use Ownable2Step access control, which supports NetworkAccount or NoAuth.
fn build_auth_component(
    access_control: &AccessControl,
    auth_method: AuthMethod,
) -> Result<miden_protocol::account::AccountComponent, UsdcxFaucetError> {
    use miden_standards::account::auth::{AuthNetworkAccount, NoAuth};

    match (access_control, auth_method) {
        // Ownable2Step + NetworkAccount: typical network-style faucet.
        (
            AccessControl::Ownable2Step { .. },
            AuthMethod::NetworkAccount { allowed_script_roots },
        ) => Ok(AuthNetworkAccount::with_allowlist(allowed_script_roots)
            .map_err(|err| {
                UsdcxFaucetError::FungibleFaucet(FungibleFaucetError::UnsupportedAuthMethod(
                    format!("invalid network account allowlist: {err}"),
                ))
            })?
            .into()),

        // Ownable2Step + NoAuth: valid; the setter gate is the in-procedure owner check.
        (AccessControl::Ownable2Step { .. }, AuthMethod::NoAuth) => Ok(NoAuth::new().into()),

        // All other combinations are unsupported for USDCx.
        _ => Err(UsdcxFaucetError::FungibleFaucet(
            FungibleFaucetError::UnsupportedAccessControlAuthCombination(
                "USDCx faucet requires Ownable2Step access control with NetworkAccount or NoAuth \
                 authentication"
                    .into(),
            ),
        )),
    }
}

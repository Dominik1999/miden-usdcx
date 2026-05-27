// Shared test helpers for USDCx integration tests.

use miden_protocol::account::{Account, AccountId};
use miden_protocol::{Felt, Word, ZERO};
use miden_standards::AuthMethod;
use usdcx_faucet::faucet::{UsdcxFaucetConfig, UsdcxFaucetError, create_usdcx_faucet};

// CONSTANTS
// ================================================================================================

pub const TEST_DOMAIN_ID: u32 = 99999;
pub const TEST_MIN_BURN_SIZE: u64 = 1_000;
pub const TEST_MAX_SUPPLY: u64 = 1_000_000_000_000;

// HELPERS
// ================================================================================================

/// Creates a deterministic `PK_COMM` word for testing, keyed by `index`.
///
/// Each index produces a unique, reproducible word so tests can register
/// distinct attesters without coordination.
pub fn mock_attester_pk_comm(index: u8) -> Word {
    Word::new([
        Felt::new_unchecked(index as u64 + 1),
        Felt::new_unchecked(index as u64 + 2),
        Felt::new_unchecked(index as u64 + 3),
        ZERO,
    ])
}

/// Creates a USDCx faucet with default test configuration.
///
/// Uses `TEST_DOMAIN_ID`, `TEST_MIN_BURN_SIZE`, and `TEST_MAX_SUPPLY` as defaults.
/// The faucet is created with `AuthMethod::NoAuth` for simplicity in tests.
/// A single deterministic attester (index 0) is registered.
pub fn create_test_usdcx_faucet(
    owner_id: AccountId,
) -> Result<Account, UsdcxFaucetError> {
    let config = UsdcxFaucetConfig {
        init_seed: [0u8; 32],
        max_supply: TEST_MAX_SUPPLY,
        owner: owner_id,
        auth_method: AuthMethod::NoAuth,
        domain_id: TEST_DOMAIN_ID,
        min_burn_size: TEST_MIN_BURN_SIZE,
        initial_attesters: vec![mock_attester_pk_comm(0)],
    };
    create_usdcx_faucet(config)
}

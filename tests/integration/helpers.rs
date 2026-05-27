// Shared test helpers for USDCx integration tests.

use miden_protocol::{Felt, Word, ZERO};

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

// TODO(Task 7): Uncomment once `create_usdcx_faucet` is implemented in
// `usdcx_faucet::faucet`.
//
// use miden_protocol::account::{Account, AccountId};
// use usdcx_faucet::{
//     domain_config::DomainConfig,
//     faucet::create_usdcx_faucet,
// };
//
// /// Creates a USDCx faucet with default test configuration.
// pub fn create_test_usdcx_faucet(owner_id: AccountId) -> anyhow::Result<Account> {
//     let domain_config = DomainConfig::new(TEST_DOMAIN_ID, TEST_MIN_BURN_SIZE);
//     create_usdcx_faucet(owner_id, domain_config, TEST_MAX_SUPPLY)
// }

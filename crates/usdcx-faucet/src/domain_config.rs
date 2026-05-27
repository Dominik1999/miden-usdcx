use miden_protocol::{Felt, Word, ZERO};

// CONSTANTS
// ================================================================================================

/// Storage slot name for the domain configuration.
pub const DOMAIN_CONFIG_SLOT_NAME: &str = "usdcx::domain_config";

// DOMAIN CONFIG
// ================================================================================================

/// Per-domain configuration stored in faucet account storage.
///
/// Storage word layout: `[domain_id, min_burn_size, 0, 0]`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DomainConfig {
    /// The Circle CCTP domain ID for this chain.
    pub domain_id: u32,
    /// The minimum amount (in base units) that must be burned per operation.
    pub min_burn_size: u64,
}

impl DomainConfig {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Creates a new `DomainConfig`.
    pub fn new(domain_id: u32, min_burn_size: u64) -> Self {
        Self { domain_id, min_burn_size }
    }

    // SERIALIZATION
    // --------------------------------------------------------------------------------------------

    /// Serializes this config to a storage `Word`.
    ///
    /// Layout: `[domain_id, min_burn_size, 0, 0]`
    pub fn to_word(&self) -> Word {
        Word::new([
            Felt::new_unchecked(self.domain_id as u64),
            Felt::new_unchecked(self.min_burn_size),
            ZERO,
            ZERO,
        ])
    }

    /// Deserializes a `DomainConfig` from a storage `Word`.
    ///
    /// The word must follow the layout produced by [`to_word`](Self::to_word).
    pub fn from_word(word: Word) -> Self {
        let domain_id = word[0].as_canonical_u64() as u32;
        let min_burn_size = word[1].as_canonical_u64();
        Self { domain_id, min_burn_size }
    }
}

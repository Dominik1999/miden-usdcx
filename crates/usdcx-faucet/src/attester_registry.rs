use miden_protocol::account::{StorageMap, StorageMapKey};
use miden_protocol::{ONE, Word, ZERO};
use thiserror::Error;

// CONSTANTS
// ================================================================================================

/// Storage slot name for the attester registry map.
pub const ATTESTER_REGISTRY_SLOT_NAME: &str = "usdcx::attesters";

/// Value stored for each active attester: `[1, 0, 0, 0]`.
pub const ATTESTER_ACTIVE: Word = Word::new([ONE, ZERO, ZERO, ZERO]);

// ERRORS
// ================================================================================================

#[derive(Debug, Error)]
pub enum AttesterRegistryError {
    #[error("at least one attester is required")]
    NoAttesters,
}

// ATTESTER REGISTRY
// ================================================================================================

/// An initial set of attester public-key commitments stored in a `StorageMap`.
///
/// Each entry maps `PK_COMM -> ATTESTER_ACTIVE` where `PK_COMM` is a `Word` representing
/// the public-key commitment of a registered attester.
pub struct AttesterRegistry {
    attesters: Vec<Word>,
}

impl AttesterRegistry {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Creates a new `AttesterRegistry` from a list of attester public-key commitments.
    ///
    /// # Errors
    ///
    /// Returns `AttesterRegistryError::NoAttesters` if `attesters` is empty.
    pub fn new(attesters: Vec<Word>) -> Result<Self, AttesterRegistryError> {
        if attesters.is_empty() {
            return Err(AttesterRegistryError::NoAttesters);
        }
        Ok(Self { attesters })
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the list of attester public-key commitments.
    pub fn attesters(&self) -> &[Word] {
        &self.attesters
    }

    // STORAGE
    // --------------------------------------------------------------------------------------------

    /// Builds a `StorageMap` mapping each `PK_COMM -> ATTESTER_ACTIVE`.
    ///
    /// This map is intended to be stored in the faucet account's storage slot named
    /// [`ATTESTER_REGISTRY_SLOT_NAME`].
    pub fn build_storage_map(&self) -> StorageMap {
        let entries = self
            .attesters
            .iter()
            .map(|pk_comm| (StorageMapKey::new(*pk_comm), ATTESTER_ACTIVE));

        StorageMap::with_entries(entries)
            .expect("attester public-key commitments must be unique")
    }
}

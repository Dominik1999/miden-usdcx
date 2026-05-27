use miden_protocol::account::StorageMap;
use miden_protocol::{ONE, Word, ZERO};

// CONSTANTS
// ================================================================================================

/// Storage slot name for the used-nonces map.
pub const NONCE_REGISTRY_SLOT_NAME: &str = "usdcx::used_nonces";

/// Value stored for each used nonce: `[1, 0, 0, 0]`.
pub const NONCE_USED: Word = Word::new([ONE, ZERO, ZERO, ZERO]);

// NONCE REGISTRY
// ================================================================================================

/// Registry of consumed deposit-intent nonces, stored as a `StorageMap`.
///
/// At genesis the registry is empty - no nonces have been spent yet.
/// During transaction execution the MASM kernel inserts entries as nonces are consumed.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct NonceRegistry;

impl NonceRegistry {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Creates a new empty `NonceRegistry`.
    pub fn new() -> Self {
        Self
    }

    // STORAGE
    // --------------------------------------------------------------------------------------------

    /// Returns an empty `StorageMap` (no nonces have been spent at genesis).
    ///
    /// This map is intended to be stored in the faucet account's storage slot named
    /// [`NONCE_REGISTRY_SLOT_NAME`].
    pub fn build_storage_map(&self) -> StorageMap {
        StorageMap::new()
    }
}

use miden_protocol::account::AccountId;
use miden_protocol::{Felt, Hasher, Word, ZERO};
use thiserror::Error;

// CONSTANTS
// ================================================================================================

pub const DEPOSIT_INTENT_MAGIC: u32 = 0x5a2e_0acd;
pub const DEPOSIT_INTENT_VERSION: u32 = 1;

// ERRORS
// ================================================================================================

#[derive(Debug, Error)]
pub enum DepositIntentError {
    #[error("invalid magic: expected {expected:#010x}, got {got:#010x}")]
    InvalidMagic { expected: u32, got: u32 },

    #[error("unsupported version: expected {expected}, got {got}")]
    InvalidVersion { expected: u32, got: u32 },

    #[error("domain mismatch: expected {expected}, got {got}")]
    DomainMismatch { expected: u32, got: u32 },

    #[error("token mismatch: remote_token {remote_token} does not match faucet {faucet}")]
    TokenMismatch {
        remote_token: AccountId,
        faucet: AccountId,
    },

    #[error("amount is zero")]
    ZeroAmount,

    #[error("amount {amount} is less than max_fee {max_fee}")]
    AmountBelowMaxFee { amount: u64, max_fee: u64 },

    #[error("local_token is zero (all bytes are 0)")]
    ZeroLocalToken,

    #[error("local_depositor is zero (all bytes are 0)")]
    ZeroLocalDepositor,
}

// DEPOSIT INTENT
// ================================================================================================

/// A Circle CCTP deposit intent carried in the advice stack.
///
/// Layout (Circle spec):
/// - magic            : identifies this as a deposit intent (0x5a2e0acd)
/// - version          : protocol version (must be 1)
/// - amount           : token amount (in smallest unit)
/// - remote_domain    : target chain's Circle domain ID
/// - remote_token     : faucet's AccountId on Miden
/// - remote_recipient : 32-byte recipient address on Miden
/// - local_token      : 32-byte source USDC contract on Ethereum
/// - local_depositor  : 32-byte depositor address on Ethereum
/// - max_fee          : maximum fee the depositor accepts
/// - nonce            : 32-byte unique nonce for replay protection
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepositIntent {
    pub magic: u32,
    pub version: u32,
    pub nonce: [u8; 32],
    pub amount: u64,
    pub max_fee: u64,
    pub remote_domain: u32,
    pub remote_token: AccountId,
    pub remote_recipient: [u8; 32],
    pub local_token: [u8; 32],
    pub local_depositor: [u8; 32],
}

impl DepositIntent {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Creates a new `DepositIntent` with the canonical magic and version constants pre-set.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        nonce: [u8; 32],
        amount: u64,
        max_fee: u64,
        remote_domain: u32,
        remote_token: AccountId,
        remote_recipient: [u8; 32],
        local_token: [u8; 32],
        local_depositor: [u8; 32],
    ) -> Self {
        Self {
            magic: DEPOSIT_INTENT_MAGIC,
            version: DEPOSIT_INTENT_VERSION,
            nonce,
            amount,
            max_fee,
            remote_domain,
            remote_token,
            remote_recipient,
            local_token,
            local_depositor,
        }
    }

    // VALIDATION
    // --------------------------------------------------------------------------------------------

    /// Validates this intent against the Circle CCTP spec preconditions.
    ///
    /// Checks:
    /// 1. `magic` matches `DEPOSIT_INTENT_MAGIC`
    /// 2. `version` matches `DEPOSIT_INTENT_VERSION`
    /// 3. `remote_domain` matches the chain's `expected_domain`
    /// 4. `remote_token` matches the `faucet_id`
    /// 5. `amount` is non-zero
    /// 6. `amount` >= `max_fee` (Circle spec: amount must be at least max_fee)
    /// 7. `local_token` is not zero
    /// 8. `local_depositor` is not zero
    pub fn validate(
        &self,
        expected_domain: u32,
        faucet_id: AccountId,
    ) -> Result<(), DepositIntentError> {
        if self.magic != DEPOSIT_INTENT_MAGIC {
            return Err(DepositIntentError::InvalidMagic {
                expected: DEPOSIT_INTENT_MAGIC,
                got: self.magic,
            });
        }

        if self.version != DEPOSIT_INTENT_VERSION {
            return Err(DepositIntentError::InvalidVersion {
                expected: DEPOSIT_INTENT_VERSION,
                got: self.version,
            });
        }

        if self.remote_domain != expected_domain {
            return Err(DepositIntentError::DomainMismatch {
                expected: expected_domain,
                got: self.remote_domain,
            });
        }

        if self.remote_token != faucet_id {
            return Err(DepositIntentError::TokenMismatch {
                remote_token: self.remote_token,
                faucet: faucet_id,
            });
        }

        if self.amount == 0 {
            return Err(DepositIntentError::ZeroAmount);
        }

        if self.amount < self.max_fee {
            return Err(DepositIntentError::AmountBelowMaxFee {
                amount: self.amount,
                max_fee: self.max_fee,
            });
        }

        if self.local_token == [0u8; 32] {
            return Err(DepositIntentError::ZeroLocalToken);
        }

        if self.local_depositor == [0u8; 32] {
            return Err(DepositIntentError::ZeroLocalDepositor);
        }

        Ok(())
    }

    // SERIALIZATION
    // --------------------------------------------------------------------------------------------

    /// Serializes this intent to a `Vec<Felt>` suitable for pushing onto the Miden advice stack.
    ///
    /// Encoding (8 u32 felts per bytes32, AggLayer convention):
    /// - [0]      : magic      (u32, fits in a felt)
    /// - [1]      : version    (u32, fits in a felt)
    /// - [2..9]   : nonce (32 bytes as 8 felts, one u32 per felt)
    /// - [10]     : amount
    /// - [11]     : max_fee
    /// - [12]     : remote_domain (u32, fits in a felt)
    /// - [13..14] : remote_token (2 Felts from AccountId)
    /// - [15..22] : remote_recipient (32 bytes as 8 felts, one u32 per felt)
    /// - [23..30] : local_token (32 bytes as 8 felts, one u32 per felt)
    /// - [31..38] : local_depositor (32 bytes as 8 felts, one u32 per felt)
    pub fn to_advice_felts(&self) -> Vec<Felt> {
        let mut out = Vec::with_capacity(39);

        out.push(Felt::new_unchecked(self.magic as u64));
        out.push(Felt::new_unchecked(self.version as u64));

        out.extend(bytes32_to_felts(&self.nonce));

        out.push(Felt::new_unchecked(self.amount));
        out.push(Felt::new_unchecked(self.max_fee));
        out.push(Felt::new_unchecked(self.remote_domain as u64));

        let id_felts: [Felt; 2] = self.remote_token.into();
        out.push(id_felts[0]);
        out.push(id_felts[1]);

        out.extend(bytes32_to_felts(&self.remote_recipient));
        out.extend(bytes32_to_felts(&self.local_token));
        out.extend(bytes32_to_felts(&self.local_depositor));

        out
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Computes the Poseidon2 message hash over all critical depositIntent fields.
    ///
    /// This is the message that the attester signs. It covers:
    /// magic, version, nonce(8), amount, max_fee, remote_domain,
    /// remote_token(2), remote_recipient(8), local_token(8), local_depositor(8).
    ///
    /// Total: 39 felts hashed via `Hasher::hash_elements`.
    pub fn message_hash(&self) -> Word {
        Hasher::hash_elements(&self.to_advice_felts())
    }

    /// Returns the nonce as a `Word` for use as a storage map key.
    ///
    /// The 32-byte nonce is first expanded to 8 u32 felts (AggLayer convention),
    /// then hashed via Poseidon2 to produce a single Word (4 felts) suitable
    /// for storage map lookups and message hash computation.
    pub fn nonce_key(&self) -> Word {
        bytes32_to_key(&self.nonce)
    }
}

// BYTES32 <-> FELTS ENCODING
// ================================================================================================

/// Converts a 32-byte array into 8 felts, one u32 per felt (little-endian).
///
/// This is the standard Miden convention for bytes32: each 4-byte chunk
/// becomes one u32 value stored in a felt. No packing, no Goldilocks
/// overflow possible.
pub fn bytes32_to_felts(bytes: &[u8; 32]) -> [Felt; 8] {
    let mut felts = [ZERO; 8];
    for i in 0..8 {
        let limb = u32::from_le_bytes(bytes[i * 4..i * 4 + 4].try_into().unwrap());
        felts[i] = Felt::new_unchecked(limb as u64);
    }
    felts
}

/// Converts 8 felts back into a 32-byte array (inverse of `bytes32_to_felts`).
pub fn felts_to_bytes32(felts: &[Felt; 8]) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for i in 0..8 {
        let limb = felts[i].as_canonical_u64() as u32;
        bytes[i * 4..i * 4 + 4].copy_from_slice(&limb.to_le_bytes());
    }
    bytes
}

/// Hashes a bytes32 (8 felts) into a Word for use as a storage map key.
///
/// Uses Poseidon2 hash to compress 8 felts into 4 felts (1 Word).
pub fn bytes32_to_key(bytes: &[u8; 32]) -> Word {
    let felts = bytes32_to_felts(bytes);
    Hasher::hash_elements(&felts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes32_felts_roundtrip() {
        let original: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        ];
        let felts = bytes32_to_felts(&original);
        let recovered = felts_to_bytes32(&felts);
        assert_eq!(original, recovered);
    }

    #[test]
    fn bytes32_felts_zero() {
        let zero = [0u8; 32];
        let felts = bytes32_to_felts(&zero);
        assert_eq!(felts, [ZERO; 8]);
        assert_eq!(felts_to_bytes32(&felts), zero);
    }

    #[test]
    fn bytes32_felts_max_u32() {
        // Every byte 0xFF: each u32 limb is 0xFFFFFFFF, which fits in a felt.
        let bytes = [0xFF; 32];
        let felts = bytes32_to_felts(&bytes);
        for felt in &felts {
            assert_eq!(felt.as_canonical_u64(), 0xFFFF_FFFF);
        }
        let recovered = felts_to_bytes32(&felts);
        assert_eq!(bytes, recovered);
    }

    #[test]
    fn bytes32_felts_individual_limbs() {
        // Verify each 4-byte chunk maps to the correct felt.
        let mut bytes = [0u8; 32];
        for i in 0..8 {
            let val = (i as u32 + 1) * 0x1111_1111;
            bytes[i * 4..i * 4 + 4].copy_from_slice(&val.to_le_bytes());
        }
        let felts = bytes32_to_felts(&bytes);
        for i in 0..8 {
            let expected = (i as u64 + 1) * 0x1111_1111;
            assert_eq!(felts[i].as_canonical_u64(), expected);
        }
    }

    #[test]
    fn bytes32_to_key_deterministic() {
        let bytes: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        ];
        let key1 = bytes32_to_key(&bytes);
        let key2 = bytes32_to_key(&bytes);
        assert_eq!(key1, key2);
    }

    #[test]
    fn bytes32_previously_overflowing_now_works() {
        // hi=0xFFFFFFFF, lo=0x00000001 would have overflowed with packed encoding.
        // With 8 u32 felts, every u32 fits trivially.
        let mut bytes = [0u8; 32];
        bytes[0..4].copy_from_slice(&0x0000_0001u32.to_le_bytes());
        bytes[4..8].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        let felts = bytes32_to_felts(&bytes);
        assert_eq!(felts[0].as_canonical_u64(), 1);
        assert_eq!(felts[1].as_canonical_u64(), 0xFFFF_FFFF);
        let recovered = felts_to_bytes32(&felts);
        assert_eq!(bytes, recovered);
    }
}


use miden_protocol::account::AccountId;
use miden_protocol::{Felt, Word, ZERO};
use thiserror::Error;

// CONSTANTS
// ================================================================================================

pub const DEPOSIT_INTENT_MAGIC: u32 = 0x5a2e_0acd;
pub const DEPOSIT_INTENT_VERSION: u32 = 1;

/// The Goldilocks prime: p = 2^64 - 2^32 + 1.
const GOLDILOCKS_PRIME: u128 = (1u128 << 64) - (1u128 << 32) + 1;

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

    #[error("amount {amount} is not greater than max_fee {max_fee}")]
    AmountBelowMaxFee { amount: u64, max_fee: u64 },
}

// DEPOSIT INTENT
// ================================================================================================

/// A Circle CCTP deposit intent carried in the advice stack.
///
/// Layout (Circle spec):
/// - magic          : identifies this as a deposit intent
/// - version        : protocol version
/// - nonce          : 32-byte unique nonce
/// - amount         : token amount (in smallest unit)
/// - max_fee        : maximum fee the depositor accepts
/// - remote_domain  : the Circle domain ID of the source chain
/// - remote_token   : the AccountId of the token on the source chain
/// - local_token    : 32-byte commitment identifying the local token
/// - local_depositor: 32-byte address of the local depositor
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepositIntent {
    pub magic: u32,
    pub version: u32,
    pub nonce: [u8; 32],
    pub amount: u64,
    pub max_fee: u64,
    pub remote_domain: u32,
    pub remote_token: AccountId,
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
    /// 6. `amount` is greater than `max_fee`
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

        if self.amount <= self.max_fee {
            return Err(DepositIntentError::AmountBelowMaxFee {
                amount: self.amount,
                max_fee: self.max_fee,
            });
        }

        Ok(())
    }

    // SERIALIZATION
    // --------------------------------------------------------------------------------------------

    /// Serializes this intent to a `Vec<Felt>` suitable for pushing onto the Miden advice stack.
    ///
    /// Encoding:
    /// - [0]    : magic      (u32, fits in a felt)
    /// - [1]    : version    (u32, fits in a felt)
    /// - [2..5] : nonce (32 bytes as 4 felts via u32-limb packing)
    /// - [6]    : amount
    /// - [7]    : max_fee
    /// - [8]    : remote_domain (u32, fits in a felt)
    /// - [9..10]: remote_token (2 Felts from AccountId)
    /// - [11..14]: local_token (32 bytes as 4 felts via u32-limb packing)
    /// - [15..18]: local_depositor (32 bytes as 4 felts via u32-limb packing)
    pub fn to_advice_felts(&self) -> Vec<Felt> {
        let mut out = Vec::with_capacity(19);

        out.push(Felt::new_unchecked(self.magic as u64));
        out.push(Felt::new_unchecked(self.version as u64));

        let nonce_word = bytes32_to_word(&self.nonce);
        out.extend(nonce_word.as_elements());

        out.push(Felt::new_unchecked(self.amount));
        out.push(Felt::new_unchecked(self.max_fee));
        out.push(Felt::new_unchecked(self.remote_domain as u64));

        let id_felts: [Felt; 2] = self.remote_token.into();
        out.push(id_felts[0]);
        out.push(id_felts[1]);

        let local_token_word = bytes32_to_word(&self.local_token);
        out.extend(local_token_word.as_elements());

        let local_depositor_word = bytes32_to_word(&self.local_depositor);
        out.extend(local_depositor_word.as_elements());

        out
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the nonce as a `Word` using safe u32-limb packing.
    ///
    /// 32 bytes are split into 8 u32 limbs (little-endian), then paired into
    /// 4 felts via `(hi * 2^32) + lo`. This matches the AggLayer's `build_felt`
    /// pattern and avoids silent mod-p reduction in the Goldilocks field.
    pub fn nonce_word(&self) -> Word {
        bytes32_to_word(&self.nonce)
    }
}

// BYTES32 <-> WORD ENCODING
// ================================================================================================

/// Packs two u32 limbs into a single Felt: `felt = (hi * 2^32) + lo`.
///
/// Panics if the packed value would reduce mod the Goldilocks prime
/// (p = 2^64 - 2^32 + 1), which would silently corrupt the data.
///
/// This matches the AggLayer's `build_felt` procedure in MASM.
fn build_felt(lo: u32, hi: u32) -> Felt {
    let value = (hi as u64) * (1u64 << 32) + (lo as u64);
    assert!(
        (value as u128) < GOLDILOCKS_PRIME,
        "u32 limbs ({lo:#010x}, {hi:#010x}) pack to {value} which overflows the Goldilocks field"
    );
    Felt::new_unchecked(value)
}

/// Converts a 32-byte array into a `Word` (4 felts) using safe u32-limb packing.
///
/// The 32 bytes are split into 8 little-endian u32 limbs, then paired into
/// 4 felts: `felt[i] = (limb[2i+1] * 2^32) + limb[2i]`.
///
/// This encoding is field-safe: each felt is guaranteed to be less than the
/// Goldilocks prime, so no silent mod-p reduction can occur.
pub fn bytes32_to_word(bytes: &[u8; 32]) -> Word {
    let mut felts = [ZERO; 4];
    for i in 0..4 {
        let lo = u32::from_le_bytes(bytes[i * 8..i * 8 + 4].try_into().unwrap());
        let hi = u32::from_le_bytes(bytes[i * 8 + 4..i * 8 + 8].try_into().unwrap());
        felts[i] = build_felt(lo, hi);
    }
    Word::new(felts)
}

/// Converts a `Word` back into a 32-byte array (inverse of `bytes32_to_word`).
///
/// Each felt is split into two u32 limbs via `u32split` semantics:
/// `lo = felt % 2^32`, `hi = felt / 2^32`.
pub fn word_to_bytes32(word: Word) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for i in 0..4 {
        let value = word[i].as_canonical_u64();
        let lo = (value & 0xFFFF_FFFF) as u32;
        let hi = (value >> 32) as u32;
        bytes[i * 8..i * 8 + 4].copy_from_slice(&lo.to_le_bytes());
        bytes[i * 8 + 4..i * 8 + 8].copy_from_slice(&hi.to_le_bytes());
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes32_roundtrip() {
        let original: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        ];
        let word = bytes32_to_word(&original);
        let recovered = word_to_bytes32(word);
        assert_eq!(original, recovered);
    }

    #[test]
    fn bytes32_zero() {
        let zero = [0u8; 32];
        let word = bytes32_to_word(&zero);
        assert_eq!(word, Word::new([ZERO; 4]));
        assert_eq!(word_to_bytes32(word), zero);
    }

    #[test]
    fn bytes32_max_safe_value() {
        // Max u32 limbs that DON'T overflow: hi=0xFFFFFFFF, lo=0x00000000
        // packed = 0xFFFFFFFF_00000000 = 18446744069414584320 < p
        let mut bytes = [0u8; 32];
        // Set hi limb of first felt to 0xFFFFFFFF, lo to 0x00000000
        bytes[4..8].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        let word = bytes32_to_word(&bytes);
        let recovered = word_to_bytes32(word);
        assert_eq!(bytes, recovered);
    }

    #[test]
    #[should_panic(expected = "overflows the Goldilocks field")]
    fn bytes32_overflow_panics() {
        // hi=0xFFFFFFFF, lo=0x00000001 -> packed = p = 2^64 - 2^32 + 1 -> wraps to 0
        let mut bytes = [0u8; 32];
        bytes[0..4].copy_from_slice(&0x0000_0001u32.to_le_bytes()); // lo = 1
        bytes[4..8].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // hi = 0xFFFFFFFF
        let _ = bytes32_to_word(&bytes); // should panic
    }
}


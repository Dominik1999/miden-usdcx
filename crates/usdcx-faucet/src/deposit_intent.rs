use miden_protocol::account::AccountId;
use miden_protocol::{Felt, Word, ZERO};
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
    /// Encoding (all multi-byte values are packed as little-endian u64 within each `Felt`):
    /// - [0]    : magic      (u32 -> u64)
    /// - [1]    : version    (u32 -> u64)
    /// - [2..5] : nonce (32 bytes packed as 4 x LE u64 Felts)
    /// - [6]    : amount
    /// - [7]    : max_fee
    /// - [8]    : remote_domain (u32 -> u64)
    /// - [9..10]: remote_token (2 Felts from AccountId -> [Felt; 2])
    /// - [11..14]: local_token (32 bytes as 4 Felts)
    /// - [15..18]: local_depositor (32 bytes as 4 Felts)
    pub fn to_advice_felts(&self) -> Vec<Felt> {
        let mut out = Vec::with_capacity(19);

        out.push(Felt::new_unchecked(self.magic as u64));
        out.push(Felt::new_unchecked(self.version as u64));

        // nonce: 32 bytes -> 4 x u64 (little-endian chunks of 8 bytes each)
        for chunk in self.nonce.chunks(8) {
            let mut buf = [0u8; 8];
            buf[..chunk.len()].copy_from_slice(chunk);
            out.push(Felt::new_unchecked(u64::from_le_bytes(buf)));
        }

        out.push(Felt::new_unchecked(self.amount));
        out.push(Felt::new_unchecked(self.max_fee));
        out.push(Felt::new_unchecked(self.remote_domain as u64));

        // remote_token: AccountId -> [Felt; 2]
        let id_felts: [Felt; 2] = self.remote_token.into();
        out.push(id_felts[0]);
        out.push(id_felts[1]);

        // local_token: 32 bytes -> 4 x u64 LE
        for chunk in self.local_token.chunks(8) {
            let mut buf = [0u8; 8];
            buf[..chunk.len()].copy_from_slice(chunk);
            out.push(Felt::new_unchecked(u64::from_le_bytes(buf)));
        }

        // local_depositor: 32 bytes -> 4 x u64 LE
        for chunk in self.local_depositor.chunks(8) {
            let mut buf = [0u8; 8];
            buf[..chunk.len()].copy_from_slice(chunk);
            out.push(Felt::new_unchecked(u64::from_le_bytes(buf)));
        }

        out
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the nonce as a `Word` (4 x u64 LE packed into `[Felt; 4]`).
    pub fn nonce_word(&self) -> Word {
        let mut arr = [ZERO; 4];
        for (i, chunk) in self.nonce.chunks(8).enumerate() {
            let mut buf = [0u8; 8];
            buf[..chunk.len()].copy_from_slice(chunk);
            arr[i] = Felt::new_unchecked(u64::from_le_bytes(buf));
        }
        Word::new(arr)
    }
}


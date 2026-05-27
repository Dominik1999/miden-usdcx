use thiserror::Error;

use crate::circle_api::{CircleApiClient, CircleApiError, WithdrawalStatus};
use crate::config::RelayerConfig;

/// A USDCx burn event detected on Miden.
#[derive(Debug, Clone)]
pub struct BurnEvent {
    pub tx_id: String,
    pub amount: u64,
    pub destination_domain: u32,
    pub destination_recipient: String,
}

/// Trait implemented by each required co-signer of a withdrawal batch.
pub trait BurnIntentSigner {
    /// Sign the encoded burn batch and return the signature bytes.
    fn sign(&self, encoded_batch: &[u8]) -> Result<Vec<u8>, SignerError>;
}

/// Coordinates processing of USDCx burn events into Circle xReserve withdrawals.
pub struct WithdrawalService {
    config: RelayerConfig,
    circle_client: CircleApiClient,
}

impl WithdrawalService {
    /// Create a new service from the given config and Circle API client.
    pub fn new(config: RelayerConfig, circle_client: CircleApiClient) -> Self {
        Self { config, circle_client }
    }

    /// Poll Miden for new USDCx burn events.
    pub async fn poll_burns(&self) -> Result<Vec<BurnEvent>, WithdrawalError> {
        let _ = (&self.config, &self.circle_client);
        todo!("poll Miden node for USDCx burn events")
    }

    /// Process a single burn event through the Circle xReserve withdrawal flow.
    ///
    /// At least two signers are required to authorise the withdrawal batch.
    pub async fn process_withdrawal(
        &self,
        burn: BurnEvent,
        signers: &[&dyn BurnIntentSigner],
    ) -> Result<WithdrawalStatus, WithdrawalError> {
        assert!(signers.len() >= 2, "at least 2 signers required for withdrawal");
        let _ = (burn, signers, &self.config, &self.circle_client);
        todo!("prepare, sign, submit withdrawal and return status")
    }
}

/// Errors produced during withdrawal processing.
#[derive(Debug, Error)]
pub enum WithdrawalError {
    #[error("Circle API error: {0}")]
    CircleApi(#[from] CircleApiError),

    #[error("Signer error: {0}")]
    Signer(#[from] SignerError),

    #[error("Miden node error: {0}")]
    MidenNode(String),
}

/// Errors produced by a [`BurnIntentSigner`].
#[derive(Debug, Error)]
pub enum SignerError {
    #[error("signing failed: {0}")]
    SigningFailed(String),
}

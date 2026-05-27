use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Attestation returned by Circle for a cross-chain deposit message.
#[derive(Debug, Clone, Deserialize)]
pub struct Attestation {
    pub attestation: String,
    pub deposit_message_hash: String,
}

/// A batch of encoded burn intents prepared for submission.
#[derive(Debug, Clone, Deserialize)]
pub struct PreparedWithdrawal {
    pub burn_intents: Vec<EncodedBurnIntent>,
}

/// A single burn intent encoded as a hex or base64 string.
#[derive(Debug, Clone, Deserialize)]
pub struct EncodedBurnIntent {
    pub encoded: String,
}

/// Result of submitting a withdrawal batch to Circle.
#[derive(Debug, Clone, Deserialize)]
pub struct WithdrawalResult {
    pub withdrawal_id: String,
}

/// Status of a previously submitted withdrawal.
#[derive(Debug, Clone, Deserialize)]
pub struct WithdrawalStatus {
    pub id: String,
    pub status: String,
}

/// A burn intent to be sent to Circle's xReserve API.
#[derive(Debug, Clone, Serialize)]
pub struct BurnIntent {
    pub amount: u64,
    pub destination_domain: u32,
    pub destination_recipient: String,
}

/// HTTP client for the Circle xReserve API.
pub struct CircleApiClient {
    base_url: String,
    client: reqwest::Client,
}

impl CircleApiClient {
    /// Create a new client pointing at the given base URL.
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            client: reqwest::Client::new(),
        }
    }

    /// Retrieve an attestation for a cross-chain deposit message hash.
    pub async fn get_attestation(&self, hash: &str) -> Result<Attestation, CircleApiError> {
        let _ = (hash, &self.client, &self.base_url);
        todo!("fetch attestation from Circle API")
    }

    /// Prepare a batch withdrawal from a list of burn intents.
    pub async fn prepare_withdrawal(
        &self,
        intents: Vec<BurnIntent>,
    ) -> Result<PreparedWithdrawal, CircleApiError> {
        let _ = (intents, &self.client, &self.base_url);
        todo!("prepare withdrawal batch via Circle API")
    }

    /// Submit a signed withdrawal batch to Circle.
    pub async fn submit_withdrawal(
        &self,
        batch: Vec<u8>,
    ) -> Result<WithdrawalResult, CircleApiError> {
        let _ = (batch, &self.client, &self.base_url);
        todo!("submit withdrawal batch to Circle API")
    }

    /// Poll the status of a previously submitted withdrawal.
    pub async fn get_withdrawal_status(
        &self,
        id: &str,
    ) -> Result<WithdrawalStatus, CircleApiError> {
        let _ = (id, &self.client, &self.base_url);
        todo!("get withdrawal status from Circle API")
    }
}

/// Errors returned by the Circle API client.
#[derive(Debug, Error)]
pub enum CircleApiError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Circle API error (status {status}): {message}")]
    Api { status: u16, message: String },
}

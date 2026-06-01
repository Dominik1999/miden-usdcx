use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, info};

// TYPES
// ================================================================================================

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

// TRAIT
// ================================================================================================

/// Abstraction over the Circle xReserve API.
///
/// The trait allows swapping the real HTTP client for a mock in tests,
/// enabling end-to-end relayer orchestration tests without Circle credentials.
#[allow(async_fn_in_trait)]
pub trait CircleApi {
    /// Retrieve an attestation for a cross-chain deposit message hash.
    async fn get_attestation(&self, hash: &str) -> Result<Attestation, CircleApiError>;

    /// Prepare a batch withdrawal from a list of burn intents.
    async fn prepare_withdrawal(
        &self,
        intents: Vec<BurnIntent>,
    ) -> Result<PreparedWithdrawal, CircleApiError>;

    /// Submit a signed withdrawal batch to Circle.
    async fn submit_withdrawal(
        &self,
        batch: Vec<u8>,
    ) -> Result<WithdrawalResult, CircleApiError>;

    /// Poll the status of a previously submitted withdrawal.
    async fn get_withdrawal_status(
        &self,
        id: &str,
    ) -> Result<WithdrawalStatus, CircleApiError>;
}

// HTTP IMPLEMENTATION
// ================================================================================================

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

    /// Helper to check an HTTP response status and convert errors.
    async fn check_response(resp: reqwest::Response) -> Result<reqwest::Response, CircleApiError> {
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let message = resp.text().await.unwrap_or_default();
            return Err(CircleApiError::Api { status, message });
        }
        Ok(resp)
    }
}

impl CircleApi for CircleApiClient {
    async fn get_attestation(&self, hash: &str) -> Result<Attestation, CircleApiError> {
        let url = format!("{}/v1/attestations/{}", self.base_url, hash);
        debug!(hash, url, "fetching attestation from Circle API");

        let resp = self.client.get(&url).send().await?;
        let resp = Self::check_response(resp).await?;
        let attestation: Attestation = resp.json().await?;

        info!(
            hash,
            attestation_len = attestation.attestation.len(),
            "received attestation"
        );
        Ok(attestation)
    }

    async fn prepare_withdrawal(
        &self,
        intents: Vec<BurnIntent>,
    ) -> Result<PreparedWithdrawal, CircleApiError> {
        let url = format!("{}/v1/withdrawals/prepare", self.base_url);
        let intent_count = intents.len();
        debug!(intent_count, url, "preparing withdrawal batch");

        let resp = self.client.post(&url).json(&intents).send().await?;
        let resp = Self::check_response(resp).await?;
        let prepared: PreparedWithdrawal = resp.json().await?;

        info!(
            intent_count,
            encoded_count = prepared.burn_intents.len(),
            "withdrawal batch prepared"
        );
        Ok(prepared)
    }

    async fn submit_withdrawal(
        &self,
        batch: Vec<u8>,
    ) -> Result<WithdrawalResult, CircleApiError> {
        let url = format!("{}/v1/withdrawals/submit", self.base_url);
        let batch_size = batch.len();
        debug!(batch_size, url, "submitting signed withdrawal batch");

        let resp = self.client.post(&url).body(batch).send().await?;
        let resp = Self::check_response(resp).await?;
        let result: WithdrawalResult = resp.json().await?;

        info!(withdrawal_id = %result.withdrawal_id, "withdrawal submitted");
        Ok(result)
    }

    async fn get_withdrawal_status(
        &self,
        id: &str,
    ) -> Result<WithdrawalStatus, CircleApiError> {
        let url = format!("{}/v1/withdrawals/{}/status", self.base_url, id);
        debug!(id, url, "polling withdrawal status");

        let resp = self.client.get(&url).send().await?;
        let resp = Self::check_response(resp).await?;
        let status: WithdrawalStatus = resp.json().await?;

        info!(id, status = %status.status, "withdrawal status retrieved");
        Ok(status)
    }
}

// MOCK IMPLEMENTATION
// ================================================================================================

/// Mock Circle API that returns canned responses for testing.
///
/// Exercises the full relayer orchestration (attestation fetch, withdrawal
/// prepare/sign/submit/poll) without needing real Circle credentials.
pub struct MockCircleApi;

impl CircleApi for MockCircleApi {
    async fn get_attestation(&self, hash: &str) -> Result<Attestation, CircleApiError> {
        info!(hash, "mock: returning sample attestation");
        Ok(Attestation {
            attestation: "0xMOCK_ECDSA_ATTESTATION_SIGNATURE".into(),
            deposit_message_hash: hash.into(),
        })
    }

    async fn prepare_withdrawal(
        &self,
        intents: Vec<BurnIntent>,
    ) -> Result<PreparedWithdrawal, CircleApiError> {
        info!(intent_count = intents.len(), "mock: preparing withdrawal");
        let burn_intents = intents
            .iter()
            .enumerate()
            .map(|(i, intent)| EncodedBurnIntent {
                encoded: format!(
                    "encoded_intent_{}_amount_{}_domain_{}_recipient_{}",
                    i, intent.amount, intent.destination_domain, intent.destination_recipient
                ),
            })
            .collect();
        Ok(PreparedWithdrawal { burn_intents })
    }

    async fn submit_withdrawal(
        &self,
        batch: Vec<u8>,
    ) -> Result<WithdrawalResult, CircleApiError> {
        info!(batch_size = batch.len(), "mock: submitting withdrawal");
        Ok(WithdrawalResult {
            withdrawal_id: "mock-withdrawal-001".into(),
        })
    }

    async fn get_withdrawal_status(
        &self,
        id: &str,
    ) -> Result<WithdrawalStatus, CircleApiError> {
        info!(id, "mock: returning finalized status");
        Ok(WithdrawalStatus {
            id: id.into(),
            status: "finalized".into(),
        })
    }
}

// ERRORS
// ================================================================================================

/// Errors returned by the Circle API client.
#[derive(Debug, Error)]
pub enum CircleApiError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Circle API error (status {status}): {message}")]
    Api { status: u16, message: String },
}

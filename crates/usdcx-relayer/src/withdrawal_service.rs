use thiserror::Error;
use tracing::{debug, info, warn};

use crate::circle_api::{BurnIntent, CircleApiClient, CircleApiError, WithdrawalStatus};
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
    ///
    /// In production this would query the Miden node for note consumption events
    /// on the USDCx faucet account that correspond to burn operations. For now it
    /// logs and returns an empty vec.
    pub async fn poll_burns(&self) -> Result<Vec<BurnEvent>, WithdrawalError> {
        info!(
            miden_node_url = %self.config.miden_node_url,
            faucet_id = %self.config.faucet_account_id,
            "polling Miden for USDCx burn events (stub - no real RPC calls)"
        );

        // Production implementation would:
        // 1. Connect to the Miden node at `self.config.miden_node_url`
        // 2. Query for recent transactions on the faucet account
        // 3. Filter for burn note consumptions (notes that destroy USDCx tokens)
        // 4. Extract destination domain, recipient, and amount from note metadata
        // 5. Convert each matching event into a BurnEvent

        Ok(vec![])
    }

    /// Process a single burn event through the Circle xReserve withdrawal flow.
    ///
    /// The full lifecycle is: prepare -> collect multi-sig -> submit -> poll status.
    /// At least two signers are required to authorize the withdrawal batch.
    pub async fn process_withdrawal(
        &self,
        burn: BurnEvent,
        signers: &[&dyn BurnIntentSigner],
    ) -> Result<WithdrawalStatus, WithdrawalError> {
        if signers.len() < 2 {
            return Err(WithdrawalError::Signer(SignerError::SigningFailed(
                format!("at least 2 signers required, got {}", signers.len()),
            )));
        }

        info!(
            tx_id = %burn.tx_id,
            amount = burn.amount,
            destination_domain = burn.destination_domain,
            destination_recipient = %burn.destination_recipient,
            signer_count = signers.len(),
            "processing withdrawal"
        );

        // Step 1: Prepare the withdrawal batch via Circle API
        let intent = BurnIntent {
            amount: burn.amount,
            destination_domain: burn.destination_domain,
            destination_recipient: burn.destination_recipient.clone(),
        };

        debug!(amount = intent.amount, "preparing withdrawal with Circle API");
        let prepared = self.circle_client.prepare_withdrawal(vec![intent]).await?;

        // Step 2: Collect signatures from all co-signers
        // Each signer signs the same encoded batch; all signatures are concatenated
        // into the final submission payload
        let encoded_batch: Vec<u8> = prepared
            .burn_intents
            .iter()
            .flat_map(|bi| bi.encoded.as_bytes())
            .copied()
            .collect();

        let mut all_signatures: Vec<Vec<u8>> = Vec::with_capacity(signers.len());
        for (i, signer) in signers.iter().enumerate() {
            debug!(signer_index = i, "collecting signature from co-signer");
            let sig = signer.sign(&encoded_batch)?;
            all_signatures.push(sig);
        }

        info!(
            signature_count = all_signatures.len(),
            "all co-signer signatures collected"
        );

        // Step 3: Assemble the signed batch payload
        // Format: [encoded_batch_len (4 bytes) | encoded_batch | sig_count (4 bytes)
        //          | for each sig: sig_len (4 bytes) | sig_bytes]
        let mut submission = Vec::new();
        submission.extend_from_slice(&(encoded_batch.len() as u32).to_le_bytes());
        submission.extend_from_slice(&encoded_batch);
        submission.extend_from_slice(&(all_signatures.len() as u32).to_le_bytes());
        for sig in &all_signatures {
            submission.extend_from_slice(&(sig.len() as u32).to_le_bytes());
            submission.extend_from_slice(sig);
        }

        debug!(
            submission_size = submission.len(),
            "submitting signed withdrawal batch"
        );
        let result = self.circle_client.submit_withdrawal(submission).await?;

        // Step 4: Poll for completion
        info!(
            withdrawal_id = %result.withdrawal_id,
            "withdrawal submitted, polling for status"
        );
        let status = self
            .circle_client
            .get_withdrawal_status(&result.withdrawal_id)
            .await?;

        info!(
            withdrawal_id = %status.id,
            status = %status.status,
            "withdrawal status retrieved"
        );

        Ok(status)
    }

    /// Run the withdrawal processing loop.
    ///
    /// Polls for burns and processes each one through the full withdrawal lifecycle.
    /// Requires a set of co-signers to be provided.
    pub async fn run(&self, signers: &[&dyn BurnIntentSigner]) -> Result<(), WithdrawalError> {
        let interval = std::time::Duration::from_secs(self.config.burn_poll_interval_secs);
        info!(
            poll_interval_secs = self.config.burn_poll_interval_secs,
            signer_count = signers.len(),
            "starting withdrawal service loop"
        );

        loop {
            match self.poll_burns().await {
                Ok(burns) if burns.is_empty() => {
                    debug!("no new burn events found");
                }
                Ok(burns) => {
                    info!(count = burns.len(), "found new burn events");
                    for burn in burns {
                        let tx_id = burn.tx_id.clone();
                        match self.process_withdrawal(burn, signers).await {
                            Ok(status) => {
                                info!(
                                    tx_id,
                                    withdrawal_id = %status.id,
                                    status = %status.status,
                                    "withdrawal processed"
                                );
                            }
                            Err(e) => {
                                warn!(tx_id, error = %e, "failed to process withdrawal");
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!(error = %e, "burn polling failed");
                }
            }

            tokio::time::sleep(interval).await;
        }
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

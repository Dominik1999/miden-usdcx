use thiserror::Error;
use tracing::{debug, info, warn};

use crate::circle_api::{BurnIntent, CircleApi, CircleApiError, WithdrawalStatus};
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
pub struct WithdrawalService<C: CircleApi> {
    config: RelayerConfig,
    circle_client: C,
}

impl<C: CircleApi> WithdrawalService<C> {
    /// Create a new service from the given config and Circle API client.
    pub fn new(config: RelayerConfig, circle_client: C) -> Self {
        Self { config, circle_client }
    }

    /// Poll Miden for new USDCx burn events.
    ///
    /// Production: queries the Miden node for consumed BurnNotes on the faucet
    /// account (tagged with `NoteTag::with_account_target(faucet_id)`).
    ///
    /// Current: returns a sample burn event so the downstream withdrawal
    /// lifecycle (prepare, multi-sig, submit, poll) is exercised.
    pub async fn poll_burns(&self) -> Result<Vec<BurnEvent>, WithdrawalError> {
        info!(
            miden_node_url = %self.config.miden_node_url,
            faucet_id = %self.config.faucet_account_id,
            "polling Miden for USDCx burn events"
        );

        // TODO(production): replace with real Miden node RPC query:
        //   1. Connect to Miden node at `self.config.miden_node_url`
        //   2. Query faucet account for consumed notes since last checkpoint
        //   3. Filter for BurnNotes (notes tagged with faucet_id that called
        //      receive_and_burn)
        //   4. Extract amount from burned asset, destination from off-chain metadata
        //   5. Track last processed block to avoid reprocessing

        let sample = BurnEvent {
            tx_id: "0x000102030405060708090a0b0c0d0e0f...sample".into(),
            amount: 500_000, // 0.5 USDC (6 decimals)
            destination_domain: 0,  // Ethereum mainnet
            destination_recipient: "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD1e".into(),
        };

        info!(tx_id = %sample.tx_id, amount = sample.amount, "sample burn event");
        Ok(vec![sample])
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

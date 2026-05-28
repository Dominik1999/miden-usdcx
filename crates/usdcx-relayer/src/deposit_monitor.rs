use thiserror::Error;
use tracing::{debug, info, warn};

use crate::circle_api::{Attestation, CircleApiClient, CircleApiError};
use crate::config::RelayerConfig;

/// An on-chain deposit event detected on the source chain.
#[derive(Debug, Clone)]
pub struct DepositEvent {
    pub tx_hash: String,
    pub deposit_message_hash: String,
    pub amount: u64,
    pub recipient: String,
}

/// A Miden transaction that mints USDCx to a recipient.
#[derive(Debug, Clone)]
pub struct MintTransaction {
    pub tx_bytes: Vec<u8>,
}

/// Monitors the source chain for xReserve deposit events and builds corresponding
/// mint transactions for the Miden faucet.
pub struct DepositMonitor {
    config: RelayerConfig,
    circle_client: CircleApiClient,
}

impl DepositMonitor {
    /// Create a new monitor from the given config and Circle API client.
    pub fn new(config: RelayerConfig, circle_client: CircleApiClient) -> Self {
        Self { config, circle_client }
    }

    /// Poll for new deposit events on the source chain.
    ///
    /// In production this would use ethers/alloy to query the xReserve contract
    /// for `DepositForBurn` events on Ethereum. For now it logs and returns an
    /// empty vec.
    pub async fn poll_deposits(&self) -> Result<Vec<DepositEvent>, DepositMonitorError> {
        info!(
            rpc_url = %self.config.ethereum_rpc_url,
            contract = %self.config.xreserve_contract_address,
            "polling Ethereum for xReserve deposit events (stub - no real RPC calls)"
        );

        // Production implementation would:
        // 1. Connect to Ethereum via `self.config.ethereum_rpc_url`
        // 2. Query the xReserve contract at `self.config.xreserve_contract_address`
        //    for DepositForBurn(nonce, burnToken, amount, depositor, mintRecipient,
        //    destinationDomain, destinationTokenMessenger, destinationCaller) events
        // 3. Filter for events targeting our domain (`self.config.domain_id`)
        // 4. Convert each matching log into a DepositEvent

        Ok(vec![])
    }

    /// Build a Miden mint transaction from a deposit event and its Circle attestation.
    ///
    /// This constructs a transaction that invokes the USDCx faucet's
    /// `mint_with_attestation` procedure. The attestation data is placed into the
    /// advice provider so the faucet's MASM policy can verify it on-chain.
    pub async fn build_mint_transaction(
        &self,
        deposit: DepositEvent,
        attestation: Attestation,
    ) -> Result<MintTransaction, DepositMonitorError> {
        info!(
            tx_hash = %deposit.tx_hash,
            amount = deposit.amount,
            recipient = %deposit.recipient,
            "building mint transaction for deposit"
        );

        // The mint transaction follows the attestation_advice pattern from the faucet:
        //
        // 1. Parse the Circle attestation (ECDSA secp256k1 signature over the deposit
        //    message). The attestation bytes contain:
        //    - Attester public key commitment (4 field elements)
        //    - Deposit nonce (4 field elements)
        //    - ECDSA signature components
        //
        // 2. Set up the advice provider:
        //    - Put [pk0, pk1, pk2, pk3, n0, n1, n2, n3] under ATTESTATION_DATA_KEY
        //      in the advice map
        //    - Put the ECDSA signature under merge(PK_COMM, MESSAGE) in the advice map
        //
        // 3. Build a Miden transaction script that:
        //    - Calls the faucet account's `mint_with_attestation` procedure
        //    - Passes (recipient_id, relayer_id, fee_amount) on the stack
        //    - The procedure internally reads attestation data from the advice provider,
        //      verifies it, checks the nonce hasn't been consumed, and mints tokens
        //
        // 4. Execute the transaction against the faucet account state to produce
        //    a proven transaction that can be submitted to the Miden node

        debug!(
            faucet_id = %self.config.faucet_account_id,
            attestation_hash = %attestation.deposit_message_hash,
            attestation_len = attestation.attestation.len(),
            "attestation data loaded, transaction construction not yet implemented"
        );

        // Placeholder: real implementation would use miden-tx to build and prove
        // the transaction, then serialize it
        warn!("mint transaction building is not yet implemented - returning empty tx");
        Err(DepositMonitorError::BuildTransaction(
            "mint transaction construction not yet implemented".into(),
        ))
    }

    /// Run the deposit monitoring loop.
    ///
    /// Polls for deposits, fetches attestations from Circle, and builds mint
    /// transactions in a continuous loop.
    pub async fn run(&self) -> Result<(), DepositMonitorError> {
        let interval = std::time::Duration::from_secs(self.config.deposit_poll_interval_secs);
        info!(
            poll_interval_secs = self.config.deposit_poll_interval_secs,
            "starting deposit monitor loop"
        );

        loop {
            match self.poll_deposits().await {
                Ok(deposits) if deposits.is_empty() => {
                    debug!("no new deposits found");
                }
                Ok(deposits) => {
                    info!(count = deposits.len(), "found new deposits");
                    for deposit in deposits {
                        let hash = deposit.deposit_message_hash.clone();
                        match self.circle_client.get_attestation(&hash).await {
                            Ok(attestation) => {
                                match self.build_mint_transaction(deposit, attestation).await {
                                    Ok(tx) => {
                                        info!(
                                            tx_size = tx.tx_bytes.len(),
                                            "mint transaction built, ready for submission"
                                        );
                                        // Production: submit tx to Miden node
                                    }
                                    Err(e) => {
                                        warn!(error = %e, "failed to build mint transaction");
                                    }
                                }
                            }
                            Err(e) => {
                                warn!(
                                    hash,
                                    error = %e,
                                    "failed to fetch attestation, will retry"
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!(error = %e, "deposit polling failed");
                }
            }

            tokio::time::sleep(interval).await;
        }
    }
}

/// Errors produced by the deposit monitor.
#[derive(Debug, Error)]
pub enum DepositMonitorError {
    #[error("Circle API error: {0}")]
    CircleApi(#[from] CircleApiError),

    #[error("Failed to build mint transaction: {0}")]
    BuildTransaction(String),

    #[error("RPC error: {0}")]
    Rpc(String),
}

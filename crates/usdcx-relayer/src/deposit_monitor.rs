use thiserror::Error;
use tracing::{debug, info, warn};

use crate::circle_api::{Attestation, CircleApi, CircleApiError};
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
pub struct DepositMonitor<C: CircleApi> {
    config: RelayerConfig,
    circle_client: C,
}

impl<C: CircleApi> DepositMonitor<C> {
    /// Create a new monitor from the given config and Circle API client.
    pub fn new(config: RelayerConfig, circle_client: C) -> Self {
        Self { config, circle_client }
    }

    /// Poll for new deposit events on the source chain.
    ///
    /// Production: uses ethers/alloy to query the xReserve contract for
    /// `DepositForBurn` events on Ethereum, filtered by `self.config.domain_id`.
    ///
    /// Current: returns a sample deposit event so the downstream orchestration
    /// (attestation fetch, transaction build, submission) is exercised.
    pub async fn poll_deposits(&self) -> Result<Vec<DepositEvent>, DepositMonitorError> {
        info!(
            rpc_url = %self.config.ethereum_rpc_url,
            contract = %self.config.xreserve_contract_address,
            domain_id = self.config.domain_id,
            "polling Ethereum for xReserve deposit events"
        );

        // TODO(production): replace with real Ethereum RPC query via ethers/alloy:
        //   1. provider.get_logs(filter) on the xReserve contract
        //   2. Decode DepositForBurn(nonce, burnToken, amount, depositor,
        //      mintRecipient, destinationDomain, ...) events
        //   3. Filter for destinationDomain == self.config.domain_id
        //   4. Track last processed block to avoid reprocessing

        let sample = DepositEvent {
            tx_hash: "0xabc123def456789...sample".into(),
            deposit_message_hash: "0xdeadbeef00000000000000000000000000000000000000000000000000000001".into(),
            amount: 1_000_000, // 1 USDC (6 decimals)
            recipient: self.config.faucet_account_id.clone(),
        };

        info!(tx_hash = %sample.tx_hash, amount = sample.amount, "sample deposit event");
        Ok(vec![sample])
    }

    /// Build a Miden mint transaction from a deposit event and its Circle attestation.
    ///
    /// Production: uses miden-tx to construct and prove a transaction that calls
    /// `mint_with_attestation` on the faucet with the attestation in the advice map.
    ///
    /// Current: returns a representative transaction payload so the submission
    /// pipeline is exercised.
    pub async fn build_mint_transaction(
        &self,
        deposit: DepositEvent,
        attestation: Attestation,
    ) -> Result<MintTransaction, DepositMonitorError> {
        info!(
            tx_hash = %deposit.tx_hash,
            amount = deposit.amount,
            recipient = %deposit.recipient,
            attestation_hash = %attestation.deposit_message_hash,
            "building mint transaction for deposit"
        );

        // TODO(production): replace with real miden-tx transaction construction:
        //   1. Parse Circle attestation -> extract PK_COMM, NONCE, ECDSA signature
        //   2. Build advice map:
        //      - ATTESTATION_DATA_KEY -> [PK_COMM(4), NONCE(4), fee_amount, max_fee, 0, 0]
        //      - merge(PK_COMM, MESSAGE) -> prepared ECDSA signature
        //   3. Build tx script calling mint_and_send on the faucet
        //   4. Execute transaction against faucet account state
        //   5. Prove the transaction
        //   6. Serialize proven transaction

        let tx_payload = format!(
            "mint:faucet={},amount={},recipient={},attestation={}",
            self.config.faucet_account_id,
            deposit.amount,
            deposit.recipient,
            attestation.deposit_message_hash,
        );

        info!(payload_size = tx_payload.len(), "mint transaction built");
        Ok(MintTransaction {
            tx_bytes: tx_payload.into_bytes(),
        })
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

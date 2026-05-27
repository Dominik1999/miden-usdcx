use thiserror::Error;

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
    pub async fn poll_deposits(&self) -> Result<Vec<DepositEvent>, DepositMonitorError> {
        let _ = (&self.config, &self.circle_client);
        todo!("poll Ethereum for xReserve deposit events")
    }

    /// Build a Miden mint transaction from a deposit event and its Circle attestation.
    pub async fn build_mint_transaction(
        &self,
        deposit: DepositEvent,
        attestation: Attestation,
    ) -> Result<MintTransaction, DepositMonitorError> {
        let _ = (deposit, attestation, &self.config);
        todo!("build mint transaction from deposit event and attestation")
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

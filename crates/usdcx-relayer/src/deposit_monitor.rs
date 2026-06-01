use std::sync::Arc;

use miden_protocol::assembly::DefaultSourceManager;
use miden_protocol::note::NoteType;
use miden_protocol::vm::AdviceInputs;
use miden_protocol::{Felt, Hasher, Word, ZERO};
use miden_standards::code_builder::CodeBuilder;
use thiserror::Error;
use tracing::{debug, info, warn};
use usdcx_faucet::deposit_intent::DepositIntent;

use crate::circle_api::{Attestation, CircleApi, CircleApiError};
use crate::config::RelayerConfig;

// CONSTANTS
// ================================================================================================

/// Well-known advice map key for attestation data, must match the MASM constant.
const ATTESTATION_DATA_KEY: Word = Word::new([
    Felt::new_unchecked(3735928559),
    Felt::new_unchecked(3405691582),
    Felt::new_unchecked(3735928559),
    Felt::new_unchecked(3405691582),
]);

// TYPES
// ================================================================================================

/// An on-chain deposit event detected on the source chain.
#[derive(Debug, Clone)]
pub struct DepositEvent {
    pub tx_hash: String,
    pub deposit_message_hash: String,
    pub amount: u64,
    pub recipient: String,
}

/// A prepared Miden mint transaction ready for proving and submission.
#[derive(Debug, Clone)]
pub struct MintTransaction {
    /// The compiled transaction script source (MASM).
    pub tx_script_code: String,
    /// Advice inputs containing attestation data and ECDSA signature.
    pub advice_inputs: AdviceInputs,
    /// The faucet account ID this transaction targets.
    pub faucet_account_id: String,
    /// The deposit amount being minted.
    pub amount: u64,
}

// DEPOSIT MONITOR
// ================================================================================================

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
        //   2. Decode DepositForBurn events
        //   3. Filter for destinationDomain == self.config.domain_id
        //   4. Track last processed block to avoid reprocessing

        let sample = DepositEvent {
            tx_hash: "0xabc123def456789...sample".into(),
            deposit_message_hash: "0xdeadbeef00000000000000000000000000000000000000000000000000000001".into(),
            amount: 1_000_000,
            recipient: self.config.faucet_account_id.clone(),
        };

        info!(tx_hash = %sample.tx_hash, amount = sample.amount, "sample deposit event");
        Ok(vec![sample])
    }

    /// Build a Miden mint transaction from a deposit event and its Circle attestation.
    ///
    /// Constructs the real transaction script (MASM) and advice map needed to call
    /// `mint_and_send` on the faucet with attestation verification. The returned
    /// `MintTransaction` contains everything needed to execute and prove the
    /// transaction once the faucet account state is available.
    ///
    /// The advice map carries the full depositIntent data (39 felts), PK_COMM,
    /// fee_amount, NONCE_KEY, max_fee, MESSAGE, and the ECDSA signature.
    pub fn build_mint_transaction(
        &self,
        deposit: &DepositEvent,
        _attestation: &Attestation,
        pk_comm: Word,
        intent: &DepositIntent,
        faucet_id_prefix: Felt,
        faucet_id_suffix: Felt,
        recipient: Word,
        prepared_signature: Vec<Felt>,
        fee_amount: u64,
    ) -> Result<MintTransaction, DepositMonitorError> {
        info!(
            tx_hash = %deposit.tx_hash,
            amount = deposit.amount,
            recipient = %deposit.recipient,
            "building mint transaction"
        );

        // 1. Build the transaction script (real MASM, same as integration tests)
        let tag: u32 = 0; // TODO(production): NoteTag::with_account_target(recipient_account_id)
        let note_type = NoteType::Private;

        let tx_script_code = format!(
            r#"
            begin
                push.{recipient}
                push.{note_type}
                push.{tag}
                push.{amount}
                push.{faucet_id_prefix}
                push.{faucet_id_suffix}
                push.1
                exec.::miden::protocol::asset::create_fungible_asset
                call.::miden::standards::faucets::fungible::mint_and_send
                dropw dropw dropw dropw
            end
            "#,
            recipient = recipient,
            note_type = note_type as u8,
            tag = tag,
            amount = deposit.amount,
            faucet_id_prefix = faucet_id_prefix,
            faucet_id_suffix = faucet_id_suffix,
        );

        // Verify the script compiles
        let source_manager = Arc::new(DefaultSourceManager::default());
        let _tx_script = CodeBuilder::with_source_manager(source_manager)
            .compile_tx_script(&tx_script_code)
            .map_err(|e| DepositMonitorError::BuildTransaction(format!("MASM compile error: {e}")))?;

        debug!("transaction script compiled successfully");

        // 2. Build the advice map with full depositIntent data
        let message = intent.message_hash();
        let nonce_key = intent.nonce_key();
        let sig_key = Hasher::merge(&[pk_comm, message]);

        // Advice map value layout (matches check_policy read order):
        // [PK_COMM(4), DEPOSIT_INTENT(39) + pad(1), fee_amount word(4),
        //  NONCE_KEY(4), max_fee word(4), MESSAGE(4)]
        let mut attestation_data: Vec<Felt> = Vec::new();

        // PK_COMM (4 felts)
        attestation_data.extend(pk_comm.as_elements());

        // DEPOSIT_INTENT (39 felts) + 1 padding zero = 40 felts
        attestation_data.extend(intent.to_advice_felts());
        attestation_data.push(ZERO);

        // fee_amount word [fee_amount, 0, 0, 0]
        attestation_data.push(Felt::new_unchecked(fee_amount));
        attestation_data.push(ZERO);
        attestation_data.push(ZERO);
        attestation_data.push(ZERO);

        // NONCE_KEY (4 felts)
        attestation_data.extend(nonce_key.as_elements());

        // max_fee word [max_fee, 0, 0, 0]
        attestation_data.push(Felt::new_unchecked(intent.max_fee));
        attestation_data.push(ZERO);
        attestation_data.push(ZERO);
        attestation_data.push(ZERO);

        // MESSAGE (4 felts)
        attestation_data.extend(message.as_elements());

        let advice_inputs = AdviceInputs::default()
            .with_map([
                (ATTESTATION_DATA_KEY, attestation_data),
                (sig_key, prepared_signature),
            ]);

        info!(
            script_len = tx_script_code.len(),
            "mint transaction built with real tx script and advice map"
        );

        Ok(MintTransaction {
            tx_script_code,
            advice_inputs,
            faucet_account_id: self.config.faucet_account_id.clone(),
            amount: deposit.amount,
        })
    }

    /// Run the deposit monitoring loop.
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
                                info!(
                                    hash = %attestation.deposit_message_hash,
                                    "attestation fetched, ready to build transaction"
                                );
                                // In production: parse attestation to extract PK_COMM,
                                // NONCE, and prepared ECDSA signature, then call
                                // build_mint_transaction with real values and submit
                                // the proven transaction to the Miden node.
                                let _ = attestation;
                            }
                            Err(e) => {
                                warn!(hash, error = %e, "failed to fetch attestation, will retry");
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

// ERRORS
// ================================================================================================

/// Errors produced by the deposit monitor.
#[derive(Debug, Error)]
pub enum DepositMonitorError {
    #[error("Circle API error: {0}")]
    CircleApi(#[from] CircleApiError),

    #[error("failed to build mint transaction: {0}")]
    BuildTransaction(String),

    #[error("RPC error: {0}")]
    Rpc(String),
}

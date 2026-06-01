//! End-to-end relayer orchestration tests using MockCircleApi.
//!
//! These tests exercise the full deposit and withdrawal pipelines with
//! canned data - no real Ethereum RPC, Miden node, or Circle credentials needed.

use usdcx_relayer::circle_api::{CircleApi, MockCircleApi};
use usdcx_relayer::config::RelayerConfig;
use usdcx_relayer::deposit_monitor::DepositMonitor;
use usdcx_relayer::withdrawal_service::{BurnEvent, BurnIntentSigner, SignerError, WithdrawalService};

fn test_config() -> RelayerConfig {
    RelayerConfig {
        circle_api_url: "https://mock.circle.com".into(),
        miden_node_url: "http://localhost:57291".into(),
        faucet_account_id: "0xTEST_FAUCET".into(),
        domain_id: 99999,
        deposit_poll_interval_secs: 1,
        burn_poll_interval_secs: 1,
        ethereum_rpc_url: "http://localhost:8545".into(),
        xreserve_contract_address: "0xTEST_XRESERVE".into(),
    }
}

/// A trivial signer for testing that returns a deterministic signature.
struct TestSigner {
    id: u8,
}

impl BurnIntentSigner for TestSigner {
    fn sign(&self, encoded_batch: &[u8]) -> Result<Vec<u8>, SignerError> {
        // Deterministic: hash of (signer_id, batch_len)
        Ok(vec![self.id, encoded_batch.len() as u8, 0xAB, 0xCD])
    }
}

// DEPOSIT PIPELINE TESTS
// ================================================================================================

#[tokio::test]
async fn deposit_poll_returns_sample_event() {
    let monitor = DepositMonitor::new(test_config(), MockCircleApi);
    let deposits = monitor.poll_deposits().await.unwrap();

    assert_eq!(deposits.len(), 1);
    assert_eq!(deposits[0].amount, 1_000_000);
    assert!(!deposits[0].tx_hash.is_empty());
    assert!(!deposits[0].deposit_message_hash.is_empty());
}

#[tokio::test]
async fn deposit_attestation_fetch_and_tx_build() {
    let monitor = DepositMonitor::new(test_config(), MockCircleApi);
    let deposits = monitor.poll_deposits().await.unwrap();

    let deposit = deposits.into_iter().next().unwrap();
    let hash = deposit.deposit_message_hash.clone();

    // Fetch attestation via mock Circle API
    let attestation = MockCircleApi.get_attestation(&hash).await.unwrap();
    assert_eq!(attestation.deposit_message_hash, hash);
    assert!(!attestation.attestation.is_empty());

    // Build mint transaction
    let tx = monitor.build_mint_transaction(deposit, attestation).await.unwrap();
    assert!(!tx.tx_bytes.is_empty());

    // Verify the transaction payload contains expected fields
    let payload = String::from_utf8(tx.tx_bytes).unwrap();
    assert!(payload.contains("mint:faucet="));
    assert!(payload.contains("amount=1000000"));
}

// WITHDRAWAL PIPELINE TESTS
// ================================================================================================

#[tokio::test]
async fn withdrawal_poll_returns_sample_event() {
    let service = WithdrawalService::new(test_config(), MockCircleApi);
    let burns = service.poll_burns().await.unwrap();

    assert_eq!(burns.len(), 1);
    assert_eq!(burns[0].amount, 500_000);
    assert_eq!(burns[0].destination_domain, 0);
    assert!(!burns[0].destination_recipient.is_empty());
}

#[tokio::test]
async fn withdrawal_full_lifecycle() {
    let service = WithdrawalService::new(test_config(), MockCircleApi);

    let burn = BurnEvent {
        tx_id: "test-burn-001".into(),
        amount: 250_000,
        destination_domain: 0,
        destination_recipient: "0xAliceOnEthereum".into(),
    };

    let signer_a = TestSigner { id: 1 };
    let signer_b = TestSigner { id: 2 };
    let signers: Vec<&dyn BurnIntentSigner> = vec![&signer_a, &signer_b];

    let status = service.process_withdrawal(burn, &signers).await.unwrap();

    assert_eq!(status.id, "mock-withdrawal-001");
    assert_eq!(status.status, "finalized");
}

#[tokio::test]
async fn withdrawal_rejects_insufficient_signers() {
    let service = WithdrawalService::new(test_config(), MockCircleApi);

    let burn = BurnEvent {
        tx_id: "test-burn-002".into(),
        amount: 100_000,
        destination_domain: 0,
        destination_recipient: "0xBobOnEthereum".into(),
    };

    // Only 1 signer - should fail (Circle requires minimum 2)
    let signer_a = TestSigner { id: 1 };
    let signers: Vec<&dyn BurnIntentSigner> = vec![&signer_a];

    let result = service.process_withdrawal(burn, &signers).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("at least 2 signers required"));
}

// END-TO-END PIPELINE TEST
// ================================================================================================

#[tokio::test]
async fn deposit_to_withdrawal_full_pipeline() {
    // Simulate the full relayer pipeline: deposit detected -> attestation fetched ->
    // mint tx built -> (later) burn detected -> withdrawal processed

    let config = test_config();

    // --- Deposit side ---
    let deposit_monitor = DepositMonitor::new(config.clone(), MockCircleApi);

    let deposits = deposit_monitor.poll_deposits().await.unwrap();
    assert_eq!(deposits.len(), 1);

    let deposit = deposits.into_iter().next().unwrap();
    let attestation = MockCircleApi
        .get_attestation(&deposit.deposit_message_hash)
        .await
        .unwrap();
    let mint_tx = deposit_monitor
        .build_mint_transaction(deposit, attestation)
        .await
        .unwrap();
    assert!(!mint_tx.tx_bytes.is_empty());

    // --- Withdrawal side ---
    let withdrawal_service = WithdrawalService::new(config, MockCircleApi);

    let burns = withdrawal_service.poll_burns().await.unwrap();
    assert_eq!(burns.len(), 1);

    let burn = burns.into_iter().next().unwrap();
    let signer_a = TestSigner { id: 1 };
    let signer_b = TestSigner { id: 2 };
    let signers: Vec<&dyn BurnIntentSigner> = vec![&signer_a, &signer_b];

    let status = withdrawal_service
        .process_withdrawal(burn, &signers)
        .await
        .unwrap();
    assert_eq!(status.status, "finalized");
}

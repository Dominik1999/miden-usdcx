//! End-to-end relayer orchestration tests using MockCircleApi.
//!
//! These tests exercise the full deposit and withdrawal pipelines with
//! canned data - no real Ethereum RPC, Miden node, or Circle credentials needed.
//! The tx script compilation and advice map construction are REAL - only the
//! chain polling and account state fetch remain mocked.

use miden_protocol::{Felt, Word, ZERO};
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
        Ok(vec![self.id, encoded_batch.len() as u8, 0xAB, 0xCD])
    }
}

/// Sample values for tx construction tests. In production these come from
/// parsing the Circle attestation.
fn sample_pk_comm() -> Word {
    Word::new([
        Felt::new_unchecked(1111),
        Felt::new_unchecked(2222),
        Felt::new_unchecked(3333),
        Felt::new_unchecked(4444),
    ])
}

fn sample_nonce() -> Word {
    Word::new([
        Felt::new_unchecked(100),
        Felt::new_unchecked(200),
        Felt::new_unchecked(300),
        Felt::new_unchecked(400),
    ])
}

fn sample_recipient() -> Word {
    Word::new([
        Felt::new_unchecked(10),
        Felt::new_unchecked(20),
        Felt::new_unchecked(30),
        Felt::new_unchecked(40),
    ])
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

    // Build mint transaction with real tx script compilation and advice map
    let tx = monitor.build_mint_transaction(
        &deposit,
        &attestation,
        sample_pk_comm(),
        sample_nonce(),
        Felt::new_unchecked(0xABCD), // faucet prefix
        Felt::new_unchecked(0x1234), // faucet suffix
        sample_recipient(),
        vec![ZERO; 4], // mock prepared signature
        0,             // fee_amount
        0,             // max_fee
    ).unwrap();

    // The tx script is real compiled MASM
    assert!(tx.tx_script_code.contains("mint_and_send"));
    assert!(tx.tx_script_code.contains("create_fungible_asset"));
    assert_eq!(tx.amount, 1_000_000);
}

#[tokio::test]
async fn tx_script_compiles_with_various_amounts() {
    let monitor = DepositMonitor::new(test_config(), MockCircleApi);
    let attestation = MockCircleApi.get_attestation("test").await.unwrap();

    for amount in [1u64, 1_000, 1_000_000, 100_000_000] {
        let deposit = usdcx_relayer::deposit_monitor::DepositEvent {
            tx_hash: "0xtest".into(),
            deposit_message_hash: "0xtest".into(),
            amount,
            recipient: "0xrecipient".into(),
        };

        let tx = monitor.build_mint_transaction(
            &deposit,
            &attestation,
            sample_pk_comm(),
            sample_nonce(),
            Felt::new_unchecked(0xABCD),
            Felt::new_unchecked(0x1234),
            sample_recipient(),
            vec![ZERO; 4],
            0,
            0,
        ).unwrap();

        assert_eq!(tx.amount, amount);
    }
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
    let config = test_config();

    // --- Deposit side: poll -> fetch attestation -> build real tx ---
    let deposit_monitor = DepositMonitor::new(config.clone(), MockCircleApi);

    let deposits = deposit_monitor.poll_deposits().await.unwrap();
    assert_eq!(deposits.len(), 1);

    let deposit = deposits.into_iter().next().unwrap();
    let attestation = MockCircleApi
        .get_attestation(&deposit.deposit_message_hash)
        .await
        .unwrap();

    let mint_tx = deposit_monitor.build_mint_transaction(
        &deposit,
        &attestation,
        sample_pk_comm(),
        sample_nonce(),
        Felt::new_unchecked(0xABCD),
        Felt::new_unchecked(0x1234),
        sample_recipient(),
        vec![ZERO; 4],
        0,
        0,
    ).unwrap();

    // Verify the tx is real: compiled MASM script + advice inputs
    assert!(mint_tx.tx_script_code.contains("mint_and_send"));
    assert_eq!(mint_tx.amount, 1_000_000);

    // --- Withdrawal side: poll -> prepare -> multi-sig -> submit -> finalize ---
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

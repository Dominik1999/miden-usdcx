use usdcx_relayer::circle_api::CircleApiClient;
use usdcx_relayer::config::RelayerConfig;
use usdcx_relayer::deposit_monitor::DepositMonitor;
use usdcx_relayer::withdrawal_service::WithdrawalService;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // In production, parse from env vars or a config file (e.g. via envy or figment).
    // For the PoC we use hardcoded defaults.
    let config = RelayerConfig {
        circle_api_url: std::env::var("CIRCLE_API_URL")
            .unwrap_or_else(|_| "https://iris-api-sandbox.circle.com".into()),
        miden_node_url: std::env::var("MIDEN_NODE_URL")
            .unwrap_or_else(|_| "http://localhost:57291".into()),
        faucet_account_id: std::env::var("FAUCET_ACCOUNT_ID")
            .unwrap_or_else(|_| "0x0000000000000000".into()),
        domain_id: std::env::var("DOMAIN_ID")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0),
        deposit_poll_interval_secs: std::env::var("DEPOSIT_POLL_INTERVAL")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(15),
        burn_poll_interval_secs: std::env::var("BURN_POLL_INTERVAL")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(15),
        ethereum_rpc_url: std::env::var("ETHEREUM_RPC_URL")
            .unwrap_or_else(|_| "http://localhost:8545".into()),
        xreserve_contract_address: std::env::var("XRESERVE_CONTRACT")
            .unwrap_or_else(|_| "0x0000000000000000000000000000000000000000".into()),
    };

    let circle_client = CircleApiClient::new(&config.circle_api_url);

    let deposit_monitor = DepositMonitor::new(config.clone(), CircleApiClient::new(&config.circle_api_url));
    let withdrawal_service = WithdrawalService::new(config.clone(), circle_client);

    println!("USDCx relayer started");
    println!("  Circle API:   {}", config.circle_api_url);
    println!("  Miden node:   {}", config.miden_node_url);
    println!("  Faucet ID:    {}", config.faucet_account_id);
    println!("  Domain ID:    {}", config.domain_id);

    // Run both loops concurrently. In production, the withdrawal service would
    // also be provided with real co-signers (e.g. HSM-backed or KMS-backed).
    // For the PoC we just run the deposit monitor since the withdrawal loop
    // requires signers.
    tokio::select! {
        result = deposit_monitor.run() => {
            if let Err(e) = result {
                eprintln!("deposit monitor exited with error: {e}");
            }
        }
        // withdrawal_service.run(&signers) would go here with real signers
    }

    // Suppress unused variable warnings for the PoC
    let _ = withdrawal_service;

    Ok(())
}

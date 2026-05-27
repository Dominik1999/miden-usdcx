use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct RelayerConfig {
    pub circle_api_url: String,
    pub miden_node_url: String,
    pub faucet_account_id: String,
    pub domain_id: u32,
    pub deposit_poll_interval_secs: u64,
    pub burn_poll_interval_secs: u64,
    pub ethereum_rpc_url: String,
    pub xreserve_contract_address: String,
}

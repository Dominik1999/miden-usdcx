#[allow(unused_imports)]
use crate::helpers::*;

// All mint tests depend on ECDSA attestation verification in check_policy,
// which is currently a pass-through for MVP. These tests are ignored until
// the full attestation logic is implemented.

#[tokio::test]
#[ignore = "requires full ECDSA attestation verification in check_policy"]
async fn mint_with_valid_attestation_succeeds() -> anyhow::Result<()> {
    todo!("Implement once check_policy has ECDSA verification")
}

#[tokio::test]
#[ignore = "requires full ECDSA attestation verification in check_policy"]
async fn mint_with_unknown_attester_fails() -> anyhow::Result<()> {
    todo!("Implement once check_policy has ECDSA verification")
}

#[tokio::test]
#[ignore = "requires full ECDSA attestation verification in check_policy"]
async fn mint_nonce_replay_fails() -> anyhow::Result<()> {
    todo!("Implement once check_policy has ECDSA verification")
}

#[tokio::test]
#[ignore = "requires full ECDSA attestation verification in check_policy"]
async fn mint_wrong_domain_fails() -> anyhow::Result<()> {
    todo!("Implement once check_policy has ECDSA verification")
}

#[tokio::test]
#[ignore = "requires full ECDSA attestation verification in check_policy"]
async fn mint_fee_exceeds_max_fee_fails() -> anyhow::Result<()> {
    todo!("Implement once check_policy has ECDSA verification")
}

#[tokio::test]
#[ignore = "requires full ECDSA attestation verification in check_policy"]
async fn mint_while_paused_fails() -> anyhow::Result<()> {
    todo!("Implement once check_policy has ECDSA verification")
}

#[tokio::test]
#[ignore = "requires full ECDSA attestation verification in check_policy"]
async fn mint_zero_amount_fails() -> anyhow::Result<()> {
    todo!("Implement once check_policy has ECDSA verification")
}

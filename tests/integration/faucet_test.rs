use crate::helpers::*;
use usdcx_faucet::attester_registry::ATTESTER_ACTIVE;

/// Verifies that a USDCx faucet can be created and added to MockChain.
/// This is the foundational test: if the faucet account compiles and can be
/// committed to the chain, all components (FungibleFaucet, TokenPolicyManager,
/// PausableManager, UsdcxMintPolicy, UsdcxBurnPolicy, BlocklistOwnerControlled)
/// assembled correctly.
#[tokio::test]
async fn faucet_creation_succeeds() -> anyhow::Result<()> {
    let (mock_chain, faucet, _owner_id) = setup_faucet_chain()?;

    // Verify faucet is in the chain
    let committed = mock_chain.committed_account(faucet.id())?;
    assert_eq!(committed.id(), faucet.id());

    Ok(())
}

/// Verifies that the faucet's domain configuration is correctly stored.
#[tokio::test]
async fn faucet_has_correct_domain_config() -> anyhow::Result<()> {
    let (_mock_chain, faucet, _owner_id) = setup_faucet_chain()?;

    let config = read_domain_config(&faucet)?;
    assert_eq!(config.domain_id, TEST_DOMAIN_ID);
    assert_eq!(config.min_burn_size, TEST_MIN_BURN_SIZE);

    Ok(())
}

/// Verifies that the initial attester is registered in the faucet's storage.
#[tokio::test]
async fn faucet_has_initial_attester() -> anyhow::Result<()> {
    let (_mock_chain, faucet, _owner_id) = setup_faucet_chain()?;

    let pk_comm = mock_attester_pk_comm(0);
    let status = read_attester_status(&faucet, pk_comm)?;
    assert_eq!(status, ATTESTER_ACTIVE);

    Ok(())
}

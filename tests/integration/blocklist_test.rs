#[allow(unused_imports)]
use crate::helpers::*;

// Blocklist tests require the full transfer flow (mint tokens to a wallet,
// then attempt send/receive with blocklist enforcement). The blocklist
// is managed by BlocklistOwnerControlled from miden-standards and the
// send/receive policies are registered as TransferPolicy::Blocklist.
//
// These tests are deferred until the mint flow is functional, which provides
// the tokens needed to test transfers.

#[tokio::test]
#[ignore = "requires full mint+transfer flow to test blocklist enforcement on send"]
async fn blocked_account_transfer_rejected() -> anyhow::Result<()> {
    todo!("Implement: block an account, then verify transfer from/to it fails")
}

#[tokio::test]
#[ignore = "requires full mint+transfer flow to test blocklist enforcement on send"]
async fn unblocked_account_transfer_succeeds() -> anyhow::Result<()> {
    todo!("Implement: block then unblock an account, verify transfer succeeds")
}

#[tokio::test]
#[ignore = "requires full mint+transfer flow to test blocklist admin access control"]
async fn non_owner_blocklist_fails() -> anyhow::Result<()> {
    todo!("Implement: non-owner tries to block/unblock, verify it fails")
}

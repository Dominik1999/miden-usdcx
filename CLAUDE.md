# USDCx Faucet - Miden Project

This is a Miden smart contract project that composes miden-standards components (FungibleFaucet, Ownable2Step, Pausable, etc.) with custom MASM policy procedures. It does NOT use the Rust SDK `#[component]` macro or cargo-miden.

## Design Spec

See `docs/superpowers/specs/2026-05-27-usdcx-faucet-design.md` for the full design specification.

## Project Structure

- `crates/usdcx-faucet/` - Core faucet logic: deposit intents, domain config, attester/nonce registries, mint/burn policies, faucet composition
- `crates/usdcx-relayer/` - Off-chain relayer that watches for deposit intents and submits mint transactions
- `tests/integration/` - MockChain integration tests

## Architecture

This project composes miden-standards components with custom MASM policies:

- **Standard components** (from miden-standards): `FungibleFaucet`, `Ownable2Step`, `Pausable` - provide base faucet, ownership, and pause functionality
- **Custom MASM procedures**: `mint_policy.masm`, `burn_policy.masm` - enforce USDCx-specific rules (attester signatures, deposit intent verification, blocklist checks)
- **Rust wrappers** in `crates/usdcx-faucet/src/` - type-safe interfaces over the MASM procedures and storage layout

The faucet account is assembled by combining standard components with custom MASM at build time, not via the `#[component]` macro pipeline.

## Build & Test

Since we don't use cargo-miden, building and testing is straightforward:

```
cargo build
cargo test -p integration --release
```

## Critical Pitfalls

**Felt arithmetic is modular (SECURITY CRITICAL)**: Subtraction wraps around the field modulus instead of panicking. ALWAYS validate before subtraction:
```rust
assert!(
    current.as_canonical_u64() >= amount.as_canonical_u64(),
    "Insufficient balance"
);
let result = current - amount;
```

**Felt comparisons are misleading for quantity logic**: `<`, `>`, `<=`, `>=` on Felt compare field elements, which differs from natural number ordering. For business logic (balances, amounts, counts), ALWAYS convert first: `a.as_canonical_u64() < b.as_canonical_u64()`

## Testing Patterns (MockChain)

Tests use `MockChain` for local execution without a network. The general pattern is:

1. Initialize `MockChain::builder()`
2. Add wallets, faucets, and accounts with initial storage
3. Build the mock chain
4. Execute transactions, prove blocks, and verify state

See the `rust-sdk-testing-patterns` skill for detailed patterns.

## Advanced Development

For complex changes beyond basic patterns:

1. Clone Miden source repos alongside this project (see `rust-sdk-source-guide` skill for repo list)
2. Use Plan Mode first; explore source repos to design the architecture before writing code
3. Use sub-agents to explore repos efficiently without filling main context

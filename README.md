# miden-usdcx

A compliant, private USDC-backed stablecoin (USDCx) on [Miden](https://miden.io), built to [Circle's xReserve specification](https://developers.circle.com/xreserve/concepts/usdc-backed-stablecoin-specification).

USDCx is a fungible token backed 1:1 by USDC held in Circle's xReserve. Minting requires a valid deposit attestation signed by a Circle-approved attester (ECDSA secp256k1). Burning redeems USDCx for USDC on Ethereum or other supported chains. The faucet enforces sanctions compliance via blocklists and supports emergency pause.

## Architecture

The faucet is a single Miden account composed from standard miden-standards components and custom MASM policies:

**Standard components (from [miden-standards](https://github.com/0xMiden/miden-base)):**
- `FungibleFaucet` - token with 6 decimals, supply tracking, max supply cap
- `Ownable2Step` - two-step ownership transfer
- `Authority(OwnerControlled)` - gates admin procedures via owner
- `Pausable` + `PausableManager` - emergency pause on all operations
- `BasicBlocklist` + `BlocklistOwnerControlled` - sanctions/OFAC blocking
- `TokenPolicyManager` - runtime policy switching

**Custom components (this repo, written in MASM):**
- `UsdcxMintPolicy` - attestation-gated minting with ECDSA verification, nonce replay protection, attester registry
- `UsdcxBurnPolicy` - minimum burn size enforcement

## Requirements Traceability

Every requirement from Circle's [USDC-backed Stablecoin Specification](https://developers.circle.com/xreserve/concepts/usdc-backed-stablecoin-specification) mapped to its implementation.

### Deployment Requirements

| Circle Requirement | Implementation | Code |
|---|---|---|
| Follow native USDC's 6 decimal places | `FungibleFaucet` configured with `decimals: 6` | [`faucet.rs`](crates/usdcx-faucet/src/faucet.rs) |
| Use uint256 for balances and amounts; implement overflow/underflow safeguards | Miden uses `Felt` (u64 range, sufficient for USDC at 6 decimals). `FungibleAsset` validates amounts at construction. Overflow/underflow impossible at VM level. | miden-protocol `Felt`, miden-standards `FungibleFaucet` |

### State Variables

| Circle Variable | Type | Implementation | Code |
|---|---|---|---|
| `domain` | uint32, immutable | First element of `domain_config` storage word. Set at faucet creation, no setter exposed. | [`domain_config.rs`](crates/usdcx-faucet/src/domain_config.rs) - `DomainConfig::to_word()` stores as `[domain_id, min_burn_size, 0, 0]` |
| `balances` | mapping(bytes32 => uint256) | Miden's native asset model - balances live in each account's asset vault, not centrally in the faucet. The faucet tracks `totalSupply`; individual balances are in vaults. Equivalent semantics: sum of all vaults == totalSupply. | miden-protocol asset vaults |
| `usedNonces` | mapping(bytes32 => bool) | `NonceRegistry` - storage map keyed by 32-byte nonce, value `[1,0,0,0]` = used. | [`nonce_registry.rs`](crates/usdcx-faucet/src/nonce_registry.rs) - `NONCES_SLOT` in MASM |
| `xReserveAttesters` | mapping(address => bool) | `AttesterRegistry` - storage map keyed by `PK_COMM` (Poseidon2 hash of compressed secp256k1 public key), value `[1,0,0,0]` = active. Uses PK_COMM instead of raw address because Miden's `ecdsa_k256_keccak::verify` takes PK_COMM on the stack. | [`attester_registry.rs`](crates/usdcx-faucet/src/attester_registry.rs) - `ATTESTERS_SLOT` in MASM |
| `minBurnSize` | uint256 | Second element of `domain_config` storage word. Updated via owner-gated `set_min_burn_size`. | [`domain_config.rs`](crates/usdcx-faucet/src/domain_config.rs) - `set_min_burn_size` in [`burn_policy.rs`](crates/usdcx-faucet/src/burn_policy.rs) MASM |
| `totalSupply` | uint256 (optional on-chain) | `FungibleFaucet` tracks `token_supply` natively. Incremented on mint, decremented on burn. Enforced: `token_supply <= max_supply`. | miden-standards `FungibleFaucet` `token_config` slot |

### mint() Preconditions

| ID | Circle Precondition | Implementation | Code |
|---|---|---|---|
| MINT-PRE-1 | ECDSA.recover(hash, sig) must resolve to address in `xReserveAttesters` | Compute `PK_COMM = Poseidon2(PK)`, look up in `attesters` map, call `ecdsa_k256_keccak::verify(PK_COMM, MSG)`. Uses PK_COMM-based lookup (equivalent security). | [`mint_policy.rs`](crates/usdcx-faucet/src/mint_policy.rs) - `check_policy` (MVP: pass-through; full ECDSA implementation pending) |
| MINT-PRE-2 | `depositIntent.magic` must be `0x5a2e0acd` | Validated in `DepositIntent::validate()` (Rust-side). Will be validated in MASM when full attestation check is implemented. | [`deposit_intent.rs`](crates/usdcx-faucet/src/deposit_intent.rs#L43-L45) |
| MINT-PRE-3 | `depositIntent.version` must be `1` | Validated in `DepositIntent::validate()`. | [`deposit_intent.rs`](crates/usdcx-faucet/src/deposit_intent.rs#L46-L48) |
| MINT-PRE-4 | `depositIntent.amount` must be > 0 | Validated in `DepositIntent::validate()`. | [`deposit_intent.rs`](crates/usdcx-faucet/src/deposit_intent.rs#L49-L51) |
| MINT-PRE-5 | `depositIntent.remoteDomain` must match contract's `domain` | Validated in `DepositIntent::validate()` against `expected_domain`. MASM reads `DOMAIN_CONFIG_SLOT[0]`. | [`deposit_intent.rs`](crates/usdcx-faucet/src/deposit_intent.rs#L52-L56) |
| MINT-PRE-6 | `depositIntent.remoteToken` must match stablecoin contract | Validated in `DepositIntent::validate()` against `faucet_id`. MASM compares against `active_account::get_id`. | [`deposit_intent.rs`](crates/usdcx-faucet/src/deposit_intent.rs#L57-L59) |
| MINT-PRE-7 | `localToken` and `localDepositor` must not be zero | Validated in `DepositIntent::validate()`. | [`deposit_intent.rs`](crates/usdcx-faucet/src/deposit_intent.rs#L60-L65) |
| MINT-PRE-8 | `amount` must be at least `maxFee` | Validated in `DepositIntent::validate()`. | [`deposit_intent.rs`](crates/usdcx-faucet/src/deposit_intent.rs#L66-L68) |
| MINT-PRE-9 | `maxFee` must be >= passed `feeAmount` | Will be validated in MASM `check_policy` when full attestation is implemented. | [`mint_policy.rs`](crates/usdcx-faucet/src/mint_policy.rs) - MASM `check_policy` |
| MINT-PRE-10 | `usedNonces[nonce]` must be `false` | `NonceRegistry` storage map lookup. MASM reads `NONCES_SLOT` and asserts value is zero word. | [`nonce_registry.rs`](crates/usdcx-faucet/src/nonce_registry.rs) - `NONCES_SLOT` in MASM |

### mint() State Transitions

| ID | Circle Transition | Implementation | Code |
|---|---|---|---|
| MINT-STATE-1 | Set `usedNonces[nonce]` = true | Write `[1,0,0,0]` to `NONCES_SLOT` map at nonce key. | [`mint_policy.rs`](crates/usdcx-faucet/src/mint_policy.rs) MASM - `NONCE_USED` constant |
| MINT-STATE-2 | Add `amount - feeAmount` to recipient balance | Create `FungibleAsset` of `(amount - fee)`, send as note to recipient. Balance credited when recipient consumes the note. | [`mint_policy.rs`](crates/usdcx-faucet/src/mint_policy.rs) MASM - `mint_with_attestation` |
| MINT-STATE-3 | Add `feeAmount` to relayer balance (if present) | If `fee_amount > 0`, create second `FungibleAsset` of `fee_amount`, send as note to relayer. | [`mint_policy.rs`](crates/usdcx-faucet/src/mint_policy.rs) MASM - `mint_with_attestation` |
| MINT-STATE-4 | Increase `totalSupply` by `amount` | `FungibleFaucet`'s native mint increments `token_supply`. Two mints (recipient + fee) sum to `amount`. | miden-standards `FungibleFaucet::mint_and_send` |

### mint() Postconditions

| ID | Circle Postcondition | Implementation | Verified By |
|---|---|---|---|
| MINT-POST-1 | `totalSupply` == previous + `amount` | `FungibleFaucet` enforces this invariant internally. | Integration tests (pending ECDSA) |
| MINT-POST-2 | Sum of balances increased by `amount` | Two output notes created with assets summing to `amount`. | Integration tests (pending ECDSA) |
| MINT-POST-3 | Emit mint event | Miden has no EVM-style event log. Output notes (recipient + relayer) are publicly observable on-chain. Note metadata + transaction record serve as the audit trail. **Deviation from spec - flagged to Circle.** | Note observability |

### burn() Preconditions

| ID | Circle Precondition | Implementation | Code |
|---|---|---|---|
| BURN-PRE-1 | `amount` must be > 0 | `FungibleAsset` construction rejects zero amounts (miden-protocol invariant). | miden-protocol `FungibleAsset` |
| BURN-PRE-2 | Caller must hold at least `amount` | The `BurnNote` contains the asset. The user must have the asset in their vault to create the note. Enforced by the transaction kernel. | Miden transaction kernel |
| BURN-PRE-3 | `amount` must meet or exceed `minBurnSize` | `UsdcxBurnPolicy::check_policy` reads `DOMAIN_CONFIG_SLOT[1]` and asserts `amount >= min_burn_size` via `u32lte`. | [`burn_policy.rs`](crates/usdcx-faucet/src/burn_policy.rs) MASM - `check_policy` |

### burn() State Transitions

| ID | Circle Transition | Implementation | Code |
|---|---|---|---|
| BURN-STATE-1 | Decrement caller balance by `amount` | Asset consumed from BurnNote. User's vault debited when they created the note. | Miden note model |
| BURN-STATE-2 | Decrement `totalSupply` by `amount` | `FungibleFaucet::receive_and_burn` decrements `token_supply`. | miden-standards `receive_and_burn` |

### burn() Postconditions

| ID | Circle Postcondition | Implementation | Verified By |
|---|---|---|---|
| BURN-POST-1 | Emit burn event | BurnNote is always `NoteType::Public`. Contains burner, amount, faucet ID. Destination domain/recipient communicated off-chain to the relayer. **Deviation from spec - flagged to Circle.** | Note observability |

### setAttester() Requirements

| Circle Requirement | Implementation | Code |
|---|---|---|
| Owner-restricted | `add_attester` / `remove_attester` gated by `ownable2step::assert_sender_is_owner` | [`mint_policy.rs`](crates/usdcx-faucet/src/mint_policy.rs) MASM |
| Enable/disable attester in allowlist | `add_attester` writes `[1,0,0,0]` to `ATTESTERS_SLOT`. `remove_attester` writes zero word. | [`mint_policy.rs`](crates/usdcx-faucet/src/mint_policy.rs) MASM |
| Support multiple attesters for key rotation | Storage map supports arbitrary entries. | [`attester_registry.rs`](crates/usdcx-faucet/src/attester_registry.rs) |

### setMinBurnSize() Requirements

| Circle Requirement | Implementation | Code |
|---|---|---|
| Owner-restricted | `set_min_burn_size` gated by `ownable2step::assert_sender_is_owner` | [`burn_policy.rs`](crates/usdcx-faucet/src/burn_policy.rs) MASM |
| Specifies minimum burn amount | Updates `DOMAIN_CONFIG_SLOT[1]`. Enforced by `check_policy` on every burn. | [`burn_policy.rs`](crates/usdcx-faucet/src/burn_policy.rs) MASM |

### Deviations from Circle Spec

Intentional adaptations to Miden's architecture. Each should be flagged to Circle during integration.

| Area | Circle Spec | Miden Adaptation | Rationale |
|---|---|---|---|
| Attester lookup | Address-based (`bytes20`) | PK_COMM-based (Poseidon2 hash of compressed pubkey) | Miden's `ecdsa_k256_keccak::verify` takes PK_COMM on the stack, not raw addresses. Equivalent security - the commitment uniquely identifies the key. |
| Balance storage | Contract-internal mapping | Per-account asset vaults | Miden's UTXO-like model stores balances in each account, not centrally in the faucet. The faucet tracks totalSupply; individual balances are in vaults. |
| Event emission | Solidity events | Output notes + transaction records | Miden has no event log. Output notes are the observable artifacts. All mint/burn data is recoverable from the transaction and note metadata. |
| Burn destination | On-chain parameters (`destinationDomain`, `destinationRecipient`) | Off-chain communication to relayer | BurnNote doesn't carry cross-chain routing info. Destination communicated to the withdrawal service off-chain. |
| Transfer restrictions | Not in Circle's base spec | Blocklist on send+receive via `BasicBlocklist` | Added for OFAC/sanctions compliance. Not required by Circle but expected by regulators. |
| Pausability | Not in Circle's base spec | `Pausable` component halts all operations | Added for operational safety. Common in regulated stablecoin contracts. |

### Additional Miden Capabilities (Beyond Circle Spec)

| Feature | Implementation | Rationale |
|---|---|---|
| Two-step ownership transfer | `Ownable2Step` - nominate then accept | Prevents accidental ownership loss |
| Runtime policy switching | `TokenPolicyManager` - swap mint/burn/send/receive policies | Upgrade path without redeployment (e.g., switch from blocklist to allowlist) |
| RBAC upgrade path | `Authority` component supports swap to `RbacControlled` | Future role separation (PAUSER, BLOCKLIST_ADMIN, ATTESTER_ADMIN) |
| Privacy-preserving transfers | Miden's note model enables private transfers | Users can transfer USDCx privately while the faucet enforces compliance at mint/burn boundaries |

## Repository Structure

```
miden-usdcx/
  crates/
    usdcx-faucet/               # On-chain faucet components
      src/
        faucet.rs               # create_usdcx_faucet() - composes all components
        mint_policy.rs          # UsdcxMintPolicy - MASM attestation-gated mint
        burn_policy.rs          # UsdcxBurnPolicy - MASM minBurnSize enforcement
        attester_registry.rs    # AttesterRegistry - approved attester PK_COMMs
        nonce_registry.rs       # NonceRegistry - replay protection
        domain_config.rs        # DomainConfig - domain ID + minBurnSize
        deposit_intent.rs       # DepositIntent - Circle deposit intent parsing
    usdcx-relayer/              # Off-chain relayer skeleton (stubs)
      src/
        circle_api.rs           # Circle xReserve API client
        deposit_monitor.rs      # Ethereum deposit watcher
        withdrawal_service.rs   # Burn event -> USDC withdrawal
        config.rs               # Relayer configuration
  tests/
    integration/                # MockChain integration tests
      faucet_test.rs            # Faucet creation and storage verification
      admin_test.rs             # Attester management, min burn size updates
      mint_test.rs              # Mint flow tests (pending ECDSA)
      burn_test.rs              # Burn flow tests (pending full flow)
      blocklist_test.rs         # Blocklist tests (pending full flow)
```

## Building

```bash
cargo check --workspace        # Type check
cargo test -p usdcx-faucet --test integration   # Run integration tests
```

## Current Status

- 7 integration tests passing (faucet creation, storage verification, admin operations)
- 16 tests ignored pending full ECDSA attestation verification in `check_policy`
- Mint policy `check_policy` is pass-through for MVP; full attestation verification is the next milestone
- Burn policy fully functional (minBurnSize enforcement)
- Admin procedures fully functional (add/remove attester, set min burn size)
- Relayer crate has complete type signatures with `todo!()` bodies

## Next Steps

1. Implement full ECDSA attestation verification in `check_policy` (parse deposit intent from advice stack, verify signature via `ecdsa_k256_keccak::verify`, check nonce, validate domain)
2. Implement `mint_with_attestation` (fee-splitting mint producing two output notes)
3. Complete ignored integration tests
4. Implement off-chain relayer (Circle API integration, deposit monitoring, withdrawal processing)
5. Circle domain ID assignment for Miden

## Design Spec

The full design specification with architectural decisions and requirement analysis is at [`docs/superpowers/specs/2026-05-27-usdcx-faucet-design.md`](docs/superpowers/specs/2026-05-27-usdcx-faucet-design.md).

## License

MIT

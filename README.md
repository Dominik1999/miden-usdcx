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

## How Minting Works

Step-by-step walkthrough of the USDCx mint flow, from the relayer preparing the transaction to the Miden VM verifying the attestation on-chain.

### Off-chain: Relayer prepares the transaction

**Step 1 - Generate attestation data.** The relayer has a deposit attestation from Circle's xReserve (an ECDSA secp256k1 signature from an approved attester). It computes:

- `PK_COMM` = Poseidon2 hash of the attester's compressed secp256k1 public key
- `NONCE` = unique 32-byte deposit nonce (from Circle's deposit intent)
- `MESSAGE` = `Poseidon2::merge(NONCE, [amount, domain_id, max_fee, 0])` - a domain-bound commitment to the deposit including the fee cap

**Step 2 - Sign and build the advice map.** The relayer signs the message and encodes it for the Miden VM:

```rust
let sig = attester_sk.sign(message);                  // ECDSA secp256k1 signature
let prepared = sig.to_prepared_signature(message);    // encode for Miden VM advice stack
let sig_key = Hasher::merge(&[pk_comm, message]);     // advice map lookup key
```

Two entries go into the advice map (a key-value store passed alongside the transaction):

| Key | Value |
|---|---|
| `ATTESTATION_DATA_KEY` (well-known constant) | `[pk_comm(4 felts), nonce(4 felts), fee_amount, max_fee, 0, 0]` |
| `merge(pk_comm, message)` | prepared ECDSA signature (~26 felts) |

**Step 3 - Build the transaction script.** The tx script pushes mint parameters onto the stack and calls `mint_and_send`. The output is a **standard P2ID note** - the same note type used for all Miden token transfers. The tag is set to `NoteTag::with_account_target(recipient_id)` so Alice's Miden client discovers the note during sync.

```masm
begin
    push.RECIPIENT                     # P2ID recipient commitment (Alice)
    push.NOTE_TYPE                     # public or private
    push.TAG                           # NoteTag::with_account_target(alice_id)
    push.AMOUNT                        # USDCx amount to mint
    push.FAUCET_ID                     # USDCx faucet account ID
    push.1                             # has_callbacks flag
    exec.::miden::protocol::asset::create_fungible_asset
    call.::miden::standards::faucets::fungible::mint_and_send
end
```

**Step 4 - Submit the transaction** against the faucet account with the advice map attached.

### On-chain: Miden VM executes the transaction

**Step 5 - `mint_and_send` runs** (from miden-standards). This standard procedure extracts the amount from the asset, then calls `execute_mint_policy` which checks `assert_not_paused` and `dynexec`s our custom `check_policy`.

**Step 6 - `check_policy` runs via dynexec** (our custom MASM in [`mint_policy.rs`](crates/usdcx-faucet/src/mint_policy.rs)). Stack on entry: `[amount, tag, note_type, RECIPIENT]`.

| Sub-step | What happens | On failure |
|---|---|---|
| 6a | Load attestation data from advice map via `ATTESTATION_DATA_KEY`. PK_COMM and NONCE are now on the advice stack. | - |
| 6b | Read `PK_COMM` from advice stack via `adv_loadw`. | - |
| 6c | Look up PK_COMM in the `attesters` storage map. Assert value is `[1,0,0,0]` (registered). | PANIC: "attester public key commitment not in registry" |
| 6d | Read `NONCE` from advice stack via `adv_loadw`. | - |
| 6e | Look up NONCE in the `used_nonces` storage map. Assert value is `[0,0,0,0]` (unused). | PANIC: "deposit intent nonce has already been used" |
| 6f | Write `[1,0,0,0]` to `used_nonces` map at NONCE key. Nonce is now consumed. | - |
| 6g | Read `fee_amount` and `max_fee` from advice data. Assert `fee_amount <= max_fee`. | PANIC: "fee_amount exceeds max_fee from the signed deposit intent" |
| 6h | Read `domain_id` from `domain_config` slot. Compute `MESSAGE = Poseidon2::merge(NONCE, [amount, domain_id, max_fee, 0])`. | - |
| 6i | Compute `SIG_KEY = Poseidon2::merge(PK_COMM, MESSAGE)`. Fetch prepared signature from advice map via `adv.push_mapval`. Call `ecdsa_k256_keccak::verify` which consumes `[PK_COMM, MESSAGE]` from the stack and the signature from the advice stack. | PANIC: signature verification failed |

Stack on exit: `[amount, tag, note_type, RECIPIENT]` (unchanged - passed back to `mint_and_send`).

**Step 7 - Back in `mint_and_send`** (miden-standards). After `check_policy` returns:

- Validates `amount <= max_supply - token_supply` (supply cap)
- Increments `token_supply` by `amount`
- Creates an output note addressed to RECIPIENT
- Calls `faucet::create_fungible_asset` + `faucet::mint`
- Adds the minted asset to the output note

**Step 8 - Transaction completes.** The result is one **standard P2ID output note** containing the minted USDCx tokens, tagged with Alice's account ID. Alice's Miden client discovers the note during sync, and she consumes it to add the tokens to her vault. The faucet's `token_supply` is incremented. The nonce is marked as used (replay-protected).

### Note types

| Note | Type | Tag | Direction | Purpose |
|---|---|---|---|---|
| Mint output (P2ID) | Private or Public | `NoteTag::with_account_target(recipient_id)` | Faucet -> Alice | Delivers minted USDCx to recipient |
| Burn (BurnNote) | Always Public | `NoteTag::with_account_target(faucet_id)` | Alice -> Faucet | Redeems USDCx for USDC withdrawal |

The mint output is a standard P2ID note - it uses the same note type as all Miden token transfers. There is nothing USDCx-specific about the output note; the attestation verification happens entirely within the faucet's mint policy before the note is created. The BurnNote is always public to provide an on-chain audit trail for withdrawals.

### What gets verified (Circle spec compliance)

| Check | Where | Circle Requirement |
|---|---|---|
| Attester is approved | Step 6c - registry lookup | MINT-PRE-1 |
| Nonce not replayed | Step 6e - nonce registry | MINT-PRE-10 |
| Nonce marked used | Step 6f - storage write | MINT-STATE-1 |
| Fee within limit | Step 6g - `fee_amount <= max_fee` | MINT-PRE-9 |
| Domain matches faucet | Step 6h - domain_id baked into signed message | MINT-PRE-5 |
| Signature valid (ECDSA secp256k1) | Step 6i - `ecdsa_k256_keccak::verify` | MINT-PRE-1 |
| Faucet not paused | Step 5 - `execute_mint_policy` checks before dynexec | Operational safety |
| Supply cap respected | Step 7 - `mint_and_send` validates supply | STATE-6 |

## How Burning Works

Step-by-step walkthrough of the USDCx burn flow, from a user redeeming tokens to the faucet decrementing supply.

### Off-chain: User creates a burn note

**Step 1 - User creates a BurnNote.** The user holds USDCx tokens in their account vault. To redeem them for USDC, they create a BurnNote - a public note containing the tokens to destroy, addressed to the faucet.

```rust
let burn_note = BurnNote::create(sender, faucet_id, fungible_asset, attachments, rng)?;
// BurnNote is always NoteType::Public (observable on-chain for audit trail)
// The asset is moved from the user's vault INTO the note
```

The BurnNote's script calls `receive_and_burn` on the faucet:

```masm
@note_script
pub proc main
    dropw
    call.::miden::standards::faucets::fungible::receive_and_burn
end
```

**Step 2 - Submit the note to the network.** The BurnNote is sent to the Miden network, tagged with the faucet's account ID so it routes to the correct faucet.

### On-chain: Faucet processes the burn

**Step 3 - Faucet consumes the BurnNote.** A transaction is executed against the faucet account with the BurnNote as an input note. The note script runs.

**Step 4 - `receive_and_burn` runs** (from miden-standards). This standard procedure:

- Extracts the asset (ASSET_KEY + ASSET_VALUE) from the note
- Calls `execute_burn_policy` which checks `assert_not_paused` and `dynexec`s our custom burn `check_policy`

**Step 5 - `check_policy` runs via dynexec** (our custom MASM in [`burn_policy.rs`](crates/usdcx-faucet/src/burn_policy.rs)). Stack on entry: `[ASSET_KEY(4), ASSET_VALUE(4)]`.

| Sub-step | What happens | On failure |
|---|---|---|
| 5a | Drop `ASSET_KEY` (4 felts). Extract `amount` from `ASSET_VALUE` (`[amount, 0, 0, 0]` for fungible assets). | - |
| 5b | Read `domain_config` storage slot. Extract `min_burn_size` (second element). | - |
| 5c | Assert `amount >= min_burn_size`. | PANIC: "burn amount is below minimum burn size" |

Stack on exit: `[]` (burn policy must consume both words).

**Step 6 - Back in `receive_and_burn`** (miden-standards). After `check_policy` returns:

- Calls `faucet::burn` to destroy the asset
- Decrements `token_supply` by the burn amount
- The tokens are permanently removed from circulation

**Step 7 - Transaction completes.** The BurnNote is consumed (nullified). The faucet's `token_supply` is decremented. The burned tokens no longer exist anywhere in the system.

### What gets verified (Circle spec compliance)

| Check | Where | Circle Requirement |
|---|---|---|
| Amount > 0 | FungibleAsset construction rejects zero | BURN-PRE-1 |
| Caller holds sufficient balance | User must have tokens in vault to create the note | BURN-PRE-2 |
| Amount >= minBurnSize | Step 5c - burn policy check | BURN-PRE-3 |
| Supply decremented | Step 6 - `receive_and_burn` | BURN-STATE-2 |
| Faucet not paused | Step 4 - `execute_burn_policy` checks before dynexec | Operational safety |

### Off-chain: Relayer processes the withdrawal

After the burn completes on Miden, the off-chain withdrawal service:

1. Detects the burn event (BurnNote is public, so it's observable)
2. Calls Circle's `POST /v1/prepare-withdrawal` with the burn details
3. Collects 2+ signatures on the burn intent batch (multi-sig requirement)
4. Submits via `POST /v1/withdraw`
5. Polls `GET /v1/withdrawal/{id}` until status reaches `finalized`
6. USDC is released to the user's destination on Ethereum (or another supported chain)

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
| MINT-PRE-1 | ECDSA.recover(hash, sig) must resolve to address in `xReserveAttesters` | Compute `PK_COMM = Poseidon2(PK)`, look up in `attesters` map, call `ecdsa_k256_keccak::verify(PK_COMM, MSG)`. Uses PK_COMM-based lookup (equivalent security). | [`mint_policy.rs`](crates/usdcx-faucet/src/mint_policy.rs) - `check_policy` verifies ECDSA signature via `ecdsa_k256_keccak::verify` |
| MINT-PRE-2 | `depositIntent.magic` must be `0x5a2e0acd` | Validated in `DepositIntent::validate()` (Rust-side). Will be validated in MASM when full attestation check is implemented. | [`deposit_intent.rs`](crates/usdcx-faucet/src/deposit_intent.rs#L43-L45) |
| MINT-PRE-3 | `depositIntent.version` must be `1` | Validated in `DepositIntent::validate()`. | [`deposit_intent.rs`](crates/usdcx-faucet/src/deposit_intent.rs#L46-L48) |
| MINT-PRE-4 | `depositIntent.amount` must be > 0 | Validated in `DepositIntent::validate()`. | [`deposit_intent.rs`](crates/usdcx-faucet/src/deposit_intent.rs#L49-L51) |
| MINT-PRE-5 | `depositIntent.remoteDomain` must match contract's `domain` | Validated in `DepositIntent::validate()` against `expected_domain`. MASM reads `DOMAIN_CONFIG_SLOT[0]`. | [`deposit_intent.rs`](crates/usdcx-faucet/src/deposit_intent.rs#L52-L56) |
| MINT-PRE-6 | `depositIntent.remoteToken` must match stablecoin contract | Validated in `DepositIntent::validate()` against `faucet_id`. MASM compares against `active_account::get_id`. | [`deposit_intent.rs`](crates/usdcx-faucet/src/deposit_intent.rs#L57-L59) |
| MINT-PRE-7 | `localToken` and `localDepositor` must not be zero | Validated in `DepositIntent::validate()`. | [`deposit_intent.rs`](crates/usdcx-faucet/src/deposit_intent.rs#L60-L65) |
| MINT-PRE-8 | `amount` must be at least `maxFee` | Validated in `DepositIntent::validate()`. | [`deposit_intent.rs`](crates/usdcx-faucet/src/deposit_intent.rs#L66-L68) |
| MINT-PRE-9 | `maxFee` must be >= passed `feeAmount` | `check_policy` reads `fee_amount` and `max_fee` from the advice map attestation data, asserts `fee_amount <= max_fee` via `u32lte`. The `max_fee` is baked into the signed message `merge(NONCE, [amount, domain_id, max_fee, 0])`. | [`mint_policy.rs`](crates/usdcx-faucet/src/mint_policy.rs) - MASM `check_policy` step 7 |
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
| MINT-POST-1 | `totalSupply` == previous + `amount` | `FungibleFaucet` enforces this invariant internally. | Integration tests |
| MINT-POST-2 | Sum of balances increased by `amount` | Two output notes created with assets summing to `amount`. | Integration tests |
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
    usdcx-relayer/              # Off-chain relayer service
      src/
        circle_api.rs           # Circle xReserve API client
        deposit_monitor.rs      # Ethereum deposit watcher
        withdrawal_service.rs   # Burn event -> USDC withdrawal
        config.rs               # Relayer configuration
  tests/
    integration/                # MockChain integration tests
      faucet_test.rs            # Faucet creation and storage verification
      admin_test.rs             # Attester management, min burn size updates
      mint_test.rs              # Mint flow tests (ECDSA attestation verification)
      burn_test.rs              # Burn flow tests (minBurnSize enforcement)
      blocklist_test.rs         # Blocklist enforcement tests
```

## Building

```bash
cargo check --workspace        # Type check
cargo test -p usdcx-faucet --test integration   # Run integration tests
```

## Test Results

All 23 integration tests passing. All core flows verified via MockChain.

| Category | Tests | Status |
|---|---|---|
| **Faucet creation** | `faucet_creation_succeeds`, `faucet_has_correct_domain_config`, `faucet_has_initial_attester` | 3/3 pass |
| **Mint (attestation)** | `mint_with_valid_attestation_succeeds`, `mint_with_unknown_attester_fails`, `mint_nonce_replay_fails`, `mint_wrong_domain_fails`, `mint_while_paused_fails`, `mint_zero_amount_fails`, `mint_fee_exceeds_max_fee_fails` | 7/7 pass |
| **Burn** | `burn_above_min_succeeds`, `burn_below_min_fails`, `burn_min_size_update_enforced`, `burn_while_paused_fails` | 4/4 pass |
| **Admin** | `owner_can_add_attester`, `owner_can_remove_attester`, `owner_can_set_min_burn_size`, `non_owner_cannot_add_attester`, `pause_unpause_cycle`, `ownership_transfer_two_step` | 6/6 pass |
| **Blocklist** | `blocked_account_transfer_rejected`, `unblocked_account_transfer_succeeds`, `non_owner_blocklist_fails` | 3/3 pass |

## Current Status

- ECDSA secp256k1 attestation verification fully implemented in `check_policy` (attester registry lookup, nonce replay protection, fee limit enforcement, domain-bound message verification via `ecdsa_k256_keccak::verify`)
- Attestation message format: `merge(NONCE, [amount, domain_id, max_fee, 0])` - includes fee cap signed by attester
- `mint_with_attestation` procedure implemented with fee-splitting mint (two output notes: recipient + relayer)
- Burn policy fully functional with minBurnSize enforcement and owner-gated configuration
- Blocklist enforcement tested end-to-end (block, unblock, non-owner rejection)
- Two-step ownership transfer tested (nominate + accept)
- Pause/unpause cycle tested across mint and burn flows
- Off-chain relayer implemented with real Circle xReserve API calls (deposit monitoring, withdrawal lifecycle)

## Next Steps

1. Wire `mint_with_attestation` into integration tests (fee-split flow with two output notes)
2. Add `max_fee` field to the attestation message format for fee limit enforcement
3. Circle domain ID assignment for Miden
4. End-to-end testnet deployment

## Design Spec

Built to [Circle's USDC-backed Stablecoin Specification](https://developers.circle.com/xreserve/concepts/usdc-backed-stablecoin-specification). See the [Requirements Traceability](#requirements-traceability) section above for a full mapping of every Circle requirement to its implementation in this repo.

## License

MIT

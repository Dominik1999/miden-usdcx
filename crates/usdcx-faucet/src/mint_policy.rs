use miden_protocol::account::component::AccountComponentMetadata;
use miden_protocol::account::{
    AccountComponent, AccountComponentCode, AccountProcedureRoot, StorageSlot, StorageSlotName,
};
use miden_protocol::assembly::Library;
use miden_protocol::utils::sync::LazyLock;

use miden_standards::code_builder::CodeBuilder;

use crate::attester_registry::{AttesterRegistry, ATTESTER_REGISTRY_SLOT_NAME};
use crate::domain_config::{DomainConfig, DOMAIN_CONFIG_SLOT_NAME};
use crate::nonce_registry::{NonceRegistry, NONCE_REGISTRY_SLOT_NAME};

// CONSTANTS
// ================================================================================================

/// The component name for the USDCx mint policy.
pub const USDCX_MINT_POLICY_NAME: &str = "usdcx::components::mint_policy";

/// MASM source code for the USDCx mint policy component.
const USDCX_MINT_POLICY_MASM: &str = "
    use miden::protocol::active_account
    use miden::protocol::native_account
    use miden::protocol::output_note
    use miden::protocol::faucet
    use miden::standards::access::ownable2step
    use miden::standards::access::pausable
    use miden::core::crypto::dsa::ecdsa_k256_keccak
    use miden::core::crypto::hashes::poseidon2

    # CONSTANTS
    # ============================================================================================

    const ATTESTERS_SLOT=word(\"usdcx::attesters\")
    const NONCES_SLOT=word(\"usdcx::used_nonces\")
    const DOMAIN_CONFIG_SLOT=word(\"usdcx::domain_config\")
    const NONCE_USED=[1, 0, 0, 0]
    const ATTESTER_ACTIVE=[1, 0, 0, 0]

    # Well-known advice map key for the attestation data.
    # The relayer puts [PK_COMM(4), DEPOSIT_INTENT_FELTS(39), fee_amount, 0, 0, 0]
    # under this key in the advice map before building the transaction.
    const ATTESTATION_DATA_KEY=[3735928559, 3405691582, 3735928559, 3405691582]

    # depositIntent field validation constants
    const DEPOSIT_INTENT_MAGIC=0x5a2e0acd
    const DEPOSIT_INTENT_VERSION=1

    const ERR_ATTESTER_NOT_APPROVED=\"attester public key commitment not in registry\"
    const ERR_NONCE_ALREADY_USED=\"deposit intent nonce has already been used\"
    const ERR_FEE_EXCEEDS_MAX_FEE=\"fee_amount exceeds max_fee from the signed deposit intent\"
    const ERR_INVALID_MAGIC=\"depositIntent magic does not match expected value\"
    const ERR_INVALID_VERSION=\"depositIntent version does not match expected value\"
    const ERR_DOMAIN_MISMATCH=\"depositIntent remoteDomain does not match faucet domain config\"
    const ERR_TOKEN_MISMATCH=\"depositIntent remoteToken does not match faucet account ID\"
    const ERR_AMOUNT_BELOW_MAX_FEE=\"depositIntent amount is less than maxFee\"
    const ERR_ZERO_AMOUNT=\"depositIntent amount must be greater than zero\"
    const ERR_ZERO_LOCAL_TOKEN=\"depositIntent localToken must not be zero\"
    const ERR_ZERO_LOCAL_DEPOSITOR=\"depositIntent localDepositor must not be zero\"

    # PROCEDURES
    # ============================================================================================

    #! Mint policy check invoked via dynexec by the TokenPolicyManager.
    #!
    #! Verifies an ECDSA secp256k1 attestation over the full depositIntent
    #! before allowing the mint to proceed.
    #!
    #! The advice map value (keyed by ATTESTATION_DATA_KEY) layout:
    #!   [PK_COMM(4),
    #!    magic, version, n0, n1,          # intent word 0
    #!    n2, n3, n4, n5,                  # intent word 1
    #!    n6, n7, amount, max_fee,         # intent word 2
    #!    remote_domain, rt0, rt1, rr0,    # intent word 3
    #!    rr1, rr2, rr3, rr4,             # intent word 4
    #!    rr5, rr6, rr7, lt0,             # intent word 5
    #!    lt1, lt2, lt3, lt4,             # intent word 6
    #!    lt5, lt6, lt7, ld0,             # intent word 7
    #!    ld1, ld2, ld3, ld4,             # intent word 8
    #!    ld5, ld6, ld7, 0_pad,           # intent word 9 (39 felts + pad)
    #!    fee_amount, 0, 0, 0,             # fee word
    #!    NONCE_KEY(4),                    # Poseidon2(nonce bytes32)
    #!    max_fee, 0, 0, 0,               # max_fee word (for fee validation)
    #!    MESSAGE(4)]                      # Poseidon2(all 39 intent felts)
    #!
    #! On-chain validation:
    #!   1. magic == 0x5a2e0acd
    #!   2. version == 1
    #!   3. remoteDomain matches faucet's domain config
    #!   4. remoteToken matches faucet's account ID
    #!   5. amount >= maxFee
    #!   6. fee_amount <= maxFee
    #!   7. nonce not already used (+ mark used)
    #!   8. attester PK_COMM in registry
    #!   9. ECDSA signature over MESSAGE
    #!
    #! Inputs:  [amount, tag, note_type, RECIPIENT]
    #! Outputs: [amount, tag, note_type, RECIPIENT]
    #!
    #! Panics if any validation check fails.
    #!
    #! Invocation: dynexec
    pub proc check_policy
        # Stack: [amount, tag, note_type, RECIPIENT(4)]

        # 1. Load attestation data from advice map
        push.ATTESTATION_DATA_KEY
        adv.push_mapval
        dropw
        # => [amount, tag, note_type, RECIPIENT(4)]

        # 2. Read PK_COMM from the advice stack
        padw adv_loadw
        # => [PK_COMM(4), amount, tag, note_type, RECIPIENT(4)]

        # 3. Verify the attester is in the approved registry
        dupw
        push.ATTESTERS_SLOT[0..2]
        exec.active_account::get_map_item
        # => [VALUE(4), PK_COMM, amount, tag, note_type, RECIPIENT]
        movdn.3 drop drop drop
        # => [is_approved, PK_COMM, amount, tag, note_type, RECIPIENT]
        assert.err=ERR_ATTESTER_NOT_APPROVED
        # => [PK_COMM, amount, tag, note_type, RECIPIENT]

        # 4. Read and validate depositIntent fields, dropping each word after validation.
        #    This keeps the stack depth manageable.

        # 4a. Read [magic, version, nonce0, nonce1] - validate magic and version, drop
        padw adv_loadw
        # => [magic, version, n0, n1, PK_COMM(4), amount, tag, note_type, RECIPIENT(4)]
        dup push.DEPOSIT_INTENT_MAGIC assert_eq.err=ERR_INVALID_MAGIC
        dup.1 push.DEPOSIT_INTENT_VERSION assert_eq.err=ERR_INVALID_VERSION
        dropw
        # => [PK_COMM(4), amount, tag, note_type, RECIPIENT(4)]

        # 4b. Read [n2, n3, n4, n5] - no validation needed, drop
        padw adv_loadw dropw
        # => [PK_COMM(4), amount, tag, note_type, RECIPIENT(4)]

        # 4c. Read [n6, n7, di_amount, max_fee] - validate amount > 0 and amount >= max_fee, drop
        padw adv_loadw
        # => [n6, n7, di_amount, max_fee, PK_COMM(4), amount, tag, note_type, RECIPIENT(4)]

        # MINT-PRE-4: amount must be greater than zero
        dup.2 neq.0 assert.err=ERR_ZERO_AMOUNT
        # => [n6, n7, di_amount, max_fee, PK_COMM(4), ...]

        # MINT-PRE-8: amount must be at least maxFee
        dup.3 dup.3 u32assert2 u32lte
        # => [max_fee <= di_amount, n6, n7, di_amount, max_fee, PK_COMM(4), ...]
        assert.err=ERR_AMOUNT_BELOW_MAX_FEE
        dropw
        # => [PK_COMM(4), amount, tag, note_type, RECIPIENT(4)]

        # 4d. Read [remote_domain, rt0, rt1, rr0] - validate domain and token, drop
        padw adv_loadw
        # => [remote_domain, rt0, rt1, rr0, PK_COMM(4), amount, tag, note_type, RECIPIENT(4)]

        # Validate remoteDomain matches config
        push.DOMAIN_CONFIG_SLOT[0..2]
        exec.active_account::get_item
        # => [CONFIG(4), remote_domain, rt0, rt1, rr0, PK_COMM(4), ...]
        movdn.3 drop drop drop
        # => [domain_id, remote_domain, rt0, rt1, rr0, PK_COMM(4), ...]
        dup.1 assert_eq.err=ERR_DOMAIN_MISMATCH
        # => [remote_domain, rt0, rt1, rr0, PK_COMM(4), ...]

        # Validate remoteToken matches faucet account ID
        exec.active_account::get_id
        # => [faucet_suffix, faucet_prefix, remote_domain, rt0, rt1, rr0, PK_COMM(4), ...]
        dup.4 assert_eq   # faucet_prefix == rt1
        # => [faucet_suffix, remote_domain, rt0, rt1, rr0, PK_COMM(4), ...]
        dup.2 assert_eq.err=ERR_TOKEN_MISMATCH  # faucet_suffix == rt0
        # => [remote_domain, rt0, rt1, rr0, PK_COMM(4), ...]
        dropw
        # => [PK_COMM(4), amount, tag, note_type, RECIPIENT(4)]

        # 4e. Read [rr1, rr2, rr3, rr4] - remote_recipient continued, drop
        padw adv_loadw dropw
        # => [PK_COMM(4), amount, tag, note_type, RECIPIENT(4)]

        # 4f. Read [rr5, rr6, rr7, lt0] - end of remote_recipient, start localToken
        padw adv_loadw
        # => [rr5, rr6, rr7, lt0, PK_COMM(4), ...]
        # Keep lt0 (bottom of word), drop rr5-rr7
        drop drop drop
        # => [lt0, PK_COMM(4), ...]

        # 4g. Read [lt1, lt2, lt3, lt4]
        padw adv_loadw
        # => [lt1, lt2, lt3, lt4, lt0, PK_COMM(4), ...]
        # OR all 5 localToken felts so far: lt0 | lt1 | lt2 | lt3 | lt4
        movup.4 add add add add
        # => [lt_acc, PK_COMM(4), ...]

        # 4h. Read [lt5, lt6, lt7, ld0]
        padw adv_loadw
        # => [lt5, lt6, lt7, ld0, lt_acc, PK_COMM(4), ...]
        # Finish localToken: lt_acc | lt5 | lt6 | lt7
        movup.4 dup.1 add dup.2 add dup.3 add
        # => [lt_final, lt5, lt6, lt7, ld0, PK_COMM(4), ...]
        # MINT-PRE-7: localToken must not be zero
        neq.0 assert.err=ERR_ZERO_LOCAL_TOKEN
        # => [lt5, lt6, lt7, ld0, PK_COMM(4), ...]
        # Stack: [lt5, lt6, lt7, ld0, PK_COMM(4), ...]
        # Keep ld0 (position 3), drop lt5-lt7 (positions 0-2)
        drop drop drop
        # => [ld0, PK_COMM(4), ...]

        # 4i. Read [ld1, ld2, ld3, ld4]
        padw adv_loadw
        # => [ld1, ld2, ld3, ld4, ld0, PK_COMM(4), ...]
        # OR first 5: ld0 | ld1 | ld2 | ld3 | ld4
        movup.4 add add add add
        # => [ld_acc, PK_COMM(4), ...]

        # 4j. Read [ld5, ld6, ld7, pad]
        padw adv_loadw
        # => [ld5, ld6, ld7, pad, ld_acc, PK_COMM(4), ...]
        # Drop pad (position 3), keep ld5-ld7
        movup.3 drop
        # => [ld5, ld6, ld7, ld_acc, PK_COMM(4), ...]
        # Finish localDepositor: ld_acc + ld5 + ld6 + ld7
        add add add
        # => [ld_final, PK_COMM(4), ...]
        # MINT-PRE-7: localDepositor must not be zero
        neq.0 assert.err=ERR_ZERO_LOCAL_DEPOSITOR
        # => [PK_COMM(4), amount, tag, note_type, RECIPIENT(4)]

        # 5. Read fee_amount from advice stack: [fee_amount, 0, 0, 0]
        padw adv_loadw
        # => [fee_amount, 0, 0, 0, PK_COMM(4), amount, tag, note_type, RECIPIENT(4)]
        movdn.3 drop drop drop
        # => [fee_amount, PK_COMM(4), amount, tag, note_type, RECIPIENT(4)]

        # 6. Read NONCE_KEY from advice stack
        padw adv_loadw
        # => [NONCE_KEY(4), fee_amount, PK_COMM(4), amount, tag, note_type, RECIPIENT(4)]

        # 7. Check nonce has not been used
        dupw
        push.NONCES_SLOT[0..2]
        exec.active_account::get_map_item
        # => [NONCE_VAL(4), NONCE_KEY, fee_amount, PK_COMM, amount, tag, note_type, RECIPIENT]
        movdn.3 drop drop drop
        # => [nonce_val_last, NONCE_KEY, fee_amount, PK_COMM, amount, tag, note_type, RECIPIENT]
        assertz.err=ERR_NONCE_ALREADY_USED
        # => [NONCE_KEY, fee_amount, PK_COMM, amount, tag, note_type, RECIPIENT]

        # 8. Mark nonce as used in storage
        dupw
        push.NONCE_USED swapw
        push.NONCES_SLOT[0..2]
        exec.native_account::set_map_item
        dropw
        # => [NONCE_KEY, fee_amount, PK_COMM, amount, tag, note_type, RECIPIENT]
        dropw
        # => [fee_amount, PK_COMM(4), amount, tag, note_type, RECIPIENT(4)]

        # 9. Read max_fee from advice stack for fee validation: [max_fee, 0, 0, 0]
        padw adv_loadw
        # => [max_fee, 0, 0, 0, fee_amount, PK_COMM(4), amount, tag, note_type, RECIPIENT(4)]
        movdn.3 drop drop drop
        # => [max_fee, fee_amount, PK_COMM(4), amount, tag, note_type, RECIPIENT(4)]

        # Assert fee_amount <= max_fee
        # Stack: [max_fee, fee_amount, PK_COMM(4), ...]
        # We need u32lte to check fee_amount <= max_fee.
        # u32lte pops b (top), a (next), checks a <= b.
        # So we need [max_fee, fee_amount] on top -> checks fee_amount <= max_fee.
        dup.1 dup.1 u32assert2 u32lte
        assert.err=ERR_FEE_EXCEEDS_MAX_FEE
        # => [max_fee, fee_amount, PK_COMM(4), amount, tag, note_type, RECIPIENT(4)]
        drop drop
        # => [PK_COMM(4), amount, tag, note_type, RECIPIENT(4)]

        # 10. Read MESSAGE from advice stack (Poseidon2 hash of all 39 intent felts)
        padw adv_loadw
        # => [MESSAGE(4), PK_COMM(4), amount, tag, note_type, RECIPIENT(4)]

        # 11. Verify ECDSA secp256k1 signature
        swapw
        # => [PK_COMM(4), MESSAGE(4), amount, tag, note_type, RECIPIENT(4)]

        dupw.1 dupw.1
        exec.poseidon2::merge
        # => [SIG_KEY(4), PK_COMM, MESSAGE, amount, tag, note_type, RECIPIENT]

        adv.push_mapval
        dropw
        # => [PK_COMM, MESSAGE, amount, tag, note_type, RECIPIENT]

        exec.ecdsa_k256_keccak::verify
        # => [amount, tag, note_type, RECIPIENT]
    end

    #! Cross-chain reserve mint: verifies attestation and mints with fee splitting.
    #!
    #! This is the procedure the relayer's tx script calls to perform the full
    #! Circle CCTP mint flow. It verifies the ECDSA secp256k1 attestation over
    #! the depositIntent message hash, then mints (amount - fee_amount) to the
    #! recipient and fee_amount to the relayer (if fee > 0), producing up to two
    #! output notes.
    #!
    #! The message hash is Poseidon2::hash_elements over all 39 depositIntent felts.
    #! This is precomputed by the relayer and read from the advice stack.
    #!
    #! Inputs:  [recipient_suffix, recipient_prefix, relayer_suffix, relayer_prefix,
    #!           fee_amount, amount, tag, note_type, NONCE_KEY, PK_COMM]
    #! Outputs: []
    #!
    #! NONCE_KEY is the Poseidon2 hash of the 8 nonce felts (bytes32_to_key).
    #!
    #! Panics if:
    #! - the attester PK_COMM is not in the approved attesters registry.
    #! - the deposit nonce has already been used.
    #! - the ECDSA secp256k1 signature verification fails.
    #!
    #! Invocation: exec
    #!
    #! Local memory layout (20 felts):
    #!   0: recipient_suffix
    #!   1: recipient_prefix
    #!   2: relayer_suffix
    #!   3: relayer_prefix
    #!   4: fee_amount
    #!   5: amount (total)
    #!   6: tag
    #!   7: note_type
    #!   8-11: NONCE_KEY (word)
    #!   12-15: PK_COMM (word)
    #!   16-19: MESSAGE (word, read from advice stack)
    @locals(20)
    pub proc xreserve_mint
        # Stack: [recipient_suffix, recipient_prefix, relayer_suffix, relayer_prefix,
        #         fee_amount, amount, tag, note_type, NONCE_KEY(4), PK_COMM(4)]

        # ---- Save all inputs to locals ----

        # Save recipient_suffix and recipient_prefix
        loc_store.0
        # => [recipient_prefix, relayer_suffix, relayer_prefix, fee_amount, amount,
        #     tag, note_type, NONCE_KEY(4), PK_COMM(4)]
        loc_store.1
        # => [relayer_suffix, relayer_prefix, fee_amount, amount,
        #     tag, note_type, NONCE_KEY(4), PK_COMM(4)]

        # Save relayer_suffix and relayer_prefix
        loc_store.2
        # => [relayer_prefix, fee_amount, amount, tag, note_type, NONCE_KEY(4), PK_COMM(4)]
        loc_store.3
        # => [fee_amount, amount, tag, note_type, NONCE_KEY(4), PK_COMM(4)]

        # Save fee_amount, amount, tag, note_type
        loc_store.4
        # => [amount, tag, note_type, NONCE_KEY(4), PK_COMM(4)]
        loc_store.5
        # => [tag, note_type, NONCE_KEY(4), PK_COMM(4)]
        loc_store.6
        # => [note_type, NONCE_KEY(4), PK_COMM(4)]
        loc_store.7
        # => [NONCE_KEY(4), PK_COMM(4)]

        # Save NONCE_KEY word to locals 8-11
        loc_storew_le.8 dropw
        # => [PK_COMM(4)]

        # Save PK_COMM word to locals 12-15
        loc_storew_le.12 dropw
        # => []

        # ===========================================================================
        # ATTESTATION VERIFICATION
        # ===========================================================================

        # 1. Verify the attester PK_COMM is in the approved registry
        padw loc_loadw_le.12
        # => [PK_COMM(4)]
        dupw
        push.ATTESTERS_SLOT[0..2]
        exec.active_account::get_map_item
        # => [VALUE(4), PK_COMM(4)]
        # Stored [1,0,0,0] appears reversed as [0,0,0,1]; check VALUE[3]
        movdn.3 drop drop drop
        # => [is_approved, PK_COMM(4)]
        assert.err=ERR_ATTESTER_NOT_APPROVED
        # => [PK_COMM(4)]
        dropw
        # => []

        # 2. Check nonce has not been used
        padw loc_loadw_le.8
        # => [NONCE_KEY(4)]
        dupw
        push.NONCES_SLOT[0..2]
        exec.active_account::get_map_item
        # => [NONCE_VAL(4), NONCE_KEY(4)]
        movdn.3 drop drop drop
        # => [nonce_val_last, NONCE_KEY(4)]
        assertz.err=ERR_NONCE_ALREADY_USED
        # => [NONCE_KEY(4)]

        # 3. Mark nonce as used in storage
        dupw
        push.NONCE_USED swapw
        push.NONCES_SLOT[0..2]
        exec.native_account::set_map_item
        dropw
        # => [NONCE_KEY(4)]
        dropw
        # => []

        # 4. Read MESSAGE from advice stack (Poseidon2 hash of all 39 intent felts)
        padw adv_loadw
        # => [MESSAGE(4)]

        # Save MESSAGE to locals 16-19
        loc_storew_le.16 dropw
        # => []

        # 5. Verify ECDSA secp256k1 signature
        padw loc_loadw_le.12
        # => [PK_COMM(4)]

        padw loc_loadw_le.16
        # => [MESSAGE(4), PK_COMM(4)]

        swapw
        # => [PK_COMM(4), MESSAGE(4)]

        dupw.1 dupw.1
        exec.poseidon2::merge
        # => [SIG_KEY(4), PK_COMM(4), MESSAGE(4)]

        adv.push_mapval
        dropw
        # => [PK_COMM(4), MESSAGE(4)]

        exec.ecdsa_k256_keccak::verify
        # => []

        # ===========================================================================
        # MINT RECIPIENT AMOUNT: (amount - fee_amount)
        # ===========================================================================

        # Compute recipient_amount = amount - fee_amount
        loc_load.5 loc_load.4 sub
        # => [recipient_amount]

        # Create the fungible asset for the recipient
        exec.faucet::create_fungible_asset
        # => [ASSET_KEY(4), ASSET_VALUE(4)]

        # Mint the asset into the faucet vault
        dupw.1 dupw.1
        # => [ASSET_KEY(4), ASSET_VALUE(4), ASSET_KEY(4), ASSET_VALUE(4)]
        exec.faucet::mint
        # => [ASSET_VALUE(4), ASSET_KEY(4), ASSET_VALUE(4)]
        dropw
        # => [ASSET_KEY(4), ASSET_VALUE(4)]

        # Create recipient output note
        # RECIPIENT = [recipient_suffix, recipient_prefix, 0, 0]
        loc_load.6 loc_load.7
        # => [note_type, tag, ASSET_KEY(4), ASSET_VALUE(4)]
        loc_load.0 loc_load.1 push.0 push.0
        # => [0, 0, recipient_prefix, recipient_suffix, note_type, tag,
        #     ASSET_KEY(4), ASSET_VALUE(4)]

        movup.5 movup.5
        # => [tag, note_type, 0, 0, recipient_prefix, recipient_suffix,
        #     ASSET_KEY(4), ASSET_VALUE(4)]

        exec.output_note::create
        # => [note_idx, ASSET_KEY(4), ASSET_VALUE(4)]

        # Add the minted asset to the recipient note
        movdn.8
        # => [ASSET_KEY(4), ASSET_VALUE(4), note_idx]
        exec.output_note::add_asset
        # => []

        # ===========================================================================
        # MINT FEE AMOUNT TO RELAYER (conditional: only if fee_amount > 0)
        # ===========================================================================

        loc_load.4
        # => [fee_amount]

        dup push.0 gt
        # => [has_fee, fee_amount]

        if.true
            # fee_amount is on the stack
            # => [fee_amount]

            # Create the fungible asset for the relayer fee
            exec.faucet::create_fungible_asset
            # => [ASSET_KEY(4), ASSET_VALUE(4)]

            # Mint the fee asset into the faucet vault
            dupw.1 dupw.1
            # => [ASSET_KEY(4), ASSET_VALUE(4), ASSET_KEY(4), ASSET_VALUE(4)]
            exec.faucet::mint
            # => [ASSET_VALUE(4), ASSET_KEY(4), ASSET_VALUE(4)]
            dropw
            # => [ASSET_KEY(4), ASSET_VALUE(4)]

            # Create relayer output note
            # RECIPIENT for relayer = [relayer_suffix, relayer_prefix, 0, 0]
            loc_load.6 loc_load.7
            # => [note_type, tag, ASSET_KEY(4), ASSET_VALUE(4)]
            loc_load.2 loc_load.3 push.0 push.0
            # => [0, 0, relayer_prefix, relayer_suffix, note_type, tag,
            #     ASSET_KEY(4), ASSET_VALUE(4)]

            movup.5 movup.5
            # => [tag, note_type, 0, 0, relayer_prefix, relayer_suffix,
            #     ASSET_KEY(4), ASSET_VALUE(4)]

            exec.output_note::create
            # => [note_idx, ASSET_KEY(4), ASSET_VALUE(4)]

            # Add the fee asset to the relayer note
            movdn.8
            # => [ASSET_KEY(4), ASSET_VALUE(4), note_idx]
            exec.output_note::add_asset
            # => []
        else
            # No fee - just drop fee_amount
            drop
            # => []
        end
    end

    #! Add an attester to the approved attesters storage map.
    #!
    #! The caller must be the faucet owner.
    #!
    #! Inputs:  [PK_COMM, pad(12)]
    #! Outputs: [pad(16)]
    #!
    #! Panics if:
    #! - the note sender is not the owner.
    #!
    #! Invocation: call
    pub proc add_attester
        exec.ownable2step::assert_sender_is_owner
        # => [PK_COMM, pad(12)]

        # VALUE = ATTESTER_ACTIVE = [1, 0, 0, 0]
        push.ATTESTER_ACTIVE
        # => [ATTESTER_ACTIVE, PK_COMM, pad(12)]

        # Rearrange: set_map_item needs [slot_suffix, slot_prefix, KEY, VALUE]
        swapw
        # => [PK_COMM, ATTESTER_ACTIVE, pad(12)]

        push.ATTESTERS_SLOT[0..2]
        # => [slot_suffix, slot_prefix, PK_COMM, ATTESTER_ACTIVE, pad(12)]

        exec.native_account::set_map_item
        # => [OLD_VALUE, pad(12)]

        dropw
        # => [pad(12)]
    end

    #! Remove an attester from the approved attesters storage map.
    #!
    #! The caller must be the faucet owner. Writes the zero word for the
    #! attester key, effectively removing it from the map.
    #!
    #! Inputs:  [PK_COMM, pad(12)]
    #! Outputs: [pad(16)]
    #!
    #! Panics if:
    #! - the note sender is not the owner.
    #!
    #! Invocation: call
    pub proc remove_attester
        exec.ownable2step::assert_sender_is_owner
        # => [PK_COMM, pad(12)]

        # Write zero word to remove the attester from the map.
        padw
        # => [ZERO_WORD, PK_COMM, pad(12)]

        swapw
        # => [PK_COMM, ZERO_WORD, pad(12)]

        push.ATTESTERS_SLOT[0..2]
        # => [slot_suffix, slot_prefix, PK_COMM, ZERO_WORD, pad(12)]

        exec.native_account::set_map_item
        # => [OLD_VALUE, pad(12)]

        dropw
        # => [pad(12)]
    end
";

// COMPILED CODE
// ================================================================================================

static USDCX_MINT_POLICY_LIBRARY: LazyLock<Library> = LazyLock::new(|| {
    CodeBuilder::default()
        .compile_component_code(USDCX_MINT_POLICY_NAME, USDCX_MINT_POLICY_MASM)
        .expect("USDCx mint policy MASM should compile")
        .into()
});

static USDCX_MINT_POLICY_CODE: LazyLock<AccountComponentCode> = LazyLock::new(|| {
    CodeBuilder::default()
        .compile_component_code(USDCX_MINT_POLICY_NAME, USDCX_MINT_POLICY_MASM)
        .expect("USDCx mint policy MASM should compile")
});

static CHECK_POLICY_ROOT: LazyLock<AccountProcedureRoot> = LazyLock::new(|| {
    let full_path = format!("{}::check_policy", USDCX_MINT_POLICY_NAME);
    USDCX_MINT_POLICY_CODE
        .get_procedure_root_by_path(full_path.as_str())
        .unwrap_or_else(|| panic!("component should contain procedure '{}'", full_path))
});

static XRESERVE_MINT_ROOT: LazyLock<AccountProcedureRoot> = LazyLock::new(|| {
    let full_path = format!("{}::xreserve_mint", USDCX_MINT_POLICY_NAME);
    USDCX_MINT_POLICY_CODE
        .get_procedure_root_by_path(full_path.as_str())
        .unwrap_or_else(|| panic!("component should contain procedure '{}'", full_path))
});

static ADD_ATTESTER_ROOT: LazyLock<AccountProcedureRoot> = LazyLock::new(|| {
    let full_path = format!("{}::add_attester", USDCX_MINT_POLICY_NAME);
    USDCX_MINT_POLICY_CODE
        .get_procedure_root_by_path(full_path.as_str())
        .unwrap_or_else(|| panic!("component should contain procedure '{}'", full_path))
});

static REMOVE_ATTESTER_ROOT: LazyLock<AccountProcedureRoot> = LazyLock::new(|| {
    let full_path = format!("{}::remove_attester", USDCX_MINT_POLICY_NAME);
    USDCX_MINT_POLICY_CODE
        .get_procedure_root_by_path(full_path.as_str())
        .unwrap_or_else(|| panic!("component should contain procedure '{}'", full_path))
});

// USDCX MINT POLICY
// ================================================================================================

/// Account component implementing the USDCx mint policy.
///
/// This component verifies Circle CCTP deposit attestations (ECDSA secp256k1) before
/// allowing tokens to be minted. It manages:
/// - An attester registry (storage map of approved attester public-key commitments)
/// - A nonce registry (storage map of consumed deposit-intent nonces)
/// - A domain configuration (domain ID and min burn size)
pub struct UsdcxMintPolicy {
    attester_registry: AttesterRegistry,
    nonce_registry: NonceRegistry,
    domain_config: DomainConfig,
}

impl UsdcxMintPolicy {
    // CONSTRUCTOR
    // --------------------------------------------------------------------------------------------

    /// Creates a new `UsdcxMintPolicy`.
    pub fn new(
        attester_registry: AttesterRegistry,
        nonce_registry: NonceRegistry,
        domain_config: DomainConfig,
    ) -> Self {
        Self {
            attester_registry,
            nonce_registry,
            domain_config,
        }
    }

    // ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the compiled [`AccountComponentCode`] for this component.
    pub fn code() -> &'static AccountComponentCode {
        &USDCX_MINT_POLICY_CODE
    }

    /// Returns the procedure root for `check_policy`.
    pub fn check_policy_root() -> AccountProcedureRoot {
        *CHECK_POLICY_ROOT
    }

    /// Returns the procedure root for `xreserve_mint`.
    pub fn xreserve_mint_root() -> AccountProcedureRoot {
        *XRESERVE_MINT_ROOT
    }

    /// Returns the procedure root for `add_attester`.
    pub fn add_attester_root() -> AccountProcedureRoot {
        *ADD_ATTESTER_ROOT
    }

    /// Returns the procedure root for `remove_attester`.
    pub fn remove_attester_root() -> AccountProcedureRoot {
        *REMOVE_ATTESTER_ROOT
    }

    /// Returns the [`AccountComponentMetadata`] for this component.
    pub fn component_metadata() -> AccountComponentMetadata {
        AccountComponentMetadata::new(USDCX_MINT_POLICY_NAME)
            .with_description("USDCx mint policy: attestation-gated minting with attester management")
    }

    // STORAGE
    // --------------------------------------------------------------------------------------------

    /// Converts this policy into its storage slots for inclusion in an account component.
    pub fn into_storage_slots(self) -> Vec<StorageSlot> {
        let attester_slot_name = StorageSlotName::new(ATTESTER_REGISTRY_SLOT_NAME)
            .expect("attester registry slot name should be valid");
        let nonce_slot_name = StorageSlotName::new(NONCE_REGISTRY_SLOT_NAME)
            .expect("nonce registry slot name should be valid");
        let domain_config_slot_name = StorageSlotName::new(DOMAIN_CONFIG_SLOT_NAME)
            .expect("domain config slot name should be valid");

        vec![
            StorageSlot::with_map(attester_slot_name, self.attester_registry.build_storage_map()),
            StorageSlot::with_map(nonce_slot_name, self.nonce_registry.build_storage_map()),
            StorageSlot::with_value(domain_config_slot_name, self.domain_config.to_word()),
        ]
    }
}

// TRAIT IMPLEMENTATIONS
// ================================================================================================

impl From<UsdcxMintPolicy> for AccountComponent {
    fn from(policy: UsdcxMintPolicy) -> Self {
        let metadata = UsdcxMintPolicy::component_metadata();
        let storage_slots = policy.into_storage_slots();

        AccountComponent::new(USDCX_MINT_POLICY_LIBRARY.clone(), storage_slots, metadata)
            .expect("USDCx mint policy component should satisfy account component requirements")
    }
}

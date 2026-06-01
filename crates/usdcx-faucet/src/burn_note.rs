use miden_protocol::account::AccountId;
use miden_protocol::asset::Asset;
use miden_protocol::crypto::rand::FeltRng;
use miden_protocol::errors::NoteError;
use miden_protocol::note::{
    Note, NoteAssets, NoteRecipient, NoteStorage, NoteTag, NoteType, PartialNoteMetadata,
};
use miden_protocol::utils::sync::LazyLock;
use miden_protocol::Felt;

use miden_standards::code_builder::CodeBuilder;
use miden_protocol::note::NoteScript;

use crate::deposit_intent::bytes32_to_felts;

// NOTE SCRIPT
// ================================================================================================

/// Custom MASM script for USDCx burn notes with destination storage.
///
/// Storage layout (9 felts):
///   [0]    destination_domain (u32)
///   [1-8]  destination_recipient (bytes32 as 8 u32 felts)
///
/// The note is always public. The withdrawal service reads destination_domain
/// and destination_recipient from the note's on-chain storage to know where
/// to send USDC via Circle's xReserve API.
///
/// The script itself loads the note storage into memory (making it available
/// for inspection), then calls `receive_and_burn` on the faucet to burn the
/// asset. The faucet's burn policy validates the amount, etc.
const USDCX_BURN_NOTE_MASM: &str = "
    use miden::standards::faucets::fungible->faucet

    #! Burns the fungible asset in this note via the faucet's receive_and_burn.
    #!
    #! The note's public storage contains [destination_domain, destination_recipient(8)]
    #! which is readable by anyone (withdrawal service, auditors) directly from the
    #! chain. The script itself only needs to trigger the burn.
    #!
    #! Inputs:  [ARGS, pad(12)]
    #! Outputs: [pad(16)]
    #!
    #! Panics if:
    #! - the faucet does not expose receive_and_burn.
    #! - any validation in the faucet's burn policy fails.
    @note_script
    pub proc main
        dropw
        # => [pad(16)]

        # Burn the asset via the faucet
        call.faucet::receive_and_burn
        # => [pad(16)]
    end
";

/// Lazily compiled note script for USDCx burn notes.
static USDCX_BURN_NOTE_SCRIPT: LazyLock<NoteScript> = LazyLock::new(|| {
    CodeBuilder::default()
        .compile_note_script(USDCX_BURN_NOTE_MASM)
        .expect("USDCx burn note MASM should compile")
});

// BURN NOTE
// ================================================================================================

/// Custom USDCx burn note with destination data in storage.
///
/// Unlike the standard `BurnNote` from miden-standards which has empty storage,
/// this note stores the Circle CCTP destination information needed by the
/// off-chain withdrawal service:
///
/// - `destination_domain` (u32) - Circle domain ID for USDC release
/// - `destination_recipient` (bytes32 as 8 u32 felts) - recipient on destination chain
///
/// The note is always public for audit trail and withdrawal service visibility.
pub struct UsdcxBurnNote;

impl UsdcxBurnNote {
    // CONSTANTS
    // --------------------------------------------------------------------------------------------

    /// Number of storage felts: 1 (domain) + 8 (recipient) = 9.
    pub const NUM_STORAGE_ITEMS: usize = 9;

    // PUBLIC ACCESSORS
    // --------------------------------------------------------------------------------------------

    /// Returns the compiled note script for USDCx burn notes.
    pub fn script() -> NoteScript {
        USDCX_BURN_NOTE_SCRIPT.clone()
    }

    // BUILDERS
    // --------------------------------------------------------------------------------------------

    /// Creates a USDCx burn note with destination data in storage.
    ///
    /// The note is always public and tagged to the faucet for proper routing.
    /// The withdrawal service reads `destination_domain` and `destination_recipient`
    /// from the note's on-chain storage to know where to send USDC via Circle's
    /// xReserve API.
    ///
    /// # Parameters
    /// - `sender`: The account ID of the note creator
    /// - `faucet_id`: The account ID of the faucet that will burn the assets
    /// - `fungible_asset`: The fungible asset to be burned
    /// - `destination_domain`: Circle domain ID for USDC release (e.g. 0 = Ethereum)
    /// - `destination_recipient`: 32-byte recipient address on the destination chain
    /// - `rng`: Random number generator for creating the serial number
    ///
    /// # Errors
    /// Returns an error if note creation fails.
    pub fn create<R: FeltRng>(
        sender: AccountId,
        faucet_id: AccountId,
        fungible_asset: Asset,
        destination_domain: u32,
        destination_recipient: &[u8; 32],
        rng: &mut R,
    ) -> Result<Note, NoteError> {
        let note_script = Self::script();

        // Build storage: [destination_domain, recipient_felts(8)]
        let mut storage_items = Vec::with_capacity(Self::NUM_STORAGE_ITEMS);
        storage_items.push(Felt::new_unchecked(destination_domain as u64));
        storage_items.extend(bytes32_to_felts(destination_recipient));
        let storage = NoteStorage::new(storage_items)?;

        let serial_num = rng.draw_word();
        let note_type = NoteType::Public;
        let tag = NoteTag::with_account_target(faucet_id);
        let metadata = PartialNoteMetadata::new(sender, note_type).with_tag(tag);
        let assets = NoteAssets::new(vec![fungible_asset])?;
        let recipient = NoteRecipient::new(serial_num, note_script, storage);

        Ok(Note::new(assets, metadata, recipient))
    }
}

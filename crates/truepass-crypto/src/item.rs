//! Per-item keys and payload sealing: spec §3.
//!
//! Each item version gets its own random item key, sealed under the vault key.
//! Two reasons, both load-bearing: a single credential can be shared without
//! handing over the whole vault, and rotating one item costs one re-seal.
//!
//! Payload bytes are opaque here. Serializing item contents belongs to the
//! layer above — keeping a serde format out of the crypto core.

use zeroize::Zeroizing;

use crate::aead;
use crate::error::{Error, Result};
use crate::secret::Key32;
use crate::vault::{Epoch, VAULT_ID_LEN, VaultId, VaultKey};

/// Length of a serialized item identifier.
pub const ITEM_ID_LEN: usize = 16;

/// Length of the AAD bound to every item ciphertext.
pub const ITEM_AAD_LEN: usize = VAULT_ID_LEN + ITEM_ID_LEN + 4 + 4;

/// An item identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ItemId([u8; ITEM_ID_LEN]);

impl ItemId {
    /// Generate a fresh random item id.
    pub fn generate() -> Result<Self> {
        Ok(Self(crate::rand::bytes::<ITEM_ID_LEN>()?))
    }

    /// Wrap raw bytes.
    pub const fn from_bytes(bytes: [u8; ITEM_ID_LEN]) -> Self {
        Self(bytes)
    }

    /// Raw bytes.
    pub fn as_bytes(&self) -> &[u8; ITEM_ID_LEN] {
        &self.0
    }
}

/// One encrypted item version, as stored locally and shipped over sync.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedItem {
    vault: VaultId,
    item: ItemId,
    version: u32,
    epoch: Epoch,
    sealed_item_key: Vec<u8>,
    ciphertext: Vec<u8>,
}

impl SealedItem {
    /// Encrypt `payload` for `item` at `version` under the given vault key.
    ///
    /// The epoch is taken from the vault key, so an item can never be sealed
    /// claiming an epoch whose key was not actually used.
    pub fn seal(
        vault_key: &VaultKey,
        vault: VaultId,
        item: ItemId,
        version: u32,
        payload: &[u8],
    ) -> Result<Self> {
        let epoch = vault_key.epoch();
        let aad = item_aad(vault, item, version, epoch);

        let item_key = Key32::random()?;
        let sealed_item_key = aead::wrap_key(vault_key.key(), &item_key, &aad)?;
        let ciphertext = aead::seal(&item_key, payload, &aad)?;

        Ok(Self {
            vault,
            item,
            version,
            epoch,
            sealed_item_key,
            ciphertext,
        })
    }

    /// Decrypt, returning the payload in a wrapper that wipes on drop.
    pub fn open(&self, vault_key: &VaultKey) -> Result<Zeroizing<Vec<u8>>> {
        if vault_key.epoch() != self.epoch {
            return Err(Error::EpochMismatch {
                expected: self.epoch.value(),
                got: vault_key.epoch().value(),
            });
        }
        let aad = item_aad(self.vault, self.item, self.version, self.epoch);
        let item_key = aead::unwrap_key(vault_key.key(), &self.sealed_item_key, &aad)?;
        aead::open(&item_key, &self.ciphertext, &aad)
    }

    /// The vault this item belongs to.
    pub fn vault(&self) -> VaultId {
        self.vault
    }

    /// The item identifier.
    pub fn item(&self) -> ItemId {
        self.item
    }

    /// The version number of this item revision.
    pub fn version(&self) -> u32 {
        self.version
    }

    /// The key epoch this item was sealed under.
    pub fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// The sealed item key, as stored.
    pub fn sealed_item_key(&self) -> &[u8] {
        &self.sealed_item_key
    }

    /// The item ciphertext, as stored.
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Reassemble from stored parts. Does not validate; any tampering surfaces
    /// as an authentication failure on [`SealedItem::open`].
    pub fn from_parts(
        vault: VaultId,
        item: ItemId,
        version: u32,
        epoch: Epoch,
        sealed_item_key: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> Self {
        Self {
            vault,
            item,
            version,
            epoch,
            sealed_item_key,
            ciphertext,
        }
    }
}

/// The AAD from spec §3: `vault_id ‖ item_id ‖ version ‖ epoch`.
///
/// This is the binding that stops a hostile relay (A1) moving one item's
/// ciphertext into another item's slot, replaying an old version over a new
/// one, or passing a pre-rotation blob off as current.
///
/// Every field is fixed width, so concatenation is already unambiguous and no
/// length prefixes are needed.
fn item_aad(vault: VaultId, item: ItemId, version: u32, epoch: Epoch) -> [u8; ITEM_AAD_LEN] {
    let mut aad = [0u8; ITEM_AAD_LEN];
    let mut at = 0;

    aad[at..at + VAULT_ID_LEN].copy_from_slice(vault.as_bytes());
    at += VAULT_ID_LEN;
    aad[at..at + ITEM_ID_LEN].copy_from_slice(item.as_bytes());
    at += ITEM_ID_LEN;
    aad[at..at + 4].copy_from_slice(&version.to_be_bytes());
    at += 4;
    aad[at..at + 4].copy_from_slice(&epoch.value().to_be_bytes());

    aad
}

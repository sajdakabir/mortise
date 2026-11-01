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

    /// The id of the environment secret `key` in `environment` (spec §6.7).
    ///
    /// Deterministic, so two members who create the same variable in the same
    /// environment — offline, at the same moment — write the same item and
    /// last-write-wins converges on one, instead of leaving two that an `.env`
    /// export would emit twice.
    ///
    /// Keyed under a key derived from the vault's **first** key, which every
    /// member holds and no rotation changes. A plain hash of the name would let
    /// anyone holding the file, or the relay, confirm a guess like
    /// `STRIPE_SECRET_KEY`; this way the id says nothing without the vault key.
    ///
    /// The environment is compared case-insensitively (ASCII), like the
    /// project's environment set; the variable name is not, as in a shell.
    pub fn for_env_secret(
        first_key: &VaultKey,
        vault: VaultId,
        environment: &str,
        key: &str,
    ) -> Result<Self> {
        if first_key.epoch() != Epoch::INITIAL {
            return Err(Error::EpochMismatch {
                expected: Epoch::INITIAL.value(),
                got: first_key.epoch().value(),
            });
        }
        let id_key = crate::kdf::subkey(first_key.key(), crate::kdf::info::ENV_ITEM_ID)?;
        let environment = environment.to_ascii_lowercase();

        let mut hasher = blake3::Hasher::new_keyed(id_key.expose());
        hasher.update(vault.as_bytes());
        hasher.update(&(environment.len() as u32).to_be_bytes());
        hasher.update(environment.as_bytes());
        hasher.update(&(key.len() as u32).to_be_bytes());
        hasher.update(key.as_bytes());

        let mut id = [0u8; ITEM_ID_LEN];
        id.copy_from_slice(&hasher.finalize().as_bytes()[..ITEM_ID_LEN]);
        Ok(Self(id))
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

//! Vault keys, epochs and HPKE key wrapping: spec §3, §6.
//!
//! A vault key is symmetric and shared by every member. It is distributed by
//! sealing it to each member device's X25519 public key with HPKE, so the key
//! itself never transits in the clear and the relay never sees it.
//!
//! Every vault key belongs to an **epoch**. Revoking a member increments the
//! epoch and generates a fresh key (spec §6). The epoch is bound into both the
//! HPKE `aad` and the item AAD, so a wrapped key from one epoch cannot be
//! passed off as another — which is what makes rotation meaningful rather than
//! cosmetic.

use hpke::{Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable};

use crate::error::{Error, Result};
use crate::identity::{Device, DevicePublic, Kem};
use crate::secret::Key32;

/// Length of a serialized vault identifier.
pub const VAULT_ID_LEN: usize = 16;

const HPKE_INFO: &[u8] = b"truepass/v1/vaultkey";

type HpkeAead = hpke::aead::ChaCha20Poly1305;
type HpkeKdf = hpke::kdf::HkdfSha256;

/// A vault identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct VaultId([u8; VAULT_ID_LEN]);

impl VaultId {
    /// Generate a fresh random vault id.
    pub fn generate() -> Result<Self> {
        Ok(Self(crate::rand::bytes::<VAULT_ID_LEN>()?))
    }

    /// Wrap raw bytes.
    pub const fn from_bytes(bytes: [u8; VAULT_ID_LEN]) -> Self {
        Self(bytes)
    }

    /// Raw bytes.
    pub fn as_bytes(&self) -> &[u8; VAULT_ID_LEN] {
        &self.0
    }
}

/// A key epoch. Starts at 0 and increments on every revocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Epoch(pub u32);

impl Epoch {
    /// The epoch a vault starts life in.
    pub const INITIAL: Epoch = Epoch(0);

    /// The next epoch. Saturates rather than wrapping: wrapping would let an
    /// attacker who can force 2^32 rotations replay an old wrapped key.
    pub fn next(self) -> Epoch {
        Epoch(self.0.saturating_add(1))
    }

    /// Raw value.
    pub fn value(self) -> u32 {
        self.0
    }
}

/// The symmetric key protecting one vault at one epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultKey {
    key: Key32,
    epoch: Epoch,
}

impl VaultKey {
    /// Generate the initial key for a new vault.
    pub fn generate() -> Result<Self> {
        Ok(Self {
            key: Key32::random()?,
            epoch: Epoch::INITIAL,
        })
    }

    /// Generate the replacement key for the next epoch.
    ///
    /// Spec §6: this is step 2 of revocation. The caller must then re-wrap for
    /// every remaining member device.
    pub fn rotate(&self) -> Result<Self> {
        Ok(Self {
            key: Key32::random()?,
            epoch: self.epoch.next(),
        })
    }

    /// Reconstruct from raw key material at a known epoch.
    pub fn from_parts(key: Key32, epoch: Epoch) -> Self {
        Self { key, epoch }
    }

    /// The epoch this key belongs to.
    pub fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// The raw key, for sealing item keys.
    pub fn key(&self) -> &Key32 {
        &self.key
    }

    /// Seal this vault key to a member device.
    pub fn wrap_for(&self, recipient: &DevicePublic, vault: VaultId) -> Result<WrappedVaultKey> {
        let aad = wrap_aad(vault, self.epoch);
        let (encapped, ciphertext) = hpke::single_shot_seal::<HpkeAead, HpkeKdf, Kem>(
            &OpModeS::Base,
            &recipient.kex_public()?,
            HPKE_INFO,
            self.key.expose(),
            &aad,
        )
        .map_err(|_| Error::Encrypt)?;

        Ok(WrappedVaultKey {
            epoch: self.epoch,
            encapped: encapped.to_bytes().to_vec(),
            ciphertext,
        })
    }

    /// Recover a vault key sealed to this device.
    pub fn unwrap_for(device: &Device, wrapped: &WrappedVaultKey, vault: VaultId) -> Result<Self> {
        let encapped = <Kem as KemTrait>::EncappedKey::from_bytes(&wrapped.encapped)
            .map_err(|_| Error::Decrypt)?;
        let aad = wrap_aad(vault, wrapped.epoch);

        let plaintext = hpke::single_shot_open::<HpkeAead, HpkeKdf, Kem>(
            &OpModeR::Base,
            device.kex_private(),
            &encapped,
            HPKE_INFO,
            &wrapped.ciphertext,
            &aad,
        )
        .map_err(|_| Error::Decrypt)?;

        Ok(Self {
            key: Key32::from_slice(&plaintext)?,
            epoch: wrapped.epoch,
        })
    }
}

/// A vault key sealed to one device's X25519 public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrappedVaultKey {
    epoch: Epoch,
    encapped: Vec<u8>,
    ciphertext: Vec<u8>,
}

impl WrappedVaultKey {
    /// The epoch of the key inside.
    pub fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Serialize for storage or sync: `epoch(4) ‖ len(4) ‖ encapped ‖ ciphertext`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + self.encapped.len() + self.ciphertext.len());
        out.extend_from_slice(&self.epoch.0.to_be_bytes());
        out.extend_from_slice(&(self.encapped.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.encapped);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    /// Parse bytes produced by [`WrappedVaultKey::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 8 {
            return Err(Error::Decrypt);
        }
        let epoch = Epoch(u32::from_be_bytes(
            bytes[..4].try_into().map_err(|_| Error::Decrypt)?,
        ));
        let encapped_len =
            u32::from_be_bytes(bytes[4..8].try_into().map_err(|_| Error::Decrypt)?) as usize;

        let rest = &bytes[8..];
        if rest.len() < encapped_len {
            return Err(Error::Decrypt);
        }
        let (encapped, ciphertext) = rest.split_at(encapped_len);

        Ok(Self {
            epoch,
            encapped: encapped.to_vec(),
            ciphertext: ciphertext.to_vec(),
        })
    }
}

/// AAD binding a wrapped vault key to its vault and epoch.
///
/// Fixed width by construction, so no length prefixes are needed.
fn wrap_aad(vault: VaultId, epoch: Epoch) -> [u8; VAULT_ID_LEN + 4] {
    let mut aad = [0u8; VAULT_ID_LEN + 4];
    aad[..VAULT_ID_LEN].copy_from_slice(vault.as_bytes());
    aad[VAULT_ID_LEN..].copy_from_slice(&epoch.0.to_be_bytes());
    aad
}

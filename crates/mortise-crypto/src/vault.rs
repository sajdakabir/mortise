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
use crate::identity::{DEVICE_ID_LEN, Device, DeviceId, DevicePublic, Kem, KexPublic};
use crate::secret::Key32;

/// Length of a serialized vault identifier.
pub const VAULT_ID_LEN: usize = 16;

const HPKE_INFO: &[u8] = b"truepass/v1/vaultkey";

/// Leading byte of a serialized authenticated (HPKE Auth mode) wrapped key.
///
/// A legacy Base-mode blob has no such tag — it begins with the epoch's
/// big-endian high byte, which for every realistic epoch is `0x00`. The two are
/// told apart by the stored `format` column rather than by guessing from bytes;
/// the tag is a self-describing cross-check.
const FORMAT_AUTH: u8 = 0x02;

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

    /// Seal this vault key to a member device, authenticated as `sender`.
    ///
    /// Uses HPKE **Auth mode** (spec §3): the seal is bound to `sender`'s X25519
    /// key, so a device that opens it learns not merely that the key is intact
    /// but that whoever produced it held `sender`'s private key. The recipient
    /// side ([`VaultKey::unwrap_for`]) authenticates against that key, and the
    /// vault layer checks `sender` was an admin — which is what stops a hostile
    /// relay, or a member revoked after it synced the ACL, from substituting a
    /// vault key of its own: neither holds an admin's device key.
    ///
    /// The sender id travels in the blob and is bound into the AAD, so it cannot
    /// be relabelled to point at a different device after the fact.
    pub fn wrap_for(
        &self,
        sender: &Device,
        recipient: &DevicePublic,
        vault: VaultId,
    ) -> Result<WrappedVaultKey> {
        let sender_id = sender.id();
        let aad = wrap_aad(vault, self.epoch, Some(sender_id));
        let mode = OpModeS::Auth((sender.kex_private().clone(), sender.public().kex_public()?));
        let (encapped, ciphertext) = hpke::single_shot_seal::<HpkeAead, HpkeKdf, Kem>(
            &mode,
            &recipient.kex_public()?,
            HPKE_INFO,
            self.key.expose(),
            &aad,
        )
        .map_err(|_| Error::Encrypt)?;

        Ok(WrappedVaultKey {
            sender: Some(sender_id),
            epoch: self.epoch,
            encapped: encapped.to_bytes().to_vec(),
            ciphertext,
        })
    }

    /// Seal in the pre-authentication HPKE Base mode.
    ///
    /// Retained only so a vault written before authenticated wrapping existed
    /// can still be read and upgraded (see [`VaultKey::unwrap_legacy`]), and so
    /// migration tests can construct a genuine legacy blob. **Production code
    /// must use [`VaultKey::wrap_for`]** — a Base-mode blob carries no sender
    /// identity, which is exactly the gap authenticated wrapping closes.
    pub fn wrap_legacy_for(
        &self,
        recipient: &DevicePublic,
        vault: VaultId,
    ) -> Result<WrappedVaultKey> {
        let aad = wrap_aad(vault, self.epoch, None);
        let (encapped, ciphertext) = hpke::single_shot_seal::<HpkeAead, HpkeKdf, Kem>(
            &OpModeS::Base,
            &recipient.kex_public()?,
            HPKE_INFO,
            self.key.expose(),
            &aad,
        )
        .map_err(|_| Error::Encrypt)?;

        Ok(WrappedVaultKey {
            sender: None,
            epoch: self.epoch,
            encapped: encapped.to_bytes().to_vec(),
            ciphertext,
        })
    }

    /// Recover a vault key sealed to this device, authenticating the sender
    /// against `sender_kex`.
    ///
    /// Fails if the blob was not sealed by the holder of `sender_kex` — which is
    /// how a substituted key is rejected. The caller is responsible for having
    /// established that `sender_kex` belongs to a device entitled to set the
    /// vault key (an admin); the vault layer does this against the ACL before
    /// calling in.
    pub fn unwrap_for(
        device: &Device,
        wrapped: &WrappedVaultKey,
        vault: VaultId,
        sender_kex: &KexPublic,
    ) -> Result<Self> {
        let encapped = <Kem as KemTrait>::EncappedKey::from_bytes(&wrapped.encapped)
            .map_err(|_| Error::Decrypt)?;
        let aad = wrap_aad(vault, wrapped.epoch, wrapped.sender);

        let plaintext = hpke::single_shot_open::<HpkeAead, HpkeKdf, Kem>(
            &OpModeR::Auth(sender_kex.clone()),
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

    /// Recover a vault key sealed in the pre-authentication Base mode.
    ///
    /// For reading a vault written before authenticated wrapping, on the path
    /// that upgrades it in place. New blobs always go through
    /// [`VaultKey::unwrap_for`].
    pub fn unwrap_legacy(
        device: &Device,
        wrapped: &WrappedVaultKey,
        vault: VaultId,
    ) -> Result<Self> {
        let encapped = <Kem as KemTrait>::EncappedKey::from_bytes(&wrapped.encapped)
            .map_err(|_| Error::Decrypt)?;
        let aad = wrap_aad(vault, wrapped.epoch, None);

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
    /// `Some` for an authenticated (Auth-mode) blob, naming the sealing device;
    /// `None` for a legacy Base-mode blob read off an older vault.
    sender: Option<DeviceId>,
    epoch: Epoch,
    encapped: Vec<u8>,
    ciphertext: Vec<u8>,
}

impl WrappedVaultKey {
    /// The epoch of the key inside.
    pub fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// The device that sealed this key, if it is an authenticated blob.
    pub fn sender_id(&self) -> Option<DeviceId> {
        self.sender
    }

    /// Serialize an authenticated blob:
    /// `0x02 ‖ sender(16) ‖ epoch(4) ‖ enc_len(4) ‖ encapped ‖ ciphertext`.
    ///
    /// A legacy blob (no sender) serializes in the old layout, via
    /// [`WrappedVaultKey::to_bytes_legacy`].
    pub fn to_bytes(&self) -> Vec<u8> {
        let Some(sender) = self.sender else {
            return self.to_bytes_legacy();
        };
        let mut out =
            Vec::with_capacity(1 + DEVICE_ID_LEN + 8 + self.encapped.len() + self.ciphertext.len());
        out.push(FORMAT_AUTH);
        out.extend_from_slice(sender.as_bytes());
        out.extend_from_slice(&self.epoch.0.to_be_bytes());
        out.extend_from_slice(&(self.encapped.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.encapped);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    /// Serialize in the legacy Base-mode layout:
    /// `epoch(4) ‖ enc_len(4) ‖ encapped ‖ ciphertext`.
    pub fn to_bytes_legacy(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + self.encapped.len() + self.ciphertext.len());
        out.extend_from_slice(&self.epoch.0.to_be_bytes());
        out.extend_from_slice(&(self.encapped.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.encapped);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    /// Parse an authenticated blob produced by [`WrappedVaultKey::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        const HEADER: usize = 1 + DEVICE_ID_LEN + 8;
        if bytes.len() < HEADER || bytes[0] != FORMAT_AUTH {
            return Err(Error::Decrypt);
        }
        let sender = DeviceId::from_bytes(
            bytes[1..1 + DEVICE_ID_LEN]
                .try_into()
                .map_err(|_| Error::Decrypt)?,
        );
        let epoch_at = 1 + DEVICE_ID_LEN;
        let epoch = Epoch(u32::from_be_bytes(
            bytes[epoch_at..epoch_at + 4]
                .try_into()
                .map_err(|_| Error::Decrypt)?,
        ));
        let encapped_len = u32::from_be_bytes(
            bytes[epoch_at + 4..HEADER]
                .try_into()
                .map_err(|_| Error::Decrypt)?,
        ) as usize;

        let rest = &bytes[HEADER..];
        if rest.len() < encapped_len {
            return Err(Error::Decrypt);
        }
        let (encapped, ciphertext) = rest.split_at(encapped_len);

        Ok(Self {
            sender: Some(sender),
            epoch,
            encapped: encapped.to_vec(),
            ciphertext: ciphertext.to_vec(),
        })
    }

    /// Parse a legacy Base-mode blob (`epoch(4) ‖ len(4) ‖ encapped ‖ ciphertext`).
    pub fn from_bytes_legacy(bytes: &[u8]) -> Result<Self> {
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
            sender: None,
            epoch,
            encapped: encapped.to_vec(),
            ciphertext: ciphertext.to_vec(),
        })
    }
}

/// AAD binding a wrapped vault key to its vault, epoch, and — for an
/// authenticated blob — the sealing device, so none of the three can be
/// relabelled without the open failing.
fn wrap_aad(vault: VaultId, epoch: Epoch, sender: Option<DeviceId>) -> Vec<u8> {
    let mut aad = Vec::with_capacity(VAULT_ID_LEN + 4 + DEVICE_ID_LEN);
    aad.extend_from_slice(vault.as_bytes());
    aad.extend_from_slice(&epoch.0.to_be_bytes());
    if let Some(sender) = sender {
        aad.extend_from_slice(sender.as_bytes());
    }
    aad
}

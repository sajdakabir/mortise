//! Vault keys, epochs and HPKE key wrapping: spec §3, §6.
//!
//! A vault key is symmetric and shared by every member. It is distributed by
//! sealing it to each member device's X25519 public key with HPKE, so the key
//! itself never transits in the clear and the relay never sees it.
//!
//! ## Why Auth mode, and not Base
//!
//! HPKE Base mode proves only that *somebody who knew the recipient's public
//! key* produced the blob — and those keys are public by construction, listed
//! in the ACL log every member replays. A relay, or a member removed after
//! they had synced the ACL, could therefore seal a vault key of their own
//! choosing to a member and have it accepted: the AAD binds the vault and the
//! epoch, both of which the attacker knows, and `WrappedVaultKey` carries no
//! signature.
//!
//! Auth mode mixes the *sender's* static X25519 key into the key schedule, so
//! opening one requires naming the sender in advance and succeeds only if that
//! device really sealed it. Callers take the sender's key from the signed ACL
//! log, which makes "this key came from an admin" checkable rather than
//! assumed.
//!
//! Blobs written before this change were sealed in Base mode and are opened by
//! [`VaultKey::unwrap_legacy_base`], which exists only so an existing vault can
//! be migrated on unlock. Nothing writes Base mode any more, and a wrapped key
//! that arrives over sync is *never* opened with it — accepting an
//! unauthenticated blob from the network is the whole vulnerability.
//!
//! ## Why Auth mode, and not Base
//!
//! HPKE Base mode proves only that *somebody who knew the recipient's public
//! key* produced the blob — and those keys are public by construction, listed
//! in the ACL log every member replays. A relay, or a member removed after
//! they had synced the ACL, could therefore seal a vault key of their own
//! choosing to a remaining member and have it accepted: `WrappedVaultKey` is
//! unsigned and the AAD binds only the vault and the epoch, both of which the
//! attacker knows.
//!
//! Auth mode mixes the *sender's* static X25519 key into the key schedule, so
//! opening a blob means naming the sender in advance and succeeds only if that
//! device really sealed it. Callers take the sender's key from the signed ACL
//! log, which turns "this key came from an admin" into something checkable.
//!
//! Keys written before this existed are Base mode and are read by
//! [`VaultKey::unwrap_legacy_base`], which is there so an existing vault
//! migrates on unlock. Nothing writes Base mode now, and a wrapped key that
//! arrives over sync is never opened with it.
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

    /// Seal this vault key to a member device, authenticated as `sender`.
    ///
    /// The recipient opens it with `sender`'s public key, so a blob sealed by
    /// anyone else — including a relay holding every public key the ACL lists
    /// — fails to open rather than yielding a key of the attacker's choosing.
    ///
    /// A device sealing to itself passes its own key as both. Self-wraps are
    /// then authenticated on the same path as everything else, leaving no
    /// second code path that accepts an unauthenticated blob.
    pub fn wrap_for(
        &self,
        sender: &Device,
        recipient: &DevicePublic,
        vault: VaultId,
    ) -> Result<WrappedVaultKey> {
        let aad = wrap_aad(vault, self.epoch);
        let (encapped, ciphertext) = hpke::single_shot_seal::<HpkeAead, HpkeKdf, Kem>(
            &OpModeS::Auth((sender.kex_private().clone(), sender.public().kex_public()?)),
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

    /// Recover a vault key sealed to this device by `sender`.
    ///
    /// `sender` is the authentication: it must be the device that actually
    /// sealed this blob. Callers take it from the signed ACL log rather than
    /// from whatever delivered the blob, or the check proves nothing.
    pub fn unwrap_for(
        recipient: &Device,
        sender: &DevicePublic,
        wrapped: &WrappedVaultKey,
        vault: VaultId,
    ) -> Result<Self> {
        Self::open(
            recipient,
            OpModeR::Auth(sender.kex_public()?),
            wrapped,
            vault,
        )
    }

    /// Seal in HPKE **Base** mode, the format this crate no longer writes.
    ///
    /// Exists so the migration off Base mode can be tested with a blob that is
    /// genuinely in the old format, rather than one a test pretended was. It is
    /// behind a feature the application never enables, so there is no way to
    /// reach it from a shipped build — the property that matters is structural
    /// here, not a naming convention.
    #[cfg(any(test, feature = "legacy-base-wrap"))]
    pub fn wrap_base_legacy(
        &self,
        recipient: &DevicePublic,
        vault: VaultId,
    ) -> Result<WrappedVaultKey> {
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

    /// Open a vault key sealed in HPKE **Base** mode, which authenticates
    /// nobody.
    ///
    /// Only for migrating keys a device sealed to *itself* before Auth mode
    /// existed. Never call it on a blob that arrived over the network: Base
    /// mode is precisely the gap Auth mode closes, and a caller that falls
    /// back to this when `unwrap_for` fails has reopened it in full.
    pub fn unwrap_legacy_base(
        recipient: &Device,
        wrapped: &WrappedVaultKey,
        vault: VaultId,
    ) -> Result<Self> {
        Self::open(recipient, OpModeR::Base, wrapped, vault)
    }

    fn open(
        recipient: &Device,
        mode: OpModeR<'_, Kem>,
        wrapped: &WrappedVaultKey,
        vault: VaultId,
    ) -> Result<Self> {
        let encapped = <Kem as KemTrait>::EncappedKey::from_bytes(&wrapped.encapped)
            .map_err(|_| Error::Decrypt)?;
        let aad = wrap_aad(vault, wrapped.epoch);

        let plaintext = hpke::single_shot_open::<HpkeAead, HpkeKdf, Kem>(
            &mode,
            recipient.kex_private(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Device;

    /// The vulnerability, directly.
    ///
    /// Base mode needs only the recipient's public key, which the ACL log
    /// publishes to every member. Before Auth mode this blob opened cleanly and
    /// the recipient adopted a key the attacker chose. `unwrap_for` must refuse
    /// it whoever is named as sender — there is no sender to name, which is the
    /// entire problem.
    #[test]
    fn a_base_mode_blob_is_refused_by_the_authenticated_path() {
        let vault = VaultId::generate().unwrap();
        let attacker = Device::generate().unwrap();
        let member = Device::generate().unwrap();
        let vk = VaultKey::generate().unwrap();

        let legacy = vk.wrap_base_legacy(member.public(), vault).unwrap();

        // Naming the attacker does not help: Base mode committed to no sender.
        assert_eq!(
            VaultKey::unwrap_for(&member, attacker.public(), &legacy, vault).unwrap_err(),
            Error::Decrypt
        );
        // Nor does naming the recipient itself.
        assert_eq!(
            VaultKey::unwrap_for(&member, member.public(), &legacy, vault).unwrap_err(),
            Error::Decrypt
        );
        // The legacy path still opens it, which is what migration relies on.
        assert_eq!(
            VaultKey::unwrap_legacy_base(&member, &legacy, vault).unwrap(),
            vk
        );
    }
}

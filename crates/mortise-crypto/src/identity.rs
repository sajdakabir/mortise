//! Identity and device keys: spec §2.3.
//!
//! An account has one long-lived **identity** keypair (Ed25519). Each machine
//! has its own **device** keypair pair (Ed25519 for signing, X25519 for key
//! agreement), and the identity key signs a [`DeviceCert`] binding those device
//! public keys to the account.
//!
//! Vault keys are sealed to *device* keys, never to the identity key. That is
//! what lets a stolen laptop be revoked by dropping one certificate, instead of
//! re-keying the identity and re-enrolling every other device.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hpke::{Deserializable, Kem as KemTrait, Serializable};
use zeroize::Zeroizing;

use crate::aead;
use crate::encode::{Canonical, Reader, Tag, Writer};
use crate::error::{Error, Result};
use crate::secret::Key32;

/// The KEM from spec §1: DHKEM(X25519, HKDF-SHA256).
pub type Kem = hpke::kem::X25519HkdfSha256;

/// A device's X25519 private key, used to unwrap vault keys.
pub type KexPrivate = <Kem as KemTrait>::PrivateKey;
/// A device's X25519 public key, used to seal vault keys to it.
pub type KexPublic = <Kem as KemTrait>::PublicKey;

/// Length of a serialized device identifier.
pub const DEVICE_ID_LEN: usize = 16;

/// Length of a serialized [`DeviceCert`]: tag, identity, device id, both device
/// keys, issue time, signature (spec §2.3).
pub const DEVICE_CERT_LEN: usize = 1 + 32 + DEVICE_ID_LEN + 32 + 32 + 8 + 64;

/// Context string for the identity fingerprint (spec §6.5).
const FINGERPRINT_CONTEXT: &str = "truepass/v1/fingerprint";

/// Digit groups in a rendered fingerprint.
pub const FINGERPRINT_GROUPS: usize = 12;

const IDENTITY_AAD: &[u8] = b"truepass/v1/identity";
const DEVICE_AAD: &[u8] = b"truepass/v1/device";

/// A device identifier: the first 16 bytes of BLAKE3 over the device's Ed25519
/// public key. Derived, never chosen, so two devices cannot collide by claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DeviceId([u8; DEVICE_ID_LEN]);

impl DeviceId {
    /// Derive the device id from an Ed25519 public key.
    ///
    /// Public so verifiers can confirm a change's stated author actually
    /// corresponds to the key that signed it.
    pub fn from_signing_public(sign_pub: &[u8; 32]) -> Self {
        let digest = blake3::hash(sign_pub);
        let mut id = [0u8; DEVICE_ID_LEN];
        id.copy_from_slice(&digest.as_bytes()[..DEVICE_ID_LEN]);
        Self(id)
    }

    /// Raw bytes.
    pub fn as_bytes(&self) -> &[u8; DEVICE_ID_LEN] {
        &self.0
    }

    /// Wrap raw bytes. Only for decoding values produced by this crate.
    pub const fn from_bytes(bytes: [u8; DEVICE_ID_LEN]) -> Self {
        Self(bytes)
    }
}

/// An account's public identity: the Ed25519 key that signs device certificates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdentityPublic([u8; 32]);

impl IdentityPublic {
    /// Raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Wrap raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    fn verifying_key(&self) -> Result<VerifyingKey> {
        VerifyingKey::from_bytes(&self.0).map_err(|_| Error::Signature)
    }

    /// Fingerprint for out-of-band verification (threat model A3, spec §6.5).
    ///
    /// Shown to users so they can confirm the person they are granting access
    /// to, or joining, holds the identity they think — rather than whoever got
    /// hold of an invite link, or whatever key a relay would have liked them to
    /// trust. Covers the identity only; a [`DeviceCert`] binds each device to it.
    pub fn fingerprint(&self) -> Fingerprint {
        let mut hasher = blake3::Hasher::new_derive_key(FINGERPRINT_CONTEXT);
        hasher.update(&self.0);
        let mut bytes = [0u8; FINGERPRINT_GROUPS * 5];
        hasher.finalize_xof().fill(&mut bytes);

        let mut groups = [0u32; FINGERPRINT_GROUPS];
        for (group, chunk) in groups.iter_mut().zip(bytes.chunks_exact(5)) {
            let mut wide = [0u8; 8];
            wide[3..].copy_from_slice(chunk);
            *group = (u64::from_be_bytes(wide) % 100_000) as u32;
        }
        Fingerprint(groups)
    }
}

/// An identity fingerprint: twelve groups of five decimal digits (spec §6.5).
///
/// Digits rather than hex because people compare them aloud, over a call, and
/// "four two seven one nine" survives that better than "eff zero bee".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Fingerprint([u32; FINGERPRINT_GROUPS]);

impl Fingerprint {
    /// The twelve groups, each below 100000.
    pub fn groups(&self) -> &[u32; FINGERPRINT_GROUPS] {
        &self.0
    }
}

/// `12345 67890 …`: zero-padded groups separated by single spaces.
impl core::fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for (i, group) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(" ")?;
            }
            write!(f, "{group:05}")?;
        }
        Ok(())
    }
}

/// An account's long-lived identity keypair.
///
/// Stored wrapped under the MUK and never leaves the device in the clear.
pub struct Identity {
    signing: SigningKey,
}

impl Identity {
    /// Generate a fresh identity.
    pub fn generate() -> Result<Self> {
        let seed = Zeroizing::new(crate::rand::bytes::<32>()?);
        Ok(Self {
            signing: SigningKey::from_bytes(&seed),
        })
    }

    /// The public half.
    pub fn public(&self) -> IdentityPublic {
        IdentityPublic(self.signing.verifying_key().to_bytes())
    }

    /// Seal the private key under the master unlock key.
    pub fn wrap(&self, muk: &Key32) -> Result<Vec<u8>> {
        let secret = Zeroizing::new(self.signing.to_bytes());
        aead::seal(muk, secret.as_ref(), IDENTITY_AAD)
    }

    /// Recover the identity from bytes produced by [`Identity::wrap`].
    pub fn unwrap(muk: &Key32, sealed: &[u8]) -> Result<Self> {
        let bytes = aead::open(muk, sealed, IDENTITY_AAD)?;
        let seed: [u8; 32] = bytes.as_slice().try_into().map_err(|_| Error::Length {
            expected: 32,
            got: bytes.len(),
        })?;
        Ok(Self {
            signing: SigningKey::from_bytes(&seed),
        })
    }

    /// Issue a certificate binding a device's public keys to this account.
    pub fn certify(&self, device: &DevicePublic, issued_at_ms: u64) -> DeviceCert {
        let mut cert = DeviceCert {
            identity: self.public(),
            device: device.clone(),
            issued_at_ms,
            signature: [0u8; 64],
        };
        let digest = cert.canonical_digest();
        cert.signature = self.signing.sign(&digest).to_bytes();
        cert
    }
}

impl core::fmt::Debug for Identity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Identity({:?})", self.public())
    }
}

/// A device's public keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevicePublic {
    id: DeviceId,
    sign_pub: [u8; 32],
    kex_pub: [u8; 32],
}

impl DevicePublic {
    /// The derived device identifier.
    pub fn id(&self) -> DeviceId {
        self.id
    }

    /// Ed25519 public key, for verifying this device's changes.
    pub fn signing_public(&self) -> &[u8; 32] {
        &self.sign_pub
    }

    /// X25519 public key, for sealing vault keys to this device.
    pub fn kex_public(&self) -> Result<KexPublic> {
        KexPublic::from_bytes(&self.kex_pub).map_err(|_| Error::InvalidKey)
    }

    /// Raw X25519 public key bytes.
    pub fn kex_public_bytes(&self) -> &[u8; 32] {
        &self.kex_pub
    }

    /// Reassemble from raw bytes, recomputing the id.
    pub fn from_parts(sign_pub: [u8; 32], kex_pub: [u8; 32]) -> Self {
        Self {
            id: DeviceId::from_signing_public(&sign_pub),
            sign_pub,
            kex_pub,
        }
    }
}

/// One machine's keypairs.
pub struct Device {
    signing: SigningKey,
    kex_private: KexPrivate,
    public: DevicePublic,
}

impl Device {
    /// Generate fresh device keys.
    pub fn generate() -> Result<Self> {
        let sign_seed = Zeroizing::new(crate::rand::bytes::<32>()?);
        let signing = SigningKey::from_bytes(&sign_seed);

        let kex_ikm = Zeroizing::new(crate::rand::bytes::<32>()?);
        let (kex_private, kex_public) = Kem::derive_keypair(kex_ikm.as_ref());

        let sign_pub = signing.verifying_key().to_bytes();
        let kex_pub: [u8; 32] = kex_public
            .to_bytes()
            .as_slice()
            .try_into()
            .map_err(|_| Error::InvalidKey)?;

        Ok(Self {
            signing,
            kex_private,
            public: DevicePublic::from_parts(sign_pub, kex_pub),
        })
    }

    /// The public half.
    pub fn public(&self) -> &DevicePublic {
        &self.public
    }

    /// This device's identifier.
    pub fn id(&self) -> DeviceId {
        self.public.id
    }

    /// The X25519 private key, for unwrapping vault keys sealed to this device.
    pub fn kex_private(&self) -> &KexPrivate {
        &self.kex_private
    }

    /// Sign a 32-byte digest.
    pub fn sign(&self, digest: &[u8; 32]) -> [u8; 64] {
        self.signing.sign(digest).to_bytes()
    }

    /// Seal both private keys under the master unlock key.
    pub fn wrap(&self, muk: &Key32) -> Result<Vec<u8>> {
        let mut secret = Zeroizing::new([0u8; 64]);
        secret[..32].copy_from_slice(&self.signing.to_bytes());
        secret[32..].copy_from_slice(self.kex_private.to_bytes().as_slice());
        aead::seal(muk, secret.as_ref(), DEVICE_AAD)
    }

    /// Recover device keys from bytes produced by [`Device::wrap`].
    pub fn unwrap(muk: &Key32, sealed: &[u8]) -> Result<Self> {
        let bytes = aead::open(muk, sealed, DEVICE_AAD)?;
        if bytes.len() != 64 {
            return Err(Error::Length {
                expected: 64,
                got: bytes.len(),
            });
        }
        let sign_seed: [u8; 32] = bytes[..32].try_into().map_err(|_| Error::InvalidKey)?;
        let signing = SigningKey::from_bytes(&sign_seed);
        let kex_private = KexPrivate::from_bytes(&bytes[32..]).map_err(|_| Error::InvalidKey)?;

        let kex_public = <Kem as KemTrait>::sk_to_pk(&kex_private);
        let kex_pub: [u8; 32] = kex_public
            .to_bytes()
            .as_slice()
            .try_into()
            .map_err(|_| Error::InvalidKey)?;
        let sign_pub = signing.verifying_key().to_bytes();

        Ok(Self {
            signing,
            kex_private,
            public: DevicePublic::from_parts(sign_pub, kex_pub),
        })
    }
}

impl core::fmt::Debug for Device {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Device({:?})", self.public.id)
    }
}

/// An identity's signature over a device's public keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceCert {
    identity: IdentityPublic,
    device: DevicePublic,
    issued_at_ms: u64,
    signature: [u8; 64],
}

impl DeviceCert {
    /// The issuing account identity.
    pub fn identity(&self) -> IdentityPublic {
        self.identity
    }

    /// The certified device.
    pub fn device(&self) -> &DevicePublic {
        &self.device
    }

    /// Issue time, milliseconds since the Unix epoch.
    pub fn issued_at_ms(&self) -> u64 {
        self.issued_at_ms
    }

    /// Serialize: the canonical encoding followed by the signature, exactly
    /// [`DEVICE_CERT_LEN`] bytes (spec §2.3).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.canonical_bytes();
        out.extend_from_slice(&self.signature);
        out
    }

    /// Parse and **verify** a certificate produced by [`DeviceCert::to_bytes`].
    ///
    /// Refuses anything of the wrong length or tag, a device id that does not
    /// derive from the device's signing key, and a signature that does not
    /// verify under the stated identity. As with [`DeviceCert::verify`], the
    /// caller must still decide whether that identity is the expected one.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != DEVICE_CERT_LEN {
            return Err(Error::Length {
                expected: DEVICE_CERT_LEN,
                got: bytes.len(),
            });
        }
        let mut r = Reader::new(bytes, Tag::DeviceCert).ok_or(Error::Signature)?;
        let parsed = (|| {
            let identity = IdentityPublic(r.fixed::<32>()?);
            let device_id = DeviceId(r.fixed::<DEVICE_ID_LEN>()?);
            let sign_pub = r.fixed::<32>()?;
            let kex_pub = r.fixed::<32>()?;
            let issued_at_ms = r.u64()?;
            let signature = r.fixed::<64>()?;
            Some((
                identity,
                device_id,
                sign_pub,
                kex_pub,
                issued_at_ms,
                signature,
            ))
        })();
        let (identity, device_id, sign_pub, kex_pub, issued_at_ms, signature) =
            parsed.ok_or(Error::Signature)?;
        r.finish().ok_or(Error::Signature)?;

        let device = DevicePublic::from_parts(sign_pub, kex_pub);
        // The id is encoded for the signature's sake but never trusted: one
        // that does not derive from the key would let a certificate name a
        // device other than the one whose keys it carries.
        if device.id() != device_id {
            return Err(Error::Signature);
        }
        device.kex_public()?;

        let cert = Self {
            identity,
            device,
            issued_at_ms,
            signature,
        };
        cert.verify()?;
        Ok(cert)
    }

    /// Verify the certificate against its stated identity.
    ///
    /// Callers must still check that the identity is the one they expect —
    /// a self-consistent certificate proves nothing on its own.
    pub fn verify(&self) -> Result<()> {
        let digest = {
            let mut unsigned = self.clone();
            unsigned.signature = [0u8; 64];
            unsigned.canonical_digest()
        };
        let signature = Signature::from_bytes(&self.signature);
        self.identity
            .verifying_key()?
            .verify_strict(&digest, &signature)
            .map_err(|_| Error::Signature)
    }
}

impl Canonical for DeviceCert {
    fn tag() -> Tag {
        Tag::DeviceCert
    }

    fn encode(&self, w: &mut Writer) {
        w.fixed(self.identity.as_bytes())
            .fixed(self.device.id.as_bytes())
            .fixed(&self.device.sign_pub)
            .fixed(&self.device.kex_pub)
            .u64(self.issued_at_ms);
    }
}

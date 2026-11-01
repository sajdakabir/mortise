//! Invites to a project vault, and the join request that answers one: spec §6.4.
//!
//! Joining takes one link from the owner and one click from the owner.
//!
//! The **invite** carries everything the joiner has to trust — the relay, the
//! vault id, the inviting device's certificate and the genesis owner's keys —
//! plus a one-time secret. It is not signed: it travels over whatever channel
//! the owner picks, and anyone able to alter it there could replace a signature
//! along with everything else. The joiner is protected by the inviter's
//! fingerprint, shown before anything is sent.
//!
//! The **join request** goes back through a relay mailbox, sealed to the
//! inviting device in HPKE AuthPSK mode. The PSK is derived from the invite's
//! secret, so the relay — which sees only a mailbox id derived the other way —
//! can neither fabricate nor alter one. AuthPSK rather than PSK alone also
//! proves the request came from the holder of the device key it carries.
//!
//! Anyone holding the link can still produce a valid request: the link is a
//! bearer secret. That is why nothing here grants anything. The owner sees the
//! requester's fingerprint and decides.

use data_encoding::BASE64URL_NOPAD;
use hpke::{Deserializable, Kem as KemTrait, OpModeR, OpModeS, PskBundle, Serializable};
use zeroize::Zeroizing;

use crate::encode::{Reader, Tag, Writer};
use crate::error::{Error, Result};
use crate::identity::{DEVICE_CERT_LEN, Device, DeviceCert, DevicePublic, Kem, KexPublic};
use crate::kdf;
use crate::secret::Key32;
use crate::vault::{VAULT_ID_LEN, VaultId};

/// What every invite link starts with. A fragment rather than a path, so a link
/// pasted into a browser by mistake never sends the secret to a server.
pub const LINK_PREFIX: &str = "mortise://join#";

/// Length of a mailbox id.
pub const MAILBOX_ID_LEN: usize = 16;

/// Longest display name, in bytes, for a person.
pub const MAX_NAME_LEN: usize = 64;

/// Longest project name, in bytes.
pub const MAX_PROJECT_NAME_LEN: usize = 128;

/// Longest relay URL, in bytes.
pub const MAX_URL_LEN: usize = 2048;

/// Longest an invite may stay open (spec §6.4).
pub const MAX_INVITE_LIFETIME_MS: u64 = 7 * 24 * 60 * 60 * 1000;

const CHECKSUM_LEN: usize = 4;
const JOIN_REQUEST_INFO: &[u8] = b"truepass/v1/join-request";
const REQUEST_FORMAT: u8 = 0x01;

type HpkeAead = hpke::aead::ChaCha20Poly1305;
type HpkeKdf = hpke::kdf::HkdfSha256;

/// Where on the relay a join request is left: derived from the invite secret,
/// so the relay learns the address without learning the secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MailboxId([u8; MAILBOX_ID_LEN]);

impl MailboxId {
    /// Raw bytes.
    pub fn as_bytes(&self) -> &[u8; MAILBOX_ID_LEN] {
        &self.0
    }

    /// Wrap raw bytes.
    pub const fn from_bytes(bytes: [u8; MAILBOX_ID_LEN]) -> Self {
        Self(bytes)
    }
}

/// An invite's one-time secret. Whoever holds it can ask to join; only the
/// owner can let them in.
///
/// Zeroized on drop and redacted in `Debug`, like every key in this crate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InviteSecret(Key32);

impl InviteSecret {
    /// A fresh secret from the OS CSPRNG.
    pub fn generate() -> Result<Self> {
        Ok(Self(Key32::random()?))
    }

    /// Rebuild from stored bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Key32::new(bytes))
    }

    /// The raw secret, for storing on the inviting device.
    pub fn expose(&self) -> &[u8; 32] {
        self.0.expose()
    }

    /// The relay mailbox this invite's request is posted to.
    pub fn mailbox_id(&self) -> Result<MailboxId> {
        let derived = kdf::subkey(&self.0, kdf::info::INVITE_MAILBOX)?;
        let mut id = [0u8; MAILBOX_ID_LEN];
        id.copy_from_slice(&derived.expose()[..MAILBOX_ID_LEN]);
        Ok(MailboxId(id))
    }

    fn psk(&self) -> Result<Key32> {
        kdf::subkey(&self.0, kdf::info::INVITE_PSK)
    }
}

/// Whether a relay URL may be used: `https://`, or `http://` to this machine.
///
/// The same rule the relay setting applies. Plain http anywhere else would put
/// device keys and sync timing on the wire in the clear. The host is parsed
/// out rather than searched for, so `http://localhost.evil.example/` and
/// `http://evil.example/#127.0.0.1` are refused.
pub fn relay_url_allowed(url: &str) -> bool {
    if let Some(rest) = url.strip_prefix("https://") {
        return !rest.is_empty() && !url.chars().any(char::is_whitespace);
    }
    let Some(rest) = url.strip_prefix("http://") else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host_port = match authority.rsplit_once('@') {
        Some((_, after)) => after,
        None => authority,
    };
    let host = if let Some(end) = host_port.strip_prefix('[').and_then(|r| r.find(']')) {
        &host_port[..end + 2]
    } else {
        host_port.split(':').next().unwrap_or_default()
    };
    matches!(
        host.to_ascii_lowercase().as_str(),
        "127.0.0.1" | "localhost" | "[::1]"
    )
}

/// Whether a self-chosen name may be shown to someone deciding whom to trust.
///
/// Control characters and Unicode bidi overrides are refused: both let a name
/// render as something other than what it is, and a name is only ever shown
/// beside a fingerprint someone is meant to compare against it.
fn name_allowed(name: &str, max: usize) -> bool {
    !name.trim().is_empty()
        && name.len() <= max
        && !name.chars().any(|c| {
            c.is_control() || matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
        })
}

/// An invite to a project vault (spec §6.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invite {
    vault: VaultId,
    relay_url: String,
    inviter: DeviceCert,
    inviter_name: String,
    project_name: String,
    owner: DevicePublic,
    secret: InviteSecret,
    expires_at_ms: u64,
}

impl Invite {
    /// Create an invite with a fresh secret.
    ///
    /// `owner` is the vault's genesis owner (spec §6.2), which the joiner pins
    /// to replay the ACL from — not necessarily the inviting device, since an
    /// admin may invite. `expires_at_ms` must be within
    /// [`MAX_INVITE_LIFETIME_MS`] of `now_ms`.
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        vault: VaultId,
        relay_url: &str,
        inviter: DeviceCert,
        inviter_name: &str,
        project_name: &str,
        owner: DevicePublic,
        now_ms: u64,
        expires_at_ms: u64,
    ) -> Result<Self> {
        if expires_at_ms <= now_ms || expires_at_ms - now_ms > MAX_INVITE_LIFETIME_MS {
            return Err(Error::Invite("an invite must expire within seven days"));
        }
        let invite = Self {
            vault,
            relay_url: relay_url.to_string(),
            inviter,
            inviter_name: inviter_name.trim().to_string(),
            project_name: project_name.trim().to_string(),
            owner,
            secret: InviteSecret::generate()?,
            expires_at_ms,
        };
        invite.validate(now_ms)?;
        Ok(invite)
    }

    /// The vault being joined.
    pub fn vault(&self) -> VaultId {
        self.vault
    }

    /// The relay the vault syncs through.
    pub fn relay_url(&self) -> &str {
        &self.relay_url
    }

    /// The inviting device's certificate. Its identity's fingerprint is what
    /// the joiner should check.
    pub fn inviter(&self) -> &DeviceCert {
        &self.inviter
    }

    /// The inviter's self-chosen name. Never shown without the fingerprint.
    pub fn inviter_name(&self) -> &str {
        &self.inviter_name
    }

    /// The project's name, as the inviter calls it.
    pub fn project_name(&self) -> &str {
        &self.project_name
    }

    /// The genesis owner's device keys, to pin as the start of the ACL.
    pub fn owner(&self) -> &DevicePublic {
        &self.owner
    }

    /// The one-time secret.
    pub fn secret(&self) -> &InviteSecret {
        &self.secret
    }

    /// When the invite stops working.
    pub fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }

    /// The relay mailbox for this invite's join request.
    pub fn mailbox_id(&self) -> Result<MailboxId> {
        self.secret.mailbox_id()
    }

    fn validate(&self, now_ms: u64) -> Result<()> {
        if self.relay_url.len() > MAX_URL_LEN || !relay_url_allowed(&self.relay_url) {
            return Err(Error::Invite(
                "the relay must use https://, or http:// only on this machine",
            ));
        }
        if !name_allowed(&self.inviter_name, MAX_NAME_LEN) {
            return Err(Error::Invite(
                "the inviter's name is empty, too long or unprintable",
            ));
        }
        if !name_allowed(&self.project_name, MAX_PROJECT_NAME_LEN) {
            return Err(Error::Invite(
                "the project's name is empty, too long or unprintable",
            ));
        }
        self.owner.kex_public()?;
        if now_ms >= self.expires_at_ms {
            return Err(Error::Invite("this invite has expired"));
        }
        Ok(())
    }

    /// The canonical bytes, without the checksum.
    fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new(Tag::Invite);
        w.fixed(self.vault.as_bytes())
            .bytes(self.relay_url.as_bytes())
            .bytes(&self.inviter.to_bytes())
            .bytes(self.inviter_name.as_bytes())
            .bytes(self.project_name.as_bytes())
            .fixed(self.owner.signing_public())
            .fixed(self.owner.kex_public_bytes())
            .fixed(self.secret.expose())
            .u64(self.expires_at_ms);
        w.finish()
    }

    /// Render as a link to hand to the joiner.
    ///
    /// The link contains the secret. Show it to the person who asked for it and
    /// nowhere else; it is never logged.
    pub fn to_link(&self) -> String {
        let mut bytes = Zeroizing::new(self.encode());
        let check = blake3::hash(&bytes);
        bytes.extend_from_slice(&check.as_bytes()[..CHECKSUM_LEN]);
        format!("{LINK_PREFIX}{}", BASE64URL_NOPAD.encode(&bytes))
    }

    /// Parse and validate a link produced by [`Invite::to_link`].
    ///
    /// Refuses a damaged link, a relay that is neither https nor this machine,
    /// an unprintable or oversized name, an inviter certificate that does not
    /// verify, and an invite past its expiry at `now_ms`. Surrounding
    /// whitespace — the usual result of copying from a chat — is ignored.
    pub fn from_link(link: &str, now_ms: u64) -> Result<Self> {
        let encoded = link
            .trim()
            .strip_prefix(LINK_PREFIX)
            .ok_or(Error::Invite("that is not a Mortise invite link"))?;
        let bytes = Zeroizing::new(
            BASE64URL_NOPAD
                .decode(encoded.as_bytes())
                .map_err(|_| Error::Invite("this invite link is damaged"))?,
        );
        if bytes.len() < CHECKSUM_LEN {
            return Err(Error::Invite("this invite link is damaged"));
        }
        let (body, check) = bytes.split_at(bytes.len() - CHECKSUM_LEN);
        if blake3::hash(body).as_bytes()[..CHECKSUM_LEN] != *check {
            return Err(Error::Invite("this invite link is damaged"));
        }
        Self::decode(body, now_ms)
    }

    fn decode(body: &[u8], now_ms: u64) -> Result<Self> {
        let damaged = Error::Invite("this invite link is damaged");
        let mut r = Reader::new(body, Tag::Invite).ok_or(damaged.clone())?;

        let vault = VaultId::from_bytes(r.fixed::<VAULT_ID_LEN>().ok_or(damaged.clone())?);
        let relay_url = utf8(r.bytes(MAX_URL_LEN))?;
        let inviter_bytes = r.bytes(DEVICE_CERT_LEN).ok_or(damaged.clone())?;
        let inviter_name = utf8(r.bytes(MAX_NAME_LEN))?;
        let project_name = utf8(r.bytes(MAX_PROJECT_NAME_LEN))?;
        let owner_sign = r.fixed::<32>().ok_or(damaged.clone())?;
        let owner_kex = r.fixed::<32>().ok_or(damaged.clone())?;
        let secret = InviteSecret::from_bytes(r.fixed::<32>().ok_or(damaged.clone())?);
        let expires_at_ms = r.u64().ok_or(damaged.clone())?;
        r.finish().ok_or(damaged)?;

        let inviter = DeviceCert::from_bytes(inviter_bytes)
            .map_err(|_| Error::Invite("the inviter's certificate does not verify"))?;

        let invite = Self {
            vault,
            relay_url,
            inviter,
            inviter_name,
            project_name,
            owner: DevicePublic::from_parts(owner_sign, owner_kex),
            secret,
            expires_at_ms,
        };
        invite.validate(now_ms)?;
        Ok(invite)
    }
}

fn utf8(bytes: Option<&[u8]>) -> Result<String> {
    let bytes = bytes.ok_or(Error::Invite("this invite link is damaged"))?;
    String::from_utf8(bytes.to_vec()).map_err(|_| Error::Invite("this invite link is damaged"))
}

/// A join request, opened and checked: who is asking, and what they call
/// themselves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinRequest {
    cert: DeviceCert,
    name: String,
}

impl JoinRequest {
    /// The requesting device's certificate. Verified, and proven to belong to
    /// the device that sealed the request.
    pub fn cert(&self) -> &DeviceCert {
        &self.cert
    }

    /// The requester's self-chosen name. Show it only beside
    /// `cert().identity().fingerprint()`.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Seal a request to join `invite`'s vault as `device`.
    ///
    /// `cert` must certify `device` — the request is sealed with that device's
    /// X25519 key (AuthPSK), and the inviter checks the two agree.
    pub fn seal(
        invite: &Invite,
        device: &Device,
        cert: &DeviceCert,
        name: &str,
    ) -> Result<Vec<u8>> {
        if cert.device() != device.public() {
            return Err(Error::Invite("the certificate is for a different device"));
        }
        cert.verify()?;
        let name = name.trim();
        if !name_allowed(name, MAX_NAME_LEN) {
            return Err(Error::Invite("your name is empty, too long or unprintable"));
        }

        let mailbox = invite.mailbox_id()?;
        let psk = invite.secret.psk()?;
        let mut w = Writer::new(Tag::JoinRequest);
        w.bytes(&cert.to_bytes()).bytes(name.as_bytes());
        let plaintext = Zeroizing::new(w.finish());

        let mode = OpModeS::AuthPsk(
            (device.kex_private().clone(), device.public().kex_public()?),
            PskBundle::new(psk.expose(), mailbox.as_bytes()).map_err(|_| Error::Encrypt)?,
        );
        let (encapped, ciphertext) = hpke::single_shot_seal::<HpkeAead, HpkeKdf, Kem>(
            &mode,
            &invite.inviter.device().kex_public()?,
            JOIN_REQUEST_INFO,
            &plaintext,
            &request_aad(invite.vault, mailbox),
        )
        .map_err(|_| Error::Encrypt)?;

        let encapped = encapped.to_bytes();
        let mut out = Vec::with_capacity(1 + 32 + encapped.len() + ciphertext.len());
        out.push(REQUEST_FORMAT);
        out.extend_from_slice(device.public().kex_public_bytes());
        out.extend_from_slice(&encapped);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Open a request posted to the mailbox of the invite with `secret`, on the
    /// inviting `device`.
    ///
    /// Fails, opaquely, on anything the relay could have produced or altered:
    /// without the secret it cannot derive the PSK. Then requires the
    /// certificate inside to verify and to name the device that sealed it.
    pub fn open(
        device: &Device,
        vault: VaultId,
        secret: &InviteSecret,
        request: &[u8],
    ) -> Result<Self> {
        const HEADER: usize = 1 + 32 + 32;
        if request.len() < HEADER || request[0] != REQUEST_FORMAT {
            return Err(Error::Decrypt);
        }
        let sender_bytes: [u8; 32] = request[1..33].try_into().map_err(|_| Error::Decrypt)?;
        let sender = KexPublic::from_bytes(&sender_bytes).map_err(|_| Error::Decrypt)?;
        let encapped = <Kem as KemTrait>::EncappedKey::from_bytes(&request[33..HEADER])
            .map_err(|_| Error::Decrypt)?;

        let mailbox = secret.mailbox_id()?;
        let psk = secret.psk()?;
        let mode = OpModeR::AuthPsk(
            sender,
            PskBundle::new(psk.expose(), mailbox.as_bytes()).map_err(|_| Error::Decrypt)?,
        );
        let plaintext = Zeroizing::new(
            hpke::single_shot_open::<HpkeAead, HpkeKdf, Kem>(
                &mode,
                device.kex_private(),
                &encapped,
                JOIN_REQUEST_INFO,
                &request[HEADER..],
                &request_aad(vault, mailbox),
            )
            .map_err(|_| Error::Decrypt)?,
        );

        let mut r = Reader::new(&plaintext, Tag::JoinRequest).ok_or(Error::Decrypt)?;
        let cert_bytes = r.bytes(DEVICE_CERT_LEN).ok_or(Error::Decrypt)?;
        let name = r.bytes(MAX_NAME_LEN).ok_or(Error::Decrypt)?;
        r.finish().ok_or(Error::Decrypt)?;

        let cert = DeviceCert::from_bytes(cert_bytes)?;
        // The proof of possession: the request was sealed with this X25519 key,
        // so the certificate must be for the device holding it. Otherwise
        // anyone with the link could forward someone else's public certificate.
        if *cert.device().kex_public_bytes() != sender_bytes {
            return Err(Error::Signature);
        }
        let name = String::from_utf8(name.to_vec()).map_err(|_| Error::Decrypt)?;
        if !name_allowed(&name, MAX_NAME_LEN) {
            return Err(Error::Invite(
                "the requester's name is empty, too long or unprintable",
            ));
        }
        Ok(Self { cert, name })
    }
}

fn request_aad(vault: VaultId, mailbox: MailboxId) -> [u8; VAULT_ID_LEN + MAILBOX_ID_LEN] {
    let mut aad = [0u8; VAULT_ID_LEN + MAILBOX_ID_LEN];
    aad[..VAULT_ID_LEN].copy_from_slice(vault.as_bytes());
    aad[VAULT_ID_LEN..].copy_from_slice(mailbox.as_bytes());
    aad
}

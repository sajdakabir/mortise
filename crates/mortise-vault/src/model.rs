//! The item model: the layer where payloads stop being opaque bytes.
//!
//! `mortise-crypto` deliberately knows nothing about item contents (spec
//! §5.1). This is where that structure lives.
//!
//! Metadata and secrets are split deliberately. [`ItemMeta`] is what you search
//! and list; [`ItemPayload`] is what actually needs protecting and is only ever
//! decrypted for one item at a time, on demand.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// What kind of thing an item is.
///
/// Stored as an integer. **Never renumber a variant** — the number is the only
/// thing linking a stored row to its payload shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ItemKind {
    /// Website or app login.
    Login = 1,
    /// Free-form encrypted note.
    SecureNote = 2,
    /// Payment card.
    Card = 3,
    /// API key or token.
    ApiKey = 4,
    /// A WebAuthn passkey.
    Passkey = 5,
    /// A single environment-style secret, for the dev-secrets layer (M8).
    EnvSecret = 6,
}

impl ItemKind {
    /// Parse from its stored integer.
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => Self::Login,
            2 => Self::SecureNote,
            3 => Self::Card,
            4 => Self::ApiKey,
            5 => Self::Passkey,
            6 => Self::EnvSecret,
            _ => return None,
        })
    }
}

/// Searchable, listable metadata.
///
/// Sealed under the **vault** key, so it syncs and shared-vault members can
/// read it. Not secret in the way a password is, but still never stored in a
/// plaintext column: which sites someone has accounts on is exactly the kind of
/// thing a stolen laptop should not reveal.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemMeta {
    /// Display name.
    pub title: String,
    /// Origins this item applies to. Drives autofill matching at M5.
    #[serde(default)]
    pub urls: Vec<String>,
    /// Username or account identifier.
    #[serde(default)]
    pub username: Option<String>,
    /// Containing folder, if any.
    #[serde(default)]
    pub folder: Option<String>,
    /// The project this belongs to, for the developer-secrets layer.
    ///
    /// A plain string rather than a foreign key: a project is a label on its
    /// items and nothing else owns it, so creating one costs no row and
    /// renaming one cannot leave an item pointing at something gone.
    ///
    /// Not yet the unit of sharing. That has to be a vault, because the ACL,
    /// the key epoch and the member list all hang off one — see `vault` in
    /// the schema. Promoting a project to its own vault later means
    /// re-sealing its items under that vault's key, which is mechanical.
    #[serde(default)]
    pub project: Option<String>,
    /// Which environment within the project: `dev`, `staging`, `prod`.
    ///
    /// Free-form on purpose. Every team draws these lines differently, and a
    /// fixed enum would be wrong for someone on the first day.
    #[serde(default)]
    pub environment: Option<String>,
    /// Free-form tags.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Rotate every this many days. `None` means no policy.
    ///
    /// Set by the user. Lives in the synced metadata so a team shares one
    /// policy per secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotate_every_days: Option<u32>,
    /// When the secret value last changed, in Unix milliseconds.
    ///
    /// **Maintained by the vault**, not callers: whatever a caller passes is
    /// replaced on write (see [`crate::rotation`]). Absent on items written
    /// before rotation tracking existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotated_at_ms: Option<u64>,
    /// Until when a previous value can be restored, in Unix milliseconds.
    ///
    /// Maintained by the vault. Mirrors the payload's previous value so a
    /// list can show "restorable" without decrypting anything.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_until_ms: Option<u64>,
}

impl ItemMeta {
    /// When this item is next due for rotation, if it has a policy.
    ///
    /// `fallback_rotated_at_ms` stands in for items written before rotation
    /// tracking existed; callers pass the best time they know.
    pub fn rotation_due_at_ms(&self, fallback_rotated_at_ms: u64) -> Option<u64> {
        let days = u64::from(self.rotate_every_days?);
        let since = self.rotated_at_ms.unwrap_or(fallback_rotated_at_ms);
        Some(since.saturating_add(days.saturating_mul(86_400_000)))
    }
}

/// The value a secret had before its last rotation, kept briefly so a bad
/// rotation can be undone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
pub struct PreviousValue {
    /// The old secret.
    pub value: String,
    /// When the old value had been set, so restoring it restores its age.
    #[serde(default)]
    pub rotated_at_ms: Option<u64>,
    /// When this stops being restorable and is wiped.
    pub until_ms: u64,
}

/// The secret half of an item.
///
/// Zeroized on drop. Only ever decrypted for a single item, on demand — never
/// in bulk for a list view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(tag = "kind")]
pub enum ItemPayload {
    /// A login's secrets.
    Login {
        /// The password.
        password: String,
        /// TOTP seed, base32, if configured.
        totp_seed: Option<String>,
        /// Private notes.
        notes: Option<String>,
    },
    /// A note's body.
    SecureNote {
        /// The note text.
        body: String,
    },
    /// A payment card.
    Card {
        /// Card number.
        number: String,
        /// Expiry, `MM/YY`.
        expiry: String,
        /// Security code.
        cvv: String,
        /// Name on the card.
        holder: String,
    },
    /// An API key or token.
    ApiKey {
        /// The key itself. Indexed by Agent Guard.
        key: String,
        /// Private notes.
        notes: Option<String>,
        /// The key before the last rotation, while still restorable.
        /// Maintained by the vault; never sent to the webview.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        previous: Option<PreviousValue>,
    },
    /// A WebAuthn passkey.
    ///
    /// The schema slot spec §10 required reserving before M2 closed. The
    /// ceremony logic is deferred, but the shape is fixed now: retrofitting the
    /// item model later is expensive.
    Passkey {
        /// Relying party id, e.g. `github.com`.
        rp_id: String,
        /// Credential id as issued.
        credential_id: Vec<u8>,
        /// The credential private key.
        private_key: Vec<u8>,
        /// Opaque user handle from the relying party.
        user_handle: Vec<u8>,
    },
    /// A single environment-style secret.
    EnvSecret {
        /// The value. May reference another secret as `${NAME}` (M8).
        value: String,
        /// The value before the last rotation, while still restorable.
        /// Maintained by the vault; never sent to the webview.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        previous: Option<PreviousValue>,
    },
}

impl ItemPayload {
    /// The kind this payload corresponds to.
    pub fn kind(&self) -> ItemKind {
        match self {
            Self::Login { .. } => ItemKind::Login,
            Self::SecureNote { .. } => ItemKind::SecureNote,
            Self::Card { .. } => ItemKind::Card,
            Self::ApiKey { .. } => ItemKind::ApiKey,
            Self::Passkey { .. } => ItemKind::Passkey,
            Self::EnvSecret { .. } => ItemKind::EnvSecret,
        }
    }

    /// The secret whose change counts as a rotation, for kinds that have one.
    pub fn primary_secret(&self) -> Option<&str> {
        match self {
            Self::Login { password, .. } => Some(password),
            Self::ApiKey { key, .. } => Some(key),
            Self::EnvSecret { value, .. } => Some(value),
            Self::SecureNote { .. } | Self::Card { .. } | Self::Passkey { .. } => None,
        }
    }

    /// The restorable previous value, for kinds that keep one.
    pub fn previous(&self) -> Option<&PreviousValue> {
        match self {
            Self::ApiKey { previous, .. } | Self::EnvSecret { previous, .. } => previous.as_ref(),
            _ => None,
        }
    }

    /// Whether this kind keeps a previous value at all.
    pub fn keeps_previous(&self) -> bool {
        matches!(self, Self::ApiKey { .. } | Self::EnvSecret { .. })
    }

    /// Replace the previous value. A no-op for kinds that do not keep one.
    pub fn set_previous(&mut self, value: Option<PreviousValue>) {
        if let Self::ApiKey { previous, .. } | Self::EnvSecret { previous, .. } = self {
            if let Some(old) = previous.as_mut() {
                old.zeroize();
            }
            *previous = value;
        }
    }

    /// Replace the primary secret. A no-op for kinds without one.
    pub fn set_primary_secret(&mut self, secret: String) {
        let slot = match self {
            Self::Login { password, .. } => password,
            Self::ApiKey { key, .. } => key,
            Self::EnvSecret { value, .. } => value,
            _ => return,
        };
        slot.zeroize();
        *slot = secret;
    }

    /// A copy with the previous value removed, for anything leaving the
    /// Rust process. Restoring happens here, so the webview never needs it.
    pub fn without_previous(&self) -> Self {
        let mut copy = self.clone();
        copy.set_previous(None);
        copy
    }

    /// Values Agent Guard should index for this item (spec §8).
    ///
    /// Only genuinely secret strings. Usernames and titles are excluded: they
    /// appear in ordinary text constantly and would make the guard useless.
    pub fn guard_values(&self) -> Vec<&str> {
        match self {
            Self::Login { password, .. } => vec![password.as_str()],
            Self::ApiKey { key, .. } => vec![key.as_str()],
            Self::EnvSecret { value, .. } => vec![value.as_str()],
            Self::Card { number, cvv, .. } => vec![number.as_str(), cvv.as_str()],
            // Note bodies are prose; indexing them whole would never match a
            // token anyway. Passkey private keys never appear as text.
            Self::SecureNote { .. } | Self::Passkey { .. } => vec![],
        }
    }
}

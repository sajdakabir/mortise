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
    /// Free-form tags.
    #[serde(default)]
    pub tags: Vec<String>,
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

    /// Values Agent Guard should index for this item (spec §8).
    ///
    /// Only genuinely secret strings. Usernames and titles are excluded: they
    /// appear in ordinary text constantly and would make the guard useless.
    pub fn guard_values(&self) -> Vec<&str> {
        match self {
            Self::Login { password, .. } => vec![password.as_str()],
            Self::ApiKey { key, .. } => vec![key.as_str()],
            Self::EnvSecret { value } => vec![value.as_str()],
            Self::Card { number, cvv, .. } => vec![number.as_str(), cvv.as_str()],
            // Note bodies are prose; indexing them whole would never match a
            // token anyway. Passkey private keys never appear as text.
            Self::SecureNote { .. } | Self::Passkey { .. } => vec![],
        }
    }
}

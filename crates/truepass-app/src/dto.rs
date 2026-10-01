//! Data transfer objects for the webview boundary.
//!
//! These exist so the IPC surface is explicit rather than incidental. The rule
//! this file enforces: **no key material crosses this boundary, ever**, and
//! secrets cross only in the one direction and one shape that [`crate::commands::reveal`]
//! defines.
//!
//! Ids become hex strings here because the webview has no use for byte arrays
//! and JSON would mangle them into number lists.

use serde::{Deserialize, Serialize};
use truepass_crypto::item::ItemId;
use truepass_vault::{ItemKind, ItemMeta, ItemSummary};

/// Render an item id for the webview.
pub fn id_to_hex(id: ItemId) -> String {
    id.as_bytes().iter().map(|b| format!("{b:02x}")).collect()
}

/// Parse an item id that came back from the webview.
pub fn id_from_hex(hex: &str) -> Option<ItemId> {
    if hex.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let s = core::str::from_utf8(chunk).ok()?;
        bytes[i] = u8::from_str_radix(s, 16).ok()?;
    }
    Some(ItemId::from_bytes(bytes))
}

fn kind_name(kind: ItemKind) -> &'static str {
    match kind {
        ItemKind::Login => "login",
        ItemKind::SecureNote => "note",
        ItemKind::Card => "card",
        ItemKind::ApiKey => "apikey",
        ItemKind::Passkey => "passkey",
        ItemKind::EnvSecret => "env",
    }
}

/// One row in the item list. Contains no secrets.
#[derive(Debug, Clone, Serialize)]
pub struct ItemRow {
    /// Hex item id.
    pub id: String,
    /// Kind slug, e.g. `login`.
    pub kind: &'static str,
    /// Display name.
    pub title: String,
    /// Username, if the item has one.
    pub username: Option<String>,
    /// Associated origins.
    pub urls: Vec<String>,
    /// Containing folder.
    pub folder: Option<String>,
    /// Tags.
    pub tags: Vec<String>,
    /// Last modified, milliseconds since the Unix epoch.
    pub updated_at_ms: u64,
}

impl From<ItemSummary> for ItemRow {
    fn from(s: ItemSummary) -> Self {
        Self {
            id: id_to_hex(s.id),
            kind: kind_name(s.kind),
            title: s.meta.title,
            username: s.meta.username,
            urls: s.meta.urls,
            folder: s.meta.folder,
            tags: s.meta.tags,
            updated_at_ms: s.updated_at_ms,
        }
    }
}

/// What the UI needs to decide which screen to show.
#[derive(Debug, Clone, Serialize)]
pub struct VaultStatus {
    /// Whether a vault file exists on this machine.
    pub exists: bool,
    /// Whether secrets are currently accessible.
    pub unlocked: bool,
    /// Whether search and listing are available (true after one unlock).
    pub searchable: bool,
    /// Live item count, available while locked.
    pub item_count: u32,
}

/// Returned once, on vault creation.
#[derive(Debug, Clone, Serialize)]
pub struct NewVault {
    /// The recovery kit string. Shown once and never retrievable again.
    pub recovery_kit: String,
}

/// Metadata as the webview sends it when saving.
#[derive(Debug, Clone, Deserialize)]
pub struct MetaInput {
    /// Display name.
    pub title: String,
    /// Associated origins.
    #[serde(default)]
    pub urls: Vec<String>,
    /// Username.
    #[serde(default)]
    pub username: Option<String>,
    /// Containing folder.
    #[serde(default)]
    pub folder: Option<String>,
    /// Tags.
    #[serde(default)]
    pub tags: Vec<String>,
}

impl From<MetaInput> for ItemMeta {
    fn from(m: MetaInput) -> Self {
        Self {
            title: m.title,
            urls: m
                .urls
                .into_iter()
                .filter(|u| !u.trim().is_empty())
                .collect(),
            username: m.username.filter(|u| !u.trim().is_empty()),
            folder: m.folder.filter(|f| !f.trim().is_empty()),
            tags: m
                .tags
                .into_iter()
                .filter(|t| !t.trim().is_empty())
                .collect(),
        }
    }
}

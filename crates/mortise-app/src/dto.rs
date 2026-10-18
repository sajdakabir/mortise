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
use mortise_crypto::item::ItemId;
use mortise_vault::{ItemKind, ItemMeta, ItemSummary};

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
    /// Project, for the developer-secrets workspace.
    pub project: Option<String>,
    /// Environment within that project.
    pub environment: Option<String>,
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
            project: s.meta.project,
            environment: s.meta.environment,
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
    /// Whether the account key is in the keychain, so only a password is needed.
    pub account_key_remembered: bool,
    /// Whether Touch ID unlock is set up.
    pub biometric_enabled: bool,
}

/// A login waiting to be saved. Carries no password.
#[derive(Debug, Clone, Serialize)]
pub struct CaptureSummary {
    /// Origin it was submitted on.
    pub origin: String,
    /// Username, if the page had one.
    pub username: Option<String>,
}

/// What an import did.
#[derive(Debug, Clone, Serialize)]
pub struct ImportReport {
    /// Exporter the file appeared to come from, for display.
    pub source: String,
    /// Items actually written to the vault.
    pub imported: u32,
    /// Rows already present, matched on name and username.
    pub duplicates: u32,
    /// Rows with nothing worth importing.
    pub empty: u32,
    /// Rows of a kind not supported yet, such as cards.
    pub unsupported: u32,
    /// Rows that parsed but could not be saved.
    pub failed: u32,
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
    /// Project this belongs to, for the developer-secrets layer.
    #[serde(default)]
    pub project: Option<String>,
    /// Environment within that project.
    #[serde(default)]
    pub environment: Option<String>,
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
            project: m.project.filter(|p| !p.trim().is_empty()),
            environment: m.environment.filter(|e| !e.trim().is_empty()),
            tags: m
                .tags
                .into_iter()
                .filter(|t| !t.trim().is_empty())
                .collect(),
        }
    }
}

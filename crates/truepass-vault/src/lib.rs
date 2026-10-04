//! # truepass-vault
//!
//! The local encrypted store. SQLite on disk, no network, no UI.
//!
//! This is the layer where item structure exists — `truepass-crypto` treats
//! payloads as opaque bytes on purpose, so the schema lives here.
//!
//! See [`docs/crypto-spec.md`](../../../docs/crypto-spec.md) §4 for the storage
//! design, and [`schema`] for why this does not use SQLCipher.

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::all)]

pub mod changelog;
pub mod enroll;
pub mod error;
pub mod items;
pub mod model;
pub mod origin;
pub mod schema;
pub mod vault;

pub use error::{Error, Result};
pub use items::ItemSummary;
pub use model::{ItemKind, ItemMeta, ItemPayload};
pub use origin::Origin;
pub use vault::{UnlockToken, Vault, VaultMeta};

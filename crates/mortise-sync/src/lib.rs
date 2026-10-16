//! Client side of sync.
//!
//! Moves signed, sealed changes between a local vault and a relay. It makes no
//! trust decisions of its own: every change it brings back goes through
//! [`mortise_vault::Vault::ingest`], which verifies signatures and membership
//! before anything is stored.
//!
//! That division matters. This crate talks to an untrusted server; the vault
//! decides what to believe.

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::all)]

pub mod error;
pub mod syncer;
pub mod transport;
pub mod wire;

pub use error::{Error, Result};
pub use syncer::{SyncOutcome, Syncer};
pub use transport::{HttpTransport, Transport};

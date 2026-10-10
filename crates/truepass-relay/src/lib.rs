//! A zero-knowledge sync relay.
//!
//! It stores signed ciphertext blobs and hands them back in order. It cannot
//! read any of them, and the design keeps it that way: there is no column in
//! the schema that could hold a title, a URL, or a password even if someone
//! wanted one there.
//!
//! What it unavoidably *does* learn is recorded against A1 in the threat model:
//! vault ids, device public keys, and therefore who syncs with whom, when, and
//! roughly how much. That is the cost of brokered sync, and it is stated rather
//! than papered over.

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::all)]

pub mod auth;
pub mod protocol;

#[cfg(feature = "server")]
pub mod server;
#[cfg(feature = "server")]
pub mod store;

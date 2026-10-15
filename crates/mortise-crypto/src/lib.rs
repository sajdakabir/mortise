//! # mortise-crypto
//!
//! The cryptographic core of TruePassword. This crate has **no** dependency on
//! Tauri, the UI, the filesystem, or the network, so it can be reviewed and
//! tested entirely in isolation.
//!
//! Its contract is [`docs/crypto-spec.md`](../../../docs/crypto-spec.md), which
//! traces to the adversaries in [`docs/threat-model.md`](../../../docs/threat-model.md).
//! Spec §9: no primitive, parameter, or encoding may appear here that is not in
//! that document. If something is needed, amend the spec first.
//!
//! ## Key hierarchy (spec §2)
//!
//! ```text
//! master password ──Argon2id──┐
//!                             ├──HKDF──> MUK ──> identity keys, DB key, guard key
//! account key ────────────────┘
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::all)]

pub mod acl;
pub mod aead;
pub mod change;
pub mod encode;
pub mod error;
pub mod generate;
pub mod guard;
pub mod identity;
pub mod item;
pub mod kdf;
pub mod rand;
pub mod recovery;
pub mod secret;
pub mod vault;

/// The ed25519 implementation this project uses.
///
/// Re-exported so dependants cannot accidentally pull a second, incompatible
/// copy into the graph — two versions would typecheck and then fail to verify
/// each other's signatures.
pub mod ed25519 {
    pub use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
}

pub use error::{Error, Result};
pub use secret::{Key32, Salt16, SecretBytes};

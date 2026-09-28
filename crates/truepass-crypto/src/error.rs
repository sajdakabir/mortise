//! Error type for the crypto core.
//!
//! Decryption and authentication failures collapse into a single opaque
//! [`Error::Decrypt`] on purpose. Distinguishing "wrong key" from "bad tag"
//! from "truncated input" would hand an attacker an oracle, so we do not.

/// Errors returned by this crate.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    /// Decryption or authentication failed. Deliberately carries no detail.
    #[error("decryption failed")]
    Decrypt,

    /// Encryption failed. Should only happen on absurd input sizes.
    #[error("encryption failed")]
    Encrypt,

    /// A key derivation step failed.
    #[error("key derivation failed")]
    Derive,

    /// Argon2 parameters were outside the algorithm's accepted range.
    #[error("invalid argon2 parameters")]
    Params,

    /// A byte slice was not the length its type requires.
    #[error("invalid length: expected {expected} bytes, got {got}")]
    Length {
        /// Bytes the type requires.
        expected: usize,
        /// Bytes actually supplied.
        got: usize,
    },

    /// A signature did not verify, or was malformed.
    #[error("signature verification failed")]
    Signature,

    /// A public or private key was malformed or not on the curve.
    #[error("invalid key")]
    InvalidKey,

    /// An item was sealed under a different key epoch than the vault key
    /// supplied. Not an attack: the caller needs the key for that epoch.
    #[error("epoch mismatch: item is at epoch {expected}, vault key is at {got}")]
    EpochMismatch {
        /// Epoch the item was sealed under.
        expected: u32,
        /// Epoch of the vault key supplied.
        got: u32,
    },

    /// An ACL entry was rejected. The reason is safe to surface: it reflects
    /// policy, not key material.
    #[error("acl entry rejected: {0}")]
    AclRejected(&'static str),

    /// The OS random number generator failed. Not recoverable; do not retry
    /// with a fallback PRNG.
    #[error("OS random number generator unavailable")]
    Rng,
}

/// Convenience alias.
pub type Result<T> = core::result::Result<T, Error>;

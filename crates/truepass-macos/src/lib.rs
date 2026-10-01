//! macOS keychain integration.
//!
//! **This is the only crate in the project that uses `unsafe`.** Everything
//! else is `forbid(unsafe_code)`, and the point of isolating the FFI here is
//! that a reviewer only has to read one small file carefully.
//!
//! The job is narrow: store a few bytes in the login keychain, optionally
//! behind a Touch ID prompt, and read them back.
//!
//! ## Why no LocalAuthentication
//!
//! The obvious approach — call `LAContext.evaluatePolicy`, and on success read
//! an unprotected keychain item — is weaker than it looks: the item is still
//! readable by anything that can skip the check. Instead the keychain item
//! itself carries a `SecAccessControl` requiring user presence, so the
//! *keychain* enforces it and raises the prompt during `SecItemCopyMatching`.
//! Nothing can read the bytes without passing that check.
//!
//! It also sidesteps biometric enrolment entirely: `kSecAccessControlUserPresence`
//! means "Touch ID, or the device passcode", so there is no availability check
//! to get wrong and no path where a user without Touch ID is locked out.

#![cfg_attr(not(target_os = "macos"), allow(unused))]
#![warn(missing_docs)]

mod error;

#[cfg(target_os = "macos")]
mod keychain;

pub use error::{Error, Result};

#[cfg(target_os = "macos")]
pub use keychain::{Protection, delete, exists, load, store};

/// Stubs for non-macOS builds, so the rest of the workspace still compiles.
///
/// v1 is macOS only; these exist so `cargo check` on another platform fails
/// with a clear runtime error rather than a wall of missing symbols.
#[cfg(not(target_os = "macos"))]
mod stub {
    use super::{Error, Result};
    use zeroize::Zeroizing;

    /// How a stored secret is protected.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Protection {
        /// Readable whenever the device is unlocked.
        DeviceUnlocked,
        /// Requires Touch ID or the device passcode on every read.
        UserPresence,
    }

    /// Unsupported off macOS.
    pub fn store(_: &str, _: &str, _: &[u8], _: Protection) -> Result<()> {
        Err(Error::Unsupported)
    }
    /// Unsupported off macOS.
    pub fn load(_: &str, _: &str, _: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        Err(Error::Unsupported)
    }
    /// Unsupported off macOS.
    pub fn delete(_: &str, _: &str) -> Result<()> {
        Err(Error::Unsupported)
    }
    /// Unsupported off macOS.
    pub fn exists(_: &str, _: &str) -> Result<bool> {
        Err(Error::Unsupported)
    }
}

#[cfg(not(target_os = "macos"))]
pub use stub::{Protection, delete, exists, load, store};

//! Keychain errors.

/// Errors from keychain access.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    /// The user dismissed the Touch ID or passcode prompt.
    ///
    /// Distinct from [`Error::AuthFailed`] because the UI should treat it as a
    /// shrug, not a failure — no error banner, just return to the lock screen.
    #[error("authentication was cancelled")]
    Cancelled,

    /// The user failed authentication.
    #[error("authentication failed")]
    AuthFailed,

    /// The item is protected by an access control this device cannot satisfy —
    /// typically a Mac with no passcode set at all.
    #[error("this device cannot satisfy the required authentication")]
    NotAvailable,

    /// The process lacks the entitlement needed for access-controlled items.
    ///
    /// `errSecMissingEntitlement`. Creating a keychain item with a
    /// `SecAccessControl` requires a **code-signed** binary carrying the
    /// `keychain-access-groups` entitlement. Plain `cargo run` and `cargo test`
    /// binaries are not signed, so Touch ID protection is unavailable there
    /// while unprotected items work fine.
    ///
    /// This is a build-configuration problem, not a user problem, and the UI
    /// should say so rather than blaming the Mac.
    #[error("this build is not signed, so Touch ID protection is unavailable")]
    RequiresSignedApp,

    /// The keychain refused the operation for some other reason.
    #[error("keychain error (OSStatus {0})")]
    Os(i32),

    /// Keychain access is not available on this platform.
    #[error("keychain access is only available on macOS")]
    Unsupported,
}

/// Convenience alias.
pub type Result<T> = core::result::Result<T, Error>;

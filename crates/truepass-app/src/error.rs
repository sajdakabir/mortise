//! The error shape the webview sees.
//!
//! Every error carries a stable machine-readable `code` so the UI can branch on
//! it without string matching, and a message safe to display.
//!
//! Vault errors are mapped deliberately, not forwarded wholesale: internal
//! detail about why a decryption failed is exactly what should not reach a
//! webview that hostile page content can observe.

use serde::Serialize;

/// An error returned from a Tauri command.
#[derive(Debug, Clone, Serialize)]
pub struct CmdError {
    /// Stable machine-readable code.
    pub code: &'static str,
    /// Human-readable message, safe to display.
    pub message: String,
}

impl CmdError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// No vault exists yet.
    pub fn no_vault() -> Self {
        Self::new("no_vault", "No vault on this machine yet.")
    }

    /// Something the UI should not have asked for in this state.
    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self::new("bad_request", msg)
    }
}

impl From<truepass_vault::Error> for CmdError {
    fn from(e: truepass_vault::Error) -> Self {
        use truepass_vault::Error as E;
        match e {
            E::WrongCredentials => Self::new(
                "wrong_credentials",
                "Incorrect master password or recovery key.",
            ),
            E::Locked => Self::new("locked", "The vault is locked."),
            E::ItemNotFound => Self::new("not_found", "That item no longer exists."),
            E::SchemaTooNew { .. } => Self::new(
                "schema_too_new",
                "This vault was created by a newer version of TruePassword.",
            ),
            // Everything below is either a bug or a damaged file. The UI gets a
            // generic message; the detail goes to the log, not the webview.
            other => {
                eprintln!("truepass: internal error: {other}");
                Self::new("internal", "Something went wrong.")
            }
        }
    }
}

impl From<truepass_crypto::Error> for CmdError {
    fn from(e: truepass_crypto::Error) -> Self {
        eprintln!("truepass: crypto error: {e}");
        Self::new("internal", "Something went wrong.")
    }
}

impl From<truepass_macos::Error> for CmdError {
    fn from(e: truepass_macos::Error) -> Self {
        use truepass_macos::Error as E;
        match e {
            // Not a failure as far as the user is concerned — they dismissed a
            // prompt. The UI should quietly return to the lock screen.
            E::Cancelled => Self::new("cancelled", "Authentication was cancelled."),
            E::AuthFailed => Self::new("auth_failed", "Authentication failed."),
            E::RequiresSignedApp => Self::new(
                "requires_signed_app",
                "Touch ID needs a signed build of TruePassword. It is unavailable in this development build.",
            ),
            E::NotAvailable => Self::new(
                "biometrics_unavailable",
                "This Mac cannot use Touch ID or a device passcode for this.",
            ),
            other => {
                eprintln!("truepass: keychain error: {other}");
                Self::new("internal", "Could not reach the keychain.")
            }
        }
    }
}

/// Command result alias.
pub type CmdResult<T> = Result<T, CmdError>;

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

    /// A vault file is present but could not be opened.
    pub fn vault_unopenable(reason: impl Into<String>) -> Self {
        Self::new(
            "vault_unopenable",
            format!(
                "The vault is on this Mac but will not open: {}",
                reason.into()
            ),
        )
    }

    /// Something the UI should not have asked for in this state.
    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self::new("bad_request", msg)
    }
}

impl From<mortise_vault::Error> for CmdError {
    fn from(e: mortise_vault::Error) -> Self {
        use mortise_vault::Error as E;
        match e {
            E::WrongCredentials => Self::new(
                "wrong_credentials",
                "Incorrect master password or recovery key.",
            ),
            E::Locked => Self::new("locked", "The vault is locked."),
            E::ItemNotFound => Self::new("not_found", "That item no longer exists."),
            E::SchemaTooNew { .. } => Self::new(
                "schema_too_new",
                "This vault was created by a newer version of Mortise.",
            ),
            // Written to be read by a person: "a project with that name
            // already exists" is the whole answer, and replacing it with
            // "something went wrong" leaves someone retyping the same name.
            E::Invalid(message) => Self::new("invalid", message),
            // Everything below is either a bug or a damaged file. The UI gets a
            // generic message; the detail goes to the log, not the webview.
            other => {
                eprintln!("mortise: internal error: {other}");
                Self::new("internal", "Something went wrong.")
            }
        }
    }
}

impl From<mortise_crypto::Error> for CmdError {
    fn from(e: mortise_crypto::Error) -> Self {
        eprintln!("mortise: crypto error: {e}");
        Self::new("internal", "Something went wrong.")
    }
}

impl From<mortise_macos::Error> for CmdError {
    fn from(e: mortise_macos::Error) -> Self {
        use mortise_macos::Error as E;
        match e {
            // Not a failure as far as the user is concerned — they dismissed a
            // prompt. The UI should quietly return to the lock screen.
            E::Cancelled => Self::new("cancelled", "Authentication was cancelled."),
            E::AuthFailed => Self::new("auth_failed", "Authentication failed."),
            E::RequiresSignedApp => Self::new(
                "requires_signed_app",
                "Touch ID needs a signed build of Mortise. It is unavailable in this development build.",
            ),
            E::NotAvailable => Self::new(
                "biometrics_unavailable",
                "This Mac cannot use Touch ID or a device passcode for this.",
            ),
            other => {
                eprintln!("mortise: keychain error: {other}");
                Self::new("internal", "Could not reach the keychain.")
            }
        }
    }
}

impl From<mortise_vault::import::Error> for CmdError {
    fn from(e: mortise_vault::import::Error) -> Self {
        use mortise_vault::import::Error as E;
        // These describe the user's own file, not anything secret, and the
        // detail is what makes the problem fixable. The messages deliberately
        // never quote a row: the rows are credentials.
        let code = match e {
            E::NotCsv => "not_csv",
            E::NoRecognisedColumns => "no_columns",
            E::NoRows => "no_rows",
        };
        Self::new(code, e.to_string())
    }
}

impl From<crate::browser::native_host::Error> for CmdError {
    fn from(e: crate::browser::native_host::Error) -> Self {
        use crate::browser::native_host::Error as E;
        // Unlike the vault errors above, every one of these is about the user's
        // own machine rather than about a secret, so the detail is safe to show
        // and is the only thing that makes the failure fixable.
        let code = match e {
            E::BadExtensionId => "bad_extension_id",
            E::NoBrowsers => "no_browsers",
            E::ProxyMissing(_) => "proxy_missing",
            E::Io(_) => "host_write_failed",
        };
        Self::new(code, e.to_string())
    }
}

/// Command result alias.
pub type CmdResult<T> = Result<T, CmdError>;

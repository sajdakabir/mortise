//! Sync errors.

/// Why a sync did not complete.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The relay could not be reached.
    #[error("could not reach the relay: {0}")]
    Unreachable(String),

    /// The relay refused the request.
    ///
    /// Carries the relay's own code so the UI can distinguish "this device is
    /// not authorized" from "the server is broken".
    #[error("relay refused the request ({code}): {message}")]
    Refused {
        /// Relay error code.
        code: String,
        /// Relay message.
        message: String,
    },

    /// The relay sent something unparseable. Treated as a server fault rather
    /// than retried, since retrying will not make it parse.
    #[error("relay sent a response this client does not understand")]
    BadResponse,

    /// This vault id is already registered to different devices.
    #[error("that vault is already registered on the relay")]
    AlreadyClaimed,

    /// The local vault refused something.
    #[error(transparent)]
    Vault(#[from] mortise_vault::Error),

    /// A cryptographic operation failed.
    #[error(transparent)]
    Crypto(#[from] mortise_crypto::Error),

    /// Serialization failed.
    #[error(transparent)]
    Serde(#[from] serde_json::Error),
}

/// Convenience alias.
pub type Result<T> = core::result::Result<T, Error>;

//! Online account metadata, separate from local vault encryption.
#![forbid(unsafe_code)]

#[cfg(feature = "server")]
mod database;

#[cfg(feature = "client")]
pub mod client;
#[cfg(feature = "oidc")]
pub mod oidc;
pub mod protocol;
#[cfg(feature = "server")]
pub mod server;
#[cfg(feature = "server")]
pub mod store;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Sign in again to continue.")]
    Unauthorized,
    #[error("Approve this device from an already trusted device first.")]
    Untrusted,
    #[error("You do not have permission for this action.")]
    Forbidden,
    #[error("{0}")]
    Invalid(&'static str),
    #[error("{0}")]
    Conflict(&'static str),
    #[error("Account service is temporarily unavailable.")]
    Unavailable,
    #[error("Account storage failed.")]
    Storage,
}
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(feature = "server")]
impl From<rusqlite::Error> for Error {
    fn from(_: rusqlite::Error) -> Self {
        Self::Storage
    }
}

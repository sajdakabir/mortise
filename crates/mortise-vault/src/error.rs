//! Error type for the local store.

/// Errors returned by this crate.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The master password or account key was wrong.
    ///
    /// Reported as one error on purpose: telling a caller which half failed
    /// would help an attacker who holds only one of them.
    #[error("incorrect master password or account key")]
    WrongCredentials,

    /// The operation needs the vault unlocked.
    #[error("vault is locked")]
    Locked,

    /// No item with that id.
    #[error("item not found")]
    ItemNotFound,

    /// The database was written by a newer build of the app.
    #[error("vault schema is version {found}, this build understands {supported}")]
    SchemaTooNew {
        /// Version found in the file.
        found: u32,
        /// Newest version this build can open.
        supported: u32,
    },

    /// The file is not a TruePassword vault, or is corrupt beyond a key problem.
    #[error("vault file is corrupt or not a TruePassword vault: {0}")]
    Corrupt(&'static str),

    /// A cryptographic operation failed.
    #[error(transparent)]
    Crypto(#[from] mortise_crypto::Error),

    /// SQLite failed.
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),

    /// Item payload serialization failed.
    #[error(transparent)]
    Serde(#[from] serde_json::Error),
}

/// Convenience alias.
pub type Result<T> = core::result::Result<T, Error>;

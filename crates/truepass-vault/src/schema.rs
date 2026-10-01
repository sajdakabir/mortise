//! SQLite schema and migrations.
//!
//! # Why not SQLCipher
//!
//! Spec §4 called for SQLCipher over the whole file. On macOS that means either
//! vendoring OpenSSL into the binary or requiring every developer to have brew's
//! OpenSSL at build time — and it adds a second crypto stack to audit, against
//! an explicit "keep it light" product goal.
//!
//! What SQLCipher actually buys is metadata-at-rest encryption. We get that by
//! encrypting the metadata ourselves with the XChaCha20-Poly1305 path already
//! audited in `truepass-crypto`, so nothing sensitive is in a plaintext column.
//!
//! What we give up, honestly: the whole file is not opaque. An attacker with the
//! file at rest learns the row count, the table shape, and blob sizes. They do
//! not learn titles, URLs, usernames, or any secret. Row counts and sizes are a
//! real but minor leak, and it is recorded in the threat model.
//!
//! The two layers compose, so this does not foreclose anything: adding
//! SQLCipher later is one extra `PRAGMA key` and changes no schema. It becomes
//! optional defence-in-depth rather than the thing holding the roof up.

use rusqlite::Connection;

use crate::error::{Error, Result};

/// Schema version this build writes and understands.
pub const SCHEMA_VERSION: u32 = 1;

const SCHEMA_V1: &str = r#"
-- One row. Everything needed to attempt an unlock.
CREATE TABLE vault_meta (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    vault_id        BLOB    NOT NULL,
    salt            BLOB    NOT NULL,
    argon2_m_kib    INTEGER NOT NULL,
    argon2_t        INTEGER NOT NULL,
    argon2_p        INTEGER NOT NULL,
    epoch           INTEGER NOT NULL,
    schema_version  INTEGER NOT NULL,
    created_at_ms   INTEGER NOT NULL
) STRICT;

-- The account identity keypair, sealed under the MUK.
CREATE TABLE identity (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    public_key  BLOB NOT NULL,
    wrapped     BLOB NOT NULL
) STRICT;

-- This machine's keypairs, sealed under the MUK.
CREATE TABLE device (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    device_id   BLOB NOT NULL,
    wrapped     BLOB NOT NULL
) STRICT;

-- Vault keys, HPKE-sealed to this device. Old epochs are retained: items
-- sealed before a rotation still need their epoch's key to open.
CREATE TABLE vault_key (
    epoch   INTEGER PRIMARY KEY,
    wrapped BLOB NOT NULL
) STRICT;

-- Items. Nothing here is plaintext except ids, counters and timestamps.
--
-- sealed_meta is encrypted under the VAULT key, so it syncs and shared-vault
-- members can read it. search_cache is encrypted under the account META key,
-- so it stays readable while the vault is locked and never leaves this machine.
CREATE TABLE item (
    item_id         BLOB    PRIMARY KEY,
    version         INTEGER NOT NULL,
    epoch           INTEGER NOT NULL,
    kind            INTEGER NOT NULL,
    sealed_meta     BLOB    NOT NULL,
    sealed_item_key BLOB    NOT NULL,
    ciphertext      BLOB    NOT NULL,
    created_at_ms   INTEGER NOT NULL,
    updated_at_ms   INTEGER NOT NULL,
    deleted         INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE INDEX item_updated ON item (updated_at_ms);
CREATE INDEX item_kind ON item (kind, deleted);

-- Local search cache, encrypted under the account META key. Derived data:
-- safe to drop and rebuild from sealed_meta on the next unlock.
CREATE TABLE search_cache (
    item_id BLOB PRIMARY KEY REFERENCES item (item_id) ON DELETE CASCADE,
    sealed  BLOB NOT NULL
) STRICT;
"#;

/// Apply the schema to a fresh database.
pub fn initialize(conn: &Connection) -> Result<()> {
    conn.execute_batch(SCHEMA_V1)?;
    Ok(())
}

/// Connection pragmas. Applied on every open, not just creation.
pub fn apply_pragmas(conn: &Connection) -> Result<()> {
    // WAL for crash safety and concurrent reads; NORMAL is the right sync level
    // under WAL. foreign_keys is off by default in SQLite and we rely on the
    // search_cache cascade.
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.pragma_update(None, "foreign_keys", true)?;
    Ok(())
}

/// Check the file's schema version against this build.
///
/// A newer version is refused rather than guessed at: opening a file we do not
/// understand and writing to it is how data gets destroyed.
pub fn check_version(conn: &Connection) -> Result<()> {
    let found: u32 = conn
        .query_row(
            "SELECT schema_version FROM vault_meta WHERE id = 1",
            [],
            |r| r.get(0),
        )
        .map_err(|_| Error::Corrupt("vault_meta row is missing"))?;

    if found > SCHEMA_VERSION {
        return Err(Error::SchemaTooNew {
            found,
            supported: SCHEMA_VERSION,
        });
    }
    Ok(())
}

/// Whether the file has already been initialized.
pub fn is_initialized(conn: &Connection) -> Result<bool> {
    let count: u32 = conn.query_row(
        "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'vault_meta'",
        [],
        |r| r.get(0),
    )?;
    Ok(count == 1)
}

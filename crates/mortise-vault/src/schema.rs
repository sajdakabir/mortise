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
//! audited in `mortise-crypto`, so nothing sensitive is in a plaintext column.
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
pub const SCHEMA_VERSION: u32 = 4;

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

/// Added in v2: the signed change log, and the DAG state sync needs.
const SCHEMA_V2: &str = r#"
-- Every mutation, signed by the device that made it. This is the source of
-- truth; the item table is a materialized view of it.
--
-- payload is sealed under the vault key, so the relay cannot even see which
-- item a change touches. That costs the ability to materialize while locked —
-- changes pulled during a locked session sit here until the next unlock.
CREATE TABLE change_log (
    id           BLOB    PRIMARY KEY,
    vault_id     BLOB    NOT NULL,
    epoch        INTEGER NOT NULL,
    hlc_wall     INTEGER NOT NULL,
    hlc_counter  INTEGER NOT NULL,
    author       BLOB    NOT NULL,
    payload      BLOB    NOT NULL,
    signature    BLOB    NOT NULL,
    received_at  INTEGER NOT NULL,
    -- 0 until the relay has acknowledged it.
    pushed       INTEGER NOT NULL DEFAULT 0,
    -- 0 until it has been folded into the item table.
    applied      INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE INDEX change_unpushed ON change_log (pushed, hlc_wall);
CREATE INDEX change_unapplied ON change_log (applied, hlc_wall, hlc_counter);

-- Parent edges. A change may have several, which is what makes the log a DAG
-- rather than a line and lets two offline devices merge without a server.
CREATE TABLE change_parent (
    change_id BLOB NOT NULL,
    parent_id BLOB NOT NULL,
    PRIMARY KEY (change_id, parent_id)
) STRICT;

-- Current DAG tips. The next local change takes all of these as its parents.
CREATE TABLE dag_head (
    change_id BLOB PRIMARY KEY
) STRICT;

-- The device's hybrid logical clock, persisted so it survives a restart.
-- Losing it would let a change be issued with a timestamp below one already
-- written, which is exactly what the HLC exists to prevent.
CREATE TABLE sync_state (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    hlc_wall    INTEGER NOT NULL,
    hlc_counter INTEGER NOT NULL
) STRICT;

INSERT INTO sync_state (id, hlc_wall, hlc_counter) VALUES (1, 0, 0);

-- Which change currently owns each item, for last-write-wins. Without this a
-- change that arrives late could overwrite a newer one simply by being applied
-- second.
ALTER TABLE item ADD COLUMN lww_wall    INTEGER NOT NULL DEFAULT 0;
ALTER TABLE item ADD COLUMN lww_counter INTEGER NOT NULL DEFAULT 0;
ALTER TABLE item ADD COLUMN lww_author  BLOB    NOT NULL DEFAULT x'';

-- Signing keys of devices whose changes we accept. Seeded with this device;
-- sharing adds the others from the ACL.
CREATE TABLE known_device (
    device_id   BLOB PRIMARY KEY,
    signing_key BLOB NOT NULL
) STRICT;
"#;

/// Added in v3: where sync left off.
const SCHEMA_V3: &str = r#"
-- The relay's sequence number we have pulled up to. Stored with the vault
-- rather than in app settings: it is only meaningful alongside this change
-- log, and a cursor that outlived its database would skip changes silently.
ALTER TABLE sync_state ADD COLUMN cursor INTEGER NOT NULL DEFAULT 0;

-- Which relay this vault syncs with. Empty means sync is off.
ALTER TABLE sync_state ADD COLUMN relay_url TEXT NOT NULL DEFAULT '';
"#;

/// Added in v4: the access control log.
const SCHEMA_V4: &str = r#"
-- ACL entries, in order. Unlike the change log this is a strict sequence, not
-- a DAG: concurrent membership edits cannot be merged safely, so the second of
-- two is rejected and must be reissued (see mortise_crypto::acl).
CREATE TABLE acl_log (
    seq          INTEGER PRIMARY KEY,
    id           BLOB    NOT NULL UNIQUE,
    prev         BLOB    NOT NULL,
    op_kind      INTEGER NOT NULL,
    op_body      BLOB    NOT NULL,
    author       BLOB    NOT NULL,
    issued_at_ms INTEGER NOT NULL,
    signature    BLOB    NOT NULL,
    -- 0 until the relay has it, same as the change log.
    pushed       INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE INDEX acl_unpushed ON acl_log (pushed, seq);
"#;

/// Apply the schema to a fresh database.
pub fn initialize(conn: &Connection) -> Result<()> {
    conn.execute_batch(SCHEMA_V1)?;
    conn.execute_batch(SCHEMA_V2)?;
    conn.execute_batch(SCHEMA_V3)?;
    conn.execute_batch(SCHEMA_V4)?;
    Ok(())
}

/// Bring an older vault up to the current schema.
///
/// Runs inside a transaction: a migration that fails halfway and leaves the
/// file in neither version is how a vault becomes unopenable.
pub fn migrate(conn: &Connection) -> Result<()> {
    let found: u32 = conn
        .query_row(
            "SELECT schema_version FROM vault_meta WHERE id = 1",
            [],
            |r| r.get(0),
        )
        .map_err(|_| Error::Corrupt("vault_meta row is missing"))?;

    if found >= SCHEMA_VERSION {
        return Ok(());
    }

    let tx = conn.unchecked_transaction()?;
    if found < 2 {
        tx.execute_batch(SCHEMA_V2)?;
    }
    if found < 3 {
        tx.execute_batch(SCHEMA_V3)?;
    }
    if found < 4 {
        tx.execute_batch(SCHEMA_V4)?;
    }
    tx.execute(
        "UPDATE vault_meta SET schema_version = ?1 WHERE id = 1",
        [SCHEMA_VERSION],
    )?;
    tx.commit()?;
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

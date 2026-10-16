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
pub const SCHEMA_VERSION: u32 = 5;

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
    conn.execute_batch(SCHEMA_V5)?;
    Ok(())
}

/// Added in v5: more than one vault per file.
///
/// `vault_meta` conflated two things that have different cardinality. The salt
/// and Argon2 parameters derive the master unlock key and so are per *account*
/// — one per file, forever. The vault id and epoch describe one *vault*, and a
/// file now holds several: your own, plus a vault for each project shared with
/// you. Splitting them is what makes the rest of this possible.
///
/// `vault_key` is rebuilt rather than altered because its primary key changes:
/// two vaults may each be at epoch 0, so the epoch alone no longer identifies
/// a key. `item` and `acl_log` only gain a column, so they are altered in
/// place and backfilled to the one vault that existed.
const SCHEMA_V5: &str = r#"
-- Per account. One row, forever.
CREATE TABLE IF NOT EXISTS account (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    salt            BLOB    NOT NULL,
    argon2_m_kib    INTEGER NOT NULL,
    argon2_t        INTEGER NOT NULL,
    argon2_p        INTEGER NOT NULL,
    schema_version  INTEGER NOT NULL,
    created_at_ms   INTEGER NOT NULL
) STRICT;

-- Per vault. Your own, and one per project.
CREATE TABLE IF NOT EXISTS vault (
    vault_id      BLOB    PRIMARY KEY,
    name          TEXT    NOT NULL,
    -- 0 personal, 1 project. The personal vault cannot be shared or deleted,
    -- which is a property of the vault rather than of its contents.
    kind          INTEGER NOT NULL DEFAULT 0,
    epoch         INTEGER NOT NULL,
    created_at_ms INTEGER NOT NULL
) STRICT;

INSERT OR IGNORE INTO account (id, salt, argon2_m_kib, argon2_t, argon2_p, schema_version, created_at_ms)
    SELECT 1, salt, argon2_m_kib, argon2_t, argon2_p, schema_version, created_at_ms
    FROM vault_meta WHERE id = 1;

INSERT OR IGNORE INTO vault (vault_id, name, kind, epoch, created_at_ms)
    SELECT vault_id, 'Personal', 0, epoch, created_at_ms
    FROM vault_meta WHERE id = 1;

-- Rebuilt: the primary key gains the vault.
CREATE TABLE vault_key_v5 (
    vault_id BLOB    NOT NULL,
    epoch    INTEGER NOT NULL,
    wrapped  BLOB    NOT NULL,
    PRIMARY KEY (vault_id, epoch)
) STRICT;

INSERT INTO vault_key_v5 (vault_id, epoch, wrapped)
    SELECT (SELECT vault_id FROM vault LIMIT 1), epoch, wrapped FROM vault_key;

DROP TABLE vault_key;
ALTER TABLE vault_key_v5 RENAME TO vault_key;

-- Altered in place. The empty default is immediately backfilled; SQLite will
-- not add a NOT NULL column without one.
ALTER TABLE item ADD COLUMN vault_id BLOB NOT NULL DEFAULT x'';
UPDATE item SET vault_id = (SELECT vault_id FROM vault LIMIT 1);
CREATE INDEX item_vault ON item (vault_id, deleted);

-- seq stays globally unique rather than restarting per vault: each vault's
-- entries are a subsequence of it, which is enough to order them, and it
-- avoids rebuilding the table.
ALTER TABLE acl_log ADD COLUMN vault_id BLOB NOT NULL DEFAULT x'';
UPDATE acl_log SET vault_id = (SELECT vault_id FROM vault LIMIT 1);
CREATE INDEX acl_vault ON acl_log (vault_id, seq);

-- The relay cursor is per vault: each syncs independently and at its own
-- rate. The clock and the relay URL stay on sync_state, which is per device.
CREATE TABLE IF NOT EXISTS vault_sync (
    vault_id BLOB    PRIMARY KEY,
    cursor   INTEGER NOT NULL DEFAULT 0
) STRICT;

INSERT OR IGNORE INTO vault_sync (vault_id, cursor)
    SELECT vault_id, (SELECT cursor FROM sync_state WHERE id = 1) FROM vault;

DROP TABLE IF EXISTS vault_meta;
"#;

/// The file's schema version, from whichever table holds it.
///
/// v5 moved it out of `vault_meta` and into `account`. Both have to be
/// readable here: the old one to decide whether to migrate at all, the new one
/// on every open afterwards.
fn read_version(conn: &Connection) -> Result<u32> {
    for sql in [
        "SELECT schema_version FROM account WHERE id = 1",
        "SELECT schema_version FROM vault_meta WHERE id = 1",
    ] {
        if let Ok(v) = conn.query_row(sql, [], |r| r.get::<_, u32>(0)) {
            return Ok(v);
        }
    }
    Err(Error::Corrupt("no schema version row"))
}

/// Bring an older vault up to the current schema.
///
/// Runs inside a transaction: a migration that fails halfway and leaves the
/// file in neither version is how a vault becomes unopenable.
pub fn migrate(conn: &Connection) -> Result<()> {
    let found = read_version(conn)?;

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
    if found < 5 {
        tx.execute_batch(SCHEMA_V5)?;
    }
    // After v5 the version lives on `account`; vault_meta no longer exists.
    tx.execute(
        "UPDATE account SET schema_version = ?1 WHERE id = 1",
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
    let found = read_version(conn)?;

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
        "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name IN ('vault_meta', 'account')",
        [],
        |r| r.get(0),
    )?;
    Ok(count == 1)
}

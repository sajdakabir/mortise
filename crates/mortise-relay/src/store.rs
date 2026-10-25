//! Relay storage.
//!
//! Everything here is either opaque ciphertext or the minimum metadata needed
//! to order and deduplicate it. There is deliberately no column that could hold
//! a title, a URL, or anything else a subpoena would find interesting.

use std::sync::{Arc, Mutex};

use rusqlite::{Connection, OptionalExtension, params};

use crate::protocol::{WireAclEntry, WireChange, WireKey};

const SCHEMA: &str = r#"
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS vault (
    vault_id      TEXT PRIMARY KEY,
    created_at_ms INTEGER NOT NULL
) STRICT;

-- The per-vault device allowlist. This is how the relay authenticates without
-- accounts, and it is also the social graph it unavoidably learns.
CREATE TABLE IF NOT EXISTS vault_device (
    vault_id    TEXT NOT NULL REFERENCES vault (vault_id) ON DELETE CASCADE,
    device_id   TEXT NOT NULL,
    signing_key TEXT NOT NULL,
    added_at_ms INTEGER NOT NULL,
    PRIMARY KEY (vault_id, device_id)
) STRICT;

-- Changes, stored verbatim. `seq` gives clients a cursor; the relay never
-- looks inside `body` beyond having been handed it.
CREATE TABLE IF NOT EXISTS change_blob (
    seq          INTEGER PRIMARY KEY AUTOINCREMENT,
    vault_id     TEXT NOT NULL REFERENCES vault (vault_id) ON DELETE CASCADE,
    change_id    TEXT NOT NULL,
    body         TEXT NOT NULL,
    stored_at_ms INTEGER NOT NULL,
    UNIQUE (vault_id, change_id)
) STRICT;

CREATE INDEX IF NOT EXISTS change_pull ON change_blob (vault_id, seq);

-- ACL entries, stored verbatim and ordered by their own sequence number. Like
-- change_blob, the relay never looks inside: it cannot read roles or validate
-- authority, so clients verify every entry on apply.
CREATE TABLE IF NOT EXISTS acl_entry (
    vault_id     TEXT    NOT NULL REFERENCES vault (vault_id) ON DELETE CASCADE,
    seq          INTEGER NOT NULL,
    body         TEXT    NOT NULL,
    stored_at_ms INTEGER NOT NULL,
    PRIMARY KEY (vault_id, seq)
) STRICT;

-- Vault keys re-wrapped for a specific device after a rotation, waiting for
-- that device to collect them. The body is an opaque sealed blob; one row per
-- (vault, recipient, epoch), replaced if re-sent.
CREATE TABLE IF NOT EXISTS wrapped_key (
    vault_id            TEXT    NOT NULL REFERENCES vault (vault_id) ON DELETE CASCADE,
    recipient_device_id TEXT    NOT NULL,
    epoch               INTEGER NOT NULL,
    body                TEXT    NOT NULL,
    stored_at_ms        INTEGER NOT NULL,
    PRIMARY KEY (vault_id, recipient_device_id, epoch)
) STRICT;
"#;

/// Handle to the relay's database.
///
/// A single connection behind a mutex. Honest about what it is: correct, and
/// fine up to the point where it is not. Swapping in a pool is a contained
/// change if this ever carries real traffic.
#[derive(Clone)]
pub struct Store {
    conn: Arc<Mutex<Connection>>,
}

/// What a push did.
#[derive(Debug, Clone, Copy, Default)]
pub struct StoreReport {
    /// Newly stored.
    pub accepted: u32,
    /// Already present.
    pub duplicates: u32,
}

impl Store {
    /// Open or create the database at `path`, or in memory for `:memory:`.
    pub fn open(path: &str) -> rusqlite::Result<Self> {
        let conn = if path == ":memory:" {
            Connection::open_in_memory()?
        } else {
            Connection::open(path)?
        };
        conn.execute_batch(SCHEMA)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    fn with<T>(&self, f: impl FnOnce(&Connection) -> rusqlite::Result<T>) -> rusqlite::Result<T> {
        let guard = match self.conn.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        f(&guard)
    }

    /// Register a vault and its first device. Fails if already claimed.
    pub fn claim(
        &self,
        vault_id: &str,
        device_id: &str,
        signing_key: &str,
        now_ms: i64,
    ) -> rusqlite::Result<bool> {
        self.with(|conn| {
            let tx = conn.unchecked_transaction()?;
            let existing: Option<String> = tx
                .query_row(
                    "SELECT vault_id FROM vault WHERE vault_id = ?1",
                    params![vault_id],
                    |r| r.get(0),
                )
                .optional()?;
            if existing.is_some() {
                return Ok(false);
            }

            tx.execute(
                "INSERT INTO vault (vault_id, created_at_ms) VALUES (?1, ?2)",
                params![vault_id, now_ms],
            )?;
            tx.execute(
                "INSERT INTO vault_device (vault_id, device_id, signing_key, added_at_ms)
                 VALUES (?1, ?2, ?3, ?4)",
                params![vault_id, device_id, signing_key, now_ms],
            )?;
            tx.commit()?;
            Ok(true)
        })
    }

    /// A device's signing key for this vault, if it is allowed to sync it.
    pub fn signing_key(&self, vault_id: &str, device_id: &str) -> rusqlite::Result<Option<String>> {
        self.with(|conn| {
            conn.query_row(
                "SELECT signing_key FROM vault_device WHERE vault_id = ?1 AND device_id = ?2",
                params![vault_id, device_id],
                |r| r.get(0),
            )
            .optional()
        })
    }

    /// Authorize another device.
    pub fn add_device(
        &self,
        vault_id: &str,
        device_id: &str,
        signing_key: &str,
        now_ms: i64,
    ) -> rusqlite::Result<()> {
        self.with(|conn| {
            conn.execute(
                "INSERT INTO vault_device (vault_id, device_id, signing_key, added_at_ms)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT (vault_id, device_id) DO UPDATE SET signing_key = ?3",
                params![vault_id, device_id, signing_key, now_ms],
            )?;
            Ok(())
        })
    }

    /// Revoke a device's access.
    pub fn remove_device(&self, vault_id: &str, device_id: &str) -> rusqlite::Result<()> {
        self.with(|conn| {
            conn.execute(
                "DELETE FROM vault_device WHERE vault_id = ?1 AND device_id = ?2",
                params![vault_id, device_id],
            )?;
            Ok(())
        })
    }

    /// Devices allowed to sync this vault.
    pub fn devices(&self, vault_id: &str) -> rusqlite::Result<Vec<(String, String)>> {
        self.with(|conn| {
            let mut stmt = conn.prepare(
                "SELECT device_id, signing_key FROM vault_device WHERE vault_id = ?1
                 ORDER BY device_id",
            )?;
            let rows = stmt.query_map(params![vault_id], |r| Ok((r.get(0)?, r.get(1)?)))?;
            rows.collect()
        })
    }

    /// Store changes, ignoring ones already held.
    pub fn push(
        &self,
        vault_id: &str,
        changes: &[WireChange],
        now_ms: i64,
    ) -> rusqlite::Result<(StoreReport, u64)> {
        self.with(|conn| {
            let tx = conn.unchecked_transaction()?;
            let mut report = StoreReport::default();

            for change in changes {
                let body = serde_json::to_string(change).unwrap_or_default();
                let inserted = tx.execute(
                    "INSERT OR IGNORE INTO change_blob
                       (vault_id, change_id, body, stored_at_ms)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![vault_id, change.id, body, now_ms],
                )?;
                if inserted > 0 {
                    report.accepted += 1;
                } else {
                    report.duplicates += 1;
                }
            }

            // SQLite integers are i64; seq is an AUTOINCREMENT rowid so it is
            // never negative, but the cast is explicit rather than implied.
            let cursor: i64 = tx
                .query_row(
                    "SELECT COALESCE(MAX(seq), 0) FROM change_blob WHERE vault_id = ?1",
                    params![vault_id],
                    |r| r.get(0),
                )
                .unwrap_or(0);
            let cursor = cursor.max(0) as u64;

            tx.commit()?;
            Ok((report, cursor))
        })
    }

    /// Changes after `after`, up to `limit`.
    pub fn pull(
        &self,
        vault_id: &str,
        after: u64,
        limit: u32,
    ) -> rusqlite::Result<(Vec<WireChange>, u64, bool)> {
        self.with(|conn| {
            let mut stmt = conn.prepare(
                "SELECT seq, body FROM change_blob
                 WHERE vault_id = ?1 AND seq > ?2
                 ORDER BY seq LIMIT ?3",
            )?;
            let rows = stmt
                .query_map(params![vault_id, after as i64, i64::from(limit) + 1], |r| {
                    Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
                })?;

            let mut out = Vec::new();
            let mut cursor = after;
            for row in rows {
                let (seq, body) = row?;
                let seq = seq.max(0) as u64;
                if out.len() as u32 == limit {
                    // The extra row only tells us more exist.
                    return Ok((out, cursor, true));
                }
                if let Ok(change) = serde_json::from_str(&body) {
                    out.push(change);
                }
                cursor = seq;
            }
            Ok((out, cursor, false))
        })
    }

    /// Store ACL entries, ignoring ones already held at that sequence number.
    pub fn push_acl(
        &self,
        vault_id: &str,
        entries: &[WireAclEntry],
        now_ms: i64,
    ) -> rusqlite::Result<u32> {
        self.with(|conn| {
            let tx = conn.unchecked_transaction()?;
            let mut accepted = 0;
            for entry in entries {
                let body = serde_json::to_string(entry).unwrap_or_default();
                let inserted = tx.execute(
                    "INSERT OR IGNORE INTO acl_entry (vault_id, seq, body, stored_at_ms)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![vault_id, entry.seq as i64, body, now_ms],
                )?;
                accepted += inserted as u32;
            }
            tx.commit()?;
            Ok(accepted)
        })
    }

    /// ACL entries after sequence `after`, up to `limit`, in order.
    pub fn pull_acl(
        &self,
        vault_id: &str,
        after: u64,
        limit: u32,
    ) -> rusqlite::Result<(Vec<WireAclEntry>, bool)> {
        self.with(|conn| {
            let mut stmt = conn.prepare(
                "SELECT body FROM acl_entry
                 WHERE vault_id = ?1 AND seq > ?2
                 ORDER BY seq LIMIT ?3",
            )?;
            let rows = stmt.query_map(
                params![vault_id, after as i64, i64::from(limit) + 1],
                |r| r.get::<_, String>(0),
            )?;

            let mut out = Vec::new();
            let mut more = false;
            for row in rows {
                if out.len() as u32 == limit {
                    more = true;
                    break;
                }
                if let Ok(entry) = serde_json::from_str(&row?) {
                    out.push(entry);
                }
            }
            Ok((out, more))
        })
    }

    /// Store re-wrapped keys, replacing any for the same recipient and epoch.
    pub fn push_keys(
        &self,
        vault_id: &str,
        keys: &[WireKey],
        now_ms: i64,
    ) -> rusqlite::Result<u32> {
        self.with(|conn| {
            let tx = conn.unchecked_transaction()?;
            let mut accepted = 0;
            for key in keys {
                tx.execute(
                    "INSERT INTO wrapped_key
                       (vault_id, recipient_device_id, epoch, body, stored_at_ms)
                     VALUES (?1, ?2, ?3, ?4, ?5)
                     ON CONFLICT (vault_id, recipient_device_id, epoch)
                       DO UPDATE SET body = ?4, stored_at_ms = ?5",
                    params![vault_id, key.recipient_device_id, key.epoch, key.body, now_ms],
                )?;
                accepted += 1;
            }
            tx.commit()?;
            Ok(accepted)
        })
    }

    /// Keys addressed to `recipient_device_id`, newest epoch last.
    pub fn pull_keys(
        &self,
        vault_id: &str,
        recipient_device_id: &str,
    ) -> rusqlite::Result<Vec<WireKey>> {
        self.with(|conn| {
            let mut stmt = conn.prepare(
                "SELECT epoch, body FROM wrapped_key
                 WHERE vault_id = ?1 AND recipient_device_id = ?2
                 ORDER BY epoch",
            )?;
            let rows = stmt.query_map(params![vault_id, recipient_device_id], |r| {
                Ok(WireKey {
                    recipient_device_id: recipient_device_id.to_string(),
                    epoch: r.get::<_, u32>(0)?,
                    body: r.get::<_, String>(1)?,
                })
            })?;
            rows.collect()
        })
    }
}

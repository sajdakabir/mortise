//! Relay storage.
//!
//! Everything here is either opaque ciphertext or the minimum metadata needed
//! to order and deduplicate it. There is deliberately no column that could hold
//! a title, a URL, or anything else a subpoena would find interesting.

use std::sync::{Arc, Mutex};

use rusqlite::{Connection, OptionalExtension, params};

use crate::protocol::{WireAclEntry, WireChange, WireWrappedKey};

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

-- ACL entries, verbatim. Unlike changes these form one linear log, so the
-- client's own sequence number is the key and the relay's cursor both.
--
-- First writer wins. Two devices that both believe they are issuing seq 9 is a
-- fork, and the relay cannot adjudicate it — it cannot read the entries, let
-- alone the roles inside them. Refusing the second one keeps the stored log
-- consistent for everyone pulling it, and the loser re-issues at the next free
-- sequence number once it has pulled what it was missing.
CREATE TABLE IF NOT EXISTS acl_blob (
    vault_id     TEXT NOT NULL REFERENCES vault (vault_id) ON DELETE CASCADE,
    seq          INTEGER NOT NULL,
    body         TEXT NOT NULL,
    stored_at_ms INTEGER NOT NULL,
    PRIMARY KEY (vault_id, seq)
) STRICT;

-- Vault keys, each sealed to exactly one device. The relay cannot open them;
-- it only needs to know who to hand each one to.
--
-- Addressed storage rather than a broadcast, because a wrapped key is useful
-- to precisely one recipient and handing every member every blob would tell
-- the relay nothing it does not already know while wasting everyone's pulls.
CREATE TABLE IF NOT EXISTS key_blob (
    vault_id     TEXT NOT NULL REFERENCES vault (vault_id) ON DELETE CASCADE,
    recipient    TEXT NOT NULL,
    epoch        INTEGER NOT NULL,
    body         TEXT NOT NULL,
    stored_at_ms INTEGER NOT NULL,
    PRIMARY KEY (vault_id, recipient, epoch)
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

    /// Store ACL entries. An entry at a sequence number already held is left
    /// alone and counted as a duplicate.
    pub fn push_acl(
        &self,
        vault_id: &str,
        entries: &[WireAclEntry],
        now_ms: i64,
    ) -> rusqlite::Result<StoreReport> {
        self.with(|conn| {
            let tx = conn.unchecked_transaction()?;
            let mut report = StoreReport::default();
            for entry in entries {
                let body = serde_json::to_string(entry).unwrap_or_default();
                let inserted = tx.execute(
                    "INSERT OR IGNORE INTO acl_blob (vault_id, seq, body, stored_at_ms)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![vault_id, entry.seq as i64, body, now_ms],
                )?;
                if inserted > 0 {
                    report.accepted += 1;
                } else {
                    report.duplicates += 1;
                }
            }
            tx.commit()?;
            Ok(report)
        })
    }

    /// ACL entries after `after`, in order, up to `limit`.
    pub fn pull_acl(
        &self,
        vault_id: &str,
        after: u64,
        limit: u32,
    ) -> rusqlite::Result<(Vec<WireAclEntry>, bool)> {
        self.with(|conn| {
            let mut stmt = conn.prepare(
                "SELECT body FROM acl_blob WHERE vault_id = ?1 AND seq > ?2
                 ORDER BY seq LIMIT ?3",
            )?;
            let rows = stmt.query_map(
                params![vault_id, after as i64, i64::from(limit) + 1],
                |r| r.get::<_, String>(0),
            )?;

            let mut out = Vec::new();
            for row in rows {
                if out.len() as u32 == limit {
                    return Ok((out, true));
                }
                if let Ok(entry) = serde_json::from_str(&row?) {
                    out.push(entry);
                }
            }
            Ok((out, false))
        })
    }

    /// Store wrapped vault keys, each addressed to one device.
    ///
    /// A key already held for that recipient and epoch is left alone. Letting
    /// a later push overwrite one would hand a hostile member a way to replace
    /// a key a recipient has not collected yet.
    pub fn push_keys(
        &self,
        vault_id: &str,
        keys: &[WireWrappedKey],
        now_ms: i64,
    ) -> rusqlite::Result<StoreReport> {
        self.with(|conn| {
            let tx = conn.unchecked_transaction()?;
            let mut report = StoreReport::default();
            for key in keys {
                let body = serde_json::to_string(key).unwrap_or_default();
                let inserted = tx.execute(
                    "INSERT OR IGNORE INTO key_blob
                       (vault_id, recipient, epoch, body, stored_at_ms)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![vault_id, key.recipient, key.epoch, body, now_ms],
                )?;
                if inserted > 0 {
                    report.accepted += 1;
                } else {
                    report.duplicates += 1;
                }
            }
            tx.commit()?;
            Ok(report)
        })
    }

    /// Keys addressed to one device, oldest epoch first.
    pub fn keys_for(
        &self,
        vault_id: &str,
        recipient: &str,
    ) -> rusqlite::Result<Vec<WireWrappedKey>> {
        self.with(|conn| {
            let mut stmt = conn.prepare(
                "SELECT body FROM key_blob WHERE vault_id = ?1 AND recipient = ?2
                 ORDER BY epoch",
            )?;
            let rows =
                stmt.query_map(params![vault_id, recipient], |r| r.get::<_, String>(0))?;

            let mut out = Vec::new();
            for row in rows {
                if let Ok(key) = serde_json::from_str(&row?) {
                    out.push(key);
                }
            }
            Ok(out)
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
}

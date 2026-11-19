//! A record of what the command line was given, and to whom.
//!
//! One sealed row per decision: approved, refused, or timed out. Values are
//! never recorded — key names, the requesting process and the outcome are
//! what someone reviewing access needs, and all they get.
//!
//! Sealed under the META key, so it is readable while locked (after the
//! first unlock), the same as search. Capped at [`MAX_ENTRIES`]; the oldest
//! go first. Local only: it is not part of the change log and does not sync,
//! because which commands ran on this Mac is nobody else's business.

use rusqlite::params;
use serde::{Deserialize, Serialize};

use mortise_crypto::aead;

use crate::error::Result;
use crate::vault::{Vault, now_ms};

/// Most entries kept.
pub const MAX_ENTRIES: u32 = 1000;

/// What happened to a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Approved for this request only.
    AllowedOnce,
    /// Approved, and a directory grant was made.
    AllowedForDirectory,
    /// Served under an existing directory grant.
    ServedByGrant,
    /// An agent session was started.
    SessionStarted,
    /// Served under an agent session.
    ServedBySession,
    /// The user said no.
    Denied,
    /// Nobody answered.
    TimedOut,
    /// Refused before asking: unknown project, missing keys, locked, busy.
    Refused,
}

/// One logged request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessEvent {
    /// When, in Unix milliseconds. Filled in on write.
    #[serde(default)]
    pub at_ms: u64,
    /// Project as requested or resolved.
    pub project: String,
    /// Environment as requested or resolved.
    pub environment: String,
    /// Key names, or `None` for the whole environment. Never values.
    pub keys: Option<Vec<String>>,
    /// The command the caller said it would run.
    pub command: String,
    /// Working directory, from the kernel.
    pub directory: String,
    /// Requesting process and its ancestors, from the kernel.
    pub process_chain: Vec<String>,
    /// What happened.
    pub outcome: Outcome,
    /// Why, for refusals.
    pub detail: Option<String>,
}

fn entry_aad(id: &[u8]) -> Vec<u8> {
    let mut aad = b"mortise/access-log/v1".to_vec();
    aad.extend_from_slice(id);
    aad
}

impl Vault {
    /// Append an event, dropping the oldest beyond [`MAX_ENTRIES`].
    pub fn record_access(&self, event: &AccessEvent) -> Result<()> {
        let key = self.meta_key()?;
        let id = mortise_crypto::rand::bytes::<16>()?;
        let at_ms = now_ms();
        let mut event = event.clone();
        event.at_ms = at_ms;
        let sealed = aead::seal(key, &serde_json::to_vec(&event)?, &entry_aad(&id))?;

        let tx = self.conn().unchecked_transaction()?;
        tx.execute(
            "INSERT INTO access_log (entry_id, at_ms, sealed) VALUES (?1, ?2, ?3)",
            params![id.as_slice(), at_ms as i64, sealed],
        )?;
        tx.execute(
            "DELETE FROM access_log WHERE entry_id NOT IN (
                 SELECT entry_id FROM access_log ORDER BY at_ms DESC, rowid DESC LIMIT ?1)",
            params![MAX_ENTRIES],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Up to `limit` events, newest first.
    pub fn access_log(&self, limit: u32) -> Result<Vec<AccessEvent>> {
        let key = self.meta_key()?;
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT entry_id, sealed FROM access_log ORDER BY at_ms DESC, rowid DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit], |r| {
            Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (id, sealed) = row?;
            let plain = aead::open(key, &sealed, &entry_aad(&id))?;
            out.push(serde_json::from_slice(&plain)?);
        }
        Ok(out)
    }
}

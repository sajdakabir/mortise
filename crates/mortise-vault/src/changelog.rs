//! The signed change log: spec §5.
//!
//! Every mutation becomes an immutable, signed change before it touches the
//! item table. The item table is a **materialized view** of this log, not the
//! other way round — which is what makes sync possible without a rewrite later.
//!
//! # Item-level last-write-wins
//!
//! The spec says LWW *per field*. This implements it per *item*, which is a
//! deliberate amendment.
//!
//! Per-field merging would require sealing each field separately, so that two
//! devices editing different fields of one item could both win. For a password
//! manager that case is rare — concurrent edits land on different items far
//! more often than on different fields of the same item — and the cost is a
//! much larger ciphertext layout plus per-field metadata the relay could count.
//!
//! Nothing is lost either way: the losing change stays in the log, so a future
//! history view can show it. Losing data would not be an acceptable trade; a
//! coarser merge granularity is.
//!
//! # Why payloads are sealed again
//!
//! A change's payload is the mutation, sealed under the vault key — even though
//! the item ciphertext inside it is already encrypted. The outer seal hides
//! *which item* a change touches, so the relay cannot watch one item's update
//! frequency or correlate changes across devices.
//!
//! The cost is that changes cannot be materialized while locked. Changes pulled
//! during a locked session sit in the log until the next unlock.

use mortise_crypto::aead;
use mortise_crypto::change::{Change, ChangeId, Hlc, UnsignedChange};
use mortise_crypto::identity::DeviceId;
use mortise_crypto::item::{ITEM_ID_LEN, ItemId};
use mortise_crypto::vault::{Epoch, VaultId};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::vault::{Vault, now_ms};

/// What one change does.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Mutation {
    /// Create or replace an item.
    Upsert(ItemRecord),
    /// Remove an item.
    Delete {
        /// Which item.
        item_id: [u8; ITEM_ID_LEN],
        /// When, for display only — ordering uses the HLC.
        at_ms: u64,
    },
}

/// An item as it travels in the log. Mirrors the `item` table's row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemRecord {
    /// Item identifier.
    pub item_id: [u8; ITEM_ID_LEN],
    /// Revision number.
    pub version: u32,
    /// Key epoch it was sealed under.
    pub epoch: u32,
    /// Item kind discriminant.
    pub kind: u8,
    /// Metadata, sealed under the vault key.
    pub sealed_meta: Vec<u8>,
    /// Item key, wrapped under the vault key.
    pub sealed_item_key: Vec<u8>,
    /// Payload ciphertext.
    pub ciphertext: Vec<u8>,
    /// Creation time.
    pub created_at_ms: u64,
    /// Last modification time.
    pub updated_at_ms: u64,
}

/// What [`Vault::ingest`] did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IngestReport {
    /// Changes stored for the first time.
    pub accepted: u32,
    /// Changes already present. Normal: sync is not exactly-once.
    pub duplicates: u32,
    /// Changes refused — bad signature, unknown author, or wrong vault.
    pub rejected: u32,
}

fn seal_aad(vault: VaultId, epoch: Epoch) -> Vec<u8> {
    let mut aad = Vec::with_capacity(16 + 4 + 7);
    aad.extend_from_slice(vault.as_bytes());
    aad.extend_from_slice(&epoch.value().to_be_bytes());
    aad.extend_from_slice(b"/change");
    aad
}

impl Vault {
    /// Append a signed change for `mutation` and return its id.
    pub(crate) fn record_mutation(&mut self, mutation: &Mutation) -> Result<ChangeId> {
        let vault_id = self.meta().vault_id;
        let key = self.current_vault_key()?;
        let epoch = key.epoch();

        let plaintext = Zeroizing::new(serde_json::to_vec(mutation)?);
        let payload = aead::seal(key.key(), &plaintext, &seal_aad(vault_id, epoch))?;

        let hlc = self.tick_clock()?;
        let parents = self.heads()?;
        let device = self.device()?;

        let change =
            UnsignedChange::new(vault_id, epoch, parents, hlc, device.id(), payload).sign(device);

        self.store_change(&change, true)?;
        Ok(change.id())
    }

    /// Store a change and make it the sole DAG head.
    ///
    /// `local` marks it as not yet pushed. Ingested changes are already on the
    /// relay, so they do not need pushing back.
    fn store_change(&self, change: &Change, local: bool) -> Result<()> {
        let tx = self.conn().unchecked_transaction()?;

        tx.execute(
            "INSERT OR IGNORE INTO change_log
               (id, vault_id, epoch, hlc_wall, hlc_counter, author, payload,
                signature, received_at, pushed, applied)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 0)",
            params![
                change.id().as_bytes().as_slice(),
                change.vault().as_bytes().as_slice(),
                change.epoch().value(),
                change.hlc().wall_ms as i64,
                change.hlc().counter,
                change.author().as_bytes().as_slice(),
                change.payload(),
                change.signature().as_slice(),
                now_ms() as i64,
                if local { 0 } else { 1 },
            ],
        )?;

        for parent in change.parents() {
            tx.execute(
                "INSERT OR IGNORE INTO change_parent (change_id, parent_id) VALUES (?1, ?2)",
                params![
                    change.id().as_bytes().as_slice(),
                    parent.as_bytes().as_slice()
                ],
            )?;
            // A referenced change is no longer a tip.
            tx.execute(
                "DELETE FROM dag_head WHERE change_id = ?1",
                params![parent.as_bytes().as_slice()],
            )?;
        }

        tx.execute(
            "INSERT OR IGNORE INTO dag_head (change_id) VALUES (?1)",
            params![change.id().as_bytes().as_slice()],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Current DAG tips. The next local change takes all of these as parents.
    pub fn heads(&self) -> Result<Vec<ChangeId>> {
        let conn = self.conn();
        let mut stmt = conn.prepare("SELECT change_id FROM dag_head")?;
        let rows = stmt.query_map([], |r| r.get::<_, Vec<u8>>(0))?;

        let mut out = Vec::new();
        for row in rows {
            let bytes: [u8; 32] = row?
                .try_into()
                .map_err(|_| Error::Corrupt("change id is the wrong length"))?;
            out.push(ChangeId::from_bytes(bytes));
        }
        Ok(out)
    }

    /// Advance and persist the hybrid logical clock.
    ///
    /// Persisted because losing it across a restart would let a change be
    /// issued with a timestamp below one already written — the exact ordering
    /// failure the HLC exists to prevent.
    fn tick_clock(&self) -> Result<Hlc> {
        let (wall, counter): (i64, u32) = self.conn().query_row(
            "SELECT hlc_wall, hlc_counter FROM sync_state WHERE id = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;

        let next = Hlc {
            wall_ms: wall as u64,
            counter,
        }
        .tick(now_ms());

        self.conn().execute(
            "UPDATE sync_state SET hlc_wall = ?1, hlc_counter = ?2 WHERE id = 1",
            params![next.wall_ms as i64, next.counter],
        )?;
        Ok(next)
    }

    /// Merge a remote clock into the local one.
    fn merge_clock(&self, remote: Hlc) -> Result<()> {
        let (wall, counter): (i64, u32) = self.conn().query_row(
            "SELECT hlc_wall, hlc_counter FROM sync_state WHERE id = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;

        let merged = Hlc {
            wall_ms: wall as u64,
            counter,
        }
        .merge(remote, now_ms());

        self.conn().execute(
            "UPDATE sync_state SET hlc_wall = ?1, hlc_counter = ?2 WHERE id = 1",
            params![merged.wall_ms as i64, merged.counter],
        )?;
        Ok(())
    }

    /// The relay sequence number this vault has pulled up to.
    pub fn sync_cursor(&self) -> Result<u64> {
        let cursor: i64 =
            self.conn()
                .query_row("SELECT cursor FROM sync_state WHERE id = 1", [], |r| {
                    r.get(0)
                })?;
        Ok(cursor.max(0) as u64)
    }

    /// Record how far sync has pulled.
    ///
    /// Never moves backwards. A relay that replayed an old cursor could
    /// otherwise make this device re-pull and re-ingest indefinitely.
    pub fn set_sync_cursor(&self, cursor: u64) -> Result<()> {
        self.conn().execute(
            "UPDATE sync_state SET cursor = MAX(cursor, ?1) WHERE id = 1",
            params![cursor as i64],
        )?;
        Ok(())
    }

    /// The relay this vault syncs with, if any.
    pub fn relay_url(&self) -> Result<Option<String>> {
        let url: String =
            self.conn()
                .query_row("SELECT relay_url FROM sync_state WHERE id = 1", [], |r| {
                    r.get(0)
                })?;
        Ok(if url.is_empty() { None } else { Some(url) })
    }

    /// Set or clear the relay. Clearing turns sync off without deleting the log.
    pub fn set_relay_url(&self, url: Option<&str>) -> Result<()> {
        self.conn().execute(
            "UPDATE sync_state SET relay_url = ?1 WHERE id = 1",
            params![url.unwrap_or("")],
        )?;
        Ok(())
    }

    /// Register a device whose changes this vault will accept.
    ///
    /// The X25519 `kex_key` is stored too, so a vault key sealed by this device
    /// (an admin re-wrapping after a rotation) can be authenticated when it
    /// arrives over the relay — including the genesis owner, whom the ACL log
    /// does not otherwise name with a device key.
    pub fn trust_device(
        &self,
        device: DeviceId,
        signing_key: &[u8; 32],
        kex_key: &[u8; 32],
    ) -> Result<()> {
        self.conn().execute(
            "INSERT INTO known_device (device_id, signing_key, kex_key) VALUES (?1, ?2, ?3)
             ON CONFLICT (device_id) DO UPDATE SET signing_key = ?2, kex_key = ?3",
            params![
                device.as_bytes().as_slice(),
                signing_key.as_slice(),
                kex_key.as_slice()
            ],
        )?;
        Ok(())
    }

    fn signing_key_of(&self, device: DeviceId) -> Result<Option<[u8; 32]>> {
        let found: Option<Vec<u8>> = self
            .conn()
            .query_row(
                "SELECT signing_key FROM known_device WHERE device_id = ?1",
                params![device.as_bytes().as_slice()],
                |r| r.get(0),
            )
            .optional()?;

        Ok(match found {
            Some(bytes) => Some(
                bytes
                    .try_into()
                    .map_err(|_| Error::Corrupt("signing key is the wrong length"))?,
            ),
            None => None,
        })
    }

    /// Accept changes from a peer.
    ///
    /// Each is verified before it is stored, and anything that fails is dropped
    /// rather than quarantined: a change we cannot verify is a change we will
    /// never apply, so keeping it only grows the file.
    ///
    /// Does not require the vault to be unlocked — verification is signature
    /// work, not decryption. Applying them does.
    pub fn ingest(&mut self, changes: &[Change]) -> Result<IngestReport> {
        let vault_id = self.meta().vault_id;
        let mut report = IngestReport::default();
        // Ids accepted in this batch, so a change can be parented on one that
        // arrived alongside it rather than only on one already stored.
        let mut accepted: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();

        for change in changes {
            if change.vault() != vault_id {
                report.rejected += 1;
                continue;
            }
            let Some(key) = self.signing_key_of(change.author())? else {
                // An author we do not trust. Not necessarily hostile — it may
                // be a device added to the ACL since our last sync — but we
                // cannot accept it until we learn its key.
                report.rejected += 1;
                continue;
            };
            if change.verify(&key).is_err() {
                report.rejected += 1;
                continue;
            }
            // The role check. The relay cannot do this — roles live in an
            // encrypted log it cannot read — so a viewer could push changes the
            // relay happily stores. Refusing them here is the only thing that
            // makes a read-only role mean anything.
            //
            // Checks the author's *current* role, not their role when the
            // change was made. Demoting someone therefore stops their future
            // changes while leaving already-applied ones in place, which is the
            // practical reading of a demotion.
            if !self.may_write(change.author())? {
                report.rejected += 1;
                continue;
            }
            if self.has_change(change.id())? {
                report.duplicates += 1;
                continue;
            }
            // Every parent must be one we already hold. This is the check
            // `change.rs` names as the third of the three that make a hostile
            // relay unable to reorder history, and it was the one not
            // implemented — so a relay could drop a single change and serve
            // its descendants, and they applied cleanly with nothing to
            // notice the hole. Rejecting here keeps the cursor behind the gap,
            // so the missing ancestor is re-pulled rather than lost.
            let mut parents_known = true;
            for parent in change.parents() {
                if !accepted.contains(parent.as_bytes()) && !self.has_change(*parent)? {
                    parents_known = false;
                    break;
                }
            }
            if !parents_known {
                report.rejected += 1;
                continue;
            }

            accepted.insert(*change.id().as_bytes());
            self.store_change(change, false)?;
            self.merge_clock(change.hlc())?;
            report.accepted += 1;
        }

        Ok(report)
    }

    /// Whether this change is already stored.
    pub fn has_change(&self, id: ChangeId) -> Result<bool> {
        let count: u32 = self.conn().query_row(
            "SELECT count(*) FROM change_log WHERE id = ?1",
            params![id.as_bytes().as_slice()],
            |r| r.get(0),
        )?;
        Ok(count > 0)
    }

    /// Changes not yet acknowledged by the relay, oldest first.
    pub fn unpushed_changes(&self, limit: u32) -> Result<Vec<Change>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT id, vault_id, epoch, hlc_wall, hlc_counter, author, payload, signature
             FROM change_log WHERE pushed = 0
             ORDER BY hlc_wall, hlc_counter LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit], |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, u32>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, u32>(4)?,
                r.get::<_, Vec<u8>>(5)?,
                r.get::<_, Vec<u8>>(6)?,
                r.get::<_, Vec<u8>>(7)?,
            ))
        })?;

        let mut out = Vec::new();
        for row in rows {
            let (id, vault, epoch, wall, counter, author, payload, signature) = row?;
            out.push(
                self.rebuild_change(id, vault, epoch, wall, counter, author, payload, signature)?,
            );
        }
        Ok(out)
    }

    #[allow(clippy::too_many_arguments)]
    fn rebuild_change(
        &self,
        id: Vec<u8>,
        vault: Vec<u8>,
        epoch: u32,
        wall: i64,
        counter: u32,
        author: Vec<u8>,
        payload: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<Change> {
        let bad = |_| Error::Corrupt("change row has a malformed field");

        let id_bytes: [u8; 32] = id.clone().try_into().map_err(bad)?;
        let vault_bytes: [u8; 16] = vault.try_into().map_err(bad)?;
        let author_bytes: [u8; 16] = author.try_into().map_err(bad)?;
        let sig_bytes: [u8; 64] = signature.try_into().map_err(bad)?;

        let parents = self.parents_of(&id)?;
        let unsigned = UnsignedChange::new(
            VaultId::from_bytes(vault_bytes),
            Epoch(epoch),
            parents,
            Hlc {
                wall_ms: wall as u64,
                counter,
            },
            DeviceId::from_bytes(author_bytes),
            payload,
        );

        Ok(Change::from_parts(
            unsigned,
            ChangeId::from_bytes(id_bytes),
            sig_bytes,
        ))
    }

    fn parents_of(&self, change_id: &[u8]) -> Result<Vec<ChangeId>> {
        let conn = self.conn();
        let mut stmt = conn.prepare("SELECT parent_id FROM change_parent WHERE change_id = ?1")?;
        let rows = stmt.query_map(params![change_id], |r| r.get::<_, Vec<u8>>(0))?;

        let mut out = Vec::new();
        for row in rows {
            let bytes: [u8; 32] = row?
                .try_into()
                .map_err(|_| Error::Corrupt("parent id is the wrong length"))?;
            out.push(ChangeId::from_bytes(bytes));
        }
        Ok(out)
    }

    /// Mark changes as acknowledged by the relay.
    pub fn mark_pushed(&mut self, ids: &[ChangeId]) -> Result<()> {
        let tx = self.conn().unchecked_transaction()?;
        for id in ids {
            tx.execute(
                "UPDATE change_log SET pushed = 1 WHERE id = ?1",
                params![id.as_bytes().as_slice()],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Fold unapplied changes into the item table.
    ///
    /// Requires unlock: payloads are sealed under the vault key.
    ///
    /// Applies in HLC order, and skips any change the target item has already
    /// moved past. Ordering alone is not enough — a change pulled late can have
    /// a lower HLC than one already applied, and without the per-item check it
    /// would overwrite newer data simply by arriving second.
    pub fn apply_pending(&mut self) -> Result<u32> {
        // Checked up front so "locked" cannot be mistaken for "nothing to do".
        // Without this the per-change key lookup below swallows the lock error
        // as a missing epoch, and the caller gets a silent Ok(0) having applied
        // nothing — the worst possible answer, because it looks like success.
        if !self.is_unlocked() {
            return Err(Error::Locked);
        }

        let vault_id = self.meta().vault_id;
        let pending = self.unapplied_changes()?;
        let mut applied = 0;

        for (id, epoch, hlc, author, payload) in pending {
            let Ok(key) = self.vault_key_at(Epoch(epoch)) else {
                // Sealed under an epoch whose key this device does not hold.
                // Left unapplied so a later enrolment or rotation can bring it
                // in. Distinct from being locked, which was rejected above.
                continue;
            };
            let plaintext = match aead::open(key.key(), &payload, &seal_aad(vault_id, Epoch(epoch)))
            {
                Ok(p) => p,
                Err(_) => {
                    self.mark_applied(&id)?;
                    continue;
                }
            };

            let mutation: Mutation = serde_json::from_slice(&plaintext)?;
            self.materialize(&mutation, hlc, author)?;
            self.mark_applied(&id)?;
            applied += 1;
        }

        Ok(applied)
    }

    #[allow(clippy::type_complexity)]
    fn unapplied_changes(&self) -> Result<Vec<(Vec<u8>, u32, Hlc, DeviceId, Vec<u8>)>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT id, epoch, hlc_wall, hlc_counter, author, payload
             FROM change_log WHERE applied = 0 ORDER BY hlc_wall, hlc_counter",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, u32>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, u32>(3)?,
                r.get::<_, Vec<u8>>(4)?,
                r.get::<_, Vec<u8>>(5)?,
            ))
        })?;

        let mut out = Vec::new();
        for row in rows {
            let (id, epoch, wall, counter, author, payload) = row?;
            let author_bytes: [u8; 16] = author
                .try_into()
                .map_err(|_| Error::Corrupt("author id is the wrong length"))?;
            out.push((
                id,
                epoch,
                Hlc {
                    wall_ms: wall as u64,
                    counter,
                },
                DeviceId::from_bytes(author_bytes),
                payload,
            ));
        }
        Ok(out)
    }

    fn mark_applied(&self, id: &[u8]) -> Result<()> {
        self.conn().execute(
            "UPDATE change_log SET applied = 1 WHERE id = ?1",
            params![id],
        )?;
        Ok(())
    }

    /// Whether `incoming` beats what the item already has.
    ///
    /// Device id breaks HLC ties, so two devices independently resolving the
    /// same conflict always pick the same winner.
    fn wins(&self, item_id: &[u8], incoming: Hlc, author: DeviceId) -> Result<bool> {
        let current: Option<(i64, u32, Vec<u8>)> = self
            .conn()
            .query_row(
                "SELECT lww_wall, lww_counter, lww_author FROM item WHERE item_id = ?1",
                params![item_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;

        Ok(match current {
            None => true,
            Some((wall, counter, existing_author)) => {
                let existing = Hlc {
                    wall_ms: wall as u64,
                    counter,
                };
                (incoming, author.as_bytes().as_slice()) > (existing, existing_author.as_slice())
            }
        })
    }

    fn materialize(&self, mutation: &Mutation, hlc: Hlc, author: DeviceId) -> Result<()> {
        match mutation {
            Mutation::Upsert(record) => {
                if !self.wins(&record.item_id, hlc, author)? {
                    return Ok(());
                }
                self.conn().execute(
                    "INSERT INTO item
                       (item_id, version, epoch, kind, sealed_meta, sealed_item_key,
                        ciphertext, created_at_ms, updated_at_ms, deleted,
                        lww_wall, lww_counter, lww_author)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 0, ?10, ?11, ?12)
                     ON CONFLICT (item_id) DO UPDATE SET
                       version = ?2, epoch = ?3, kind = ?4, sealed_meta = ?5,
                       sealed_item_key = ?6, ciphertext = ?7, updated_at_ms = ?9,
                       deleted = 0, lww_wall = ?10, lww_counter = ?11, lww_author = ?12",
                    params![
                        record.item_id.as_slice(),
                        record.version,
                        record.epoch,
                        record.kind,
                        record.sealed_meta,
                        record.sealed_item_key,
                        record.ciphertext,
                        record.created_at_ms as i64,
                        record.updated_at_ms as i64,
                        hlc.wall_ms as i64,
                        hlc.counter,
                        author.as_bytes().as_slice(),
                    ],
                )?;
                self.refresh_cache_for(ItemId::from_bytes(record.item_id))?;
            }

            Mutation::Delete { item_id, at_ms } => {
                if !self.wins(item_id, hlc, author)? {
                    return Ok(());
                }
                let tx = self.conn().unchecked_transaction()?;
                // A tombstone, not a bare UPDATE.
                //
                // An UPDATE matches nothing when this device has never seen
                // the item, so no watermark was written — and `wins` treats a
                // missing row as "incoming always wins". A later Upsert for
                // the same id, which the relay chooses when to deliver, would
                // then reinstate a secret the user deleted, live and
                // decryptable. The row has to exist for the delete to be
                // remembered; list, search and find_for_origin all filter
                // deleted = 0, so it stays invisible.
                tx.execute(
                    "INSERT INTO item
                       (item_id, version, epoch, kind, sealed_meta, sealed_item_key,
                        ciphertext, created_at_ms, updated_at_ms, deleted,
                        lww_wall, lww_counter, lww_author)
                     VALUES (?1, 0, 0, 0, x'', x'', x'', ?2, ?2, 1, ?3, ?4, ?5)
                     ON CONFLICT (item_id) DO UPDATE SET
                       deleted = 1, sealed_meta = x'', sealed_item_key = x'',
                       ciphertext = x'', updated_at_ms = ?2,
                       lww_wall = ?3, lww_counter = ?4, lww_author = ?5",
                    params![
                        item_id.as_slice(),
                        *at_ms as i64,
                        hlc.wall_ms as i64,
                        hlc.counter,
                        author.as_bytes().as_slice(),
                    ],
                )?;
                tx.execute(
                    "DELETE FROM search_cache WHERE item_id = ?1",
                    params![item_id.as_slice()],
                )?;
                tx.commit()?;
            }
        }
        Ok(())
    }
}

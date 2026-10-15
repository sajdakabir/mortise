//! Item CRUD and search.
//!
//! Three encrypted blobs per item, with three different jobs:
//!
//! | Blob | Key | Why |
//! |---|---|---|
//! | `ciphertext` + `sealed_item_key` | item key, under the vault key | the secret; decrypted one item at a time |
//! | `sealed_meta` | vault key | canonical metadata; syncs, shared members read it |
//! | `search_cache.sealed` | account metadata key | local cache; readable while locked |
//!
//! The split exists because the vault key is dropped on lock and is shared with
//! other members, so it cannot back a cache that must survive locking and must
//! never leave this machine.

use rusqlite::{OptionalExtension, params};
use mortise_crypto::aead;
use mortise_crypto::item::{ItemId, SealedItem};
use mortise_crypto::vault::{Epoch, VaultId};
use zeroize::Zeroizing;

use crate::changelog::{ItemRecord, Mutation};
use crate::error::{Error, Result};
use crate::model::{ItemKind, ItemMeta, ItemPayload};
use crate::origin::Origin;
use crate::vault::{Vault, now_ms};

/// An item as it appears in a list or search result. No secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemSummary {
    /// Item identifier.
    pub id: ItemId,
    /// What kind of item this is.
    pub kind: ItemKind,
    /// Metadata.
    pub meta: ItemMeta,
    /// Last modification time.
    pub updated_at_ms: u64,
}

/// AAD for the metadata blob.
///
/// Domain-tagged so a metadata blob can never be swapped in for a payload blob,
/// which shares the same vault key and the same item identity.
fn meta_aad(vault: VaultId, item: ItemId, version: u32, epoch: Epoch) -> Vec<u8> {
    let mut aad = Vec::with_capacity(16 + 16 + 4 + 4 + 5);
    aad.extend_from_slice(vault.as_bytes());
    aad.extend_from_slice(item.as_bytes());
    aad.extend_from_slice(&version.to_be_bytes());
    aad.extend_from_slice(&epoch.value().to_be_bytes());
    aad.extend_from_slice(b"/meta");
    aad
}

/// AAD for the local search cache. Bound to the item only: the cache is
/// rebuilt from scratch rather than versioned.
fn cache_aad(item: ItemId) -> Vec<u8> {
    let mut aad = Vec::with_capacity(16 + 6);
    aad.extend_from_slice(item.as_bytes());
    aad.extend_from_slice(b"/cache");
    aad
}

impl Vault {
    /// Store a new item. Returns its generated id.
    pub fn create_item(&mut self, meta: &ItemMeta, payload: &ItemPayload) -> Result<ItemId> {
        let id = ItemId::generate()?;
        self.write_item(id, 1, meta, payload, None)?;
        Ok(id)
    }

    /// Replace an item's metadata and payload, bumping its version.
    pub fn update_item(
        &mut self,
        id: ItemId,
        meta: &ItemMeta,
        payload: &ItemPayload,
    ) -> Result<()> {
        let (version, created): (u32, i64) = self
            .conn()
            .query_row(
                "SELECT version, created_at_ms FROM item WHERE item_id = ?1 AND deleted = 0",
                params![id.as_bytes().as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?
            .ok_or(Error::ItemNotFound)?;

        self.write_item(id, version + 1, meta, payload, Some(created as u64))
    }

    fn write_item(
        &mut self,
        id: ItemId,
        version: u32,
        meta: &ItemMeta,
        payload: &ItemPayload,
        created_at_ms: Option<u64>,
    ) -> Result<()> {
        let vault_id = self.meta().vault_id;
        let vault_key = self.current_vault_key()?;
        let epoch = vault_key.epoch();

        let payload_json = Zeroizing::new(serde_json::to_vec(payload)?);
        let sealed = SealedItem::seal(vault_key, vault_id, id, version, &payload_json)?;

        let meta_json = serde_json::to_vec(meta)?;
        let sealed_meta = aead::seal(
            vault_key.key(),
            &meta_json,
            &meta_aad(vault_id, id, version, epoch),
        )?;

        let now = now_ms();
        let record = ItemRecord {
            item_id: *id.as_bytes(),
            version,
            epoch: epoch.value(),
            kind: payload.kind() as u8,
            sealed_meta,
            sealed_item_key: sealed.sealed_item_key().to_vec(),
            ciphertext: sealed.ciphertext().to_vec(),
            created_at_ms: created_at_ms.unwrap_or(now),
            updated_at_ms: now,
        };

        // Log first, then materialize. The item table is a view of the log
        // (see `changelog`), so writing it directly would leave local edits
        // invisible to sync.
        self.record_mutation(&Mutation::Upsert(record))?;
        self.apply_pending()?;
        Ok(())
    }

    /// Re-seal one item's cached metadata under the local metadata key.
    ///
    /// Called after materializing a change, so search reflects items that
    /// arrived from another device.
    pub(crate) fn refresh_cache_for(&self, id: ItemId) -> Result<()> {
        let meta = match self.item_meta(id) {
            Ok(meta) => meta,
            // Sealed under an epoch we lack, or not yet decryptable. The cache
            // is derived data, so skipping is safe: a later rebuild fixes it.
            Err(_) => return Ok(()),
        };
        let json = serde_json::to_vec(&meta)?;
        let cached = aead::seal(self.meta_key()?, &json, &cache_aad(id))?;
        self.conn().execute(
            "INSERT INTO search_cache (item_id, sealed) VALUES (?1, ?2)
             ON CONFLICT (item_id) DO UPDATE SET sealed = ?2",
            params![id.as_bytes().as_slice(), cached],
        )?;
        Ok(())
    }

    /// Decrypt one item's secrets.
    ///
    /// The only path to a plaintext secret. Deliberately per-item and on
    /// demand: nothing in this crate decrypts payloads in bulk, so a list view
    /// can never accidentally materialize every password at once.
    pub fn reveal(&self, id: ItemId) -> Result<ItemPayload> {
        let (version, epoch, sealed_key, ciphertext): (u32, u32, Vec<u8>, Vec<u8>) = self
            .conn()
            .query_row(
                "SELECT version, epoch, sealed_item_key, ciphertext
                 FROM item WHERE item_id = ?1 AND deleted = 0",
                params![id.as_bytes().as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?
            .ok_or(Error::ItemNotFound)?;

        let vault_key = self.vault_key_at(Epoch(epoch))?;
        let sealed = SealedItem::from_parts(
            self.meta().vault_id,
            id,
            version,
            Epoch(epoch),
            sealed_key,
            ciphertext,
        );
        let plaintext = sealed.open(vault_key)?;
        Ok(serde_json::from_slice(&plaintext)?)
    }

    /// One item's metadata, from the canonical blob. Requires unlock.
    pub fn item_meta(&self, id: ItemId) -> Result<ItemMeta> {
        let (version, epoch, sealed_meta): (u32, u32, Vec<u8>) = self
            .conn()
            .query_row(
                "SELECT version, epoch, sealed_meta FROM item
                 WHERE item_id = ?1 AND deleted = 0",
                params![id.as_bytes().as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?
            .ok_or(Error::ItemNotFound)?;

        let vault_key = self.vault_key_at(Epoch(epoch))?;
        let plaintext = aead::open(
            vault_key.key(),
            &sealed_meta,
            &meta_aad(self.meta().vault_id, id, version, Epoch(epoch)),
        )?;
        Ok(serde_json::from_slice(&plaintext)?)
    }

    /// Every item, newest first. Reads the local cache, so it works locked.
    pub fn list(&self) -> Result<Vec<ItemSummary>> {
        let key = self.meta_key()?;
        let conn = self.conn();

        let mut stmt = conn.prepare(
            "SELECT i.item_id, i.kind, i.updated_at_ms, c.sealed
             FROM item i JOIN search_cache c ON c.item_id = i.item_id
             WHERE i.deleted = 0
             ORDER BY i.updated_at_ms DESC",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, u8>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, Vec<u8>>(3)?,
            ))
        })?;

        let mut out = Vec::new();
        for row in rows {
            let (id_bytes, kind, updated, sealed) = row?;
            let id_bytes: [u8; 16] = id_bytes
                .try_into()
                .map_err(|_| Error::Corrupt("item id is the wrong length"))?;
            let id = ItemId::from_bytes(id_bytes);

            let plaintext = aead::open(key, &sealed, &cache_aad(id))?;
            out.push(ItemSummary {
                id,
                kind: ItemKind::from_u8(kind).ok_or(Error::Corrupt("unknown item kind"))?,
                meta: serde_json::from_slice(&plaintext)?,
                updated_at_ms: updated as u64,
            });
        }
        Ok(out)
    }

    /// Case-insensitive substring search over title, URLs, username and tags.
    ///
    /// Works while locked, which is the whole reason the search cache exists.
    /// Matching happens in memory after decryption — there is no way to index
    /// or `LIKE` an encrypted column, and for a vault's realistic item count
    /// that is entirely fine.
    pub fn search(&self, query: &str) -> Result<Vec<ItemSummary>> {
        let needle = query.trim().to_lowercase();
        if needle.is_empty() {
            return self.list();
        }

        Ok(self
            .list()?
            .into_iter()
            .filter(|s| {
                let m = &s.meta;
                m.title.to_lowercase().contains(&needle)
                    || m.username
                        .as_deref()
                        .is_some_and(|u| u.to_lowercase().contains(&needle))
                    || m.folder
                        .as_deref()
                        .is_some_and(|f| f.to_lowercase().contains(&needle))
                    || m.urls.iter().any(|u| u.to_lowercase().contains(&needle))
                    || m.tags.iter().any(|t| t.to_lowercase().contains(&needle))
            })
            .collect())
    }

    /// Items whose stored URLs permit filling on `page`.
    ///
    /// The autofill lookup. Works while locked, from the search cache, because
    /// the extension needs to know *whether* there is a credential before the
    /// user commits to unlocking — otherwise every page visit would prompt.
    ///
    /// Matching is delegated to [`Origin::may_fill`], which is exact. An item
    /// with a URL this crate cannot parse simply never matches, rather than
    /// falling back to something looser: a parse failure must not become a
    /// permissive match.
    pub fn find_for_origin(&self, page: &Origin) -> Result<Vec<ItemSummary>> {
        Ok(self
            .list()?
            .into_iter()
            .filter(|item| {
                item.meta
                    .urls
                    .iter()
                    .filter_map(|u| Origin::parse(u))
                    .any(|stored| stored.may_fill(page))
            })
            .collect())
    }

    /// Delete an item.
    ///
    /// Leaves a tombstone row so the deletion can propagate at M6, but wipes
    /// the ciphertext and metadata immediately: a deleted secret should not
    /// survive on disk waiting for a sync that may never happen.
    pub fn delete_item(&mut self, id: ItemId) -> Result<()> {
        let exists: u32 = self.conn().query_row(
            "SELECT count(*) FROM item WHERE item_id = ?1 AND deleted = 0",
            params![id.as_bytes().as_slice()],
            |r| r.get(0),
        )?;
        if exists == 0 {
            return Err(Error::ItemNotFound);
        }

        self.record_mutation(&Mutation::Delete {
            item_id: *id.as_bytes(),
            at_ms: now_ms(),
        })?;
        self.apply_pending()?;
        Ok(())
    }

    /// Number of live items. Available while locked, without decrypting.
    pub fn item_count(&self) -> Result<u32> {
        Ok(self
            .conn()
            .query_row("SELECT count(*) FROM item WHERE deleted = 0", [], |r| {
                r.get(0)
            })?)
    }

    /// Drop the local search cache.
    ///
    /// The cache is derived data, so this is safe at any time — [`Vault::list`]
    /// and [`Vault::search`] simply return nothing until it is rebuilt. Useful
    /// as the repair path, and as the thing to do when a device is handed on.
    pub fn clear_search_cache(&mut self) -> Result<()> {
        self.conn().execute("DELETE FROM search_cache", [])?;
        Ok(())
    }

    /// Rebuild the local search cache from the canonical metadata blobs.
    ///
    /// Needed after sync pulls items this device has never seen, and as the
    /// repair path if the cache is ever dropped. Requires unlock, since the
    /// canonical blobs are under the vault key.
    pub fn rebuild_search_cache(&mut self) -> Result<u32> {
        let ids: Vec<ItemId> = {
            let conn = self.conn();
            let mut stmt = conn.prepare("SELECT item_id FROM item WHERE deleted = 0")?;
            let rows = stmt.query_map([], |r| r.get::<_, Vec<u8>>(0))?;
            let mut ids = Vec::new();
            for row in rows {
                let bytes: [u8; 16] = row?
                    .try_into()
                    .map_err(|_| Error::Corrupt("item id is the wrong length"))?;
                ids.push(ItemId::from_bytes(bytes));
            }
            ids
        };

        let mut rebuilt = 0;
        for id in ids {
            self.refresh_cache_for(id)?;
            rebuilt += 1;
        }
        Ok(rebuilt)
    }
}

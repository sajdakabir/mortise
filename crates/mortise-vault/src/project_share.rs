//! The manifest of a shared project (crypto-spec §6.6).
//!
//! Its mutations travel in the signed, vault-key-sealed change log. This
//! module materializes them into one META-key-sealed cache row so the app can
//! still name projects while locked without leaking those names on disk.

use std::path::Path;

use mortise_crypto::aead;
use mortise_crypto::change::Hlc;
use mortise_crypto::identity::{DEVICE_CERT_LEN, DeviceCert, DeviceId};
use mortise_crypto::vault::{VaultId, VaultKey};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};

use crate::changelog::Mutation;
use crate::error::{Error, Result};
use crate::schema;
use crate::vault::{KEY_FORMAT_AUTH, Vault, now_ms};

/// A member label as shown to people. The certificate is retained so the UI
/// can always put the identity fingerprint beside the self-chosen name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberLabel {
    /// Certified device.
    pub device_id: [u8; 16],
    /// Human label.
    pub name: String,
    /// Verified certificate bytes.
    pub cert: Vec<u8>,
}

/// The materialized definition of one shared project.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SharedProjectManifest {
    /// Project name.
    pub name: String,
    /// Project description.
    pub description: String,
    /// Environments in convergent add order.
    pub environments: Vec<String>,
    /// Labels by member device.
    pub members: Vec<MemberLabel>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
struct Stamp {
    wall: u64,
    counter: u32,
    author: [u8; 16],
}

impl Stamp {
    fn new(hlc: Hlc, author: DeviceId) -> Self {
        Self {
            wall: hlc.wall_ms,
            counter: hlc.counter,
            author: *author.as_bytes(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Named {
    name: String,
    stamp: Stamp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Labelled {
    label: MemberLabel,
    stamp: Stamp,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct CachedManifest {
    name: String,
    description: String,
    info_stamp: Stamp,
    environments: Vec<Named>,
    members: Vec<Labelled>,
}

fn cache_aad(vault: mortise_crypto::vault::VaultId) -> Vec<u8> {
    let mut aad = vault.as_bytes().to_vec();
    aad.extend_from_slice(b"/project-manifest-cache");
    aad
}

fn valid_name(name: &str, max: usize) -> bool {
    !name.trim().is_empty()
        && name.len() <= max
        && !name.chars().any(|c| {
            c.is_control() || matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
        })
}

impl Vault {
    /// Promote a local project into its own vault file.
    ///
    /// The new file copies the account identity and this machine's device keys
    /// still sealed under the same MUK, but generates an independent vault id,
    /// ACL, key epoch and change log (crypto-spec §6.1).
    pub fn create_project_vault(
        path: impl AsRef<Path>,
        account: &Vault,
        name: &str,
        description: &str,
    ) -> Result<Self> {
        if !account.is_unlocked() {
            return Err(Error::Locked);
        }
        let path = path.as_ref();
        let conn = Connection::open(path)?;
        schema::apply_pragmas(&conn)?;
        if schema::is_initialized(&conn)? {
            return Err(Error::Corrupt("a vault already exists at this path"));
        }
        schema::initialize(&conn)?;

        let meta = account.meta();
        let device = account.device()?;
        let identity = account.identity()?;
        let vault_id = VaultId::generate()?;
        let key = VaultKey::generate()?;
        let created = now_ms();
        let identity_wrapped: Vec<u8> =
            account
                .conn()
                .query_row("SELECT wrapped FROM identity WHERE id = 1", [], |row| {
                    row.get(0)
                })?;
        let device_wrapped: Vec<u8> =
            account
                .conn()
                .query_row("SELECT wrapped FROM device WHERE id = 1", [], |row| {
                    row.get(0)
                })?;

        conn.execute(
            "INSERT INTO account
               (id, salt, argon2_m_kib, argon2_t, argon2_p, schema_version, created_at_ms)
             VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                meta.salt.as_slice(),
                meta.params.m_cost_kib,
                meta.params.t_cost,
                meta.params.p_cost,
                schema::SCHEMA_VERSION,
                created as i64
            ],
        )?;
        conn.execute(
            "INSERT INTO vault (vault_id, name, kind, epoch, created_at_ms) VALUES (?1, '', 1, ?2, ?3)",
            params![vault_id.as_bytes().as_slice(), key.epoch().value(), created as i64],
        )?;
        conn.execute(
            "INSERT INTO identity (id, public_key, wrapped) VALUES (1, ?1, ?2)",
            params![identity.public().as_bytes().as_slice(), identity_wrapped],
        )?;
        conn.execute(
            "INSERT INTO device (id, device_id, wrapped) VALUES (1, ?1, ?2)",
            params![device.id().as_bytes().as_slice(), device_wrapped],
        )?;
        conn.execute(
            "INSERT INTO vault_key (vault_id, epoch, wrapped, format) VALUES (?1, ?2, ?3, ?4)",
            params![
                vault_id.as_bytes().as_slice(),
                key.epoch().value(),
                key.wrap_for(device, device.public(), vault_id)?.to_bytes(),
                KEY_FORMAT_AUTH
            ],
        )?;
        conn.execute(
            "INSERT INTO known_device (device_id, signing_key, kex_key) VALUES (?1, ?2, ?3)",
            params![
                device.id().as_bytes().as_slice(),
                device.public().signing_public().as_slice(),
                device.public().kex_public_bytes().as_slice()
            ],
        )?;
        conn.execute(
            "INSERT INTO vault_genesis (vault_id, signing_key, kex_key) VALUES (?1, ?2, ?3)",
            params![
                vault_id.as_bytes().as_slice(),
                device.public().signing_public().as_slice(),
                device.public().kex_public_bytes().as_slice()
            ],
        )?;
        drop(conn);

        let token = account.unlock_token()?;
        let mut project = Vault::open(path)?;
        project.unlock_with_token(&token)?;
        project.set_shared_project_info(name, description)?;
        Ok(project)
    }

    /// Create the keyless local project used while an invite request awaits
    /// approval. The invite's genesis owner is pinned before any relay data is
    /// accepted; keys can only be installed after that ACL admits this device.
    pub fn create_waiting_project_vault(
        path: impl AsRef<Path>,
        account: &Vault,
        vault_id: VaultId,
        owner: &mortise_crypto::identity::DevicePublic,
    ) -> Result<Self> {
        if !account.is_unlocked() {
            return Err(Error::Locked);
        }
        let path = path.as_ref();
        let conn = Connection::open(path)?;
        schema::apply_pragmas(&conn)?;
        if schema::is_initialized(&conn)? {
            return Err(Error::Corrupt("a vault already exists at this path"));
        }
        schema::initialize(&conn)?;
        let meta = account.meta();
        let device = account.device()?;
        let identity = account.identity()?;
        let created = now_ms();
        let identity_wrapped: Vec<u8> =
            account
                .conn()
                .query_row("SELECT wrapped FROM identity WHERE id = 1", [], |row| {
                    row.get(0)
                })?;
        let device_wrapped: Vec<u8> =
            account
                .conn()
                .query_row("SELECT wrapped FROM device WHERE id = 1", [], |row| {
                    row.get(0)
                })?;
        conn.execute(
            "INSERT INTO account (id, salt, argon2_m_kib, argon2_t, argon2_p, schema_version, created_at_ms)
             VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6)",
            params![meta.salt.as_slice(), meta.params.m_cost_kib, meta.params.t_cost,
                meta.params.p_cost, schema::SCHEMA_VERSION, created as i64],
        )?;
        conn.execute(
            "INSERT INTO vault (vault_id, name, kind, epoch, created_at_ms) VALUES (?1, '', 1, 0, ?2)",
            params![vault_id.as_bytes().as_slice(), created as i64],
        )?;
        conn.execute(
            "INSERT INTO identity (id, public_key, wrapped) VALUES (1, ?1, ?2)",
            params![identity.public().as_bytes().as_slice(), identity_wrapped],
        )?;
        conn.execute(
            "INSERT INTO device (id, device_id, wrapped) VALUES (1, ?1, ?2)",
            params![device.id().as_bytes().as_slice(), device_wrapped],
        )?;
        conn.execute(
            "INSERT INTO known_device (device_id, signing_key, kex_key) VALUES (?1, ?2, ?3)",
            params![
                device.id().as_bytes().as_slice(),
                device.public().signing_public().as_slice(),
                device.public().kex_public_bytes().as_slice()
            ],
        )?;
        conn.execute(
            "INSERT INTO vault_genesis (vault_id, signing_key, kex_key) VALUES (?1, ?2, ?3)",
            params![
                vault_id.as_bytes().as_slice(),
                owner.signing_public().as_slice(),
                owner.kex_public_bytes().as_slice()
            ],
        )?;
        drop(conn);
        let token = account.unlock_token()?;
        let mut project = Vault::open(path)?;
        project.unlock_with_token(&token)?;
        Ok(project)
    }

    /// Read the shared-project cache. Available after idle lock, like search.
    pub fn shared_project_manifest(&self) -> Result<Option<SharedProjectManifest>> {
        let Some(sealed) = self
            .conn()
            .query_row(
                "SELECT sealed FROM project_manifest_cache WHERE id = 1",
                [],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?
        else {
            return Ok(None);
        };
        let plain = aead::open(self.meta_key()?, &sealed, &cache_aad(self.meta().vault_id))?;
        let cached: CachedManifest = serde_json::from_slice(&plain)?;
        Ok(Some(SharedProjectManifest {
            name: cached.name,
            description: cached.description,
            environments: cached
                .environments
                .into_iter()
                .map(|entry| entry.name)
                .collect(),
            members: cached
                .members
                .into_iter()
                .map(|entry| entry.label)
                .collect(),
        }))
    }

    /// Set the project name and description through the signed change log.
    pub fn set_shared_project_info(&mut self, name: &str, description: &str) -> Result<()> {
        let name = name.trim();
        if !valid_name(name, 128) {
            return Err(Error::Invalid("a project needs a printable name"));
        }
        self.record_mutation(&Mutation::ProjectSetInfo {
            name: name.to_string(),
            description: description.trim().to_string(),
        })?;
        self.apply_pending()?;
        Ok(())
    }

    /// Add an environment; duplicate ASCII-case spellings converge to one.
    pub fn add_shared_project_environment(&mut self, name: &str) -> Result<()> {
        let name = name.trim();
        if !valid_name(name, 128) {
            return Err(Error::Invalid("an environment needs a printable name"));
        }
        self.record_mutation(&Mutation::ProjectAddEnvironment {
            name: name.to_string(),
        })?;
        self.apply_pending()?;
        Ok(())
    }

    /// Set this device's own member label. Admin-authored labels received from
    /// peers are accepted by the materializer as specified in §6.6.
    pub fn set_own_project_member_label(&mut self, cert: &DeviceCert, name: &str) -> Result<()> {
        if cert.device().id() != self.device()?.id() {
            return Err(Error::Invalid("the certificate is for another device"));
        }
        let name = name.trim();
        if !valid_name(name, 64) {
            return Err(Error::Invalid("a member needs a printable name"));
        }
        self.record_mutation(&Mutation::ProjectSetMemberLabel {
            cert: cert.to_bytes(),
            name: name.to_string(),
        })?;
        self.apply_pending()?;
        Ok(())
    }

    /// Set a label for a member as an ACL manager during an explicit grant.
    pub fn set_project_member_label(&mut self, cert: &DeviceCert, name: &str) -> Result<()> {
        if !self
            .acl()?
            .role(self.device()?.id())
            .is_some_and(|role| role.can_manage_acl())
        {
            return Err(Error::Invalid(
                "only an owner or admin may label another member",
            ));
        }
        if self.acl()?.role(cert.device().id()).is_none() {
            return Err(Error::Invalid("the certificate is not an admitted member"));
        }
        let name = name.trim();
        if !valid_name(name, 64) {
            return Err(Error::Invalid("a member needs a printable name"));
        }
        self.record_mutation(&Mutation::ProjectSetMemberLabel {
            cert: cert.to_bytes(),
            name: name.to_string(),
        })?;
        self.apply_pending()?;
        Ok(())
    }

    pub(crate) fn apply_project_manifest_mutation(
        &self,
        mutation: &Mutation,
        hlc: Hlc,
        author: DeviceId,
    ) -> Result<()> {
        let mut cached = self.read_cached_manifest()?.unwrap_or_default();
        let stamp = Stamp::new(hlc, author);
        match mutation {
            Mutation::ProjectSetInfo { name, description } => {
                if !valid_name(name, 128) {
                    return Ok(());
                }
                if stamp > cached.info_stamp {
                    cached.name = name.clone();
                    cached.description = description.clone();
                    cached.info_stamp = stamp;
                }
            }
            Mutation::ProjectAddEnvironment { name } => {
                if !valid_name(name, 128) {
                    return Ok(());
                }
                if let Some(existing) = cached
                    .environments
                    .iter_mut()
                    .find(|entry| entry.name.eq_ignore_ascii_case(name))
                {
                    if stamp < existing.stamp {
                        existing.name = name.clone();
                        existing.stamp = stamp;
                    }
                } else {
                    cached.environments.push(Named {
                        name: name.clone(),
                        stamp,
                    });
                }
                cached.environments.sort_by_key(|entry| entry.stamp);
            }
            Mutation::ProjectSetMemberLabel { cert, name } => {
                if cert.len() != DEVICE_CERT_LEN || !valid_name(name, 64) {
                    return Ok(());
                }
                let Ok(cert) = DeviceCert::from_bytes(cert) else {
                    return Ok(());
                };
                let labelled = cert.device().id();
                let acl = self.acl()?;
                let author_role = acl.role(author);
                if author != labelled && !author_role.is_some_and(|role| role.can_manage_acl()) {
                    return Ok(());
                }
                let Some(member) = acl
                    .members()
                    .find(|(id, _)| **id == labelled)
                    .map(|(_, member)| member)
                else {
                    return Ok(());
                };
                if member.device().signing_public() != cert.device().signing_public() {
                    return Ok(());
                }
                let label = MemberLabel {
                    device_id: *labelled.as_bytes(),
                    name: name.clone(),
                    cert: cert.to_bytes(),
                };
                if let Some(existing) = cached
                    .members
                    .iter_mut()
                    .find(|entry| entry.label.device_id == label.device_id)
                {
                    if stamp > existing.stamp {
                        *existing = Labelled { label, stamp };
                    }
                } else {
                    cached.members.push(Labelled { label, stamp });
                }
            }
            Mutation::Upsert(_) | Mutation::Delete { .. } => {
                unreachable!("only project mutations are routed here")
            }
        }
        self.write_cached_manifest(&cached)
    }

    fn read_cached_manifest(&self) -> Result<Option<CachedManifest>> {
        let Some(sealed) = self
            .conn()
            .query_row(
                "SELECT sealed FROM project_manifest_cache WHERE id = 1",
                [],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?
        else {
            return Ok(None);
        };
        let plain = aead::open(self.meta_key()?, &sealed, &cache_aad(self.meta().vault_id))?;
        Ok(Some(serde_json::from_slice(&plain)?))
    }

    fn write_cached_manifest(&self, manifest: &CachedManifest) -> Result<()> {
        let plain = serde_json::to_vec(manifest)?;
        let sealed = aead::seal(self.meta_key()?, &plain, &cache_aad(self.meta().vault_id))?;
        self.conn().execute(
            "INSERT INTO project_manifest_cache (id, sealed) VALUES (1, ?1) ON CONFLICT (id) DO UPDATE SET sealed = ?1",
            params![sealed],
        )?;
        Ok(())
    }
}

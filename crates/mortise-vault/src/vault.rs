//! Vault lifecycle: create, open, unlock, lock.
//!
//! # What "locked" means
//!
//! Locking drops the MUK, the identity and device keys, and every vault key.
//! What survives is the metadata key, so the local search cache stays readable.
//!
//! So "locked" protects **secrets**, not metadata, against a process that is
//! still running. That is the trade recorded in the threat model: search has to
//! work from the menu bar without a password prompt, and that is only possible
//! if something stays readable.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension, params};
use mortise_crypto::identity::{Device, DeviceId, Identity};
use mortise_crypto::kdf::{self, Argon2Params};
use mortise_crypto::secret::{Key32, Salt16};
use mortise_crypto::vault::{Epoch, VaultId, VaultKey, WrappedVaultKey};

use crate::error::{Error, Result};
use crate::schema;

/// Material that unlocks a vault without the master password.
///
/// # This is as powerful as the master password
///
/// It wraps the master unlock key. Anything holding one can open the vault
/// outright — it is not a weaker, scoped credential, and there is no honest way
/// to make it one: whatever unlocks the vault *is* the vault.
///
/// It exists for exactly one purpose: handing to the macOS keychain under an
/// access control that requires Touch ID or the device passcode, so the user
/// can skip typing their password. Storing it anywhere else — a file, a config,
/// a log, an unprotected keychain item — would reduce the vault's security to
/// whatever protects that location.
///
/// Zeroized on drop, and deliberately not `Clone`, `Debug` or serializable, so
/// it cannot be copied around or printed by accident.
pub struct UnlockToken(Key32);

impl UnlockToken {
    /// The raw bytes, for writing to the keychain.
    pub fn expose(&self) -> &[u8; 32] {
        self.0.expose()
    }

    /// Rebuild from keychain bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        Ok(Self(Key32::from_slice(bytes)?))
    }
}

/// Milliseconds since the Unix epoch.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Everything needed to attempt an unlock. Readable without any key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultMeta {
    /// This vault's identifier.
    pub vault_id: VaultId,
    /// Per-user Argon2 salt.
    pub salt: Salt16,
    /// Argon2 cost parameters this vault was created with.
    pub params: Argon2Params,
    /// Current key epoch.
    pub epoch: Epoch,
    /// Creation time.
    pub created_at_ms: u64,
}

/// What the vault a new file is created with is called. It is the one vault
/// that cannot be shared or deleted, so its name is fixed rather than chosen.
pub const DEFAULT_VAULT_NAME: &str = "Personal";

/// Secret state, present only while unlocked. Dropped — and therefore
/// zeroized — by [`Vault::lock`].
struct Unlocked {
    muk: Key32,
    identity: Identity,
    device: Device,
    /// Every epoch's key. Old epochs are retained because items sealed before a
    /// rotation still need their own epoch's key to open.
    vault_keys: BTreeMap<Epoch, VaultKey>,
}

/// A local vault.
pub struct Vault {
    conn: Connection,
    meta: VaultMeta,
    /// Survives [`Vault::lock`] by design, so the local search cache stays
    /// readable. Set on the first successful unlock in this process; a vault
    /// that has never been unlocked here cannot search either.
    meta_key: Option<Key32>,
    unlocked: Option<Box<Unlocked>>,
}

impl Vault {
    /// Create a new vault at `path`.
    ///
    /// Returns the vault, already unlocked, and the generated account key. That
    /// key is returned exactly once: the caller must render it as a recovery
    /// kit immediately, because nothing in this crate will ever produce it
    /// again (spec §7).
    pub fn create(
        path: impl AsRef<Path>,
        password: &[u8],
        params: Argon2Params,
    ) -> Result<(Self, Key32)> {
        let conn = Connection::open(path)?;
        schema::apply_pragmas(&conn)?;
        if schema::is_initialized(&conn)? {
            return Err(Error::Corrupt("vault already exists at this path"));
        }
        schema::initialize(&conn)?;

        let account_key = kdf::generate_account_key()?;
        let salt = kdf::generate_salt()?;
        let muk = kdf::unlock(password, &account_key, &salt, params)?;

        let identity = Identity::generate()?;
        let device = Device::generate()?;
        let vault_id = VaultId::generate()?;
        let vault_key = VaultKey::generate()?;

        let meta = VaultMeta {
            vault_id,
            salt,
            params,
            epoch: vault_key.epoch(),
            created_at_ms: now_ms(),
        };

        conn.execute(
            "INSERT INTO account
               (id, salt, argon2_m_kib, argon2_t, argon2_p, schema_version, created_at_ms)
             VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                salt.as_slice(),
                params.m_cost_kib,
                params.t_cost,
                params.p_cost,
                schema::SCHEMA_VERSION,
                meta.created_at_ms as i64,
            ],
        )?;

        conn.execute(
            "INSERT INTO vault (vault_id, name, kind, epoch, created_at_ms)
             VALUES (?1, ?2, 0, ?3, ?4)",
            params![
                vault_id.as_bytes().as_slice(),
                DEFAULT_VAULT_NAME,
                meta.epoch.value(),
                meta.created_at_ms as i64,
            ],
        )?;
        conn.execute(
            "INSERT INTO identity (id, public_key, wrapped) VALUES (1, ?1, ?2)",
            params![
                identity.public().as_bytes().as_slice(),
                identity.wrap(&muk)?
            ],
        )?;
        conn.execute(
            "INSERT INTO device (id, device_id, wrapped) VALUES (1, ?1, ?2)",
            params![device.id().as_bytes().as_slice(), device.wrap(&muk)?],
        )?;
        conn.execute(
            "INSERT INTO vault_key (vault_id, epoch, wrapped) VALUES (?1, ?2, ?3)",
            params![
                vault_id.as_bytes().as_slice(),
                vault_key.epoch().value(),
                vault_key.wrap_for(device.public(), vault_id)?.to_bytes()
            ],
        )?;

        conn.execute(
            "INSERT INTO known_device (device_id, signing_key) VALUES (?1, ?2)",
            params![
                device.id().as_bytes().as_slice(),
                device.public().signing_public().as_slice()
            ],
        )?;

        let meta_key = kdf::derive_meta_key(&muk)?;
        let mut vault_keys = BTreeMap::new();
        vault_keys.insert(vault_key.epoch(), vault_key);

        Ok((
            Self {
                conn,
                meta,
                meta_key: Some(meta_key),
                unlocked: Some(Box::new(Unlocked {
                    muk,
                    identity,
                    device,
                    vault_keys,
                })),
            },
            account_key,
        ))
    }

    /// Open an existing vault, locked.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let conn = Connection::open(path)?;
        schema::apply_pragmas(&conn)?;
        if !schema::is_initialized(&conn)? {
            return Err(Error::Corrupt("no vault at this path"));
        }
        schema::check_version(&conn)?;
        schema::migrate(&conn)?;

        let meta = read_meta(&conn)?;
        Ok(Self {
            conn,
            meta,
            meta_key: None,
            unlocked: None,
        })
    }

    /// Readable without unlocking.
    pub fn meta(&self) -> &VaultMeta {
        &self.meta
    }

    /// Whether secrets are currently accessible.
    pub fn is_unlocked(&self) -> bool {
        self.unlocked.is_some()
    }

    /// Derive the keys and load them into memory.
    ///
    /// Unlocking an already-unlocked vault re-derives from scratch rather than
    /// short-circuiting, so a wrong password cannot be masked by stale state.
    pub fn unlock(&mut self, password: &[u8], account_key: &Key32) -> Result<()> {
        self.lock_fully();

        let muk = kdf::unlock(password, account_key, &self.meta.salt, self.meta.params)?;

        self.load_keys(muk)
    }

    /// Load identity, device and vault keys using an already-derived MUK.
    fn load_keys(&mut self, muk: Key32) -> Result<()> {
        let (_identity_public, identity_wrapped): (Vec<u8>, Vec<u8>) = self
            .conn
            .query_row(
                "SELECT public_key, wrapped FROM identity WHERE id = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|_| Error::Corrupt("identity row is missing"))?;

        // The first thing sealed under the MUK that we try to open doubles as
        // the credential check. A decrypt failure here means the password or
        // account key was wrong, not that the file is damaged.
        let identity = Identity::unwrap(&muk, &identity_wrapped).map_err(|e| match e {
            mortise_crypto::Error::Decrypt => Error::WrongCredentials,
            other => Error::Crypto(other),
        })?;

        let device_wrapped: Vec<u8> = self
            .conn
            .query_row("SELECT wrapped FROM device WHERE id = 1", [], |r| r.get(0))
            .map_err(|_| Error::Corrupt("device row is missing"))?;
        let device = Device::unwrap(&muk, &device_wrapped)?;

        let mut vault_keys = BTreeMap::new();
        {
            let mut stmt = self
                .conn
                .prepare("SELECT epoch, wrapped FROM vault_key WHERE vault_id = ?1 ORDER BY epoch")?;
            let rows = stmt.query_map(params![self.meta.vault_id.as_bytes().as_slice()], |r| {
                Ok((r.get::<_, u32>(0)?, r.get::<_, Vec<u8>>(1)?))
            })?;
            for row in rows {
                let (epoch, wrapped) = row?;
                let wrapped = WrappedVaultKey::from_bytes(&wrapped)?;
                let key = VaultKey::unwrap_for(&device, &wrapped, self.meta.vault_id)?;
                vault_keys.insert(Epoch(epoch), key);
            }
        }
        if vault_keys.is_empty() {
            return Err(Error::Corrupt("vault has no keys"));
        }

        self.meta_key = Some(kdf::derive_meta_key(&muk)?);
        self.unlocked = Some(Box::new(Unlocked {
            muk,
            identity,
            device,
            vault_keys,
        }));
        Ok(())
    }

    /// Drop the MUK, the identity and device keys, and every vault key.
    ///
    /// Idempotent. The metadata key is deliberately kept so search still works
    /// from a locked state — see the module docs for why that is a trade rather
    /// than an oversight.
    pub fn lock(&mut self) {
        self.unlocked = None;
    }

    /// Drop everything, including the metadata key.
    ///
    /// For sign-out rather than idle-lock: after this, search is dead until the
    /// next successful unlock.
    pub fn lock_fully(&mut self) {
        self.unlocked = None;
        self.meta_key = None;
    }

    /// Produce an unlock token for biometric unlock.
    ///
    /// Requires the vault to be unlocked already: the token is derived from
    /// live key material, so there is no way to mint one without the password
    /// having been entered at least once. Read [`UnlockToken`] before using
    /// this — it is as powerful as the master password.
    pub fn unlock_token(&self) -> Result<UnlockToken> {
        Ok(UnlockToken(self.unlocked()?.muk.clone()))
    }

    /// Unlock using a token instead of the master password.
    ///
    /// Skips Argon2 entirely, which is the point — the stretching already
    /// happened when the token was minted. It also means a stolen token is not
    /// slowed down by cost parameters, which is why it may only ever live
    /// behind a keychain access control.
    pub fn unlock_with_token(&mut self, token: &UnlockToken) -> Result<()> {
        self.lock_fully();
        let muk = Key32::from_slice(token.expose())?;
        self.load_keys(muk)
    }

    /// Record a new current epoch after a key rotation.
    ///
    /// Only moves forward. An epoch that went backwards would make items
    /// sealed under the newer key unreadable while looking like a valid state.
    pub(crate) fn set_epoch(&mut self, epoch: Epoch) -> Result<()> {
        if epoch <= self.meta.epoch {
            return Err(Error::Corrupt("epoch must advance"));
        }
        self.conn.execute(
            "UPDATE vault SET epoch = ?1 WHERE vault_id = ?2",
            params![epoch.value(), self.meta.vault_id.as_bytes().as_slice()],
        )?;
        self.meta.epoch = epoch;
        Ok(())
    }

    /// Install a rotated vault key, sealed to this device.
    pub(crate) fn store_vault_key(&mut self, key: VaultKey) -> Result<()> {
        let device = self.device()?;
        let wrapped = key.wrap_for(device.public(), self.meta.vault_id)?;
        self.conn.execute(
            "INSERT INTO vault_key (vault_id, epoch, wrapped) VALUES (?1, ?2, ?3)
             ON CONFLICT (vault_id, epoch) DO UPDATE SET wrapped = ?3",
            params![
                self.meta.vault_id.as_bytes().as_slice(),
                key.epoch().value(),
                wrapped.to_bytes()
            ],
        )?;
        if let Some(unlocked) = self.unlocked.as_mut() {
            unlocked.vault_keys.insert(key.epoch(), key);
        }
        Ok(())
    }

    /// This machine's device id. Available while locked.
    pub fn device_id(&self) -> Result<DeviceId> {
        let bytes: Vec<u8> = self
            .conn
            .query_row("SELECT device_id FROM device WHERE id = 1", [], |r| {
                r.get(0)
            })
            .map_err(|_| Error::Corrupt("device row is missing"))?;
        let bytes: [u8; 16] = bytes
            .try_into()
            .map_err(|_| Error::Corrupt("device id is the wrong length"))?;
        Ok(DeviceId::from_bytes(bytes))
    }

    /// Flush the write-ahead log into the main database file.
    ///
    /// Worth calling before copying the file for backup: without it, recent
    /// writes live only in the `-wal` sidecar and a naive copy loses them.
    pub fn checkpoint(&self) -> Result<()> {
        self.conn
            .pragma_update(None, "wal_checkpoint", "TRUNCATE")?;
        Ok(())
    }

    fn unlocked(&self) -> Result<&Unlocked> {
        self.unlocked.as_deref().ok_or(Error::Locked)
    }

    /// The key for the current epoch.
    pub(crate) fn current_vault_key(&self) -> Result<&VaultKey> {
        let u = self.unlocked()?;
        u.vault_keys
            .get(&self.meta.epoch)
            .ok_or(Error::Corrupt("no key for the current epoch"))
    }

    /// The key for a specific epoch, for opening older items.
    pub(crate) fn vault_key_at(&self, epoch: Epoch) -> Result<&VaultKey> {
        self.unlocked()?
            .vault_keys
            .get(&epoch)
            .ok_or(Error::Corrupt("no key for that epoch"))
    }

    pub(crate) fn meta_key(&self) -> Result<&Key32> {
        self.meta_key.as_ref().ok_or(Error::Locked)
    }

    pub(crate) fn conn(&self) -> &Connection {
        &self.conn
    }

    /// The MUK. For deriving the Agent Guard scan key.
    pub fn guard_key(&self) -> Result<Key32> {
        Ok(kdf::derive_guard_key(&self.unlocked()?.muk)?)
    }

    /// The account identity, for signing.
    pub fn identity(&self) -> Result<&Identity> {
        Ok(&self.unlocked()?.identity)
    }

    /// This device's keys, for signing changes.
    pub fn device(&self) -> Result<&Device> {
        Ok(&self.unlocked()?.device)
    }
}

fn read_meta(conn: &Connection) -> Result<VaultMeta> {
    let row = conn
        .query_row(
            "SELECT v.vault_id, a.salt, a.argon2_m_kib, a.argon2_t, a.argon2_p,
                    v.epoch, v.created_at_ms
             FROM vault v, account a
             WHERE a.id = 1
             ORDER BY v.kind, v.created_at_ms
             LIMIT 1",
            [],
            |r| {
                Ok((
                    r.get::<_, Vec<u8>>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, u32>(2)?,
                    r.get::<_, u32>(3)?,
                    r.get::<_, u32>(4)?,
                    r.get::<_, u32>(5)?,
                    r.get::<_, i64>(6)? as u64,
                ))
            },
        )
        .optional()?
        .ok_or(Error::Corrupt("no vault row"))?;

    let vault_id: [u8; 16] = row
        .0
        .try_into()
        .map_err(|_| Error::Corrupt("vault id is the wrong length"))?;
    let salt: Salt16 = row
        .1
        .try_into()
        .map_err(|_| Error::Corrupt("salt is the wrong length"))?;

    Ok(VaultMeta {
        vault_id: VaultId::from_bytes(vault_id),
        salt,
        params: Argon2Params {
            m_cost_kib: row.2,
            t_cost: row.3,
            p_cost: row.4,
        },
        epoch: Epoch(row.5),
        created_at_ms: row.6,
    })
}

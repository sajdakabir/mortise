//! Adding a second device to an account.
//!
//! The new device already knows the master password and account key, so it can
//! derive the same MUK. What it cannot derive is the vault key — that is random
//! and only exists sealed to devices that already hold it.
//!
//! So enrolment is: the new device generates its own keypairs and sends the
//! public halves; an existing device seals every epoch's vault key to them and
//! hands back the vault's identity. Spec §2.3 — vault keys go to *device* keys,
//! which is what lets a lost laptop be revoked without re-keying everything.
//!
//! The private half never leaves the new device, and the enrolment bundle is
//! useless without the master password and account key.

use std::collections::BTreeMap;
use std::path::Path;

use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use truepass_crypto::acl::{AclOp, Role};
use truepass_crypto::identity::{Device, DevicePublic, Identity};
use truepass_crypto::kdf::{self, Argon2Params};
use truepass_crypto::secret::Key32;
use truepass_crypto::vault::{Epoch, VaultId, VaultKey, WrappedVaultKey};

use crate::access::AclEntryRecord;
use crate::error::{Error, Result};
use crate::schema;
use crate::vault::Vault;

/// Everything a new device needs, once it has the password and account key.
///
/// Contains no plaintext key material: the vault keys inside are sealed to the
/// new device's X25519 key, and the identity is sealed under the MUK.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Enrollment {
    /// The vault being joined.
    pub vault_id: [u8; 16],
    /// Argon2 salt, so the new device derives the same MUK.
    pub salt: [u8; 16],
    /// Argon2 cost parameters.
    pub params: Argon2Params,
    /// Current key epoch.
    pub epoch: u32,
    /// Vault creation time, carried over so both devices agree.
    pub created_at_ms: u64,
    /// Account identity, sealed under the MUK.
    pub identity_wrapped: Vec<u8>,
    /// Every epoch's vault key, sealed to the new device.
    ///
    /// All epochs, not just the current one: items sealed before a rotation
    /// still need their own epoch's key, and a device that cannot open its own
    /// history is not much use.
    pub vault_keys: Vec<(u32, Vec<u8>)>,
    /// Devices the new one should accept changes from, with their signing keys.
    pub known_devices: Vec<([u8; 16], [u8; 32])>,
    /// The access control log, so the new device can replay it.
    ///
    /// Without this the new device would be in `known_device` but absent from
    /// the ACL, so its own changes would be refused by its own role check.
    pub acl: Vec<AclEntryRecord>,
}

impl Vault {
    /// Build an enrolment bundle for `new_device`.
    ///
    /// Also records the new device as trusted here, so changes it makes are
    /// accepted when they arrive.
    pub fn enroll_device(&mut self, new_device: &DevicePublic) -> Result<Enrollment> {
        let meta = self.meta().clone();
        // Validate the recipient key before doing any work: a malformed one
        // should fail here rather than halfway through sealing.
        new_device.kex_public()?;

        let mut vault_keys = Vec::new();
        for epoch in self.known_epochs()? {
            let key = self.vault_key_at(Epoch(epoch))?;
            vault_keys.push((epoch, key.wrap_for(new_device, meta.vault_id)?.to_bytes()));
        }

        let identity_wrapped: Vec<u8> =
            self.conn()
                .query_row("SELECT wrapped FROM identity WHERE id = 1", [], |r| {
                    r.get(0)
                })?;

        let mut known_devices = self.known_devices()?;
        known_devices.push((*new_device.id().as_bytes(), *new_device.signing_public()));

        self.trust_device(new_device.id(), new_device.signing_public())?;

        // Record the device in the ACL as well, at Member. Trusting its
        // signature is not the same as granting it the right to write, and the
        // ingest check reads the ACL rather than the trust table.
        self.issue_acl_op(AclOp::AddMember {
            device: new_device.clone(),
            role: Role::Member,
        })?;

        Ok(Enrollment {
            vault_id: *meta.vault_id.as_bytes(),
            salt: meta.salt,
            params: meta.params,
            epoch: meta.epoch.value(),
            created_at_ms: meta.created_at_ms,
            identity_wrapped,
            vault_keys,
            known_devices,
            acl: self.acl_records()?,
        })
    }

    /// Epochs this device holds a key for.
    pub fn known_epochs(&self) -> Result<Vec<u32>> {
        let conn = self.conn();
        let mut stmt = conn.prepare("SELECT epoch FROM vault_key ORDER BY epoch")?;
        let rows = stmt.query_map([], |r| r.get::<_, u32>(0))?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// Devices whose changes this vault accepts.
    pub fn known_devices(&self) -> Result<Vec<([u8; 16], [u8; 32])>> {
        let conn = self.conn();
        let mut stmt = conn.prepare("SELECT device_id, signing_key FROM known_device")?;
        let rows = stmt.query_map([], |r| {
            Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?))
        })?;

        let mut out = Vec::new();
        for row in rows {
            let (id, key) = row?;
            let id: [u8; 16] = id
                .try_into()
                .map_err(|_| Error::Corrupt("device id is the wrong length"))?;
            let key: [u8; 32] = key
                .try_into()
                .map_err(|_| Error::Corrupt("signing key is the wrong length"))?;
            out.push((id, key));
        }
        Ok(out)
    }
}

/// Create a vault on a new device from an enrolment bundle.
///
/// The password and account key must be the account's real ones: the bundle
/// alone opens nothing, because the identity inside is sealed under the MUK
/// they derive.
pub fn join(
    path: impl AsRef<Path>,
    password: &[u8],
    account_key: &Key32,
    device: &Device,
    enrollment: &Enrollment,
) -> Result<Vault> {
    let conn = Connection::open(path.as_ref())?;
    schema::apply_pragmas(&conn)?;
    if schema::is_initialized(&conn)? {
        return Err(Error::Corrupt("a vault already exists at this path"));
    }
    schema::initialize(&conn)?;

    let muk = kdf::unlock(password, account_key, &enrollment.salt, enrollment.params)?;

    // Opening the identity is the credential check: wrong password or wrong
    // account key fails here, before anything is written.
    let identity = Identity::unwrap(&muk, &enrollment.identity_wrapped).map_err(|e| match e {
        truepass_crypto::Error::Decrypt => Error::WrongCredentials,
        other => Error::Crypto(other),
    })?;

    let vault_id = VaultId::from_bytes(enrollment.vault_id);

    // Confirm every key actually unwraps before committing to the file. A
    // half-usable vault is worse than a refused enrolment.
    let mut keys = BTreeMap::new();
    for (epoch, wrapped) in &enrollment.vault_keys {
        let wrapped = WrappedVaultKey::from_bytes(wrapped)?;
        let key = VaultKey::unwrap_for(device, &wrapped, vault_id)?;
        if key.epoch() != Epoch(*epoch) {
            return Err(Error::Corrupt(
                "enrolment key epoch does not match its label",
            ));
        }
        keys.insert(*epoch, wrapped);
    }
    if keys.is_empty() {
        return Err(Error::Corrupt("enrolment contains no vault keys"));
    }

    conn.execute(
        "INSERT INTO vault_meta
           (id, vault_id, salt, argon2_m_kib, argon2_t, argon2_p, epoch,
            schema_version, created_at_ms)
         VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            enrollment.vault_id.as_slice(),
            enrollment.salt.as_slice(),
            enrollment.params.m_cost_kib,
            enrollment.params.t_cost,
            enrollment.params.p_cost,
            enrollment.epoch,
            schema::SCHEMA_VERSION,
            enrollment.created_at_ms as i64,
        ],
    )?;
    conn.execute(
        "INSERT INTO identity (id, public_key, wrapped) VALUES (1, ?1, ?2)",
        params![
            identity.public().as_bytes().as_slice(),
            enrollment.identity_wrapped
        ],
    )?;
    conn.execute(
        "INSERT INTO device (id, device_id, wrapped) VALUES (1, ?1, ?2)",
        params![device.id().as_bytes().as_slice(), device.wrap(&muk)?],
    )?;
    for (epoch, wrapped) in &enrollment.vault_keys {
        conn.execute(
            "INSERT INTO vault_key (epoch, wrapped) VALUES (?1, ?2)",
            params![epoch, wrapped],
        )?;
    }
    for (id, signing_key) in &enrollment.known_devices {
        conn.execute(
            "INSERT OR REPLACE INTO known_device (device_id, signing_key) VALUES (?1, ?2)",
            params![id.as_slice(), signing_key.as_slice()],
        )?;
    }
    conn.execute(
        "INSERT OR REPLACE INTO known_device (device_id, signing_key) VALUES (?1, ?2)",
        params![
            device.id().as_bytes().as_slice(),
            device.public().signing_public().as_slice()
        ],
    )?;

    drop(conn);

    let mut vault = Vault::open(path)?;
    vault.unlock(password, account_key)?;

    // Replay the ACL so this device knows the membership it is joining — and
    // so its own entry is present, without which its changes would fail their
    // own role check on arrival.
    let vault_id = vault.meta().vault_id;
    for record in &enrollment.acl {
        let entry = record
            .to_entry(vault_id)
            .ok_or(Error::Corrupt("enrolment contains an unreadable acl entry"))?;
        vault.apply_acl_entry(&entry, false)?;
    }

    Ok(vault)
}

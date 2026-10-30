//! Persisting and enforcing the access control list.
//!
//! `mortise_crypto::acl` has the rules — who may grant what, who may not be
//! removed — and validates each entry against the current state. This module
//! stores the entries, replays them to rebuild that state, and applies the
//! result where it matters: deciding whose changes to accept.
//!
//! # Why enforcement lives on ingest
//!
//! The relay cannot do it. Roles are in an encrypted log it cannot read, so it
//! can only check that a pusher is *some* member of the vault. A member with a
//! read-only role could therefore push changes the relay happily stores.
//!
//! Clients are where that gets caught: a change is accepted only if its author
//! held a writing role when it was made. Without this, "viewer" would be a
//! label with nothing behind it.

use mortise_crypto::acl::{Acl, AclEntry, AclOp, Role, UnsignedAclEntry};
use mortise_crypto::identity::{DeviceId, DevicePublic};
use mortise_crypto::vault::{Epoch, VaultKey, WrappedVaultKey};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::vault::{Vault, now_ms};

/// What a revocation did, and what it could not undo.
///
/// # How it reaches other devices
///
/// The removal and the key rotation are issued as signed ACL entries, and the
/// new key is re-wrapped for every remaining member. All of it travels on the
/// next sync: the ACL entries and the re-wrapped keys are pushed to the relay,
/// and peers apply them, stop accepting the removed device's changes, and pick
/// up the new epoch's key. Until a peer syncs it still trusts the removed
/// device — propagation is as prompt as sync, not instant.
///
/// # What it cannot undo
///
/// Forward secrecy only. Whatever the removed device already synced is theirs
/// forever; rotation protects only what is written afterwards.
/// `items_the_removed_device_retains` is how many items the caller should tell
/// the user to rotate by hand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Revocation {
    /// The epoch now in force.
    pub new_epoch: u32,
    /// How many remaining devices the key was re-wrapped for.
    pub rewrapped_for: u32,
    /// Items the removed device may already hold copies of.
    ///
    /// Not a count of anything that was deleted — nothing was. This is the
    /// number the UI should use to say how much needs rotating by hand.
    pub items_the_removed_device_retains: u32,
}

/// A revocation built against the current ACL head but not applied locally.
///
/// The sync layer first submits both entries to the relay as one conditional
/// batch, then calls [`Vault::commit_revocation`] only after acceptance. The
/// fresh key remains memory-only until that point (crypto-spec §6.3).
pub struct PreparedRevocation {
    remove: AclEntry,
    rotate: AclEntry,
    key: VaultKey,
}

impl PreparedRevocation {
    /// The two entries the relay must accept atomically, in sequence order.
    pub fn entries(&self) -> [&AclEntry; 2] {
        [&self.remove, &self.rotate]
    }
}

/// Discriminants for the stored op. **Never renumber**: these are the only
/// link between a stored row and how to read its body.
mod kind {
    pub const ADD_MEMBER: u8 = 1;
    pub const REMOVE_MEMBER: u8 = 2;
    pub const CHANGE_ROLE: u8 = 3;
    pub const ROTATE_KEY: u8 = 4;
}

fn role_to_u8(role: Role) -> u8 {
    role as u8
}

fn role_from_u8(value: u8) -> Option<Role> {
    Some(match value {
        1 => Role::Viewer,
        2 => Role::Member,
        3 => Role::Admin,
        4 => Role::Owner,
        _ => return None,
    })
}

/// Encode an op for storage.
///
/// Hand-rolled rather than serde because the bytes must reconstruct an `AclOp`
/// *exactly* — the signature is over the canonical encoding of the op, so a
/// round trip that changed any field would invalidate every entry.
fn encode_op(op: &AclOp) -> (u8, Vec<u8>) {
    match op {
        AclOp::AddMember { device, role } => {
            let mut body = Vec::with_capacity(65);
            body.extend_from_slice(device.signing_public());
            body.extend_from_slice(device.kex_public_bytes());
            body.push(role_to_u8(*role));
            (kind::ADD_MEMBER, body)
        }
        AclOp::RemoveMember { device } => (kind::REMOVE_MEMBER, device.as_bytes().to_vec()),
        AclOp::ChangeRole { device, role } => {
            let mut body = device.as_bytes().to_vec();
            body.push(role_to_u8(*role));
            (kind::CHANGE_ROLE, body)
        }
        AclOp::RotateKey { epoch } => (kind::ROTATE_KEY, epoch.value().to_be_bytes().to_vec()),
    }
}

fn decode_op(op_kind: u8, body: &[u8]) -> Option<AclOp> {
    match op_kind {
        kind::ADD_MEMBER if body.len() == 65 => {
            let sign: [u8; 32] = body[..32].try_into().ok()?;
            let kex: [u8; 32] = body[32..64].try_into().ok()?;
            Some(AclOp::AddMember {
                device: DevicePublic::from_parts(sign, kex),
                role: role_from_u8(body[64])?,
            })
        }
        kind::REMOVE_MEMBER if body.len() == 16 => Some(AclOp::RemoveMember {
            device: DeviceId::from_bytes(body.try_into().ok()?),
        }),
        kind::CHANGE_ROLE if body.len() == 17 => Some(AclOp::ChangeRole {
            device: DeviceId::from_bytes(body[..16].try_into().ok()?),
            role: role_from_u8(body[16])?,
        }),
        kind::ROTATE_KEY if body.len() == 4 => Some(AclOp::RotateKey {
            epoch: Epoch(u32::from_be_bytes(body.try_into().ok()?)),
        }),
        _ => None,
    }
}

/// An ACL entry in transportable form.
///
/// Hand-encoded for the same reason as the op body: the signature covers the
/// canonical encoding, so a round trip that altered any field would invalidate
/// it. Serde is used only for the envelope, never for the signed parts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AclEntryRecord {
    /// Sequence number.
    pub seq: u64,
    /// Entry id.
    pub id: [u8; 32],
    /// Previous entry's id.
    pub prev: [u8; 32],
    /// Operation discriminant.
    pub op_kind: u8,
    /// Operation body.
    pub op_body: Vec<u8>,
    /// Authoring device.
    pub author: [u8; 16],
    /// Issue time.
    pub issued_at_ms: u64,
    /// Signature. A `Vec` because serde does not derive for arrays over 32,
    /// and its length is checked on the way back in.
    pub signature: Vec<u8>,
}

impl AclEntryRecord {
    /// Capture an entry for transport.
    pub fn from_entry(entry: &AclEntry) -> Self {
        let (op_kind, op_body) = encode_op(entry.op());
        Self {
            seq: entry.seq(),
            id: entry.id(),
            prev: entry.prev(),
            op_kind,
            op_body,
            author: *entry.author().as_bytes(),
            issued_at_ms: entry.issued_at_ms(),
            signature: entry.signature().to_vec(),
        }
    }

    /// Rebuild an entry. `None` if any field is malformed.
    pub fn to_entry(&self, vault: mortise_crypto::vault::VaultId) -> Option<AclEntry> {
        let op = decode_op(self.op_kind, &self.op_body)?;
        let signature: [u8; 64] = self.signature.clone().try_into().ok()?;
        let unsigned = UnsignedAclEntry::new(
            vault,
            self.seq,
            self.prev,
            op,
            DeviceId::from_bytes(self.author),
            self.issued_at_ms,
        );
        Some(AclEntry::from_parts(unsigned, self.id, signature))
    }
}

impl Vault {
    /// The whole ACL log, for handing to a device being enrolled.
    pub fn acl_records(&self) -> Result<Vec<AclEntryRecord>> {
        Ok(self
            .acl_entries()?
            .iter()
            .map(AclEntryRecord::from_entry)
            .collect())
    }

    /// Rebuild the ACL by replaying the stored log.
    ///
    /// Replayed rather than cached because `Acl::apply` is what enforces the
    /// rules — a cached snapshot could hold a state no sequence of legal
    /// operations could reach.
    pub fn acl(&self) -> Result<Acl> {
        let owner = self.owner_device()?;
        let mut acl = Acl::genesis(self.meta().vault_id, &owner);

        for entry in self.acl_entries()? {
            // An entry that no longer validates means the log is inconsistent,
            // which is worth failing on rather than quietly serving a
            // half-applied ACL.
            acl.apply(&entry)?;
        }
        Ok(acl)
    }

    /// The device the genesis ACL names as owner.
    ///
    /// On the device that created the vault this is itself. An enrolled device
    /// learns it from the known-device rows the enrolment bundle carried.
    pub(crate) fn owner_device(&self) -> Result<DevicePublic> {
        let row: Option<(Vec<u8>, Vec<u8>)> = self
            .conn()
            .query_row(
                "SELECT signing_key, kex_key FROM vault_genesis WHERE vault_id = ?1",
                params![self.meta().vault_id.as_bytes().as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;

        let (signing, kex) = row.ok_or(Error::Corrupt("vault has no genesis owner"))?;
        let signing: [u8; 32] = signing
            .try_into()
            .map_err(|_| Error::Corrupt("signing key is the wrong length"))?;
        // Role decisions never read the kex half; authenticating a vault key the
        // owner re-wrapped does. A vault created before v8 has an empty kex here,
        // which only matters once another device must verify a key this owner
        // sealed — and an enrolment under v8 records the real one.
        let kex: [u8; 32] = kex.try_into().unwrap_or([0u8; 32]);

        Ok(DevicePublic::from_parts(signing, kex))
    }

    fn acl_entries(&self) -> Result<Vec<AclEntry>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT seq, id, prev, op_kind, op_body, author, issued_at_ms, signature
             FROM acl_log ORDER BY seq",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, Vec<u8>>(2)?,
                r.get::<_, u8>(3)?,
                r.get::<_, Vec<u8>>(4)?,
                r.get::<_, Vec<u8>>(5)?,
                r.get::<_, i64>(6)?,
                r.get::<_, Vec<u8>>(7)?,
            ))
        })?;

        let bad = |_| Error::Corrupt("acl row has a malformed field");
        let mut out = Vec::new();
        for row in rows {
            let (seq, id, prev, op_kind, op_body, author, issued, signature) = row?;
            let op = decode_op(op_kind, &op_body)
                .ok_or(Error::Corrupt("acl row has an unreadable operation"))?;

            let unsigned = UnsignedAclEntry::new(
                self.meta().vault_id,
                seq as u64,
                prev.try_into().map_err(bad)?,
                op,
                DeviceId::from_bytes(author.try_into().map_err(bad)?),
                issued as u64,
            );
            out.push(AclEntry::from_parts(
                unsigned,
                id.try_into().map_err(bad)?,
                signature.try_into().map_err(bad)?,
            ));
        }
        Ok(out)
    }

    /// Validate and store one ACL entry.
    ///
    /// Validated against the replayed ACL before it is written, so the stored
    /// log only ever contains entries that were legal when applied.
    pub fn apply_acl_entry(&mut self, entry: &AclEntry, local: bool) -> Result<()> {
        let mut acl = self.acl()?;
        acl.apply(entry)?;

        let (op_kind, op_body) = encode_op(entry.op());
        self.conn().execute(
            "INSERT INTO acl_log
               (seq, id, prev, op_kind, op_body, author, issued_at_ms, signature, pushed)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                entry.seq() as i64,
                entry.id().as_slice(),
                entry.prev().as_slice(),
                op_kind,
                op_body,
                entry.author().as_bytes().as_slice(),
                entry.issued_at_ms() as i64,
                entry.signature().as_slice(),
                if local { 0 } else { 1 },
            ],
        )?;

        // Adding a member means trusting their changes; removing means the
        // opposite. Keeping known_device in step with the ACL is what makes
        // revocation actually stop a device.
        match entry.op() {
            AclOp::AddMember { device, .. } => {
                self.trust_device(
                    device.id(),
                    device.signing_public(),
                    device.kex_public_bytes(),
                )?;
            }
            AclOp::RemoveMember { device } => {
                self.conn().execute(
                    "DELETE FROM known_device WHERE device_id = ?1",
                    params![device.as_bytes().as_slice()],
                )?;
            }
            AclOp::ChangeRole { .. } | AclOp::RotateKey { .. } => {}
        }

        if let AclOp::RotateKey { epoch } = entry.op() {
            self.set_epoch(*epoch)?;
        }
        Ok(())
    }

    /// Issue a signed ACL operation from this device.
    pub fn issue_acl_op(&mut self, op: AclOp) -> Result<AclEntry> {
        let entry = self.prepare_acl_op(op)?;

        self.apply_acl_entry(&entry, true)?;
        Ok(entry)
    }

    /// Build and sign an ACL operation without changing local state.
    ///
    /// Networked membership changes use this before the relay's conditional
    /// commit. Keeping preparation side-effect free prevents a losing admin in
    /// a concurrent edit from forking its local ACL.
    pub fn prepare_acl_op(&self, op: AclOp) -> Result<AclEntry> {
        let acl = self.acl()?;
        let device = self.device()?;
        Ok(UnsignedAclEntry::new(
            self.meta().vault_id,
            acl.next_seq(),
            acl.head(),
            op,
            device.id(),
            now_ms(),
        )
        .sign(device))
    }

    /// Whether `device` may write to this vault.
    ///
    /// Used on ingest. A viewer's changes are refused here, which is the only
    /// place that can happen — the relay cannot read roles.
    pub fn may_write(&self, device: DeviceId) -> Result<bool> {
        Ok(matches!(
            self.acl()?.role(device),
            Some(Role::Member) | Some(Role::Admin) | Some(Role::Owner)
        ))
    }

    /// Remove a member and rotate the vault key.
    ///
    /// Spec §6, the whole sequence in one call because doing it in pieces
    /// invites stopping halfway: removing without rotating leaves the ex-member
    /// able to read everything written afterwards.
    ///
    /// Forward secrecy only. Whatever they already synced is theirs forever, so
    /// the caller must tell the user to rotate the actual credentials — the
    /// returned list of affected item ids is there for exactly that message.
    pub fn revoke_member(&mut self, device: DeviceId) -> Result<Revocation> {
        let prepared = self.prepare_revocation(device)?;
        self.commit_revocation(prepared)
    }

    /// Prepare the remove-and-rotate pair without writing either entry or the
    /// new vault key to disk.
    pub fn prepare_revocation(&self, device: DeviceId) -> Result<PreparedRevocation> {
        let before = self.acl()?;
        if before.role(device).is_none() {
            return Err(Error::Crypto(mortise_crypto::Error::AclRejected(
                "device is not a member",
            )));
        }

        let signing = self.device()?;
        let remove = UnsignedAclEntry::new(
            self.meta().vault_id,
            before.next_seq(),
            before.head(),
            AclOp::RemoveMember { device },
            signing.id(),
            now_ms(),
        )
        .sign(signing);
        let mut after_remove = before;
        after_remove.apply(&remove)?;

        let key = self.current_vault_key()?.rotate()?;
        let rotate = UnsignedAclEntry::new(
            self.meta().vault_id,
            after_remove.next_seq(),
            after_remove.head(),
            AclOp::RotateKey { epoch: key.epoch() },
            signing.id(),
            now_ms(),
        )
        .sign(signing);
        after_remove.apply(&rotate)?;

        Ok(PreparedRevocation {
            remove,
            rotate,
            key,
        })
    }

    /// Apply a prepared revocation after the relay accepted its two entries.
    pub fn commit_revocation(&mut self, prepared: PreparedRevocation) -> Result<Revocation> {
        // Revalidation against the current head happens inside each apply. If
        // local state moved since preparation, nothing is silently reissued.
        self.apply_acl_entry(&prepared.remove, true)?;
        let new_epoch = prepared.key.epoch();
        self.store_vault_key(prepared.key)?;
        self.apply_acl_entry(&prepared.rotate, true)?;

        // Re-wrap for everyone who remains and queue the sealed copies for the
        // relay. Each gets the new key sealed to their own device key, which is
        // what the removed device no longer has; an offline member collects it
        // on its next sync.
        let acl = self.acl()?;
        let recipients: Vec<_> = acl.key_recipients().cloned().collect();
        let mut rewrapped = 0;
        for recipient in &recipients {
            let recipient_id = recipient.id();
            if recipient_id == self.device()?.id() {
                continue; // already stored above
            }
            let bytes = self
                .current_vault_key()?
                .wrap_for(self.device()?, recipient, self.meta().vault_id)?
                .to_bytes();
            self.queue_rewrapped_key(recipient_id, new_epoch, &bytes)?;
            rewrapped += 1;
        }

        let affected = self.item_count()?;
        Ok(Revocation {
            new_epoch: new_epoch.value(),
            rewrapped_for: rewrapped,
            items_the_removed_device_retains: affected,
        })
    }

    /// ACL entries the relay has not acknowledged.
    pub fn unpushed_acl_entries(&self) -> Result<Vec<AclEntry>> {
        let pushed: Vec<u64> = {
            let conn = self.conn();
            let mut stmt = conn.prepare("SELECT seq FROM acl_log WHERE pushed = 0 ORDER BY seq")?;
            let rows = stmt.query_map([], |r| r.get::<_, i64>(0))?;
            rows.map(|r| r.map(|s| s as u64))
                .collect::<std::result::Result<_, _>>()?
        };
        Ok(self
            .acl_entries()?
            .into_iter()
            .filter(|e| pushed.contains(&e.seq()))
            .collect())
    }

    /// Mark ACL entries as acknowledged.
    pub fn mark_acl_pushed(&mut self, up_to_seq: u64) -> Result<()> {
        self.conn().execute(
            "UPDATE acl_log SET pushed = 1 WHERE seq <= ?1",
            params![up_to_seq as i64],
        )?;
        Ok(())
    }

    /// The sequence number of the latest ACL entry held, 0 if only genesis.
    ///
    /// Used as the pull cursor: the strict ACL sequence is its own cursor, so no
    /// separate one is stored.
    pub fn acl_seq(&self) -> Result<u64> {
        // The ACL log is one strict sequence per file, like `acl_entries` reads
        // it — not filtered by vault_id, which `apply_acl_entry` leaves empty.
        let max: Option<i64> = self
            .conn()
            .query_row("SELECT MAX(seq) FROM acl_log", [], |r| r.get(0))?;
        Ok(max.unwrap_or(0) as u64)
    }

    /// Queue a re-wrapped key for a remaining member to collect over the relay.
    fn queue_rewrapped_key(&self, recipient: DeviceId, epoch: Epoch, wrapped: &[u8]) -> Result<()> {
        self.conn().execute(
            "INSERT INTO key_outbox (vault_id, recipient_device_id, epoch, wrapped, pushed)
             VALUES (?1, ?2, ?3, ?4, 0)
             ON CONFLICT (vault_id, recipient_device_id, epoch)
               DO UPDATE SET wrapped = ?4, pushed = 0",
            params![
                self.meta().vault_id.as_bytes().as_slice(),
                recipient.as_bytes().as_slice(),
                epoch.value(),
                wrapped,
            ],
        )?;
        Ok(())
    }

    /// Re-wrapped keys not yet pushed: `(recipient, epoch, wrapped bytes)`.
    pub fn unpushed_keys(&self) -> Result<Vec<(DeviceId, u32, Vec<u8>)>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT recipient_device_id, epoch, wrapped FROM key_outbox
             WHERE vault_id = ?1 AND pushed = 0 ORDER BY epoch",
        )?;
        let rows = stmt.query_map(params![self.meta().vault_id.as_bytes().as_slice()], |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, u32>(1)?,
                r.get::<_, Vec<u8>>(2)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (id, epoch, wrapped) = row?;
            let id: [u8; 16] = id
                .try_into()
                .map_err(|_| Error::Corrupt("outbox device id is the wrong length"))?;
            out.push((DeviceId::from_bytes(id), epoch, wrapped));
        }
        Ok(out)
    }

    /// Mark all queued keys as delivered to the relay.
    pub fn mark_keys_pushed(&mut self) -> Result<()> {
        self.conn().execute(
            "UPDATE key_outbox SET pushed = 1 WHERE vault_id = ?1",
            params![self.meta().vault_id.as_bytes().as_slice()],
        )?;
        Ok(())
    }

    /// Whether a key for `epoch` is already stored.
    fn has_vault_key(&self, epoch: Epoch) -> Result<bool> {
        let count: u32 = self.conn().query_row(
            "SELECT COUNT(*) FROM vault_key WHERE vault_id = ?1 AND epoch = ?2",
            params![self.meta().vault_id.as_bytes().as_slice(), epoch.value()],
            |r| r.get(0),
        )?;
        Ok(count > 0)
    }

    /// Store a vault key received over the relay, after authenticating it.
    ///
    /// The blob is addressed to this device and sealed by another device after a
    /// rotation. It is authenticated against the ACL — the sealer must be a
    /// current admin or owner — then re-sealed to this device so later unlocks
    /// take the self path. Returns whether the key was new.
    ///
    /// Requires the vault to be unlocked: re-sealing needs this device's key.
    pub fn apply_wrapped_key(&mut self, epoch: u32, wrapped: &[u8]) -> Result<bool> {
        if self.has_vault_key(Epoch(epoch))? {
            return Ok(false);
        }
        let wrapped = WrappedVaultKey::from_bytes(wrapped).map_err(Error::Crypto)?;
        if wrapped.epoch() != Epoch(epoch) {
            return Err(Error::Corrupt(
                "delivered key epoch does not match its label",
            ));
        }

        let key = {
            let device = self.device()?;
            let sender = wrapped
                .sender_id()
                .ok_or(Error::Corrupt("delivered key has no sender"))?;
            let sender_kex = self.resolve_sender_kex(device, sender)?;
            VaultKey::unwrap_for(device, &wrapped, self.meta().vault_id, &sender_kex)
                .map_err(Error::Crypto)?
        };
        self.store_vault_key(key)?;
        Ok(true)
    }
}

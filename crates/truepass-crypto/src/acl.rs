//! Access control: spec §6.
//!
//! The ACL is its own signed log, separate from the change log. Unlike changes,
//! which form a DAG, **ACL entries form a strict sequence**: each carries a
//! sequence number and the hash of its predecessor, and applying one out of
//! order is rejected.
//!
//! That is deliberate. Concurrent ACL edits are genuinely dangerous — two
//! admins each removing the other, applied in different orders on different
//! devices, would leave the two devices disagreeing about who is a member. A
//! DAG cannot resolve that safely, which is exactly why any-sync gives ACL
//! validation its own consensus node. Serializing the log sidesteps the problem:
//! the second of two concurrent edits is rejected and must be reissued against
//! the new head.

use std::collections::BTreeMap;

use ed25519_dalek::{Signature, VerifyingKey};

use crate::encode::{Canonical, Tag, Writer};
use crate::error::{Error, Result};
use crate::identity::{Device, DeviceId, DevicePublic};
use crate::vault::{Epoch, VaultId};

/// What a member is allowed to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Role {
    /// Read items only.
    Viewer = 1,
    /// Read and write items.
    Member = 2,
    /// Manage members and viewers, and rotate keys.
    Admin = 3,
    /// Everything, including managing admins and other owners.
    Owner = 4,
}

impl Role {
    /// Whether this role may change the ACL at all.
    pub fn can_manage_acl(self) -> bool {
        self >= Role::Admin
    }

    /// Whether this role may grant or revoke `target`.
    ///
    /// An admin cannot touch another admin or an owner — otherwise any admin
    /// could unilaterally take over a vault by demoting everyone above them.
    pub fn can_manage(self, target: Role) -> bool {
        match self {
            Role::Owner => true,
            Role::Admin => target < Role::Admin,
            _ => false,
        }
    }
}

/// A single access-control operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AclOp {
    /// Grant a device access at a role.
    AddMember {
        /// The device being granted access.
        device: DevicePublic,
        /// The role granted.
        role: Role,
    },
    /// Revoke a device's access.
    RemoveMember {
        /// The device being removed.
        device: DeviceId,
    },
    /// Change an existing member's role.
    ChangeRole {
        /// The device whose role changes.
        device: DeviceId,
        /// The new role.
        role: Role,
    },
    /// Advance the key epoch. Follows a removal (spec §6 step 2).
    RotateKey {
        /// The epoch being moved to. Must be exactly current + 1.
        epoch: Epoch,
    },
}

impl AclOp {
    fn discriminant(&self) -> u8 {
        match self {
            AclOp::AddMember { .. } => 1,
            AclOp::RemoveMember { .. } => 2,
            AclOp::ChangeRole { .. } => 3,
            AclOp::RotateKey { .. } => 4,
        }
    }

    fn encode(&self, w: &mut Writer) {
        w.u8(self.discriminant());
        match self {
            AclOp::AddMember { device, role } => {
                w.fixed(device.id().as_bytes())
                    .fixed(device.signing_public())
                    .fixed(device.kex_public_bytes())
                    .u8(*role as u8);
            }
            AclOp::RemoveMember { device } => {
                w.fixed(device.as_bytes());
            }
            AclOp::ChangeRole { device, role } => {
                w.fixed(device.as_bytes()).u8(*role as u8);
            }
            AclOp::RotateKey { epoch } => {
                w.u32(epoch.value());
            }
        }
    }
}

/// An ACL entry before signing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsignedAclEntry {
    vault: VaultId,
    seq: u64,
    prev: [u8; 32],
    op: AclOp,
    author: DeviceId,
    issued_at_ms: u64,
}

impl UnsignedAclEntry {
    /// Build an entry extending `head` at `seq`.
    pub fn new(
        vault: VaultId,
        seq: u64,
        prev: [u8; 32],
        op: AclOp,
        author: DeviceId,
        issued_at_ms: u64,
    ) -> Self {
        Self {
            vault,
            seq,
            prev,
            op,
            author,
            issued_at_ms,
        }
    }

    /// The id this entry will have once signed.
    pub fn id(&self) -> [u8; 32] {
        self.canonical_digest()
    }

    /// Sign with the authoring device.
    pub fn sign(self, device: &Device) -> AclEntry {
        let id = self.id();
        let signature = device.sign(&id);
        AclEntry {
            unsigned: self,
            id,
            signature,
        }
    }
}

impl Canonical for UnsignedAclEntry {
    fn tag() -> Tag {
        Tag::AclEntry
    }

    fn encode(&self, w: &mut Writer) {
        w.fixed(self.vault.as_bytes())
            .u64(self.seq)
            .fixed(&self.prev)
            .fixed(self.author.as_bytes())
            .u64(self.issued_at_ms);
        self.op.encode(w);
    }
}

/// A signed ACL entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AclEntry {
    unsigned: UnsignedAclEntry,
    id: [u8; 32],
    signature: [u8; 64],
}

impl AclEntry {
    /// Entry id.
    pub fn id(&self) -> [u8; 32] {
        self.id
    }

    /// Sequence number.
    pub fn seq(&self) -> u64 {
        self.unsigned.seq
    }

    /// The operation.
    pub fn op(&self) -> &AclOp {
        &self.unsigned.op
    }

    /// The authoring device.
    pub fn author(&self) -> DeviceId {
        self.unsigned.author
    }

    /// Hash of the entry this one chains from.
    pub fn prev(&self) -> [u8; 32] {
        self.unsigned.prev
    }

    /// Issue time, milliseconds since the Unix epoch.
    pub fn issued_at_ms(&self) -> u64 {
        self.unsigned.issued_at_ms
    }

    /// The raw signature, for storage.
    pub fn signature(&self) -> &[u8; 64] {
        &self.signature
    }

    /// Verify the entry against the author's signing key, recomputing the id.
    fn verify(&self, author_signing_key: &[u8; 32]) -> Result<()> {
        if self.unsigned.id() != self.id {
            return Err(Error::Signature);
        }
        if DeviceId::from_signing_public(author_signing_key) != self.unsigned.author {
            return Err(Error::Signature);
        }
        let key = VerifyingKey::from_bytes(author_signing_key).map_err(|_| Error::InvalidKey)?;
        key.verify_strict(&self.id, &Signature::from_bytes(&self.signature))
            .map_err(|_| Error::Signature)
    }

    /// Reassemble from stored parts. Unvalidated.
    pub fn from_parts(unsigned: UnsignedAclEntry, id: [u8; 32], signature: [u8; 64]) -> Self {
        Self {
            unsigned,
            id,
            signature,
        }
    }
}

/// One member's entry in the access control list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    device: DevicePublic,
    role: Role,
}

impl Member {
    /// The member's device.
    pub fn device(&self) -> &DevicePublic {
        &self.device
    }

    /// The member's role.
    pub fn role(&self) -> Role {
        self.role
    }
}

/// The materialized access control list for one vault.
#[derive(Debug, Clone)]
pub struct Acl {
    vault: VaultId,
    members: BTreeMap<DeviceId, Member>,
    epoch: Epoch,
    head: [u8; 32],
    seq: u64,
}

impl Acl {
    /// Create the genesis ACL, with `owner` as the sole owner.
    ///
    /// The genesis entry is self-authorizing: there is nobody to approve it.
    /// Every subsequent entry chains from here.
    pub fn genesis(vault: VaultId, owner: &DevicePublic) -> Self {
        let mut members = BTreeMap::new();
        members.insert(
            owner.id(),
            Member {
                device: owner.clone(),
                role: Role::Owner,
            },
        );
        Self {
            vault,
            members,
            epoch: Epoch::INITIAL,
            head: *blake3::hash(vault.as_bytes()).as_bytes(),
            seq: 0,
        }
    }

    /// The current key epoch.
    pub fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// The hash of the most recent entry. New entries must chain from this.
    pub fn head(&self) -> [u8; 32] {
        self.head
    }

    /// The sequence number the next entry must carry.
    pub fn next_seq(&self) -> u64 {
        self.seq + 1
    }

    /// A device's role, if it is a member.
    pub fn role(&self, device: DeviceId) -> Option<Role> {
        self.members.get(&device).map(|m| m.role)
    }

    /// All current members, ordered by device id.
    pub fn members(&self) -> impl Iterator<Item = (&DeviceId, &Member)> {
        self.members.iter()
    }

    /// Devices that should receive a wrapped vault key, i.e. everyone who can
    /// read. Spec §6 step 3 re-wraps for exactly this set.
    pub fn key_recipients(&self) -> impl Iterator<Item = &DevicePublic> {
        self.members.values().map(|m| &m.device)
    }

    fn owner_count(&self) -> usize {
        self.members
            .values()
            .filter(|m| m.role == Role::Owner)
            .count()
    }

    /// Validate and apply one entry.
    ///
    /// Rejects anything out of sequence, off-chain, unsigned, from a non-member,
    /// or beyond the author's authority. On any error the ACL is unchanged.
    pub fn apply(&mut self, entry: &AclEntry) -> Result<()> {
        if entry.unsigned.vault != self.vault {
            return Err(Error::AclRejected("entry belongs to another vault"));
        }
        if entry.unsigned.seq != self.next_seq() {
            return Err(Error::AclRejected("entry is out of sequence"));
        }
        if entry.unsigned.prev != self.head {
            return Err(Error::AclRejected("entry does not chain from the head"));
        }

        let author = self
            .members
            .get(&entry.unsigned.author)
            .ok_or(Error::AclRejected("author is not a member"))?;
        let author_role = author.role;
        entry.verify(author.device.signing_public())?;

        if !author_role.can_manage_acl() {
            return Err(Error::AclRejected("author may not modify the ACL"));
        }

        match &entry.unsigned.op {
            AclOp::AddMember { device, role } => {
                if self.members.contains_key(&device.id()) {
                    return Err(Error::AclRejected("device is already a member"));
                }
                if !author_role.can_manage(*role) {
                    return Err(Error::AclRejected("author may not grant that role"));
                }
                self.members.insert(
                    device.id(),
                    Member {
                        device: device.clone(),
                        role: *role,
                    },
                );
            }

            AclOp::RemoveMember { device } => {
                let target = self
                    .members
                    .get(device)
                    .ok_or(Error::AclRejected("device is not a member"))?;
                if !author_role.can_manage(target.role) && *device != entry.unsigned.author {
                    return Err(Error::AclRejected("author may not remove that member"));
                }
                if target.role == Role::Owner && self.owner_count() == 1 {
                    return Err(Error::AclRejected("cannot remove the last owner"));
                }
                self.members.remove(device);
            }

            AclOp::ChangeRole { device, role } => {
                let target = self
                    .members
                    .get(device)
                    .ok_or(Error::AclRejected("device is not a member"))?;
                if !author_role.can_manage(target.role) || !author_role.can_manage(*role) {
                    return Err(Error::AclRejected("author may not set that role"));
                }
                if target.role == Role::Owner && *role != Role::Owner && self.owner_count() == 1 {
                    return Err(Error::AclRejected("cannot demote the last owner"));
                }
                self.members.entry(*device).and_modify(|m| m.role = *role);
            }

            AclOp::RotateKey { epoch } => {
                if *epoch != self.epoch.next() {
                    return Err(Error::AclRejected(
                        "rotation must advance exactly one epoch",
                    ));
                }
                self.epoch = *epoch;
            }
        }

        self.head = entry.id;
        self.seq = entry.unsigned.seq;
        Ok(())
    }
}

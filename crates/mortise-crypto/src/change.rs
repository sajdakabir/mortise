//! The signed, hash-linked change log: spec §5.
//!
//! Every mutation is an immutable change, identified by the BLAKE3 digest of
//! its canonical encoding and signed by the authoring device. Changes reference
//! their parents, so the log is a DAG rather than a line — two devices editing
//! offline both extend from a common ancestor and merge cleanly.
//!
//! This is what makes a hostile relay (A1) unable to forge or reorder history:
//! a client rejects any change whose signature fails, whose id does not match
//! its contents, or whose parents it has never seen.

use ed25519_dalek::{Signature, VerifyingKey};

use crate::encode::{Canonical, Tag, Writer};
use crate::error::{Error, Result};
use crate::identity::{Device, DeviceId};
use crate::vault::{Epoch, VaultId};

/// A hybrid logical clock.
///
/// Wall-clock milliseconds paired with a counter that breaks ties when events
/// happen inside the same millisecond, or when a device's clock is behind. The
/// counter is what stops a skewed clock from silently losing writes — unlike a
/// bare timestamp, an HLC never goes backwards.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Hlc {
    /// Wall-clock milliseconds since the Unix epoch. Ordered first.
    pub wall_ms: u64,
    /// Tie-breaking counter within a millisecond.
    pub counter: u32,
}

impl Hlc {
    /// A clock at the given wall time with a zero counter.
    pub fn new(wall_ms: u64) -> Self {
        Self {
            wall_ms,
            counter: 0,
        }
    }

    /// Advance for a local event observed at `now_ms`.
    pub fn tick(self, now_ms: u64) -> Self {
        if now_ms > self.wall_ms {
            Self::new(now_ms)
        } else {
            Self {
                wall_ms: self.wall_ms,
                counter: self.counter.saturating_add(1),
            }
        }
    }

    /// Advance on receiving `remote`, observed locally at `now_ms`.
    ///
    /// The standard HLC merge. The result is strictly greater than both inputs,
    /// so causality is preserved even when the remote device's clock is ahead.
    pub fn merge(self, remote: Hlc, now_ms: u64) -> Self {
        let wall = self.wall_ms.max(remote.wall_ms).max(now_ms);

        let counter = if wall == self.wall_ms && wall == remote.wall_ms {
            self.counter.max(remote.counter).saturating_add(1)
        } else if wall == self.wall_ms {
            self.counter.saturating_add(1)
        } else if wall == remote.wall_ms {
            remote.counter.saturating_add(1)
        } else {
            0
        };

        Self {
            wall_ms: wall,
            counter,
        }
    }
}

/// A change identifier: BLAKE3 over the change's canonical encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ChangeId([u8; 32]);

impl ChangeId {
    /// Raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Wrap raw bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// A change before it has been signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsignedChange {
    vault: VaultId,
    epoch: Epoch,
    parents: Vec<ChangeId>,
    hlc: Hlc,
    author: DeviceId,
    payload: Vec<u8>,
}

impl UnsignedChange {
    /// Build a change.
    ///
    /// Parents are **sorted here**. They are a set, not a sequence, so leaving
    /// caller order intact would mean two devices encoding the same logical
    /// change into different bytes and computing different ids.
    pub fn new(
        vault: VaultId,
        epoch: Epoch,
        mut parents: Vec<ChangeId>,
        hlc: Hlc,
        author: DeviceId,
        payload: Vec<u8>,
    ) -> Self {
        parents.sort_unstable();
        parents.dedup();
        Self {
            vault,
            epoch,
            parents,
            hlc,
            author,
            payload,
        }
    }

    /// The id this change will have once signed.
    pub fn id(&self) -> ChangeId {
        ChangeId(self.canonical_digest())
    }

    /// Sign with the authoring device.
    ///
    /// The device must be the one named in `author`, or the resulting change
    /// will not verify.
    pub fn sign(self, device: &Device) -> Change {
        let id = self.id();
        let signature = device.sign(id.as_bytes());
        Change {
            unsigned: self,
            id,
            signature,
        }
    }
}

impl Canonical for UnsignedChange {
    fn tag() -> Tag {
        Tag::Change
    }

    fn encode(&self, w: &mut Writer) {
        w.fixed(self.vault.as_bytes())
            .u32(self.epoch.value())
            .fixed_seq(self.parents.iter().map(|p| p.as_bytes()))
            .u64(self.hlc.wall_ms)
            .u32(self.hlc.counter)
            .fixed(self.author.as_bytes())
            .bytes(&self.payload);
    }
}

/// A signed change, as stored and synced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    unsigned: UnsignedChange,
    id: ChangeId,
    signature: [u8; 64],
}

impl Change {
    /// The change identifier.
    pub fn id(&self) -> ChangeId {
        self.id
    }

    /// The vault this change belongs to.
    pub fn vault(&self) -> VaultId {
        self.unsigned.vault
    }

    /// The key epoch in force when this change was made.
    pub fn epoch(&self) -> Epoch {
        self.unsigned.epoch
    }

    /// The changes this one extends.
    pub fn parents(&self) -> &[ChangeId] {
        &self.unsigned.parents
    }

    /// The authoring device.
    pub fn author(&self) -> DeviceId {
        self.unsigned.author
    }

    /// The logical timestamp.
    pub fn hlc(&self) -> Hlc {
        self.unsigned.hlc
    }

    /// The encrypted payload. Opaque to this crate.
    pub fn payload(&self) -> &[u8] {
        &self.unsigned.payload
    }

    /// The raw signature.
    pub fn signature(&self) -> &[u8; 64] {
        &self.signature
    }

    /// Verify the change against the authoring device's public key.
    ///
    /// Recomputes the id from the contents rather than trusting the stored one.
    /// Skipping that would let a relay ship altered contents under a valid
    /// signature over the original id.
    ///
    /// The caller must separately confirm that `author` is in the ACL at
    /// `epoch` — a well-formed signature from a non-member is still a change
    /// that must be rejected.
    pub fn verify(&self, author_signing_key: &[u8; 32]) -> Result<()> {
        let recomputed = self.unsigned.id();
        if recomputed != self.id {
            return Err(Error::Signature);
        }
        if DeviceId::from_signing_public(author_signing_key) != self.unsigned.author {
            return Err(Error::Signature);
        }

        let key = VerifyingKey::from_bytes(author_signing_key).map_err(|_| Error::InvalidKey)?;
        key.verify_strict(self.id.as_bytes(), &Signature::from_bytes(&self.signature))
            .map_err(|_| Error::Signature)
    }

    /// Reassemble from stored parts. Unvalidated; call [`Change::verify`].
    pub fn from_parts(unsigned: UnsignedChange, id: ChangeId, signature: [u8; 64]) -> Self {
        Self {
            unsigned,
            id,
            signature,
        }
    }

    /// Total order for last-write-wins merging: HLC first, then device id.
    ///
    /// Spec §5. The device tiebreak is what makes the order total — without it
    /// two devices could disagree about which of two concurrent writes won.
    pub fn merge_order(&self) -> (Hlc, DeviceId) {
        (self.unsigned.hlc, self.unsigned.author)
    }
}

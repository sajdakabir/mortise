//! The sync wire protocol and request signing.
//!
//! Shared by the relay and its clients, so there is one definition of what a
//! signed request looks like rather than two that can drift.
//!
//! # How the relay authenticates
//!
//! There are no accounts and no passwords. A request is authenticated by an
//! Ed25519 signature from a device the relay already knows belongs to that
//! vault. The relay therefore needs a per-vault list of device public keys —
//! which is exactly the metadata leak recorded against A1 in the threat model.
//! The relay learns *who syncs with whom*; it never learns what they sync.
//!
//! The signature covers the method, path, timestamp and a hash of the body, so
//! a captured request cannot be replayed against a different endpoint or with
//! altered contents. The timestamp bounds replay of the request itself.

use serde::{Deserialize, Serialize};

/// Header carrying the hex device id.
pub const HEADER_DEVICE: &str = "x-tp-device";
/// Header carrying the unix-millisecond timestamp.
pub const HEADER_TIMESTAMP: &str = "x-tp-timestamp";
/// Header carrying the hex Ed25519 signature.
pub const HEADER_SIGNATURE: &str = "x-tp-signature";

/// How far a request's timestamp may be from the relay's clock.
///
/// Five minutes is enough for ordinary clock skew and not much more. It bounds
/// how long a captured request stays replayable — which matters less than it
/// sounds, since every request is already bound to its own body and path, but
/// a push could otherwise be replayed indefinitely to waste storage.
pub const MAX_CLOCK_SKEW_MS: i64 = 5 * 60 * 1000;

/// Bytes a request's signature is computed over.
///
/// Built with length prefixes for the same reason as the browser proof: without
/// them, different field splits could produce identical signed bytes.
pub fn signing_payload(method: &str, path: &str, timestamp_ms: i64, body: &[u8]) -> Vec<u8> {
    let body_hash = blake3::hash(body);

    let mut out = Vec::new();
    let mut push = |part: &[u8]| {
        out.extend_from_slice(&(part.len() as u32).to_be_bytes());
        out.extend_from_slice(part);
    };

    push(b"truepass/relay/v1");
    push(method.as_bytes());
    push(path.as_bytes());
    push(&timestamp_ms.to_be_bytes());
    push(body_hash.as_bytes());
    out
}

/// Claim a vault id, registering the first device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimVault {
    /// The vault being claimed.
    pub vault_id: String,
    /// Hex Ed25519 public key of the claiming device.
    pub device_signing_key: String,
}

/// Authorize another device to sync this vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddDevice {
    /// Hex device id.
    pub device_id: String,
    /// Hex Ed25519 public key.
    pub device_signing_key: String,
}

/// One stored change, as it travels to and from the relay.
///
/// Every field here is either opaque ciphertext or metadata the relay needs to
/// order and deduplicate. It can read none of the contents.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WireChange {
    /// Hex change id.
    pub id: String,
    /// Key epoch, for clients to pick the right key.
    pub epoch: u32,
    /// Hybrid logical clock, wall component.
    pub hlc_wall: u64,
    /// Hybrid logical clock, counter component.
    pub hlc_counter: u32,
    /// Hex device id of the author.
    pub author: String,
    /// Hex parent change ids.
    pub parents: Vec<String>,
    /// Base64 sealed payload. Opaque.
    pub payload: String,
    /// Hex Ed25519 signature.
    pub signature: String,
}

/// Request body for a push.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushRequest {
    /// Changes to store.
    pub changes: Vec<WireChange>,
}

/// Response to a push.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushResponse {
    /// Changes newly stored.
    pub accepted: u32,
    /// Changes the relay already had.
    pub duplicates: u32,
    /// Sequence number to resume pulling from.
    pub cursor: u64,
}

/// Response to a pull.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PullResponse {
    /// Changes after the requested cursor.
    pub changes: Vec<WireChange>,
    /// Cursor to pass next time.
    pub cursor: u64,
    /// Whether more remain beyond this page.
    pub more: bool,
}

/// One ACL entry as it travels to and from the relay.
///
/// The relay cannot read the operation and cannot tell an owner from a viewer
/// — roles live inside `op_body`, which is only meaningful to a client that
/// has replayed the log. It stores these verbatim and hands them back in
/// order. Everything that matters is checked on the client: the signature, the
/// author's role at that point in the log, and the `prev` chain.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WireAclEntry {
    /// Position in the log. Unique per vault, and the relay's cursor.
    pub seq: u64,
    /// Hex entry id.
    pub id: String,
    /// Hex id of the previous entry.
    pub prev: String,
    /// Operation discriminant.
    pub op_kind: u8,
    /// Hex operation body.
    pub op_body: String,
    /// Hex device id of the issuing device.
    pub author: String,
    /// Issue time, in unix milliseconds.
    pub issued_at_ms: u64,
    /// Hex Ed25519 signature over the entry.
    pub signature: String,
}

/// A vault key sealed to one device, in transit.
///
/// `sender` is a device id rather than a key: the recipient resolves the
/// sealing device's X25519 key from its own replayed ACL log and checks that
/// the device held an admin role, so a relay cannot nominate the sender by
/// putting a key of its choosing in the payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WireWrappedKey {
    /// Hex device id this key is sealed to.
    pub recipient: String,
    /// Hex device id of the device that sealed it.
    pub sender: String,
    /// Key epoch.
    pub epoch: u32,
    /// Base64 sealed key. Opaque.
    pub blob: String,
}

/// Request body for an ACL push.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AclPushRequest {
    /// Entries to store.
    pub entries: Vec<WireAclEntry>,
}

/// Response to an ACL pull.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AclPullResponse {
    /// Entries after the requested sequence number, in order.
    pub entries: Vec<WireAclEntry>,
    /// Whether more remain beyond this page.
    pub more: bool,
}

/// Request body for a wrapped-key push.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPushRequest {
    /// Keys to store, each addressed to one device.
    pub keys: Vec<WireWrappedKey>,
}

/// Response to a wrapped-key pull.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPullResponse {
    /// Keys addressed to the calling device.
    pub keys: Vec<WireWrappedKey>,
}

/// What a push of ACL entries or keys did.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreCounts {
    /// Newly stored.
    pub accepted: u32,
    /// Already present, and left alone.
    pub duplicates: u32,
}

/// An error from the relay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorBody {
    /// Stable machine-readable code.
    pub code: String,
    /// Human-readable detail. Never contains vault contents.
    pub message: String,
}

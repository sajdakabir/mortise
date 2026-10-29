//! Converting changes to and from the relay's wire shape.
//!
//! The relay needs a few fields in the clear to order and deduplicate — id,
//! clock, author, parents. Everything that could reveal content stays inside
//! the sealed payload it cannot open.
//!
//! Conversion back is fallible and returns `None` on anything malformed. A
//! relay is untrusted, so a field it mangled must not panic a client or, worse,
//! decode into something plausible.

use data_encoding::BASE64;
use mortise_crypto::acl::AclEntry;
use mortise_crypto::change::{Change, ChangeId, Hlc, UnsignedChange};
use mortise_crypto::identity::DeviceId;
use mortise_crypto::vault::{Epoch, VaultId};
use mortise_relay::protocol::{WireAclEntry, WireChange};
use mortise_vault::access::AclEntryRecord;

/// Lowercase hex.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Parse hex into a fixed-size array.
pub fn unhex<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        out[i] = u8::from_str_radix(core::str::from_utf8(chunk).ok()?, 16).ok()?;
    }
    Some(out)
}

/// Render a change for the relay.
pub fn to_wire(change: &Change) -> WireChange {
    WireChange {
        id: hex(change.id().as_bytes()),
        epoch: change.epoch().value(),
        hlc_wall: change.hlc().wall_ms,
        hlc_counter: change.hlc().counter,
        author: hex(change.author().as_bytes()),
        parents: change.parents().iter().map(|p| hex(p.as_bytes())).collect(),
        payload: BASE64.encode(change.payload()),
        signature: hex(change.signature()),
    }
}

/// Rebuild a change from the relay's representation.
///
/// Does **not** verify the signature — that is `mortise_vault::ingest`'s job,
/// and doing it in two places invites one of them drifting. This only ensures
/// the shape is well formed.
pub fn from_wire(wire: &WireChange, vault: VaultId) -> Option<Change> {
    let id = ChangeId::from_bytes(unhex::<32>(&wire.id)?);
    let author = DeviceId::from_bytes(unhex::<16>(&wire.author)?);
    let signature = unhex::<64>(&wire.signature)?;
    let payload = BASE64.decode(wire.payload.as_bytes()).ok()?;

    let parents = wire
        .parents
        .iter()
        .map(|p| unhex::<32>(p).map(ChangeId::from_bytes))
        .collect::<Option<Vec<_>>>()?;

    let unsigned = UnsignedChange::new(
        vault,
        Epoch(wire.epoch),
        parents,
        Hlc {
            wall_ms: wire.hlc_wall,
            counter: wire.hlc_counter,
        },
        author,
        payload,
    );

    Some(Change::from_parts(unsigned, id, signature))
}

/// Render an ACL entry for the relay.
pub fn acl_to_wire(entry: &AclEntry) -> WireAclEntry {
    let rec = AclEntryRecord::from_entry(entry);
    WireAclEntry {
        seq: rec.seq,
        id: hex(&rec.id),
        prev: hex(&rec.prev),
        op_kind: rec.op_kind,
        op_body: BASE64.encode(&rec.op_body),
        author: hex(&rec.author),
        issued_at_ms: rec.issued_at_ms,
        signature: hex(&rec.signature),
    }
}

/// Rebuild an ACL entry from the relay's representation.
///
/// Like [`from_wire`], does not verify the signature — `apply_acl_entry` does —
/// and returns `None` on anything malformed, so a relay cannot panic a client.
pub fn acl_from_wire(wire: &WireAclEntry, vault: VaultId) -> Option<AclEntry> {
    let rec = AclEntryRecord {
        seq: wire.seq,
        id: unhex::<32>(&wire.id)?,
        prev: unhex::<32>(&wire.prev)?,
        op_kind: wire.op_kind,
        op_body: BASE64.decode(wire.op_body.as_bytes()).ok()?,
        author: unhex::<16>(&wire.author)?,
        issued_at_ms: wire.issued_at_ms,
        signature: unhex::<64>(&wire.signature)?.to_vec(),
    };
    rec.to_entry(vault)
}

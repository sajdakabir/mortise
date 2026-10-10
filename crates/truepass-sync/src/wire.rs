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
use truepass_crypto::change::{Change, ChangeId, Hlc, UnsignedChange};
use truepass_crypto::identity::DeviceId;
use truepass_crypto::vault::{Epoch, VaultId};
use truepass_relay::protocol::WireChange;

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
/// Does **not** verify the signature — that is `truepass_vault::ingest`'s job,
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

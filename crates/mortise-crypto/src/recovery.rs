//! The recovery kit: spec §7.
//!
//! The account key is 256 bits of randomness the user must keep. It is shown
//! once, at onboarding, and never again. Both the master password *and* this
//! key are required to unlock — the kit alone is not a bypass, and neither is
//! the password alone.
//!
//! Losing both means the data is gone. There is no escrow, no reset, and no
//! support path. That is the design working, not a bug, and the onboarding UI
//! has to say so plainly rather than burying it.
//!
//! Format: `TP1-XXXXX-XXXXX-…`, base32 over the key plus a 2-byte checksum.
//! RFC 4648 base32 excludes `0`, `1` and `8`, so the usual `0`/`O` and `1`/`I`
//! transcription confusions cannot arise. The checksum catches the rest before
//! the user sits through a 64 MiB Argon2 run that was never going to succeed.

use data_encoding::BASE32_NOPAD;
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::secret::Key32;

/// Version prefix. Bump if the encoding ever changes.
pub const PREFIX: &str = "TP1";

/// Characters per dash-separated group.
const GROUP: usize = 5;

/// Bytes of BLAKE3 appended as a transcription checksum.
const CHECKSUM_LEN: usize = 2;

/// Render an account key as a recovery kit string.
///
/// Every buffer on the way is `Zeroizing`, including the returned string. The
/// account key is the one secret with no replacement path — spec §9 says never
/// to hold key material in a plain `String`, and this is the worst place to
/// make an exception. Capacities are reserved up front so a reallocation
/// cannot strand a half-copy in freed heap that the wipe never reaches.
pub fn encode(account_key: &Key32) -> Zeroizing<String> {
    let mut payload = Zeroizing::new(Vec::with_capacity(32 + CHECKSUM_LEN));
    payload.extend_from_slice(account_key.expose());
    payload.extend_from_slice(&checksum(account_key.expose()));

    let encoded = Zeroizing::new(BASE32_NOPAD.encode(&payload));

    let mut out = Zeroizing::new(String::with_capacity(
        PREFIX.len() + encoded.len() + encoded.len() / GROUP + 1,
    ));
    out.push_str(PREFIX);
    for (i, ch) in encoded.chars().enumerate() {
        if i % GROUP == 0 {
            out.push('-');
        }
        out.push(ch);
    }
    out
}

/// Parse a recovery kit string back into an account key.
///
/// Tolerant of the ways people retype things: lowercase, missing or extra
/// dashes, surrounding whitespace, and a missing prefix are all accepted. What
/// is not tolerated is a failed checksum.
pub fn decode(kit: &str) -> Result<Key32> {
    let mut cleaned = Zeroizing::new(String::with_capacity(kit.len()));
    for ch in kit.trim().chars() {
        if !ch.is_whitespace() && ch != '-' {
            cleaned.push(ch.to_ascii_uppercase());
        }
    }

    let body = cleaned
        .strip_prefix(&PREFIX.to_ascii_uppercase())
        .unwrap_or(&cleaned);

    let payload = Zeroizing::new(
        BASE32_NOPAD
            .decode(body.as_bytes())
            .map_err(|_| Error::RecoveryKit)?,
    );

    if payload.len() != 32 + CHECKSUM_LEN {
        return Err(Error::RecoveryKit);
    }

    let (key_bytes, given) = payload.split_at(32);
    if checksum(key_bytes) != given {
        return Err(Error::RecoveryKit);
    }

    Key32::from_slice(key_bytes)
}

fn checksum(key_bytes: &[u8]) -> [u8; CHECKSUM_LEN] {
    let digest = blake3::hash(key_bytes);
    let mut out = [0u8; CHECKSUM_LEN];
    out.copy_from_slice(&digest.as_bytes()[..CHECKSUM_LEN]);
    out
}

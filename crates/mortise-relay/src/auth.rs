//! Request authentication.
//!
//! No accounts, no passwords, no bearer tokens. A request is authenticated by
//! an Ed25519 signature from a device the relay already knows belongs to that
//! vault.
//!
//! # What the relay deliberately does not verify
//!
//! It does **not** check the signature on each individual change. It could —
//! it has the device keys — but it would have to reconstruct the canonical
//! change encoding, which welds the relay to the client's data format: a client
//! upgrade would need a relay upgrade in lockstep.
//!
//! More importantly it would buy nothing. Clients do not trust the relay, so
//! they verify every change on ingest regardless (see `mortise_vault::ingest`).
//! A second check by an untrusted party adds coupling, not a guarantee.
//!
//! What the request signature *does* establish is that the pusher is a member
//! of this vault, which is what stops a stranger filling the relay's disk.

use mortise_crypto::identity::DeviceId;

use crate::protocol::{MAX_CLOCK_SKEW_MS, signing_payload};

/// Why a request was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AuthError {
    /// A required header was absent or unparseable.
    #[error("missing or malformed authentication headers")]
    MalformedHeaders,
    /// The timestamp is too far from the relay's clock.
    #[error("request timestamp is outside the accepted window")]
    StaleTimestamp,
    /// The device is not on this vault's allowlist.
    #[error("device is not authorized for this vault")]
    UnknownDevice,
    /// The signature did not verify.
    #[error("signature verification failed")]
    BadSignature,
}

/// The pieces a signed request carries.
#[derive(Debug, Clone)]
pub struct SignedRequest<'a> {
    /// HTTP method.
    pub method: &'a str,
    /// Request path.
    pub path: &'a str,
    /// Hex device id.
    pub device_id: &'a str,
    /// Client's unix-millisecond timestamp.
    pub timestamp_ms: i64,
    /// Hex Ed25519 signature.
    pub signature: &'a str,
    /// Raw body.
    pub body: &'a [u8],
}

/// Verify a signed request against a known signing key.
///
/// `now_ms` is passed in rather than read from the clock so the window logic
/// can be tested without sleeping.
pub fn verify(
    request: &SignedRequest<'_>,
    signing_key_hex: &str,
    now_ms: i64,
) -> Result<(), AuthError> {
    if (now_ms - request.timestamp_ms).abs() > MAX_CLOCK_SKEW_MS {
        return Err(AuthError::StaleTimestamp);
    }

    let key_bytes: [u8; 32] = unhex(signing_key_hex)
        .and_then(|b| b.try_into().ok())
        .ok_or(AuthError::MalformedHeaders)?;
    let signature: [u8; 64] = unhex(request.signature)
        .and_then(|b| b.try_into().ok())
        .ok_or(AuthError::MalformedHeaders)?;

    // The device id must match the key it claims. Without this a member could
    // sign as themselves while naming another device as the author.
    let claimed: [u8; 16] = unhex(request.device_id)
        .and_then(|b| b.try_into().ok())
        .ok_or(AuthError::MalformedHeaders)?;
    if DeviceId::from_signing_public(&key_bytes) != DeviceId::from_bytes(claimed) {
        return Err(AuthError::UnknownDevice);
    }

    let payload = signing_payload(
        request.method,
        request.path,
        request.timestamp_ms,
        request.body,
    );
    let digest = blake3::hash(&payload);

    let key = ed25519_verifying_key(&key_bytes).ok_or(AuthError::MalformedHeaders)?;
    key.verify_strict(digest.as_bytes(), &ed25519_signature(&signature))
        .map_err(|_| AuthError::BadSignature)
}

/// Sign a request. Used by clients and by the relay's own tests.
pub fn sign(
    device: &mortise_crypto::identity::Device,
    method: &str,
    path: &str,
    timestamp_ms: i64,
    body: &[u8],
) -> String {
    let payload = signing_payload(method, path, timestamp_ms, body);
    let digest = blake3::hash(&payload);
    hex(&device.sign(digest.as_bytes()))
}

fn ed25519_verifying_key(bytes: &[u8; 32]) -> Option<ed25519_dalek_reexport::VerifyingKey> {
    ed25519_dalek_reexport::VerifyingKey::from_bytes(bytes).ok()
}

fn ed25519_signature(bytes: &[u8; 64]) -> ed25519_dalek_reexport::Signature {
    ed25519_dalek_reexport::Signature::from_bytes(bytes)
}

/// Re-exported through mortise-crypto so the relay and the client agree on a
/// single ed25519 version. Two copies in one dependency graph would typecheck
/// and then fail to verify each other's signatures.
mod ed25519_dalek_reexport {
    pub use mortise_crypto::ed25519::{Signature, VerifyingKey};
}

/// Lowercase hex.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Parse lowercase or uppercase hex.
pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    s.as_bytes()
        .chunks(2)
        .map(|c| u8::from_str_radix(core::str::from_utf8(c).ok()?, 16).ok())
        .collect()
}

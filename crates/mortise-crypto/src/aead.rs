//! Authenticated encryption: spec §1, §3.
//!
//! XChaCha20-Poly1305 with a 192-bit nonce. The extended nonce is the whole
//! reason for choosing XChaCha over ChaCha: at 24 bytes, random nonces have a
//! negligible collision probability, so we never have to maintain a counter or
//! worry about nonce reuse across devices that cannot coordinate.
//!
//! Sealed layout: `nonce (24) ‖ ciphertext ‖ tag (16)`.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::secret::Key32;

/// Nonce length in bytes.
pub const NONCE_LEN: usize = 24;
/// Poly1305 tag length in bytes.
pub const TAG_LEN: usize = 16;
/// Smallest possible sealed output: nonce + tag, with empty plaintext.
pub const MIN_SEALED_LEN: usize = NONCE_LEN + TAG_LEN;

/// Encrypt `plaintext` under `key`, binding `aad` to the result.
///
/// `aad` is authenticated but not encrypted. Spec §3 requires callers to bind
/// each item's ciphertext to its own identity this way, so a hostile relay
/// cannot move one item's blob into another item's slot.
pub fn seal(key: &Key32, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new_from_slice(key.expose()).map_err(|_| Error::Encrypt)?;
    let nonce_bytes = crate::rand::bytes::<NONCE_LEN>()?;
    let nonce = XNonce::from(nonce_bytes);

    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::Encrypt)?;

    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt a buffer produced by [`seal`], verifying `aad` matches.
///
/// The plaintext comes back in a [`Zeroizing`] wrapper so it is wiped when the
/// caller drops it. Any failure — wrong key, tampered ciphertext, mismatched
/// aad, truncated input — returns the same opaque [`Error::Decrypt`].
pub fn open(key: &Key32, sealed: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if sealed.len() < MIN_SEALED_LEN {
        return Err(Error::Decrypt);
    }
    let (nonce_bytes, ciphertext) = sealed.split_at(NONCE_LEN);

    let cipher = XChaCha20Poly1305::new_from_slice(key.expose()).map_err(|_| Error::Decrypt)?;
    let nonce = XNonce::try_from(nonce_bytes).map_err(|_| Error::Decrypt)?;

    let plaintext = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| Error::Decrypt)?;

    Ok(Zeroizing::new(plaintext))
}

/// Wrap one key under another. Thin alias over [`seal`] to make key-wrapping
/// call sites read as what they are.
pub fn wrap_key(wrapping_key: &Key32, key: &Key32, aad: &[u8]) -> Result<Vec<u8>> {
    seal(wrapping_key, key.expose(), aad)
}

/// Unwrap a key sealed by [`wrap_key`].
pub fn unwrap_key(wrapping_key: &Key32, sealed: &[u8], aad: &[u8]) -> Result<Key32> {
    let bytes = open(wrapping_key, sealed, aad)?;
    Key32::from_slice(&bytes)
}

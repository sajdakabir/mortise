//! AEAD tests for spec §3.
//!
//! These assert the properties the threat model actually depends on, not just
//! that encryption round-trips. Each negative test names the adversary it
//! stands in for.

use mortise_crypto::aead::{self, MIN_SEALED_LEN, NONCE_LEN};
use mortise_crypto::error::Error;
use mortise_crypto::secret::Key32;
use proptest::prelude::*;

fn key(b: u8) -> Key32 {
    Key32::new([b; 32])
}

#[test]
fn round_trip() {
    let k = key(1);
    let sealed = aead::seal(&k, b"hunter2", b"item:42").unwrap();
    let opened = aead::open(&k, &sealed, b"item:42").unwrap();
    assert_eq!(&opened[..], b"hunter2");
}

#[test]
fn empty_plaintext_round_trips() {
    let k = key(1);
    let sealed = aead::seal(&k, b"", b"").unwrap();
    assert_eq!(sealed.len(), MIN_SEALED_LEN);
    assert!(aead::open(&k, &sealed, b"").unwrap().is_empty());
}

/// Adversary A1: a hostile relay with write access must not be able to move one
/// item's ciphertext into another item's slot. Spec §3 binds each blob to its
/// identity via the AAD; this is the test that the binding is load-bearing.
#[test]
fn aad_mismatch_is_rejected() {
    let k = key(1);
    let sealed = aead::seal(&k, b"secret", b"vault:1|item:42|v1").unwrap();

    assert_eq!(
        aead::open(&k, &sealed, b"vault:1|item:43|v1").unwrap_err(),
        Error::Decrypt,
        "ciphertext opened under a different item id"
    );
    assert_eq!(
        aead::open(&k, &sealed, b"").unwrap_err(),
        Error::Decrypt,
        "ciphertext opened with the aad stripped entirely"
    );
}

#[test]
fn wrong_key_is_rejected() {
    let sealed = aead::seal(&key(1), b"secret", b"aad").unwrap();
    assert_eq!(
        aead::open(&key(2), &sealed, b"aad").unwrap_err(),
        Error::Decrypt
    );
}

/// Every single-bit change anywhere in the sealed buffer — nonce, ciphertext or
/// tag — must fail authentication.
#[test]
fn any_single_bit_flip_is_rejected() {
    let k = key(1);
    let sealed = aead::seal(&k, b"a moderately long secret value", b"aad").unwrap();

    for byte in 0..sealed.len() {
        for bit in 0..8 {
            let mut tampered = sealed.clone();
            tampered[byte] ^= 1 << bit;
            assert_eq!(
                aead::open(&k, &tampered, b"aad").unwrap_err(),
                Error::Decrypt,
                "flipping bit {bit} of byte {byte} was not detected"
            );
        }
    }
}

#[test]
fn truncated_input_is_rejected_without_panicking() {
    let k = key(1);
    let sealed = aead::seal(&k, b"secret", b"aad").unwrap();

    for len in 0..sealed.len() {
        assert_eq!(
            aead::open(&k, &sealed[..len], b"aad").unwrap_err(),
            Error::Decrypt,
            "truncation to {len} bytes was mishandled"
        );
    }
}

/// XChaCha20-Poly1305 is chosen for its 192-bit nonce precisely so random
/// nonces are safe (spec §1). If seal ever became deterministic, identical
/// plaintexts would leak equality — and nonce reuse under one key is
/// catastrophic for this construction.
#[test]
fn nonces_are_fresh_per_seal() {
    let k = key(1);
    let a = aead::seal(&k, b"same plaintext", b"same aad").unwrap();
    let b = aead::seal(&k, b"same plaintext", b"same aad").unwrap();

    assert_ne!(a[..NONCE_LEN], b[..NONCE_LEN], "nonce was reused");
    assert_ne!(
        a, b,
        "seal is deterministic; identical plaintexts are linkable"
    );
}

#[test]
fn key_wrap_round_trips() {
    let wrapping = key(9);
    let inner = Key32::random().unwrap();

    let sealed = aead::wrap_key(&wrapping, &inner, b"epoch:1").unwrap();
    let unwrapped = aead::unwrap_key(&wrapping, &sealed, b"epoch:1").unwrap();
    assert_eq!(inner, unwrapped);
}

/// A wrapped key must not unwrap under the wrong epoch — this is what makes
/// key rotation (spec §6) meaningful rather than cosmetic.
#[test]
fn wrapped_key_is_bound_to_its_epoch() {
    let wrapping = key(9);
    let inner = Key32::random().unwrap();
    let sealed = aead::wrap_key(&wrapping, &inner, b"epoch:1").unwrap();

    assert_eq!(
        aead::unwrap_key(&wrapping, &sealed, b"epoch:2").unwrap_err(),
        Error::Decrypt
    );
}

#[test]
fn secret_debug_does_not_leak_bytes() {
    let k = Key32::new([0xAB; 32]);
    let printed = format!("{k:?}");
    assert!(!printed.contains("ab"), "Debug impl leaked key material");
    assert!(printed.contains("redacted"));
}

proptest! {
    #[test]
    fn round_trips_for_arbitrary_input(
        plaintext in proptest::collection::vec(any::<u8>(), 0..2048),
        aad in proptest::collection::vec(any::<u8>(), 0..256),
        key_bytes in any::<[u8; 32]>(),
    ) {
        let k = Key32::new(key_bytes);
        let sealed = aead::seal(&k, &plaintext, &aad).unwrap();
        let opened = aead::open(&k, &sealed, &aad).unwrap();
        prop_assert_eq!(&opened[..], &plaintext[..]);
    }

    #[test]
    fn any_aad_change_is_rejected(
        plaintext in proptest::collection::vec(any::<u8>(), 0..256),
        aad in proptest::collection::vec(any::<u8>(), 1..128),
        idx in any::<prop::sample::Index>(),
    ) {
        let k = Key32::new([7; 32]);
        let sealed = aead::seal(&k, &plaintext, &aad).unwrap();

        let mut other = aad.clone();
        let i = idx.index(other.len());
        other[i] = other[i].wrapping_add(1);

        prop_assert!(aead::open(&k, &sealed, &other).is_err());
    }
}

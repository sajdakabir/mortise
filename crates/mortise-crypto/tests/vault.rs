//! Vault key and rotation tests for spec §3 and §6.

use mortise_crypto::error::Error;
use mortise_crypto::identity::{Device, KexPublic};
use mortise_crypto::vault::{Epoch, VaultId, VaultKey, WrappedVaultKey};

/// The sender's X25519 public key, as the recipient must supply it to open an
/// authenticated blob.
fn kex(d: &Device) -> KexPublic {
    d.public().kex_public().unwrap()
}

#[test]
fn wrap_round_trips_to_the_intended_device() {
    let vault = VaultId::generate().unwrap();
    let device = Device::generate().unwrap();
    let vk = VaultKey::generate().unwrap();

    // The common case: a device sealing a key it holds to itself.
    let wrapped = vk.wrap_for(&device, device.public(), vault).unwrap();
    let opened = VaultKey::unwrap_for(&device, &wrapped, vault, &kex(&device)).unwrap();

    assert_eq!(vk, opened);
    assert_eq!(opened.epoch(), Epoch::INITIAL);
    assert_eq!(wrapped.sender_id(), Some(device.id()));
}

#[test]
fn another_device_cannot_unwrap() {
    let vault = VaultId::generate().unwrap();
    let admin = Device::generate().unwrap();
    let member = Device::generate().unwrap();
    let outsider = Device::generate().unwrap();

    let wrapped = VaultKey::generate()
        .unwrap()
        .wrap_for(&admin, member.public(), vault)
        .unwrap();

    assert_eq!(
        VaultKey::unwrap_for(&outsider, &wrapped, vault, &kex(&admin)).unwrap_err(),
        Error::Decrypt
    );
}

/// The point of Auth mode: a blob only opens if the sender it is authenticated
/// against is the one that actually sealed it. Claiming a different sender — or
/// substituting a blob an attacker sealed themselves — is rejected.
#[test]
fn a_forged_or_misattributed_sender_is_rejected() {
    let vault = VaultId::generate().unwrap();
    let admin = Device::generate().unwrap();
    let attacker = Device::generate().unwrap();
    let recipient = Device::generate().unwrap();
    let vk = VaultKey::generate().unwrap();

    let wrapped = vk.wrap_for(&admin, recipient.public(), vault).unwrap();

    // Authenticated against the real sender, it opens.
    assert!(VaultKey::unwrap_for(&recipient, &wrapped, vault, &kex(&admin)).is_ok());

    // Authenticated against anyone else, it does not.
    assert_eq!(
        VaultKey::unwrap_for(&recipient, &wrapped, vault, &kex(&attacker)).unwrap_err(),
        Error::Decrypt
    );

    // And a blob the attacker sealed themselves does not open as if it were the
    // admin's, even sealed to the right recipient.
    let forged = vk.wrap_for(&attacker, recipient.public(), vault).unwrap();
    assert_eq!(
        VaultKey::unwrap_for(&recipient, &forged, vault, &kex(&admin)).unwrap_err(),
        Error::Decrypt
    );
}

/// A wrapped key must not be transplantable into a different vault.
#[test]
fn wrapped_key_is_bound_to_its_vault() {
    let vault_a = VaultId::generate().unwrap();
    let vault_b = VaultId::generate().unwrap();
    let admin = Device::generate().unwrap();
    let device = Device::generate().unwrap();

    let wrapped = VaultKey::generate()
        .unwrap()
        .wrap_for(&admin, device.public(), vault_a)
        .unwrap();

    assert_eq!(
        VaultKey::unwrap_for(&device, &wrapped, vault_b, &kex(&admin)).unwrap_err(),
        Error::Decrypt
    );
}

/// Spec §6: the epoch is bound into the HPKE aad, so a wrapped key cannot be
/// relabelled as belonging to a different epoch.
#[test]
fn epoch_cannot_be_relabelled() {
    let vault = VaultId::generate().unwrap();
    let admin = Device::generate().unwrap();
    let device = Device::generate().unwrap();
    let vk = VaultKey::generate().unwrap();

    let wrapped = vk.wrap_for(&admin, device.public(), vault).unwrap();

    // Rewrite the epoch field in the serialized form. In the authenticated
    // layout it sits after the 1-byte tag and the 16-byte sender id.
    let mut bytes = wrapped.to_bytes();
    bytes[17..21].copy_from_slice(&7u32.to_be_bytes());
    let tampered = WrappedVaultKey::from_bytes(&bytes).unwrap();

    assert_eq!(tampered.epoch(), Epoch(7), "test setup failed");
    assert_eq!(
        VaultKey::unwrap_for(&device, &tampered, vault, &kex(&admin)).unwrap_err(),
        Error::Decrypt
    );
}

/// The sender id is bound into the aad, so relabelling it breaks the open even
/// though the blob is still structurally valid.
#[test]
fn sender_cannot_be_relabelled() {
    let vault = VaultId::generate().unwrap();
    let admin = Device::generate().unwrap();
    let device = Device::generate().unwrap();
    let vk = VaultKey::generate().unwrap();

    let wrapped = vk.wrap_for(&admin, device.public(), vault).unwrap();

    // Flip a byte of the recorded sender id.
    let mut bytes = wrapped.to_bytes();
    bytes[1] ^= 0xff;
    let tampered = WrappedVaultKey::from_bytes(&bytes).unwrap();
    assert_ne!(tampered.sender_id(), Some(admin.id()), "test setup failed");

    // Even authenticated against the real admin key, the mismatched aad fails.
    assert_eq!(
        VaultKey::unwrap_for(&device, &tampered, vault, &kex(&admin)).unwrap_err(),
        Error::Decrypt
    );
}

#[test]
fn rotation_produces_a_new_key_at_the_next_epoch() {
    let vk = VaultKey::generate().unwrap();
    let rotated = vk.rotate().unwrap();

    assert_ne!(vk.key(), rotated.key(), "rotation reused the key");
    assert_eq!(rotated.epoch(), Epoch(1));
    assert_eq!(rotated.rotate().unwrap().epoch(), Epoch(2));
}

/// The whole point of §6. After a member is removed, the vault rotates and
/// re-wraps for everyone who remains. The removed device must be unable to
/// unwrap the new key — forward secrecy, even though it keeps what it already
/// synced (threat model A8).
#[test]
fn a_revoked_device_cannot_unwrap_the_rotated_key() {
    let vault = VaultId::generate().unwrap();
    let admin = Device::generate().unwrap();
    let staying = Device::generate().unwrap();
    let removed = Device::generate().unwrap();

    let vk = VaultKey::generate().unwrap();
    let removed_copy = vk.wrap_for(&admin, removed.public(), vault).unwrap();
    assert!(
        VaultKey::unwrap_for(&removed, &removed_copy, vault, &kex(&admin)).is_ok(),
        "device should have access before revocation"
    );

    // Revoke: rotate, then re-wrap only for remaining members.
    let rotated = vk.rotate().unwrap();
    let staying_copy = rotated.wrap_for(&admin, staying.public(), vault).unwrap();

    assert!(VaultKey::unwrap_for(&staying, &staying_copy, vault, &kex(&admin)).is_ok());
    assert_eq!(
        VaultKey::unwrap_for(&removed, &staying_copy, vault, &kex(&admin)).unwrap_err(),
        Error::Decrypt,
        "revoked device could still unwrap the post-rotation key"
    );
}

#[test]
fn serialization_round_trips() {
    let vault = VaultId::generate().unwrap();
    let admin = Device::generate().unwrap();
    let device = Device::generate().unwrap();
    let wrapped = VaultKey::generate()
        .unwrap()
        .wrap_for(&admin, device.public(), vault)
        .unwrap();

    let parsed = WrappedVaultKey::from_bytes(&wrapped.to_bytes()).unwrap();
    assert_eq!(wrapped, parsed);
    assert!(VaultKey::unwrap_for(&device, &parsed, vault, &kex(&admin)).is_ok());
}

/// A pre-authentication Base-mode blob still parses and opens on the legacy
/// path, which is what lets an older vault be read and upgraded in place.
#[test]
fn legacy_blob_round_trips_and_opens() {
    let vault = VaultId::generate().unwrap();
    let device = Device::generate().unwrap();
    let vk = VaultKey::generate().unwrap();

    let wrapped = vk.wrap_legacy_for(device.public(), vault).unwrap();
    assert_eq!(wrapped.sender_id(), None);

    let parsed = WrappedVaultKey::from_bytes_legacy(&wrapped.to_bytes()).unwrap();
    assert_eq!(wrapped, parsed);

    let opened = VaultKey::unwrap_legacy(&device, &parsed, vault).unwrap();
    assert_eq!(vk, opened);

    // A legacy blob is not mistaken for an authenticated one.
    assert!(WrappedVaultKey::from_bytes(&wrapped.to_bytes()).is_err());
}

#[test]
fn malformed_wrapped_keys_are_rejected_without_panicking() {
    let vault = VaultId::generate().unwrap();
    let admin = Device::generate().unwrap();
    let device = Device::generate().unwrap();
    let bytes = VaultKey::generate()
        .unwrap()
        .wrap_for(&admin, device.public(), vault)
        .unwrap()
        .to_bytes();

    for len in 0..bytes.len() {
        match WrappedVaultKey::from_bytes(&bytes[..len]) {
            Err(_) => {}
            Ok(truncated) => {
                assert!(VaultKey::unwrap_for(&device, &truncated, vault, &kex(&admin)).is_err());
            }
        }
    }
}

/// Saturating rather than wrapping: a wrapping epoch would let an attacker who
/// can force 2^32 rotations replay a pre-rotation key.
#[test]
fn epoch_saturates_instead_of_wrapping() {
    assert_eq!(Epoch(u32::MAX).next(), Epoch(u32::MAX));
}

#[test]
fn each_wrap_is_fresh_even_for_the_same_recipient() {
    let vault = VaultId::generate().unwrap();
    let admin = Device::generate().unwrap();
    let device = Device::generate().unwrap();
    let vk = VaultKey::generate().unwrap();

    let a = vk.wrap_for(&admin, device.public(), vault).unwrap();
    let b = vk.wrap_for(&admin, device.public(), vault).unwrap();

    assert_ne!(a, b, "HPKE encapsulation is not producing a fresh key");
    assert_eq!(
        VaultKey::unwrap_for(&device, &a, vault, &kex(&admin)).unwrap(),
        VaultKey::unwrap_for(&device, &b, vault, &kex(&admin)).unwrap()
    );
}

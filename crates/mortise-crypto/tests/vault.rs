//! Vault key and rotation tests for spec §3 and §6.

use mortise_crypto::error::Error;
use mortise_crypto::identity::Device;
use mortise_crypto::vault::{Epoch, VaultId, VaultKey, WrappedVaultKey};

#[test]
fn wrap_round_trips_to_the_intended_device() {
    let vault = VaultId::generate().unwrap();
    let device = Device::generate().unwrap();
    let vk = VaultKey::generate().unwrap();

    let wrapped = vk.wrap_for(device.public(), vault).unwrap();
    let opened = VaultKey::unwrap_for(&device, &wrapped, vault).unwrap();

    assert_eq!(vk, opened);
    assert_eq!(opened.epoch(), Epoch::INITIAL);
}

#[test]
fn another_device_cannot_unwrap() {
    let vault = VaultId::generate().unwrap();
    let member = Device::generate().unwrap();
    let outsider = Device::generate().unwrap();

    let wrapped = VaultKey::generate()
        .unwrap()
        .wrap_for(member.public(), vault)
        .unwrap();

    assert_eq!(
        VaultKey::unwrap_for(&outsider, &wrapped, vault).unwrap_err(),
        Error::Decrypt
    );
}

/// A wrapped key must not be transplantable into a different vault.
#[test]
fn wrapped_key_is_bound_to_its_vault() {
    let vault_a = VaultId::generate().unwrap();
    let vault_b = VaultId::generate().unwrap();
    let device = Device::generate().unwrap();

    let wrapped = VaultKey::generate()
        .unwrap()
        .wrap_for(device.public(), vault_a)
        .unwrap();

    assert_eq!(
        VaultKey::unwrap_for(&device, &wrapped, vault_b).unwrap_err(),
        Error::Decrypt
    );
}

/// Spec §6: the epoch is bound into the HPKE aad, so a wrapped key cannot be
/// relabelled as belonging to a different epoch.
#[test]
fn epoch_cannot_be_relabelled() {
    let vault = VaultId::generate().unwrap();
    let device = Device::generate().unwrap();
    let vk = VaultKey::generate().unwrap();

    let wrapped = vk.wrap_for(device.public(), vault).unwrap();

    // Rewrite the epoch field in the serialized form.
    let mut bytes = wrapped.to_bytes();
    bytes[..4].copy_from_slice(&7u32.to_be_bytes());
    let tampered = WrappedVaultKey::from_bytes(&bytes).unwrap();

    assert_eq!(tampered.epoch(), Epoch(7), "test setup failed");
    assert_eq!(
        VaultKey::unwrap_for(&device, &tampered, vault).unwrap_err(),
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
    let staying = Device::generate().unwrap();
    let removed = Device::generate().unwrap();

    let vk = VaultKey::generate().unwrap();
    let removed_copy = vk.wrap_for(removed.public(), vault).unwrap();
    assert!(
        VaultKey::unwrap_for(&removed, &removed_copy, vault).is_ok(),
        "device should have access before revocation"
    );

    // Revoke: rotate, then re-wrap only for remaining members.
    let rotated = vk.rotate().unwrap();
    let staying_copy = rotated.wrap_for(staying.public(), vault).unwrap();

    assert!(VaultKey::unwrap_for(&staying, &staying_copy, vault).is_ok());
    assert_eq!(
        VaultKey::unwrap_for(&removed, &staying_copy, vault).unwrap_err(),
        Error::Decrypt,
        "revoked device could still unwrap the post-rotation key"
    );
}

#[test]
fn serialization_round_trips() {
    let vault = VaultId::generate().unwrap();
    let device = Device::generate().unwrap();
    let wrapped = VaultKey::generate()
        .unwrap()
        .wrap_for(device.public(), vault)
        .unwrap();

    let parsed = WrappedVaultKey::from_bytes(&wrapped.to_bytes()).unwrap();
    assert_eq!(wrapped, parsed);
    assert!(VaultKey::unwrap_for(&device, &parsed, vault).is_ok());
}

#[test]
fn malformed_wrapped_keys_are_rejected_without_panicking() {
    let vault = VaultId::generate().unwrap();
    let device = Device::generate().unwrap();
    let bytes = VaultKey::generate()
        .unwrap()
        .wrap_for(device.public(), vault)
        .unwrap()
        .to_bytes();

    for len in 0..bytes.len() {
        match WrappedVaultKey::from_bytes(&bytes[..len]) {
            Err(_) => {}
            Ok(truncated) => {
                assert!(VaultKey::unwrap_for(&device, &truncated, vault).is_err());
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
    let device = Device::generate().unwrap();
    let vk = VaultKey::generate().unwrap();

    let a = vk.wrap_for(device.public(), vault).unwrap();
    let b = vk.wrap_for(device.public(), vault).unwrap();

    assert_ne!(a, b, "HPKE encapsulation is not producing a fresh key");
    assert_eq!(
        VaultKey::unwrap_for(&device, &a, vault).unwrap(),
        VaultKey::unwrap_for(&device, &b, vault).unwrap()
    );
}

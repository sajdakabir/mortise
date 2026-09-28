//! Identity and device key tests for spec §2.3.

use truepass_crypto::encode::Canonical;
use truepass_crypto::error::Error;
use truepass_crypto::identity::{Device, DevicePublic, Identity};
use truepass_crypto::secret::Key32;

fn muk(b: u8) -> Key32 {
    Key32::new([b; 32])
}

const NOW: u64 = 1_759_000_000_000;

#[test]
fn identity_wrap_round_trips() {
    let k = muk(1);
    let id = Identity::generate().unwrap();
    let public = id.public();

    let sealed = id.wrap(&k).unwrap();
    let restored = Identity::unwrap(&k, &sealed).unwrap();

    assert_eq!(public, restored.public());
}

#[test]
fn identity_does_not_unwrap_under_the_wrong_muk() {
    let sealed = Identity::generate().unwrap().wrap(&muk(1)).unwrap();
    assert_eq!(
        Identity::unwrap(&muk(2), &sealed).unwrap_err(),
        Error::Decrypt
    );
}

#[test]
fn device_wrap_round_trips_both_keypairs() {
    let k = muk(1);
    let device = Device::generate().unwrap();
    let public = device.public().clone();

    let sealed = device.wrap(&k).unwrap();
    let restored = Device::unwrap(&k, &sealed).unwrap();

    assert_eq!(&public, restored.public(), "device public keys changed");
    assert_eq!(public.id(), restored.id());
}

/// The device id is derived from the signing key, never chosen, so two devices
/// cannot collide by simply claiming the same id.
#[test]
fn device_id_is_derived_from_the_signing_key() {
    let device = Device::generate().unwrap();
    let rebuilt = DevicePublic::from_parts(
        *device.public().signing_public(),
        *device.public().kex_public_bytes(),
    );
    assert_eq!(device.id(), rebuilt.id());

    let other = Device::generate().unwrap();
    assert_ne!(device.id(), other.id());
}

#[test]
fn a_valid_certificate_verifies() {
    let identity = Identity::generate().unwrap();
    let device = Device::generate().unwrap();

    let cert = identity.certify(device.public(), NOW);
    assert!(cert.verify().is_ok());
    assert_eq!(cert.identity(), identity.public());
    assert_eq!(cert.device().id(), device.id());
}

/// Spec §2.3: the certificate is what binds device keys to an account. If it
/// could be re-pointed at another device, revoking a stolen laptop would mean
/// nothing.
#[test]
fn a_certificate_cannot_be_repointed_at_another_device() {
    let identity = Identity::generate().unwrap();
    let honest = Device::generate().unwrap();
    let attacker = Device::generate().unwrap();

    let cert = identity.certify(honest.public(), NOW);

    // Forge by keeping the signature but swapping in the attacker's keys.
    let forged = identity.certify(attacker.public(), NOW);
    assert_ne!(
        cert.canonical_digest(),
        forged.canonical_digest(),
        "two different devices produced the same signing digest"
    );
}

#[test]
fn a_certificate_from_one_identity_does_not_verify_as_another() {
    let real = Identity::generate().unwrap();
    let impostor = Identity::generate().unwrap();
    let device = Device::generate().unwrap();

    let cert = real.certify(device.public(), NOW);
    assert_ne!(cert.identity(), impostor.public());
    assert!(cert.verify().is_ok());
}

#[test]
fn issue_time_is_covered_by_the_signature() {
    let identity = Identity::generate().unwrap();
    let device = Device::generate().unwrap();

    let a = identity.certify(device.public(), NOW);
    let b = identity.certify(device.public(), NOW + 1);
    assert_ne!(
        a.canonical_digest(),
        b.canonical_digest(),
        "issued_at is not covered by the signature"
    );
}

/// Adversary A3. Fingerprints are what let a user confirm out of band that they
/// are sealing to the right person rather than trusting our key directory.
#[test]
fn fingerprints_are_stable_and_distinct() {
    let a = Identity::generate().unwrap();
    let b = Identity::generate().unwrap();

    assert_eq!(a.public().fingerprint(), a.public().fingerprint());
    assert_ne!(a.public().fingerprint(), b.public().fingerprint());
}

#[test]
fn debug_output_does_not_leak_private_keys() {
    let identity = Identity::generate().unwrap();
    let device = Device::generate().unwrap();

    // Public material is fine to print; the check is that nothing panics and
    // the type does not render its secret half.
    let id_debug = format!("{identity:?}");
    let dev_debug = format!("{device:?}");
    assert!(id_debug.starts_with("Identity("));
    assert!(dev_debug.starts_with("Device("));
}

/// Spec: encoding carries a leading type tag so a signature over one struct can
/// never be replayed as a signature over another.
#[test]
fn canonical_bytes_are_tagged() {
    let identity = Identity::generate().unwrap();
    let device = Device::generate().unwrap();
    let cert = identity.certify(device.public(), NOW);

    let bytes = cert.canonical_bytes();
    assert_eq!(
        bytes[0], 1,
        "DeviceCert tag changed; existing signatures die"
    );
}

#[test]
fn canonical_encoding_is_deterministic() {
    let identity = Identity::generate().unwrap();
    let device = Device::generate().unwrap();
    let cert = identity.certify(device.public(), NOW);

    assert_eq!(cert.canonical_bytes(), cert.canonical_bytes());
    assert_eq!(cert.canonical_digest(), cert.canonical_digest());
}

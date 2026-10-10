//! Item sealing tests for spec §3.
//!
//! Most of these exist to prove the AAD binding is real. Spec §3 calls it "not
//! optional" — these are what make that claim checkable.

use truepass_crypto::error::Error;
use truepass_crypto::item::{ItemId, SealedItem};
use truepass_crypto::vault::{VaultId, VaultKey};

struct Fixture {
    vault: VaultId,
    key: VaultKey,
    item: ItemId,
}

impl Fixture {
    fn new() -> Self {
        Self {
            vault: VaultId::generate().unwrap(),
            key: VaultKey::generate().unwrap(),
            item: ItemId::generate().unwrap(),
        }
    }

    fn seal(&self, version: u32, payload: &[u8]) -> SealedItem {
        SealedItem::seal(&self.key, self.vault, self.item, version, payload).unwrap()
    }
}

#[test]
fn round_trips() {
    let f = Fixture::new();
    let sealed = f.seal(1, b"hunter2");
    assert_eq!(&sealed.open(&f.key).unwrap()[..], b"hunter2");
}

#[test]
fn metadata_is_preserved() {
    let f = Fixture::new();
    let sealed = f.seal(3, b"x");

    assert_eq!(sealed.vault(), f.vault);
    assert_eq!(sealed.item(), f.item);
    assert_eq!(sealed.version(), 3);
    assert_eq!(sealed.epoch(), f.key.epoch());
}

#[test]
fn another_vault_key_cannot_open_it() {
    let f = Fixture::new();
    let sealed = f.seal(1, b"secret");
    let other = VaultKey::generate().unwrap();

    assert_eq!(sealed.open(&other).unwrap_err(), Error::Decrypt);
}

/// Adversary A1. A relay with write access must not be able to move one item's
/// ciphertext into another item's slot.
#[test]
fn ciphertext_cannot_be_moved_to_another_item() {
    let f = Fixture::new();
    let sealed = f.seal(1, b"the admin password");
    let other_item = ItemId::generate().unwrap();

    let relabelled = SealedItem::from_parts(
        f.vault,
        other_item,
        sealed.version(),
        sealed.epoch(),
        sealed.sealed_item_key().to_vec(),
        sealed.ciphertext().to_vec(),
    );

    assert_eq!(relabelled.open(&f.key).unwrap_err(), Error::Decrypt);
}

/// Same attack, across vaults.
#[test]
fn ciphertext_cannot_be_moved_to_another_vault() {
    let f = Fixture::new();
    let sealed = f.seal(1, b"secret");

    let relabelled = SealedItem::from_parts(
        VaultId::generate().unwrap(),
        sealed.item(),
        sealed.version(),
        sealed.epoch(),
        sealed.sealed_item_key().to_vec(),
        sealed.ciphertext().to_vec(),
    );

    assert_eq!(relabelled.open(&f.key).unwrap_err(), Error::Decrypt);
}

/// Rollback: an old revision must not be presentable as a newer one. Without
/// version in the AAD, a relay could serve the pre-rotation password forever.
#[test]
fn an_old_version_cannot_be_replayed_as_a_new_one() {
    let f = Fixture::new();
    let old = f.seal(1, b"old password");

    let replayed = SealedItem::from_parts(
        f.vault,
        f.item,
        2,
        old.epoch(),
        old.sealed_item_key().to_vec(),
        old.ciphertext().to_vec(),
    );

    assert_eq!(replayed.open(&f.key).unwrap_err(), Error::Decrypt);
}

#[test]
fn tampering_with_the_ciphertext_is_detected() {
    let f = Fixture::new();
    let sealed = f.seal(1, b"secret value here");

    let mut ct = sealed.ciphertext().to_vec();
    ct[0] ^= 1;

    let tampered = SealedItem::from_parts(
        f.vault,
        f.item,
        1,
        sealed.epoch(),
        sealed.sealed_item_key().to_vec(),
        ct,
    );
    assert_eq!(tampered.open(&f.key).unwrap_err(), Error::Decrypt);
}

#[test]
fn tampering_with_the_sealed_item_key_is_detected() {
    let f = Fixture::new();
    let sealed = f.seal(1, b"secret");

    let mut sk = sealed.sealed_item_key().to_vec();
    sk[0] ^= 1;

    let tampered = SealedItem::from_parts(
        f.vault,
        f.item,
        1,
        sealed.epoch(),
        sk,
        sealed.ciphertext().to_vec(),
    );
    assert_eq!(tampered.open(&f.key).unwrap_err(), Error::Decrypt);
}

/// A wrong-epoch key is a caller mistake, not an attack, so it gets a distinct
/// error the app layer can act on — it needs to fetch the key for that epoch.
#[test]
fn epoch_mismatch_is_reported_distinctly() {
    let f = Fixture::new();
    let sealed = f.seal(1, b"secret");
    let rotated = f.key.rotate().unwrap();

    assert_eq!(
        sealed.open(&rotated).unwrap_err(),
        Error::EpochMismatch {
            expected: 0,
            got: 1
        }
    );
}

/// Spec §3: a fresh item key per version. If item keys were reused, two
/// versions of one item would share a key and the per-item sharing story would
/// collapse.
#[test]
fn every_seal_uses_a_fresh_item_key() {
    let f = Fixture::new();
    let a = f.seal(1, b"same payload");
    let b = f.seal(1, b"same payload");

    assert_ne!(a.sealed_item_key(), b.sealed_item_key());
    assert_ne!(a.ciphertext(), b.ciphertext());
    assert_eq!(&a.open(&f.key).unwrap()[..], &b.open(&f.key).unwrap()[..]);
}

#[test]
fn empty_and_large_payloads_round_trip() {
    let f = Fixture::new();

    assert!(f.seal(1, b"").open(&f.key).unwrap().is_empty());

    let big = vec![0xAB; 128 * 1024];
    assert_eq!(&f.seal(2, &big).open(&f.key).unwrap()[..], &big[..]);
}

#[test]
fn items_sealed_after_rotation_open_with_the_rotated_key() {
    let f = Fixture::new();
    let rotated = f.key.rotate().unwrap();

    let sealed = SealedItem::seal(&rotated, f.vault, f.item, 1, b"post-rotation").unwrap();
    assert_eq!(&sealed.open(&rotated).unwrap()[..], b"post-rotation");
    assert!(matches!(
        sealed.open(&f.key).unwrap_err(),
        Error::EpochMismatch { .. }
    ));
}

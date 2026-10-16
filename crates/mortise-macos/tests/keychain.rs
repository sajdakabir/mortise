//! Keychain round-trip tests against the real login keychain.
//!
//! These write to the actual keychain, so every test uses a unique service
//! name under a `mortise.test.` prefix and deletes what it created. Nothing
//! here reads a `UserPresence` item: that would raise a Touch ID prompt and
//! block the suite forever on a machine with nobody sitting at it.

#![cfg(target_os = "macos")]

use std::sync::atomic::{AtomicU64, Ordering};

use mortise_macos::{Error, Protection, delete, exists, load, store};

const ACCOUNT: &str = "test-account";

/// A unique service name per test, so concurrent runs cannot collide.
fn service() -> String {
    static N: AtomicU64 = AtomicU64::new(0);
    format!(
        "mortise.test.{}.{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    )
}

/// Deletes its service on drop, so a failing assertion still cleans up.
struct Scoped(String);

impl Scoped {
    fn new() -> Self {
        Self(service())
    }
    fn name(&self) -> &str {
        &self.0
    }
}

impl Drop for Scoped {
    fn drop(&mut self) {
        let _ = delete(&self.0, ACCOUNT);
    }
}

#[test]
fn store_and_load_round_trips() {
    let s = Scoped::new();
    let secret = b"an account key would go here, 32B";

    store(s.name(), ACCOUNT, secret, Protection::DeviceUnlocked).unwrap();
    let loaded = load(s.name(), ACCOUNT, "").unwrap().expect("item missing");
    assert_eq!(&loaded[..], secret);
}

#[test]
fn a_missing_item_is_none_not_an_error() {
    let s = Scoped::new();
    assert_eq!(load(s.name(), ACCOUNT, "").unwrap(), None);
    assert!(!exists(s.name(), ACCOUNT).unwrap());
}

/// SecItemAdd refuses duplicates rather than overwriting, so `store` deletes
/// first. If that ever regressed, the second write would silently keep the old
/// value — which for a rotated account key would be a very confusing bug.
#[test]
fn storing_twice_replaces_the_value() {
    let s = Scoped::new();

    store(
        s.name(),
        ACCOUNT,
        b"first value here",
        Protection::DeviceUnlocked,
    )
    .unwrap();
    store(
        s.name(),
        ACCOUNT,
        b"second value here",
        Protection::DeviceUnlocked,
    )
    .unwrap();

    let loaded = load(s.name(), ACCOUNT, "").unwrap().unwrap();
    assert_eq!(&loaded[..], b"second value here");
}

#[test]
fn delete_removes_the_item_and_is_idempotent() {
    let s = Scoped::new();
    store(
        s.name(),
        ACCOUNT,
        b"delete me please",
        Protection::DeviceUnlocked,
    )
    .unwrap();
    assert!(exists(s.name(), ACCOUNT).unwrap());

    delete(s.name(), ACCOUNT).unwrap();
    assert!(!exists(s.name(), ACCOUNT).unwrap());

    // Deleting something already gone is a normal outcome, not a failure.
    delete(s.name(), ACCOUNT).unwrap();
}

#[test]
fn binary_secrets_survive_intact() {
    let s = Scoped::new();
    let secret: Vec<u8> = (0..=255u8).collect();

    store(s.name(), ACCOUNT, &secret, Protection::DeviceUnlocked).unwrap();
    assert_eq!(
        &load(s.name(), ACCOUNT, "").unwrap().unwrap()[..],
        &secret[..]
    );
}

#[test]
fn empty_secrets_round_trip() {
    let s = Scoped::new();
    store(s.name(), ACCOUNT, b"", Protection::DeviceUnlocked).unwrap();
    assert_eq!(&load(s.name(), ACCOUNT, "").unwrap().unwrap()[..], b"");
}

#[test]
fn items_are_scoped_to_their_service_and_account() {
    let a = Scoped::new();
    let b = Scoped::new();

    store(
        a.name(),
        ACCOUNT,
        b"value for a here",
        Protection::DeviceUnlocked,
    )
    .unwrap();

    assert!(load(b.name(), ACCOUNT, "").unwrap().is_none());
    assert!(load(a.name(), "other-account", "").unwrap().is_none());
    assert!(load(a.name(), ACCOUNT, "").unwrap().is_some());
}

/// Writing a user-presence item must not prompt — only reading one does. This
/// also confirms `exists` can see such an item without raising a dialog, which
/// is what lets the UI decide whether to offer biometric unlock.
///
/// Skipped in unsigned builds. Creating an access-controlled item needs the
/// `keychain-access-groups` entitlement on a signed binary, and `cargo test`
/// binaries are not signed — so this passes vacuously here and only really
/// exercises anything inside a signed bundle.
#[test]
fn user_presence_items_can_be_written_and_detected_without_a_prompt() {
    let s = Scoped::new();

    match store(
        s.name(),
        ACCOUNT,
        b"unlock key here!",
        Protection::UserPresence,
    ) {
        Ok(()) => {
            assert!(
                exists(s.name(), ACCOUNT).unwrap(),
                "a user-presence item should be detectable without reading it"
            );
            delete(s.name(), ACCOUNT).unwrap();
            assert!(!exists(s.name(), ACCOUNT).unwrap());
        }
        Err(Error::RequiresSignedApp) => {
            eprintln!(
                "skipped: unsigned test binary cannot create access-controlled items \
                 (errSecMissingEntitlement); this path only runs in a signed bundle"
            );
        }
        Err(Error::NotAvailable) => {
            eprintln!("skipped: this Mac cannot create a user-presence access control");
        }
        Err(e) => panic!("unexpected error: {e}"),
    }
}

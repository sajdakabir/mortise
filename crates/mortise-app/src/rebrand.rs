//! One-time move off the old `com.truepassword.desktop` identity.
//!
//! The product was renamed to Mortise and the bundle identifier went with it.
//! Two things are keyed to that identifier and neither follows a rename on its
//! own: Tauri derives `app_data_dir()` from it, and macOS scopes keychain items
//! by service name. Without this, the first launch after the rename opens on an
//! empty vault and an unremembered account key — the data is still on disk, but
//! the app is looking somewhere else entirely.
//!
//! Runs on every start rather than behind a flag file. The check is a pair of
//! `exists` calls against paths that will not be there on a clean install, and
//! a marker file is one more piece of state to get wrong.

use std::path::{Path, PathBuf};

const LEGACY_BUNDLE: &str = "com.truepassword.desktop";
const LEGACY_VAULT_FILE: &str = "truepass.vault";

/// Keychain accounts carried over.
///
/// `unlock-token` is deliberately absent. It is stored with
/// [`Protection::UserPresence`], so reading it raises a Touch ID prompt — at
/// startup, before the window draws, for a value the user can regenerate by
/// toggling biometric unlock back on. Not worth a prompt nobody asked for.
const LEGACY_KEYCHAIN_ITEMS: &[&str] = &["account-key", "browser-associations"];

fn legacy_dir() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    Some(
        PathBuf::from(home)
            .join("Library/Application Support")
            .join(LEGACY_BUNDLE),
    )
}

/// Carry the vault across, if an old one is there.
///
/// Synchronous, and must run before the vault is opened: the app would
/// otherwise create an empty database at the new path and the copy would then
/// be skipped as "already there".
///
/// Best effort: a failure leaves the old copy untouched and the app starts as
/// it would for a new user, which is recoverable. Refusing to launch over a
/// failed migration would not be.
pub fn migrate_vault(data_dir: &Path, vault_file: &str) {
    let Some(old_dir) = legacy_dir() else { return };
    copy_vault(&old_dir, data_dir, vault_file);
}

fn copy_vault(old_dir: &Path, new_dir: &Path, vault_file: &str) {
    let old = old_dir.join(LEGACY_VAULT_FILE);
    let new = new_dir.join(vault_file);
    if !old.exists() || new.exists() {
        return;
    }
    if let Err(e) = std::fs::create_dir_all(new_dir) {
        eprintln!("mortise: cannot create the data directory: {e}");
        return;
    }

    // Copy rather than rename: a rename across directories is atomic here, but
    // leaving the original in place means a failed migration costs nothing and
    // the user can always point an older build back at it.
    //
    // The write-ahead log and shared-memory file travel with the database. A
    // vault copied without its -wal has lost every commit still sitting in that
    // log, which is to say the most recent ones.
    for suffix in ["", "-wal", "-shm"] {
        let (from, to) = (with_suffix(&old, suffix), with_suffix(&new, suffix));
        if from.exists()
            && let Err(e) = std::fs::copy(&from, &to)
        {
            eprintln!("mortise: could not carry over {}: {e}", from.display());
            return;
        }
    }
    eprintln!("mortise: carried the vault over from {}", old.display());
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    if suffix.is_empty() {
        return path.to_path_buf();
    }
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

/// Carry the account key and browser pairings to the new service name.
///
/// **Must not be called on the startup path.** macOS re-authorises a keychain
/// item when the reading binary's signature changes, and an unsigned build is
/// re-signed on every rebuild, so this read can raise a password prompt — and
/// the app blocks while it is up. Run it on the same thread as
/// [`browser::associations::warm`](crate::browser::associations::warm), and
/// before it, so a migrated pairing is in place by the time the cache fills.
pub fn migrate_keychain() {
    for account in LEGACY_KEYCHAIN_ITEMS {
        if mortise_macos::exists(crate::KEYCHAIN_SERVICE, account).unwrap_or(false) {
            continue;
        }
        let Ok(Some(secret)) = mortise_macos::load(LEGACY_BUNDLE, account, "") else {
            continue;
        };
        match mortise_macos::store(
            crate::KEYCHAIN_SERVICE,
            account,
            &secret,
            mortise_macos::Protection::DeviceUnlocked,
        ) {
            Ok(()) => eprintln!("mortise: carried over the keychain item {account}"),
            Err(e) => eprintln!("mortise: could not carry over {account}: {e}"),
        }
    }
}

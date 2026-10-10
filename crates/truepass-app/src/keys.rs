//! What this app keeps in the macOS keychain, and under what protection.
//!
//! Two entries, with deliberately different security properties:
//!
//! | Entry | Protection | Effect |
//! |---|---|---|
//! | account key | device unlocked, no prompt | you type only your password, not the recovery key |
//! | unlock token | Touch ID or passcode | you type nothing at all |
//!
//! ## Why the account key is not behind Touch ID
//!
//! Storing it means an attacker with your unlocked Mac has one of the two
//! factors. That is the intended posture: the account key's job (spec §2.2) is
//! to defeat *offline* attacks on a stolen vault file, and it still does that —
//! the file alone is useless. The master password remains the thing a live
//! attacker does not have.
//!
//! Putting it behind Touch ID would prompt on every unlock *in addition to* the
//! password, which is friction with no benefit: the password is already the
//! second factor.
//!
//! ## What biometric unlock actually gives away
//!
//! The unlock token is master-password-equivalent (see [`UnlockToken`]). Turning
//! it on means anyone who can pass Touch ID on this Mac can open the vault. For
//! most people that is a good trade; it should be an explicit choice, not a
//! default, and the UI says so plainly.
//!
//! Both entries are `ThisDeviceOnly`, so neither ever syncs to iCloud Keychain.

use truepass_crypto::secret::Key32;
use truepass_macos::{Error as KeychainError, Protection};
use truepass_vault::UnlockToken;

const SERVICE: &str = "com.truepassword.desktop";
const ACCOUNT_KEY: &str = "account-key";
const UNLOCK_TOKEN: &str = "unlock-token";

const PROMPT: &str = "Unlock TruePassword";

/// Remember the account key so unlocking needs only the master password.
pub fn remember_account_key(key: &Key32) -> Result<(), KeychainError> {
    truepass_macos::store(
        SERVICE,
        ACCOUNT_KEY,
        key.expose(),
        Protection::DeviceUnlocked,
    )
}

/// Read the remembered account key. No prompt.
pub fn recall_account_key() -> Result<Option<Key32>, KeychainError> {
    match truepass_macos::load(SERVICE, ACCOUNT_KEY, "")? {
        Some(bytes) => Ok(Key32::from_slice(&bytes).ok()),
        None => Ok(None),
    }
}

/// Forget the account key. The recovery key will be required again.
pub fn forget_account_key() -> Result<(), KeychainError> {
    truepass_macos::delete(SERVICE, ACCOUNT_KEY)
}

/// Whether an account key is remembered on this Mac.
pub fn account_key_remembered() -> bool {
    truepass_macos::exists(SERVICE, ACCOUNT_KEY).unwrap_or(false)
}

/// Turn on biometric unlock.
///
/// Fails with [`KeychainError::RequiresSignedApp`] in an unsigned build —
/// access-controlled keychain items need the `keychain-access-groups`
/// entitlement, so this never works under a plain `cargo run`.
pub fn enable_biometric(token: &UnlockToken) -> Result<(), KeychainError> {
    truepass_macos::store(
        SERVICE,
        UNLOCK_TOKEN,
        token.expose(),
        Protection::UserPresence,
    )
}

/// Read the unlock token, prompting for Touch ID.
///
/// **Blocks** while the prompt is up. Must not be called on the UI thread.
pub fn biometric_token() -> Result<Option<UnlockToken>, KeychainError> {
    match truepass_macos::load(SERVICE, UNLOCK_TOKEN, PROMPT)? {
        Some(bytes) => Ok(UnlockToken::from_slice(&bytes).ok()),
        None => Ok(None),
    }
}

/// Turn off biometric unlock.
pub fn disable_biometric() -> Result<(), KeychainError> {
    truepass_macos::delete(SERVICE, UNLOCK_TOKEN)
}

/// Whether biometric unlock is set up. Does not prompt.
pub fn biometric_enabled() -> bool {
    truepass_macos::exists(SERVICE, UNLOCK_TOKEN).unwrap_or(false)
}

/// Remove everything this app stores in the keychain.
///
/// Called on sign-out. Failures are swallowed: the user asked to be signed out,
/// and refusing because a keychain delete failed would leave them worse off.
pub fn forget_everything() {
    let _ = forget_account_key();
    let _ = disable_biometric();
}

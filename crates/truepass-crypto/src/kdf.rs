//! Key derivation: spec §2.1.
//!
//! ```text
//! stretch  = Argon2id(MP, S_user, m=64MiB, t=3, p=4)
//! MUK      = HKDF-SHA256(ikm = stretch ‖ AK, salt = S_user, info = "truepass/v1/muk")
//! DB_KEY   = HKDF-SHA256(ikm = MUK, info = "truepass/v1/dbkey")
//! scan_key = HKDF-SHA256(ikm = MUK, info = "truepass/v1/guard-index")
//! ```
//!
//! Every `info` string is prefixed `truepass/v1/` so a future v2 hierarchy
//! cannot collide with this one. Never reuse an `info`.

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::secret::{Key32, Salt16};

/// Domain separation strings. Adding one here is a spec change.
pub mod info {
    /// Master unlock key.
    pub const MUK: &[u8] = b"truepass/v1/muk";
    /// SQLCipher database key.
    pub const DB_KEY: &[u8] = b"truepass/v1/dbkey";
    /// Agent Guard known-secret index key.
    pub const GUARD_INDEX: &[u8] = b"truepass/v1/guard-index";
}

/// Argon2id cost parameters, stored per-vault so they can be raised later
/// without invalidating existing vaults.
///
/// Spec §10 flags these as provisional: they must be measured on the oldest
/// Mac we intend to support before being frozen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Argon2Params {
    /// Memory cost in KiB.
    pub m_cost_kib: u32,
    /// Iterations.
    pub t_cost: u32,
    /// Parallelism (lanes).
    pub p_cost: u32,
}

impl Default for Argon2Params {
    /// Spec §1: m = 64 MiB, t = 3, p = 4.
    ///
    /// Deliberately well above the OWASP floor of 19 MiB / t=2. A password
    /// manager is the one application where the offline-guessing cost
    /// (adversary A4) is worth paying interactive latency for.
    fn default() -> Self {
        Self {
            m_cost_kib: 64 * 1024,
            t_cost: 3,
            p_cost: 4,
        }
    }
}

impl Argon2Params {
    fn to_argon2(self) -> Result<Argon2<'static>> {
        let params = Params::new(self.m_cost_kib, self.t_cost, self.p_cost, Some(32))
            .map_err(|_| Error::Params)?;
        Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
    }
}

/// Stretch the master password with Argon2id.
///
/// This output is *not* the unlock key — it must still be combined with the
/// account key by [`derive_muk`]. Spec §2.2 explains why.
pub fn stretch_password(password: &[u8], salt: &Salt16, params: Argon2Params) -> Result<Key32> {
    let mut out = Zeroizing::new([0u8; 32]);
    params
        .to_argon2()?
        .hash_password_into(password, salt, out.as_mut())
        .map_err(|_| Error::Derive)?;
    Ok(Key32::new(*out))
}

/// Combine the stretched password with the account key into the master unlock
/// key.
///
/// The account key is what makes an offline attack on the vault (A4) useless
/// regardless of how weak the user's password is.
pub fn derive_muk(stretch: &Key32, account_key: &Key32, salt: &Salt16) -> Result<Key32> {
    // ikm = stretch ‖ AK
    let mut ikm = Zeroizing::new([0u8; 64]);
    ikm[..32].copy_from_slice(stretch.expose());
    ikm[32..].copy_from_slice(account_key.expose());

    let hkdf = Hkdf::<Sha256>::new(Some(salt.as_slice()), ikm.as_ref());
    let mut out = Zeroizing::new([0u8; 32]);
    hkdf.expand(info::MUK, out.as_mut())
        .map_err(|_| Error::Derive)?;
    Ok(Key32::new(*out))
}

/// Derive a purpose-specific subkey from the master unlock key.
///
/// No salt: the MUK is already uniformly random, so HKDF-Extract has nothing to
/// condition. Separation comes entirely from `info`, which is why reusing one
/// would be a real bug rather than a style problem.
pub fn subkey(muk: &Key32, info: &[u8]) -> Result<Key32> {
    let hkdf = Hkdf::<Sha256>::new(None, muk.expose());
    let mut out = Zeroizing::new([0u8; 32]);
    hkdf.expand(info, out.as_mut()).map_err(|_| Error::Derive)?;
    Ok(Key32::new(*out))
}

/// The SQLCipher key for the local database.
pub fn derive_db_key(muk: &Key32) -> Result<Key32> {
    subkey(muk, info::DB_KEY)
}

/// The HMAC key for the Agent Guard known-secret index.
pub fn derive_guard_key(muk: &Key32) -> Result<Key32> {
    subkey(muk, info::GUARD_INDEX)
}

/// Generate a fresh 128-bit per-user salt.
pub fn generate_salt() -> Result<Salt16> {
    crate::rand::bytes::<16>()
}

/// Generate a fresh 256-bit account key. Shown to the user once, on the
/// recovery kit, and never again.
pub fn generate_account_key() -> Result<Key32> {
    Key32::random()
}

/// Run the whole unlock path: password + account key -> MUK.
pub fn unlock(
    password: &[u8],
    account_key: &Key32,
    salt: &Salt16,
    params: Argon2Params,
) -> Result<Key32> {
    let stretch = stretch_password(password, salt, params)?;
    derive_muk(&stretch, account_key, salt)
}

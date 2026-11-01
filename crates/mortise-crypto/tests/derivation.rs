//! Derivation tests for spec §2.1.
//!
//! What these vectors DO prove: the derivation is stable. If someone edits an
//! `info` string, reorders the `stretch ‖ AK` concatenation, swaps the HKDF
//! salt, or changes a primitive, these fail loudly. That is a real class of bug
//! — silent and catastrophic, because existing vaults stop opening.
//!
//! What they do NOT prove: that Argon2id or HKDF-SHA256 are implemented
//! correctly. Those are the upstream crates' responsibility and both are
//! validated against RFC 9106 / RFC 5869 vectors in their own test suites.
//!
//! The vectors use deliberately cheap Argon2 parameters so the suite stays
//! fast. `default_params_match_spec` separately pins the real cost parameters.

use mortise_crypto::kdf::{self, Argon2Params};
use mortise_crypto::secret::Key32;

/// Cheap params, for speed. Never use these in production.
const TEST_PARAMS: Argon2Params = Argon2Params {
    m_cost_kib: 64,
    t_cost: 1,
    p_cost: 1,
};
const SALT: [u8; 16] = [0x42; 16];
const PASSWORD: &[u8] = b"correct horse battery staple";

fn account_key() -> Key32 {
    Key32::new([0x11; 32])
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;

    bytes.iter().fold(String::new(), |mut output, byte| {
        write!(output, "{byte:02x}").expect("writing to a String cannot fail");
        output
    })
}

#[test]
fn stretch_password_is_stable() {
    let got = kdf::stretch_password(PASSWORD, &SALT, TEST_PARAMS).unwrap();
    assert_eq!(
        hex(got.expose()),
        "a45bbb8a08c924e27c7f7475b048677059cce83d359d9de4812d409a39eb0207"
    );
}

#[test]
fn muk_derivation_is_stable() {
    let stretch = kdf::stretch_password(PASSWORD, &SALT, TEST_PARAMS).unwrap();
    let muk = kdf::derive_muk(&stretch, &account_key(), &SALT).unwrap();
    assert_eq!(
        hex(muk.expose()),
        "ff04321abe01544656f0b7ca5de47d5a4cd89b62d4becd213520bf235115cf30"
    );
}

#[test]
fn subkeys_are_stable() {
    let muk = kdf::unlock(PASSWORD, &account_key(), &SALT, TEST_PARAMS).unwrap();
    assert_eq!(
        hex(kdf::derive_db_key(&muk).unwrap().expose()),
        "6f2e78d0fa9e62ef6b9032bd70e18ee871975de286abf255453a40478895d0aa"
    );
    assert_eq!(
        hex(kdf::derive_guard_key(&muk).unwrap().expose()),
        "be9fdebf1a3904bc0247dc33c9d507cae86b8e19a1c25279fcac5e417edab327"
    );
}

#[test]
fn unlock_matches_manual_two_step_derivation() {
    let stretch = kdf::stretch_password(PASSWORD, &SALT, TEST_PARAMS).unwrap();
    let manual = kdf::derive_muk(&stretch, &account_key(), &SALT).unwrap();
    let combined = kdf::unlock(PASSWORD, &account_key(), &SALT, TEST_PARAMS).unwrap();
    assert_eq!(manual, combined);
}

/// Spec §1. Pinned separately from the vectors so lowering the cost parameters
/// cannot pass review unnoticed.
#[test]
fn default_params_match_spec() {
    let p = Argon2Params::default();
    assert_eq!(p.m_cost_kib, 64 * 1024, "spec §1 requires m = 64 MiB");
    assert_eq!(p.t_cost, 3, "spec §1 requires t = 3");
    assert_eq!(p.p_cost, 4, "spec §1 requires p = 4");
}

/// Spec §2.2 / adversary A4. If the account key were ever dropped from the
/// derivation, an offline attacker would face only the master password. This
/// test is the tripwire for that regression.
#[test]
fn account_key_actually_affects_the_muk() {
    let stretch = kdf::stretch_password(PASSWORD, &SALT, TEST_PARAMS).unwrap();
    let a = kdf::derive_muk(&stretch, &Key32::new([0x11; 32]), &SALT).unwrap();
    let b = kdf::derive_muk(&stretch, &Key32::new([0x12; 32]), &SALT).unwrap();
    assert_ne!(a, b, "account key is not being mixed into the MUK");
}

#[test]
fn salt_affects_the_muk() {
    let stretch = kdf::stretch_password(PASSWORD, &SALT, TEST_PARAMS).unwrap();
    let a = kdf::derive_muk(&stretch, &account_key(), &SALT).unwrap();
    let b = kdf::derive_muk(&stretch, &account_key(), &[0x43; 16]).unwrap();
    assert_ne!(a, b);
}

/// Spec §2.1: never reuse an `info`. Distinct purposes must yield distinct keys.
#[test]
fn subkeys_are_domain_separated() {
    let muk = kdf::unlock(PASSWORD, &account_key(), &SALT, TEST_PARAMS).unwrap();
    let db = kdf::derive_db_key(&muk).unwrap();
    let guard = kdf::derive_guard_key(&muk).unwrap();

    let meta = kdf::derive_meta_key(&muk).unwrap();

    assert_ne!(db, guard, "db key and guard key must differ");
    assert_ne!(db, meta, "db key and meta key must differ");
    assert_ne!(guard, meta, "guard key and meta key must differ");
    assert_ne!(db, muk, "subkey must not equal the MUK");
    assert_ne!(guard, muk, "subkey must not equal the MUK");
    assert_ne!(meta, muk, "subkey must not equal the MUK");
}

#[test]
fn distinct_info_strings_give_distinct_subkeys() {
    let muk = Key32::new([0x77; 32]);
    let a = kdf::subkey(&muk, b"truepass/v1/one").unwrap();
    let b = kdf::subkey(&muk, b"truepass/v1/two").unwrap();
    assert_ne!(a, b);
}

#[test]
fn all_spec_info_strings_carry_the_version_prefix() {
    for info in [
        kdf::info::MUK,
        kdf::info::DB_KEY,
        kdf::info::GUARD_INDEX,
        kdf::info::META_KEY,
        kdf::info::ENV_ITEM_ID,
        kdf::info::INVITE_MAILBOX,
        kdf::info::INVITE_PSK,
    ] {
        assert!(
            info.starts_with(b"truepass/v1/"),
            "info string {:?} is missing the truepass/v1/ prefix",
            core::str::from_utf8(info)
        );
    }
}

/// Spec §1: never reuse an `info`. Two subsystems sharing one would derive the
/// same key for different jobs.
#[test]
fn no_two_spec_info_strings_are_the_same() {
    let all = [
        kdf::info::MUK,
        kdf::info::DB_KEY,
        kdf::info::GUARD_INDEX,
        kdf::info::META_KEY,
        kdf::info::ENV_ITEM_ID,
        kdf::info::INVITE_MAILBOX,
        kdf::info::INVITE_PSK,
    ];
    for (i, a) in all.iter().enumerate() {
        for b in &all[i + 1..] {
            assert_ne!(a, b);
        }
    }
}

#[test]
fn generated_salts_and_account_keys_are_not_constant() {
    assert_ne!(kdf::generate_salt().unwrap(), kdf::generate_salt().unwrap());
    assert_ne!(
        kdf::generate_account_key().unwrap(),
        kdf::generate_account_key().unwrap()
    );
}

#[test]
fn absurd_argon2_params_are_rejected_not_panicked() {
    let bad = Argon2Params {
        m_cost_kib: 0,
        t_cost: 0,
        p_cost: 0,
    };
    assert!(kdf::stretch_password(PASSWORD, &SALT, bad).is_err());
}

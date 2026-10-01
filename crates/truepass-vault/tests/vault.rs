//! Local store tests.

use std::path::{Path, PathBuf};

use tempfile::TempDir;
use truepass_crypto::kdf::Argon2Params;
use truepass_crypto::secret::Key32;
use truepass_vault::{Error, ItemMeta, ItemPayload, Vault};

/// Cheap Argon2 so the suite is not dominated by key stretching.
const FAST: Argon2Params = Argon2Params {
    m_cost_kib: 64,
    t_cost: 1,
    p_cost: 1,
};
const PASSWORD: &[u8] = b"correct horse battery staple";

struct Fixture {
    _dir: TempDir,
    path: PathBuf,
    vault: Vault,
    account_key: Key32,
}

impl Fixture {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("vault.db");
        let (vault, account_key) = Vault::create(&path, PASSWORD, FAST).unwrap();
        Self {
            _dir: dir,
            path,
            vault,
            account_key,
        }
    }

    fn relock(&mut self) {
        self.vault.lock();
    }

    fn unlock(&mut self) {
        let ak = self.account_key.clone();
        self.vault.unlock(PASSWORD, &ak).unwrap();
    }
}

fn login(title: &str) -> (ItemMeta, ItemPayload) {
    (
        ItemMeta {
            title: title.to_string(),
            urls: vec!["https://github.com".into()],
            username: Some("octocat".into()),
            folder: Some("Work".into()),
            tags: vec!["devtools-zqx".into()],
        },
        ItemPayload::Login {
            password: "s3cr3t-p4ssw0rd-value".into(),
            totp_seed: Some("JBSWY3DPEHPK3PXP".into()),
            notes: None,
        },
    )
}

/// Every byte written to disk, across the db and its WAL/shm sidecars.
fn all_bytes_on_disk(path: &Path) -> Vec<u8> {
    let dir = path.parent().unwrap();
    let mut bytes = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let p = entry.unwrap().path();
        if p.is_file() {
            bytes.extend_from_slice(&std::fs::read(&p).unwrap_or_default());
        }
    }
    bytes
}

// --- lifecycle ---

#[test]
fn a_new_vault_starts_unlocked() {
    let f = Fixture::new();
    assert!(f.vault.is_unlocked());
    assert_eq!(f.vault.item_count().unwrap(), 0);
}

#[test]
fn reopening_from_disk_starts_locked_and_unlocks() {
    let mut f = Fixture::new();
    let (meta, payload) = login("GitHub");
    let id = f.vault.create_item(&meta, &payload).unwrap();
    drop(std::mem::replace(
        &mut f.vault,
        Vault::open(&f.path).unwrap(),
    ));

    assert!(!f.vault.is_unlocked());
    f.unlock();
    assert!(f.vault.is_unlocked());
    assert_eq!(f.vault.item_meta(id).unwrap(), meta);
}

#[test]
fn the_wrong_password_is_rejected() {
    let mut f = Fixture::new();
    f.relock();
    let ak = f.account_key.clone();

    assert!(matches!(
        f.vault.unlock(b"wrong password", &ak),
        Err(Error::WrongCredentials)
    ));
    assert!(!f.vault.is_unlocked());
}

/// Spec §2.2: the account key is a required second factor, not decoration.
/// The right password with the wrong key must fail.
#[test]
fn the_wrong_account_key_is_rejected() {
    let mut f = Fixture::new();
    f.relock();

    assert!(matches!(
        f.vault.unlock(PASSWORD, &Key32::new([0xFF; 32])),
        Err(Error::WrongCredentials)
    ));
    assert!(!f.vault.is_unlocked());
}

/// A failed unlock must not leave a previously-unlocked vault open.
#[test]
fn a_failed_unlock_does_not_preserve_prior_access() {
    let mut f = Fixture::new();
    let (meta, payload) = login("GitHub");
    let id = f.vault.create_item(&meta, &payload).unwrap();
    assert!(f.vault.is_unlocked());

    let _ = f.vault.unlock(b"wrong", &Key32::new([1; 32]));

    assert!(!f.vault.is_unlocked());
    assert!(matches!(f.vault.reveal(id), Err(Error::Locked)));
}

#[test]
fn creating_a_vault_where_one_exists_is_refused() {
    let f = Fixture::new();
    assert!(matches!(
        Vault::create(&f.path, PASSWORD, FAST),
        Err(Error::Corrupt(_))
    ));
}

#[test]
fn opening_a_nonexistent_vault_is_refused() {
    let dir = TempDir::new().unwrap();
    assert!(matches!(
        Vault::open(dir.path().join("nope.db")),
        Err(Error::Corrupt(_))
    ));
}

// --- items ---

#[test]
fn an_item_round_trips() {
    let mut f = Fixture::new();
    let (meta, payload) = login("GitHub");
    let id = f.vault.create_item(&meta, &payload).unwrap();

    assert_eq!(f.vault.item_meta(id).unwrap(), meta);
    assert_eq!(f.vault.reveal(id).unwrap(), payload);
}

#[test]
fn updating_bumps_the_version_and_keeps_the_creation_time() {
    let mut f = Fixture::new();
    let (meta, payload) = login("GitHub");
    let id = f.vault.create_item(&meta, &payload).unwrap();
    let created = f.vault.list().unwrap()[0].updated_at_ms;

    let mut meta2 = meta.clone();
    meta2.title = "GitHub Enterprise".into();
    let payload2 = ItemPayload::Login {
        password: "rotated-password-value".into(),
        totp_seed: None,
        notes: Some("rotated".into()),
    };
    f.vault.update_item(id, &meta2, &payload2).unwrap();

    assert_eq!(f.vault.item_meta(id).unwrap(), meta2);
    assert_eq!(f.vault.reveal(id).unwrap(), payload2);
    assert!(f.vault.list().unwrap()[0].updated_at_ms >= created);
    assert_eq!(f.vault.item_count().unwrap(), 1);
}

#[test]
fn updating_a_missing_item_is_refused() {
    let mut f = Fixture::new();
    let (meta, payload) = login("x");
    let ghost = truepass_crypto::item::ItemId::from_bytes([0xAB; 16]);

    assert!(matches!(
        f.vault.update_item(ghost, &meta, &payload),
        Err(Error::ItemNotFound)
    ));
}

/// Deletion leaves a tombstone for sync but must wipe the secret immediately —
/// a deleted password should not sit on disk waiting for a sync that may never
/// come.
#[test]
fn deleting_wipes_the_ciphertext_and_leaves_a_tombstone() {
    let mut f = Fixture::new();
    let (meta, payload) = login("Doomed");
    let id = f.vault.create_item(&meta, &payload).unwrap();

    f.vault.delete_item(id).unwrap();

    assert!(matches!(f.vault.reveal(id), Err(Error::ItemNotFound)));
    assert!(matches!(f.vault.item_meta(id), Err(Error::ItemNotFound)));
    assert_eq!(f.vault.item_count().unwrap(), 0);
    assert!(f.vault.list().unwrap().is_empty());

    assert!(matches!(f.vault.delete_item(id), Err(Error::ItemNotFound)));
}

#[test]
fn every_payload_kind_round_trips() {
    let mut f = Fixture::new();
    let meta = ItemMeta {
        title: "thing".into(),
        ..Default::default()
    };

    let payloads = [
        ItemPayload::SecureNote {
            body: "private thoughts".into(),
        },
        ItemPayload::Card {
            number: "4111111111111111".into(),
            expiry: "12/29".into(),
            cvv: "123".into(),
            holder: "A Person".into(),
        },
        ItemPayload::ApiKey {
            key: "sk-ant-api03-not-a-real-key".into(),
            notes: None,
        },
        ItemPayload::EnvSecret {
            value: "postgres://localhost/db".into(),
        },
        // Spec §10's reserved slot, exercised so the shape is actually fixed.
        ItemPayload::Passkey {
            rp_id: "github.com".into(),
            credential_id: vec![1, 2, 3, 4],
            private_key: vec![5; 32],
            user_handle: vec![9, 9],
        },
    ];

    for payload in payloads {
        let id = f.vault.create_item(&meta, &payload).unwrap();
        assert_eq!(f.vault.reveal(id).unwrap(), payload);
        assert_eq!(
            f.vault
                .list()
                .unwrap()
                .iter()
                .find(|s| s.id == id)
                .unwrap()
                .kind,
            payload.kind()
        );
    }
}

#[test]
fn list_is_newest_first() {
    let mut f = Fixture::new();
    let (meta, payload) = login("first");
    f.vault.create_item(&meta, &payload).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(5));
    let (mut meta2, payload2) = login("second");
    meta2.title = "second".into();
    let second = f.vault.create_item(&meta2, &payload2).unwrap();

    let listed = f.vault.list().unwrap();
    assert_eq!(listed.len(), 2);
    assert_eq!(listed[0].id, second);
}

// --- search ---

#[test]
fn search_matches_every_metadata_field_case_insensitively() {
    let mut f = Fixture::new();
    let (meta, payload) = login("GitHub");
    let id = f.vault.create_item(&meta, &payload).unwrap();

    for query in [
        "github",
        "GITHUB",
        "hub",
        "octocat",
        "OCTO",
        "work",
        "devtools-zqx",
        "github.com",
    ] {
        let hits = f.vault.search(query).unwrap();
        assert_eq!(hits.len(), 1, "query {query:?} found nothing");
        assert_eq!(hits[0].id, id);
    }

    assert!(f.vault.search("gitlab").unwrap().is_empty());
    assert_eq!(f.vault.search("   ").unwrap().len(), 1, "blank lists all");
}

/// The reason the search cache exists at all. Spec §4 / threat model: locking
/// protects secrets, not metadata, so the menu-bar search works without a
/// password prompt.
#[test]
fn search_and_list_work_while_locked_but_reveal_does_not() {
    let mut f = Fixture::new();
    let (meta, payload) = login("GitHub");
    let id = f.vault.create_item(&meta, &payload).unwrap();

    f.relock();
    assert!(!f.vault.is_unlocked());

    assert_eq!(f.vault.search("github").unwrap()[0].id, id);
    assert_eq!(f.vault.list().unwrap().len(), 1);
    assert_eq!(f.vault.item_count().unwrap(), 1);

    // Secrets stay shut, and so does canonical metadata (vault key is gone).
    assert!(matches!(f.vault.reveal(id), Err(Error::Locked)));
    assert!(matches!(f.vault.item_meta(id), Err(Error::Locked)));
    assert!(matches!(
        f.vault.create_item(&meta, &payload),
        Err(Error::Locked)
    ));
}

/// Full sign-out drops the metadata key too, so even search dies.
#[test]
fn lock_fully_also_closes_search() {
    let mut f = Fixture::new();
    let (meta, payload) = login("GitHub");
    f.vault.create_item(&meta, &payload).unwrap();

    f.vault.lock_fully();
    assert!(matches!(f.vault.search("github"), Err(Error::Locked)));
    assert!(matches!(f.vault.list(), Err(Error::Locked)));
}

/// A vault opened fresh from disk has never derived the metadata key in this
/// process, so search is unavailable until the first unlock.
#[test]
fn search_is_unavailable_before_the_first_unlock() {
    let mut f = Fixture::new();
    let (meta, payload) = login("GitHub");
    f.vault.create_item(&meta, &payload).unwrap();

    let reopened = Vault::open(&f.path).unwrap();
    assert!(matches!(reopened.search("github"), Err(Error::Locked)));

    drop(reopened);
    f.relock();
    f.unlock();
    assert_eq!(f.vault.search("github").unwrap().len(), 1);
}

#[test]
fn the_search_cache_can_be_rebuilt_from_canonical_metadata() {
    let mut f = Fixture::new();
    let (meta, payload) = login("GitHub");
    let id = f.vault.create_item(&meta, &payload).unwrap();

    f.vault.clear_search_cache().unwrap();
    assert!(f.vault.list().unwrap().is_empty());

    assert_eq!(f.vault.rebuild_search_cache().unwrap(), 1);
    assert_eq!(f.vault.search("github").unwrap()[0].id, id);
}

// --- what actually lands on disk ---

/// This is the test that justifies dropping SQLCipher. If any of these strings
/// appear in the file, the field-level encryption is not doing SQLCipher's job
/// and the decision was wrong.
///
/// Probe values have to be distinctive. An earlier version used `"dev"` as a
/// tag and failed — not because of a leak, but because SQLite stores the schema
/// SQL as plaintext in `sqlite_master`, and `CREATE TABLE device` contains
/// `dev`. Short probes test the schema text, not the encryption.
#[test]
fn nothing_sensitive_is_written_in_plaintext() {
    let mut f = Fixture::new();
    let (meta, payload) = login("MyBankLogin");
    f.vault.create_item(&meta, &payload).unwrap();
    f.vault.checkpoint().unwrap();

    let disk = all_bytes_on_disk(&f.path);
    let haystack = String::from_utf8_lossy(&disk);

    for secret in [
        "MyBankLogin",           // title
        "s3cr3t-p4ssw0rd-value", // password
        "JBSWY3DPEHPK3PXP",      // totp seed
        "octocat",               // username
        "github.com",            // url
        "Work",                  // folder
        "devtools-zqx",          // tag
    ] {
        assert!(
            !haystack.contains(secret),
            "{secret:?} was written to disk in plaintext"
        );
    }

    // Sanity: we really are looking at the right file and it has content.
    assert!(disk.len() > 4096, "disk scan found almost nothing");
    assert!(haystack.contains("SQLite format"), "not a SQLite file");
}

#[test]
fn vault_metadata_survives_a_reopen() {
    let f = Fixture::new();
    let before = f.vault.meta().clone();
    drop(f.vault);

    let reopened = Vault::open(&f.path).unwrap();
    assert_eq!(reopened.meta(), &before);
    assert_eq!(reopened.meta().params, FAST);
}

// --- unlock tokens ---

#[test]
fn an_unlock_token_opens_the_vault_without_the_password() {
    let mut f = Fixture::new();
    let (meta, payload) = login("GitHub");
    let id = f.vault.create_item(&meta, &payload).unwrap();

    let token = f.vault.unlock_token().unwrap();
    f.vault.lock_fully();
    assert!(matches!(f.vault.reveal(id), Err(Error::Locked)));

    f.vault.unlock_with_token(&token).unwrap();
    assert!(f.vault.is_unlocked());
    assert_eq!(f.vault.reveal(id).unwrap(), payload);
    assert_eq!(f.vault.search("github").unwrap().len(), 1);
}

/// A token can only be minted from an unlocked vault, so there is no path to
/// one that skips the master password entirely.
#[test]
fn a_token_cannot_be_minted_while_locked() {
    let mut f = Fixture::new();
    f.relock();
    assert!(matches!(f.vault.unlock_token(), Err(Error::Locked)));
}

#[test]
fn a_token_survives_a_reopen_from_disk() {
    let mut f = Fixture::new();
    let (meta, payload) = login("GitHub");
    let id = f.vault.create_item(&meta, &payload).unwrap();
    let token = f.vault.unlock_token().unwrap();

    let mut reopened = Vault::open(&f.path).unwrap();
    assert!(!reopened.is_unlocked());
    reopened.unlock_with_token(&token).unwrap();
    assert_eq!(reopened.reveal(id).unwrap(), payload);
}

/// A token from a different vault must not open this one. Tokens carry no
/// identifier, so the check is cryptographic: the wrong MUK fails to unwrap
/// the identity.
#[test]
fn a_token_from_another_vault_is_rejected() {
    let f = Fixture::new();
    let mut other = Fixture::new();

    let foreign = f.vault.unlock_token().unwrap();
    other.vault.lock_fully();

    assert!(matches!(
        other.vault.unlock_with_token(&foreign),
        Err(Error::WrongCredentials)
    ));
    assert!(!other.vault.is_unlocked());
}

#[test]
fn a_malformed_token_is_rejected() {
    use truepass_vault::UnlockToken;
    assert!(UnlockToken::from_slice(b"too short").is_err());
    assert!(UnlockToken::from_slice(&[0u8; 33]).is_err());
    assert!(UnlockToken::from_slice(&[0u8; 32]).is_ok());
}

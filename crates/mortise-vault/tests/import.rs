//! Importing an export into a real vault.
//!
//! The unit tests in `import.rs` prove the CSV is read correctly. This proves
//! the other half: that what was read survives encryption and comes back
//! byte-identical. A password that imports but decrypts to something else is
//! worse than one that fails to import at all, because nothing reports it.

use tempfile::TempDir;
use mortise_crypto::kdf::Argon2Params;
use mortise_vault::import;
use mortise_vault::{ItemPayload, Vault};

const FAST: Argon2Params = Argon2Params {
    m_cost_kib: 64,
    t_cost: 1,
    p_cost: 1,
};
const PASSWORD: &[u8] = b"correct horse battery staple";

/// Deliberately awkward: a comma in a name, an escaped quote and a comma in a
/// password, a multi-line note, and a row that is a note rather than a login.
const EXPORT: &str = "\
name,url,username,password,notes
GitHub,https://github.com,octocat,hunter2,
\"Acme, Inc.\",https://acme.example,alice,\"pa,ss\"\"word\",\"line one
line two\"
Shopping list,,,,\"milk, eggs\"
";

fn vault() -> (TempDir, Vault) {
    let dir = TempDir::new().unwrap();
    let (vault, _key) = Vault::create(dir.path().join("v.db"), PASSWORD, FAST).unwrap();
    (dir, vault)
}

#[test]
fn an_export_round_trips_through_encryption() {
    let (_dir, mut v) = vault();
    let (items, report) = import::parse(EXPORT.as_bytes()).unwrap();
    assert_eq!(report.parsed, 3);

    for (meta, payload) in &items {
        v.create_item(meta, payload).unwrap();
    }

    let rows = v.search("").unwrap();
    assert_eq!(rows.len(), 3);

    // The awkward one: both the title and the password carry characters that
    // naive CSV handling eats.
    let acme = rows
        .iter()
        .find(|r| r.meta.title == "Acme, Inc.")
        .expect("the quoted title did not survive");
    let payload = v.reveal(acme.id).unwrap();
    match &payload {
        ItemPayload::Login { password, notes, .. } => {
            assert_eq!(password, "pa,ss\"word");
            assert_eq!(notes.as_deref(), Some("line one\nline two"));
        }
        other => panic!("expected a login, got {other:?}"),
    }
}

#[test]
fn a_note_row_becomes_a_note_item() {
    let (_dir, mut v) = vault();
    let (items, _) = import::parse(EXPORT.as_bytes()).unwrap();
    for (meta, payload) in &items {
        v.create_item(meta, payload).unwrap();
    }

    let rows = v.search("Shopping").unwrap();
    assert_eq!(rows.len(), 1);
    let payload = v.reveal(rows[0].id).unwrap();
    match &payload {
        ItemPayload::SecureNote { body } => assert_eq!(body, "milk, eggs"),
        other => panic!("expected a note, got {other:?}"),
    }
}

/// Imported logins have to be reachable by autofill, which matches on origin.
/// An import that lands the URL in the wrong place produces a vault that looks
/// full and fills nothing.
#[test]
fn imported_logins_are_findable_by_origin() {
    let (_dir, mut v) = vault();
    let (items, _) = import::parse(EXPORT.as_bytes()).unwrap();
    for (meta, payload) in &items {
        v.create_item(meta, payload).unwrap();
    }

    let found = v
        .find_for_origin(&mortise_vault::Origin::parse("https://github.com").unwrap())
        .unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].meta.title, "GitHub");
}

//! Change log and two-device sync.
//!
//! The log is the source of truth; the item table is a view of it. These tests
//! are mostly about what happens when two devices disagree.

use tempfile::TempDir;
use mortise_crypto::change::{Change, Hlc};
use mortise_crypto::identity::Device;
use mortise_crypto::kdf::Argon2Params;
use mortise_crypto::secret::Key32;
use mortise_vault::enroll;
use mortise_vault::{Error, ItemMeta, ItemPayload, Vault};

const FAST: Argon2Params = Argon2Params {
    m_cost_kib: 64,
    t_cost: 1,
    p_cost: 1,
};
const PASSWORD: &[u8] = b"correct horse battery staple";

/// Two devices on one account, as device pairing produces.
struct Pair {
    _dir: TempDir,
    a: Vault,
    b: Vault,
}

impl Pair {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let (mut a, account_key) = Vault::create(dir.path().join("a.db"), PASSWORD, FAST).unwrap();

        let device_b = Device::generate().unwrap();
        let enrollment = a.enroll_device(device_b.public()).unwrap();
        let b = enroll::join(
            dir.path().join("b.db"),
            PASSWORD,
            &account_key,
            &device_b,
            &enrollment,
        )
        .unwrap();

        Self { _dir: dir, a, b }
    }
}

fn item(title: &str, password: &str) -> (ItemMeta, ItemPayload) {
    (
        ItemMeta {
            title: title.into(),
            ..Default::default()
        },
        ItemPayload::Login {
            password: password.into(),
            totp_seed: None,
            notes: None,
        },
    )
}

/// Move every outstanding change from `from` to `to`.
fn sync(from: &mut Vault, to: &mut Vault) {
    let changes = from.unpushed_changes(1000).unwrap();
    let report = to.ingest(&changes).unwrap();
    assert_eq!(report.rejected, 0, "a legitimate change was rejected");
    to.apply_pending().unwrap();
}

fn titles(vault: &Vault) -> Vec<String> {
    let mut names: Vec<String> = vault
        .list()
        .unwrap()
        .into_iter()
        .map(|s| s.meta.title)
        .collect();
    names.sort();
    names
}

// --- the log itself ---

#[test]
fn every_write_produces_a_change() {
    let dir = TempDir::new().unwrap();
    let (mut vault, _) = Vault::create(dir.path().join("v.db"), PASSWORD, FAST).unwrap();

    assert!(vault.unpushed_changes(10).unwrap().is_empty());

    let (meta, payload) = item("GitHub", "hunter2");
    let id = vault.create_item(&meta, &payload).unwrap();
    assert_eq!(vault.unpushed_changes(10).unwrap().len(), 1);

    vault.update_item(id, &meta, &payload).unwrap();
    vault.delete_item(id).unwrap();
    assert_eq!(vault.unpushed_changes(10).unwrap().len(), 3);
}

#[test]
fn changes_chain_into_a_single_head() {
    let dir = TempDir::new().unwrap();
    let (mut vault, _) = Vault::create(dir.path().join("v.db"), PASSWORD, FAST).unwrap();

    let (meta, payload) = item("One", "a");
    vault.create_item(&meta, &payload).unwrap();
    let first_head = vault.heads().unwrap();
    assert_eq!(first_head.len(), 1);

    vault
        .create_item(&item("Two", "b").0, &item("Two", "b").1)
        .unwrap();
    let second_head = vault.heads().unwrap();

    assert_eq!(second_head.len(), 1, "a linear history should have one tip");
    assert_ne!(first_head, second_head);

    let changes = vault.unpushed_changes(10).unwrap();
    let latest = changes.iter().find(|c| c.id() == second_head[0]).unwrap();
    assert_eq!(latest.parents(), &first_head[..]);
}

#[test]
fn marking_pushed_clears_the_outbox() {
    let dir = TempDir::new().unwrap();
    let (mut vault, _) = Vault::create(dir.path().join("v.db"), PASSWORD, FAST).unwrap();
    let (meta, payload) = item("GitHub", "hunter2");
    vault.create_item(&meta, &payload).unwrap();

    let pending = vault.unpushed_changes(10).unwrap();
    let ids: Vec<_> = pending.iter().map(|c| c.id()).collect();
    vault.mark_pushed(&ids).unwrap();

    assert!(vault.unpushed_changes(10).unwrap().is_empty());
}

/// The clock must survive a restart. If it reset, a change could be issued with
/// a timestamp below one already written — the exact ordering failure an HLC
/// exists to prevent.
#[test]
fn the_logical_clock_survives_a_reopen() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("v.db");
    let (mut vault, account_key) = Vault::create(&path, PASSWORD, FAST).unwrap();

    let (meta, payload) = item("One", "a");
    vault.create_item(&meta, &payload).unwrap();
    let before = vault.unpushed_changes(10).unwrap()[0].hlc();
    drop(vault);

    let mut reopened = Vault::open(&path).unwrap();
    reopened.unlock(PASSWORD, &account_key).unwrap();
    reopened
        .create_item(&item("Two", "b").0, &item("Two", "b").1)
        .unwrap();

    let after = reopened
        .unpushed_changes(10)
        .unwrap()
        .into_iter()
        .map(|c| c.hlc())
        .max()
        .unwrap();

    assert!(after > before, "the clock went backwards across a restart");
}

// --- two devices ---

#[test]
fn an_enrolled_device_sees_the_same_items() {
    let mut p = Pair::new();
    let (meta, payload) = item("GitHub", "hunter2");
    let id = p.a.create_item(&meta, &payload).unwrap();

    sync(&mut p.a, &mut p.b);

    assert_eq!(titles(&p.b), vec!["GitHub"]);
    assert_eq!(p.b.reveal(id).unwrap(), payload);
}

/// The point of the whole design: two devices editing different items offline
/// both keep their work.
#[test]
fn concurrent_edits_to_different_items_both_survive() {
    let mut p = Pair::new();

    p.a.create_item(&item("From A", "a").0, &item("From A", "a").1)
        .unwrap();
    p.b.create_item(&item("From B", "b").0, &item("From B", "b").1)
        .unwrap();

    sync(&mut p.a, &mut p.b);
    sync(&mut p.b, &mut p.a);

    assert_eq!(titles(&p.a), vec!["From A", "From B"]);
    assert_eq!(titles(&p.b), vec!["From A", "From B"]);
}

/// Item-level last-write-wins. Both devices must independently pick the same
/// winner, or they diverge permanently.
#[test]
fn concurrent_edits_to_one_item_converge_on_the_same_winner() {
    let mut p = Pair::new();

    let id =
        p.a.create_item(&item("Shared", "original").0, &item("Shared", "original").1)
            .unwrap();
    sync(&mut p.a, &mut p.b);

    p.a.update_item(id, &item("Shared", "from A").0, &item("Shared", "from A").1)
        .unwrap();
    p.b.update_item(id, &item("Shared", "from B").0, &item("Shared", "from B").1)
        .unwrap();

    sync(&mut p.a, &mut p.b);
    sync(&mut p.b, &mut p.a);

    let from_a = p.a.reveal(id).unwrap();
    let from_b = p.b.reveal(id).unwrap();
    assert_eq!(from_a, from_b, "the two devices disagree about the winner");
}

#[test]
fn deletions_propagate() {
    let mut p = Pair::new();
    let id =
        p.a.create_item(&item("Doomed", "x").0, &item("Doomed", "x").1)
            .unwrap();
    sync(&mut p.a, &mut p.b);
    assert_eq!(p.b.item_count().unwrap(), 1);

    p.a.delete_item(id).unwrap();
    sync(&mut p.a, &mut p.b);

    assert_eq!(p.b.item_count().unwrap(), 0);
    assert!(matches!(p.b.reveal(id), Err(Error::ItemNotFound)));
}

#[test]
fn syncing_twice_changes_nothing() {
    let mut p = Pair::new();
    p.a.create_item(&item("GitHub", "x").0, &item("GitHub", "x").1)
        .unwrap();

    let changes = p.a.unpushed_changes(100).unwrap();
    let first = p.b.ingest(&changes).unwrap();
    let second = p.b.ingest(&changes).unwrap();

    assert_eq!(first.accepted, changes.len() as u32);
    assert_eq!(second.accepted, 0);
    assert_eq!(second.duplicates, changes.len() as u32);

    // Ingest stores; applying materializes. The split is deliberate — ingest
    // works while locked, applying needs the vault key — so a caller that
    // only ingests sees no item change at all.
    p.b.apply_pending().unwrap();
    assert_eq!(p.b.item_count().unwrap(), 1);

    // And applying twice is also a no-op.
    assert_eq!(p.b.apply_pending().unwrap(), 0);
    assert_eq!(p.b.item_count().unwrap(), 1);
}

/// A change that arrives late with a lower clock must not clobber newer data.
/// Applying in arrival order alone would get this wrong.
#[test]
fn a_late_change_does_not_overwrite_a_newer_one() {
    let mut p = Pair::new();
    let id =
        p.a.create_item(&item("Shared", "original").0, &item("Shared", "original").1)
            .unwrap();
    sync(&mut p.a, &mut p.b);

    // B edits first, A second — so A's change has the higher clock.
    p.b.update_item(
        id,
        &item("Shared", "older from B").0,
        &item("Shared", "older from B").1,
    )
    .unwrap();
    let late = p.b.unpushed_changes(100).unwrap();

    p.a.update_item(
        id,
        &item("Shared", "newer from A").0,
        &item("Shared", "newer from A").1,
    )
    .unwrap();
    let newer_hlc =
        p.a.unpushed_changes(100)
            .unwrap()
            .iter()
            .map(Change::hlc)
            .max()
            .unwrap();
    let late_hlc = late.iter().map(Change::hlc).max().unwrap();
    assert!(late_hlc < newer_hlc, "test setup: B's edit should be older");

    // Now deliver B's older change to A, after A already has the newer one.
    p.a.ingest(&late).unwrap();
    p.a.apply_pending().unwrap();

    assert_eq!(
        p.a.reveal(id).unwrap(),
        item("Shared", "newer from A").1,
        "an older change overwrote a newer one"
    );
}

// --- what ingest refuses ---

#[test]
fn a_change_from_an_unknown_device_is_rejected() {
    let dir = TempDir::new().unwrap();
    let (mut a, _) = Vault::create(dir.path().join("a.db"), PASSWORD, FAST).unwrap();
    let (mut b, _) = Vault::create(dir.path().join("b.db"), PASSWORD, FAST).unwrap();

    b.create_item(&item("Foreign", "x").0, &item("Foreign", "x").1)
        .unwrap();
    let foreign = b.unpushed_changes(10).unwrap();

    let report = a.ingest(&foreign).unwrap();
    assert_eq!(report.accepted, 0);
    assert_eq!(report.rejected, foreign.len() as u32);
    assert_eq!(a.item_count().unwrap(), 0);
}

/// Adversary A1: a relay that tampers with a change must not get it applied.
#[test]
fn a_tampered_change_is_rejected() {
    let mut p = Pair::new();
    p.a.create_item(&item("GitHub", "x").0, &item("GitHub", "x").1)
        .unwrap();

    let original = p.a.unpushed_changes(10).unwrap();
    let tampered: Vec<Change> = original
        .iter()
        .map(|c| {
            let mut payload = c.payload().to_vec();
            payload[0] ^= 1;
            let unsigned = mortise_crypto::change::UnsignedChange::new(
                c.vault(),
                c.epoch(),
                c.parents().to_vec(),
                c.hlc(),
                c.author(),
                payload,
            );
            Change::from_parts(unsigned, c.id(), *c.signature())
        })
        .collect();

    let report = p.b.ingest(&tampered).unwrap();
    assert_eq!(report.accepted, 0);
    assert_eq!(report.rejected, tampered.len() as u32);
    assert_eq!(p.b.item_count().unwrap(), 0);
}

// --- enrolment ---

#[test]
fn enrolment_requires_the_real_credentials() {
    let dir = TempDir::new().unwrap();
    let (mut a, _) = Vault::create(dir.path().join("a.db"), PASSWORD, FAST).unwrap();

    let device_b = Device::generate().unwrap();
    let enrollment = a.enroll_device(device_b.public()).unwrap();

    assert!(matches!(
        enroll::join(
            dir.path().join("wrong-pw.db"),
            b"not the password",
            &Key32::new([9; 32]),
            &device_b,
            &enrollment,
        ),
        Err(Error::WrongCredentials)
    ));
}

/// An enrolment bundle is sealed to one device's key. Another device holding
/// the same bundle must get nothing from it.
#[test]
fn an_enrolment_is_bound_to_the_device_it_was_made_for() {
    let dir = TempDir::new().unwrap();
    let (mut a, account_key) = Vault::create(dir.path().join("a.db"), PASSWORD, FAST).unwrap();

    let intended = Device::generate().unwrap();
    let interloper = Device::generate().unwrap();
    let enrollment = a.enroll_device(intended.public()).unwrap();

    assert!(
        enroll::join(
            dir.path().join("wrong-device.db"),
            PASSWORD,
            &account_key,
            &interloper,
            &enrollment,
        )
        .is_err(),
        "a device the bundle was not sealed to could join"
    );
}

#[test]
fn an_enrolled_device_can_push_back() {
    let mut p = Pair::new();
    p.b.create_item(&item("From B", "x").0, &item("From B", "x").1)
        .unwrap();

    sync(&mut p.b, &mut p.a);
    assert_eq!(titles(&p.a), vec!["From B"]);
}

#[test]
fn hlc_ordering_is_total_across_devices() {
    let a = Hlc {
        wall_ms: 10,
        counter: 0,
    };
    let b = Hlc {
        wall_ms: 10,
        counter: 1,
    };
    assert!(a < b);
    assert!(Hlc::new(9) < a);
}

/// A delete that arrives before the item it deletes must stay deleted.
///
/// The relay chooses what each pull contains, so it can serve the delete on
/// its own and the upsert on a later page. `deletions_propagate` only covers
/// the case where the receiving device already holds the item.
#[test]
fn a_delete_that_arrives_first_is_not_undone_by_the_item() {
    let mut p = Pair::new();
    let id = p
        .a
        .create_item(&item("Leaked", "x").0, &item("Leaked", "x").1)
        .unwrap();
    p.a.delete_item(id).unwrap();

    // Both changes exist on A. Deliver them to B in the order a hostile relay
    // would choose: the delete alone, then the upsert.
    let changes = p.a.unpushed_changes(1000).unwrap();
    assert!(changes.len() >= 2, "expected an upsert and a delete");
    let (first, rest) = changes.split_at(1);

    p.b.ingest(rest).unwrap();
    p.b.apply_pending().unwrap();
    p.b.ingest(first).unwrap();
    p.b.apply_pending().unwrap();

    assert_eq!(
        p.b.item_count().unwrap(),
        0,
        "a deleted secret came back when its upsert arrived after the delete"
    );
    assert!(matches!(p.b.reveal(id), Err(Error::ItemNotFound)));
}

//! Access control and revocation.
//!
//! The relay cannot enforce roles — they live in a log it cannot read — so
//! every one of these properties has to hold on the client or not at all.

use tempfile::TempDir;
use mortise_crypto::acl::{AclOp, Role};
use mortise_crypto::identity::Device;
use mortise_crypto::kdf::Argon2Params;
use mortise_vault::enroll;
use mortise_vault::{ItemMeta, ItemPayload, Vault};

const FAST: Argon2Params = Argon2Params {
    m_cost_kib: 64,
    t_cost: 1,
    p_cost: 1,
};
const PASSWORD: &[u8] = b"correct horse battery staple";

struct Pair {
    _dir: TempDir,
    a: Vault,
    b: Vault,
    b_device: Device,
}

impl Pair {
    fn new() -> Self {
        let dir = TempDir::new().unwrap();
        let (mut a, account_key) = Vault::create(dir.path().join("a.db"), PASSWORD, FAST).unwrap();

        let b_device = Device::generate().unwrap();
        let enrollment = a.enroll_device(b_device.public()).unwrap();
        let b = enroll::join(
            dir.path().join("b.db"),
            PASSWORD,
            &account_key,
            &b_device,
            &enrollment,
        )
        .unwrap();

        Self {
            _dir: dir,
            a,
            b,
            b_device,
        }
    }
}

fn item(title: &str) -> (ItemMeta, ItemPayload) {
    (
        ItemMeta {
            title: title.into(),
            ..Default::default()
        },
        ItemPayload::Login {
            password: "hunter2".into(),
            totp_seed: None,
            notes: None,
        },
    )
}

fn hand_over(from: &mut Vault, to: &mut Vault) -> mortise_vault::changelog::IngestReport {
    let changes = from.unpushed_changes(1000).unwrap();
    let report = to.ingest(&changes).unwrap();
    let _ = to.apply_pending();
    report
}

// --- membership ---

#[test]
fn enrolment_puts_the_new_device_in_the_acl() {
    let p = Pair::new();
    let acl = p.a.acl().unwrap();

    assert_eq!(acl.role(p.b_device.public().id()), Some(Role::Member));
    assert!(p.a.may_write(p.b_device.public().id()).unwrap());
}

/// Both sides must agree about membership, or one will silently refuse the
/// other's changes.
#[test]
fn both_devices_see_the_same_membership() {
    let p = Pair::new();
    let from_a = p.a.acl().unwrap();
    let from_b = p.b.acl().unwrap();

    assert_eq!(from_a.head(), from_b.head());
    assert_eq!(
        from_a.members().count(),
        from_b.members().count(),
        "the two devices disagree about who is a member"
    );
}

#[test]
fn a_members_changes_are_accepted() {
    let mut p = Pair::new();
    p.b.create_item(&item("From B").0, &item("From B").1)
        .unwrap();

    let report = hand_over(&mut p.b, &mut p.a);
    assert_eq!(report.rejected, 0);
    assert_eq!(p.a.item_count().unwrap(), 1);
}

/// The point of the role check. A viewer's signature is perfectly valid and the
/// relay would store their changes happily; only this refuses them.
#[test]
fn a_viewers_changes_are_refused() {
    let mut p = Pair::new();
    let b_id = p.b_device.public().id();

    p.a.issue_acl_op(AclOp::ChangeRole {
        device: b_id,
        role: Role::Viewer,
    })
    .unwrap();
    assert!(!p.a.may_write(b_id).unwrap());

    p.b.create_item(&item("Should not land").0, &item("Should not land").1)
        .unwrap();

    let report = hand_over(&mut p.b, &mut p.a);
    assert!(report.accepted == 0 && report.rejected > 0);
    assert_eq!(p.a.item_count().unwrap(), 0);
}

/// Demotion stops future writes without unwinding past ones. That is the
/// practical reading, and it is a deliberate choice rather than an oversight.
#[test]
fn demotion_stops_future_changes_but_keeps_past_ones() {
    let mut p = Pair::new();
    let b_id = p.b_device.public().id();

    p.b.create_item(&item("Before").0, &item("Before").1)
        .unwrap();
    hand_over(&mut p.b, &mut p.a);
    assert_eq!(p.a.item_count().unwrap(), 1);

    p.a.issue_acl_op(AclOp::ChangeRole {
        device: b_id,
        role: Role::Viewer,
    })
    .unwrap();

    p.b.create_item(&item("After").0, &item("After").1).unwrap();
    hand_over(&mut p.b, &mut p.a);

    assert_eq!(
        p.a.item_count().unwrap(),
        1,
        "the earlier item should remain"
    );
}

// --- revocation ---

#[test]
fn revocation_removes_the_member_and_advances_the_epoch() {
    let mut p = Pair::new();
    p.a.create_item(&item("Shared").0, &item("Shared").1)
        .unwrap();

    let before = p.a.meta().epoch;
    let outcome = p.a.revoke_member(p.b_device.public().id()).unwrap();

    assert!(
        outcome.new_epoch > before.value(),
        "the epoch did not advance"
    );
    assert_eq!(p.a.acl().unwrap().role(p.b_device.public().id()), None);
    assert!(!p.a.may_write(p.b_device.public().id()).unwrap());
}

/// The threat model's A8 made concrete: revocation is forward secrecy only.
/// The report exists so the UI can tell the user how much to rotate by hand,
/// rather than implying the data was somehow clawed back.
#[test]
fn revocation_reports_what_the_removed_device_keeps() {
    let mut p = Pair::new();
    p.a.create_item(&item("One").0, &item("One").1).unwrap();
    p.a.create_item(&item("Two").0, &item("Two").1).unwrap();

    let outcome = p.a.revoke_member(p.b_device.public().id()).unwrap();
    assert_eq!(outcome.items_the_removed_device_retains, 2);
}

#[test]
fn a_revoked_devices_changes_are_refused() {
    let mut p = Pair::new();
    p.a.revoke_member(p.b_device.public().id()).unwrap();

    p.b.create_item(&item("After revocation").0, &item("After revocation").1)
        .unwrap();
    let report = hand_over(&mut p.b, &mut p.a);

    assert_eq!(report.accepted, 0);
    assert!(report.rejected > 0);
    assert_eq!(p.a.item_count().unwrap(), 0);
}

/// Items written after a rotation use the new key, which the removed device
/// never received.
#[test]
fn items_written_after_revocation_use_the_new_epoch() {
    let mut p = Pair::new();
    p.a.revoke_member(p.b_device.public().id()).unwrap();
    let epoch = p.a.meta().epoch;

    let id = p.a.create_item(&item("New").0, &item("New").1).unwrap();
    let changes = p.a.unpushed_changes(1000).unwrap();
    let latest = changes.last().unwrap();

    assert_eq!(latest.epoch(), epoch);
    // And it still opens locally, with the rotated key.
    assert_eq!(p.a.reveal(id).unwrap(), item("New").1);
}

#[test]
fn revoking_a_device_that_is_not_a_member_is_refused() {
    let mut p = Pair::new();
    let stranger = Device::generate().unwrap();

    assert!(p.a.revoke_member(stranger.public().id()).is_err());
}

/// The last owner cannot be removed, so a vault cannot be orphaned by
/// revoking your way out of it.
#[test]
fn the_last_owner_cannot_revoke_themselves() {
    let mut p = Pair::new();
    let owner = p.a.device().unwrap().id();

    assert!(p.a.revoke_member(owner).is_err());
    assert_eq!(p.a.acl().unwrap().role(owner), Some(Role::Owner));
}

// --- the log itself ---

#[test]
fn the_acl_log_survives_a_reopen() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("v.db");
    let (mut a, account_key) = Vault::create(&path, PASSWORD, FAST).unwrap();

    let b_device = Device::generate().unwrap();
    a.enroll_device(b_device.public()).unwrap();
    let head = a.acl().unwrap().head();
    drop(a);

    let mut reopened = Vault::open(&path).unwrap();
    reopened.unlock(PASSWORD, &account_key).unwrap();

    assert_eq!(reopened.acl().unwrap().head(), head);
    assert_eq!(
        reopened.acl().unwrap().role(b_device.public().id()),
        Some(Role::Member)
    );
}

/// ACL entries are a strict sequence. Two issued against the same head cannot
/// both apply — the second must be reissued, which is what stops two devices
/// ending up with different membership.
#[test]
fn concurrent_acl_entries_do_not_both_apply() {
    let mut p = Pair::new();
    let one = Device::generate().unwrap();
    let two = Device::generate().unwrap();

    let first = p.a.acl().unwrap().next_seq();
    p.a.issue_acl_op(AclOp::AddMember {
        device: one.public().clone(),
        role: Role::Member,
    })
    .unwrap();
    let second = p.a.acl().unwrap().next_seq();

    assert_eq!(second, first + 1, "the sequence should advance by one");

    p.a.issue_acl_op(AclOp::AddMember {
        device: two.public().clone(),
        role: Role::Member,
    })
    .unwrap();
    assert_eq!(p.a.acl().unwrap().next_seq(), first + 2);
}

//! Access control tests for spec §6.

use mortise_crypto::acl::{Acl, AclEntry, AclOp, Role, UnsignedAclEntry};
use mortise_crypto::error::Error;
use mortise_crypto::identity::Device;
use mortise_crypto::vault::{Epoch, VaultId};

const NOW: u64 = 1_759_000_000_000;
const VAULT: VaultId = VaultId::from_bytes([7; 16]);

/// Build an entry chaining from the ACL's current head, signed by `author`.
///
/// Free functions rather than methods on a fixture: `Device` is deliberately
/// not `Clone` (it holds private keys), so tests hold devices as locals and
/// pass references instead of duplicating secret material.
fn entry(acl: &Acl, author: &Device, op: AclOp) -> AclEntry {
    UnsignedAclEntry::new(VAULT, acl.next_seq(), acl.head(), op, author.id(), NOW).sign(author)
}

fn apply(acl: &mut Acl, author: &Device, op: AclOp) -> Result<(), Error> {
    let e = entry(acl, author, op);
    acl.apply(&e)
}

fn add(acl: &mut Acl, author: &Device, who: &Device, role: Role) -> Result<(), Error> {
    apply(
        acl,
        author,
        AclOp::AddMember {
            device: who.public().clone(),
            role,
        },
    )
}

fn genesis() -> (Acl, Device) {
    let owner = Device::generate().unwrap();
    let acl = Acl::genesis(VAULT, owner.public());
    (acl, owner)
}

#[test]
fn genesis_makes_the_creator_an_owner() {
    let (acl, owner) = genesis();
    assert_eq!(acl.role(owner.id()), Some(Role::Owner));
    assert_eq!(acl.epoch(), Epoch::INITIAL);
    assert_eq!(acl.next_seq(), 1);
}

#[test]
fn an_owner_can_add_a_member() {
    let (mut acl, owner) = genesis();
    let alice = Device::generate().unwrap();

    add(&mut acl, &owner, &alice, Role::Member).unwrap();
    assert_eq!(acl.role(alice.id()), Some(Role::Member));
    assert_eq!(acl.next_seq(), 2);
}

#[test]
fn a_non_member_cannot_modify_the_acl() {
    let (mut acl, _owner) = genesis();
    let outsider = Device::generate().unwrap();
    let victim = Device::generate().unwrap();

    assert_eq!(
        add(&mut acl, &outsider, &victim, Role::Member).unwrap_err(),
        Error::AclRejected("author is not a member")
    );
}

#[test]
fn a_plain_member_cannot_modify_the_acl() {
    let (mut acl, owner) = genesis();
    let alice = Device::generate().unwrap();
    let bob = Device::generate().unwrap();

    add(&mut acl, &owner, &alice, Role::Member).unwrap();
    assert_eq!(
        add(&mut acl, &alice, &bob, Role::Member).unwrap_err(),
        Error::AclRejected("author may not modify the ACL")
    );
}

/// Privilege escalation. If an admin could appoint admins or owners, any admin
/// could unilaterally take over a vault.
#[test]
fn an_admin_cannot_appoint_an_admin_or_owner() {
    let (mut acl, owner) = genesis();
    let admin = Device::generate().unwrap();
    let target = Device::generate().unwrap();

    add(&mut acl, &owner, &admin, Role::Admin).unwrap();

    assert_eq!(
        add(&mut acl, &admin, &target, Role::Admin).unwrap_err(),
        Error::AclRejected("author may not grant that role")
    );
    assert_eq!(
        add(&mut acl, &admin, &target, Role::Owner).unwrap_err(),
        Error::AclRejected("author may not grant that role")
    );

    // But may add a plain member.
    add(&mut acl, &admin, &target, Role::Member).unwrap();
    assert_eq!(acl.role(target.id()), Some(Role::Member));
}

/// The mirror image: one admin must not be able to remove another.
#[test]
fn an_admin_cannot_remove_a_peer_admin() {
    let (mut acl, owner) = genesis();
    let a = Device::generate().unwrap();
    let b = Device::generate().unwrap();

    add(&mut acl, &owner, &a, Role::Admin).unwrap();
    add(&mut acl, &owner, &b, Role::Admin).unwrap();

    assert_eq!(
        apply(&mut acl, &a, AclOp::RemoveMember { device: b.id() }).unwrap_err(),
        Error::AclRejected("author may not remove that member")
    );
}

#[test]
fn an_admin_cannot_demote_an_owner() {
    let (mut acl, owner) = genesis();
    let admin = Device::generate().unwrap();
    add(&mut acl, &owner, &admin, Role::Admin).unwrap();

    assert_eq!(
        apply(
            &mut acl,
            &admin,
            AclOp::ChangeRole {
                device: owner.id(),
                role: Role::Viewer,
            },
        )
        .unwrap_err(),
        Error::AclRejected("author may not set that role")
    );
}

#[test]
fn the_last_owner_cannot_be_removed_or_demoted() {
    let (mut acl, owner) = genesis();

    assert_eq!(
        apply(&mut acl, &owner, AclOp::RemoveMember { device: owner.id() }).unwrap_err(),
        Error::AclRejected("cannot remove the last owner")
    );
    assert_eq!(
        apply(
            &mut acl,
            &owner,
            AclOp::ChangeRole {
                device: owner.id(),
                role: Role::Admin,
            },
        )
        .unwrap_err(),
        Error::AclRejected("cannot demote the last owner")
    );
}

#[test]
fn a_second_owner_can_be_removed() {
    let (mut acl, owner) = genesis();
    let other = Device::generate().unwrap();

    add(&mut acl, &owner, &other, Role::Owner).unwrap();
    apply(&mut acl, &owner, AclOp::RemoveMember { device: other.id() }).unwrap();
    assert_eq!(acl.role(other.id()), None);
}

/// The reason the ACL is a strict sequence rather than a DAG. Two admins acting
/// concurrently would otherwise leave devices disagreeing about who is a
/// member; here the second entry is rejected and must be reissued.
#[test]
fn concurrent_acl_edits_are_rejected_not_merged() {
    let (mut acl, owner) = genesis();
    let alice = Device::generate().unwrap();
    let bob = Device::generate().unwrap();

    // Both built against the same head, before either is applied.
    let first = entry(
        &acl,
        &owner,
        AclOp::AddMember {
            device: alice.public().clone(),
            role: Role::Member,
        },
    );
    let second = entry(
        &acl,
        &owner,
        AclOp::AddMember {
            device: bob.public().clone(),
            role: Role::Member,
        },
    );

    acl.apply(&first).unwrap();
    assert_eq!(
        acl.apply(&second).unwrap_err(),
        Error::AclRejected("entry is out of sequence")
    );
    assert_eq!(acl.role(bob.id()), None);
}

#[test]
fn an_entry_that_does_not_chain_from_the_head_is_rejected() {
    let (mut acl, owner) = genesis();
    let alice = Device::generate().unwrap();

    let forged = UnsignedAclEntry::new(
        VAULT,
        acl.next_seq(),
        [0xFF; 32],
        AclOp::AddMember {
            device: alice.public().clone(),
            role: Role::Member,
        },
        owner.id(),
        NOW,
    )
    .sign(&owner);

    assert_eq!(
        acl.apply(&forged).unwrap_err(),
        Error::AclRejected("entry does not chain from the head")
    );
}

#[test]
fn an_entry_for_another_vault_is_rejected() {
    let (mut acl, owner) = genesis();
    let alice = Device::generate().unwrap();

    let foreign = UnsignedAclEntry::new(
        VaultId::from_bytes([1; 16]),
        acl.next_seq(),
        acl.head(),
        AclOp::AddMember {
            device: alice.public().clone(),
            role: Role::Member,
        },
        owner.id(),
        NOW,
    )
    .sign(&owner);

    assert_eq!(
        acl.apply(&foreign).unwrap_err(),
        Error::AclRejected("entry belongs to another vault")
    );
}

/// A forged entry claiming an authorized author must still fail on signature.
#[test]
fn an_entry_signed_by_the_wrong_device_is_rejected() {
    let (mut acl, owner) = genesis();
    let attacker = Device::generate().unwrap();
    let alice = Device::generate().unwrap();

    let forged = UnsignedAclEntry::new(
        VAULT,
        acl.next_seq(),
        acl.head(),
        AclOp::AddMember {
            device: alice.public().clone(),
            role: Role::Owner,
        },
        owner.id(),
        NOW,
    )
    .sign(&attacker);

    assert_eq!(acl.apply(&forged).unwrap_err(), Error::Signature);
    assert_eq!(acl.role(alice.id()), None);
}

#[test]
fn rotation_must_advance_exactly_one_epoch() {
    let (mut acl, owner) = genesis();

    assert_eq!(
        apply(&mut acl, &owner, AclOp::RotateKey { epoch: Epoch(5) }).unwrap_err(),
        Error::AclRejected("rotation must advance exactly one epoch")
    );
    assert_eq!(
        apply(&mut acl, &owner, AclOp::RotateKey { epoch: Epoch(0) }).unwrap_err(),
        Error::AclRejected("rotation must advance exactly one epoch")
    );

    apply(&mut acl, &owner, AclOp::RotateKey { epoch: Epoch(1) }).unwrap();
    assert_eq!(acl.epoch(), Epoch(1));
}

/// Spec §6, the full revocation sequence: remove, rotate, then re-wrap for
/// exactly the remaining recipients.
#[test]
fn revocation_removes_the_member_from_key_recipients() {
    let (mut acl, owner) = genesis();
    let staying = Device::generate().unwrap();
    let leaving = Device::generate().unwrap();

    add(&mut acl, &owner, &staying, Role::Member).unwrap();
    add(&mut acl, &owner, &leaving, Role::Member).unwrap();
    assert_eq!(acl.key_recipients().count(), 3);

    apply(
        &mut acl,
        &owner,
        AclOp::RemoveMember {
            device: leaving.id(),
        },
    )
    .unwrap();
    apply(&mut acl, &owner, AclOp::RotateKey { epoch: Epoch(1) }).unwrap();

    let recipients: Vec<_> = acl.key_recipients().map(|d| d.id()).collect();
    assert_eq!(recipients.len(), 2);
    assert!(!recipients.contains(&leaving.id()));
    assert!(recipients.contains(&staying.id()));
    assert_eq!(acl.epoch(), Epoch(1));
}

/// A rejected entry must leave the ACL untouched — no partial application.
#[test]
fn a_rejected_entry_does_not_mutate_the_acl() {
    let (mut acl, _owner) = genesis();
    let outsider = Device::generate().unwrap();
    let victim = Device::generate().unwrap();

    let before_head = acl.head();
    let before_seq = acl.next_seq();

    let _ = add(&mut acl, &outsider, &victim, Role::Owner);

    assert_eq!(acl.head(), before_head);
    assert_eq!(acl.next_seq(), before_seq);
    assert_eq!(acl.role(victim.id()), None);
}

#[test]
fn a_device_cannot_be_added_twice() {
    let (mut acl, owner) = genesis();
    let alice = Device::generate().unwrap();

    add(&mut acl, &owner, &alice, Role::Member).unwrap();
    assert_eq!(
        add(&mut acl, &owner, &alice, Role::Admin).unwrap_err(),
        Error::AclRejected("device is already a member")
    );
}

#[test]
fn a_member_may_remove_themselves() {
    let (mut acl, owner) = genesis();
    let alice = Device::generate().unwrap();

    add(&mut acl, &owner, &alice, Role::Admin).unwrap();
    apply(&mut acl, &alice, AclOp::RemoveMember { device: alice.id() }).unwrap();
    assert_eq!(acl.role(alice.id()), None);
}

//! Change log tests for spec §5.

use truepass_crypto::change::{Change, ChangeId, Hlc, UnsignedChange};
use truepass_crypto::encode::Canonical;
use truepass_crypto::error::Error;
use truepass_crypto::identity::Device;
use truepass_crypto::vault::{Epoch, VaultId};

fn change_id(b: u8) -> ChangeId {
    ChangeId::from_bytes([b; 32])
}

fn make(device: &Device, parents: Vec<ChangeId>, payload: &[u8]) -> Change {
    UnsignedChange::new(
        VaultId::from_bytes([9; 16]),
        Epoch(0),
        parents,
        Hlc::new(1_759_000_000_000),
        device.id(),
        payload.to_vec(),
    )
    .sign(device)
}

#[test]
fn sign_and_verify_round_trip() {
    let device = Device::generate().unwrap();
    let change = make(&device, vec![change_id(1)], b"payload");

    assert!(change.verify(device.public().signing_public()).is_ok());
}

#[test]
fn a_different_key_does_not_verify() {
    let device = Device::generate().unwrap();
    let other = Device::generate().unwrap();
    let change = make(&device, vec![], b"payload");

    assert_eq!(
        change.verify(other.public().signing_public()).unwrap_err(),
        Error::Signature
    );
}

/// Adversary A1, the important one. A relay that ships altered contents under
/// the original id and signature must be rejected — which only works because
/// verify recomputes the id from the contents instead of trusting the stored
/// one.
#[test]
fn altered_contents_under_a_valid_signature_are_rejected() {
    let device = Device::generate().unwrap();
    let honest = make(&device, vec![], b"transfer 10");

    let forged = Change::from_parts(
        UnsignedChange::new(
            honest.vault(),
            honest.epoch(),
            honest.parents().to_vec(),
            honest.hlc(),
            honest.author(),
            b"transfer 10000".to_vec(),
        ),
        honest.id(),
        *honest.signature(),
    );

    assert_eq!(
        forged.verify(device.public().signing_public()).unwrap_err(),
        Error::Signature
    );
}

/// A change may not claim an author that does not match the key which signed
/// it, even if both are otherwise valid.
#[test]
fn author_must_match_the_signing_key() {
    let real = Device::generate().unwrap();
    let other = Device::generate().unwrap();

    let impersonating = UnsignedChange::new(
        VaultId::from_bytes([9; 16]),
        Epoch(0),
        vec![],
        Hlc::new(1),
        other.id(),
        b"x".to_vec(),
    )
    .sign(&real);

    assert_eq!(
        impersonating
            .verify(real.public().signing_public())
            .unwrap_err(),
        Error::Signature
    );
}

/// Parents are a set. If caller ordering leaked into the encoding, two devices
/// forming the same logical change would compute different ids and fork the DAG
/// permanently.
#[test]
fn parent_order_does_not_affect_the_id() {
    let device = Device::generate().unwrap();

    let a = make(
        &device,
        vec![change_id(1), change_id(2), change_id(3)],
        b"p",
    );
    let b = make(
        &device,
        vec![change_id(3), change_id(1), change_id(2)],
        b"p",
    );

    assert_eq!(a.id(), b.id());
}

#[test]
fn duplicate_parents_are_collapsed() {
    let device = Device::generate().unwrap();

    let a = make(&device, vec![change_id(1), change_id(1)], b"p");
    let b = make(&device, vec![change_id(1)], b"p");

    assert_eq!(a.id(), b.id());
    assert_eq!(a.parents().len(), 1);
}

#[test]
fn every_field_is_covered_by_the_id() {
    let device = Device::generate().unwrap();
    let base = UnsignedChange::new(
        VaultId::from_bytes([9; 16]),
        Epoch(0),
        vec![change_id(1)],
        Hlc::new(100),
        device.id(),
        b"payload".to_vec(),
    );
    let id = base.id();

    let variants = [
        UnsignedChange::new(
            VaultId::from_bytes([8; 16]),
            Epoch(0),
            vec![change_id(1)],
            Hlc::new(100),
            device.id(),
            b"payload".to_vec(),
        ),
        UnsignedChange::new(
            VaultId::from_bytes([9; 16]),
            Epoch(1),
            vec![change_id(1)],
            Hlc::new(100),
            device.id(),
            b"payload".to_vec(),
        ),
        UnsignedChange::new(
            VaultId::from_bytes([9; 16]),
            Epoch(0),
            vec![change_id(2)],
            Hlc::new(100),
            device.id(),
            b"payload".to_vec(),
        ),
        UnsignedChange::new(
            VaultId::from_bytes([9; 16]),
            Epoch(0),
            vec![change_id(1)],
            Hlc::new(101),
            device.id(),
            b"payload".to_vec(),
        ),
        UnsignedChange::new(
            VaultId::from_bytes([9; 16]),
            Epoch(0),
            vec![change_id(1)],
            Hlc::new(100),
            device.id(),
            b"payload!".to_vec(),
        ),
    ];

    for (i, v) in variants.iter().enumerate() {
        assert_ne!(v.id(), id, "variant {i} did not change the id");
    }
}

#[test]
fn change_encoding_is_tagged() {
    let device = Device::generate().unwrap();
    let unsigned = UnsignedChange::new(
        VaultId::from_bytes([9; 16]),
        Epoch(0),
        vec![],
        Hlc::new(1),
        device.id(),
        b"x".to_vec(),
    );
    assert_eq!(unsigned.canonical_bytes()[0], 2, "Change tag changed");
}

// --- hybrid logical clock ---

#[test]
fn tick_never_goes_backwards() {
    let clock = Hlc::new(1000);

    // Time moved forward.
    assert_eq!(clock.tick(2000), Hlc::new(2000));
    // Same millisecond: counter breaks the tie.
    assert_eq!(
        clock.tick(1000),
        Hlc {
            wall_ms: 1000,
            counter: 1
        }
    );
    // Clock went backwards; the HLC must not.
    let backwards = clock.tick(500);
    assert!(backwards > clock, "HLC regressed on a backwards clock");
}

#[test]
fn repeated_ticks_are_strictly_increasing() {
    let mut clock = Hlc::new(1000);
    for _ in 0..100 {
        let next = clock.tick(1000);
        assert!(next > clock);
        clock = next;
    }
}

/// Causality: after merging a remote change, the local clock must exceed both
/// its previous value and the remote one, even if the remote device's clock is
/// far ahead.
#[test]
fn merge_exceeds_both_inputs() {
    let local = Hlc {
        wall_ms: 1000,
        counter: 5,
    };
    let remote_ahead = Hlc {
        wall_ms: 9000,
        counter: 2,
    };

    let merged = local.merge(remote_ahead, 1000);
    assert!(merged > local);
    assert!(merged > remote_ahead);

    let remote_behind = Hlc {
        wall_ms: 10,
        counter: 0,
    };
    let merged = local.merge(remote_behind, 1000);
    assert!(merged > local);
    assert!(merged > remote_behind);
}

#[test]
fn merge_of_identical_clocks_still_advances() {
    let clock = Hlc {
        wall_ms: 1000,
        counter: 3,
    };
    assert!(clock.merge(clock, 1000) > clock);
}

#[test]
fn hlc_orders_by_wall_time_then_counter() {
    assert!(Hlc::new(1) < Hlc::new(2));
    assert!(
        Hlc {
            wall_ms: 1,
            counter: 0
        } < Hlc {
            wall_ms: 1,
            counter: 1
        }
    );
    assert!(
        Hlc {
            wall_ms: 2,
            counter: 0
        } > Hlc {
            wall_ms: 1,
            counter: 99
        }
    );
}

/// Spec §5: ties break on device id, which is what makes the order total. Two
/// devices must never disagree about which concurrent write won.
#[test]
fn merge_order_is_total_across_concurrent_writes() {
    let a = Device::generate().unwrap();
    let b = Device::generate().unwrap();

    let ca = make(&a, vec![], b"from a");
    let cb = make(&b, vec![], b"from b");

    assert_eq!(ca.hlc(), cb.hlc(), "test needs identical clocks");
    assert_ne!(
        ca.merge_order(),
        cb.merge_order(),
        "concurrent writes did not get a total order"
    );

    // Both devices must reach the same verdict.
    let winner_here = ca.merge_order().max(cb.merge_order());
    let winner_there = cb.merge_order().max(ca.merge_order());
    assert_eq!(winner_here, winner_there);
}

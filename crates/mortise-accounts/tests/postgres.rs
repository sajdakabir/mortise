#![cfg(feature = "postgres")]
use mortise_accounts::{
    Error,
    protocol::*,
    store::{Actor, Identity, Store},
};
use mortise_crypto::identity::{Device, Identity as VaultIdentity};

fn login(store: &Store, subject: &str, device: &Device) -> Session {
    let identity = VaultIdentity::generate().unwrap();
    let certificate = hex(&identity
        .certify(device.public(), (now() * 1000) as u64)
        .to_bytes());
    let input = LoginStart {
        certificate,
        device_name: "Synthetic integration device".into(),
    };
    let body = serde_json::to_vec(&input).unwrap();
    let challenge = store
        .start_login(
            &input,
            &Proof::sign(device, "POST", "/v1/auth/start", "", &body).unwrap(),
            &body,
            now(),
        )
        .unwrap();
    let body = serde_json::to_vec(&LoginFinish {
        id: challenge.id.clone(),
        id_token: "synthetic-not-a-real-token".into(),
        access_token: None,
    })
    .unwrap();
    store
        .finish_login(
            &challenge.id,
            &Identity {
                issuer: "https://integration.invalid".into(),
                subject: subject.into(),
                email: format!("{subject}@example.invalid"),
                name: "Synthetic account".into(),
            },
            &Proof::sign(device, "POST", "/v1/auth/finish", "", &body).unwrap(),
            &body,
            now(),
        )
        .unwrap()
}
fn actor(store: &Store, device: &Device, session: &Session) -> Actor {
    let proof = Proof::sign(device, "GET", "/v1/me", &session.token, b"").unwrap();
    let actor = store
        .authenticate(&session.token, &proof, "GET", "/v1/me", b"", now())
        .unwrap();
    assert!(matches!(
        store.authenticate(&session.token, &proof, "GET", "/v1/me", b"", now()),
        Err(Error::Unauthorized)
    ));
    actor
}

#[test]
#[ignore = "requires an isolated Neon test branch and MORTISE_TEST_DATABASE_URL"]
fn postgres_account_device_invitation_and_concurrency_flow() {
    let store = Store::postgres(
        &std::env::var("MORTISE_TEST_DATABASE_URL").expect("Set the isolated test branch URL"),
    )
    .unwrap();
    let subject = random().unwrap();
    // Two API instances log in to the same identity at once. Exactly one
    // first device may become trusted, even when the processes do not share a mutex.
    let other = Store::postgres(&std::env::var("MORTISE_TEST_DATABASE_URL").unwrap()).unwrap();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let first = Device::generate().unwrap();
    let second = Device::generate().unwrap();
    let (one, two) = std::thread::scope(|scope| {
        let a = scope.spawn(|| {
            barrier.wait();
            login(&store, &subject, &first)
        });
        let b = scope.spawn(|| {
            barrier.wait();
            login(&other, &subject, &second)
        });
        (a.join().unwrap(), b.join().unwrap())
    });
    let a = actor(&store, &first, &one);
    let b = actor(&other, &second, &two);
    let dashboard = store.dashboard(&a).unwrap();
    assert_eq!(dashboard.devices.len(), 2);
    assert_eq!(
        dashboard
            .devices
            .iter()
            .filter(|d| d.status == "trusted")
            .count(),
        1
    );
    let (trusted, pending, pending_device, pending_session) = if dashboard
        .devices
        .iter()
        .any(|d| d.id == a.device_id && d.status == "trusted")
    {
        (&a, &b, &second, &two)
    } else {
        (&b, &a, &first, &one)
    };
    assert!(matches!(
        store.create_team(pending, "Must be rejected", now()),
        Err(Error::Untrusted)
    ));
    let pending_info = dashboard
        .devices
        .iter()
        .find(|d| d.id == pending.device_id)
        .unwrap();
    store
        .approve_device(trusted, &pending.device_id, &pending_info.certificate)
        .unwrap();
    let team = store
        .create_team(pending, "Synthetic integration team", now())
        .unwrap();
    let guest_device = Device::generate().unwrap();
    let guest = login(&store, &random().unwrap(), &guest_device);
    let guest_actor = actor(&store, &guest_device, &guest);
    assert!(matches!(
        store.members(&guest_actor, &team.id),
        Err(Error::Forbidden)
    ));
    let invite = store
        .invite(
            pending,
            &team.id,
            &NewInvite {
                email: Some(guest.account.email.clone()),
                role: "member".into(),
            },
            now(),
        )
        .unwrap();
    assert_eq!(
        store
            .preview(&guest_actor, &invite.token, now())
            .unwrap()
            .team_id,
        team.id
    );
    store
        .request_invite(&guest_actor, &invite.token, now())
        .unwrap();
    assert!(matches!(
        store.members(&guest_actor, &team.id),
        Err(Error::Forbidden)
    ));
    let requests = store.requests(pending, &team.id, now()).unwrap();
    assert_eq!(requests.len(), 1);
    store
        .decide(
            pending,
            &team.id,
            &invite.id,
            &DecideInvite {
                account_id: guest.account.id.clone(),
                approve: true,
            },
            now(),
        )
        .unwrap();
    assert_eq!(store.members(&guest_actor, &team.id).unwrap().len(), 2);
    store
        .remove_member(pending, &team.id, &guest.account.id)
        .unwrap();
    assert!(matches!(
        store.members(&guest_actor, &team.id),
        Err(Error::Forbidden)
    ));
    store.revoke_device(trusted, &pending.device_id).unwrap();
    let proof = Proof::sign(pending_device, "GET", "/v1/me", &pending_session.token, b"").unwrap();
    assert!(matches!(
        store.authenticate(&pending_session.token, &proof, "GET", "/v1/me", b"", now()),
        Err(Error::Unauthorized)
    ));
    assert!(store.revoke_device(trusted, &trusted.device_id).is_err());
    println!(
        "Postgres verified: concurrent enrollment, trust approval, replay rejection, invitations, membership isolation, revocation."
    );
}

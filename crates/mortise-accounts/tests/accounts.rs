use mortise_accounts::{
    Error,
    protocol::*,
    store::{Actor, Identity, Store},
};
use mortise_crypto::identity::{Device, Identity as VaultIdentity};

#[test]
fn approval_addresses_cannot_contain_display_control_characters() {
    use mortise_accounts::store::normalize_email;
    assert_eq!(
        normalize_email(" Alice@Example.com ").unwrap(),
        "alice@example.com"
    );
    assert!(normalize_email("alice\u{202e}@example.com").is_err());
    assert!(normalize_email("alice\u{a0}@example.com").is_err());
}

#[tokio::test]
async fn http_routes_require_signed_sessions_and_reject_replay_and_secret_fields() {
    use axum::{body::Body, http::Request};
    use mortise_accounts::server::{Service, router};
    use tower::ServiceExt;
    let store = Store::memory().unwrap();
    let alice = login(&store, "alice", "alice@example.com");
    let router = router(Service {
        store,
        auth: AuthConfig {
            issuer: "https://issuer.example".into(),
            client_id: "mortise".into(),
            callback_port: None,
            resource: None,
        },
    });
    let response = router
        .clone()
        .oneshot(Request::get("/v1/me").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), 401);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let proof = Proof::sign(&alice.device, "GET", "/v1/me", &alice.session.token, b"").unwrap();
    for status in [200, 401] {
        let request = Request::get("/v1/me")
            .header("authorization", format!("Bearer {}", alice.session.token))
            .header("x-mortise-proof", serde_json::to_string(&proof).unwrap())
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            router.clone().oneshot(request).await.unwrap().status(),
            status
        );
    }
    let body = br#"{"name":"No secret storage","password":"do-not-accept"}"#;
    let proof = Proof::sign(
        &alice.device,
        "POST",
        "/v1/teams",
        &alice.session.token,
        body,
    )
    .unwrap();
    let response = router
        .clone()
        .oneshot(
            Request::post("/v1/teams")
                .header("authorization", format!("Bearer {}", alice.session.token))
                .header("x-mortise-proof", serde_json::to_string(&proof).unwrap())
                .body(Body::from(body.to_vec()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 400);
    let response = router
        .oneshot(
            Request::post("/v1/auth/start")
                .body(Body::from(vec![0; 33 * 1024]))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 413);
}

struct User {
    device: Device,
    cert: String,
    session: Session,
}
fn login(store: &Store, subject: &str, email: &str) -> User {
    let identity = VaultIdentity::generate().unwrap();
    let device = Device::generate().unwrap();
    let cert = hex(&identity
        .certify(device.public(), (now() * 1000) as u64)
        .to_bytes());
    let session = login_device(store, subject, email, &device, &cert).unwrap();
    User {
        device,
        cert,
        session,
    }
}
fn login_device(
    store: &Store,
    subject: &str,
    email: &str,
    device: &Device,
    cert: &str,
) -> mortise_accounts::Result<Session> {
    let start = LoginStart {
        certificate: cert.into(),
        device_name: "Test Mac".into(),
    };
    let body = serde_json::to_vec(&start).unwrap();
    let proof = Proof::sign(device, "POST", "/v1/auth/start", "", &body).unwrap();
    let challenge = store.start_login(&start, &proof, &body, now())?;
    let body = serde_json::to_vec(&LoginFinish {
        id: challenge.id.clone(),
        id_token: "TEST_ID_TOKEN_NEVER_PERSIST".into(),
    })
    .unwrap();
    let proof = Proof::sign(device, "POST", "/v1/auth/finish", "", &body).unwrap();
    // This fixture represents an identity AFTER verification. Separate OIDC
    // tests cover signature/issuer/audience/nonce/expiry/email validation.
    store.finish_login(
        &challenge.id,
        &Identity {
            issuer: "https://issuer.example".into(),
            subject: subject.into(),
            email: email.into(),
            name: subject.into(),
        },
        &proof,
        &body,
        now(),
    )
}
fn actor(store: &Store, user: &User) -> Actor {
    let proof = Proof::sign(&user.device, "GET", "/v1/me", &user.session.token, b"").unwrap();
    store
        .authenticate(&user.session.token, &proof, "GET", "/v1/me", b"", now())
        .unwrap()
}

#[test]
fn new_devices_require_existing_device_approval_and_exact_certificate() {
    let store = Store::memory().unwrap();
    let first = login(&store, "alice", "alice@example.com");
    let owner = actor(&store, &first);
    assert_eq!(
        store.dashboard(&owner).unwrap().devices[0].status,
        "trusted"
    );
    let next = login(&store, "alice", "alice@example.com");
    let pending = actor(&store, &next);
    assert!(matches!(
        store.create_team(&pending, "No", now()),
        Err(Error::Untrusted)
    ));
    assert!(
        store
            .approve_device(&pending, &pending.device_id, &next.cert)
            .is_err()
    );
    assert!(
        store
            .approve_device(&owner, &pending.device_id, &first.cert)
            .is_err()
    );
    store
        .approve_device(&owner, &pending.device_id, &next.cert)
        .unwrap();
    store.create_team(&pending, "Allowed", now()).unwrap();
    assert!(
        store
            .approve_device(&owner, &pending.device_id, &next.cert)
            .is_err()
    );
}

#[test]
fn device_revocation_kills_sessions_and_does_not_rebootstrap() {
    let store = Store::memory().unwrap();
    let a = login(&store, "alice", "alice@example.com");
    let owner = actor(&store, &a);
    assert!(store.revoke_device(&owner, &owner.device_id).is_err());
    let b = login(&store, "alice", "alice@example.com");
    let pending = actor(&store, &b);
    store
        .approve_device(&owner, &pending.device_id, &b.cert)
        .unwrap();
    store.revoke_device(&owner, &pending.device_id).unwrap();
    let proof = Proof::sign(&b.device, "GET", "/v1/me", &b.session.token, b"").unwrap();
    assert!(
        store
            .authenticate(&b.session.token, &proof, "GET", "/v1/me", b"", now())
            .is_err()
    );
    assert!(login_device(&store, "alice", "alice@example.com", &b.device, &b.cert).is_err());
    let c = login(&store, "alice", "alice@example.com");
    assert!(matches!(
        store.create_team(&actor(&store, &c), "No", now()),
        Err(Error::Untrusted)
    ));
}

#[test]
fn requests_are_bound_to_device_session_path_body_and_nonce() {
    let store = Store::memory().unwrap();
    let a = login(&store, "alice", "a@example.com");
    let b = login(&store, "bob", "b@example.com");
    let proof = Proof::sign(&a.device, "GET", "/v1/me", &a.session.token, b"").unwrap();
    assert!(
        store
            .authenticate(&a.session.token, &proof, "POST", "/v1/me", b"", now())
            .is_err()
    );
    assert!(
        store
            .authenticate(&a.session.token, &proof, "GET", "/v1/me", b"changed", now())
            .is_err()
    );
    assert!(
        store
            .authenticate(&b.session.token, &proof, "GET", "/v1/me", b"", now())
            .is_err()
    );
    assert!(
        store
            .authenticate(&a.session.token, &proof, "GET", "/v1/teams", b"", now())
            .is_err()
    );
    store
        .authenticate(&a.session.token, &proof, "GET", "/v1/me", b"", now())
        .unwrap();
    assert!(
        store
            .authenticate(&a.session.token, &proof, "GET", "/v1/me", b"", now())
            .is_err()
    );
    let mut proof = Proof::sign(&a.device, "GET", "/v1/me", &a.session.token, b"").unwrap();
    proof.timestamp = i64::MIN;
    assert!(
        store
            .authenticate(&a.session.token, &proof, "GET", "/v1/me", b"", now())
            .is_err()
    );
}

#[test]
fn email_does_not_merge_accounts_and_cross_account_devices_are_denied() {
    let store = Store::memory().unwrap();
    let a = login(&store, "alice", "same@example.com");
    let b = login(&store, "impostor", "same@example.com");
    assert_ne!(a.session.account.id, b.session.account.id);
    let aa = actor(&store, &a);
    let bb = actor(&store, &b);
    assert!(store.revoke_device(&aa, &bb.device_id).is_err());
    assert!(login_device(&store, "impostor", "same@example.com", &a.device, &a.cert).is_err());
    let team = store.create_team(&aa, "Private", now()).unwrap();
    assert!(store.members(&bb, &team.id).is_err());
    assert!(
        store
            .invite(
                &bb,
                &team.id,
                &NewInvite {
                    email: None,
                    role: "member".into()
                },
                now()
            )
            .is_err()
    );
}

#[test]
fn invitation_requires_request_and_explicit_correct_account_approval() {
    let store = Store::memory().unwrap();
    let a = login(&store, "alice", "alice@example.com");
    let b = login(&store, "bob", "bob@example.com");
    let c = login(&store, "eve", "eve@example.com");
    let aa = actor(&store, &a);
    let bb = actor(&store, &b);
    let cc = actor(&store, &c);
    let team = store.create_team(&aa, "Team", now()).unwrap();
    let invitation = store
        .invite(
            &aa,
            &team.id,
            &NewInvite {
                email: Some("BOB@example.com".into()),
                role: "member".into(),
            },
            now(),
        )
        .unwrap();
    assert!(store.preview(&cc, &invitation.token, now()).is_err());
    assert!(store.request_invite(&cc, &invitation.token, now()).is_err());
    store.preview(&bb, &invitation.token, now()).unwrap();
    assert!(store.members(&bb, &team.id).is_err());
    store.request_invite(&bb, &invitation.token, now()).unwrap();
    store.request_invite(&bb, &invitation.token, now()).unwrap(); // retry is idempotent
    assert!(store.members(&bb, &team.id).is_err());
    assert!(
        store
            .decide(
                &aa,
                &team.id,
                &invitation.id,
                &DecideInvite {
                    account_id: cc.account_id.clone(),
                    approve: true
                },
                now()
            )
            .is_err()
    );
    store
        .decide(
            &aa,
            &team.id,
            &invitation.id,
            &DecideInvite {
                account_id: bb.account_id.clone(),
                approve: true,
            },
            now(),
        )
        .unwrap();
    assert_eq!(store.members(&bb, &team.id).unwrap().len(), 2);
    assert!(store.request_invite(&cc, &invitation.token, now()).is_err());
    assert!(
        store
            .invite(
                &bb,
                &team.id,
                &NewInvite {
                    email: None,
                    role: "admin".into()
                },
                now()
            )
            .is_err()
    );
    assert!(store.remove_member(&bb, &team.id, &aa.account_id).is_err());
    store.remove_member(&aa, &team.id, &bb.account_id).unwrap();
    assert!(store.members(&bb, &team.id).is_err());
}

#[test]
fn expired_declined_and_revoked_invites_never_grant_access() {
    let store = Store::memory().unwrap();
    let a = login(&store, "alice", "a@example.com");
    let b = login(&store, "bob", "b@example.com");
    let aa = actor(&store, &a);
    let bb = actor(&store, &b);
    let team = store.create_team(&aa, "Team", now()).unwrap();
    let new = || {
        store
            .invite(
                &aa,
                &team.id,
                &NewInvite {
                    email: None,
                    role: "member".into(),
                },
                now(),
            )
            .unwrap()
    };
    let expired = new();
    assert!(
        store
            .request_invite(&bb, &expired.token, expired.expires_at)
            .is_err()
    );
    let declined = new();
    store.request_invite(&bb, &declined.token, now()).unwrap();
    store
        .decide(
            &aa,
            &team.id,
            &declined.id,
            &DecideInvite {
                account_id: bb.account_id.clone(),
                approve: false,
            },
            now(),
        )
        .unwrap();
    assert!(store.request_invite(&bb, &declined.token, now()).is_err());
    let revoked = new();
    store.revoke_invite(&aa, &team.id, &revoked.id).unwrap();
    assert!(store.request_invite(&bb, &revoked.token, now()).is_err());
    assert!(store.members(&bb, &team.id).is_err());
}

#[test]
fn secrets_are_not_persisted_and_unknown_vault_fields_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("accounts.sqlite");
    let store = Store::open(&path).unwrap();
    let a = login(&store, "alice", "alice@example.com");
    let aa = actor(&store, &a);
    let team = store.create_team(&aa, "Team", now()).unwrap();
    let invite = store
        .invite(
            &aa,
            &team.id,
            &NewInvite {
                email: None,
                role: "member".into(),
            },
            now(),
        )
        .unwrap();
    let bytes = std::fs::read(path).unwrap();
    let text = String::from_utf8_lossy(&bytes);
    for secret in [
        &a.session.token,
        &invite.token,
        "TEST_ID_TOKEN_NEVER_PERSIST",
    ] {
        assert!(!text.contains(secret));
    }
    assert!(serde_json::from_str::<Named>(r#"{"name":"Team","password":"secret"}"#).is_err());
    assert!(
        serde_json::from_str::<NewInvite>(r#"{"email":null,"role":"member","env":"SECRET=value"}"#)
            .is_err()
    );
}

#[test]
fn logout_and_session_expiry_require_sign_in_again() {
    let store = Store::memory().unwrap();
    let a = login(&store, "alice", "a@example.com");
    let proof = Proof::sign(&a.device, "GET", "/v1/me", &a.session.token, b"").unwrap();
    assert!(
        store
            .authenticate(
                &a.session.token,
                &proof,
                "GET",
                "/v1/me",
                b"",
                a.session.expires_at
            )
            .is_err()
    );
    store.logout(&a.session.token).unwrap();
    assert!(
        store
            .authenticate(&a.session.token, &proof, "GET", "/v1/me", b"", now())
            .is_err()
    );
}

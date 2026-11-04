use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use mortise_accounts::{
    oidc,
    protocol::{AuthConfig, now},
};
use mortise_crypto::ed25519::SigningKey;
use openidconnect::core::{CoreJsonWebKeySet, CoreProviderMetadata};
use serde_json::{Value, json};
use signature::Signer;

fn fixture() -> (AuthConfig, CoreProviderMetadata, SigningKey, Value) {
    let config = AuthConfig {
        issuer: "https://issuer.example".into(),
        client_id: "mortise-desktop".into(),
        callback_port: None,
        resource: None,
    };
    let key = SigningKey::from_bytes(&[42; 32]);
    let jwks:CoreJsonWebKeySet=serde_json::from_value(json!({"keys":[{"kty":"OKP","crv":"Ed25519","x":B64.encode(key.verifying_key().to_bytes()),"kid":"test","use":"sig","alg":"EdDSA"}]})).unwrap();
    let metadata:CoreProviderMetadata=serde_json::from_value(json!({"issuer":config.issuer,"authorization_endpoint":"https://issuer.example/authorize","token_endpoint":"https://issuer.example/token","jwks_uri":"https://issuer.example/jwks","response_types_supported":["code"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["EdDSA"]})).unwrap();
    let claims = json!({"iss":config.issuer,"sub":"alice","aud":config.client_id,"exp":now()+300,"iat":now(),"nonce":"expected","email":"alice@example.com","email_verified":true,"name":"Alice"});
    (config, metadata.set_jwks(jwks), key, claims)
}
fn jwt(key: &SigningKey, claims: &Value) -> String {
    let header = B64.encode(br#"{"alg":"EdDSA","kid":"test"}"#);
    let payload = B64.encode(serde_json::to_vec(claims).unwrap());
    let signing = format!("{header}.{payload}");
    format!(
        "{signing}.{}",
        B64.encode(key.sign(signing.as_bytes()).to_bytes())
    )
}
#[test]
fn verified_oidc_identity_is_required() {
    let (config, metadata, key, claims) = fixture();
    let identity = oidc::verify(&config, metadata, &jwt(&key, &claims), "expected", None).unwrap();
    assert_eq!(identity.subject, "alice");
    assert_eq!(identity.email, "alice@example.com");
}
#[test]
fn token_substitution_expiry_nonce_and_unverified_email_fail_closed() {
    for (field, value) in [
        ("iss", json!("https://attacker.example")),
        ("aud", json!("another-client")),
        ("exp", json!(now() - 600)),
        ("iat", json!(now() + 600)),
        ("nonce", json!("wrong")),
        ("email_verified", json!(false)),
    ] {
        let (config, metadata, key, mut claims) = fixture();
        claims[field] = value;
        assert!(
            oidc::verify(&config, metadata, &jwt(&key, &claims), "expected", None).is_err(),
            "accepted {field}"
        );
    }
    let (config, metadata, _, claims) = fixture();
    assert!(
        oidc::verify(
            &config,
            metadata,
            &jwt(&SigningKey::from_bytes(&[43; 32]), &claims),
            "expected",
            None
        )
        .is_err()
    );
}

/// Exercise discovery, PKCE, the loopback callback, both ID-token verifiers,
/// device-signed login and authenticated requests against isolated HTTP servers.
#[cfg(feature = "client")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_login_and_account_service_work_with_a_configured_provider() {
    use axum::{
        Json, Router,
        extract::Form,
        routing::{get, post},
    };
    use mortise_accounts::{
        client::{Client, Request},
        protocol::*,
        server::{Service, router},
        store::Store,
    };
    use mortise_crypto::identity::{Device, Identity};
    use openidconnect::{PkceCodeChallenge, PkceCodeVerifier};
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
    };

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let issuer = format!("http://{}", listener.local_addr().unwrap());
    let provider_config = AuthConfig {
        issuer: issuer.clone(),
        client_id: "mortise-test".into(),
        callback_port: None,
        resource: Some("https://accounts.example".into()),
    };
    let authorization = Arc::new(Mutex::new(HashMap::<String, String>::new()));
    let token_authorization = authorization.clone();
    let token_issuer = issuer.clone();
    let metadata = json!({"issuer":issuer,"authorization_endpoint":format!("{issuer}/authorize"),"token_endpoint":format!("{issuer}/token"),"userinfo_endpoint":format!("{issuer}/userinfo"),"jwks_uri":format!("{issuer}/jwks"),"response_types_supported":["code"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["EdDSA"]});
    let key = SigningKey::from_bytes(&[42; 32]);
    let jwks = json!({"keys":[{"kty":"OKP","crv":"Ed25519","x":B64.encode(key.verifying_key().to_bytes()),"kid":"test","use":"sig","alg":"EdDSA"}]});
    let provider = Router::new()
        .route("/.well-known/openid-configuration", get(move || async move { Json(metadata) }))
        .route("/jwks", get(move || async move { Json(jwks) }))
        .route("/userinfo", get(|headers: axum::http::HeaderMap| async move {
            assert_eq!(headers["authorization"], "Bearer test-access-token");
            Json(json!({"sub":"test-alice","email":"alice@example.com","email_verified":true,"name":"Alice"}))
        }))
        .route("/token", post(move |Form(form): Form<HashMap<String,String>>| async move {
            let auth = token_authorization.lock().unwrap();
            assert_eq!(form["grant_type"], "authorization_code");
            assert_eq!(form["code"], "test-authorization-code");
            assert_eq!(form["client_id"], "mortise-test");
            assert_eq!(form["redirect_uri"], auth["redirect_uri"]);
            assert_eq!(form["resource"], "https://accounts.example");
            let challenge = PkceCodeChallenge::from_code_verifier_sha256(&PkceCodeVerifier::new(form["code_verifier"].clone()));
            assert_eq!(challenge.as_str(), auth["code_challenge"]);
            let claims = json!({"iss":token_issuer,"sub":"test-alice","aud":"mortise-test","iat":now(),"exp":now()+300,"nonce":auth["nonce"]});
            Json(json!({"access_token":"test-access-token","token_type":"Bearer","expires_in":300,"id_token":jwt(&key,&claims)}))
        }));
    let provider_task = tokio::spawn(async move {
        axum::serve(listener, provider).await.unwrap();
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let service_url = format!("http://{}", listener.local_addr().unwrap());
    let service = router(Service {
        store: Store::memory().unwrap(),
        auth: provider_config,
    });
    let account_task = tokio::spawn(async move {
        axum::serve(listener, service).await.unwrap();
    });

    tokio::task::spawn_blocking(move || {
        let identity = Identity::generate().unwrap();
        let device = Device::generate().unwrap();
        let client = Client::new(&service_url, String::new()).unwrap();
        let config = client.config().unwrap();
        let start = LoginStart {
            certificate: hex(&identity
                .certify(device.public(), now() as u64 * 1000)
                .to_bytes()),
            device_name: "Test Mac".into(),
        };
        let challenge: LoginChallenge = client
            .send(Request::signed(&device, "POST", "/v1/auth/start", "", &start).unwrap())
            .unwrap();
        let token = mortise_accounts::client::browser_login(&config, &challenge.nonce, |url| {
            let url = url::Url::parse(url).unwrap();
            let params: HashMap<String, String> = url
                .query_pairs()
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect();
            assert_eq!(url.path(), "/authorize");
            assert_eq!(params["code_challenge_method"], "S256");
            assert_eq!(params["resource"], "https://accounts.example");
            assert!(params["scope"].split(' ').any(|s| s == "openid"));
            let mut callback = url::Url::parse(&params["redirect_uri"]).unwrap();
            callback
                .query_pairs_mut()
                .append_pair("state", &params["state"])
                .append_pair("code", "test-authorization-code");
            *authorization.lock().unwrap() = params;
            std::thread::spawn(move || {
                assert_eq!(ureq::get(callback.as_str()).call().unwrap().status(), 200);
            });
            Ok(())
        })
        .unwrap();
        let finish = LoginFinish {
            id: challenge.id,
            id_token: token.id_token.to_string(),
            access_token: Some(token.access_token.to_string()),
        };
        let session: Session = client
            .send(Request::signed(&device, "POST", "/v1/auth/finish", "", &finish).unwrap())
            .unwrap();
        let client = Client::new(&service_url, session.token).unwrap();
        let dashboard: Dashboard = client
            .send(Request::signed(&device, "GET", "/v1/me", client.token(), &()).unwrap())
            .unwrap();
        assert_eq!(dashboard.account.email, "alice@example.com");
        assert_eq!(dashboard.devices[0].status, "trusted");
        let team: Team = client
            .send(
                Request::signed(
                    &device,
                    "POST",
                    "/v1/teams",
                    client.token(),
                    &Named {
                        name: "Builders".into(),
                    },
                )
                .unwrap(),
            )
            .unwrap();
        assert_eq!(team.role, "owner");
    })
    .await
    .unwrap();
    provider_task.abort();
    account_task.abort();
}

/// UserInfo is trusted only after verifying the ID token, matching its subject,
/// and checking at_hash when present. A redirect must never receive the bearer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn userinfo_requires_verified_matching_identity_and_bound_access_token() {
    use axum::{Json, Router, http::StatusCode, response::IntoResponse, routing::get};
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };
    let profile = Arc::new(Mutex::new(
        json!({"sub":"alice","email":"alice@example.com","email_verified":true,"name":"Alice"}),
    ));
    let hits = Arc::new(AtomicUsize::new(0));
    let redirects = Arc::new(AtomicUsize::new(0));
    let route_profile = profile.clone();
    let route_hits = hits.clone();
    let route_redirects = redirects.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/userinfo", listener.local_addr().unwrap());
    let redirect_target = format!("http://{}/leak", listener.local_addr().unwrap());
    let provider = Router::new()
        .route(
            "/userinfo",
            get(move |headers: axum::http::HeaderMap| async move {
                route_hits.fetch_add(1, Ordering::SeqCst);
                assert_eq!(headers["authorization"], "Bearer test-access-token");
                Json(route_profile.lock().unwrap().clone())
            }),
        )
        .route(
            "/redirect",
            get(move || async move {
                (StatusCode::FOUND, [("location", redirect_target)]).into_response()
            }),
        )
        .route(
            "/leak",
            get(move || async move {
                route_redirects.fetch_add(1, Ordering::SeqCst);
                StatusCode::OK
            }),
        );
    let task = tokio::spawn(async move {
        axum::serve(listener, provider).await.unwrap();
    });
    tokio::task::spawn_blocking(move || {
        let (config, metadata, key, mut claims) = fixture();
        for field in ["email", "email_verified", "name"] {
            claims.as_object_mut().unwrap().remove(field);
        }
        // First half of SHA-512("test-access-token"), as used by Ed25519 at_hash.
        claims["at_hash"] = json!("ejJiOBQrTitkMwotmJ0AFiWz7t_fIiCEWu7ao68p9OE");
        let metadata = metadata.set_userinfo_endpoint(Some(
            openidconnect::UserInfoUrl::new(endpoint.clone()).unwrap(),
        ));
        let token = jwt(&key, &claims);
        let identity = oidc::verify(
            &config,
            metadata.clone(),
            &token,
            "expected",
            Some("test-access-token"),
        )
        .unwrap();
        assert_eq!(identity.email, "alice@example.com");
        assert_eq!(identity.subject, "alice");
        assert_eq!(identity.name, "Alice");
        // Rejected before a bearer can be forwarded.
        for (token, nonce, access) in [
            (token.clone(), "expected", None),
            (token.clone(), "expected", Some("substituted-access-token")),
            (token.clone(), "wrong", Some("test-access-token")),
            (
                jwt(&SigningKey::from_bytes(&[43; 32]), &claims),
                "expected",
                Some("test-access-token"),
            ),
        ] {
            assert!(oidc::verify(&config, metadata.clone(), &token, nonce, access).is_err());
        }
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        for value in [
            json!({"sub":"mallory","email":"alice@example.com","email_verified":true}),
            json!({"sub":"alice","email":"alice@example.com","email_verified":false}),
            json!({"sub":"alice","email":"alice@example.com"}),
            json!({"sub":"alice","email_verified":true}),
        ] {
            *profile.lock().unwrap() = value;
            assert!(
                oidc::verify(
                    &config,
                    metadata.clone(),
                    &token,
                    "expected",
                    Some("test-access-token")
                )
                .is_err()
            );
        }
        let redirected = metadata.clone().set_userinfo_endpoint(Some(
            openidconnect::UserInfoUrl::new(endpoint.replace("/userinfo", "/redirect")).unwrap(),
        ));
        assert!(
            oidc::verify(
                &config,
                redirected,
                &token,
                "expected",
                Some("test-access-token")
            )
            .is_err()
        );
        assert_eq!(redirects.load(Ordering::SeqCst), 0);
        let missing = metadata.set_userinfo_endpoint(None);
        assert!(
            oidc::verify(
                &config,
                missing,
                &token,
                "expected",
                Some("test-access-token")
            )
            .is_err()
        );
    })
    .await
    .unwrap();
    task.abort();
}

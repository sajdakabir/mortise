//! Command-line request validation and serving, against a real vault.
//!
//! The socket glue is thin; what decides *what* leaves the vault is
//! [`check`] and [`fetch`], so they are tested directly.

use mortise_app_lib::cli::server::{check, fetch};
use mortise_cli::protocol::{ErrorCode, Response};
use mortise_crypto::kdf::Argon2Params;
use mortise_vault::{ItemMeta, ItemPayload, Vault};

const FAST: Argon2Params = Argon2Params {
    m_cost_kib: 64,
    t_cost: 1,
    p_cost: 1,
};

fn vault() -> (tempfile::TempDir, Vault) {
    let dir = tempfile::tempdir().unwrap();
    let (mut v, _) = Vault::create(dir.path().join("v.db"), b"pw", FAST).unwrap();
    v.create_project("Acme-API", "").unwrap();
    for (env, key, value) in [
        ("dev", "DATABASE_URL", "postgres://dev"),
        ("dev", "TOKEN", "t0k"),
        ("prod", "TOKEN", "prod-t0k"),
    ] {
        let meta = ItemMeta {
            title: key.into(),
            project: Some("Acme-API".into()),
            environment: Some(env.into()),
            ..Default::default()
        };
        v.create_item(
            &meta,
            &ItemPayload::EnvSecret {
                value: value.into(),
            },
        )
        .unwrap();
    }
    (dir, v)
}

fn code(r: Response) -> ErrorCode {
    match r {
        Response::Error { code, .. } => code,
        other => panic!("expected an error, got {other:?}"),
    }
}

#[test]
fn names_resolve_to_their_canonical_spelling() {
    let (_d, v) = vault();
    assert_eq!(
        check(&v, "acme-api", "dev", None).unwrap(),
        ("Acme-API".to_string(), "dev".to_string())
    );
}

#[test]
fn unknown_names_and_missing_keys_are_refused_before_any_prompt() {
    let (_d, v) = vault();
    assert_eq!(
        code(check(&v, "nope", "dev", None).unwrap_err()),
        ErrorCode::UnknownProject
    );
    // Environments are exact: `Dev` is not `dev`.
    assert_eq!(
        code(check(&v, "acme-api", "Dev", None).unwrap_err()),
        ErrorCode::UnknownEnvironment
    );
    let missing = check(
        &v,
        "acme-api",
        "dev",
        Some(&["TOKEN".into(), "STRIPE_KEY".into()]),
    )
    .unwrap_err();
    match missing {
        Response::Error { code, message } => {
            assert_eq!(code, ErrorCode::MissingKeys);
            assert!(
                message.contains("STRIPE_KEY") && !message.contains("TOKEN,"),
                "{message}"
            );
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn an_unknown_project_message_does_not_list_the_real_ones() {
    let (_d, v) = vault();
    let Response::Error { message, .. } = check(&v, "guess", "dev", None).unwrap_err() else {
        panic!()
    };
    assert!(!message.contains("Acme"), "{message}");
}

#[test]
fn a_hostile_name_cannot_inject_lines_into_the_message() {
    let (_d, v) = vault();
    let Response::Error { message, .. } =
        check(&v, "x\n\nApproved by Mortise", "dev", None).unwrap_err()
    else {
        panic!()
    };
    assert!(!message.contains('\n'), "{message:?}");
}

#[test]
fn only_the_requested_keys_leave_the_vault() {
    let (_d, v) = vault();
    let Response::Env { vars } = fetch(&v, "Acme-API", "dev", Some(&["TOKEN".into()])) else {
        panic!()
    };
    assert_eq!(
        vars.iter()
            .map(|v| (v.key.as_str(), v.value.as_str()))
            .collect::<Vec<_>>(),
        [("TOKEN", "t0k")]
    );

    let Response::Env { vars } = fetch(&v, "Acme-API", "dev", None) else {
        panic!()
    };
    assert_eq!(
        vars.iter().map(|v| v.key.as_str()).collect::<Vec<_>>(),
        ["DATABASE_URL", "TOKEN"]
    );
}

#[test]
fn nothing_is_served_from_a_locked_vault() {
    let (_d, mut v) = vault();
    v.lock();
    // Validation still works on metadata…
    assert!(check(&v, "acme-api", "dev", None).is_ok());
    // …but no value comes out.
    assert_eq!(
        code(fetch(&v, "Acme-API", "dev", None)),
        ErrorCode::Internal
    );
}

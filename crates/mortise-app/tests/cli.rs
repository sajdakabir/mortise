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
                previous: None,
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

// --- agent sessions against real processes ---

use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Command, Stdio};

use mortise_app_lib::cli::access::{
    CliAccess, Coverage, ProcessKey, RequestKind, RequestSummary, process_alive,
};

fn key(pid: i32) -> ProcessKey {
    let info = mortise_macos::process_info(pid).expect("process should exist");
    ProcessKey {
        pid,
        started_at_us: info.started_at_us,
    }
}

fn lineage(pid: i32) -> Vec<ProcessKey> {
    mortise_macos::process_chain(pid, 64)
        .into_iter()
        .map(|p| ProcessKey {
            pid: p.pid,
            started_at_us: p.started_at_us,
        })
        .collect()
}

fn session_request() -> RequestSummary {
    RequestSummary {
        id: "s".into(),
        kind: RequestKind::Session,
        project: "api".into(),
        environment: "dev".into(),
        keys: None,
        command: "agent".into(),
        directory: "/".into(),
        process_chain: Vec::new(),
    }
}

/// An "agent" (`sh`) with a grandchild (`sleep`) standing in for a command
/// it ran. Returns the agent and the grandchild's pid.
fn spawn_agent() -> (std::process::Child, i32) {
    let mut agent = Command::new("sh")
        .args(["-c", "sleep 30 & echo $!; wait"])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(agent.stdout.as_mut().unwrap())
        .read_line(&mut line)
        .unwrap();
    (agent, line.trim().parse().unwrap())
}

#[test]
fn a_session_covers_the_agents_real_descendants_and_nothing_else() {
    let (mut agent, grandchild) = spawn_agent();
    let root = key(agent.id() as i32);
    let access = CliAccess::default();
    access.start_session(&session_request(), root);

    assert_eq!(
        access.coverage("api", "dev", Path::new("/"), &lineage(grandchild)),
        Some(Coverage::Session)
    );

    // A sibling — same parent (this test), not inside the agent.
    let mut sibling = Command::new("sleep").arg("30").spawn().unwrap();
    assert_eq!(
        access.coverage("api", "dev", Path::new("/"), &lineage(sibling.id() as i32)),
        None
    );

    let _ = sibling.kill();
    let _ = agent.kill();
    let _ = agent.wait();
    let _ = sibling.wait();
    let _ = Command::new("kill").arg(grandchild.to_string()).status();

    assert!(!process_alive(root), "the agent has exited");
    assert!(
        access.grants(process_alive).is_empty(),
        "so its session is gone"
    );
}

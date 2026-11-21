//! The real `mortise` binary against a stand-in for the app's socket.
//!
//! These cover what only shows up end to end: that values reach the child's
//! environment, that the child *is* the process (exit codes and signals pass
//! straight through), and that every failure stops before anything runs.

use std::os::unix::net::UnixListener;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};

use mortise_cli::protocol::{ErrorCode, Request, Response, Var, WaitReason};
use mortise_proxy::framing::{read_frame, write_frame};

/// A fake app: answers each connection with the scripted frames for it and
/// records what was asked.
struct FakeApp {
    dir: tempfile::TempDir,
    requests: Arc<Mutex<Vec<Request>>>,
    /// The kernel's view of who connected, per request.
    peers: Arc<Mutex<Vec<i32>>>,
}

impl FakeApp {
    fn new(script: Vec<Vec<Response>>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let listener = UnixListener::bind(dir.path().join("cli.sock")).unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let peers = Arc::new(Mutex::new(Vec::new()));
        let seen = requests.clone();
        let seen_peers = peers.clone();
        std::thread::spawn(move || {
            for frames in script {
                let Ok((mut stream, _)) = listener.accept() else {
                    return;
                };
                if let Some(pid) = mortise_macos::peer_pid(std::os::fd::AsRawFd::as_raw_fd(&stream))
                {
                    seen_peers.lock().unwrap().push(pid);
                }
                let body = read_frame(&mut stream).unwrap().unwrap();
                seen.lock()
                    .unwrap()
                    .push(serde_json::from_slice(&body).unwrap());
                for frame in frames {
                    write_frame(&mut stream, &serde_json::to_vec(&frame).unwrap()).unwrap();
                }
            }
        });
        Self {
            dir,
            requests,
            peers,
        }
    }

    fn socket(&self) -> PathBuf {
        self.dir.path().join("cli.sock")
    }

    fn mortise(&self, args: &[&str]) -> Output {
        self.mortise_in(self.dir.path(), args, &[])
    }

    fn mortise_in(&self, cwd: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_mortise"))
            .args(args)
            .current_dir(cwd)
            .env("MORTISE_SOCKET", self.socket())
            .envs(env.iter().copied())
            .output()
            .unwrap()
    }

    fn requests(&self) -> Vec<Request> {
        self.requests.lock().unwrap().clone()
    }
}

fn env(vars: &[(&str, &str)]) -> Response {
    Response::Env {
        vars: vars
            .iter()
            .map(|(k, v)| Var {
                key: k.to_string(),
                value: v.to_string(),
            })
            .collect(),
    }
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[test]
fn secrets_reach_the_child_and_its_exit_code_comes_back() {
    let app = FakeApp::new(vec![vec![
        Response::Waiting {
            reason: WaitReason::Approval,
        },
        env(&[("DATABASE_URL", "postgres://x"), ("TOKEN", "t0k")]),
    ]]);
    let out = app.mortise(&[
        "run",
        "-p",
        "api",
        "-e",
        "dev",
        "--",
        "sh",
        "-c",
        "printf '%s|%s' \"$DATABASE_URL\" \"$TOKEN\"; exit 7",
    ]);

    assert_eq!(stdout(&out), "postgres://x|t0k");
    assert_eq!(out.status.code(), Some(7));
    assert!(
        stderr(&out).contains("approve access to api/dev"),
        "{}",
        stderr(&out)
    );

    let Request::Env {
        project,
        environment,
        keys,
        command,
    } = &app.requests()[0]
    else {
        panic!("expected an env request");
    };
    assert_eq!(
        (project.as_str(), environment.as_str(), keys),
        ("api", "dev", &None)
    );
    assert!(command.starts_with("sh -c"), "{command}");
}

/// `exec`, not a supervising parent: a signal that kills the command kills
/// the process the shell started, with nothing left behind to misreport it.
#[test]
fn the_command_replaces_mortise_so_signals_pass_straight_through() {
    let app = FakeApp::new(vec![vec![env(&[("A", "1")])]]);
    let out = app.mortise(&["run", "-p", "api", "-e", "dev", "sh", "-c", "kill -TERM $$"]);
    assert_eq!(out.status.signal(), Some(15), "SIGTERM");
}

#[test]
fn a_template_fetches_only_what_it_names_and_overrides_in_order() {
    let app = FakeApp::new(vec![
        vec![env(&[("DATABASE_URL", "from-vault")])],
        vec![env(&[("STRIPE_KEY", "sk_live")])],
    ]);
    std::fs::write(
        app.dir.path().join(".env.tpl"),
        "DB=mortise://api/dev/DATABASE_URL\nSTRIPE=mortise://payments/prod/STRIPE_KEY\nLOG_LEVEL=debug\n",
    )
    .unwrap();
    let out = app.mortise(&[
        "run",
        "-f",
        ".env.tpl",
        "--",
        "sh",
        "-c",
        "printf '%s|%s|%s' \"$DB\" \"$STRIPE\" \"$LOG_LEVEL\"",
    ]);

    assert_eq!(stdout(&out), "from-vault|sk_live|debug", "{}", stderr(&out));
    let asked: Vec<(String, Option<Vec<String>>)> = app
        .requests()
        .into_iter()
        .map(|r| match r {
            Request::Env { project, keys, .. } => (project, keys),
            other => panic!("expected an env request, got {other:?}"),
        })
        .collect();
    assert_eq!(
        asked,
        [
            ("api".to_string(), Some(vec!["DATABASE_URL".to_string()])),
            ("payments".to_string(), Some(vec!["STRIPE_KEY".to_string()])),
        ]
    );
}

#[test]
fn mortise_toml_supplies_the_project_and_no_override_keeps_the_shell_value() {
    let app = FakeApp::new(vec![vec![env(&[
        ("TOKEN", "vault"),
        ("OTHER", "vault-other"),
    ])]]);
    let repo = app.dir.path().join("repo");
    std::fs::create_dir_all(repo.join("sub")).unwrap();
    std::fs::write(
        repo.join(".mortise.toml"),
        "project = \"api\"\nenvironment = \"dev\"\n",
    )
    .unwrap();

    let out = app.mortise_in(
        &repo.join("sub"),
        &[
            "run",
            "--no-override",
            "--",
            "sh",
            "-c",
            "printf '%s|%s' \"$TOKEN\" \"$OTHER\"",
        ],
        &[("TOKEN", "from-shell")],
    );
    assert_eq!(stdout(&out), "from-shell|vault-other", "{}", stderr(&out));
}

#[test]
fn a_refusal_stops_before_the_command_runs() {
    let app = FakeApp::new(vec![vec![Response::error(
        ErrorCode::Denied,
        "Access was denied in Mortise.",
    )]]);
    let marker = app.dir.path().join("ran");
    let out = app.mortise(&[
        "run",
        "-p",
        "api",
        "-e",
        "dev",
        "--",
        "touch",
        marker.to_str().unwrap(),
    ]);

    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("denied"), "{}", stderr(&out));
    assert!(!marker.exists(), "the command ran despite the refusal");
}

#[test]
fn a_second_request_failing_means_nothing_runs() {
    let app = FakeApp::new(vec![
        vec![env(&[("A", "1")])],
        vec![Response::error(
            ErrorCode::MissingKeys,
            "payments/prod has no STRIPE_KEY.",
        )],
    ]);
    std::fs::write(
        app.dir.path().join("t"),
        "A=mortise://api/dev/A\nS=mortise://payments/prod/STRIPE_KEY\n",
    )
    .unwrap();
    let marker = app.dir.path().join("ran");
    let out = app.mortise(&["run", "-f", "t", "--", "touch", marker.to_str().unwrap()]);

    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("STRIPE_KEY"));
    assert!(!marker.exists());
}

#[test]
fn the_app_not_running_is_said_plainly() {
    let app = FakeApp::new(vec![]);
    let out = Command::new(env!("CARGO_BIN_EXE_mortise"))
        .args(["run", "-p", "api", "-e", "dev", "--", "true"])
        .current_dir(app.dir.path())
        .env("MORTISE_SOCKET", app.dir.path().join("nothing-here.sock"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("Mortise is not running"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn a_missing_command_exits_127_like_a_shell() {
    let app = FakeApp::new(vec![vec![env(&[("A", "1")])]]);
    let out = app.mortise(&[
        "run",
        "-p",
        "api",
        "-e",
        "dev",
        "--",
        "definitely-not-a-real-command-xyz",
    ]);
    assert_eq!(out.status.code(), Some(127));
}

#[test]
fn nothing_to_load_is_an_error_not_a_bare_run() {
    let app = FakeApp::new(vec![]);
    let out = app.mortise(&["run", "--", "true"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("nothing to load"), "{}", stderr(&out));
    assert!(app.requests().is_empty());
}

/// The session is bound to the pid that asked; `exec` must keep it, or the
/// agent would not be the process the user approved.
#[test]
fn an_agent_session_is_started_then_the_agent_runs_as_the_same_process() {
    let app = FakeApp::new(vec![vec![
        Response::Waiting {
            reason: WaitReason::Approval,
        },
        Response::SessionStarted { expires_at_ms: 1 },
    ]]);
    let out = app.mortise(&[
        "agent",
        "-p",
        "api",
        "-e",
        "dev",
        "--",
        "sh",
        "-c",
        "printf '%s|%s' \"$$\" \"${TOKEN-unset}\"",
    ]);

    let (pid, token) = stdout(&out)
        .split_once('|')
        .map(|(a, b)| (a.to_string(), b.to_string()))
        .unwrap();
    assert_eq!(
        pid.parse::<i32>().unwrap(),
        app.peers.lock().unwrap()[0],
        "agent is the approved process"
    );
    assert_eq!(
        token, "unset",
        "an agent session injects nothing into the agent"
    );
    assert!(
        stderr(&out).contains("session started for api/dev"),
        "{}",
        stderr(&out)
    );
    assert!(
        matches!(&app.requests()[0], Request::StartSession { project, environment, command }
        if project == "api" && environment == "dev" && command.starts_with("sh -c"))
    );
}

#[test]
fn a_refused_agent_session_does_not_start_the_agent() {
    let app = FakeApp::new(vec![vec![Response::error(
        ErrorCode::Denied,
        "Access was denied in Mortise.",
    )]]);
    let marker = app.dir.path().join("ran");
    let out = app.mortise(&[
        "agent",
        "-p",
        "api",
        "-e",
        "dev",
        "--",
        "touch",
        marker.to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(1));
    assert!(!marker.exists());
}

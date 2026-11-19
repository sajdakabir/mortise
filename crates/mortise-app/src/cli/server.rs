//! The command-line socket.
//!
//! One connection, one request: identify the caller from the kernel, make
//! sure the vault is unlocked, check the request names something real, then
//! serve it under an existing grant or after asking the user.
//!
//! The order matters. Validation comes before the prompt so nobody is asked
//! to approve a typo; the unlock comes before validation because project
//! names are unreadable until the first unlock; and the vault is re-checked
//! after approval because it may have locked while the prompt was up.

use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::mpsc::RecvTimeoutError;
use std::time::{Duration, Instant};

use mortise_cli::protocol::{ErrorCode, Request, Response, Var, WaitReason};
use mortise_proxy::framing::{read_frame, write_frame};
use mortise_vault::Vault;
use tauri::{AppHandle, Emitter, Manager};

use super::access::{Answer, CliAccess, RequestSummary, grant_root_on_disk};
use crate::dto::sanitize_display;
use crate::state::AppState;

/// How long a request waits for the user to unlock, and separately to
/// approve, before giving up.
pub const USER_WAIT: Duration = Duration::from_secs(120);

/// How often to look for an unlock while waiting for one.
const UNLOCK_POLL: Duration = Duration::from_millis(300);

/// Ancestors of the requesting process shown in the prompt.
const CHAIN_DEPTH: usize = 4;

/// Start listening. Returns once bound; serving continues in the background.
pub fn start(app: &AppHandle) -> io::Result<PathBuf> {
    crate::local_socket::listen(app, mortise_proxy::CLI_SOCKET, serve)
}

fn serve(app: &AppHandle, mut stream: UnixStream) -> io::Result<()> {
    let Some(frame) = read_frame(&mut stream)? else {
        return Ok(());
    };
    let response = match serde_json::from_slice::<Request>(&frame) {
        Ok(request) => handle(app, &mut stream, request),
        Err(_) => Response::error(ErrorCode::BadRequest, "Unrecognised request."),
    };
    send(&mut stream, &response)
}

fn send(stream: &mut UnixStream, response: &Response) -> io::Result<()> {
    let body = serde_json::to_vec(response).map_err(io::Error::other)?;
    write_frame(stream, &body)
}

fn handle(app: &AppHandle, stream: &mut UnixStream, request: Request) -> Response {
    let Request::Env {
        project,
        environment,
        keys,
        command,
    } = request;

    // Who is asking, according to the kernel. Refuse anything unidentified
    // rather than prompting about a process we cannot describe.
    let Some(pid) = mortise_macos::peer_pid(stream.as_raw_fd()) else {
        return unidentified();
    };
    let chain = mortise_macos::process_chain(pid, CHAIN_DEPTH);
    let Some(cwd) = chain.first().and_then(|p| p.cwd.clone()) else {
        return unidentified();
    };

    let state = app.state::<AppState>();
    if let Err(response) = wait_for_unlock(app, &state, stream) {
        return response;
    }

    let checked = state.with_vault(|vault| match vault {
        Some(v) => check(v, &project, &environment, keys.as_deref()),
        None => Err(Response::error(
            ErrorCode::NoVault,
            "There is no Mortise vault on this Mac yet.",
        )),
    });
    let (project, environment) = match checked {
        Ok(names) => names,
        Err(response) => return response,
    };

    let access = app.state::<CliAccess>();
    if !access.is_granted(&project, &environment, &cwd) {
        let summary = RequestSummary {
            id: match new_id() {
                Some(id) => id,
                None => {
                    return Response::error(ErrorCode::Internal, "Could not start the request.");
                }
            },
            project: project.clone(),
            environment: environment.clone(),
            keys: keys.clone(),
            command: sanitize_display(&command, 200),
            directory: grant_root_on_disk(&cwd).display().to_string(),
            process_chain: describe_chain(&chain),
        };
        if let Err(response) = ask(app, &access, stream, summary) {
            return response;
        }
    }

    state.with_vault(|vault| match vault {
        Some(v) if v.is_unlocked() => fetch(v, &project, &environment, keys.as_deref()),
        Some(_) => Response::error(
            ErrorCode::Locked,
            "Mortise locked before the request finished. Run it again.",
        ),
        None => Response::error(
            ErrorCode::NoVault,
            "There is no Mortise vault on this Mac yet.",
        ),
    })
}

fn unidentified() -> Response {
    Response::error(
        ErrorCode::Unidentified,
        "Mortise could not identify the process asking, so it refused.",
    )
}

/// Block until the vault is unlocked, asking the user once.
fn wait_for_unlock(
    app: &AppHandle,
    state: &AppState,
    stream: &mut UnixStream,
) -> Result<(), Response> {
    let unlocked = || state.with_vault(|v| v.map(|v| v.is_unlocked()));
    match unlocked() {
        None => {
            return Err(Response::error(
                ErrorCode::NoVault,
                "There is no Mortise vault on this Mac yet.",
            ));
        }
        Some(true) => return Ok(()),
        Some(false) => {}
    }

    send(
        stream,
        &Response::Waiting {
            reason: WaitReason::Unlock,
        },
    )
    .map_err(|_| Response::error(ErrorCode::Internal, "The command went away."))?;
    crate::show_main_window(app);

    let deadline = Instant::now() + USER_WAIT;
    while Instant::now() < deadline {
        std::thread::sleep(UNLOCK_POLL);
        if unlocked() == Some(true) {
            return Ok(());
        }
    }
    Err(Response::error(
        ErrorCode::Locked,
        "Mortise stayed locked. Unlock it and run the command again.",
    ))
}

/// Put the request in front of the user and wait for an answer.
fn ask(
    app: &AppHandle,
    access: &CliAccess,
    stream: &mut UnixStream,
    summary: RequestSummary,
) -> Result<(), Response> {
    let id = summary.id.clone();
    let Some(answer) = access.enqueue(summary) else {
        return Err(Response::error(
            ErrorCode::Busy,
            "Too many requests are already waiting for approval in Mortise.",
        ));
    };

    if send(
        stream,
        &Response::Waiting {
            reason: WaitReason::Approval,
        },
    )
    .is_err()
    {
        access.withdraw(&id);
        return Err(Response::error(
            ErrorCode::Internal,
            "The command went away.",
        ));
    }
    let _ = app.emit("cli-access-requested", ());
    crate::show_main_window(app);

    match answer.recv_timeout(USER_WAIT) {
        Ok(Answer::Once | Answer::ForEightHours) => Ok(()),
        Ok(Answer::Deny) => Err(Response::error(
            ErrorCode::Denied,
            "Access was denied in Mortise.",
        )),
        Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => {
            access.withdraw(&id);
            let _ = app.emit("cli-access-withdrawn", ());
            Err(Response::error(
                ErrorCode::Timeout,
                "Nobody approved the request in time.",
            ))
        }
    }
}

/// Resolve and validate a request against the vault's metadata.
///
/// Returns the canonical project and environment names. Works while locked
/// (after the first unlock), so it never needs a secret.
pub fn check(
    vault: &Vault,
    project: &str,
    environment: &str,
    keys: Option<&[String]>,
) -> Result<(String, String), Response> {
    let internal = |_| {
        Response::error(
            ErrorCode::Internal,
            "Mortise could not read its project list.",
        )
    };

    // Names are echoed back only after sanitising, and the list of projects
    // that *do* exist is never sent: an unapproved caller learns whether its
    // guess was right, not what to guess.
    let shown = |s: &str| sanitize_display(s, 60);
    let Some(found) = vault.project_named(project).map_err(internal)? else {
        return Err(Response::error(
            ErrorCode::UnknownProject,
            format!(
                "There is no project called “{}” in Mortise.",
                shown(project)
            ),
        ));
    };
    let Some(environment) = found
        .environments
        .iter()
        .find(|e| e.as_str() == environment.trim())
    else {
        return Err(Response::error(
            ErrorCode::UnknownEnvironment,
            format!(
                "Project “{}” has no environment called “{}”.",
                found.name,
                shown(environment)
            ),
        ));
    };

    if let Some(keys) = keys {
        let present: Vec<String> = vault
            .environment_items(&found.name, environment)
            .map_err(internal)?
            .into_iter()
            .map(|row| row.meta.title)
            .collect();
        let missing: Vec<String> = keys
            .iter()
            .filter(|k| !present.contains(k))
            .take(10)
            .map(|k| shown(k))
            .collect();
        if !missing.is_empty() {
            return Err(Response::error(
                ErrorCode::MissingKeys,
                format!(
                    "{}/{} has no {}.",
                    found.name,
                    environment,
                    missing.join(", ")
                ),
            ));
        }
    }
    Ok((found.name, environment.clone()))
}

/// The variables, after approval. Needs the vault unlocked.
pub fn fetch(vault: &Vault, project: &str, environment: &str, keys: Option<&[String]>) -> Response {
    match vault.environment_vars(project, environment) {
        Ok(vars) => Response::Env {
            vars: vars
                .into_iter()
                .filter(|v| keys.is_none_or(|keys| keys.contains(&v.key)))
                .map(|v| Var {
                    key: v.key,
                    value: v.value,
                })
                .collect(),
        },
        Err(_) => Response::error(
            ErrorCode::Internal,
            "Mortise could not read that environment.",
        ),
    }
}

fn describe_chain(chain: &[mortise_macos::ProcessInfo]) -> Vec<String> {
    chain
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let name = p.executable.as_deref().map(|path| {
                if i == 0 {
                    path.display().to_string()
                } else {
                    path.file_name().map_or_else(
                        || path.display().to_string(),
                        |n| n.to_string_lossy().into_owned(),
                    )
                }
            });
            sanitize_display(&name.unwrap_or_else(|| format!("pid {}", p.pid)), 200)
        })
        .collect()
}

fn new_id() -> Option<String> {
    let bytes = mortise_crypto::rand::bytes::<8>().ok()?;
    Some(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

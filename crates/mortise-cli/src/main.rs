//! `mortise` — see the library docs.

use std::ffi::OsString;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use mortise_cli::args::{self, Command, RunArgs, USAGE};
use mortise_cli::config;
use mortise_cli::plan::{Plan, Target};
use mortise_cli::protocol::{ErrorCode, Request, Response, WaitReason};
use mortise_cli::template;
use mortise_proxy::framing::{read_frame, write_frame};

/// Overrides the socket path. Lets the integration tests stand in for the
/// app; harmless otherwise, since anything that can set this variable can
/// already run code as you.
const SOCKET_ENV: &str = "MORTISE_SOCKET";

/// Longest the app may take to answer a single frame. The app gives up on an
/// unanswered approval at two minutes; this is that plus slack, so a hung app
/// cannot hang the terminal forever.
const READ_TIMEOUT: Duration = Duration::from_secs(150);

/// Longest command line shown in the approval prompt.
const COMMAND_PREVIEW: usize = 200;

fn main() -> ExitCode {
    match args::parse(std::env::args_os().skip(1)) {
        Ok(Command::Help) => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        Ok(Command::Version) => {
            println!("mortise {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        // Both only return on failure: success replaces this process.
        Ok(Command::Run(run_args)) => fail(run(run_args)),
        Ok(Command::Agent(agent_args)) => fail(agent(agent_args)),
        Err(message) => {
            eprintln!("mortise: {message}");
            ExitCode::from(2)
        }
    }
}

fn fail(failure: Failure) -> ExitCode {
    eprintln!("mortise: {}", failure.text);
    ExitCode::from(failure.exit)
}

/// Why `run` or `agent` returned instead of becoming the child.
struct Failure {
    text: String,
    exit: u8,
}

impl From<String> for Failure {
    fn from(text: String) -> Self {
        Self { text, exit: 1 }
    }
}

fn run(args: RunArgs) -> Failure {
    let plan = match build_plan(&args) {
        Ok(plan) => plan,
        Err(e) => return e.into(),
    };
    let socket = match socket_path() {
        Ok(socket) => socket,
        Err(e) => return e.into(),
    };

    let preview = command_preview(&args.command);
    let mut answers = Vec::new();
    for fetch in plan.fetches() {
        let request = Request::Env {
            project: fetch.target.project.clone(),
            environment: fetch.target.environment.clone(),
            keys: fetch.keys.as_ref().map(|k| k.iter().cloned().collect()),
            command: preview.clone(),
        };
        match ask_app(&socket, &request, &fetch.target) {
            Ok(Response::Env { vars }) => answers.push((fetch, vars)),
            Ok(_) => return unexpected().into(),
            Err(e) => return e.into(),
        }
    }
    let env = match plan.assemble(&answers) {
        Ok(env) => env,
        Err(e) => return e.into(),
    };

    let mut child = std::process::Command::new(&args.command[0]);
    child.args(&args.command[1..]);
    for (key, value) in &env {
        if args.no_override && std::env::var_os(key).is_some() {
            continue;
        }
        child.env(key, value.as_str());
    }
    drop(answers);
    become_child(child, &args.command[0])
}

/// Start an agent session for this process, then become the agent.
///
/// The app binds the session to *this* pid and start time. `exec` keeps
/// both, so the agent inherits the session and nothing else can claim it.
fn agent(args: RunArgs) -> Failure {
    let plan = match build_plan(&args) {
        Ok(plan) => plan,
        Err(e) => return e.into(),
    };
    let Some(target) = plan.whole else {
        return String::from("an agent session needs --project and --env (or a .mortise.toml)")
            .into();
    };
    let socket = match socket_path() {
        Ok(socket) => socket,
        Err(e) => return e.into(),
    };

    let request = Request::StartSession {
        project: target.project.clone(),
        environment: target.environment.clone(),
        command: command_preview(&args.command),
    };
    match ask_app(&socket, &request, &target) {
        Ok(Response::SessionStarted { .. }) => {
            eprintln!(
                "mortise: session started for {}/{}. Prefix commands with `mortise run --` to use it.",
                target.project, target.environment
            );
        }
        Ok(_) => return unexpected().into(),
        Err(e) => return e.into(),
    }

    let mut child = std::process::Command::new(&args.command[0]);
    child.args(&args.command[1..]);
    become_child(child, &args.command[0])
}

/// Replace this process with `child`.
///
/// Rather than supervising it: signals, exit status, the terminal and job
/// control all behave exactly as if the command had been run directly, with
/// nothing in between to get wrong. Only returns on failure.
fn become_child(mut child: std::process::Command, program: &std::ffi::OsStr) -> Failure {
    let err = child.exec();
    Failure {
        text: format!("could not run `{}`: {err}", program.to_string_lossy()),
        // The shell's conventions: 127 not found, 126 found but not runnable.
        exit: if err.kind() == std::io::ErrorKind::NotFound {
            127
        } else {
            126
        },
    }
}

fn socket_path() -> Result<PathBuf, String> {
    match std::env::var_os(SOCKET_ENV) {
        Some(path) => Ok(PathBuf::from(path)),
        None => mortise_proxy::app_socket_path(mortise_proxy::CLI_SOCKET)
            .ok_or_else(|| "cannot find the Mortise socket: HOME is not set".to_string()),
    }
}

fn unexpected() -> String {
    "Mortise answered with something this version does not expect. Update the mortise command."
        .into()
}

/// Flags, then `.mortise.toml` for whatever the flags left out.
fn build_plan(args: &RunArgs) -> Result<Plan, String> {
    let mut project = args.project.clone();
    let mut environment = args.environment.clone();

    if project.is_none() || environment.is_none() {
        let cwd = std::env::current_dir().map_err(|e| format!("no working directory: {e}"))?;
        if let Some((_, found)) = config::find(&cwd)? {
            project = project.or(found.project);
            environment = environment.or(found.environment);
        }
    }

    let whole = match (project, environment) {
        (Some(project), Some(environment)) => Some(Target {
            project,
            environment,
        }),
        (None, None) => None,
        (Some(_), None) => {
            return Err("--project needs --env too (or `environment` in .mortise.toml)".into());
        }
        (None, Some(_)) => {
            return Err("--env needs --project too (or `project` in .mortise.toml)".into());
        }
    };

    let mut templates = Vec::new();
    for path in &args.env_files {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("could not read {}: {e}", path.display()))?;
        templates.extend(template::parse(&text, &path.display().to_string())?);
    }

    let plan = Plan { whole, templates };
    if plan.is_empty() {
        return Err(format!(
            "nothing to load. Pass --project and --env, --env-file, or add a {} here.",
            config::FILE_NAME
        ));
    }
    Ok(plan)
}

/// Send one request and wait through any `Waiting` frames for the answer.
/// Errors come back as the message to show.
fn ask_app(
    socket: &std::path::Path,
    request: &Request,
    target: &Target,
) -> Result<Response, String> {
    let mut stream = UnixStream::connect(socket)
        .map_err(|_| "Mortise is not running. Open it and try again.".to_string())?;
    stream
        .set_read_timeout(Some(READ_TIMEOUT))
        .map_err(|e| e.to_string())?;

    let body = serde_json::to_vec(request).map_err(|e| e.to_string())?;
    write_frame(&mut stream, &body).map_err(|e| format!("could not reach Mortise: {e}"))?;

    let label = format!("{}/{}", target.project, target.environment);
    loop {
        let frame = match read_frame(&mut stream) {
            Ok(Some(frame)) => frame,
            Ok(None) => return Err("Mortise closed the connection without answering.".into()),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return Err("Mortise did not answer in time.".into());
            }
            Err(e) => return Err(format!("could not read Mortise's answer: {e}")),
        };
        let response: Response = serde_json::from_slice(&frame).map_err(|_| unexpected())?;
        match response {
            Response::Waiting {
                reason: WaitReason::Unlock,
            } => {
                eprintln!("mortise: Mortise is locked. Unlock it to continue…");
            }
            Response::Waiting {
                reason: WaitReason::Approval,
            } => {
                eprintln!("mortise: approve access to {label} in the Mortise window…");
            }
            Response::Error { code, message } => {
                return Err(match code {
                    ErrorCode::Other => format!("{label}: {message}"),
                    _ => message,
                });
            }
            answer => return Ok(answer),
        }
    }
}

/// The command as one readable line, for the prompt. Display only.
fn command_preview(command: &[OsString]) -> String {
    let joined = command
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join(" ");
    joined.chars().take(COMMAND_PREVIEW).collect()
}

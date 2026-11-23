//! `mortise` — see the library docs.

use std::ffi::OsString;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use mortise_cli::args::{self, Command, RunArgs, USAGE};
use mortise_cli::config;
use mortise_cli::plan::{Fetch, Plan, Target};
use mortise_cli::protocol::{ErrorCode, Request, Response, Var, WaitReason};
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
        Ok(Command::Run(run_args)) => {
            // Only returns on failure: success replaces this process.
            let message = run(run_args);
            eprintln!("mortise: {}", message.text);
            ExitCode::from(message.exit)
        }
        Err(message) => {
            eprintln!("mortise: {message}");
            ExitCode::from(2)
        }
    }
}

/// Why `run` returned instead of becoming the child.
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

    let socket = match std::env::var_os(SOCKET_ENV) {
        Some(path) => PathBuf::from(path),
        None => match mortise_proxy::app_socket_path(mortise_proxy::CLI_SOCKET) {
            Some(path) => path,
            None => return String::from("cannot find the Mortise socket: HOME is not set").into(),
        },
    };

    let preview = command_preview(&args.command);
    let mut answers = Vec::new();
    for fetch in plan.fetches() {
        match request(&socket, &fetch, &preview) {
            Ok(vars) => answers.push((fetch, vars)),
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

    // Replace this process rather than supervising a child: signals, exit
    // status, the terminal and job control all behave exactly as if the
    // command had been run directly, with nothing in between to get wrong.
    let err = child.exec();
    Failure {
        text: format!(
            "could not run `{}`: {err}",
            args.command[0].to_string_lossy()
        ),
        // The shell's conventions: 127 not found, 126 found but not runnable.
        exit: if err.kind() == std::io::ErrorKind::NotFound {
            127
        } else {
            126
        },
    }
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

/// Ask the app for one environment.
fn request(socket: &std::path::Path, fetch: &Fetch, command: &str) -> Result<Vec<Var>, String> {
    let mut stream = UnixStream::connect(socket)
        .map_err(|_| "Mortise is not running. Open it and try again.".to_string())?;
    stream
        .set_read_timeout(Some(READ_TIMEOUT))
        .map_err(|e| e.to_string())?;

    let req = Request::Env {
        project: fetch.target.project.clone(),
        environment: fetch.target.environment.clone(),
        keys: fetch.keys.as_ref().map(|k| k.iter().cloned().collect()),
        command: command.to_string(),
    };
    let body = serde_json::to_vec(&req).map_err(|e| e.to_string())?;
    write_frame(&mut stream, &body).map_err(|e| format!("could not reach Mortise: {e}"))?;

    let label = format!("{}/{}", fetch.target.project, fetch.target.environment);
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
        let response: Response = serde_json::from_slice(&frame)
            .map_err(|_| "Mortise sent an answer this version does not understand. Update the mortise command.".to_string())?;
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
            Response::Env { vars } => return Ok(vars),
            Response::Error { code, message } => {
                return Err(match code {
                    ErrorCode::Other => format!("{label}: {message}"),
                    _ => message,
                });
            }
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

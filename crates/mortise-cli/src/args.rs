//! Command-line arguments.
//!
//! Hand-written rather than a parser dependency: there is one subcommand and
//! four flags, and the one rule that matters — everything after the command
//! name belongs to the command, flags included — is easier to see here than
//! to configure.

use std::ffi::OsString;
use std::path::PathBuf;

/// Shown for `mortise help`.
pub const USAGE: &str = "\
Run a command with secrets from Mortise in its environment.

Usage:
  mortise run [options] [--] <command> [args...]

Options:
  -p, --project <name>    Project to load (default: .mortise.toml)
  -e, --env <name>        Environment to load (default: .mortise.toml)
  -f, --env-file <path>   Template whose mortise://project/env/KEY values are
                          filled from the vault; may be repeated
      --no-override       Keep variables already set in this shell instead of
                          replacing them with vault values
  -h, --help              Show this help
  -V, --version           Show the version

Mortise must be running. The first request from a directory asks you to
approve it in the app.";

/// What to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// `mortise run …`
    Run(RunArgs),
    /// `mortise help`
    Help,
    /// `mortise --version`
    Version,
}

/// Arguments to `mortise run`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunArgs {
    /// `--project`
    pub project: Option<String>,
    /// `--env`
    pub environment: Option<String>,
    /// `--env-file`, in order given.
    pub env_files: Vec<PathBuf>,
    /// `--no-override`
    pub no_override: bool,
    /// The program and its arguments, untouched.
    pub command: Vec<OsString>,
}

/// Parse everything after the program name.
pub fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Command, String> {
    let mut args = args.into_iter();
    let Some(sub) = args.next() else {
        return Ok(Command::Help);
    };
    match sub.to_str() {
        Some("run") => parse_run(args).map(Command::Run),
        Some("help" | "-h" | "--help") => Ok(Command::Help),
        Some("-V" | "--version") => Ok(Command::Version),
        _ => Err(format!(
            "unknown command `{}`. Try `mortise help`.",
            sub.to_string_lossy()
        )),
    }
}

fn parse_run(mut args: impl Iterator<Item = OsString>) -> Result<RunArgs, String> {
    let mut out = RunArgs::default();
    while let Some(arg) = args.next() {
        // A non-UTF-8 argument cannot be one of our flags, so it starts the
        // command.
        let Some(text) = arg.to_str() else {
            out.command.push(arg);
            break;
        };
        // `--flag=value` and `--flag value` both work.
        let (flag, inline) = match text.split_once('=') {
            Some((f, v)) if f.starts_with("--") => (f, Some(v.to_string())),
            _ => (text, None),
        };
        let mut value = |name: &str| -> Result<String, String> {
            inline
                .clone()
                .or_else(|| args.next().and_then(|v| v.into_string().ok()))
                .filter(|v| !v.is_empty())
                .ok_or_else(|| format!("{name} needs a value"))
        };
        match flag {
            "--" => break,
            "-p" | "--project" => out.project = Some(value("--project")?),
            "-e" | "--env" | "--environment" => out.environment = Some(value("--env")?),
            "-f" | "--env-file" => out.env_files.push(PathBuf::from(value("--env-file")?)),
            "--no-override" => out.no_override = true,
            "-h" | "--help" => return Err(USAGE.to_string()),
            _ if flag.starts_with('-') => {
                return Err(format!("unknown option `{flag}`. Try `mortise help`."));
            }
            _ => {
                out.command.push(arg);
                break;
            }
        }
    }
    out.command.extend(args);
    if out.command.is_empty() {
        return Err("no command to run. Usage: mortise run [options] -- <command>".into());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(args: &[&str]) -> Result<RunArgs, String> {
        let all = std::iter::once("run")
            .chain(args.iter().copied())
            .map(OsString::from);
        match parse(all)? {
            Command::Run(r) => Ok(r),
            other => panic!("expected run, got {other:?}"),
        }
    }

    #[test]
    fn flags_after_the_command_belong_to_the_command() {
        let r = run(&[
            "-p",
            "api",
            "--env=dev",
            "npm",
            "run",
            "dev",
            "--port",
            "3000",
        ])
        .unwrap();
        assert_eq!(r.project.as_deref(), Some("api"));
        assert_eq!(r.environment.as_deref(), Some("dev"));
        assert_eq!(
            r.command,
            ["npm", "run", "dev", "--port", "3000"].map(OsString::from)
        );
    }

    #[test]
    fn double_dash_ends_options_even_before_a_dash_command() {
        let r = run(&[
            "-f",
            "a.tpl",
            "-f",
            "b.tpl",
            "--no-override",
            "--",
            "--weird",
        ])
        .unwrap();
        assert_eq!(
            r.env_files,
            [PathBuf::from("a.tpl"), PathBuf::from("b.tpl")]
        );
        assert!(r.no_override);
        assert_eq!(r.command, [OsString::from("--weird")]);
    }

    #[test]
    fn mistakes_are_reported_not_guessed() {
        assert!(run(&["-p"]).unwrap_err().contains("needs a value"));
        assert!(
            run(&["--projct", "x", "cmd"])
                .unwrap_err()
                .contains("unknown option")
        );
        assert!(run(&["-p", "api"]).unwrap_err().contains("no command"));
        assert!(parse([OsString::from("rn")]).is_err());
    }
}

//! Native messaging bridge.
//!
//! The browser spawns this as a subprocess and owns its lifetime. It shuttles
//! length-prefixed frames between the browser's stdio and a Unix socket owned
//! by the Mortise app.
//!
//! # Why this exists at all
//!
//! The browser could not talk to the app directly: native messaging hosts are
//! spawned and killed by the browser, and a password manager must not have its
//! lifetime controlled by Chrome. KeePassXC solved this the same way and for
//! the same reason.
//!
//! This process is deliberately **dumb**. It does not parse message contents,
//! hold keys, or make authorization decisions — it moves bytes. Everything that
//! matters happens in the app, behind the socket.

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::all)]

pub mod framing;

use std::path::PathBuf;

/// Socket the browser proxy talks to.
pub const BROWSER_SOCKET: &str = "browser.sock";

/// Socket the `mortise` command-line tool talks to.
///
/// Separate from the browser's on purpose: the two have different callers,
/// different authorization (a paired key versus a per-request human
/// approval) and different message sets, and keeping them apart means a bug
/// in one protocol cannot be reached through the other.
pub const CLI_SOCKET: &str = "cli.sock";

/// Where the app listens for the browser.
pub fn socket_path() -> Option<PathBuf> {
    app_socket_path(BROWSER_SOCKET)
}

/// A socket named `name` in the app's data directory, which is already
/// private to the user.
pub fn app_socket_path(name: &str) -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    #[cfg(debug_assertions)]
    let app_id = option_env!("MORTISE_DEV_APP_ID").unwrap_or("com.mortise.desktop");
    #[cfg(not(debug_assertions))]
    let app_id = "com.mortise.desktop";
    Some(
        PathBuf::from(home)
            .join("Library/Application Support")
            .join(app_id)
            .join(name),
    )
}

/// A JSON error frame for the extension.
///
/// Used when the app cannot be reached. The extension shows this rather than
/// hanging, so the user learns their vault app is not running instead of
/// wondering why autofill stopped.
pub fn error_frame(code: &str, message: &str) -> Vec<u8> {
    format!(
        r#"{{"type":"error","code":"{}","message":"{}"}}"#,
        escape(code),
        escape(message)
    )
    .into_bytes()
}

fn escape(s: &str) -> String {
    s.chars()
        .flat_map(|c| match c {
            '"' => vec!['\\', '"'],
            '\\' => vec!['\\', '\\'],
            '\n' => vec!['\\', 'n'],
            '\r' => vec!['\\', 'r'],
            '\t' => vec!['\\', 't'],
            c if (c as u32) < 0x20 => vec![' '],
            c => vec![c],
        })
        .collect()
}

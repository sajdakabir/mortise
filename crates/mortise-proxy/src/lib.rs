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

/// Where the app listens.
///
/// Under the app's own data directory, which is already private to the user.
pub fn socket_path() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    Some(
        PathBuf::from(home)
            .join("Library/Application Support/com.mortise.desktop")
            .join("browser.sock"),
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

//! Binding the app's local Unix sockets.
//!
//! The browser and the command line each get their own socket, but the
//! mechanics of owning one are identical and security-relevant enough that
//! they should exist exactly once: clear a stale file, bind, restrict to the
//! owner, and serve each connection on its own thread.

use std::io;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

use tauri::{AppHandle, Manager};

/// Handles one connection to completion.
pub type Serve = fn(&AppHandle, UnixStream) -> io::Result<()>;

/// Bind `name` in the app data directory and serve it in the background.
///
/// Returns once the listener is bound. Connections are short-lived — one
/// request each — so there is no pool to manage and a wedged client cannot
/// outlive its request.
pub fn listen(app: &AppHandle, name: &str, serve: Serve) -> io::Result<PathBuf> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| io::Error::other(e.to_string()))?;
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(name);

    // A leftover socket from a crash would make bind fail with EADDRINUSE.
    // Removing it is safe: if another instance really is listening, the
    // single-instance guard should have stopped us before this point.
    let _ = std::fs::remove_file(&path);

    let listener = UnixListener::bind(&path)?;
    restrict_permissions(&path)?;

    let handle = app.clone();
    let label = name.to_string();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let handle = handle.clone();
            let label = label.clone();
            std::thread::spawn(move || {
                if let Err(e) = serve(&handle, stream) {
                    eprintln!("mortise: {label} connection ended: {e}");
                }
            });
        }
    });

    Ok(path)
}

/// Owner read/write only.
///
/// The socket sits in the app's data directory, which is already private, but
/// saying so explicitly costs nothing and does not depend on the directory's
/// permissions staying that way.
fn restrict_permissions(path: &Path) -> io::Result<()> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

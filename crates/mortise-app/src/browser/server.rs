//! The Unix socket the proxy connects to.
//!
//! One thread accepts connections; each connection is handled to completion on
//! its own thread. Connections are short-lived — the proxy opens one per
//! message — so there is no pool to manage and a wedged client cannot outlive
//! its request.

use std::io;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

use tauri::{AppHandle, Emitter, Manager};
use mortise_proxy::framing::{read_frame, write_frame};
use mortise_vault::{ItemPayload, Origin};

use super::associations;
use super::protocol::{LoginCandidate, Request, Response};
use crate::dto::{id_from_hex, id_to_hex};
use crate::state::AppState;

/// Socket filename inside the app data directory.
pub const SOCKET_NAME: &str = "browser.sock";

/// Start listening. Returns once the listener is bound; serving continues on
/// background threads.
pub fn start(app: &AppHandle) -> io::Result<PathBuf> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| io::Error::other(e.to_string()))?;
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(SOCKET_NAME);

    // A leftover socket from a crash would make bind fail with EADDRINUSE.
    // Removing it is safe: if another instance really is listening, the
    // single-instance guard should have stopped us before this point.
    let _ = std::fs::remove_file(&path);

    let listener = UnixListener::bind(&path)?;
    restrict_permissions(&path)?;

    let handle = app.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let handle = handle.clone();
            std::thread::spawn(move || {
                if let Err(e) = serve(&handle, stream) {
                    eprintln!("mortise: browser connection ended: {e}");
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

fn serve(app: &AppHandle, mut stream: UnixStream) -> io::Result<()> {
    let Some(frame) = read_frame(&mut stream)? else {
        return Ok(());
    };

    let response = match serde_json::from_slice::<Request>(&frame) {
        Ok(request) => handle(app, request),
        Err(_) => Response::error("bad_request", "Unrecognised message."),
    };

    let encoded = serde_json::to_vec(&response)
        .unwrap_or_else(|_| br#"{"type":"error","code":"internal","message":"?"}"#.to_vec());
    write_frame(&mut stream, &encoded)
}

fn handle(app: &AppHandle, request: Request) -> Response {
    match &request {
        Request::Status => {
            let state = app.state::<AppState>();
            Response::Status {
                associated: !associations::list().is_empty(),
                unlocked: state.with_vault(|v| v.map(|v| v.is_unlocked()).unwrap_or(false)),
            }
        }

        Request::Associate { client_name } => associate(app, client_name),

        // Everything below needs a valid proof from a paired browser.
        Request::Logins { origin, .. } => match associations::verify(&request) {
            Some(_) => logins(app, origin),
            None => Response::error("not_associated", "This browser is not paired."),
        },

        Request::Credential {
            item_id, origin, ..
        } => match associations::verify(&request) {
            Some(_) => credential(app, item_id, origin),
            None => Response::error("not_associated", "This browser is not paired."),
        },

        Request::Capture {
            origin,
            username,
            password,
            ..
        } => match associations::verify(&request) {
            Some(_) => capture(app, origin, username.as_deref(), password),
            None => Response::error("not_associated", "This browser is not paired."),
        },
    }
}

/// Pairing requires a human to approve in the app window.
///
/// A client cannot pair itself. The first call records who is asking and
/// returns `approval_required`; once someone clicks approve, the next call
/// collects the key. That round trip is deliberate — it is the only thing
/// standing between a rogue local process and the vault.
fn associate(app: &AppHandle, client_name: &str) -> Response {
    let state = app.state::<AppState>();

    if let Some(association) = state.take_approved_association() {
        return Response::Associated {
            id: association.id,
            key: association.key,
        };
    }

    let name = sanitize_client_name(client_name);
    state.set_pending_association(name.clone());
    let _ = app.emit("browser-association-requested", name);

    Response::error(
        "approval_required",
        "Approve this browser in the Mortise window.",
    )
}

fn logins(app: &AppHandle, origin: &str) -> Response {
    let Some(parsed) = Origin::parse(origin) else {
        return Response::error("bad_origin", "Unusable page origin.");
    };

    let state = app.state::<AppState>();
    state.with_vault(|vault| match vault {
        Some(v) => match v.find_for_origin(&parsed) {
            Ok(items) => Response::Logins {
                items: items
                    .into_iter()
                    .map(|i| LoginCandidate {
                        item_id: id_to_hex(i.id),
                        title: i.meta.title,
                        username: i.meta.username,
                    })
                    .collect(),
            },
            // Locked before the first unlock of this session: nothing to offer,
            // and not an error worth showing on every page load.
            Err(_) => Response::Logins { items: Vec::new() },
        },
        None => Response::Logins { items: Vec::new() },
    })
}

/// Offer a submitted login for saving.
///
/// Never saves on its own. The browser can propose; only a click in the app
/// window commits, for the same reason pairing works that way — the extension
/// is semi-trusted and writing to the vault unattended is exactly what a
/// compromised one would do.
fn capture(app: &AppHandle, origin: &str, username: Option<&str>, password: &str) -> Response {
    let Some(parsed) = Origin::parse(origin) else {
        return Response::error("bad_origin", "Unusable page origin.");
    };
    if password.is_empty() {
        return Response::error("bad_request", "Nothing to save.");
    }

    let state = app.state::<AppState>();

    state.with_vault(|vault| {
        let Some(v) = vault else {
            return Response::error("no_vault", "No vault on this machine.");
        };
        // Refusing while locked keeps a plaintext password from sitting in
        // memory waiting for an unlock that may never come. The user has just
        // typed it, so asking again later costs them nothing.
        if !v.is_unlocked() {
            return Response::error("locked", "Unlock Mortise to save this login.");
        }

        let existing = v.find_for_origin(&parsed).unwrap_or_default();

        // Matching on the password rather than only on the username.
        //
        // The username is the unreliable half: a multi-step sign-in puts it on
        // a different screen, so one offer carries it and another does not,
        // and keying on it alone saved x.com twice. Nobody has two logins for
        // one site with the same password, so an origin that already holds
        // this exact password has nothing new to learn.
        // Bound first: ItemPayload is ZeroizeOnDrop, so its fields cannot be
        // moved out of a temporary.
        let already_holds_it = existing.iter().any(|i| {
            let revealed = v.reveal(i.id);
            matches!(
                &revealed,
                Ok(mortise_vault::ItemPayload::Login { password: saved, .. })
                    if saved.as_str() == password
            )
        });
        if already_holds_it {
            return Response::Captured { queued: false };
        }

        state.set_pending_capture(crate::state::PendingCapture {
            origin: origin.to_string(),
            username: username.map(str::to_string),
            password: zeroize::Zeroizing::new(password.to_string()),
        });
        let _ = app.emit("login-capture-requested", origin.to_string());

        Response::Captured { queued: true }
    })
}

fn credential(app: &AppHandle, item_id: &str, origin: &str) -> Response {
    let Some(parsed) = Origin::parse(origin) else {
        return Response::error("bad_origin", "Unusable page origin.");
    };
    let Some(id) = id_from_hex(item_id) else {
        return Response::error("bad_request", "Malformed item id.");
    };

    let state = app.state::<AppState>();
    state.touch();

    state.with_vault(|vault| {
        let Some(v) = vault else {
            return Response::error("no_vault", "No vault on this machine.");
        };
        if !v.is_unlocked() {
            return Response::error("locked", "Unlock Mortise to fill this.");
        }

        // Re-check the origin against the item's own URLs rather than trusting
        // that this id came from a previous `logins` call. A client could ask
        // for any id it likes; without this it could name an item it was never
        // offered and get its password on an unrelated page.
        let permitted = v
            .find_for_origin(&parsed)
            .map(|items| items.iter().any(|i| i.id == id))
            .unwrap_or(false);
        if !permitted {
            return Response::error("not_permitted", "That item is not for this site.");
        }

        match v.reveal(id) {
            Ok(ItemPayload::Login { ref password, .. }) => {
                let username = v.item_meta(id).ok().and_then(|m| m.username);
                Response::Credential {
                    username,
                    password: password.clone(),
                }
            }
            Ok(_) => Response::error("not_fillable", "That item has no password to fill."),
            Err(_) => Response::error("not_found", "That item no longer exists."),
        }
    })
}

/// Clean up a client-supplied name before it is shown in a prompt.
///
/// The name comes from the extension, so it is untrusted. It ends up in a UI
/// label; stripping control characters and capping the length stops a hostile
/// value from spoofing surrounding interface text.
pub fn sanitize_client_name(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .filter(|c| !c.is_control())
        .take(40)
        .collect::<String>()
        .trim()
        .to_string();

    if cleaned.is_empty() {
        "A browser".to_string()
    } else {
        cleaned
    }
}

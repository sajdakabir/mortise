//! Mortise desktop app.
//!
//! All crypto and all storage stay in the Rust process. The webview is treated
//! as untrusted: it receives DTOs over a small explicit IPC surface and never
//! sees a key. See [`commands`] for that surface and the rules it holds to.

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::all)]

pub mod browser;
pub mod commands;
pub mod dto;
pub mod error;
pub mod keys;
pub mod rebrand;
pub mod state;

use tauri::Manager;

use crate::state::{AppState, TICK_INTERVAL};

/// Vault filename inside the app data directory.
const VAULT_FILE: &str = "mortise.vault";

/// Keychain service for everything this app stores.
///
/// Deliberately the same string as the bundle identifier, which is also
/// what `app_data_dir()` is derived from, so the app has exactly one name
/// on this machine rather than two that can drift apart.
pub const KEYCHAIN_SERVICE: &str = "com.mortise.desktop";

/// Build and run the app.
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let dir = app.path().app_data_dir()?;
            // Before the vault is opened: the rename moved it out from under
            // us, and opening first would create an empty one at the new path.
            // See [`rebrand`]. The keychain half runs off this thread, below.
            rebrand::migrate_vault(&dir, VAULT_FILE);
            let state = AppState::new(dir.join(VAULT_FILE));
            app.manage(state);

            // Auto-lock clock. A plain thread rather than an async task: it
            // wakes every ten seconds and does nothing, so there is no reason
            // to involve a runtime.
            let handle = app.handle().clone();
            std::thread::spawn(move || {
                loop {
                    std::thread::sleep(TICK_INTERVAL);
                    let state = handle.state::<AppState>();
                    if state.tick() {
                        // Tell the UI so it can drop any revealed secret it is
                        // still holding and show the lock screen.
                        use tauri::Emitter;
                        let _ = handle.emit("vault-locked", ());
                    }
                }
            });
            // Everything that touches the keychain, in order, on one thread.
            //
            // Off the startup path because a keychain read can block on a user
            // prompt, and blocking startup on that would hang the window
            // before it draws. The rename migration goes first so a carried-
            // over pairing is present before the cache is filled from it.
            std::thread::spawn(|| {
                rebrand::migrate_keychain();
                browser::associations::warm();
            });

            // The browser socket. A failure here is not fatal: the app is
            // perfectly usable without autofill, and refusing to start over it
            // would be a poor trade.
            match browser::server::start(app.handle()) {
                Ok(path) => eprintln!("mortise: browser socket at {}", path.display()),
                Err(e) => eprintln!("mortise: browser autofill unavailable: {e}"),
            }

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::status,
            commands::create_vault,
            commands::unlock,
            commands::lock,
            commands::sign_out,
            commands::unlock_biometric,
            commands::set_biometric,
            commands::forget_account_key,
            commands::search,
            commands::reveal,
            commands::save_item,
            commands::import_csv,
            commands::projects,
            commands::create_project,
            commands::add_environment,
            commands::delete_project,
            commands::import_env,
            commands::import_env_file,
            commands::copy_env,
            commands::delete_item,
            commands::generate_password,
            commands::password_entropy,
            commands::copy_secret,
            commands::approve_browser,
            commands::reject_browser,
            commands::pending_browser,
            commands::pending_capture,
            commands::save_capture,
            commands::discard_capture,
            commands::list_browsers,
            commands::unpair_browser,
            commands::native_host_status,
            commands::install_native_host,
            commands::uninstall_native_host,
            commands::sync_status,
            commands::set_relay,
            commands::sync_now,
            commands::claim_vault_on_relay,
            commands::create_project_invite,
            commands::inspect_project_invite,
            commands::request_project_access,
            commands::touch,
        ])
        .run(tauri::generate_context!())
        .expect("failed to start Mortise");
}

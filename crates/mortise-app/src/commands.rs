//! The IPC surface.
//!
//! This is the complete list of things the webview can ask the backend to do.
//! Keeping it small and explicit is the point: the webview runs content that a
//! compromised page or extension could influence, so every command here is
//! written as though the caller is untrusted.
//!
//! Two rules hold throughout:
//!
//! 1. **No key material crosses this boundary.** Not the MUK, not vault keys,
//!    not the account key after creation.
//! 2. **Secrets cross one item at a time, on request.** [`reveal`] is the only
//!    command that returns a payload, and it takes exactly one id. There is no
//!    bulk variant, so no UI mistake can materialize every password at once.

use std::time::Duration;

use mortise_crypto::generate::{PasswordSpec, password};
use mortise_crypto::kdf::Argon2Params;
use mortise_crypto::recovery;
use mortise_vault::{ItemPayload, Vault};
use tauri::{Manager, State};
use zeroize::Zeroizing;

use crate::dto::{ItemRow, MetaInput, NewVault, VaultStatus, id_from_hex};
use crate::error::{CmdError, CmdResult};
use crate::keys;
use crate::state::AppState;

/// How long a copied secret stays on the clipboard.
const CLIPBOARD_CLEAR_AFTER: Duration = Duration::from_secs(30);

/// Which screen the UI should show.
#[tauri::command]
pub fn status(state: State<'_, AppState>) -> VaultStatus {
    let exists = state.vault_exists();
    let account_key_remembered = keys::account_key_remembered();
    let biometric_enabled = keys::biometric_enabled();

    state.with_vault(|vault| match vault {
        Some(v) => VaultStatus {
            exists: true,
            unlocked: v.is_unlocked(),
            // Search availability is distinct from unlocked: it survives lock
            // but not a cold start. The UI needs to tell those apart.
            searchable: v.search("").is_ok(),
            item_count: v.item_count().unwrap_or(0),
            account_key_remembered,
            biometric_enabled,
        },
        None => VaultStatus {
            exists,
            unlocked: false,
            searchable: false,
            item_count: 0,
            account_key_remembered,
            biometric_enabled,
        },
    })
}

/// Create the vault. Returns the recovery kit, once.
///
/// The kit is the only copy of the account key that will ever exist outside
/// this vault (spec §7). If the user loses it along with their password, the
/// data is unrecoverable by design.
#[tauri::command]
pub fn create_vault(state: State<'_, AppState>, master_password: String) -> CmdResult<NewVault> {
    if state.vault_exists() {
        return Err(CmdError::bad_request("A vault already exists."));
    }
    if master_password.chars().count() < 8 {
        return Err(CmdError::bad_request(
            "Use at least 8 characters for your master password.",
        ));
    }
    if let Some(dir) = state.vault_path().parent() {
        std::fs::create_dir_all(dir).map_err(|e| {
            eprintln!("mortise: cannot create vault directory: {e}");
            CmdError::bad_request("Could not create the vault directory.")
        })?;
    }

    let (vault, account_key) = Vault::create(
        state.vault_path(),
        master_password.as_bytes(),
        Argon2Params::default(),
    )?;
    let kit = recovery::encode(&account_key);

    // Remember the account key immediately, so the very first unlock already
    // asks for the password alone. A failure here is not fatal — the user
    // still has the recovery key on screen — so it is logged, not surfaced.
    if let Err(e) = keys::remember_account_key(&account_key) {
        eprintln!("mortise: could not remember the account key: {e}");
    }

    state.install(vault);
    state.touch();

    // The one place the account key leaves Rust, and the reason the vault
    // exists: the user has to be able to write it down. Everything upstream
    // keeps it in Zeroizing; this copy is deliberate and documented in dto.rs.
    Ok(NewVault {
        recovery_kit: kit.to_string(),
    })
}

/// Unlock with the master password.
///
/// `recovery_kit` is only needed when the account key is not in this Mac's
/// keychain — a fresh install, or after the user chose to forget it. When one
/// is supplied it is remembered, so this is the last time they have to type it.
#[tauri::command]
pub fn unlock(
    state: State<'_, AppState>,
    master_password: String,
    recovery_kit: Option<String>,
) -> CmdResult<VaultStatus> {
    let account_key = match recovery_kit
        .as_deref()
        .map(str::trim)
        .filter(|k| !k.is_empty())
    {
        Some(kit) => {
            let key = recovery::decode(kit)
                .map_err(|_| CmdError::bad_request("That recovery key is not valid."))?;
            if let Err(e) = keys::remember_account_key(&key) {
                eprintln!("mortise: could not remember the account key: {e}");
            }
            key
        }
        None => keys::recall_account_key()
            .map_err(CmdError::from)?
            .ok_or_else(|| {
                CmdError::bad_request("Enter your recovery key — it is not saved on this Mac.")
            })?,
    };

    state.with_vault(|vault| {
        let v = vault.ok_or_else(|| state.no_vault_error())?;
        v.unlock(master_password.as_bytes(), &account_key)?;
        Ok::<(), CmdError>(())
    })?;
    state.touch();
    Ok(status(state))
}

/// Lock, keeping search available.
#[tauri::command]
pub fn lock(state: State<'_, AppState>) -> VaultStatus {
    state.with_vault(|vault| {
        if let Some(v) = vault {
            v.lock();
        }
    });
    status(state)
}

/// Sign out: lock, close search, and forget everything in the keychain.
///
/// Deliberately heavier than [`lock`]. Someone signing out on a shared or
/// handed-on Mac expects nothing of theirs to remain, and leaving the account
/// key behind would quietly defeat that.
#[tauri::command]
pub fn sign_out(state: State<'_, AppState>) -> VaultStatus {
    state.with_vault(|vault| {
        if let Some(v) = vault {
            v.lock_fully();
        }
    });
    keys::forget_everything();
    crate::browser::associations::clear();
    status(state)
}

/// Unlock using Touch ID or the device passcode.
///
/// Async, and the keychain read runs on a blocking thread: the prompt is modal
/// and would deadlock the UI thread if it ran there.
#[tauri::command]
pub async fn unlock_biometric(app: tauri::AppHandle) -> CmdResult<VaultStatus> {
    let token = tauri::async_runtime::spawn_blocking(keys::biometric_token)
        .await
        .map_err(|_| CmdError::bad_request("Authentication was interrupted."))?
        .map_err(CmdError::from)?
        .ok_or_else(|| CmdError::bad_request("Touch ID unlock is not set up on this Mac."))?;

    let state = app.state::<AppState>();
    state.with_vault(|vault| {
        let v = vault.ok_or_else(|| state.no_vault_error())?;
        v.unlock_with_token(&token)?;
        Ok::<(), CmdError>(())
    })?;
    state.touch();
    Ok(status(state))
}

/// Turn biometric unlock on or off.
///
/// Enabling requires the vault to be unlocked: the token is minted from live
/// key material, so there is no way to set this up without having entered the
/// master password first.
#[tauri::command]
pub fn set_biometric(state: State<'_, AppState>, enabled: bool) -> CmdResult<VaultStatus> {
    if enabled {
        let token = state.with_vault(|vault| {
            let v = vault.ok_or_else(|| state.no_vault_error())?;
            Ok::<_, CmdError>(v.unlock_token()?)
        })?;
        keys::enable_biometric(&token).map_err(CmdError::from)?;
    } else {
        keys::disable_biometric().map_err(CmdError::from)?;
    }
    Ok(status(state))
}

/// Forget the saved account key, so the recovery key is needed again.
#[tauri::command]
pub fn forget_account_key(state: State<'_, AppState>) -> CmdResult<VaultStatus> {
    keys::forget_account_key().map_err(CmdError::from)?;
    Ok(status(state))
}

/// Search items. Works while locked.
#[tauri::command]
pub fn search(state: State<'_, AppState>, query: String) -> CmdResult<Vec<ItemRow>> {
    state.touch();
    state.with_vault(|vault| {
        let v = vault.ok_or_else(|| state.no_vault_error())?;
        Ok(v.search(&query)?.into_iter().map(ItemRow::from).collect())
    })
}

/// Decrypt one item's secrets.
///
/// The only route to a plaintext secret. One id, no bulk form.
#[tauri::command]
pub fn reveal(state: State<'_, AppState>, id: String) -> CmdResult<ItemPayload> {
    state.touch();
    let item_id = id_from_hex(&id).ok_or_else(|| CmdError::bad_request("Malformed item id."))?;
    state.with_vault(|vault| {
        let v = vault.ok_or_else(|| state.no_vault_error())?;
        Ok(v.reveal(item_id)?)
    })
}

/// Create or replace an item. Returns its id.
#[tauri::command]
pub fn save_item(
    state: State<'_, AppState>,
    id: Option<String>,
    meta: MetaInput,
    payload: ItemPayload,
) -> CmdResult<String> {
    state.touch();
    if meta.title.trim().is_empty() {
        return Err(CmdError::bad_request("Give the item a name."));
    }
    let meta = meta.into();

    state.with_vault(|vault| {
        let v = vault.ok_or_else(|| state.no_vault_error())?;
        let item_id = match id {
            Some(hex) => {
                let item_id =
                    id_from_hex(&hex).ok_or_else(|| CmdError::bad_request("Malformed item id."))?;
                v.update_item(item_id, &meta, &payload)?;
                item_id
            }
            None => v.create_item(&meta, &payload)?,
        };
        Ok(crate::dto::id_to_hex(item_id))
    })
}

/// One project and what is in it.
#[derive(serde::Serialize)]
pub struct ProjectSummary {
    /// Identifier, hex.
    pub id: String,
    /// Display name.
    pub name: String,
    /// Optional description.
    pub description: String,
    /// Environments, in the order they were added.
    pub environments: Vec<String>,
    /// Secrets across every environment.
    pub secret_count: u32,
}

/// Every project, with a count of what is in it.
#[tauri::command]
pub fn projects(state: State<'_, AppState>) -> CmdResult<Vec<ProjectSummary>> {
    state.touch();
    state.with_vault(|vault| {
        let v = vault.ok_or_else(|| state.no_vault_error())?;

        // Counted from the items rather than stored on the project, so the
        // number cannot drift away from what is actually there.
        let mut counts: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
        for row in v.search("")? {
            if let Some(p) = row.meta.project.clone() {
                *counts.entry(p).or_default() += 1;
            }
        }

        Ok(v.projects()?
            .into_iter()
            .map(|p| ProjectSummary {
                secret_count: counts.get(&p.name).copied().unwrap_or(0),
                id: p.id,
                name: p.name,
                description: p.description,
                environments: p.environments,
            })
            .collect())
    })
}

/// Create a project, with the default environments in it.
#[tauri::command]
pub fn create_project(
    state: State<'_, AppState>,
    name: String,
    description: String,
) -> CmdResult<ProjectSummary> {
    state.touch();
    state.with_vault(|vault| {
        let v = vault.ok_or_else(|| state.no_vault_error())?;
        let p = v.create_project(&name, &description)?;
        Ok(ProjectSummary {
            id: p.id,
            name: p.name,
            description: p.description,
            environments: p.environments,
            secret_count: 0,
        })
    })
}

/// Add an environment to a project.
#[tauri::command]
pub fn add_environment(
    state: State<'_, AppState>,
    project_id: String,
    environment: String,
) -> CmdResult<ProjectSummary> {
    state.touch();
    state.with_vault(|vault| {
        let v = vault.ok_or_else(|| state.no_vault_error())?;
        let p = v.add_environment(&project_id, &environment)?;
        let secret_count = v
            .search("")?
            .into_iter()
            .filter(|row| row.meta.project.as_deref() == Some(p.name.as_str()))
            .count() as u32;
        Ok(ProjectSummary {
            id: p.id,
            name: p.name,
            description: p.description,
            environments: p.environments,
            secret_count,
        })
    })
}

/// Delete an empty project.
#[tauri::command]
pub fn delete_project(state: State<'_, AppState>, project_id: String) -> CmdResult<()> {
    state.touch();
    state.with_vault(|vault| {
        let v = vault.ok_or_else(|| state.no_vault_error())?;
        v.delete_project(&project_id)?;
        Ok(())
    })
}

/// What a pasted `.env` did.
#[derive(serde::Serialize)]
pub struct EnvImportReport {
    /// Variables written as new items.
    pub added: u32,
    /// Variables that replaced an existing value in this environment.
    pub updated: u32,
    /// Variables whose value was already exactly what is stored.
    pub unchanged: u32,
    /// Lines that were blank or a comment.
    pub skipped: u32,
    /// Lines that were not a `KEY=value` and were left alone.
    pub unreadable: u32,
    /// Keys defined more than once in the pasted text; the last won.
    pub duplicates: Vec<String>,
}

/// Write a pasted `.env` into a project's environment.
///
/// Updates in place rather than appending. Pasting a file twice is how people
/// check they pasted it, and a vault that doubled every variable each time
/// would be unusable within a day.
#[tauri::command]
pub fn import_env(
    state: State<'_, AppState>,
    project: String,
    environment: String,
    text: String,
) -> CmdResult<EnvImportReport> {
    use mortise_vault::envfile;

    state.touch();
    let project = project.trim().to_string();
    let environment = environment.trim().to_string();
    if project.is_empty() || environment.is_empty() {
        return Err(CmdError::bad_request(
            "A project and an environment are both needed.",
        ));
    }

    let (vars, parsed) = envfile::parse(&text);
    if vars.is_empty() {
        return Err(CmdError::bad_request(
            "Nothing in that looked like KEY=value.",
        ));
    }

    state.with_vault(|vault| {
        let v = vault.ok_or_else(|| state.no_vault_error())?;

        // Existing secrets in this exact environment, by name.
        let mut here: std::collections::HashMap<String, mortise_crypto::item::ItemId> =
            std::collections::HashMap::new();
        for row in v.search("")? {
            if row.kind == mortise_vault::ItemKind::EnvSecret
                && row.meta.project.as_deref() == Some(project.as_str())
                && row.meta.environment.as_deref() == Some(environment.as_str())
            {
                here.insert(row.meta.title.clone(), row.id);
            }
        }

        let mut report = EnvImportReport {
            added: 0,
            updated: 0,
            unchanged: 0,
            skipped: parsed.skipped as u32,
            unreadable: parsed.unreadable as u32,
            duplicates: parsed.duplicates,
        };

        for var in vars {
            let meta = mortise_vault::ItemMeta {
                title: var.key.clone(),
                urls: Vec::new(),
                username: None,
                folder: Some(format!("{project}/{environment}")),
                project: Some(project.clone()),
                environment: Some(environment.clone()),
                tags: Vec::new(),
            };
            let payload = mortise_vault::ItemPayload::EnvSecret {
                value: var.value.clone(),
            };

            match here.get(&var.key) {
                Some(&id) => {
                    // Comparing before writing keeps the change log, and so
                    // the sync traffic, to what actually changed.
                    let same = matches!(
                        v.reveal(id)?,
                        mortise_vault::ItemPayload::EnvSecret { ref value } if *value == var.value
                    );
                    if same {
                        report.unchanged += 1;
                    } else {
                        v.update_item(id, &meta, &payload)?;
                        report.updated += 1;
                    }
                }
                None => {
                    v.create_item(&meta, &payload)?;
                    report.added += 1;
                }
            }
        }

        Ok(report)
    })
}

/// Write a `.env` file from disk into a project's environment.
///
/// Takes a path rather than the file's contents, for the same reason
/// `import_csv` does: the webview is semi-trusted and the file is plaintext
/// secrets. Rust opens it, and the webview only ever sees counts.
#[tauri::command]
pub fn import_env_file(
    state: State<'_, AppState>,
    project: String,
    environment: String,
    path: String,
) -> CmdResult<EnvImportReport> {
    let text = std::fs::read_to_string(readable_plain_file(&path)?)
        .map_err(|_| CmdError::bad_request("That file could not be opened."))?;
    import_env(state, project, environment, text)
}

/// Copy a project's environment to the clipboard as `.env` text.
///
/// The text never crosses the IPC boundary. An earlier version returned it to
/// the webview, which made it the bulk variant the surface rules at the top of
/// this file say does not exist: two calls enumerated every project and
/// environment, and one call per environment dumped every secret in it, with
/// no id and no per-item action. The webview then wrote it to the clipboard
/// itself, so unlike every other copy here nothing ever cleared it.
///
/// Rust reads, formats, writes and schedules the same verified clear as
/// [`copy_secret`], and the webview learns only how many variables went and
/// how long it has.
#[tauri::command]
pub fn copy_env(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    project: String,
    environment: String,
) -> CmdResult<EnvCopyReport> {
    use mortise_vault::envfile;
    use tauri_plugin_clipboard_manager::ClipboardExt;

    state.touch();
    let text = state.with_vault(|vault| -> CmdResult<Zeroizing<String>> {
        let v = vault.ok_or_else(|| state.no_vault_error())?;

        let mut rows: Vec<_> = v
            .search("")?
            .into_iter()
            .filter(|row| {
                row.kind == mortise_vault::ItemKind::EnvSecret
                    && row.meta.project.as_deref() == Some(project.as_str())
                    && row.meta.environment.as_deref() == Some(environment.as_str())
            })
            .collect();
        // Alphabetical, so the file diffs against the last export rather than
        // against the order things happened to be created in.
        rows.sort_by(|a, b| a.meta.title.cmp(&b.meta.title));

        let mut vars = Vec::new();
        for row in rows {
            // Bound then matched by reference: ItemPayload is ZeroizeOnDrop,
            // so a field cannot be moved out of a temporary.
            let payload = v.reveal(row.id)?;
            if let mortise_vault::ItemPayload::EnvSecret { value } = &payload {
                vars.push(envfile::EnvVar {
                    key: row.meta.title,
                    value: value.clone(),
                });
            }
        }
        if vars.is_empty() {
            return Err(CmdError::bad_request("No secrets in that environment."));
        }
        Ok(Zeroizing::new(envfile::format(&vars)))
    })?;

    let count = text.lines().filter(|l| !l.trim().is_empty()).count() as u32;

    app.clipboard().write_text(text.as_str()).map_err(|e| {
        eprintln!("mortise: clipboard write failed: {e}");
        CmdError::bad_request("Could not write to the clipboard.")
    })?;

    let expected = Zeroizing::new(text.as_str().to_owned());
    let handle = app.clone();
    std::thread::spawn(move || {
        std::thread::sleep(CLIPBOARD_CLEAR_AFTER);
        if handle
            .clipboard()
            .read_text()
            .map(Zeroizing::new)
            .is_ok_and(|current| *current == *expected)
        {
            let _ = handle.clipboard().write_text(String::new());
        }
    });

    Ok(EnvCopyReport {
        copied: count,
        clears_in_secs: CLIPBOARD_CLEAR_AFTER.as_secs(),
    })
}

/// What a bulk copy did. Counts only — never the text.
#[derive(serde::Serialize)]
pub struct EnvCopyReport {
    /// Variables placed on the clipboard.
    pub copied: u32,
    /// Seconds until the clipboard is cleared.
    pub clears_in_secs: u64,
}

/// Import a CSV export from another password manager.
///
/// Takes a path rather than the file's contents on purpose. The webview is
/// semi-trusted (threat model §2) and the file is plaintext credentials; if
/// the UI read it and passed it over IPC, every password in the export would
/// pass through the JS heap for no benefit. Rust opens it, parses it, and the
/// webview only ever sees counts.
#[tauri::command]
pub fn import_csv(state: State<'_, AppState>, path: String) -> CmdResult<crate::dto::ImportReport> {
    use mortise_vault::import;

    state.touch();

    let file = std::fs::File::open(readable_plain_file(&path)?)
        .map_err(|_| CmdError::bad_request("That file could not be opened."))?;
    let (items, report) = import::parse(std::io::BufReader::new(file))?;

    state.with_vault(|vault| {
        let v = vault.ok_or_else(|| state.no_vault_error())?;

        // Matching on name plus username, which is what a person means by
        // "the same login". Importing the same export twice is a normal
        // mistake and should be a no-op rather than a doubled vault.
        let existing: std::collections::HashSet<(String, Option<String>)> = v
            .search("")?
            .into_iter()
            .map(|row| (row.meta.title, row.meta.username))
            .collect();

        let mut imported = 0u32;
        let mut duplicates = 0u32;
        let mut failed = 0u32;
        let mut seen = existing;

        for (meta, payload) in &items {
            let key = (meta.title.clone(), meta.username.clone());
            if seen.contains(&key) {
                duplicates += 1;
                continue;
            }
            match v.create_item(meta, payload) {
                Ok(_) => {
                    seen.insert(key);
                    imported += 1;
                }
                // Never log the error: it would carry the row with it.
                Err(_) => failed += 1,
            }
        }

        Ok(crate::dto::ImportReport {
            source: report.source.label().to_string(),
            imported,
            duplicates,
            empty: report.empty as u32,
            unsupported: report.unsupported as u32,
            failed,
        })
    })
}

/// Delete an item.
#[tauri::command]
pub fn delete_item(state: State<'_, AppState>, id: String) -> CmdResult<()> {
    state.touch();
    let item_id = id_from_hex(&id).ok_or_else(|| CmdError::bad_request("Malformed item id."))?;
    state.with_vault(|vault| {
        let v = vault.ok_or_else(|| state.no_vault_error())?;
        v.delete_item(item_id)?;
        Ok::<(), CmdError>(())
    })
}

/// Generate a password.
#[tauri::command]
pub fn generate_password(
    length: usize,
    lower: bool,
    upper: bool,
    digits: bool,
    symbols: bool,
) -> CmdResult<String> {
    let spec = PasswordSpec {
        length: length.clamp(8, 128),
        lower,
        upper,
        digits,
        symbols,
    };
    let generated = password(spec)
        .map_err(|_| CmdError::bad_request("Pick at least one kind of character to include."))?;
    Ok(generated.to_string())
}

/// Bits of entropy a generator setting would produce.
///
/// Honest only because selection is uniform — see `mortise_crypto::generate`.
#[tauri::command]
pub fn password_entropy(
    length: usize,
    lower: bool,
    upper: bool,
    digits: bool,
    symbols: bool,
) -> f64 {
    PasswordSpec {
        length: length.clamp(1, 128),
        lower,
        upper,
        digits,
        symbols,
    }
    .entropy_bits()
}

/// Copy one field of an item to the clipboard, then clear it after a delay.
///
/// Deliberately does the reveal, the copy, and the scheduled clear all in the
/// backend. The alternative — hand the secret to the webview and let it call a
/// clipboard API — would put a plaintext password into the webview's heap for
/// no reason. This way the copy path never crosses the IPC boundary at all.
///
/// Returns how many seconds until the clipboard is cleared.
#[tauri::command]
pub fn copy_secret(
    app: tauri::AppHandle,
    state: State<'_, AppState>,
    id: String,
    field: String,
) -> CmdResult<u64> {
    use tauri_plugin_clipboard_manager::ClipboardExt;

    state.touch();
    let item_id = id_from_hex(&id).ok_or_else(|| CmdError::bad_request("Malformed item id."))?;

    let value = state.with_vault(|vault| -> CmdResult<Zeroizing<String>> {
        let v = vault.ok_or_else(|| state.no_vault_error())?;
        let payload = v.reveal(item_id)?;
        field_of(&payload, &field).ok_or_else(|| CmdError::bad_request("No such field."))
    })?;

    app.clipboard().write_text(value.as_str()).map_err(|e| {
        eprintln!("mortise: clipboard write failed: {e}");
        CmdError::bad_request("Could not write to the clipboard.")
    })?;

    // Clear only if the clipboard still holds what we put there. Overwriting
    // whatever the user copied in the meantime would be its own small disaster.
    // Zeroizing, not a bare String: `value` derefs to String, so `to_string`
    // would allocate an unprotected copy of the password that lives for the
    // whole clear window and is freed without being wiped.
    let expected = Zeroizing::new(value.as_str().to_owned());
    let handle = app.clone();
    std::thread::spawn(move || {
        std::thread::sleep(CLIPBOARD_CLEAR_AFTER);
        if handle
            .clipboard()
            .read_text()
            // The clipboard read is itself the secret; wipe it too.
            .map(Zeroizing::new)
            .is_ok_and(|current| *current == *expected)
        {
            let _ = handle.clipboard().write_text(String::new());
        }
    });

    Ok(CLIPBOARD_CLEAR_AFTER.as_secs())
}

fn field_of(payload: &ItemPayload, field: &str) -> Option<Zeroizing<String>> {
    let value = match (payload, field) {
        (ItemPayload::Login { password, .. }, "password") => password.clone(),
        (ItemPayload::Login { totp_seed, .. }, "totp_seed") => totp_seed.clone()?,
        (ItemPayload::Login { notes, .. }, "notes") => notes.clone()?,
        (ItemPayload::SecureNote { body }, "body") => body.clone(),
        (ItemPayload::ApiKey { key, .. }, "key") => key.clone(),
        (ItemPayload::EnvSecret { value }, "value") => value.clone(),
        (ItemPayload::Card { number, .. }, "number") => number.clone(),
        (ItemPayload::Card { cvv, .. }, "cvv") => cvv.clone(),
        _ => return None,
    };
    Some(Zeroizing::new(value))
}

/// Approve the browser currently asking to pair.
///
/// Only ever called from a click in the app's own window. The extension cannot
/// trigger it, which is the whole point: pairing needs a human in a window a
/// hostile local process cannot draw.
#[tauri::command]
pub fn approve_browser(state: State<'_, AppState>) -> CmdResult<String> {
    let name = state
        .pending_association()
        .ok_or_else(|| CmdError::bad_request("No browser is waiting to be paired."))?;

    let association = crate::browser::associations::create(&name).map_err(CmdError::from)?;
    let id = association.id.clone();
    state.set_approved_association(association);
    Ok(id)
}

/// The browser currently waiting to be paired, if any.
///
/// The event alone is not enough: a browser can ask while the window is on a
/// screen with no listener attached, and the request then sits in state with
/// nothing on screen to accept it. The UI asks for this on mount so a request
/// that arrived earlier is still actionable.
#[tauri::command]
pub fn pending_browser(state: State<'_, AppState>) -> Option<String> {
    state.pending_association()
}

/// The login waiting to be saved, if any.
///
/// Returns the origin and username only. The webview has no need for the
/// password — it is saving it, not showing it — and the less of it that
/// exists outside Rust the better.
#[tauri::command]
pub fn pending_capture(state: State<'_, AppState>) -> Option<crate::dto::CaptureSummary> {
    state
        .pending_capture_summary()
        .map(|(origin, username)| crate::dto::CaptureSummary { origin, username })
}

/// Save the waiting login.
///
/// The title defaults to the origin's host, which is what the user would type
/// anyway, and the origin goes into `urls` so autofill matches it next time.
#[tauri::command]
pub fn save_capture(state: State<'_, AppState>, title: Option<String>) -> CmdResult<String> {
    state.touch();

    let capture = state
        .take_pending_capture()
        .ok_or_else(|| CmdError::bad_request("Nothing is waiting to be saved."))?;

    let title = title
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .unwrap_or_else(|| host_of(&capture.origin));

    let meta = mortise_vault::ItemMeta {
        title,
        urls: vec![capture.origin.clone()],
        username: capture.username.clone(),
        folder: None,
        tags: Vec::new(),
        project: None,
        environment: None,
    };
    let payload = mortise_vault::ItemPayload::Login {
        password: capture.password.to_string(),
        totp_seed: None,
        notes: None,
    };

    state.with_vault(|vault| {
        let v = vault.ok_or_else(|| state.no_vault_error())?;

        // Changing a password on a site should move the saved one forward,
        // not leave the old one behind beside a new entry. The browser only
        // reaches here when the password is one the vault does not already
        // hold, so a matching origin and username means exactly this case.
        //
        // Only when there is a username to match on: without one, "the same
        // login" is a guess, and guessing wrong overwrites a password the
        // user still needs.
        let parsed = mortise_vault::Origin::parse(&capture.origin);
        if let (Some(parsed), Some(username)) = (parsed, capture.username.as_deref()) {
            let existing = v.find_for_origin(&parsed).unwrap_or_default();
            if let Some(found) = existing
                .iter()
                .find(|i| i.meta.username.as_deref() == Some(username))
            {
                // Keep the item's own metadata; only the secret moves.
                let kept = v.item_meta(found.id)?;
                v.update_item(found.id, &kept, &payload)?;
                return Ok(crate::dto::id_to_hex(found.id));
            }
        }

        let id = v.create_item(&meta, &payload)?;
        Ok(crate::dto::id_to_hex(id))
    })
}

/// Throw away the waiting login.
#[tauri::command]
pub fn discard_capture(state: State<'_, AppState>) {
    state.clear_pending_capture();
}

/// `https://github.com` becomes `github.com`. Falls back to the whole origin
/// rather than inventing a name.
fn host_of(origin: &str) -> String {
    origin
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(origin)
        .trim_end_matches('/')
        .to_string()
}

/// Decline the pending pairing request.
#[tauri::command]
pub fn reject_browser(state: State<'_, AppState>) {
    state.clear_pending_association();
}

/// Browsers currently paired.
#[tauri::command]
pub fn list_browsers() -> Vec<crate::browser::associations::Association> {
    crate::browser::associations::list()
}

/// Unpair one browser.
#[tauri::command]
pub fn unpair_browser(id: String) -> CmdResult<()> {
    crate::browser::associations::remove(&id).map_err(CmdError::from)
}

/// Whether the browser knows where to find our native helper.
#[tauri::command]
pub fn native_host_status() -> crate::browser::native_host::HostStatus {
    crate::browser::native_host::status()
}

/// Tell every installed Chromium-family browser about the helper.
///
/// Writing into the user's own Application Support directory, so no elevation
/// and no terminal. The extension id is the one thing the app cannot work out
/// for itself, which is why it is the only argument.
#[tauri::command]
pub fn install_native_host(extension_id: String) -> CmdResult<Vec<String>> {
    crate::browser::native_host::install(&extension_id).map_err(CmdError::from)
}

/// Remove the registration. Autofill stops working until it is reinstalled.
#[tauri::command]
pub fn uninstall_native_host() -> CmdResult<()> {
    crate::browser::native_host::uninstall().map_err(CmdError::from)
}

/// Defer auto-lock. Called by the UI on user activity.
#[tauri::command]
pub fn touch(state: State<'_, AppState>) {
    state.touch();
}

// --- sync ---

/// What the sync section of settings shows.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SyncStatus {
    /// The relay this vault syncs with, if configured.
    pub relay_url: Option<String>,
    /// Changes waiting to be uploaded.
    pub pending: u32,
    /// How far this device has pulled.
    pub cursor: u64,
}

/// Current sync configuration and backlog.
#[tauri::command]
pub fn sync_status(state: State<'_, AppState>) -> CmdResult<SyncStatus> {
    state.with_vault(|vault| {
        let v = vault.ok_or_else(|| state.no_vault_error())?;
        Ok(SyncStatus {
            relay_url: v.relay_url()?,
            // Counting needs no key, so this works while locked.
            pending: v
                .unpushed_changes(u32::MAX)
                .map(|c| c.len() as u32)
                .unwrap_or(0),
            cursor: v.sync_cursor()?,
        })
    })
}

/// Reject a path that is not a plain readable file.
///
/// Both import commands take a path from the webview and open it. The UI gets
/// that path from a native picker, but the backend cannot see that, and the
/// app is not sandboxed — so a compromised webview could name any file the
/// user can read, have it parsed into the vault, and then read it back out
/// with `search` and `reveal`. That is a file-read primitive reaching past
/// the boundary this surface exists to define.
///
/// This does not close it — only the backend owning the picker would — but it
/// refuses the shapes that are never a file the user chose: directories,
/// devices, sockets, and symlinks, which are how a path ends up pointing
/// somewhere other than where it reads.
fn readable_plain_file(path: &str) -> Result<std::path::PathBuf, CmdError> {
    let path = std::path::Path::new(path);
    let meta = std::fs::symlink_metadata(path)
        .map_err(|_| CmdError::bad_request("That file could not be opened."))?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        return Err(CmdError::bad_request("That is not a file."));
    }
    Ok(path.to_path_buf())
}

/// Whether the URL's *host* is this machine.
///
/// Hand-parsed rather than pulling in a URL crate for one check: take what
/// sits between the scheme and the first `/`, `?` or `#`, drop any userinfo
/// before the last `@` so `http://127.0.0.1@evil.example` is read as
/// `evil.example`, then drop the port.
pub fn is_loopback_host(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("http://") else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host_port = match authority.rsplit_once('@') {
        Some((_, after)) => after,
        None => authority,
    };
    let host = if let Some(end) = host_port.strip_prefix('[').and_then(|r| r.find(']')) {
        // IPv6 literal: the brackets are part of the host, the port is after.
        &host_port[..end + 2]
    } else {
        host_port.split(':').next().unwrap_or_default()
    };

    matches!(
        host.to_ascii_lowercase().as_str(),
        "127.0.0.1" | "localhost" | "[::1]"
    )
}

/// Point this vault at a relay, or clear it to turn sync off.
///
/// Clearing leaves the change log intact — sync stops, nothing is lost, and
/// pointing at a relay again resumes from the stored cursor.
#[tauri::command]
pub fn set_relay(state: State<'_, AppState>, url: Option<String>) -> CmdResult<SyncStatus> {
    let trimmed = url.as_deref().map(str::trim).filter(|u| !u.is_empty());

    if let Some(u) = trimmed {
        if !u.starts_with("https://") && !u.starts_with("http://") {
            return Err(CmdError::bad_request(
                "Enter a relay URL starting with https://.",
            ));
        }
        // http is allowed for a relay on this machine during development, but
        // anywhere else it would put device keys and sync timing in the clear.
        //
        // Matched against the host, not anywhere in the string. `contains`
        // accepted http://relay.localhost.evil.example/, http://evil.example/
        // ?r=localhost and http://evil.example/#127.0.0.1 — a URL a support
        // page or a relay operator could hand someone, which then carried the
        // whole sync stream in plaintext while looking like it had been
        // checked.
        if u.starts_with("http://") && !is_loopback_host(u) {
            return Err(CmdError::bad_request(
                "Use https:// for a relay that is not on this machine.",
            ));
        }
    }

    state.with_vault(|vault| {
        let v = vault.ok_or_else(|| state.no_vault_error())?;
        v.set_relay_url(trimmed)?;
        Ok::<(), CmdError>(())
    })?;
    sync_status(state)
}

/// Push and pull once.
///
/// Async with the work on a blocking thread: the HTTP client is blocking, and
/// running it on the UI thread would freeze the window for the round trip.
#[tauri::command]
pub async fn sync_now(app: tauri::AppHandle) -> CmdResult<SyncReport> {
    let outcome = tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<AppState>();
        let url = state
            .with_vault(|vault| {
                let v = vault.ok_or_else(|| state.no_vault_error())?;
                v.relay_url().map_err(CmdError::from)
            })?
            .ok_or_else(|| CmdError::bad_request("No relay is configured."))?;

        let syncer = mortise_sync::Syncer::new(mortise_sync::HttpTransport::new(url));

        state.with_vault(|vault| {
            let v = vault.ok_or_else(|| state.no_vault_error())?;
            syncer.sync(v).map_err(sync_error)
        })
    })
    .await
    .map_err(|_| CmdError::bad_request("Sync was interrupted."))??;

    Ok(SyncReport {
        pushed: outcome.pushed,
        pulled: outcome.pulled,
        applied: outcome.applied,
        rejected: outcome.rejected,
    })
}

/// Register this vault with its relay, so this device may sync.
#[tauri::command]
pub async fn claim_vault_on_relay(app: tauri::AppHandle) -> CmdResult<()> {
    tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<AppState>();
        let url = state
            .with_vault(|vault| {
                let v = vault.ok_or_else(|| state.no_vault_error())?;
                v.relay_url().map_err(CmdError::from)
            })?
            .ok_or_else(|| CmdError::bad_request("No relay is configured."))?;

        let syncer = mortise_sync::Syncer::new(mortise_sync::HttpTransport::new(url));
        state.with_vault(|vault| {
            let v = vault.ok_or_else(|| state.no_vault_error())?;
            syncer.claim(v).map_err(sync_error)
        })
    })
    .await
    .map_err(|_| CmdError::bad_request("Registration was interrupted."))?
}

/// Promote one local developer-secrets project to its own vault and return the
/// single invite link to share with a teammate.
#[tauri::command]
pub async fn create_project_invite(
    app: tauri::AppHandle,
    project_id: String,
    inviter_name: String,
) -> CmdResult<String> {
    tauri::async_runtime::spawn_blocking(move || {
        let state = app.state::<AppState>();
        let project_path = state
            .vault_path()
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .join("projects")
            .join(format!("{project_id}.vault"));
        if let Some(parent) = project_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|_| CmdError::bad_request("Could not create the project vault."))?;
        }

        state.with_vault(|vault| {
            let account = vault.ok_or_else(|| state.no_vault_error())?;
            let project = account
                .projects()?
                .into_iter()
                .find(|project| project.id == project_id)
                .ok_or_else(|| CmdError::bad_request("No such project."))?;
            let relay = account
                .relay_url()?
                .ok_or_else(|| CmdError::bad_request("Configure a relay before sharing."))?;

            let mut shared = mortise_vault::Vault::create_project_vault(
                &project_path,
                account,
                &project.name,
                &project.description,
            )?;
            shared.set_relay_url(Some(&relay))?;
            for environment in &project.environments {
                shared.add_shared_project_environment(environment)?;
            }

            let rows: Vec<_> = account
                .search("")?
                .into_iter()
                .filter(|row| row.meta.project.as_deref() == Some(project.name.as_str()))
                .collect();
            for row in &rows {
                let payload = account.reveal(row.id)?;
                if let mortise_vault::ItemPayload::EnvSecret { value } = &payload {
                    shared.upsert_project_env_secret(
                        row.meta.environment.as_deref().unwrap_or("dev"),
                        &row.meta.title,
                        value,
                    )?;
                }
            }

            let syncer = mortise_sync::Syncer::new(mortise_sync::HttpTransport::new(&relay));
            syncer.claim(&shared).map_err(sync_error)?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_millis() as u64)
                .unwrap_or(0);
            let cert = shared.identity()?.certify(shared.device()?.public(), now);
            let invite = mortise_crypto::invite::Invite::create(
                shared.meta().vault_id,
                &relay,
                cert,
                &inviter_name,
                &project.name,
                shared.device()?.public().clone(),
                now,
                now + mortise_crypto::invite::MAX_INVITE_LIFETIME_MS,
            )?;
            syncer
                .register_invite(&shared, &invite)
                .map_err(sync_error)?;
            syncer.sync(&mut shared).map_err(sync_error)?;

            // Remove originals only after the independent vault is registered
            // and its contents are safely on the relay.
            for row in rows {
                account.delete_item(row.id)?;
            }
            account.delete_project(&project_id)?;
            Ok(invite.to_link())
        })
    })
    .await
    .map_err(|_| CmdError::bad_request("Sharing was interrupted."))?
}

/// Safe, key-free details shown before a join request is sent.
#[derive(Debug, serde::Serialize)]
pub struct InvitePreview {
    /// Project name claimed by the inviter.
    pub project_name: String,
    /// Self-chosen inviter label.
    pub inviter_name: String,
    /// Identity fingerprint to compare out of band.
    pub fingerprint: String,
    /// Expiry time.
    pub expires_at_ms: u64,
}

/// Parse an invite and expose only what the confirmation screen needs.
#[tauri::command]
pub fn inspect_project_invite(link: String) -> CmdResult<InvitePreview> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0);
    let invite = mortise_crypto::invite::Invite::from_link(&link, now)?;
    Ok(InvitePreview {
        project_name: invite.project_name().to_string(),
        inviter_name: invite.inviter_name().to_string(),
        fingerprint: invite.inviter().identity().fingerprint().to_string(),
        expires_at_ms: invite.expires_at_ms(),
    })
}

/// Send this device's authenticated request through the invite mailbox.
#[tauri::command]
pub async fn request_project_access(
    app: tauri::AppHandle,
    link: String,
    joiner_name: String,
) -> CmdResult<()> {
    tauri::async_runtime::spawn_blocking(move || {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_millis() as u64)
            .unwrap_or(0);
        let invite = mortise_crypto::invite::Invite::from_link(&link, now)?;
        let state = app.state::<AppState>();
        state.with_vault(|vault| {
            let account = vault.ok_or_else(|| state.no_vault_error())?;
            let cert = account.identity()?.certify(account.device()?.public(), now);
            let request = mortise_crypto::invite::JoinRequest::seal(
                &invite,
                account.device()?,
                &cert,
                &joiner_name,
            )?;
            let syncer =
                mortise_sync::Syncer::new(mortise_sync::HttpTransport::new(invite.relay_url()));
            syncer
                .post_join_request(invite.mailbox_id()?, &request)
                .map_err(sync_error)
        })
    })
    .await
    .map_err(|_| CmdError::bad_request("The join request was interrupted."))?
}

/// What one sync round did.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SyncReport {
    /// Changes uploaded.
    pub pushed: u32,
    /// Changes downloaded.
    pub pulled: u32,
    /// Changes folded into the item list.
    pub applied: u32,
    /// Changes refused. Non-zero is worth showing — it means the relay served
    /// something this device could not verify.
    pub rejected: u32,
}

fn sync_error(e: mortise_sync::Error) -> CmdError {
    use mortise_sync::Error as E;
    match e {
        E::Unreachable(_) => CmdError::bad_request("Could not reach the relay."),
        E::AlreadyClaimed => {
            CmdError::bad_request("That vault is already registered on this relay.")
        }
        E::Refused { ref code, .. } if code == "unauthorized" => CmdError::bad_request(
            "This device is not authorized on the relay. Register the vault first.",
        ),
        E::Vault(v) => CmdError::from(v),
        other => {
            eprintln!("mortise: sync error: {other}");
            CmdError::bad_request("Sync failed.")
        }
    }
}

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

use tauri::State;
use truepass_crypto::generate::{PasswordSpec, password};
use truepass_crypto::kdf::Argon2Params;
use truepass_crypto::recovery;
use truepass_vault::{ItemPayload, Vault};
use zeroize::Zeroizing;

use crate::dto::{ItemRow, MetaInput, NewVault, VaultStatus, id_from_hex};
use crate::error::{CmdError, CmdResult};
use crate::state::AppState;

/// How long a copied secret stays on the clipboard.
const CLIPBOARD_CLEAR_AFTER: Duration = Duration::from_secs(30);

/// Which screen the UI should show.
#[tauri::command]
pub fn status(state: State<'_, AppState>) -> VaultStatus {
    let exists = state.vault_exists();
    state.with_vault(|vault| match vault {
        Some(v) => VaultStatus {
            exists: true,
            unlocked: v.is_unlocked(),
            // Search availability is distinct from unlocked: it survives lock
            // but not a cold start. The UI needs to tell those apart.
            searchable: v.search("").is_ok(),
            item_count: v.item_count().unwrap_or(0),
        },
        None => VaultStatus {
            exists,
            unlocked: false,
            searchable: false,
            item_count: 0,
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
            eprintln!("truepass: cannot create vault directory: {e}");
            CmdError::bad_request("Could not create the vault directory.")
        })?;
    }

    let (vault, account_key) = Vault::create(
        state.vault_path(),
        master_password.as_bytes(),
        Argon2Params::default(),
    )?;
    let kit = recovery::encode(&account_key);
    state.install(vault);
    state.touch();

    Ok(NewVault { recovery_kit: kit })
}

/// Unlock with the master password and recovery kit.
///
/// Requiring the kit on every unlock is a deliberate M3 limitation, not the
/// intended flow. Spec §2.1 puts the account key in the macOS keychain behind
/// an access-control ACL so only the password — or Touch ID — is needed. That
/// is M4 work, and until then the honest option is to ask for it rather than
/// stash it somewhere insecure.
#[tauri::command]
pub fn unlock(
    state: State<'_, AppState>,
    master_password: String,
    recovery_kit: String,
) -> CmdResult<VaultStatus> {
    let account_key = recovery::decode(&recovery_kit)
        .map_err(|_| CmdError::bad_request("That recovery key is not valid."))?;

    state.with_vault(|vault| {
        let v = vault.ok_or_else(CmdError::no_vault)?;
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

/// Sign out: lock and close search too.
#[tauri::command]
pub fn sign_out(state: State<'_, AppState>) -> VaultStatus {
    state.with_vault(|vault| {
        if let Some(v) = vault {
            v.lock_fully();
        }
    });
    status(state)
}

/// Search items. Works while locked.
#[tauri::command]
pub fn search(state: State<'_, AppState>, query: String) -> CmdResult<Vec<ItemRow>> {
    state.touch();
    state.with_vault(|vault| {
        let v = vault.ok_or_else(CmdError::no_vault)?;
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
        let v = vault.ok_or_else(CmdError::no_vault)?;
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
        let v = vault.ok_or_else(CmdError::no_vault)?;
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

/// Delete an item.
#[tauri::command]
pub fn delete_item(state: State<'_, AppState>, id: String) -> CmdResult<()> {
    state.touch();
    let item_id = id_from_hex(&id).ok_or_else(|| CmdError::bad_request("Malformed item id."))?;
    state.with_vault(|vault| {
        let v = vault.ok_or_else(CmdError::no_vault)?;
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
/// Honest only because selection is uniform — see `truepass_crypto::generate`.
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
        let v = vault.ok_or_else(CmdError::no_vault)?;
        let payload = v.reveal(item_id)?;
        field_of(&payload, &field).ok_or_else(|| CmdError::bad_request("No such field."))
    })?;

    app.clipboard().write_text(value.as_str()).map_err(|e| {
        eprintln!("truepass: clipboard write failed: {e}");
        CmdError::bad_request("Could not write to the clipboard.")
    })?;

    // Clear only if the clipboard still holds what we put there. Overwriting
    // whatever the user copied in the meantime would be its own small disaster.
    let expected = value.to_string();
    let handle = app.clone();
    std::thread::spawn(move || {
        std::thread::sleep(CLIPBOARD_CLEAR_AFTER);
        if handle
            .clipboard()
            .read_text()
            .is_ok_and(|current| current == expected)
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

/// Defer auto-lock. Called by the UI on user activity.
#[tauri::command]
pub fn touch(state: State<'_, AppState>) {
    state.touch();
}

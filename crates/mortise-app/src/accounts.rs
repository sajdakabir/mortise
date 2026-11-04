//! Account metadata IPC. Session tokens stay in Rust/Keychain; signing uses
//! the unlocked local device, and no account action reads a vault item.
use crate::{
    error::{CmdError, CmdResult},
    state::AppState,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use mortise_accounts::{
    client::{Client, Request},
    protocol::*,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::Mutex;
use tauri::Manager;
use zeroize::Zeroizing;

#[derive(Default)]
pub(crate) struct AccountState {
    inner: Mutex<Cache>,
}
#[derive(Default)]
struct Cache {
    base: String,
    loaded: bool,
    token: Zeroizing<String>,
    expires: i64,
    generation: u64,
    signing_in: bool,
}
#[derive(Serialize, Deserialize)]
struct StoredSession {
    token: String,
    expires_at: i64,
}
#[derive(Serialize)]
pub(crate) struct AccountStatus {
    configured: bool,
    signed_in: bool,
}

fn base() -> Option<String> {
    let compiled = option_env!("MORTISE_ACCOUNTS_URL").map(str::to_owned);
    #[cfg(debug_assertions)]
    let compiled = std::env::var("MORTISE_ACCOUNTS_URL").ok().or(compiled);
    compiled
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.trim_end_matches('/').to_string())
}
fn required_base() -> CmdResult<String> {
    base().ok_or_else(|| CmdError::bad_request("Accounts are not configured in this build."))
}
fn key(base: &str) -> String {
    format!("accounts-session-{}", digest(base))
}
fn error(error: mortise_accounts::Error) -> CmdError {
    let code = match error {
        mortise_accounts::Error::Unauthorized => "account_signed_out",
        mortise_accounts::Error::Untrusted => "untrusted_device",
        _ => "bad_request",
    };
    CmdError::new(code, error.to_string())
}
impl AccountState {
    fn client(&self, base: &str) -> CmdResult<Client> {
        let mut cache = self
            .inner
            .lock()
            .map_err(|_| CmdError::bad_request("Account state unavailable."))?;
        if !cache.loaded || cache.base != base {
            let stored = mortise_macos::load(crate::KEYCHAIN_SERVICE, &key(base), "")?;
            let session = stored
                .as_ref()
                .map(|bytes| serde_json::from_slice::<StoredSession>(bytes))
                .transpose()
                .map_err(|_| {
                    CmdError::bad_request("Sign in again to restore your account session.")
                })?;
            cache.token = Zeroizing::new(
                session
                    .as_ref()
                    .map(|s| s.token.clone())
                    .unwrap_or_default(),
            );
            cache.expires = session.map(|s| s.expires_at).unwrap_or(0);
            cache.base = base.into();
            cache.loaded = true;
        }
        if cache.expires <= now() {
            cache.token = Zeroizing::new(String::new());
        }
        Client::new(base, cache.token.to_string()).map_err(error)
    }
    fn clear(&self, base: &str) -> CmdResult<()> {
        let mut cache = self
            .inner
            .lock()
            .map_err(|_| CmdError::bad_request("Account state unavailable."))?;
        cache.generation += 1;
        cache.token = Zeroizing::new(String::new());
        cache.expires = 0;
        mortise_macos::delete(crate::KEYCHAIN_SERVICE, &key(base))?;
        Ok(())
    }
}
struct LoginGuard<'a>(&'a AccountState);
impl Drop for LoginGuard<'_> {
    fn drop(&mut self) {
        if let Ok(mut cache) = self.0.inner.lock() {
            cache.signing_in = false;
        }
    }
}

#[tauri::command]
pub(crate) async fn account_status(app: tauri::AppHandle) -> CmdResult<AccountStatus> {
    tauri::async_runtime::spawn_blocking(move || {
        let Some(base) = base() else {
            return Ok(AccountStatus {
                configured: false,
                signed_in: false,
            });
        };
        let client = app.state::<AccountState>().client(&base)?;
        Ok(AccountStatus {
            configured: true,
            signed_in: !client.token().is_empty(),
        })
    })
    .await
    .map_err(|_| CmdError::bad_request("Account status was interrupted."))?
}

#[tauri::command]
pub(crate) async fn account_sign_in(app: tauri::AppHandle, device_name: String) -> CmdResult<()> {
    tauri::async_runtime::spawn_blocking(move || {
        let base = required_base()?;
        let state = app.state::<AccountState>();
        let generation = {
            let mut cache = state
                .inner
                .lock()
                .map_err(|_| CmdError::bad_request("Account state unavailable."))?;
            if cache.signing_in {
                return Err(CmdError::bad_request(
                    "Sign-in is already open in your browser.",
                ));
            }
            cache.signing_in = true;
            cache.generation
        };
        let _guard = LoginGuard(&state);
        let client = Client::new(&base, String::new()).map_err(error)?;
        let config = client.config().map_err(error)?;
        let vault_state = app.state::<AppState>();
        let start = vault_state.with_vault(|vault| {
            let vault = vault.ok_or_else(|| vault_state.no_vault_error())?;
            let cert = vault
                .identity()?
                .certify(vault.device()?.public(), (now() * 1000) as u64);
            Request::signed(
                vault.device()?,
                "POST",
                "/v1/auth/start",
                "",
                &LoginStart {
                    certificate: hex(&cert.to_bytes()),
                    device_name,
                },
            )
            .map_err(error)
        })?;
        let challenge: LoginChallenge = client.send(start).map_err(error)?;
        let token = mortise_accounts::client::browser_login(&config, &challenge.nonce, |url| {
            std::process::Command::new("open")
                .arg(url)
                .status()
                .map_err(|_| mortise_accounts::Error::Unavailable)?
                .success()
                .then_some(())
                .ok_or(mortise_accounts::Error::Unavailable)
        })
        .map_err(error)?;
        let finish = vault_state.with_vault(|vault| {
            let vault = vault.ok_or_else(|| vault_state.no_vault_error())?;
            Request::signed(
                vault.device()?,
                "POST",
                "/v1/auth/finish",
                "",
                &LoginFinish {
                    id: challenge.id,
                    id_token: token.id_token.to_string(),
                    access_token: Some(token.access_token.to_string()),
                },
            )
            .map_err(error)
        })?;
        let session: Session = client.send(finish).map_err(|cause| {
            if matches!(cause, mortise_accounts::Error::Unauthorized) {
                eprintln!("mortise: account service rejected sign-in completion");
                CmdError::bad_request("Browser sign-in finished, but the account service rejected it. Please start a new sign-in.")
            } else {
                error(cause)
            }
        })?;
        let stored = Zeroizing::new(
            serde_json::to_vec(&StoredSession {
                token: session.token.clone(),
                expires_at: session.expires_at,
            })
            .map_err(|_| CmdError::bad_request("Could not save the session."))?,
        );
        let mut cache = state
            .inner
            .lock()
            .map_err(|_| CmdError::bad_request("Account state unavailable."))?;
        if cache.generation != generation {
            return Err(CmdError::bad_request("Sign-in was cancelled."));
        }
        mortise_macos::store(
            crate::KEYCHAIN_SERVICE,
            &key(&base),
            &stored,
            mortise_macos::Protection::DeviceUnlocked,
        )?;
        cache.base = base;
        cache.loaded = true;
        cache.token = Zeroizing::new(session.token);
        cache.expires = session.expires_at;
        Ok(())
    })
    .await
    .map_err(|_| CmdError::bad_request("Sign-in was interrupted."))?
}

#[tauri::command]
pub(crate) async fn account_sign_out(app: tauri::AppHandle) -> CmdResult<()> {
    tauri::async_runtime::spawn_blocking(move || {
        let Some(base) = base() else {
            return Ok(());
        };
        let state = app.state::<AccountState>();
        let client = state.client(&base);
        // Always forget the local session, including when offline or locked.
        state.clear(&base)?;
        let Ok(client) = client else {
            return Ok(());
        };
        let vault_state = app.state::<AppState>();
        let signed = vault_state.with_vault(|vault| {
            let vault = vault.ok_or_else(|| vault_state.no_vault_error())?;
            Request::signed(vault.device()?, "POST", "/v1/logout", client.token(), &())
                .map_err(error)
        });
        if let Ok(signed) = signed {
            let _: mortise_accounts::Result<()> = client.send(signed);
        }
        Ok(())
    })
    .await
    .map_err(|_| CmdError::bad_request("Sign-out was interrupted."))?
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Action {
    Dashboard,
    ApproveDevice {
        id: String,
        certificate: String,
    },
    RevokeDevice {
        id: String,
    },
    CreateTeam {
        name: String,
    },
    Members {
        team: String,
    },
    RemoveMember {
        team: String,
        account: String,
    },
    Invite {
        team: String,
        email: Option<String>,
        role: String,
    },
    Requests {
        team: String,
    },
    Decide {
        team: String,
        invitation: String,
        account_id: String,
        approve: bool,
    },
    RevokeInvite {
        team: String,
        invitation: String,
    },
    PreviewInvite {
        link: String,
    },
    RequestInvite {
        link: String,
    },
}
fn id(value: &str) -> CmdResult<&str> {
    if !matches!(value.len(), 32 | 64) || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(CmdError::bad_request("Invalid account identifier."));
    }
    Ok(value)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TeamLink {
    server: String,
    token: String,
}
fn invite_token(link: &str, base: &str) -> CmdResult<String> {
    let token = if let Some(encoded) = link.strip_prefix("mortise://team-invite#") {
        if encoded.len() > 4096 {
            return Err(CmdError::bad_request("Invalid invitation."));
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| CmdError::bad_request("Invalid invitation."))?;
        let info: TeamLink = serde_json::from_slice(&bytes)
            .map_err(|_| CmdError::bad_request("Invalid invitation."))?;
        if info.server.trim_end_matches('/') != base {
            return Err(CmdError::bad_request(
                "This invitation belongs to a different account service.",
            ));
        }
        info.token
    } else {
        // Do not contact an arbitrary server named in an untrusted invite.
        link.strip_prefix(&format!("{base}/join#"))
            .ok_or_else(|| {
                CmdError::bad_request("Use an invitation from your Mortise account service.")
            })?
            .to_string()
    };
    if token.len() != 64 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(CmdError::bad_request("Invalid invitation."));
    }
    Ok(token)
}
impl Action {
    fn request(self, base: &str) -> CmdResult<(&'static str, String, Value, bool)> {
        Ok(match self {
            Self::Dashboard => ("GET", "/v1/me".into(), json!(null), false),
            Self::ApproveDevice {
                id: device,
                certificate,
            } => (
                "POST",
                format!("/v1/devices/{}/approve", id(&device)?),
                json!({"certificate":certificate}),
                false,
            ),
            Self::RevokeDevice { id: device } => (
                "POST",
                format!("/v1/devices/{}/revoke", id(&device)?),
                json!(null),
                false,
            ),
            Self::CreateTeam { name } => ("POST", "/v1/teams".into(), json!({"name":name}), false),
            Self::Members { team } => (
                "GET",
                format!("/v1/teams/{}/members", id(&team)?),
                json!(null),
                false,
            ),
            Self::RemoveMember { team, account } => (
                "POST",
                format!("/v1/teams/{}/members/{}/remove", id(&team)?, id(&account)?),
                json!(null),
                false,
            ),
            Self::Invite { team, email, role } => (
                "POST",
                format!("/v1/teams/{}/invitations", id(&team)?),
                json!({"email":email,"role":role}),
                true,
            ),
            Self::Requests { team } => (
                "GET",
                format!("/v1/teams/{}/requests", id(&team)?),
                json!(null),
                false,
            ),
            Self::Decide {
                team,
                invitation,
                account_id,
                approve,
            } => (
                "POST",
                format!(
                    "/v1/teams/{}/requests/{}/decide",
                    id(&team)?,
                    id(&invitation)?
                ),
                json!({"account_id":account_id,"approve":approve}),
                false,
            ),
            Self::RevokeInvite { team, invitation } => (
                "POST",
                format!(
                    "/v1/teams/{}/invitations/{}/revoke",
                    id(&team)?,
                    id(&invitation)?
                ),
                json!(null),
                false,
            ),
            Self::PreviewInvite { link } => (
                "POST",
                "/v1/invitations/preview".into(),
                json!({"token":invite_token(&link,base)?}),
                false,
            ),
            Self::RequestInvite { link } => (
                "POST",
                "/v1/invitations/request".into(),
                json!({"token":invite_token(&link,base)?}),
                false,
            ),
        })
    }
}
#[tauri::command]
pub(crate) async fn account_action(app: tauri::AppHandle, action: Action) -> CmdResult<Value> {
    tauri::async_runtime::spawn_blocking(move||{
        let base=required_base()?;let state=app.state::<AccountState>();let client=state.client(&base)?;
        if client.token().is_empty(){return Err(error(mortise_accounts::Error::Unauthorized));}
        let (method,path,body,invitation)=action.request(&base)?;
        let vault_state=app.state::<AppState>();
        let request=vault_state.with_vault(|vault|{
            let vault=vault.ok_or_else(||vault_state.no_vault_error())?;
            Request::signed(vault.device()?,method,&path,client.token(),&body).map_err(error)
        })?;
        let result:Value=match client.send(request){Ok(value)=>value,Err(e)=>{
            if matches!(e,mortise_accounts::Error::Unauthorized){state.clear(&base)?;}return Err(error(e));
        }};
        if invitation{
            let invite:Invitation=serde_json::from_value(result).map_err(|_|CmdError::bad_request("Invalid invitation response."))?;
            return Ok(json!({"id":invite.id,"link":format!("{base}/join#{}",invite.token),"expires_at":invite.expires_at}));
        }
        Ok(result)
    }).await.map_err(|_|CmdError::bad_request("Account operation was interrupted."))?
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn invite_does_not_select_a_different_account_server() {
        let token = "a".repeat(64);
        let base = "https://accounts.example";
        assert_eq!(
            invite_token(&format!("{base}/join#{token}"), base).unwrap(),
            token
        );
        assert!(invite_token(&format!("https://attacker.example/join#{token}"), base).is_err());
        let info = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&json!({"server":"https://attacker.example","token":token}))
                .unwrap(),
        );
        assert!(invite_token(&format!("mortise://team-invite#{info}"), base).is_err());
        assert!(id("../teams").is_err());
    }
}

//! The push/pull loop.

use mortise_crypto::identity::Device;
use mortise_relay::auth::sign;
use mortise_relay::protocol::{
    AddDevice, ClaimVault, ErrorBody, HEADER_DEVICE, HEADER_SIGNATURE, HEADER_TIMESTAMP,
    PullResponse, PushRequest, PushResponse,
};
use mortise_vault::Vault;

use crate::error::{Error, Result};
use crate::transport::Transport;
use crate::wire::{from_wire, hex, to_wire};

/// Most changes sent in one request. Matches the relay's own limit.
const PUSH_BATCH: u32 = 500;

/// What a sync round did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SyncOutcome {
    /// Changes uploaded.
    pub pushed: u32,
    /// Changes downloaded and accepted.
    pub pulled: u32,
    /// Changes the relay sent that this vault refused.
    ///
    /// Non-zero is worth surfacing: it means the relay is serving changes this
    /// device cannot verify, which is either a device added since the last ACL
    /// sync or something wrong.
    pub rejected: u32,
    /// Changes folded into the item table.
    pub applied: u32,
    /// Whether more remain on the relay.
    pub more: bool,
}

/// Drives sync for one vault against one relay.
pub struct Syncer<T: Transport> {
    transport: T,
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

impl<T: Transport> Syncer<T> {
    /// Build a syncer over `transport`.
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    /// Sign and send one request.
    fn call(
        &self,
        device: &Device,
        method: &str,
        path: &str,
        body: &[u8],
    ) -> Result<(u16, Vec<u8>)> {
        let timestamp = now_ms();
        let signature = sign(device, method, path, timestamp, body);

        let headers = [
            (HEADER_DEVICE, hex(device.id().as_bytes())),
            (HEADER_TIMESTAMP, timestamp.to_string()),
            (HEADER_SIGNATURE, signature),
        ];
        self.transport.send(method, path, &headers, body)
    }

    /// Turn a non-success status into the relay's own error.
    fn refuse(status: u16, body: &[u8]) -> Error {
        match serde_json::from_slice::<ErrorBody>(body) {
            Ok(parsed) => Error::Refused {
                code: parsed.code,
                message: parsed.message,
            },
            Err(_) => Error::Refused {
                code: format!("http_{status}"),
                message: "The relay refused the request.".into(),
            },
        }
    }

    /// Register this vault and device with the relay.
    ///
    /// Idempotent from the caller's view only in that a second call reports
    /// [`Error::AlreadyClaimed`] — which is also what you get if someone else
    /// registered the same id, so callers should treat it as "check whether
    /// this device is actually enrolled" rather than "fine, carry on".
    pub fn claim(&self, vault: &Vault) -> Result<()> {
        let device = vault.device()?;
        let body = serde_json::to_vec(&ClaimVault {
            vault_id: hex(vault.meta().vault_id.as_bytes()),
            device_signing_key: hex(device.public().signing_public()),
        })?;

        match self.call(device, "POST", "/v1/vaults", &body)? {
            (201, _) => Ok(()),
            (409, _) => Err(Error::AlreadyClaimed),
            (status, body) => Err(Self::refuse(status, &body)),
        }
    }

    /// Authorize another device to sync this vault.
    ///
    /// The relay cannot tell an owner from a member — roles live in the
    /// encrypted ACL — so it accepts this from any registered device. The real
    /// authority check happens on clients, which reject ACL entries from
    /// devices without the role to make them.
    pub fn authorize_device(
        &self,
        vault: &Vault,
        device_id: &[u8; 16],
        signing_key: &[u8; 32],
    ) -> Result<()> {
        let device = vault.device()?;
        let path = format!(
            "/v1/vaults/{}/devices",
            hex(vault.meta().vault_id.as_bytes())
        );
        let body = serde_json::to_vec(&AddDevice {
            device_id: hex(device_id),
            device_signing_key: hex(signing_key),
        })?;

        match self.call(device, "POST", &path, &body)? {
            (204, _) => Ok(()),
            (status, body) => Err(Self::refuse(status, &body)),
        }
    }

    /// Upload everything not yet acknowledged.
    pub fn push(&self, vault: &mut Vault) -> Result<u32> {
        let mut total = 0;

        loop {
            let pending = vault.unpushed_changes(PUSH_BATCH)?;
            if pending.is_empty() {
                return Ok(total);
            }

            let path = format!(
                "/v1/vaults/{}/changes",
                hex(vault.meta().vault_id.as_bytes())
            );
            let body = serde_json::to_vec(&PushRequest {
                changes: pending.iter().map(to_wire).collect(),
            })?;

            let device = vault.device()?;
            let (status, response) = self.call(device, "POST", &path, &body)?;
            if status != 200 {
                return Err(Self::refuse(status, &response));
            }
            let _: PushResponse =
                serde_json::from_slice(&response).map_err(|_| Error::BadResponse)?;

            // Only mark pushed once the relay has acknowledged. A crash before
            // this point costs a duplicate upload, which the relay dedupes;
            // marking first would silently lose the change instead.
            let ids: Vec<_> = pending.iter().map(|c| c.id()).collect();
            vault.mark_pushed(&ids)?;
            total += ids.len() as u32;

            if (ids.len() as u32) < PUSH_BATCH {
                return Ok(total);
            }
        }
    }

    /// Download and ingest everything after the stored cursor.
    ///
    /// Applying is separate and only happens if the vault is unlocked — changes
    /// pulled while locked wait in the log until it is.
    pub fn pull(&self, vault: &mut Vault) -> Result<SyncOutcome> {
        let vault_id = vault.meta().vault_id;
        let mut outcome = SyncOutcome::default();

        loop {
            let cursor = vault.sync_cursor()?;
            let path = format!(
                "/v1/vaults/{}/changes?after={cursor}",
                hex(vault_id.as_bytes())
            );

            let device = vault.device()?;
            let (status, response) = self.call(device, "GET", &path, b"")?;
            if status != 200 {
                return Err(Self::refuse(status, &response));
            }
            let parsed: PullResponse =
                serde_json::from_slice(&response).map_err(|_| Error::BadResponse)?;

            // A change the relay mangled is dropped here rather than handed on
            // as something that merely looks well formed.
            let changes: Vec<_> = parsed
                .changes
                .iter()
                .filter_map(|w| from_wire(w, vault_id))
                .collect();
            outcome.rejected += (parsed.changes.len() - changes.len()) as u32;

            let report = vault.ingest(&changes)?;
            outcome.pulled += report.accepted;
            outcome.rejected += report.rejected;

            vault.set_sync_cursor(parsed.cursor)?;
            outcome.more = parsed.more;

            if !parsed.more {
                break;
            }
        }

        if vault.is_unlocked() {
            outcome.applied = vault.apply_pending()?;
        }
        Ok(outcome)
    }

    /// Push then pull.
    ///
    /// In that order on purpose: uploading first means a conflicting remote
    /// change is merged against work that is already safely stored, rather than
    /// resolved against a local state the relay has never seen.
    pub fn sync(&self, vault: &mut Vault) -> Result<SyncOutcome> {
        let pushed = self.push(vault)?;
        let mut outcome = self.pull(vault)?;
        outcome.pushed = pushed;
        Ok(outcome)
    }
}

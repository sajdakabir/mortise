//! The push/pull loop.

use data_encoding::BASE64;
use mortise_crypto::identity::Device;
use mortise_crypto::identity::DeviceId;
use mortise_crypto::invite::{Invite, MailboxId};
use mortise_relay::auth::sign;
use mortise_relay::protocol::{
    AclPushResult, AddDevice, ClaimVault, ErrorBody, HEADER_DEVICE, HEADER_SIGNATURE,
    HEADER_TIMESTAMP, MailboxRequest, PullAclResponse, PullKeysResponse, PullResponse,
    PushAclRequest, PushAclResponse, PushKeysRequest, PushKeysResponse, PushRequest, PushResponse,
    RegisterMailbox, WireKey,
};
use mortise_vault::Vault;
use mortise_vault::access::Revocation;

use crate::error::{Error, Result};
use crate::transport::Transport;
use crate::wire::{acl_from_wire, acl_to_wire, from_wire, hex, to_wire};

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
    /// Peer ACL entries downloaded and applied (memberships, rotations).
    pub acl_pulled: u32,
    /// Vault keys delivered over the relay and stored.
    pub keys_applied: u32,
    /// Whether more remain on the relay.
    pub more: bool,
}

/// How far one pull may move the cursor.
///
/// The relay's own page limit, so honest syncing is never slowed, and a
/// relay that lies about the cursor gains one page rather than the account.
const MAX_CURSOR_ADVANCE: u64 = 500;

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
    /// Register the one-request mailbox for an invite.
    pub fn register_invite(&self, vault: &Vault, invite: &Invite) -> Result<()> {
        let mailbox = invite.mailbox_id()?;
        let path = format!(
            "/v1/vaults/{}/mailboxes",
            hex(vault.meta().vault_id.as_bytes())
        );
        let body = serde_json::to_vec(&RegisterMailbox {
            mailbox_id: hex(mailbox.as_bytes()),
            expires_at_ms: invite.expires_at_ms(),
        })?;
        match self.call(vault.device()?, "POST", &path, &body)? {
            (201, _) => Ok(()),
            (status, body) => Err(Self::refuse(status, &body)),
        }
    }

    /// Post the opaque join request. Possession of the mailbox id is the only
    /// relay-side authority; HPKE AuthPSK authenticates the contents.
    pub fn post_join_request(&self, mailbox: MailboxId, request: &[u8]) -> Result<()> {
        let path = format!("/v1/mailboxes/{}", hex(mailbox.as_bytes()));
        let body = serde_json::to_vec(&MailboxRequest {
            body: BASE64.encode(request),
        })?;
        match self.transport.send("POST", &path, &[], &body)? {
            (201, _) => Ok(()),
            (status, body) => Err(Self::refuse(status, &body)),
        }
    }

    /// Fetch the first request left in an invite mailbox.
    pub fn get_join_request(&self, vault: &Vault, mailbox: MailboxId) -> Result<Option<Vec<u8>>> {
        let path = format!(
            "/v1/vaults/{}/mailboxes/{}",
            hex(vault.meta().vault_id.as_bytes()),
            hex(mailbox.as_bytes())
        );
        match self.call(vault.device()?, "GET", &path, b"")? {
            (204, _) => Ok(None),
            (200, body) => {
                let request: MailboxRequest =
                    serde_json::from_slice(&body).map_err(|_| Error::BadResponse)?;
                Ok(Some(
                    BASE64
                        .decode(request.body.as_bytes())
                        .map_err(|_| Error::BadResponse)?,
                ))
            }
            (status, body) => Err(Self::refuse(status, &body)),
        }
    }

    /// Close an invite mailbox after grant, denial, or cancellation.
    pub fn close_invite(&self, vault: &Vault, mailbox: MailboxId) -> Result<()> {
        let path = format!(
            "/v1/vaults/{}/mailboxes/{}",
            hex(vault.meta().vault_id.as_bytes()),
            hex(mailbox.as_bytes())
        );
        match self.call(vault.device()?, "DELETE", &path, b"")? {
            (204, _) => Ok(()),
            (status, body) => Err(Self::refuse(status, &body)),
        }
    }

    /// Conditionally remove a member and rotate in one relay-serialized ACL
    /// commit. A conflict is pulled, re-checked and reissued once (§6.3).
    pub fn revoke_member(&self, vault: &mut Vault, removed: DeviceId) -> Result<Revocation> {
        for attempt in 0..2 {
            self.pull_acl(vault)?;
            let prepared = vault.prepare_revocation(removed)?;
            let entries = prepared.entries();
            let path = format!("/v1/vaults/{}/acl", hex(vault.meta().vault_id.as_bytes()));
            let body = serde_json::to_vec(&PushAclRequest {
                entries: entries.iter().map(|entry| acl_to_wire(entry)).collect(),
            })?;
            let (status, response) = self.call(vault.device()?, "POST", &path, &body)?;
            if status != 200 {
                return Err(Self::refuse(status, &response));
            }
            let response: PushAclResponse =
                serde_json::from_slice(&response).map_err(|_| Error::BadResponse)?;
            let conflict = response.results.len() != entries.len()
                || response.results.contains(&AclPushResult::Conflict);
            if conflict {
                if attempt == 0 {
                    continue;
                }
                return Err(Error::Refused {
                    code: "acl_conflict".into(),
                    message: "someone else changed membership".into(),
                });
            }

            let last_seq = entries[1].seq();
            let outcome = vault.commit_revocation(prepared)?;
            vault.mark_acl_pushed(last_seq)?;
            self.remove_device(vault, removed.as_bytes())?;
            self.push_keys(vault)?;
            return Ok(outcome);
        }
        unreachable!("the retry loop always returns")
    }

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

            let rejected_before = outcome.rejected;
            let report = vault.ingest(&changes)?;
            outcome.pulled += report.accepted;
            outcome.rejected += report.rejected;

            // The cursor is ours to advance, not the relay's to set.
            //
            // It used to be stored as whatever the relay sent, through
            // MAX(cursor, ?) — a one-way ratchet the relay controlled. One
            // reply carrying i64::MAX pinned the device forever: every later
            // pull asked for rows after that, matched nothing, and reported a
            // healthy sync with nothing new. It survived the user moving to an
            // honest relay, because the poisoned value lives in the client.
            //
            // Clamped to one page beyond where we were, which is the fastest
            // honest progress possible, so a lying cursor costs at most one
            // round trip instead of the account.
            //
            // Held back entirely when anything in the page was refused, so an
            // orphaned or not-yet-trusted change is re-pulled rather than
            // skipped past and lost.
            let refused = report.rejected > 0 || outcome.rejected > rejected_before;
            if !refused {
                let ceiling = cursor.saturating_add(MAX_CURSOR_ADVANCE);
                vault.set_sync_cursor(parsed.cursor.min(ceiling))?;
            }
            outcome.more = parsed.more;

            if !parsed.more || refused {
                break;
            }
        }

        if vault.is_unlocked() {
            outcome.applied = vault.apply_pending()?;
        }
        Ok(outcome)
    }

    /// Upload ACL entries the relay has not acknowledged.
    pub fn push_acl(&self, vault: &mut Vault) -> Result<u32> {
        let entries = vault.unpushed_acl_entries()?;
        if entries.is_empty() {
            return Ok(0);
        }

        let path = format!("/v1/vaults/{}/acl", hex(vault.meta().vault_id.as_bytes()));
        let body = serde_json::to_vec(&PushAclRequest {
            entries: entries.iter().map(acl_to_wire).collect(),
        })?;

        let device = vault.device()?;
        let (status, response) = self.call(device, "POST", &path, &body)?;
        if status != 200 {
            return Err(Self::refuse(status, &response));
        }
        let result: PushAclResponse =
            serde_json::from_slice(&response).map_err(|_| Error::BadResponse)?;
        if result.results.len() != entries.len()
            || result.results.contains(&AclPushResult::Conflict)
        {
            return Err(Error::Refused {
                code: "acl_conflict".into(),
                message: "someone else changed membership".into(),
            });
        }

        let max_seq = entries.iter().map(|e| e.seq()).max().unwrap_or(0);
        vault.mark_acl_pushed(max_seq)?;
        Ok(entries.len() as u32)
    }

    /// Download and apply ACL entries issued by peers.
    ///
    /// The ACL is a strict sequence, so its own sequence number is the cursor.
    /// An entry that will not apply — a fork, or one whose predecessor has not
    /// arrived — stops the run rather than being skipped past; the next sync
    /// retries from the same point.
    pub fn pull_acl(&self, vault: &mut Vault) -> Result<u32> {
        let vault_id = vault.meta().vault_id;
        let mut applied = 0;

        loop {
            let after = vault.acl_seq()?;
            let path = format!("/v1/vaults/{}/acl?after={after}", hex(vault_id.as_bytes()));

            let device = vault.device()?;
            let (status, response) = self.call(device, "GET", &path, b"")?;
            if status != 200 {
                return Err(Self::refuse(status, &response));
            }
            let parsed: PullAclResponse =
                serde_json::from_slice(&response).map_err(|_| Error::BadResponse)?;

            if parsed.entries.is_empty() {
                break;
            }

            // The relay includes our current head. Requiring it to match before
            // applying the suffix detects a fork instead of silently joining it.
            if after > 0 {
                let first = parsed
                    .entries
                    .first()
                    .and_then(|wire| acl_from_wire(wire, vault_id))
                    .ok_or(Error::BadResponse)?;
                if first.seq() != after || first.id() != vault.acl()?.head() {
                    return Err(Error::Refused {
                        code: "acl_fork".into(),
                        message: "the relay served a different membership history".into(),
                    });
                }
            }

            for wire in &parsed.entries {
                let Some(entry) = acl_from_wire(wire, vault_id) else {
                    continue;
                };
                // Skip anything already held — our own entries, or ones applied
                // on an earlier page.
                if entry.seq() <= vault.acl_seq()? {
                    continue;
                }
                match vault.apply_acl_entry(&entry, false) {
                    Ok(()) => applied += 1,
                    Err(_) => return Ok(applied),
                }
            }

            if vault.acl()?.role(vault.device_id()?).is_none() {
                vault.mark_access_removed()?;
                break;
            }

            if !parsed.more {
                break;
            }
        }
        Ok(applied)
    }

    /// Upload re-wrapped keys the relay has not acknowledged.
    pub fn push_keys(&self, vault: &mut Vault) -> Result<u32> {
        let keys = vault.unpushed_keys()?;
        if keys.is_empty() {
            return Ok(0);
        }

        let path = format!("/v1/vaults/{}/keys", hex(vault.meta().vault_id.as_bytes()));
        let body = serde_json::to_vec(&PushKeysRequest {
            keys: keys
                .iter()
                .map(|(id, epoch, wrapped)| WireKey {
                    recipient_device_id: hex(id.as_bytes()),
                    epoch: *epoch,
                    // The relay replaces this with the authenticated caller.
                    pusher_device_id: String::new(),
                    body: BASE64.encode(wrapped),
                })
                .collect(),
        })?;

        let device = vault.device()?;
        let (status, response) = self.call(device, "POST", &path, &body)?;
        if status != 200 {
            return Err(Self::refuse(status, &response));
        }
        let _: PushKeysResponse =
            serde_json::from_slice(&response).map_err(|_| Error::BadResponse)?;

        vault.mark_keys_pushed()?;
        Ok(keys.len() as u32)
    }

    /// Download and apply vault keys addressed to this device.
    ///
    /// A key that fails to authenticate against the ACL is dropped rather than
    /// fatal — a hostile relay cannot make the client reject the whole sync by
    /// serving one bad key.
    pub fn pull_keys(&self, vault: &mut Vault) -> Result<u32> {
        let path = format!("/v1/vaults/{}/keys", hex(vault.meta().vault_id.as_bytes()));

        let device = vault.device()?;
        let (status, response) = self.call(device, "GET", &path, b"")?;
        if status != 200 {
            return Err(Self::refuse(status, &response));
        }
        let parsed: PullKeysResponse =
            serde_json::from_slice(&response).map_err(|_| Error::BadResponse)?;

        let mut applied = 0;
        for key in &parsed.keys {
            let Ok(bytes) = BASE64.decode(key.body.as_bytes()) else {
                continue;
            };
            if let Ok(true) = vault.apply_wrapped_key(key.epoch, &bytes) {
                applied += 1;
            }
        }
        Ok(applied)
    }

    /// Stop the relay serving a device that has been removed from the vault.
    ///
    /// Defence in depth: clients already refuse a removed device's changes once
    /// the ACL removal reaches them. This also stops that device syncing at all.
    pub fn remove_device(&self, vault: &Vault, device_id: &[u8; 16]) -> Result<()> {
        let path = format!(
            "/v1/vaults/{}/devices/{}",
            hex(vault.meta().vault_id.as_bytes()),
            hex(device_id)
        );
        let device = vault.device()?;
        match self.call(device, "DELETE", &path, b"")? {
            (204, _) => Ok(()),
            (status, body) => Err(Self::refuse(status, &body)),
        }
    }

    /// Push then pull, across changes, the ACL, and re-wrapped keys.
    ///
    /// Order matters. Uploading first means a conflicting remote change is
    /// merged against work already safely stored. On the way down the ACL comes
    /// before keys and keys before changes: a membership change or rotation has
    /// to be known before the key it introduces is stored, and that key has to
    /// be stored before changes written under the new epoch can be applied.
    pub fn sync(&self, vault: &mut Vault) -> Result<SyncOutcome> {
        let pushed = self.push(vault)?;
        self.push_acl(vault)?;
        self.push_keys(vault)?;

        let acl_pulled = self.pull_acl(vault)?;
        let keys_applied = self.pull_keys(vault)?;

        let mut outcome = self.pull(vault)?;
        outcome.pushed = pushed;
        outcome.acl_pulled = acl_pulled;
        outcome.keys_applied = keys_applied;
        Ok(outcome)
    }
}

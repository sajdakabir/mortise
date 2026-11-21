//! Rotation bookkeeping: when a secret last changed, when it is due, and the
//! value it had before, kept briefly so a bad rotation can be undone.
//!
//! The vault maintains all of it. Callers — the webview, an import, a sync —
//! pass whatever they like in `rotated_at_ms` and the previous value; it is
//! replaced on write by what actually changed. That way a "rotation" means
//! the secret's value changed, never that someone edited a title, and no
//! caller can make an old key look fresh.

use crate::error::{Error, Result};
use crate::model::{ItemMeta, ItemPayload, PreviousValue};
use crate::vault::{Vault, now_ms};
use mortise_crypto::item::ItemId;

/// How long a previous value stays restorable.
pub const PREVIOUS_KEPT_MS: u64 = 7 * 86_400_000;

/// The item as it was before this write.
pub struct Before<'a> {
    /// Its metadata.
    pub meta: &'a ItemMeta,
    /// Its secrets.
    pub payload: &'a ItemPayload,
    /// When it was last written, standing in for `rotated_at_ms` on items
    /// from before rotation tracking.
    pub updated_at_ms: u64,
}

/// Fill in the vault-maintained fields of `meta` and `payload` for a write.
///
/// - New item: rotated now, nothing to restore.
/// - Secret changed: rotated now; the old value becomes restorable for
///   [`PREVIOUS_KEPT_MS`] (for kinds that keep one, and only if the kind did
///   not change — an old password is not a previous API key).
/// - Secret unchanged: rotation time and any restorable value carry over.
pub fn apply(before: Option<Before<'_>>, meta: &mut ItemMeta, payload: &mut ItemPayload, now: u64) {
    let has_secret = payload.primary_secret().is_some();
    match before {
        None => {
            meta.rotated_at_ms = has_secret.then_some(now);
            payload.set_previous(None);
        }
        Some(before) => {
            let best_known = before.meta.rotated_at_ms.or(Some(before.updated_at_ms));
            let same_kind = before.payload.kind() == payload.kind();
            let changed = !same_kind || payload.primary_secret() != before.payload.primary_secret();
            if has_secret && changed {
                meta.rotated_at_ms = Some(now);
                let previous = same_kind
                    .then(|| before.payload.primary_secret())
                    .flatten()
                    .map(|old| PreviousValue {
                        value: old.to_string(),
                        rotated_at_ms: best_known,
                        until_ms: now.saturating_add(PREVIOUS_KEPT_MS),
                    });
                payload.set_previous(previous);
            } else {
                meta.rotated_at_ms = if has_secret { best_known } else { None };
                payload.set_previous(before.payload.previous().cloned());
            }
        }
    }
    meta.previous_until_ms = payload.previous().map(|p| p.until_ms);
}

impl Vault {
    /// Swap an item's secret back to its previous value.
    ///
    /// A swap, not a delete: the value being replaced becomes the restorable
    /// one, so restoring by mistake is itself undoable. The restored value
    /// keeps its original age, so an overdue key does not look fresh.
    pub fn restore_previous(&mut self, id: ItemId) -> Result<()> {
        let mut meta = self.item_meta(id)?;
        let mut payload = self.reveal(id)?;
        let now = now_ms();
        let previous = payload
            .previous()
            .filter(|p| p.until_ms > now)
            .cloned()
            .ok_or(Error::Invalid("there is no previous value to restore"))?;
        let current = payload
            .primary_secret()
            .map(str::to_string)
            .ok_or(Error::Invalid("this item has no secret to restore"))?;

        payload.set_primary_secret(previous.value.clone());
        payload.set_previous(Some(PreviousValue {
            value: current,
            rotated_at_ms: meta.rotated_at_ms,
            until_ms: now.saturating_add(PREVIOUS_KEPT_MS),
        }));
        meta.rotated_at_ms = previous.rotated_at_ms;
        meta.previous_until_ms = payload.previous().map(|p| p.until_ms);
        self.rewrite_item(id, &meta, &payload)
    }

    /// Wipe previous values whose restore window has passed. Returns how
    /// many were wiped. Needs the vault unlocked.
    ///
    /// Found from metadata, so only expired items are decrypted.
    pub fn purge_expired_previous(&mut self) -> Result<u32> {
        self.purge_expired_previous_at(now_ms())
    }

    /// [`Vault::purge_expired_previous`] as of `now`, so the expiry rule can
    /// be tested without waiting a week.
    pub fn purge_expired_previous_at(&mut self, now: u64) -> Result<u32> {
        let due: Vec<ItemId> = self
            .list()?
            .into_iter()
            .filter(|row| row.meta.previous_until_ms.is_some_and(|until| until <= now))
            .map(|row| row.id)
            .collect();
        let mut wiped = 0;
        for id in due {
            let mut meta = self.item_meta(id)?;
            let mut payload = self.reveal(id)?;
            payload.set_previous(None);
            meta.previous_until_ms = None;
            self.rewrite_item(id, &meta, &payload)?;
            wiped += 1;
        }
        Ok(wiped)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(value: &str) -> ItemPayload {
        ItemPayload::EnvSecret {
            value: value.into(),
            previous: None,
        }
    }

    #[test]
    fn a_new_item_is_rotated_now_with_nothing_to_restore() {
        let mut meta = ItemMeta {
            rotated_at_ms: Some(1),
            ..Default::default()
        };
        let mut payload = ItemPayload::EnvSecret {
            value: "v".into(),
            previous: Some(PreviousValue {
                value: "forged".into(),
                rotated_at_ms: None,
                until_ms: u64::MAX,
            }),
        };
        apply(None, &mut meta, &mut payload, 500);
        assert_eq!(meta.rotated_at_ms, Some(500), "caller's value is replaced");
        assert_eq!(
            payload.previous(),
            None,
            "a caller cannot plant a previous value"
        );
        assert_eq!(meta.previous_until_ms, None);
    }

    #[test]
    fn changing_the_value_rotates_and_keeps_the_old_one_restorable() {
        let before_meta = ItemMeta {
            rotated_at_ms: Some(100),
            ..Default::default()
        };
        let before = env("old");
        let mut meta = ItemMeta::default();
        let mut payload = env("new");
        apply(
            Some(Before {
                meta: &before_meta,
                payload: &before,
                updated_at_ms: 200,
            }),
            &mut meta,
            &mut payload,
            1000,
        );

        assert_eq!(meta.rotated_at_ms, Some(1000));
        let prev = payload.previous().unwrap();
        assert_eq!(
            (prev.value.as_str(), prev.rotated_at_ms, prev.until_ms),
            ("old", Some(100), 1000 + PREVIOUS_KEPT_MS)
        );
        assert_eq!(meta.previous_until_ms, Some(1000 + PREVIOUS_KEPT_MS));
    }

    #[test]
    fn editing_anything_but_the_value_is_not_a_rotation() {
        let before_meta = ItemMeta {
            rotated_at_ms: Some(100),
            ..Default::default()
        };
        let before = ItemPayload::EnvSecret {
            value: "same".into(),
            previous: Some(PreviousValue {
                value: "older".into(),
                rotated_at_ms: Some(50),
                until_ms: 9999,
            }),
        };
        let mut meta = ItemMeta {
            title: "renamed".into(),
            rotate_every_days: Some(30),
            ..Default::default()
        };
        let mut payload = env("same");
        apply(
            Some(Before {
                meta: &before_meta,
                payload: &before,
                updated_at_ms: 200,
            }),
            &mut meta,
            &mut payload,
            1000,
        );

        assert_eq!(meta.rotated_at_ms, Some(100));
        assert_eq!(
            payload.previous().unwrap().value,
            "older",
            "restore window carries over"
        );
        assert_eq!(meta.previous_until_ms, Some(9999));
    }

    #[test]
    fn an_item_from_before_tracking_uses_its_last_write_as_its_age() {
        let before_meta = ItemMeta::default();
        let before = env("same");
        let mut meta = ItemMeta::default();
        let mut payload = env("same");
        apply(
            Some(Before {
                meta: &before_meta,
                payload: &before,
                updated_at_ms: 200,
            }),
            &mut meta,
            &mut payload,
            1000,
        );
        assert_eq!(
            meta.rotated_at_ms,
            Some(200),
            "setting a policy must not reset the clock"
        );
    }

    #[test]
    fn a_kind_change_does_not_carry_an_old_secret_across() {
        let before_meta = ItemMeta::default();
        let before = ItemPayload::Login {
            password: "pw".into(),
            totp_seed: None,
            notes: None,
        };
        let mut meta = ItemMeta::default();
        let mut payload = env("pw");
        apply(
            Some(Before {
                meta: &before_meta,
                payload: &before,
                updated_at_ms: 200,
            }),
            &mut meta,
            &mut payload,
            1000,
        );
        assert_eq!(payload.previous(), None);
        assert_eq!(meta.rotated_at_ms, Some(1000));
    }

    /// Items written before rotation tracking have none of the new fields.
    #[test]
    fn the_old_formats_still_parse() {
        let payload: ItemPayload =
            serde_json::from_str(r#"{"kind":"EnvSecret","value":"x"}"#).unwrap();
        assert_eq!(payload.previous(), None);
        let payload: ItemPayload =
            serde_json::from_str(r#"{"kind":"ApiKey","key":"k","notes":null}"#).unwrap();
        assert_eq!(payload.primary_secret(), Some("k"));
        let meta: ItemMeta = serde_json::from_str(r#"{"title":"t"}"#).unwrap();
        assert_eq!(
            (
                meta.rotate_every_days,
                meta.rotated_at_ms,
                meta.previous_until_ms
            ),
            (None, None, None)
        );
        // And nothing new is written for items without a policy or history,
        // so an older build reads them back unchanged.
        assert_eq!(
            serde_json::to_string(&env("x")).unwrap(),
            r#"{"kind":"EnvSecret","value":"x"}"#
        );
    }

    #[test]
    fn due_dates_need_a_policy_and_fall_back_for_old_items() {
        let mut meta = ItemMeta::default();
        assert_eq!(meta.rotation_due_at_ms(0), None);
        meta.rotate_every_days = Some(30);
        assert_eq!(
            meta.rotation_due_at_ms(1_000),
            Some(1_000 + 30 * 86_400_000)
        );
        meta.rotated_at_ms = Some(5_000);
        assert_eq!(
            meta.rotation_due_at_ms(1_000),
            Some(5_000 + 30 * 86_400_000)
        );
    }
}

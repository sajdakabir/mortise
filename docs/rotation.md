# Rotation

Mortise tracks when each secret last changed, reminds you when one is due,
and keeps the previous value briefly so a bad rotation can be undone. It
does not yet rotate anything with a provider on its own; see *Not yet* below.

## Policies and reminders

Any login, API key or environment secret can have a policy — rotate every
30, 60, 90, 180 or 365 days — set in the item's editor. Overdue items are
marked in the list ("Rotate"), counted at the top of it, flagged with a dot
in a project's environment, and explained in the item ("Rotated 95 days ago
· overdue by 5 days").

The policy lives in the item's sealed metadata, so it syncs: everyone with a
shared project sees the same reminder.

## What counts as a rotation

Only a change to the secret itself: the password, the key, the value.
Renaming an item, editing its notes or setting a policy does not reset the
clock. Re-importing a `.env` with a new value for a key does.

The vault maintains this, not the caller. Whatever the app, an import or a
sync sends as "last rotated" is replaced by what actually changed, so no
caller can make an old key look fresh.

Items from before rotation tracking have no recorded rotation time; their
last edit stands in for it until the value next changes.

## Rotating and restoring

**Rotate…** in an item takes the new value. For API keys and environment
secrets, the value it replaces stays restorable for **7 days**:
**Restore previous** swaps the two back. A swap, not a delete, so restoring
by mistake is itself undoable — and the restored value keeps its original
age, so an overdue key does not look freshly rotated.

The previous value never leaves the Rust process: the app's `reveal` strips
it before anything reaches the window, and restoring happens in the vault.
After 7 days it is wiped — checked when you unlock and hourly while
unlocked. Logins track rotation but do not keep old passwords.

## Not yet

- **Automatic rotation with providers.** Planned next for providers with an
  API for it (AWS IAM access keys, Postgres role passwords). Most SaaS keys —
  OpenAI, Anthropic, Stripe, GitHub tokens — can only be rotated in the
  provider's dashboard, so Mortise reminds and records rather than rotates.
- **Notifications.** Overdue secrets are shown in the app, not pushed.
- **Older builds** that edit an item drop its policy, since they do not know
  the field.

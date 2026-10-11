# Publishing the browser extension

Status: M5. The package builds and validates; nothing has been submitted,
because submitting needs a Chrome Web Store developer account.

## Why this is on the critical path

Autofill is the reason this product exists rather than being an encrypted notes
app, and autofill needs the extension. Today installing it is five manual steps
ending in a shell script, which means the honest answer to "can someone else
use this?" is no. Publishing collapses that to one click and is the single
largest usability change available to us.

It also fixes a real security wart. Loading unpacked requires Developer mode,
which Chrome nags about on every launch and which also lets *any* unpacked
extension run. Telling users to enable it to install a password manager is bad
advice we currently have to give.

## What you need

| Thing | Where from | Cost |
|---|---|---|
| Chrome Web Store developer account | chrome.google.com/webstore/devconsole | $5, one time |
| A published privacy policy URL | our own site | — |
| 128×128 icon | `extension/icons/icon128.png` | done |
| 1280×800 or 640×400 screenshots | to be made | — |

The $5 is a lifetime fee, not a subscription.

## Building the package

```bash
extension/tools/package.sh
```

Writes `target/extension/truepassword-extension-<version>.zip`. The script
assembles from an allowlist and refuses to build on a manifest that would be
rejected — a `key` field, a description over 132 characters, a missing 128px
icon, a version that disagrees with `package.json`.

It also prints the files it did **not** package. Read that list. `NOTES.md` and
`tools/` are meant to be left out; a new runtime file appearing there is a bug
that only shows up after install.

## Review will ask about permissions

This is where extension submissions actually get rejected, and vague answers
cost a review round trip of several days. Each justification has to name the
user-visible feature the permission exists for.

| Permission | What to write |
|---|---|
| `nativeMessaging` | Reads credentials from the TruePassword desktop app over a local native messaging host. The vault never leaves the user's machine and the extension never stores credentials itself; this is the only way for it to reach them. |
| `activeTab` | Grants access to the current tab only at the moment the user clicks the toolbar icon, so the extension can read the tab's origin and fill the form on that page. Deliberately used in place of host permissions. |
| `scripting` | Injects a single fill function into the active tab, once, after the user picks a credential. No script runs on page load. |
| `storage` | Stores the pairing identifier for the desktop app. No credentials, no browsing history. |

**Single purpose**, which the Store requires as one sentence:

> Fills saved credentials from the user's local TruePassword desktop vault into
> login forms, at the user's explicit request.

The strongest thing we have going into review is that we ask for `activeTab`
rather than `<all_urls>`. Most password managers request host permissions for
every site; `extension/NOTES.md` explains why we do not, and that reasoning is
worth pasting into the justification box rather than summarising.

## Data disclosures

Every answer on the privacy tab is "no", and that is not a technicality:

- Does not collect personally identifiable information
- Does not collect health, financial or payment information
- Does not collect authentication information — **note this carefully**: the
  extension transits credentials between the local app and the page, and never
  collects, stores or transmits them anywhere off the machine
- Does not collect personal communications, location, web history or activity
- Code is not sold or transferred to third parties
- Not used for purposes unrelated to the single purpose
- Not used to determine creditworthiness or for lending

A privacy policy URL is mandatory even when nothing is collected.

## After the first publish

Publishing assigns a permanent extension ID. Two things depend on it, and both
are currently parameterised by hand:

1. **`allowed_origins` in the native messaging host manifest.** The app writes
   this itself now (`browser::native_host`), taking the ID from the onboarding
   panel. Once the ID is fixed it becomes a constant and the field disappears —
   the app can register the host on first run with nothing to type.
   `extension/tools/install-host.sh` stays for scripted setups.
2. **The onboarding panel in the app**, which currently walks through loading
   unpacked. Step 1 becomes "install from the Chrome Web Store" and step 2
   goes away.

Grab the extension's public key from the dashboard and put it in a *local*
`manifest.json` `key` field so unpacked development builds get the same ID as
the published one. Do not commit it — `package.sh` refuses to build with a
`key` present, which is the backstop rather than the plan.

## Review time

First submission is typically a few days and is slower for anything touching
credentials; updates are usually faster. Budget for one rejection round on
permission justifications, because that is the normal outcome rather than a
sign something is wrong.

## Firefox and Safari

Out of scope for now. Firefox needs a `browser_specific_settings` block and
signs through AMO; Safari needs the extension wrapped in a native app bundle
and distributed through the App Store, which is a different build entirely and
would be the first thing in this repo to require App Store review.

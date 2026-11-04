# Test Chrome, Dia and Firefox

This branch adds Firefox support and fixes capture on marked password-change
forms and multi-step forms that retain their username. It also fills explicit
username-only steps without inserting a password into a text field.

**Browser verification is pending.** Per the owner's request, browser downloads
and interactive tests were stopped. Early Chrome test startup lacked the required
test binary; Dia's isolated automation did not reach the Mortise extension.
Those attempts are not successful save/fill tests. The completed checks cover
unit behavior, native-host registration, Svelte/build and packaging only.

## Prepare the app and packages

Use the desktop app built from this branch: an older app cannot register the
Firefox connector. Stop any previous Mortise dev session first so port 1420
is free. With the UI dependencies already installed, start this branch's app:

```sh
cargo build -p mortise-proxy
cargo tauri dev
```

Keep it open and unlocked while testing. In another terminal, from the repository root:

```sh
npm --prefix extension run package
```

This creates two packages under `target/extension/`:

- `mortise-extension-0.1.0.zip` — Chrome and Dia.
- `mortise-extension-firefox-0.1.0.zip` — Firefox **153 or later**.

These packages are built locally and are previews, not published store
extensions. Firefox requires version 153 for
`documentId` targeting; older versions are intentionally unsupported.

## Connect each browser

**Chrome / Dia:** unzip the Chromium package, open `chrome://extensions`, enable
Developer mode, and Load unpacked. Select the folder containing `manifest.json`.
In Mortise, open **Settings → Browsers → Connect a browser**, select Chrome / Dia,
paste the ID shown by that browser, and click Connect browser.

**Firefox:** unzip the Firefox package. Open
`about:debugging#/runtime/this-firefox`, choose Load Temporary Add-on, and select
its `manifest.json`. In Mortise's browser setup, select Firefox and click
Connect Firefox. No ID needs to be copied. Permit access to the test site if
Firefox asks. The disclosed authentication/site data is exchanged with the
local desktop app, not an account server.

For each browser, open the extension popup, choose Pair, approve in Mortise,
then select Check again in the popup. Refresh any login pages opened before
installation. A temporary Firefox extension must be loaded again after closing
Firefox; this limitation remains until an AMO-signed build is distributed.

## Five-minute check, repeated in each browser

Start the fake-login site without installing any browser or test dependency:

```sh
node extension/tools/test-site.mjs
```

Open `http://127.0.0.1:18787/`. Use fake credentials only. Submissions are
discarded by the site; Mortise's capture should save them into your local vault.

1. **Save:** submit the plain login form. Look for the saved entry in Mortise.
2. **Fill:** revisit the form; click the inline Fill button and confirm both fields.
3. **No duplicate:** submit the same login again; the saved-item count stays the same.
4. **Update:** save a login with username `octocat`, then use the change-password
   form. The saved login should contain the new password. Mismatched new/confirm
   values must not be captured. Use a disposable item for this check.
5. **Multi-step:** use the two-step form; the hidden retained username must be
   saved with the password. From the popup, a saved username should also fill
   the first step without exposing the password there.
6. **Lock:** lock Mortise and try filling. No secret should enter the page;
   unlock and retry from the popup or refresh the page for inline suggestions.
7. **Wrong site:** visit the same form through `http://localhost:18787/`. Logins
   saved for `127.0.0.1` must not fill this different origin.
8. **Restart:** restart the app/browser, then try again. For this Firefox preview,
   reload the temporary add-on and re-pair if Firefox discarded its local state.

To finish, stop the test site with Ctrl+C and remove only the fake entries you
created. Shadow-root forms and popup filling of cross-origin iframe logins
remain known limitations. Split-page flows that do not retain a username are
not covered by the new capture fix. Autofill remains user-initiated.

## Code checks (no browser required)

```sh
npm --prefix extension run test:unit
npm --prefix ui run check
npm --prefix ui run build
cargo test -p mortise-app --lib browser::native_host --locked
```

The Chromium/Firefox unit suites model their API differences; they are not
substitutes for testing the actual browsers. Packager tests verify both zip
manifests, shared runtime files and the allowlist that excludes development data.

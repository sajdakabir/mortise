# Testing Mortise on macOS

This path is for short-lived owner and tester builds. The app is ad-hoc signed,
not signed with an Apple Developer identity and not notarized. Use test data,
not real passwords or API keys.

The build is universal (Apple silicon and Intel), requires macOS 11 or later,
and includes the helper used by the Chromium browser extension.

## Get a build

After this workflow is on `master`:

1. Open the repository's **Actions** tab and choose **macOS Test Build**.
2. Click **Run workflow**, choose the branch to test, and run it. The artifact
   records the exact commit checked out from that branch.
3. Open the completed run. Under **Artifacts**, download
   `mortise-macos-test-…`. Artifacts expire after 14 days.
4. Expand the downloaded zip into its own folder. `BUILD.txt` records the exact
   commit and workflow run that produced it.

This workflow is manual and separate from the tag-based release workflow. It
does not read Apple credentials, publish a GitHub release or run on pull
requests.

## Verify, install and open it

In Terminal, change to the expanded artifact folder and check its files:

```sh
shasum -a 256 -c SHA256SUMS
```

The checksum catches a damaged or mixed-up download; because the checksum is
inside the same artifact, it is not an independent proof of who built it. Also
compare `BUILD.txt` with the workflow run you intended to test.

1. Open the `.dmg`, drag **Mortise** to **Applications**, then eject the disk
   image. Do not run the app from the disk image: the browser connector records
   its installed path.
2. In Applications, Control-click **Mortise**, choose **Open**, then confirm.
3. If macOS still blocks it, first try **System Settings → Privacy & Security →
   Open Anyway**. Gatekeeper is expected to object because this test build is
   not Developer ID signed or notarized.

As a last resort, after checking the workflow run and checksum, remove the
download quarantine flag and open the app again:

```sh
xattr -dr com.apple.quarantine "/Applications/Mortise.app"
```

## First run

1. Create a test vault with a master password of at least eight characters.
2. Save the recovery key when it is shown. It appears once; losing both it and
   the master password makes the vault unrecoverable.
3. Add a test login, or import the included `sample-data.csv` from **Settings →
   Import from another manager**. Every secret in that sample is fake.
4. Exercise lock/unlock, add/edit/delete, search, password generation and CSV
   import before trying the browser extension.

## Load the browser extension

The extension currently supports Chromium-family browsers only: Chrome,
Chromium, Brave, Edge, Arc, Dia, Vivaldi and Opera. Safari and Firefox are not
supported. For the safest test, use a disposable browser profile and test
accounts: this unpacked extension requests access to HTTP(S) pages so it can
detect submitted login forms.

1. Expand `mortise-extension-*.zip` into a folder you will not move during the
   test. Moving it can change the unpacked extension ID.
2. Open the browser's extensions page (for example `chrome://extensions` or
   `edge://extensions`), enable **Developer mode**, click **Load unpacked**, and
   select that expanded extension folder.
3. Copy the 32-letter extension ID shown by the browser.
4. Keep Mortise in `/Applications` and running. In its **Get set up** panel,
   expand **Connect your browser**, paste the ID, and click **Connect**.
5. Restart the browser. Pin/open Mortise's toolbar icon, click **Pair**, then
   approve the request in the Mortise window. Return to the extension and click
   **Check again** if needed.
6. On a test login page, save an item whose URL matches that site's origin and
   use the toolbar icon or `Command-Shift-L` to fill it.

If **Connect** says no browser was found, launch the browser once so it creates
its application-support folder, reopen Mortise, and try again.

## Known limitations

- Gatekeeper blocks the first launch; this is not a notarized distribution.
- Touch ID is unavailable in this ad-hoc build; it needs a properly signed app
  with valid keychain entitlements. Keychain approval may be requested again
  after changing builds.
- There is no automatic update path. Installing another test build over the
  app keeps the existing local vault, so continue to use non-production data.
- The extension is unpacked, requires Developer mode, and is not from a browser
  store. Its folder and extension ID must stay stable after connecting it.
- Sync needs a separately provided relay URL. Leave the relay setting empty
  unless the test owner has given you one.

## Report a bug

Open a [GitHub issue](https://github.com/sajdakabir/mortise/issues/new) with:

- the workflow run URL and commit from `BUILD.txt`;
- Mac model, Intel/Apple silicon, and macOS version;
- exact steps, expected result and actual result;
- whether it reproduces after quitting and reopening Mortise; and
- for extension bugs, the browser/version and the extension step that failed.

Screenshots are useful, but remove credentials first. Never attach a vault,
recovery key, master password, real credential, exported CSV, keychain data or
an unreviewed log that may contain any of them.

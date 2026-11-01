# Releasing Mortise

The `Release` workflow builds a universal macOS preview on GitHub Actions.
Apple Developer ID signing and notarization are not configured yet. See
[TESTING.md](../TESTING.md) for the public installation instructions.

## Why this matters more than usual

For most apps an unsigned build is an inconvenience. For a password manager it is
a security problem, and there are two distinct reasons:

1. **A malicious update is total compromise.** Whoever can ship an update to a
   password manager can ship one that exfiltrates every vault. Signing is what
   makes that require stealing a key rather than just a server.
2. **Touch ID does not work unsigned.** Keychain items with a `SecAccessControl`
   need the `keychain-access-groups` entitlement on a signed binary. An unsigned
   build gets `errSecMissingEntitlement` (OSStatus -34018), which the app
   surfaces as "Touch ID needs a signed build". This is not a warning that can
   be ignored — the feature simply does not exist until the app is signed.

## What you need for Apple signing

| Thing | Where from | Cost |
|---|---|---|
| Apple Developer Program membership | developer.apple.com | $99/year |
| **Developer ID Application** certificate | Developer portal → Certificates | included |
| App-specific password | appleid.apple.com → Sign-In and Security | free |
| Team ID | Developer portal → Membership | — |

Note the certificate type: **Developer ID Application**, not "Mac App Store" or
"Apple Development". Only Developer ID produces something distributable outside
the App Store, and picking the wrong one is a common and confusing waste of an
afternoon.

## Cutting a release

Keep the app version in the Tauri config, app Cargo package/lockfile and UI
package/lockfile in step. Then either push a matching tag or run `Release`
manually on the exact branch/commit you want to distribute:

```bash
gh workflow run release.yml --ref master -f publish=true
```

For a tag-triggered build, the tag must be `v` followed by `version` in
`crates/mortise-app/tauri.conf.json`, or the workflow stops. A manual run defaults
to `publish=false`: it uploads an Actions artifact without creating a release.
With `publish=true`, the workflow creates the matching tag at its source commit.
Do not reuse a published version; bump the version for a replacement installer.

The workflow checks/builds the frontend, runs Rust formatting, clippy and tests,
then builds the app **and browser helper** for Apple silicon and Intel. The
release config bundles the helper so browser pairing works after installation.
`scripts/stage-release.sh` verifies signatures, both binary architectures, the
invitation URL scheme, the disk image and checksums before publication.

The release contains the universal DMG, extension zip, `INSTALL.md`, fake sample
CSV, `BUILD.txt` (source commit and workflow URL), and `SHA256SUMS`. Assets upload
to a draft first, then the complete release becomes a public **prerelease**.
The landing page links to the versioned asset because GitHub's `releases/latest`
does not select prereleases.

Signing uses repository secrets — `APPLE_SIGNING_IDENTITY`, `APPLE_CERTIFICATE`,
`APPLE_CERTIFICATE_PASSWORD`, `APPLE_ID`, `APPLE_PASSWORD`, `APPLE_TEAM_ID`.
Until they are set, `APPLE_SIGNING_IDENTITY=-` produces an **ad-hoc signed**
preview. It has no Apple Developer identity and is not notarized. The release
notes and download page say so and include installation instructions. When
signing is configured, update that preview wording as part of the release.

## Building locally

```bash
cargo tauri build
```

This is a local, single-architecture build and does not bundle the browser
helper. Use the release workflow for distributable universal installers; it
explicitly builds the frontend and helper before packaging.

### Invitation links on macOS

The packaged app registers `mortise://join#…` through
`crates/mortise-app/Info.plist`. Its native `RunEvent::Opened` handler queues a
bounded link in memory; the UI opens a confirmation after setup/unlock. Merely
opening a link does not contact the relay or approve access. Do not log links:
their fragments contain the invitation's bearer secret.

Verify `CFBundleURLTypes` in the generated app's `Contents/Info.plist` and test
opening a dummy invitation with the app both closed and already running.
macOS URL registration requires a packaged `.app`; `cargo tauri dev` alone does
not register the scheme. See [Tauri's desktop link testing notes](https://v2.tauri.app/plugin/deep-linking/#desktop-1).

The link flow still requires a configured, reachable relay and Mortise on both
Macs. Requests are checked while Mortise is open and unlocked, including when
the share dialog is closed. Pending links are currently kept only for that app
session. The shipping blockers in `docs/product-readiness.md` still apply;
exercise sharing with dummy projects, not real credentials.

UI regressions use mock IPC: `cd ui && npm ci && npx playwright install chromium
&& npm test`. No real vault or relay is used. `PLAYWRIGHT_EXECUTABLE_PATH` may
point to an already installed compatible Chromium for local checks.

### Signed and notarized

```bash
export APPLE_SIGNING_IDENTITY="Developer ID Application: Your Name (TEAMID)"
export APPLE_ID="you@example.com"
export APPLE_PASSWORD="abcd-efgh-ijkl-mnop"   # app-specific, not your Apple ID password
export APPLE_TEAM_ID="TEAMID"

cargo tauri build
```

Tauri signs with the hardened runtime, applies
[`entitlements.plist`](../crates/mortise-app/entitlements.plist), submits to
Apple's notary service, and staples the ticket. The notarization round trip
usually takes a few minutes.

Verify afterwards:

```bash
codesign --verify --deep --strict --verbose=2 "target/release/bundle/macos/Mortise.app"
spctl --assess --type execute --verbose "target/release/bundle/macos/Mortise.app"
xcrun stapler validate "target/release/bundle/macos/Mortise.app"
```

`spctl` should say `accepted`, `source=Notarized Developer ID`.

## Entitlements

[`entitlements.plist`](../crates/mortise-app/entitlements.plist) grants exactly
two things:

- `keychain-access-groups` — required for Touch ID keychain items
- `com.apple.security.cs.allow-jit` — required by WKWebView, which renders the UI

What it deliberately does **not** grant is the more interesting half, and each
omission is load-bearing:

- App Sandbox is not enabled. The absence of sandbox network/file entitlements
  does **not** block network or filesystem access; the app supports sync and
  import/export. Tauri capabilities and the native command implementations
  must enforce their own boundaries.
- **no `allow-unsigned-executable-memory`, no `disable-library-validation`** —
  both weaken the hardened runtime and nothing here needs them.

Resist adding entitlements speculatively. Every one is a capability an attacker
inherits if they get code execution in the process.

## Still open

- **Updater signing.** Tauri's updater needs its own keypair, separate from the
  Apple one (`cargo tauri signer generate`). The private key must not live in
  CI — a compromised CI that can sign updates is the same catastrophe as a
  compromised Developer ID. Not set up yet.
- **Reproducible builds.** Would let someone verify a release binary matches this
  source. Worth doing for a password manager; not attempted yet.
- **CI remains trusted.** GitHub Actions builds and publishes the preview.
  Checksums detect damage, but are distributed by the same publisher and are
  not independent evidence that a binary matches its source.

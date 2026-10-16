# Releasing Mortise

Status: M4. Everything here except the final signing and notarization steps is
done and committed; those two need an Apple Developer account, which nobody has
set up yet.

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

## What you need

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

Push a tag and the `Release` workflow does the rest on a clean macOS runner —
tests, clippy and `svelte-check`, then the bundle, then a GitHub release with
the `.dmg` and a `SHA256SUMS`:

```bash
git tag v0.1.0 && git push origin v0.1.0
```

The tag must match `version` in `crates/mortise-app/tauri.conf.json` or the
workflow stops before building. Run the workflow manually from the Actions tab
to build without publishing.

Signing uses repository secrets — `APPLE_SIGNING_IDENTITY`, `APPLE_CERTIFICATE`,
`APPLE_CERTIFICATE_PASSWORD`, `APPLE_ID`, `APPLE_PASSWORD`, `APPLE_TEAM_ID`.
Until they are set the workflow still succeeds and publishes an **unsigned**
build, saying so in the release notes. That is deliberate: a silent unsigned
release is worse than a loud one.

## Building locally

```bash
cargo tauri build
```

Unsigned, this produces a working `.app` and `.dmg` that Gatekeeper will refuse
on any Mac but the one that built it. Fine for local testing, not for sending to
anyone.

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

- **no `network.client`** — v1 has no sync, so the app has no business opening a
  socket. M6 will need this and should have to justify it then, rather than
  inheriting it quietly.
- **no `files.user-selected.read-write`** — no import or export yet. M7.
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
- **The icon is placeholder art.** Generated, not designed. Replace before any
  public release.

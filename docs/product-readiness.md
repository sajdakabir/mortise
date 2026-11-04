# Mortise: product direction and PR review

Reviewed 2026-11-01. Passwords and developer secrets come first; Agent Guard
comes after those workflows are dependable. This is a targeted readiness
review, not a complete security audit.

The new account service handles configurable OIDC sign-in, trusted devices and
team invitation approval. It is separate from the encrypted project-sharing
stack reviewed below; team membership does not resolve those key-distribution
or shared-project navigation gaps. See [accounts.md](accounts.md) for setup.

## What we are building

- A lightweight Tauri/Rust app with encrypted vault files on the user's Mac.
- Passwords: import, generation, browser capture and autofill, prioritizing
  Dia, Chrome and Firefox. Native macOS autofill is a later enhancement.
- Developer secrets: projects, environments, `.env` import/export, and sharing
  with teammates using their own accounts and keys.
- An optional relay that stores encrypted content and encrypted key deliveries,
  never plaintext credentials or the private keys needed to decrypt them.
  The current protocol also exposes routing and membership metadata: device
  public keys, ACL operations, sequence numbers and timing. Base64 is not
  encryption. Do not advertise that *every* byte at the relay is ciphertext.
- Agent Guard later: local matching against vault secrets, interception and
  provider-specific revocation. Exact matching is useful, but other password
  managers could implement it too; it is not an exclusive technical moat.

## Browser priorities — decision, 2026-11-04

Prioritize Dia, Chrome and Firefox for the password workflow. Do not start
with a Safari-only native provider or assume it replaces browser capture.
This order reflects the user's target audience, not a browser market-share
claim. The desktop vault remains the authority; browser integration provides
capture and filling without sending credentials to an account service.

Repository status at this decision:

| Browser | Existing implementation | Work before claiming dependable support |
| --- | --- | --- |
| Chrome | Chromium MV3 extension and native-host registration | Verify installation, pairing, capture, updates and filling in the actual browser |
| Dia | Same extension, with its own native-host registration path | Run the same acceptance checks in Dia; Chromium ancestry alone is not verification |
| Firefox | No Firefox manifest/background target or native-host registration | Implement compatible packaging, background handling, registration and onboarding, then verify in Firefox |
| Safari | Native provider research only | Defer implementation until the priority browsers meet the checks below |

Implementation order for passwords:

1. Reproduce the existing save/fill workflow in Chrome and Dia using disposable
   test credentials. Fix failures found there while retaining document-bound
   origin checks.
2. Add a Firefox target using the same capture, fill and pairing logic where
   compatible. Test its actual background lifecycle and native messaging; a
   manifest-only change is not sufficient evidence of support.
3. Simplify onboarding: select an installed browser, show its installation
   instructions, pair, and verify the connection. Published extension IDs and
   store listings are prerequisites for removing manual development setup;
   do not invent download links or silently install browser extensions.
4. Verify all three browsers: first-login capture, no duplicate on repeat
   login, password changes, multi-step forms, revisit suggestions and filling,
   multiple matching accounts, lock/unlock, app/browser restarts and missing
   connection feedback. Navigation, cross-origin frames and focus changes must
   never send credentials to a different document.
5. Add optional Quick Access and native Safari autofill afterwards. These
   improve coverage but do not replace automatic capture in the priority browsers.

This records scope and acceptance criteria, not completed Firefox support.

## Can one desktop installation replace the browser extension?

Partly. Filling and capturing are different capabilities.

| Approach | Autofill | Saving new passwords |
| --- | --- | --- |
| Bundled Apple credential-provider `.appex` | Safari and participating native apps | User-initiated save/create in Mortise's picker; do not promise passive capture |
| Optional Quick Access with Accessibility | Explicit hotkey filling in additional apps/browsers, after target verification | Manual save; no universal automatic capture guarantee |
| Existing browser extension | Browser-aware, document-bound filling | Submit capture in supported browser forms |

The first option is an **OS app extension shipped inside Mortise.app**, not a
separate browser installation. Keep the Rust vault as the authority; the native
component should request narrowly scoped operations over authenticated local
IPC. It must not hold a second plaintext vault or expose master keys.

Apple's credential-provider controller is available on macOS 11+. On the review
date, Apple's documentation lists `ASSavePasswordRequest` for iOS, iPadOS,
Mac Catalyst and visionOS 26.2, **not native macOS**. Mac Catalyst availability
does not make an API available to our native macOS provider.

Native integration needs a signed/provisioned extension, supported-field tests,
locked-app behavior and permission onboarding. The optional system identity
index contains website/username metadata outside Mortise's encrypted file.
Do not build a background keystroke recorder to approximate auto-capture.

Sources checked:

- [Apple: credential-provider extensions](https://support.apple.com/guide/security/credential-provider-extensions-sec6319ac7b9/web)
- [Apple: ASCredentialProviderViewController](https://developer.apple.com/documentation/authenticationservices/ascredentialproviderviewcontroller)
- [Apple: ASSavePasswordRequest](https://developer.apple.com/documentation/authenticationservices/assavepasswordrequest) (platform list also checked in Apple's documentation JSON)
- [1Password: native macOS autofill and manual save/create flow](https://support.1password.com/macos-autofill/)
- [1Password: Accessibility-based Universal Autofill](https://support.1password.com/mac-universal-autofill/)

## Open PR decisions

All nine open PRs contribute useful work. Keep them; do not merge the entire
set just because deployment checks are green. The older #17 is already closed.

| PR / reviewed head | Decision |
| --- | --- |
| [#18](https://github.com/sajdakabir/mortise/pull/18), `491a5a0` | Keep the native-autofill research. Treat untested platform/security assertions as hypotheses; no native component is implemented here. |
| [#19](https://github.com/sajdakabir/mortise/pull/19), `3a89438` | Keep and prioritize: pins autofill to the intended browser document. All 12 unit regressions passed locally. |
| [#20](https://github.com/sajdakabir/mortise/pull/20), `889b1dc` | Keep the browser harness. Integrate with #19 and enable its navigation tests; address the listed shadow-DOM, multi-step and password-change gaps. Full Chromium suite not rerun in this review. |
| [#21](https://github.com/sajdakabir/mortise/pull/21), `a60d7ad` | Keep PR CI. Actual Rust/UI checks are green. The title promises a command split/tests that the current diff/body does not contain; reconcile the description with the delivered scope. |
| [#22](https://github.com/sajdakabir/mortise/pull/22), `1b6b110` | Keep the invite/crypto work, but review the trust binding described below before relying on invitations. |
| [#23](https://github.com/sajdakabir/mortise/pull/23), `f07e691` | Keep independent project vaults and manifests. Finish recovery and desktop routing before shipping. |
| [#24](https://github.com/sajdakabir/mortise/pull/24), `3386c71` | Keep relay/sync groundwork; hold for authorization, failure recovery and protocol fixes. |
| [#25](https://github.com/sajdakabir/mortise/pull/25), `eb1b263` | Keep the test-build workflow; fix its `lipo` check (`arm64`, not Rust's `aarch64`) and run it on macOS before calling the artifact verified. |
| [#26](https://github.com/sajdakabir/mortise/pull/26), `889c868` | Keep the sharing UI work, but hold: normal project operations do not route to shared vault files. |

The sharing stack is #22 → #23 → #24 → #26. #19 and #20 complement it;
#21 and #25 provide CI and test distribution. No PR was closed or merged in
this review, and no message/review was posted to another contributor.

## Confirmed gaps to resolve before sharing ships

1. **Shared projects disappear from normal navigation.** `create_project_invite`
   in `mortise-app/src/commands.rs` deletes personal-vault originals and the
   local project. But `projects`, `search`, reveal/copy and edit commands still
   operate on the personal vault. Joined files are also absent from normal
   project enumeration. Add a project registry and route operations by stable
   vault/project ID, not display name.
2. **Promotion can delete content it did not copy.** Its selection includes all
   items with the project name; the copy loop handles only `EnvSecret`, while
   the delete loop deletes every selected item. A failed attempt also leaves
   an existing destination that prevents a straightforward retry. Use a
   persisted, resumable promotion with verified copy accounting before removal.
3. **Relay device management is not role-authorized.** `remove_device` accepts
   any currently registered caller, then deletes the requested device. A
   Viewer can therefore remove the owner's relay access. Serialized ACL slots
   likewise accept structurally plausible entries without validating their
   author/role, allowing invalid entries to block the log. Client checks protect
   acceptance of secrets; they do not prevent this denial of service.
4. **Invite identity does not authenticate all link fields.** `Invite` is
   unsigned; its checksum is unkeyed, and its displayed fingerprint covers the
   inviter identity, not the separate owner anchor, vault or relay. Reusing a
   genuine inviter certificate does not prove those fields were chosen by that
   inviter. Bind the invite to the verified inviter or explicitly verify the
   complete invitation out of band; cover field substitution in tests.
5. **Revocation needs crash/network recovery.** The new epoch key is held in
   `PreparedRevocation` in memory while the ACL batch is accepted remotely;
   local commit/key delivery follow. Persist enough state to recover a lost
   response or crash. Also test offline peers and outbound changes encrypted
   under a stale epoch. Removal cannot erase previously downloaded secrets.

## First implementation fixes completed in this review

- Invalid or malformed membership responses now stop sync before keys/content
  are fetched; pagination that promises more without advancing returns an error.
- A malformed change page no longer advances its cursor past refused content.
- Known Viewers cannot create/update/delete local items or change shared-project
  metadata. Rejection leaves the item and change log unchanged; later promotion
  restores writes. This does not fix relay-side device-management authorization.
- Resolved the three native app compile warnings in the sharing commands.

Verification: five new regressions plus one strengthened assertion failed
before the fixes; 318 crypto/vault/relay/sync tests pass afterwards. The app
library builds on macOS, workspace clippy with warnings denied and formatting
pass, and Svelte check/build pass. The UI used installed local dependencies;
this was not a clean dependency install or an interactive desktop sharing test.
All database tests used temporary files; the user's vault was not opened.

## Build order and completion criteria

1. Complete browser capture and filling for Dia, Chrome and Firefox using the
   browser priorities and acceptance criteria above. Run the browser harness,
   then fix new-password capture, multi-step login and shadow-DOM cases. Keep
   credentials attached to the exact approved browser document throughout a fill.
2. Finish the shared-project registry and vault routing. Two independent
   accounts must see the project, edit permitted environments, import/copy
   `.env`, lock/reopen and sync without mixing personal or other-project data.
3. Fix invite trust, role authorization and durable grant/revocation/promotion.
   Test offline devices, invalid relays, crashes and retries before enabling
   sharing for real secrets. Provide member/role/removal UI and clear sync errors.
4. After the priority browsers work, build the bundled native password provider.
   Verify signed installation, target matching, unlock, explicit save and
   permission onboarding on supported Macs. Retain browser capture; add
   optional Quick Access later.
5. Produce a tested installer. Only then move to Agent Guard capture,
   interception and provider-specific revocation.

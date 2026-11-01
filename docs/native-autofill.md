# Autofill and capture without the browser extension

Status: research, 2026-10-29. Nothing here is built. Every claim about Apple or
browser behaviour links to its source; claims that could not be verified are
marked **(unverified)** and should be treated as things to test, not facts.

The question: *other than the browser extension, can we build something that
does autofill and auto-capture, so we are not dependent on the extension?*

## Recommendation

**Partly yes for fill, mostly no for capture. Build an AutoFill credential
provider extension, run it as a thin client of the running app, and keep the
browser extension for Chrome.**

The short version:

- **The system path exists and is the right one.** Apple's AuthenticationServices
  *credential provider extension* (an `.appex` inside `Mortise.app`) makes Mortise
  an "AutoFill from" source in System Settings › General › AutoFill & Passwords.
  It fills passwords in **Safari and native apps** (macOS 11+) and passkeys
  (macOS 14+), with the site identity supplied by the OS, not the page. That is
  the same property the extension gets from `tab.url`, so it fits A5.
- **It does not replace the extension in Chrome or Firefox for passwords.**
  Neither browser uses the system password provider for web forms. Apple's own
  answer for third-party browsers is a browser extension. Passkeys are
  different: Chrome's macOS passkey path goes through the system and *should*
  reach a third-party provider, but this has not been tested (§A.5).
- **Automatic capture outside the browser is not on offer on macOS.** Apple added
  a "save this password to your preferred manager" API in **iOS 26.2 only**. It is
  not available on macOS, including in the current OS 27-era docs (§B.1).
  Watching password fields through Accessibility or keyboard events is either
  blocked by the OS (Secure Event Input) or is keylogging, and gets an app pulled
  under App Review 5.1.1(vi). What we *can* do is capture **by invitation**:
  - a "Save a new login for this site" action inside our AutoFill picker;
  - passkey registration, which the system routes to us;
  - a save action in a Quick Access palette.
- **A hotkey Quick Access palette is a useful fallback but a weaker security
  posture.** Global hotkey → search → copy, or type into the frontmost app. It
  works everywhere, Chrome included, but typing into other apps needs the
  Accessibility permission. Outside a browser extension, the only way to know
  which site is in front is the browser's accessibility tree or the window title,
  which is a step back from A5. Make it opt-in, and ship it only on the
  Developer ID build.

### Build order and effort

Estimates assume one engineer comfortable with Swift and the Rust code here.
They are rough and calendar time, not ideal days.

| # | What | Unlocks | Estimate |
|---|---|---|---|
| 0 | **Signed build.** Apple Developer account, Developer ID certificate, App IDs and provisioning profiles; move the keychain items to the data-protection keychain with a shared access group | Everything below, and Touch ID, which already needs it | 1–2 weeks, mostly waiting on Apple setup |
| 1 | **Password provider appex**, thin client of the running app. Picker UI, QuickType suggestions via `ASCredentialIdentityStore`, "save new login" in the picker | Fill in Safari and native apps without the extension | 3–4 weeks |
| 2 | **Passkeys** in the same appex: assertion and registration, plus P-256 in `mortise-crypto` (a crypto-spec amendment) | Passkeys in Safari, native apps, and probably Chrome | 3–5 weeks |
| 3 | **Quick Access palette.** Global hotkey, search, copy with clipboard hygiene, manual "save" | A fallback everywhere, Chrome included | 1–2 weeks |
| 3b | *Optional:* typing from the palette into the frontmost app via Accessibility (Developer ID build only, opt-in) | Native apps that are not AutoFill-aware, terminals | 2–3 weeks |

Do **not** build: Accessibility or event-tap watching of password fields to
"auto-capture" what the user types (§B.3).

Do step 1 with a **thin** appex: it holds no keys and asks the running app for
everything. A thick appex, which links the Rust vault and opens the database
itself, is only needed for iOS (§F) and can come later behind the same Swift
protocol.

## What you get, per surface

| Where | Fill without the extension? | Capture without the extension? |
|---|---|---|
| Safari | **Yes**, credential provider (macOS 11+) | Only by invitation: "save new login" in our picker. Safari's own save prompt goes to Apple Passwords |
| Native apps that tag their fields (`NSTextContentType`) or use `ASAuthorization` | **Yes**, credential provider | Same as Safari |
| Native apps that tag nothing | Only with Quick Access + Accessibility typing (3b) | Manual save from the palette |
| Chrome / Edge / Brave / Arc, passwords | **No.** Chrome does not use the system password provider. Quick Access copy or typing is the fallback | No, keep `capture.js` |
| Chrome, passkeys | Probably, via the system passkey UI **(unverified hands-on)** | Passkey registration, probably, same caveat |
| Firefox | Passwords no; passkeys: iCloud Keychain confirmed, third-party providers **(unverified)** | No |
| Terminal `sudo`, SSH prompts | Quick Access copy or typing only | No |

So the honest answer to "not dependent on the extension" is: **for Safari and
native apps, yes; for passwords in Chromium browsers, no.** No supported macOS
API reaches inside Chrome's web content other than an extension.

---

## Findings

### A. Credential provider extension (AuthenticationServices)

#### A.1 What it is

An app extension (`NSExtensionPointIdentifier =
com.apple.authentication-services-credential-provider-ui`) whose principal
class subclasses
[`ASCredentialProviderViewController`](https://developer.apple.com/documentation/authenticationservices/ascredentialproviderviewcontroller).
On macOS that is an `NSViewController`, on iOS a `UIViewController`. The system
launches it on demand, in its own process, when the user picks a Mortise
suggestion or "Mortise…" in an AutoFill menu. Apple's note: the class "ignores
calls from Mac apps built with Mac Catalyst", so it has to be a real AppKit
extension.

The user enables it in System Settings › General › AutoFill & Passwords
([Apple](https://support.apple.com/en-us/120758);
[1Password's walkthrough](https://support.1password.com/macos-autofill/)). On
macOS 15+ the app can ask for this with
`ASSettingsHelper.requestToTurnOnCredentialProviderExtension`, limited to one
call per 10 s ([WWDC24 10125](https://developer.apple.com/videos/play/wwdc2024/10125/)).
WWDC24 also says users can pick up to three AutoFill apps at once.

#### A.2 API surface by macOS version

All verified against Apple's documentation JSON; method pages hang off the
view-controller link above.

| Capability | API | macOS |
|---|---|---|
| Password fill | `prepareCredentialList(for:)`, `ASPasswordCredentialIdentity`, `ASCredentialIdentityStore` | 11 Big Sur ([WWDC20 10115](https://developer.apple.com/videos/play/wwdc2020/10115/)) |
| Request-based fill (`ASCredentialRequest`: `.password`, `.passkeyAssertion`, `.passkeyRegistration`, `.oneTimeCode`) | `provideCredentialWithoutUserInteraction(for:)`, `prepareInterfaceToProvideCredential(for:)` | 14. The identity-based variants are deprecated in 14 |
| Third-party passkeys: assertion | `prepareCredentialList(for:requestParameters:)`, `ASPasskeyCredentialIdentity` | 14 ([release notes](https://developer.apple.com/documentation/macos-release-notes/macos-14-release-notes)) |
| Third-party passkeys: registration | `prepareInterface(forPasskeyRegistration:)` | 14 |
| Automatic passkey upgrade, no UI | `performWithoutUserInteractionIfPossible(passkeyRegistration:)`, `SupportsConditionalPasskeyRegistration` | 15 ([WWDC24 10125](https://developer.apple.com/videos/play/wwdc2024/10125/)) |
| One-time codes | `prepareOneTimeCodeCredentialList(for:)`, `ASOneTimeCodeCredentialIdentity` | 15 |
| Text insertion ("AutoFill" in any text field) | `prepareInterfaceForUserChoosingTextToInsert`, `ProvidesTextToInsert` | **iOS/iPadOS 18 only, not macOS** |
| Account-creation sheet that third-party managers can serve | `ASAuthorizationAccountCreationProvider` | 26 ([WWDC25 279](https://developer.apple.com/videos/play/wwdc2025/279/)) |
| Signal APIs (RP tells the manager a passkey is unknown, renamed, …) | `ASCredentialUpdater` in 26, deprecated in 26.2 for [`ASCredentialDataManager`](https://developer.apple.com/documentation/authenticationservices/ascredentialdatamanager); provider-side `report…` methods gated by `SupportsCredentialUpdate` | 26 / 26.2 |
| Credential Exchange (FIDO CXP import/export, OS-brokered, no file on disk) | `ASCredentialImportManager`, `ASCredentialExportManager` | 26 ([WWDC25 279](https://developer.apple.com/videos/play/wwdc2025/279/)) |
| **Save a newly typed password to a third-party manager** | `ASSavePasswordRequest`, `performWithoutUserInteractionIfPossible(savePasswordRequest:)`, `ASCredentialDataManager.save(password:…)` | **Not on macOS.** iOS/iPadOS/visionOS 26.2 only (§B.1) |
| Password generation by the provider | `ASGeneratePasswordsRequest`, `SupportsGeneratePasswordCredentials` | **Not on macOS.** iOS 26.2 only |

`Info.plist` capability keys
([`ASCredentialProviderExtensionCapabilities`](https://developer.apple.com/documentation/bundleresources/information-property-list/nsextension/nsextensionattributes/ascredentialproviderextensioncapabilities),
documented from macOS 14): `ProvidesPasswords`, `ProvidesPasskeys`,
`ShowsConfigurationUI`, `SupportsConditionalPasskeyRegistration` (15),
`ProvidesOneTimeCodes` (15). There is no `SupportsSavingPasswords`. The iOS key is
`SupportsSavePasswordCredentials` (26.2).

The macOS 27 docs show no further changes to the provider extension. The only
new related API found is `ASDeliveredVerificationCodesManager`, which reads
delivered SMS and email codes. **(No WWDC26 session on this was found, so absence
is inferred from docs.)**

#### A.3 Flow

1. The app keeps `ASCredentialIdentityStore` up to date with *identities*:
   service plus username, never secrets.
2. The user focuses a login field. Safari or AppKit shows matching identities in
   the QuickType / AutoFill menu, plus an entry that opens our picker.
3. When the user picks an identity, the system calls
   `provideCredentialWithoutUserInteraction(for:)`. We either return the password
   immediately or cancel with `.userInteractionRequired`. In that case the system
   shows our UI via `prepareInterfaceToProvideCredential(for:)`, for unlock.
4. If the user opens our picker instead, the system calls
   `prepareCredentialList(for: [ASCredentialServiceIdentifier])`. We show our own
   list, search, and a "Save a new login" button.
5. We complete with `extensionContext.completeRequest(withSelectedCredential:)`
   or the passkey equivalents.

1Password, which shipped this on macOS on 2026-08-11, reports these practical
limits ([announcement](https://www.1password.community/announcements-52/macos-autofill-is-now-available-to-everyone-25254/index2.html)):
- macOS adds its own Touch ID prompt on fill;
- only the first match is shown inline, behind "show more";
- some subdomain and ranking quirks.

Plan the UX around a system prompt we do not control.

#### A.4 Where the site identity comes from

`ASCredentialServiceIdentifier` is supplied by the system: a `.domain` or a
`.URL`. In Safari it is the page's URL. In a native app it is the domains the
app has proven through Associated Domains (`webcredentials:`), which Apple
verifies against the site's `apple-app-site-association` file. The page cannot
influence either one. This is the property NOTES.md calls *"the origin comes
from the browser, never the page"*, kept at OS level.

Two things to settle in `mortise-vault::origin`:

- **`.domain` identifiers carry no scheme or port.** `Origin::may_fill` is an
  exact scheme+host+port match, so a `.domain` identifier needs a defined mapping:
  `https://<domain>:443` and nothing looser.
- **Some native apps declare no domains.** The list arrives empty, so there is
  nothing to match. Show search and require an explicit pick, labelled "this app
  is not verified for any website". That is a human choice, like copying, and it
  needs its own request type rather than reusing `credential(item_id, origin)`,
  which rightly refuses items that do not match.

#### A.5 Browser coverage

- **Safari:** full support. This is Apple's primary integration.
- **Native apps:** fields tagged with `NSTextContentType` `.username`,
  `.password`, `.oneTimeCode` (11+) or `.newPassword` (14+), and anything using
  `ASAuthorizationController`
  ([WWDC20 10115](https://developer.apple.com/videos/play/wwdc2020/10115/)).
- **Chrome, passwords: no.**
  - Apple says Mac AutoFill in third-party browsers works "by enabling an
    extension", meaning the iCloud Passwords extension
    ([Apple](https://support.apple.com/en-us/120758)).
  - Nothing in Chromium calls the system password provider for web forms.
  - Dashlane says the same of its own macOS app: autofill still needs a browser
    extension "due to Apple limitations"
    ([Dashlane](https://support.dashlane.com/hc/en-us/articles/39026790117778-Install-Dashlane-on-macOS)).
- **Chrome, passkeys: probably.**
  - Chrome 118+ uses the system passkey API on macOS
    ([Chrome blog](https://developer.chrome.com/blog/passkeys-on-icloud-keychain)).
  - Chromium's `device/fido/mac/icloud_keychain.mm` uses
    `ASAuthorizationWebBrowserPlatformPublicKeyCredential` and reads
    `providerName` on 14+. Apple documents that type as covering credentials
    "managed by a third-party credential manager".
  - **Inferred from source, not tested.** Test before promising it.
- **Firefox:** passkeys work with iCloud Keychain since Firefox 122
  ([release notes](https://www.mozilla.org/en-US/firefox/122.0/releasenotes/)).
  Third-party providers are **(unverified)**. Passwords need an extension.

#### A.6 What `ASCredentialIdentityStore` holds, and the leak

Fields we would write:

- Password identity: `serviceIdentifier` (domain or URL, plus an optional
  `displayName`), `user`, `recordIdentifier`, `rank`.
- Passkey identity: `relyingPartyIdentifier`, `userName`, `credentialID`,
  `userHandle`, `recordIdentifier`.

What Apple says about the store
([`shared`](https://developer.apple.com/documentation/authenticationservices/ascredentialidentitystore/shared),
[Platform Security guide](https://support.apple.com/guide/security/credential-provider-extensions-sec6319ac7b9/web)):

- It "doesn't contain passwords, but still contains sensitive information like
  usernames".
- It is per provider and not readable by other apps.
- It is stored in the provider app's container.
- It is excluded from device backups, "so the data never leaves the device".
- It is cleared when the user disables the extension.

Whether it is encrypted at rest, and under which Data Protection class, is
**(unverified)**. Nothing Apple publishes says so.

**This does weaken our promise.** README says titles and URLs are under
`META_KEY`, and crypto-spec §4 says no plaintext column holds anything
sensitive. A populated identity store is a second copy of *site + username for
every login*, held by the OS under keys we do not control, and readable by
anyone with the user's files if it is not protected at rest. Titles need not
leak: leave `displayName` unset and use bare domains. Sites and usernames do.

Options, in order of preference:

1. **Default on, scoped.**
   - Store only `.domain` identifiers and usernames, no titles.
   - Write the store only after the first unlock.
   - `replaceCredentialIdentities([])` on full sign-out. That matches crypto-spec
     §4.1, where "locked" protects secrets, not metadata, and sign-out drops
     both.
   - Say so in the threat model's asset table and in the UI.
2. **A "private AutoFill" setting** that leaves the store empty. Inline QuickType
   suggestions then disappear, and the user opens our picker from the AutoFill
   menu, with the list coming live from the unlocked app.
   **(Unverified: whether macOS Safari still offers the "Mortise…" entry when we
   have published no identities. Test this first. It decides whether option 2 is
   viable.)**
3. Passkey `userHandle` and `credentialID` are opaque, RP-issued values. They
   are less sensitive than usernames, but still identifiers. Same treatment.

Separately, the docs already disagree about local metadata:
- threat-model §1 says metadata is "**Plaintext in the local DB by design**";
- crypto-spec §4 says it is sealed under the vault key and `META_KEY`.

Whichever is current, the identity store needs its own row in that table.

### B. Auto-capture outside the browser

#### B.1 A system "save password?" prompt routed to us: iOS only

- **Exists on iOS 26.2.**
  - `ASSavePasswordRequest` reaches the provider with `credential`,
    `serviceIdentifier`, `event` (`.userInitiated`, `.formDidDisappear`,
    `.generatedPasswordFilled`), via
    `performWithoutUserInteractionIfPossible(savePasswordRequest:)` /
    `prepareInterface(for:)`, gated by `SupportsSavePasswordCredentials`.
  - Apps can call `ASCredentialDataManager.save(password:for:title:anchor:)`,
    documented as saving "to the user's preferred password manager in the
    system".
  - Shipping products use it
    ([NordPass](https://nordpass.com/blog/autosave-credentials-ios/)).
  - Source:
    [`ASSavePasswordRequest`](https://developer.apple.com/documentation/authenticationservices/assavepasswordrequest).
- **Not on macOS.** Re-checked for this doc against Apple's documentation JSON:
  - `ASSavePasswordRequest` and `ASCredentialDataManager.save(password:…)` list
    iOS, iPadOS, Mac Catalyst and visionOS 26.2, and no macOS.
  - `ASCredentialDataManager` itself is on macOS 26.2, but only for the signal
    methods (`reportUnusedPasswordCredential`, `reportUnknownPublicKeyCredential`, …).
  - The Mac Catalyst listing does not help: the provider base class ignores
    Catalyst callers.
- **Passkeys are the exception, since macOS 14.** Registration goes to the
  provider the user picks in the system sheet. From 15, conditional upgrade
  registration needs no UI.

So on macOS, Safari's "save this password?" goes to Apple Passwords, and we
cannot intercept it. This is the single biggest gap. Re-check every WWDC.

#### B.2 Capture by invitation: possible now

Inside our own extension UI we may do anything, including creating an item.
1Password's flow is "select 1Password below the field → New Item"
([support](https://support.1password.com/macos-autofill/)). For us, the picker
shows "Save a new login for `<service>`":

1. The user enters or generates a password in *our* UI.
2. The app commits it to the vault.
3. The appex completes the request with that credential, so it fills as well.

This is capture at sign-up time, which is when it matters most, and it is no
riskier than `capture()` today: a human clicks in our UI.

#### B.3 Accessibility or event-tap watching: impossible or unacceptable

- **Reading a password field's value through Accessibility.** Password fields
  are `AXTextField` with subrole `AXSecureTextField`. WebKit's iOS accessibility
  wrapper returns one "•" per character for them, never the text
  ([source](https://chromium.googlesource.com/external/Webkit/+/3fe43cad1c5040ea4a19bd4de8882829f089873f/Source/WebCore/accessibility/ios/WebAccessibilityObjectWrapperIOS.mm)).
  The macOS behaviour in AppKit, WebKit and Chromium is **(unverified)**; assume
  bullets or empty. Even if some app leaked it, building on that leak would be
  building on a bug.
- **Watching keystrokes.**
  - `NSSecureTextField` turns on Secure Event Input. While it is on, event taps
    and `GetKeys` receive nothing
    ([TN2150](https://developer.apple.com/library/archive/technotes/tn2150/_index.html)).
  - Getting around that is the definition of a keylogger. It would need Input
    Monitoring permission.
  - App Review 5.1.1(vi): apps that "surreptitiously discover passwords" are
    removed from the Developer Program. Guideline 2.5.14 requires consent and a
    visible indicator for recording input
    ([guidelines](https://developer.apple.com/app-store/review/guidelines/)).
  - For a password manager whose pitch is "trust nobody with your secrets",
    shipping that capability is a non-starter even outside the store.
- **Clipboard watching:** no. It would sweep up every password the user copies
  from anywhere.
- **Input method (IMK) trick:** not researched in depth. Secure text fields
  restrict input sources, so an input method is not expected to see password
  entry **(unverified)**. Rejected for the same reasons as keystroke watching.

Verdict: outside the browser, macOS capture is invitation-only (B.2), plus
passkey registration, plus a "save" action in the Quick Access palette.

### C. Quick Access palette and Accessibility fill

#### C.1 Hotkey and palette

- `tauri-plugin-global-shortcut` uses `global-hotkey`, which uses Carbon
  `RegisterEventHotKey` on macOS
  ([source](https://github.com/tauri-apps/global-hotkey/blob/dev/src/platform_impl/macos/mod.rs)).
  Multiple sources say it needs no Accessibility permission; Apple does not
  document it either way.
- Avoid Option-only shortcuts: macOS 15.0 broke them, and 15.2 reversed that
  ([report](https://github.com/feedback-assistant/reports/issues/552)).
- The palette is a Tauri window: search the unlocked metadata, pick, then copy,
  type, or save. 1Password calls this Quick Access (⇧⌘Space).

#### C.2 Getting the secret into the target

| Method | Permission | Notes |
|---|---|---|
| **Copy** | none | Clipboard hygiene, below. Works anywhere, Chrome included |
| **Type** via `CGEventPost` | Accessibility (PostEvent) | What KeePassXC does ([source](https://github.com/keepassxreboot/keepassxc/blob/develop/src/autotype/mac/AutoTypeMac.cpp)). Sources conflict on whether synthetic events survive another app's Secure Event Input **(unverified)**, so test |
| **Set `AXValue`** | Accessibility | Works on plain AppKit fields. On secure fields **(unverified)**; Chromium is inconsistent |

Clipboard hygiene if we copy:
- Mark the item `org.nspasteboard.ConcealedType` and `TransientType`
  ([nspasteboard.org](https://nspasteboard.org/)).
- Write with `prepareForNewContents(with: .currentHostOnly)`, so Universal
  Clipboard does not hand it to the user's iPhone.
- Clear on a timer only if `changeCount` still matches, so we never wipe
  something the user copied later.
- `tauri-plugin-clipboard-manager` / `arboard` reportedly cannot do
  current-host-only **(unverified)**, so this belongs in `mortise-macos`.

#### C.3 Knowing what is in front

This is the weak point, and why the extension exists (A5).

- **Native apps:** bundle id plus the *code-signing identity* of the frontmost
  process (team id). Linking an item to an app on first use, as 1Password does
  with "Always Allow", is reasonable. Window titles are not: KeePass has said for
  years that "the user is responsible for ensuring that the target window is
  legitimate" ([KeePass](https://keepass.info/help/kb/sec_issues.html)).
- **Browsers:** the active tab's URL is readable as `AXURL` on the `AXWebArea`.
  - Chromium only builds its tree when poked with `AXEnhancedUserInterface`,
    which causes lag and window glitches
    ([Chromium 40865608](https://issues.chromium.org/issues/40865608)).
  - The URL is what the browser's accessibility layer reports. That is better
    than a title, but not the `chrome.tabs` origin the extension trusts.
  - **Rule:** if the frontmost app is a browser with the extension paired, hand
    off to the extension and do not type.
- **Typing into the wrong window** is a well-documented failure. A chat window
  grabs focus and the trailing Enter sends the password
  ([KeePassXC #491](https://github.com/keepassxreboot/keepassxc/issues/491)).
  Mitigations:
  - re-check the frontmost process and that the focused element is
    `AXSecureTextField` immediately before typing the password;
  - abort if focus changes;
  - never press Enter by default.

#### C.4 Distribution constraint

Accessibility APIs are not supported from sandboxed apps; DTS: "We do not
support the Accessibility APIs in sandboxed apps"
([forum 756130](https://developer.apple.com/forums/thread/756130)). Mac App
Store apps must be sandboxed. So 3b exists only in the Developer ID build. Copy,
search and save from the palette work in either.

### D. Competitors

| Product | Credential provider on macOS | Accessibility / hotkey fill | Notes |
|---|---|---|---|
| 1Password | Yes, GA 2026-08-11 (8.12.32): passwords and passkeys ([forum](https://www.1password.community/announcements-52/macos-autofill-is-now-available-to-everyone-25254/index2.html)) | Universal Autofill ⌘\ plus Quick Access, Accessibility permission ([support](https://support.1password.com/mac-universal-autofill/)) | Known bug: leaves Secure Event Input stuck after auto-lock ([thread](https://www.1password.community/1password-at-work-58/secure-input-blocking-other-apps-event-taps-25015)), which breaks other apps' hotkeys. A cautionary tale for 3b |
| Bitwarden (Electron) | Passkeys; password fill still a feature request ([forum](https://community.bitwarden.com/t/support-macos-native-autofill-provider-framework-for-passkeys-passwords/97993)) | — | **Closest precedent to us:** Swift appex in `PlugIns`, talking over a unix socket to a non-native app, with Rust IPC exposed via UniFFI ([source](https://github.com/bitwarden/clients/tree/main/apps/desktop/macos)) |
| Strongbox | Yes since Big Sur; passkeys 14+ ([1](https://strongboxsafe.com/macos-big-sur-autofill/), [2](https://strongbox.reamaze.com/kb/faqs/use-passkeys-with-strongbox)) | — | Native app; separate Chrome/Firefox extensions still needed |
| Enpass | Yes, passwords and passkeys ([App Store](https://apps.apple.com/us/app/enpass-password-manager/id732710998?mt=12)) | **(unverified)** | |
| KeePassXC | No | Auto-Type: `CGEventPost`, window-title match ([docs](https://github.com/keepassxreboot/keepassxc/blob/develop/docs/topics/AutoType.adoc)) | macOS 15 users report it also needs Screen Recording to see window titles ([#12443](https://github.com/keepassxreboot/keepassxc/issues/12443)) |
| Proton Pass, Dashlane | No | No | Both rely on browser extensions on Mac |

Nobody captures passwords typed in native apps on macOS. That is not an
oversight on their part.

### E. Comparison

| | A. Credential provider | B.2 Save by invitation | C. Palette: copy | C. Palette: type (3b) | B.3 AX/keystroke capture |
|---|---|---|---|---|---|
| Fill: Safari | ✅ | — | ✅ manual | ✅ | — |
| Fill: native apps | ✅ if fields are tagged | — | ✅ manual | ✅ | — |
| Fill: Chrome passwords | ❌ | — | ✅ manual | ✅ (weaker origin) | — |
| Passkeys | ✅ 14+ | ✅ registration | ❌ | ❌ | — |
| Capture | sign-up flow only | ✅ user-initiated | manual save | manual save | ❌ blocked / keylogging |
| Who supplies the origin | **OS (URL / verified associated domain)** | OS | user | AX tree / bundle id | — |
| Permissions | user enables in Settings | — | none | Accessibility | Input Monitoring |
| Mac App Store compatible | ✅ | ✅ | ✅ | ❌ | ❌ |
| Needs paid Apple account | **yes** | yes (inside appex) | no | no, but an unsigned build loses the Accessibility grant on every rebuild | — |
| Fit with threat model | strong | strong | ok (clipboard is A9) | weaker (A5) | violates §5 spirit |
| Effort | 3–4 wk (+3–5 passkeys) | in A | 1–2 wk | +2–3 wk | don't |

---

## Architecture for the recommended path

### Bundle

```
Mortise.app/Contents/
  MacOS/mortise-app                    Tauri binary (unsandboxed, Developer ID)
  PlugIns/MortiseAutoFill.appex        Swift, App Sandbox ON, own entitlements + profile
  embedded.provisionprofile            needed anyway: keychain-access-groups is restricted
```

- Tauri has no app-extension support: there is no Xcode project and no
  `provisioningProfile` key
  ([schema](https://schema.tauri.app/config/2),
  [issue #14332](https://github.com/tauri-apps/tauri/issues/14332)).
- Its bundler copies `bundle.macOS.files` in before signing, signs the outer app
  last, and does not use `--deep`.
- So:
  1. Build and sign the appex first with `xcodebuild` + `codesign`, using its own
     entitlements and profile.
  2. Place it with `bundle.macOS.files: { "PlugIns/MortiseAutoFill.appex": … }`.
  3. Let Tauri seal the outer bundle.
- Others do the same: Reflect's Safari extension
  ([PR](https://github.com/team-reflect/reflect-open/pull/1755)),
  `tauri-plugin-widgets`.
- **Never `--deep` the outer sign.** It overwrites the appex's entitlements
  ([example](https://github.com/HappyVoxel/granny/pull/37)).
- This is a reading of the bundler source **(not yet tried end to end)**. It is
  the first thing to prove in step 0.

### Thin appex: the app holds the keys, the appex asks

```
┌─ Mortise.app (Rust, unsandboxed) ───────────────┐
│ vault, keys, Touch ID unlock (unchanged)        │
│ autofill server ── unix socket in App Group ────┼──┐
│ identity-store writer (mortise-macos, objc FFI) │  │  peer = our appex?
└─────────────────────────────────────────────────┘  │  (audit token → SecCode
                                                     │   requirement check)
┌─ MortiseAutoFill.appex (Swift, sandboxed) ──────┐  │
│ ASCredentialProviderViewController              │◄─┘
│ VaultClient protocol → SocketVaultClient        │
│ holds no keys; holds a password only until      │
│ completeRequest returns                         │
└─────────────────────────────────────────────────┘
          ▲ serviceIdentifiers from the OS (URL / associated domain)
```

Why thin first:

- It keeps "all crypto and all storage stay in the Rust process" true. The appex
  sees one password at a time, like the extension. It needs no Argon2, which
  matters because extension memory limits are "significantly lower" than apps'
  ([guide](https://developer.apple.com/library/archive/documentation/General/Conceptual/ExtensibilityPG/ExtensionCreation.html)).
- It reuses the server's request vocabulary (`logins`, `credential`, `capture`)
  and the origin re-check in `credential()`.
- It avoids two processes writing one SQLite file. The vault sets WAL but no
  `busy_timeout` (`crates/mortise-vault/src/schema.rs`), and the DB lives in
  `~/Library/Application Support/com.mortise.desktop`, which a sandboxed appex
  cannot read.

The transport is a unix socket in the App Group container. That is permitted
from a sandbox when the socket is inside the group container
([App Groups entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.application-groups)).
It is also what Bitwarden does. XPC is cleaner, with an audit token for free and
`setCodeSigningRequirement`. But a sandboxed appex can only reach a Mach service
registered by a launch agent (`SMAppService`) whose name is prefixed by the group
id ([forum 778297](https://developer.apple.com/forums/thread/778297)). That would
mean making the Tauri process, or a helper, that agent. Revisit if the socket
proves fragile.

**Peer authentication replaces pairing.**
- Any process of the same user can reach the group container, so file
  permissions alone do not answer A9.
- The browser socket solves this with a human-approved pairing key. For our own
  appex we can do better: take the peer's audit token (`LOCAL_PEERTOKEN`;
  **verify availability**; not `LOCAL_PEERPID`, which races on pid reuse) and
  check it against a code requirement: `identifier "com.mortise.desktop.autofill"
  and anchor apple generic and certificate leaf[subject.OU] = "<TEAMID>"`.
- That FFI goes in `mortise-macos`, the crate already designated for `unsafe`.

**When the app is not running or is locked.**
- Locked: the appex shows "Unlock Mortise" and the app raises its usual Touch ID
  keychain prompt. The appex never sees the account key or the unlock token.
- Not running: the appex has to launch it. `NSWorkspace` from a sandboxed process
  generally works, but whether it does from this extension type is
  **(unverified)**. The robust answer is for Mortise to run as a login item or
  menu-bar resident, which the menu-bar search in crypto-spec §4.1 already
  implies.
- Outside the Mac App Store, the appex does not register until the app has been
  launched once.

**Identity store writer.** The host app may write `ASCredentialIdentityStore`
directly; the entitlement goes on both targets
([docs](https://developer.apple.com/documentation/authenticationservices/ascredentialidentitystore)).
- Do it from Rust via `objc2` bindings in `mortise-macos`, on unlock and on every
  item change. Check `getState().supportsIncrementalUpdates` and use incremental
  saves when it allows.
- Do it as a whole replace otherwise, and `replaceCredentialIdentities([])` on
  full sign-out (§A.6).

**Keychain.** `crates/mortise-macos/src/keychain.rs` sets neither
`kSecUseDataProtectionKeychain` nor `kSecAttrAccessGroup`, so on macOS its items
go to the file-based login keychain
([TN3137](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains)).
A thin appex does not need keychain access at all, which is one more point in its
favour. A thick appex, or iOS, would need:
- the account key and unlock token moved to the data-protection keychain under a
  shared access group, e.g. `<TEAMID>.com.mortise.shared`, listed in both
  entitlement files and authorized by both profiles;
- a one-time migration, because the two keychains are separate stores.

### Passkeys (step 2)

The vault already reserves `ItemPayload::Passkey { rp_id, credential_id,
private_key, user_handle }` (`crates/mortise-vault/src/model.rs`).

- **Crypto.** WebAuthn needs **ES256 (P-256 ECDSA)**, and crypto-spec §1 lists
  only Ed25519. Its rule is "no primitive … outside this document", so amend the
  spec first (`p256` crate) before writing code.
- **Assertion.** The appex passes `clientDataHash` and the RP id to the app. The
  app builds `authenticatorData`, signs it, and returns the signature. The
  private key never leaves the Rust process.
- **Registration.** Generate the key in Rust, use attestation `none`, store the
  item, and publish an `ASPasskeyCredentialIdentity`.
- **Migration.** macOS 26's `ASCredentialImportManager` can import passkeys from
  Apple Passwords and other managers without a file on disk.

### Skeleton plan of files (not built)

```
macos/MortiseAutoFill/
  MortiseAutoFill.xcodeproj               appex target only; no app target
  CredentialProviderViewController.swift  prepareCredentialList, provide…, passkey hooks
  VaultClient.swift                       protocol: logins(for:), credential(id, service), save(...)
  SocketVaultClient.swift                 framing identical to browser/protocol.rs
  PickerView.swift                        list, search, "Save a new login"
  Info.plist                              extension point + ASCredentialProviderExtensionCapabilities
  MortiseAutoFill.entitlements            app-sandbox, application-groups, autofill-credential-provider
scripts/build-appex.sh                    xcodebuild + codesign (appex entitlements + profile)
crates/mortise-app/src/autofill/
  mod.rs
  server.rs                               group-container socket; reuses browser handlers
  identities.rs                           vault → ASCredentialIdentityStore sync policy
crates/mortise-macos/src/
  identity_store.rs                       objc2 FFI: replace/save/remove identities, getState
  peer.rs                                 audit token → SecCode requirement check
  pasteboard.rs                           concealed/transient/current-host-only copy (step 3)
crates/mortise-app/entitlements.plist     + application-groups, + autofill-credential-provider
crates/mortise-app/tauri.conf.json        bundle.macOS.files: appex + embedded.provisionprofile
docs/threat-model.md                      new boundary: appex (semi-trusted, sandboxed);
                                          OS-supplied service identifier trusted like tab.url;
                                          identity store as a plaintext metadata asset
```

## Hard requirements

| Requirement | Status in repo | Notes |
|---|---|---|
| Apple Developer Program, $99/yr | **none** (docs/releasing.md) | Blocks everything here. The appex will not register unsigned |
| Developer ID Application certificate, notarization | not set up | Already planned in releasing.md |
| Explicit App IDs: `com.mortise.desktop`, `com.mortise.desktop.autofill` with **AutoFill Credential Provider**, **App Groups**, **Keychain Sharing** | — | AutoFill Credential Provider is available for **Developer ID** as well as App Store ([supported capabilities](https://developer.apple.com/help/account/reference/supported-capabilities-macos)), so no Mac App Store needed |
| Entitlement `com.apple.developer.authentication-services.autofill-credential-provider` on **both** app and appex | — | [docs](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.authentication-services.autofill-credential-provider) |
| Developer ID provisioning profiles, embedded at `Contents/embedded.provisionprofile` in both bundles | **missing today** | Restricted entitlements on macOS must be authorized by a profile ([TN3125](https://developer.apple.com/documentation/technotes/tn3125-inside-code-signing-provisioning-profiles)). `keychain-access-groups`, which `entitlements.plist` already claims, is one, so the signed build needs a profile even without the appex |
| App Sandbox on the appex | — | Required for macOS app extensions (DTS, [forum 798886](https://developer.apple.com/forums/thread/798886)). The main app may stay unsandboxed under Developer ID |
| App Group, team-prefixed (`<TEAMID>.com.mortise`) or profile-authorized `group.` | — | Without one of these, macOS 15 prompts the user and the approval lasts only for that launch ([forum 721701](https://developer.apple.com/forums/thread/721701)) |
| Hardened runtime on both | app: yes | |
| Minimum OS | app: 11.0 | Recommend appex deployment target **macOS 14**: request-based API and passkeys. Below 14 the app runs without AutoFill |
| Mac App Store | not planned | Would need the *main app* sandboxed too, which breaks the native-messaging host manifests written into browser directories, the socket outside a container, and 3b. Developer ID is the right channel |

## Bonus: does this give us iOS?

Partly.

- **What carries over.** The AuthenticationServices calls, request handling,
  identity-store policy and passkey logic are the same API on iOS. The picker UI
  must be rewritten in UIKit or SwiftUI.
  - iOS also has what macOS lacks: text insertion (18), and saving and
    generating passwords (26.2).
  - So iOS capture is *better* than macOS capture.
- **What does not.** The thin-client transport. On iOS there is no running Mortise
  process to ask, so the appex must be **thick**:
  - Rust vault linked as an XCFramework via UniFFI. Bitwarden's `sdk-internal`
    does exactly this ([repo](https://github.com/bitwarden/sdk-internal)).
  - The DB lives in the group container.
  - Unlock uses a keychain-held token behind Face ID / Touch ID.
  - It must stay inside extension memory limits. KeePassium reports about 120 MB
    and recommends Argon2 ≤ 32 MiB in AutoFill
    ([KeePassium](https://keepassium.com/articles/autofill-memory-limits/)); our
    default is 64 MiB. Unlock via the keychain token, not Argon2, inside the
    extension.
  - It also needs a whole iOS app.

Designing the appex around a `VaultClient` protocol from day one is cheap and
keeps that door open: `SocketVaultClient` on macOS, `EmbeddedVaultClient` (UniFFI)
on iOS, or on macOS later if the thin model disappoints.

## Risks

1. **The headline goal is only half-reachable.** Chrome password fill and all
   browser capture still need the extension. If most users live in Chrome, step
   1 mostly helps Safari and native apps.
2. **Tauri + appex packaging is unproven here.** The signing order and
   PlugInKit registration are the first spike. If they fail, the fallback is
   wrapping the Tauri binary in an Xcode-built app target.
3. **The identity store is a plaintext metadata copy we do not control** (§A.6).
   This needs a threat-model amendment and a user-facing sentence.
4. **The app must be running.** A thin appex is useless if Mortise has been quit.
   That pushes Mortise toward being a login item.
5. **Peer authentication of the socket is new FFI in a security-critical
   path.** Get it reviewed with the same care as `keychain.rs`.
6. **Keychain migration** to the data-protection keychain touches the account
   key of every existing install. A bug there locks users out. Needed for
   thick/iOS only, so defer it.
7. **The Apple API churns.** `ASCredentialUpdater` was deprecated one point
   release after it shipped. Pin the deployment target and re-read the provider
   docs every WWDC.
8. **System UX we do not control:** an extra Touch ID prompt per fill,
   first-match-only inline suggestions (per 1Password).
9. **3b specifically:** wrong-window typing, a weaker origin, interaction with
   Secure Event Input (1Password's stuck-Secure-Input bug), Chromium AX
   performance side effects.
10. **The existing extension docs are stale.** `extension/NOTES.md` says "No
    always-on content script" and "`activeTab` instead of host permissions", but
    `manifest.json` now requests `<all_urls>` and injects `capture.js` on every
    page. Not caused by this work, but anyone weighing "how dependent are we on
    the extension" should know the extension's footprint grew.

## Open questions for the owner

1. **What does "not dependent on the extension" mean to you?** If the goal is
   Chrome without an extension, there is no supported way to do that for
   passwords, and the plan should say so publicly. If it is "Safari and native
   apps work too", step 1 delivers it.
2. **Will you set up the Apple Developer account,** under which legal entity, and
   who holds the Developer ID key? Nothing here moves until then (§Hard
   requirements, and A7).
3. **The identity store: on by default (scoped) or opt-in?** It is the difference
   between inline QuickType suggestions and "open the picker each time".
4. **Raise the appex floor to macOS 14** (passkeys, current API) while the app
   stays at 11? Or raise the app too?
5. **Should Mortise run as a login item or menu-bar resident** so AutoFill always
   has something to talk to?
6. **Passkeys:** are they worth a crypto-spec amendment (P-256) now? They are the
   one place native capture actually works.
7. **Quick Access typing (3b):** is a weaker, Accessibility-derived origin
   acceptable for an opt-in feature, given A5 is the reason the extension exists?
   Copy-only Quick Access avoids the question.
8. **Mac App Store, ever?** If yes, the main app must be sandboxed, and that
   rules out 3b and reshapes the native-messaging install.
9. **Which document is right about local metadata,** threat-model §1 ("plaintext
   by design") or crypto-spec §4 (sealed)? The identity-store row has to go in
   whichever is true.

## Not verified (test before relying on)

- Whether macOS Safari offers our picker when we publish no identities (decides
  §A.6 option 2).
- Chrome's macOS passkey sheet listing third-party providers in practice;
  Firefox with third-party providers.
- `AXValue` behaviour of secure fields on macOS (AppKit, WebKit, Chromium);
  whether setting it works.
- Whether synthetic keystrokes or ⌘V are dropped under another process's Secure
  Event Input.
- Encryption at rest of `ASCredentialIdentityStore`.
- A pre-signed appex surviving Tauri's bundler, notarization and PlugInKit
  registration.
- Launching the main app from a credential-provider appex via `NSWorkspace`.
- `LOCAL_PEERTOKEN` on unix sockets on our minimum macOS.
- Any macOS save-password API in a future release. Apple does not announce
  absences; re-check each WWDC.

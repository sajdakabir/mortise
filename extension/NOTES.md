# Why this extension is shaped the way it is

## Capture and filling

`capture.js` runs on permitted HTTP(S) pages, including frames. It detects
login forms, offers inline filling, and reads submitted credential fields.
This requires broad host permissions; `activeTab` alone cannot provide capture.
The desktop app saves new captures while unlocked and shows a toast. The
extension does not hold the vault and does not send passwords to a cloud API.
Filling requires a user action and targets the exact browser document.

## Browser targets

Chrome and Dia use the MV3 service worker in `manifest.json`. Firefox uses the
same source with the module event-page configuration in `manifest.firefox.json`.
The Firefox package requires 153+ for document IDs and omits the Chromium-only
lifecycle check only when the browser identifies itself as Firefox. It still
checks the current frame's document ID, URL and error state and injects only
by document ID; it never falls back to frame IDs.

Firefox native messaging uses `allowed_extensions` and the stable add-on ID
`mortise@mortise.app`. Chrome/Dia use `allowed_origins`. Setup stays in the app;
no extension can pair without explicit approval there.

## The origin comes from the browser, never the page

This is the single most important line in the extension:

```js
const origin = new URL(tab.url).origin;   // from chrome.tabs, not the page
```

That example covers the popup. For content scripts, use the browser-supplied
sender frame origin/URL, not the enclosing tab URL. If a content script reported
its own origin, a hostile page could claim to be `github.com` and the vault
would believe it. Everything in `mortise-vault::origin` is pointless if the
origin is attacker-controlled by the time it arrives.

## A credential goes to one document, checked twice

A fill asks the vault for a credential matched against origin X, and that
takes a round trip — long enough for the page to navigate. A frame keeps its
id when it navigates, so "inject into frame 4" can land on a different site
than the one the vault matched. The fill is therefore pinned to a *document*:
`sender.documentId` for the inline button, the main frame's current document
for the popup. Just before injecting, `webNavigation.getFrame` is asked again
whether that document is still live and still on X, and the injection targets
`documentIds` so the browser itself refuses if it was replaced in between.
Anything else answers `page_changed` and nothing is filled.

`webNavigation` costs no extra install warning: `<all_urls>` already covers it.

## The proof must match the Rust exactly

`proof.js` reimplements `mortise_app_lib::browser::protocol::proof_payload`.
Length-prefixed fields, big-endian `u32`, in a fixed order. If the two ever
drift, every request fails closed — annoying, but the safe direction.

## Tests

End-to-end, in a real Chromium with this directory loaded unpacked. No
desktop app is needed: `test/e2e/support/stub-host.mjs` stands in for
mortise-proxy and the app, and the browser spawns it through ordinary native
messaging, via a host manifest written into the throwaway test profile. The
stub checks every proof the way the app does, so a proof regression fails here
rather than passing against a lenient fake.

```sh
cd extension
npm install
npm run test:setup   # once: downloads Playwright's Chromium
npm test             # or: npx playwright test fill.spec.js --headed
```

Pages in `test/e2e/pages` are served from one local server under several
hostnames (`*.test` all resolve to 127.0.0.1), so `login.test` embedding
`idp.test` is a genuinely cross-origin iframe. Fixtures cover a plain login,
a username-then-password flow, a cross-origin iframe, a late-rendering
single-page app, a form in shadow DOM and a change-password form.

Tests for behavior that does not work yet retain `test.fixme` comments — popup
filling of cross-origin iframes and shadow DOM. Multi-step retained usernames
and marked change-password capture now have enabled regression cases. Fixing one means
deleting its `.fixme`. Failures keep a trace: `npx playwright show-trace
test-results/<test>/trace.zip`.

Two things that look odd and are deliberate:

- **The popup is the real toolbar popup**, opened with `chrome.action.openPopup()`
  and reached over a second CDP connection, because Playwright does not
  surface action popups. Opening `popup.html` in a tab would make the popup
  its own active tab and its own sender — a different code path.
- **Tests run one at a time.** When two test workers launch Chromium at once,
  the extension's service worker can come up paused, without its `chrome`
  bindings, and every evaluate against it hangs.

Run `npm run test:unit` for the Node suites, including Firefox-shaped API
responses and package checks. These checks do not install browsers or claim
interactive coverage. The existing app CI is unchanged. See [manual checks](../docs/browser-testing.md) for Chrome, Dia and
Firefox. `tools/package.sh` packages from an allowlist, so test files never ship.

# Why this extension is shaped the way it is

## No always-on content script

Most password managers inject a content script into every page to watch for
login forms. That buys inline autofill at the cost of running code on every
page you visit, with access to every page's DOM.

This one injects nothing until you pick a credential. The flow is: click the
toolbar icon (or ⌘⇧L), see what matches this site, click one, and only then is
a script injected into that one tab to perform the fill.

The cost is a click. What it buys:

- **`activeTab` instead of host permissions.** The extension cannot read any
  page until you invoke it on that page, and the install prompt says so. An
  extension with `<all_urls>` can read everything, forever.
- **No background credential harvesting.** There is no code running on page
  load that could be tricked into filling a hidden form in an invisible iframe,
  which is a real technique against managers that fill automatically.
- **Far less to audit.** The injected function is a dozen lines and runs once.

Inline affordances can come later if the click proves annoying, but they should
be an addition people opt into rather than the default.

## The origin comes from the browser, never the page

This is the single most important line in the extension:

```js
const origin = new URL(tab.url).origin;   // from chrome.tabs, not the page
```

The page cannot influence `tab.url`. If the content script reported its own
origin instead, a hostile page could claim to be `github.com` and the vault
would believe it. Everything in `mortise-vault::origin` is pointless if the
origin is attacker-controlled by the time it arrives.

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

Tests for behaviour that does not work yet are `test.fixme` with a comment
saying what is wrong and what should happen — multi-step username, the popup
filling an iframe, shadow DOM, change-password capture. Fixing one means
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

There is no PR workflow in `.github/workflows` yet, so nothing runs these
automatically; run them before sending a change to anything in this directory.
`tools/package.sh` packages from an allowlist, so none of this ships.

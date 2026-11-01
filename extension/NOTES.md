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

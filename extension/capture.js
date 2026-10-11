/**
 * Notices a password being submitted, so the app can offer to save it.
 *
 * This is the only code in the extension that runs without being invoked, and
 * it is the reason the manifest asks for `<all_urls>`. That is a real cost —
 * see NOTES.md — so the script is kept to the smallest thing that can do the
 * job, and the limits below are the point of the file rather than details of
 * it:
 *
 *   - It reads `input[type="password"]` and the one field next to it. Nothing
 *     else on the page is ever touched: not the text, not other inputs, not
 *     cookies, not storage.
 *   - It sends nothing unless a password field actually had a value at the
 *     moment of submission.
 *   - It never saves anything. The app decides whether to ask, and a human
 *     clicks. The most this script can achieve is a prompt.
 *   - It reports no origin. The service worker takes that from `sender.tab`,
 *     because a page can say anything and the origin is what every lookalike
 *     check depends on.
 */

/**
 * Diagnostics, off unless asked for.
 *
 * A capture script that logs nothing is impossible to support: "it did not
 * save my password" has half a dozen causes and no way to tell them apart.
 * A script that logs by default is noise on every page the user visits, and
 * one careless line away from printing a password into the console.
 *
 * So: opt-in, and it reports only *whether* a field was found, never a value.
 * Turn on from the service worker console with
 *   chrome.storage.local.set({ debug: true })
 */
let debug = false;
try {
  // `?.then` matters: if storage were unavailable the optional chain yields
  // undefined, and calling .then on it would throw at load and take the whole
  // script — and therefore every capture — down silently.
  chrome.storage?.local
    ?.get("debug")
    ?.then((v) => {
      debug = Boolean(v?.debug);
      log("capture armed on", location.origin);
    })
    ?.catch(() => {});
} catch {
  // Nothing to do. Diagnostics are a convenience; capture must still work.
}

function log(...parts) {
  if (debug) console.log("TruePassword:", ...parts);
}

/** Visible, enabled, and actually fillable. */
function usable(el) {
  if (el.disabled || el.type === "hidden") return false;
  const rect = el.getBoundingClientRect();
  return rect.width > 0 && rect.height > 0;
}

/**
 * The username that goes with this password field.
 *
 * Same rule the fill path uses: the text-like field immediately before the
 * password beats any guess based on name or id attributes, because markup
 * conventions vary far more than visual order does.
 */
function usernameFor(passwordField) {
  const scope = passwordField.form ?? document;
  const candidates = [...scope.querySelectorAll("input")].filter(
    (el) =>
      usable(el) &&
      ["text", "email", "tel", ""].includes(el.type) &&
      el !== passwordField,
  );
  const field =
    candidates
      .reverse()
      .find(
        (el) =>
          el.compareDocumentPosition(passwordField) &
          Node.DOCUMENT_POSITION_FOLLOWING,
      ) ?? candidates[0];
  return field?.value?.trim() || null;
}

/** Read the credential out of a scope, or null if there is nothing to save. */
function credentialIn(scope) {
  const passwordField = [...scope.querySelectorAll('input[type="password"]')].find(
    (el) => usable(el) && el.value,
  );
  if (!passwordField) return null;
  return {
    username: usernameFor(passwordField),
    password: passwordField.value,
  };
}

function offer(credential, why) {
  if (!credential) {
    log(why, "- no filled password field, nothing to offer");
    return;
  }
  log(why, "- offering a credential", credential.username ? "with" : "without", "a username");
  try {
    chrome.runtime.sendMessage({ command: "capture", ...credential });
  } catch {
    // The service worker can be asleep or the extension mid-reload. A missed
    // capture is a prompt the user does not get; it is never a broken page,
    // so there is nothing to report and nothing to retry.
  }
}

// A real form submit. The reliable case, and the cheap one.
document.addEventListener(
  "submit",
  (event) => offer(credentialIn(event.target), "submit"),
  true,
);

/**
 * Sign-in buttons that are not submits.
 *
 * Plenty of sign-in forms are a div and a click handler, so listening only for
 * `submit` misses them. Reading on click is the trade: it fires more often,
 * but still reads nothing unless a filled password field is present.
 */
document.addEventListener(
  "click",
  (event) => {
    const el = event.target instanceof Element ? event.target.closest("button, [role=button], input[type=submit]") : null;
    if (!el) return;
    // Already covered by the submit listener.
    if (el.type === "submit" && el.form) return;
    offer(credentialIn(document), "click");
  },
  true,
);

/**
 * Enter inside a password field, which submits many forms without a click.
 */
document.addEventListener(
  "keydown",
  (event) => {
    if (event.key !== "Enter") return;
    const el = event.target;
    if (!(el instanceof HTMLInputElement) || el.type !== "password") return;
    offer(credentialIn(el.form ?? document), "enter");
  },
  true,
);

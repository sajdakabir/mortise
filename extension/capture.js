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
  if (debug) console.log("Mortise:", ...parts);
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

/**
 * The last password offered, and when.
 *
 * One sign-in trips several of the listeners below — a click on the button is
 * also a submit, and Enter is both. Worse, they see different scopes: the form
 * for a submit, the whole document for a click, so one can find a username
 * field the other cannot. The app deduplicates on name *and* username, so two
 * offers that disagree about the username look like two different logins and
 * both get saved. That is exactly what happened on x.com.
 *
 * Keyed on the password alone: the same password submitted twice within
 * seconds is the same sign-in, whatever the listeners made of the surrounding
 * markup.
 */
let lastOffered = { password: null, at: 0 };
const REOFFER_AFTER_MS = 10_000;

function offer(credential, why) {
  if (!credential) {
    log(why, "- no filled password field, nothing to offer");
    return;
  }

  const now = Date.now();
  if (
    credential.password === lastOffered.password &&
    now - lastOffered.at < REOFFER_AFTER_MS
  ) {
    log(why, "- same credential already offered, skipping");
    return;
  }
  lastOffered = { password: credential.password, at: now };

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

/**
 * Telling the user a saved login exists, without making them guess.
 *
 * Fill stays user-initiated: nothing is written into a field until a click on
 * a control attached to a password box the user can see. That is deliberate.
 * Managers that fill on page load can be tricked into filling a hidden form
 * in an invisible iframe, and the whole point of requiring a gesture is that
 * an invisible field gets no gesture.
 *
 * What was wrong before was not the gesture, it was that nothing on screen
 * said there was anything to click. So: a badge on the toolbar icon, and a
 * small button on the field itself.
 */

/** Shadow DOM so the host page's CSS cannot restyle or hide the button. */
function mountButton(field, items) {
  if (field.dataset.mortiseMounted) return;
  field.dataset.mortiseMounted = "1";

  const host = document.createElement("div");
  host.style.cssText = "position:absolute;z-index:2147483646;";
  const root = host.attachShadow({ mode: "closed" });

  const button = document.createElement("button");
  button.type = "button";
  button.textContent = items.length === 1 ? "Fill" : `Fill (${items.length})`;
  button.title =
    items.length === 1
      ? `Mortise: fill ${items[0].username ?? items[0].title}`
      : "Mortise: choose a saved login";
  button.style.cssText = [
    "font:600 11px -apple-system,system-ui,sans-serif",
    "padding:3px 8px",
    "border:0",
    "border-radius:5px",
    "background:#e8eaf0",
    "color:#15171d",
    "cursor:pointer",
    "box-shadow:0 1px 4px rgba(0,0,0,.35)",
  ].join(";");

  // More than one match is a choice, and a choice belongs in the popup where
  // there is room to show which account is which.
  button.addEventListener("click", (event) => {
    event.preventDefault();
    event.stopPropagation();
    button.textContent = "…";
    chrome.runtime.sendMessage(
      items.length === 1 ? { command: "fill", itemId: items[0].item_id } : { command: "openPopup" },
      (response) => {
        button.textContent =
          response?.type === "filled" ? "Filled" : items.length === 1 ? "Fill" : `Fill (${items.length})`;
        if (response?.type === "filled") setTimeout(() => host.remove(), 1200);
      },
    );
  });

  root.appendChild(button);
  document.body.appendChild(host);

  // Parked just inside the right-hand edge of the field, and kept there:
  // login forms move as validation messages appear and layouts settle.
  const place = () => {
    if (!field.isConnected) {
      host.remove();
      return;
    }
    const r = field.getBoundingClientRect();
    host.style.top = `${window.scrollY + r.top + (r.height - 20) / 2}px`;
    host.style.left = `${window.scrollX + r.right - 8 - button.offsetWidth}px`;
  };
  place();
  window.addEventListener("scroll", place, { passive: true });
  window.addEventListener("resize", place, { passive: true });
  const tick = setInterval(() => {
    place();
    if (!field.isConnected) clearInterval(tick);
  }, 500);
}

/// Origins already asked about. One answer per page is enough: the vault's
/// contents do not change while a login form sits on screen, and each ask is
/// a round trip through the native host.
let announced = false;

function announce() {
  if (announced) return;
  const field = [...document.querySelectorAll('input[type="password"]')].find(usable);
  if (!field) return;

  announced = true;
  chrome.runtime.sendMessage({ command: "pageHasLogin" }, (response) => {
    const items = response?.items ?? [];
    log("page has a login form,", items.length, "saved match(es)");
    if (items.length) mountButton(field, items);
  });
}

// Login forms are routinely rendered after load, and a multi-step sign-in
// only shows its password field on the second screen, so one check at load
// would miss most of them.
//
// Coalesced: a busy page mutates hundreds of times a second and `announce`
// is a native-messaging round trip, not a DOM read.
let scheduled = 0;
const observer = new MutationObserver(() => {
  if (announced) {
    observer.disconnect();
    return;
  }
  clearTimeout(scheduled);
  scheduled = setTimeout(announce, 300);
});
observer.observe(document.documentElement, { childList: true, subtree: true });
announce();

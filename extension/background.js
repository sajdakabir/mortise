/**
 * Service worker: owns the native messaging connection and the association key.
 *
 * The popup never talks to the native host directly. Everything funnels through
 * here, so there is one place that knows the key and one place that decides
 * which origin a request is for.
 */

import { computeProof } from "./proof.js";

const HOST = "com.mortise.proxy";

/** One request, one connection. Mirrors how the proxy behaves on its side. */
function sendNative(message) {
  return new Promise((resolve) => {
    let settled = false;
    const done = (value) => {
      if (!settled) {
        settled = true;
        resolve(value);
      }
    };

    try {
      chrome.runtime.sendNativeMessage(HOST, message, (response) => {
        if (chrome.runtime.lastError) {
          // The usual cause is the host manifest not being installed, which is
          // a setup problem rather than a bug, so say so plainly.
          done({
            type: "error",
            code: "no_host",
            message:
              "Could not reach Mortise. Check that the app is running and the browser connector is installed.",
          });
          return;
        }
        done(response);
      });
    } catch (e) {
      done({ type: "error", code: "no_host", message: String(e) });
    }

    // sendNativeMessage can hang if the host spawns but never replies.
    setTimeout(
      () => done({ type: "error", code: "timeout", message: "Mortise did not respond." }),
      10_000,
    );
  });
}

async function association() {
  const stored = await chrome.storage.local.get(["associationId", "associationKey"]);
  if (!stored.associationId || !stored.associationKey) return null;
  return { id: stored.associationId, key: stored.associationKey };
}

/** Send a request that needs a proof, computing it from the stored key. */
async function sendSigned(partial) {
  const assoc = await association();
  if (!assoc) {
    return { type: "error", code: "not_associated", message: "This browser is not paired yet." };
  }

  const request = { ...partial, id: assoc.id };
  const proof = await computeProof(assoc.key, request);
  return sendNative({ ...request, proof });
}

const handlers = {
  async status() {
    const response = await sendNative({ type: "status" });
    const assoc = await association();
    return { ...response, hasKey: assoc !== null };
  },

  async associate() {
    // The app issues a token with its first "needs approval" reply and
    // releases the key only to whoever comes back with it. Holding it across
    // polls is what makes the user's click approve *this* browser rather than
    // whichever process asks next.
    const { pairingToken } = await chrome.storage.local.get("pairingToken");
    const response = await sendNative({
      type: "associate",
      client_name: browserName(),
      request_token: pairingToken ?? null,
    });

    if (response?.type === "approval_required" && response.request_token) {
      await chrome.storage.local.set({ pairingToken: response.request_token });
    }
    if (response?.type === "associated") {
      await chrome.storage.local.set({
        associationId: response.id,
        associationKey: response.key,
      });
      // Single use: a spent token should not sit in storage.
      await chrome.storage.local.remove("pairingToken");
    }
    return response;
  },

  /// Several matches is a choice, and the popup is where there is room to
  /// show which account is which. Opening it from a page click needs no new
  /// permission — the gesture came from the user.
  async openPopup() {
    try {
      await chrome.action.openPopup();
      return { type: "ok" };
    } catch {
      // Not available on every Chromium build. The toolbar badge still says
      // there is something there, so the user can open it themselves.
      return { type: "error", code: "no_popup", message: "Open Mortise from the toolbar." };
    }
  },

  async unpair() {
    await chrome.storage.local.remove(["associationId", "associationKey", "pairingToken"]);
    return { type: "ok" };
  },

  /**
   * Credentials for the active tab.
   *
   * The origin comes from `chrome.tabs`, never from the page. This is the
   * line everything else depends on: if a page could name its own origin,
   * every lookalike check in the vault would be pointless.
   */
  async logins() {
    const origin = await activeOrigin();
    if (!origin) {
      return { type: "error", code: "bad_origin", message: "This page cannot be filled." };
    }
    const response = await sendSigned({ type: "logins", origin });
    // Hand the origin back so the popup can show which site it matched
    // against. It is the browser's value, not the page's.
    return response?.type === "logins" ? { ...response, origin } : response;
  },

  /**
   * A page reporting that it has a login form.
   *
   * Asking from the page rather than on every tab update means the native
   * host is only consulted for pages that could actually be filled, instead
   * of once for every page the user visits.
   *
   * The reply drives both the toolbar badge and the inline button, so the
   * user can see a saved login exists without having to click to find out —
   * which was the whole problem with an invoke-only extension.
   */
  async pageHasLogin(_message, sender) {
    const origin = senderOrigin(sender);
    if (!origin) return { type: "logins", items: [] };

    const response = await sendSigned({ type: "logins", origin });
    const items = response?.type === "logins" ? response.items : [];

    if (sender?.tab?.id != null) {
      chrome.action.setBadgeText({
        tabId: sender.tab.id,
        text: items.length ? String(items.length) : "",
      });
      // Neutral, to match the app: nothing else in the product is coloured.
      chrome.action.setBadgeBackgroundColor({ color: "#6b7280" });
    }
    return { type: "logins", items };
  },

  /**
   * A login the content script saw submitted.
   *
   * The origin is the *frame's*, from `sender`, not anything the script
   * reported. The content script runs inside the page, so treating its word as
   * authoritative would hand origin control to whatever is on that page — the
   * exact mistake everything else here is shaped to avoid. It is the frame's
   * rather than the tab's because a subframe is a different site, and
   * attributing its message to the embedding page was that same mistake by
   * another route.
   *
   * The app decides whether to prompt and the user decides whether to save.
   * Nothing is written to the vault by this path alone.
   */
  async capture({ username, password }, sender) {
    if (!password) return { type: "ok" };
    const origin = senderOrigin(sender);
    if (!origin) return { type: "ok" };

    const response = await sendSigned({
      type: "capture",
      origin,
      username: username ?? null,
      password,
    });

    // Same rule as the content script: opt-in, and the outcome only. The
    // response carries no secret, so this is safe to print.
    const { debug } = await chrome.storage.local.get("debug");
    if (debug) {
      console.log("Mortise: capture for", origin, "->", JSON.stringify(response));
    }

    // A badge, because the prompt opens in the app window and the user is
    // looking at the browser. Cleared as soon as they deal with it.
    if (response?.type === "captured" && response.queued) {
      chrome.action.setBadgeText({ text: "1" });
      chrome.action.setBadgeBackgroundColor({ color: "#9ece6a" });
    }
    return response;
  },

  async fill({ itemId }, sender) {
    // Two callers with different notions of "here". A content script speaks
    // for its own frame; the popup speaks for the active tab's main frame.
    // The credential has to go back to whichever one was authorised, so the
    // origin and the injection target are decided together — and pinned to
    // one document, not to a frame. A frame keeps its id when it navigates,
    // and the round trip to the vault is plenty of time for it to do so.
    const target = await fillTarget(sender);
    if (!target) {
      return { type: "error", code: "bad_origin", message: "This page cannot be filled." };
    }

    const response = await sendSigned({
      type: "credential",
      item_id: itemId,
      origin: target.origin,
    });
    if (response?.type !== "credential") return response;

    // Ask the browser again, now, what that document is and where it lives.
    // The vault matched the credential against `target.origin`; anywhere else
    // is somewhere the user never authorised, however it got there.
    if (!(await stillAt(target))) return PAGE_CHANGED;

    // Targeted by document rather than frame, so the browser itself refuses
    // if the document is replaced between the check above and this call. A
    // document cannot change origin, which is what makes the check hold.
    let result;
    try {
      [result] = await chrome.scripting.executeScript({
        target: { tabId: target.tabId, documentIds: [target.documentId] },
        func: fillForm,
        args: [response.username ?? "", response.password],
      });
    } catch {
      return PAGE_CHANGED;
    }

    return result?.result?.filled
      ? { type: "filled" }
      : {
          type: "error",
          code: "no_form",
          message: "No password field found on this page.",
        };
  },
};

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const handler = handlers[message?.command];
  if (!handler) {
    sendResponse({ type: "error", code: "bad_request", message: "Unknown command." });
    return false;
  }
  // `sender` is the browser's account of who sent this, which is why the
  // capture handler takes it rather than trusting the message's contents.
  handler(message, sender).then(sendResponse);
  return true; // keep the channel open for the async reply
});

/// The popup clears the badge once the user has been to the app.
chrome.runtime.onMessage.addListener((message) => {
  if (message?.command === "clearBadge") chrome.action.setBadgeText({ text: "" });
});

async function activeTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

async function activeOrigin() {
  return originOf(await activeTab());
}

/**
 * The origin of the frame a content script message came from.
 *
 * `sender.tab.url` is the *tab's* URL, which is the top-level document.
 * Content scripts run in every frame, so attributing a subframe's message to
 * the tab would let anything embedded on a page — an ad, a widget, any
 * third-party iframe — speak with the embedding site's authority and be
 * answered with that site's credentials.
 *
 * `sender.origin` is the frame's own origin and is exactly the right value;
 * `sender.url` is the frame's URL and covers the older browsers that predate
 * it. Neither is reported by the page.
 */
function senderOrigin(sender) {
  if (sender?.origin) {
    return sender.origin.startsWith("https://") || sender.origin.startsWith("http://")
      ? sender.origin
      : null;
  }
  if (!sender?.url) return null;
  try {
    const url = new URL(sender.url);
    if (url.protocol !== "https:" && url.protocol !== "http:") return null;
    return url.origin;
  } catch {
    return null;
  }
}

/** The tab's origin, or null for pages that must never be filled. */
function originOf(tab) {
  return urlOrigin(tab?.url);
}

function urlOrigin(href) {
  if (!href) return null;
  try {
    const url = new URL(href);
    // Only real web pages. chrome://, file://, data: and extension pages are
    // either privileged or have no meaningful origin to match against.
    if (url.protocol !== "https:" && url.protocol !== "http:") return null;
    return url.origin;
  } catch {
    return null;
  }
}

const PAGE_CHANGED = {
  type: "error",
  code: "page_changed",
  message: "The page changed before Mortise could fill it. Try again.",
};

/**
 * The one document a fill is for, and the origin the vault will match.
 *
 * A content script's document is `sender.documentId`, which the browser
 * supplies alongside `sender.origin`; nothing the page says enters into it.
 * The popup speaks for the active tab's main frame, so that frame's current
 * document is looked up, and its URL has to agree with the tab's — if they
 * differ the tab is mid-navigation and "here" is not settled yet.
 */
async function fillTarget(sender) {
  if (sender?.tab != null) {
    const origin = senderOrigin(sender);
    if (!origin || sender.tab.id == null || !sender.documentId) return null;
    return {
      tabId: sender.tab.id,
      frameId: sender.frameId ?? 0,
      documentId: sender.documentId,
      origin,
    };
  }

  const tab = await activeTab();
  if (tab?.id == null) return null;
  const frame = await frameInfo({ tabId: tab.id, frameId: 0 });
  const origin = urlOrigin(frame?.url);
  if (!origin || !frame.documentId || origin !== originOf(tab)) return null;
  return { tabId: tab.id, frameId: 0, documentId: frame.documentId, origin };
}

/**
 * Whether the frame the fill is for is still showing the target document,
 * and that document is still on the origin the credential was matched
 * against — by the browser's account, read just before injection rather
 * than trusted from earlier.
 *
 * Asked by frame rather than by document so the answer is about what the
 * frame shows *now*. `documentLifecycle` additionally rules out a document
 * kept in the back/forward cache or one that is prerendering: neither is
 * something the user is looking at.
 */
async function stillAt(target) {
  const frame = await frameInfo({ tabId: target.tabId, frameId: target.frameId });
  return (
    frame?.documentId === target.documentId &&
    frame.documentLifecycle === "active" &&
    urlOrigin(frame.url) === target.origin
  );
}

/** `webNavigation.getFrame`, with "no such frame" and errors both as null. */
async function frameInfo(details) {
  try {
    return (await chrome.webNavigation.getFrame(details)) ?? null;
  } catch {
    return null;
  }
}

function browserName() {
  const ua = navigator.userAgent;
  if (ua.includes("Edg/")) return "Microsoft Edge";
  if (ua.includes("Brave")) return "Brave";
  if (ua.includes("Chrome/")) return "Google Chrome";
  return "Browser";
}

/**
 * Runs in the page. Must be self-contained — it is serialized and injected,
 * so it cannot close over anything here.
 *
 * Fills the first visible password field and the username field nearest to it,
 * then fires the events frameworks listen for. Setting `.value` alone leaves
 * React and friends unaware the field changed.
 */
function fillForm(username, password) {
  const visible = (el) => {
    const rect = el.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0 && el.type !== "hidden" && !el.disabled;
  };

  const passwordField = [...document.querySelectorAll('input[type="password"]')].find(visible);
  if (!passwordField) return { filled: false };

  const setValue = (el, value) => {
    // React tracks the previous value on the DOM node and skips the change
    // event if it matches, so write through the native setter.
    const setter = Object.getOwnPropertyDescriptor(
      window.HTMLInputElement.prototype,
      "value",
    )?.set;
    setter ? setter.call(el, value) : (el.value = value);
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  };

  if (username) {
    const form = passwordField.form ?? document;
    const candidates = [...form.querySelectorAll("input")].filter(
      (el) =>
        visible(el) &&
        ["text", "email", "tel", ""].includes(el.type) &&
        el !== passwordField,
    );
    // The field immediately before the password is the username far more often
    // than any name-attribute heuristic would guess.
    const field =
      candidates.reverse().find(
        (el) =>
          el.compareDocumentPosition(passwordField) & Node.DOCUMENT_POSITION_FOLLOWING,
      ) ?? candidates[0];
    if (field) setValue(field, username);
  }

  setValue(passwordField, password);
  passwordField.focus();
  return { filled: true };
}

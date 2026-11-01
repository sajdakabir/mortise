/**
 * The fill path's one promise: a credential matched against origin X is only
 * ever injected into the document it was matched for, and only while that
 * document is still on X.
 *
 * Runs background.js against a fake `chrome` — no browser, no app, no
 * dependencies:
 *
 *   node --test 'extension/test/unit/*.test.js'
 *
 * The fake models what matters here and nothing else: tabs hold frames, a
 * frame holds one live document at a time, navigating replaces the document
 * and keeps the frame id, and `executeScript` with `documentIds` refuses a
 * document that is no longer live — which is how Chrome behaves.
 */

import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";

// sendNative arms a 10s timeout per request. Unref'd, so a finished run exits
// at once instead of waiting out timers nobody is listening to.
const realSetTimeout = globalThis.setTimeout;
globalThis.setTimeout = (fn, ms, ...args) => {
  const timer = realSetTimeout(fn, ms, ...args);
  timer.unref?.();
  return timer;
};

let world;

function freshWorld() {
  return {
    activeTabId: 1,
    tabs: new Map(),
    documents: [],
    nextDocument: 1,
    /** Called with each native request; returns the reply. */
    native: () => ({ type: "error", code: "unexpected", message: "no native stub" }),
    nativeRequests: [],
    injections: [],
    /** Runs inside executeScript before it looks at the target. */
    beforeInject: () => {},
  };
}

/** Load `url` into a frame, replacing whatever document was there. */
function navigate(tabId, frameId, url, { lifecycle = "active" } = {}) {
  for (const doc of world.documents) {
    if (doc.tabId === tabId && doc.frameId === frameId && doc.lifecycle === "active") {
      doc.lifecycle = "gone";
    }
  }
  const doc = { documentId: `doc-${world.nextDocument++}`, tabId, frameId, url, lifecycle };
  world.documents.push(doc);
  if (frameId === 0) world.tabs.set(tabId, { id: tabId, url });
  return doc;
}

const live = (doc) => doc.lifecycle !== "gone";

globalThis.chrome = {
  runtime: {
    lastError: undefined,
    listeners: [],
    onMessage: { addListener: (fn) => chrome.runtime.listeners.push(fn) },
    sendNativeMessage(_host, message, callback) {
      world.nativeRequests.push(message);
      Promise.resolve()
        .then(() => world.native(message))
        .then(callback);
    },
  },
  storage: {
    local: {
      async get() {
        return {
          associationId: "abcdef0123456789",
          associationKey: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        };
      },
      async set() {},
      async remove() {},
    },
  },
  tabs: {
    async query() {
      const tab = world.tabs.get(world.activeTabId);
      return tab ? [{ ...tab }] : [];
    },
  },
  webNavigation: {
    // The shape Chromium returns, which has no frameId: a frame is asked
    // about by id and answers with what it is showing.
    async getFrame({ tabId, frameId, documentId }) {
      const doc =
        documentId != null
          ? world.documents.find((d) => d.documentId === documentId && live(d))
          : world.documents.findLast(
              (d) => d.tabId === tabId && d.frameId === frameId && live(d),
            );
      if (!doc || (tabId != null && doc.tabId !== tabId)) return null;
      return {
        documentId: doc.documentId,
        documentLifecycle: doc.lifecycle,
        errorOccurred: false,
        frameType: doc.frameId === 0 ? "outermost_frame" : "sub_frame",
        parentFrameId: doc.frameId === 0 ? -1 : 0,
        url: doc.url,
      };
    },
  },
  scripting: {
    async executeScript({ target, func, args }) {
      await world.beforeInject();
      assert.equal(target.frameIds, undefined, "fill must target a document, not a frame");
      assert.equal(target.documentIds?.length, 1);
      const doc = world.documents.find(
        (d) => d.documentId === target.documentIds[0] && d.tabId === target.tabId,
      );
      if (!doc || doc.lifecycle !== "active") {
        throw new Error(`No document with id ${target.documentIds[0]}`);
      }
      world.injections.push({ ...doc, func: func.name, args });
      return [{ documentId: doc.documentId, frameId: doc.frameId, result: { filled: true } }];
    },
  },
  action: {
    setBadgeText() {},
    setBadgeBackgroundColor() {},
  },
};

world = freshWorld();
await import("../../background.js");

/** Deliver a message the way the browser would, and wait for the reply. */
function send(message, sender) {
  return new Promise((resolve) => {
    const [listener] = chrome.runtime.listeners;
    listener(message, sender, resolve);
  });
}

const POPUP = { id: "mortise", url: "chrome-extension://mortise/popup.html" };

/** A content-script sender for `doc`, as Chrome builds it. */
function pageSender(doc) {
  return {
    tab: { ...world.tabs.get(doc.tabId) },
    frameId: doc.frameId,
    documentId: doc.documentId,
    origin: new URL(doc.url).origin,
    url: doc.url,
  };
}

/** A vault that knows one login, for whichever origin it is asked about. */
function vaultReplies(onCredential = () => {}) {
  return async (message) => {
    if (message.type !== "credential") return { type: "error", code: "unexpected" };
    await onCredential(message);
    return { type: "credential", username: "octocat", password: "hunter2" };
  };
}

const credentialRequests = () => world.nativeRequests.filter((r) => r.type === "credential");

beforeEach(() => {
  world = freshWorld();
});

// --- from the page --------------------------------------------------------

test("fills the exact document the request came from, matched on the frame's origin", async () => {
  navigate(1, 0, "https://news.example/article");
  const login = navigate(1, 4, "https://login.example/embed");
  world.native = vaultReplies();

  const reply = await send({ command: "fill", itemId: "aa" }, pageSender(login));

  assert.deepEqual(reply, { type: "filled" });
  assert.deepEqual(
    credentialRequests().map((r) => r.origin),
    ["https://login.example"],
    "the vault is asked about the frame, never the embedding tab",
  );
  assert.equal(world.injections.length, 1);
  assert.equal(world.injections[0].documentId, login.documentId);
  assert.deepEqual(world.injections[0].args, ["octocat", "hunter2"]);
});

test("refuses when the frame navigates to another origin during the vault lookup", async () => {
  navigate(1, 0, "https://news.example/");
  const login = navigate(1, 4, "https://login.example/embed");
  world.native = vaultReplies(() => navigate(1, 4, "https://evil.example/"));

  const reply = await send({ command: "fill", itemId: "aa" }, pageSender(login));

  assert.equal(reply.code, "page_changed");
  assert.deepEqual(world.injections, []);
});

test("refuses when the main frame navigates to another origin during the lookup", async () => {
  const login = navigate(1, 0, "https://login.example/");
  world.native = vaultReplies(() => navigate(1, 0, "https://evil.example/"));

  const reply = await send({ command: "fill", itemId: "aa" }, pageSender(login));

  assert.equal(reply.code, "page_changed");
  assert.deepEqual(world.injections, []);
});

test("refuses a replacement document even on the same origin", async () => {
  // Stricter than the origin rule needs, and deliberately so: the user asked
  // to fill the page they were looking at, and a reload is a different page.
  const login = navigate(1, 0, "https://login.example/step1");
  world.native = vaultReplies(() => navigate(1, 0, "https://login.example/step2"));

  const reply = await send({ command: "fill", itemId: "aa" }, pageSender(login));

  assert.equal(reply.code, "page_changed");
  assert.deepEqual(world.injections, []);
});

test("refuses a document that has gone into the back/forward cache", async () => {
  const login = navigate(1, 0, "https://login.example/");
  world.native = vaultReplies(() => {
    login.lifecycle = "cached";
  });

  const reply = await send({ command: "fill", itemId: "aa" }, pageSender(login));

  assert.equal(reply.code, "page_changed");
  assert.deepEqual(world.injections, []);
});

test("refuses if the browser reports the document on a different origin", async () => {
  // Cannot happen to a real document, which keeps its origin for life. The
  // check is there so that an assumption about the browser is not the only
  // thing standing between a credential and the wrong site.
  const login = navigate(1, 0, "https://login.example/");
  world.native = vaultReplies(() => {
    login.url = "https://evil.example/";
  });

  const reply = await send({ command: "fill", itemId: "aa" }, pageSender(login));

  assert.equal(reply.code, "page_changed");
  assert.deepEqual(world.injections, []);
});

test("answers, rather than hanging, when the document goes between the check and injection", async () => {
  const login = navigate(1, 0, "https://login.example/");
  world.native = vaultReplies();
  world.beforeInject = () => navigate(1, 0, "https://evil.example/");

  const reply = await send({ command: "fill", itemId: "aa" }, pageSender(login));

  assert.equal(reply.code, "page_changed");
  assert.deepEqual(world.injections, []);
});

test("a page request without a documentId is refused before the vault is asked", async () => {
  const login = navigate(1, 0, "https://login.example/");
  world.native = vaultReplies();
  const sender = pageSender(login);
  delete sender.documentId;

  const reply = await send({ command: "fill", itemId: "aa" }, sender);

  assert.equal(reply.code, "bad_origin");
  assert.deepEqual(credentialRequests(), []);
  assert.deepEqual(world.injections, []);
});

// --- from the popup -------------------------------------------------------

test("popup: fills the active tab's main-frame document", async () => {
  const page = navigate(1, 0, "https://login.example/signin");
  navigate(1, 7, "https://ads.example/frame");
  world.native = vaultReplies();

  const reply = await send({ command: "fill", itemId: "aa" }, POPUP);

  assert.deepEqual(reply, { type: "filled" });
  assert.deepEqual(
    credentialRequests().map((r) => r.origin),
    ["https://login.example"],
  );
  assert.equal(world.injections.length, 1);
  assert.equal(world.injections[0].documentId, page.documentId);
});

test("popup: refuses when the tab navigates during the lookup", async () => {
  navigate(1, 0, "https://login.example/signin");
  world.native = vaultReplies(() => navigate(1, 0, "https://evil.example/"));

  const reply = await send({ command: "fill", itemId: "aa" }, POPUP);

  assert.equal(reply.code, "page_changed");
  assert.deepEqual(world.injections, []);
});

test("popup: refuses when the tab and its main frame disagree about where it is", async () => {
  navigate(1, 0, "https://login.example/signin");
  // The tab already reports the next page; the frame has not committed it.
  world.tabs.set(1, { id: 1, url: "https://evil.example/" });
  world.native = vaultReplies();

  const reply = await send({ command: "fill", itemId: "aa" }, POPUP);

  assert.equal(reply.code, "bad_origin");
  assert.deepEqual(credentialRequests(), []);
  assert.deepEqual(world.injections, []);
});

test("popup: refuses pages that are not http(s)", async () => {
  navigate(1, 0, "chrome://settings/");
  world.native = vaultReplies();

  const reply = await send({ command: "fill", itemId: "aa" }, POPUP);

  assert.equal(reply.code, "bad_origin");
  assert.deepEqual(credentialRequests(), []);
});

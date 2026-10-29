/**
 * Playwright fixtures: a real Chromium with the unpacked extension loaded, a
 * stub native host standing in for the app, and a local site serving the
 * pages in ../pages under several hostnames.
 *
 * No desktop app is involved. The browser spawns stub-host.mjs through the
 * ordinary native-messaging route, found via a host manifest written into the
 * test profile's own NativeMessagingHosts directory — so nothing is installed
 * on the machine and nothing outside the temp profile is touched.
 *
 * Hostnames: every *.test name resolves to 127.0.0.1, so login.test and
 * idp.test are genuinely different origins on the same local server, which is
 * what the cross-origin iframe cases need.
 */

import { test as base, expect, chromium } from "@playwright/test";
import { createServer } from "node:http";
import { mkdtemp, readFile, rm, writeFile, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, extname, join, normalize, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const EXTENSION = resolve(HERE, "../../..");
const PAGES = resolve(HERE, "../pages");
const STUB_HOST = join(HERE, "stub-host.mjs");

const ASSOCIATION = {
  id: "e2e0000000000001",
  key: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
};

/** What the stub "app" knows, unless a test says otherwise. */
const defaultVault = () => ({
  paired: true,
  unlocked: true,
  // Whether an associate request is approved straight away.
  approve: true,
  association: ASSOCIATION,
  // { item_id, title, username, password, origin }
  logins: [],
  // Per request type, how long the stub sits on its reply.
  delayMs: {},
});

const TYPES = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
};

/** Static pages, plus a POST sink so a real form submit has somewhere to go. */
function startSite() {
  const server = createServer(async (req, res) => {
    const path = new URL(req.url, "http://x").pathname;
    if (req.method === "POST") {
      req.resume();
      req.on("end", () => {
        res.writeHead(200, { "content-type": TYPES[".html"] });
        res.end("<!doctype html><title>Signed in</title><h1>Signed in</h1>");
      });
      return;
    }
    const file = normalize(join(PAGES, path === "/" ? "index.html" : path));
    if (!file.startsWith(PAGES)) {
      res.writeHead(403).end();
      return;
    }
    try {
      const body = await readFile(file);
      res.writeHead(200, { "content-type": TYPES[extname(file)] ?? "application/octet-stream" });
      res.end(body);
    } catch {
      res.writeHead(404).end("not found");
    }
  });
  return new Promise((ready) => {
    server.listen(0, "127.0.0.1", () => ready(server));
  });
}

export const test = base.extend({
  /** The local site. `site.url("login.test", "/login.html")`. */
  site: [
    async ({}, use) => {
      const server = await startSite();
      const { port } = server.address();
      await use({
        port,
        origin: (host) => `http://${host}:${port}`,
        url: (host, path) => `http://${host}:${port}${path}`,
      });
      await new Promise((done) => server.close(done));
    },
    { scope: "worker" },
  ],

  /**
   * The stub app's state for this test. `await stub.vault({ logins: [...] })`
   * before the extension asks; `await stub.requests("capture")` after.
   */
  stub: async ({}, use) => {
    const dir = await mkdtemp(join(tmpdir(), "mortise-stub-"));
    let vault = defaultVault();
    const save = () => writeFile(join(dir, "vault.json"), JSON.stringify(vault));
    await save();
    await writeFile(join(dir, "requests.jsonl"), "");

    await use({
      dir,
      async vault(changes) {
        vault = { ...vault, ...changes };
        await save();
      },
      async requests(type) {
        const lines = (await readFile(join(dir, "requests.jsonl"), "utf8")).split("\n");
        return lines
          .filter(Boolean)
          .map((line) => JSON.parse(line))
          .filter((r) => !type || r.type === type);
      },
    });
    await rm(dir, { recursive: true, force: true });
  },

  /** Paired unless a test asks for a fresh browser with `test.use({ paired: false })`. */
  paired: [true, { option: true }],

  context: async ({ stub, paired }, use) => {
    const profile = await mkdtemp(join(tmpdir(), "mortise-profile-"));
    const context = await chromium.launchPersistentContext(profile, {
      // The full Chromium build, not the headless shell, which cannot load
      // extensions.
      channel: "chromium",
      args: [
        `--disable-extensions-except=${EXTENSION}`,
        `--load-extension=${EXTENSION}`,
        "--host-resolver-rules=MAP *.test 127.0.0.1",
        // For reaching the toolbar popup; see openPopup.
        "--remote-debugging-port=0",
      ],
      // Inherited by the native host Chrome spawns, which is how the stub
      // finds this test's state.
      env: { ...process.env, MORTISE_STUB_STATE: stub.dir },
    });

    let [worker] = context.serviceWorkers();
    worker ??= await context.waitForEvent("serviceworker");
    const extensionId = new URL(worker.url()).host;

    // Read by Chrome on every sendNativeMessage, so writing it after launch is
    // fine — and it has to be after, because it must name the extension id.
    await mkdir(join(profile, "NativeMessagingHosts"), { recursive: true });
    await writeFile(
      join(profile, "NativeMessagingHosts", "com.mortise.proxy.json"),
      JSON.stringify({
        name: "com.mortise.proxy",
        description: "Mortise e2e stub",
        path: STUB_HOST,
        type: "stdio",
        allowed_origins: [`chrome-extension://${extensionId}/`],
      }),
    );

    if (paired) {
      await worker.evaluate(
        (a) => chrome.storage.local.set({ associationId: a.id, associationKey: a.key }),
        ASSOCIATION,
      );
    }

    context.extension = { id: extensionId, worker, profile };
    await use(context);
    await context.close();
    await rm(profile, { recursive: true, force: true });
  },

  extension: async ({ context }, use) => {
    const { id, worker, profile } = context.extension;
    let cdp;
    await use({
      id,
      worker,

      /** The toolbar badge text for the tab showing `page`. */
      async badge(page) {
        return worker.evaluate(async (url) => {
          const tabs = await chrome.tabs.query({});
          const tab = tabs.find((t) => t.url === url);
          return tab ? chrome.action.getBadgeText({ tabId: tab.id }) : null;
        }, page.url());
      },

      /**
       * The real toolbar popup, opened over `page` the way a click on the
       * icon would. Opening popup.html in a tab instead would make the popup
       * its own active tab — and its own sender — which is a different code
       * path from the one users hit.
       *
       * Playwright does not surface action popups on the launching
       * connection, so they are reached through a second, plain CDP one.
       */
      async openPopup(page) {
        await page.bringToFront();
        await worker.evaluate(() => chrome.action.openPopup());
        cdp ??= await chromium.connectOverCDP(`http://127.0.0.1:${await devtoolsPort(profile)}`);
        const url = `chrome-extension://${id}/popup.html`;
        let popup;
        await expect
          .poll(() => (popup = cdp.contexts().flatMap((c) => c.pages()).find((p) => p.url() === url)))
          .toBeTruthy();
        await popup.waitForLoadState();
        return popup;
      },
    });
    await cdp?.close();
  },
});

/** The port Chrome picked for --remote-debugging-port=0. */
async function devtoolsPort(profile) {
  return (await readFile(join(profile, "DevToolsActivePort"), "utf8")).split("\n")[0];
}

/**
 * The inline Fill button for a field in `frame`.
 *
 * It lives in a closed shadow root, so its text cannot be read from outside;
 * the host element is found by the z-index capture.js gives it, and a click on
 * the host lands on the button inside it.
 */
export function inlineButton(frame) {
  return frame.locator('div[style*="z-index: 2147483646"]');
}

/** A login as the stub stores it. */
export function login(origin, overrides = {}) {
  return {
    item_id: "0102030405060708090a0b0c0d0e0f10",
    title: "Example",
    username: "octocat",
    password: "correct horse battery staple",
    origin,
    ...overrides,
  };
}

export { expect };

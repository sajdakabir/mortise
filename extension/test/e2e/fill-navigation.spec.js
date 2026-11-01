/**
 * A credential is fetched for one origin and injected after a round trip to
 * the app. If the page navigates in between, it must not follow the page.
 *
 * The stub holds its credential reply open so the test can navigate while the
 * extension is waiting, which is the window a hostile or merely busy page
 * gets in real use.
 */

import { test, expect, inlineButton, login } from "./support/fixtures.js";

const HOLD_MS = 2000;

// FIXME: on master the fill targets a frame id, and a frame keeps its id when
// it navigates, so the credential lands in whatever the frame shows by the
// time the app answers — this test fails there with the idp.test password
// typed into other.test. Fixed by #19, which pins the fill to the document it
// was matched for; drop both fixmes when it lands.
test.fixme("a frame that navigates during the lookup is not filled", async ({
  context,
  site,
  stub,
}) => {
  await stub.vault({ logins: [login(site.origin("idp.test"))], delayMs: { credential: HOLD_MS } });
  const page = await context.newPage();
  await page.goto(
    site.url("login.test", `/iframe.html?frame=${encodeURIComponent(site.url("idp.test", "/login.html"))}`),
  );
  const frame = page.frameLocator("#frame");

  await inlineButton(frame).click();
  await expect.poll(() => stub.requests("credential")).toHaveLength(1);
  // While the app is "thinking", the frame goes somewhere else.
  await page.locator("#frame").evaluate((el, url) => (el.src = url), site.url("other.test", "/login.html"));
  await expect(frame.locator("#password")).toBeVisible();
  await expect.poll(() => frame.locator("body").evaluate(() => location.host)).toContain("other.test");

  await page.waitForTimeout(HOLD_MS + 1500);
  await expect(frame.locator("#password")).toHaveValue("");
  await expect(frame.locator("#username")).toHaveValue("");
});

// FIXME: as above (#19), for the popup, which fills the main frame.
test.fixme("a tab that navigates during a popup fill is not filled", async ({
  context,
  extension,
  site,
  stub,
}) => {
  await stub.vault({ logins: [login(site.origin("login.test"))], delayMs: { credential: HOLD_MS } });
  const page = await context.newPage();
  await page.goto(site.url("login.test", "/login.html"));

  const popup = await extension.openPopup(page);
  await popup.locator(".entry").click();
  await expect.poll(() => stub.requests("credential")).toHaveLength(1);
  await page.goto(site.url("other.test", "/login.html"));

  await page.waitForTimeout(HOLD_MS + 1500);
  await expect(page.locator("#password")).toHaveValue("");
  await expect(page.locator("#username")).toHaveValue("");
});

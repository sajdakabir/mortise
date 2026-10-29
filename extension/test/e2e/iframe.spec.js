/**
 * A sign-in form inside a cross-origin iframe.
 *
 * The frame is its own site. Everything about it — what it is offered, what
 * it is filled with, what it captures — has to be decided by the frame's
 * origin, never the embedding page's.
 */

import { test, expect, inlineButton, login } from "./support/fixtures.js";

function embed(site, framePath = "/login.html") {
  return site.url("login.test", `/iframe.html?frame=${encodeURIComponent(site.url("idp.test", framePath))}`);
}

test("the inline button in the frame fills the frame, for the frame's origin", async ({
  context,
  site,
  stub,
}) => {
  await stub.vault({ logins: [login(site.origin("idp.test"))] });
  const page = await context.newPage();
  await page.goto(embed(site));
  const frame = page.frameLocator("#frame");

  await inlineButton(frame).click();

  await expect(frame.locator("#username")).toHaveValue("octocat");
  await expect(frame.locator("#password")).toHaveValue("correct horse battery staple");
  const [credential] = await stub.requests("credential");
  expect(credential.origin).toBe(site.origin("idp.test"));
});

test("the frame is not offered the embedding site's logins", async ({ context, site, stub }) => {
  await stub.vault({ logins: [login(site.origin("login.test"))] });
  const page = await context.newPage();
  await page.goto(embed(site));

  await expect.poll(async () => (await stub.requests("logins")).length).toBe(1);
  // Asked about as itself: the embedding page has no password field, so the
  // only frame that announces is the embedded one.
  expect((await stub.requests("logins"))[0].origin).toBe(site.origin("idp.test"));
  await page.waitForTimeout(500);
  await expect(inlineButton(page.frameLocator("#frame"))).toHaveCount(0);
});

test("a login submitted in the frame is captured for the frame's origin", async ({
  context,
  site,
  stub,
}) => {
  const page = await context.newPage();
  await page.goto(embed(site));
  const frame = page.frameLocator("#frame");

  await frame.locator("#username").fill("octocat@example.com");
  await frame.locator("#password").fill("typed in a frame");
  await frame.locator("#submit").click();

  await expect.poll(() => stub.requests("capture")).toHaveLength(1);
  expect((await stub.requests("capture"))[0]).toMatchObject({
    origin: site.origin("idp.test"),
    username: "octocat@example.com",
    password: "typed in a frame",
  });
});

test("the popup on the embedding page lists the embedding page's logins", async ({
  context,
  extension,
  site,
  stub,
}) => {
  await stub.vault({
    logins: [login(site.origin("idp.test"), { title: "Identity provider" })],
  });
  const page = await context.newPage();
  await page.goto(embed(site));

  // The popup speaks for the tab's top-level page, so a login saved for the
  // frame is not listed. See the fixme below for what should happen instead.
  const popup = await extension.openPopup(page);
  await expect(popup.locator(".site")).toHaveText(site.origin("login.test"));
  await expect(popup.locator(".count")).toHaveText("0");
});

// FIXME: the popup only ever looks up and fills the top-level page, so a
// login form in a cross-origin iframe can only be filled from the inline
// button. The popup should offer the frame's logins — clearly labelled with
// the frame's origin, not the tab's — and fill that frame and only that frame.
test.fixme("the popup can fill a login form inside a cross-origin iframe", async ({
  context,
  extension,
  site,
  stub,
}) => {
  await stub.vault({ logins: [login(site.origin("idp.test"), { title: "Identity provider" })] });
  const page = await context.newPage();
  await page.goto(embed(site));
  const frame = page.frameLocator("#frame");

  const popup = await extension.openPopup(page);
  await expect(popup.getByText(site.origin("idp.test"))).toBeVisible();
  await popup.locator(".entry", { hasText: "Identity provider" }).click();

  await expect(frame.locator("#password")).toHaveValue("correct horse battery staple");
  const [credential] = await stub.requests("credential");
  expect(credential.origin).toBe(site.origin("idp.test"));
});

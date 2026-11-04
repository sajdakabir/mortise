/**
 * Identifier first, password second: the username and the password are never
 * on screen together.
 */

import { test, expect, inlineButton, login } from "./support/fixtures.js";

test("the password step gets the inline button and is filled", async ({
  context,
  site,
  stub,
}) => {
  await stub.vault({ logins: [login(site.origin("login.test"))] });
  const page = await context.newPage();
  await page.goto(site.url("login.test", "/multistep.html"));

  // Nothing to offer on the first screen: it has no password field.
  await page.waitForTimeout(500);
  await expect(inlineButton(page)).toHaveCount(0);

  await page.locator("#username").fill("octocat@example.com");
  await page.locator("#next").click();

  await inlineButton(page).click();
  await expect(page.locator("#password")).toHaveValue("correct horse battery staple");
});

test("the password step's submit is captured", async ({ context, site, stub }) => {
  const page = await context.newPage();
  await page.goto(site.url("login.test", "/multistep.html"));
  await page.locator("#username").fill("octocat@example.com");
  await page.locator("#next").click();
  await page.locator("#password").fill("second step password");
  await page.locator("#submit").click();

  await expect.poll(() => stub.requests("capture")).toHaveLength(1);
  expect((await stub.requests("capture"))[0]).toMatchObject({
    origin: site.origin("login.test"),
    password: "second step password",
  });
});

// Explicit autocomplete=username lets the popup fill the first step safely.
test("the popup fills the username on the username-only first step", async ({
  context,
  extension,
  site,
  stub,
}) => {
  await stub.vault({ logins: [login(site.origin("login.test"), { username: "octocat@example.com" })] });
  const page = await context.newPage();
  await page.goto(site.url("login.test", "/multistep.html"));

  const popup = await extension.openPopup(page);
  await popup.locator(".entry").click();

  await expect(page.locator("#username")).toHaveValue("octocat@example.com");
});

// The hidden username retained by this form must survive capture.
test("the capture carries the username typed on the first step", async ({
  context,
  site,
  stub,
}) => {
  const page = await context.newPage();
  await page.goto(site.url("login.test", "/multistep.html"));
  await page.locator("#username").fill("octocat@example.com");
  await page.locator("#next").click();
  await page.locator("#password").fill("second step password");
  await page.locator("#submit").click();

  await expect.poll(() => stub.requests("capture")).toHaveLength(1);
  expect((await stub.requests("capture"))[0].username).toBe("octocat@example.com");
});

/**
 * A single-page app that renders its login form after load, with no <form>
 * and a div for a button.
 */

import { test, expect, inlineButton, login } from "./support/fixtures.js";

test("a form rendered late still gets the inline button, and the fill reaches the app", async ({
  context,
  site,
  stub,
}) => {
  await stub.vault({ logins: [login(site.origin("login.test"))] });
  const page = await context.newPage();
  await page.goto(site.url("login.test", "/spa.html"));
  await expect(page.locator("#password")).toBeVisible();

  await inlineButton(page).click();
  await expect(page.locator("#password")).toHaveValue("correct horse battery staple");

  // The app only learns values through input events.
  await page.locator("#submit").click();
  await expect(page.locator("#done")).toHaveText("Signed in as octocat");
});

test("a click on a div 'button' captures the login", async ({ context, site, stub }) => {
  const page = await context.newPage();
  await page.goto(site.url("login.test", "/spa.html"));

  await page.locator("#username").fill("octocat");
  await page.locator("#password").fill("typed in an app");
  await page.locator("#submit").click();
  await expect(page.locator("#done")).toHaveText("Signed in as octocat");

  await expect.poll(() => stub.requests("capture")).toHaveLength(1);
  expect((await stub.requests("capture"))[0]).toMatchObject({
    origin: site.origin("login.test"),
    username: "octocat",
    password: "typed in an app",
  });
});

/**
 * A login form inside a web component's shadow root.
 *
 * Nothing here works yet: fill and capture both search with
 * document.querySelectorAll, which does not see into shadow roots, and the
 * capture listeners on document never see a submit from inside one (submit
 * does not cross the shadow boundary) and see clicks retargeted to the host.
 */

import { test, expect, inlineButton, login } from "./support/fixtures.js";

const form = (page) => page.locator("login-form");

// FIXME: no password field is found, so the page never announces a login and
// no inline button is mounted.
test.fixme("a form in a shadow root gets the inline button and is filled", async ({
  context,
  site,
  stub,
}) => {
  await stub.vault({ logins: [login(site.origin("login.test"))] });
  const page = await context.newPage();
  await page.goto(site.url("login.test", "/shadow.html"));

  await inlineButton(page).click();

  await expect(form(page).locator("#username")).toHaveValue("octocat");
  await expect(form(page).locator("#password")).toHaveValue("correct horse battery staple");
});

// FIXME: the popup answers "No password field found on this page."
test.fixme("the popup fills a form in a shadow root", async ({ context, extension, site, stub }) => {
  await stub.vault({ logins: [login(site.origin("login.test"))] });
  const page = await context.newPage();
  await page.goto(site.url("login.test", "/shadow.html"));

  const popup = await extension.openPopup(page);
  await popup.locator(".entry").click();

  await expect(form(page).locator("#password")).toHaveValue("correct horse battery staple");
});

// FIXME: nothing is captured.
test.fixme("a login submitted from a shadow root is captured", async ({ context, site, stub }) => {
  const page = await context.newPage();
  await page.goto(site.url("login.test", "/shadow.html"));

  await form(page).locator("#username").fill("octocat@example.com");
  await form(page).locator("#password").fill("typed in a component");
  await form(page).locator("#submit").click();

  await expect.poll(() => stub.requests("capture")).toHaveLength(1);
  expect((await stub.requests("capture"))[0]).toMatchObject({
    username: "octocat@example.com",
    password: "typed in a component",
  });
});

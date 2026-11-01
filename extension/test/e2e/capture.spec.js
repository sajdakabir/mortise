/**
 * Noticing a submitted login so the app can offer to save it.
 */

import { test, expect, login } from "./support/fixtures.js";

async function signIn(page, { username = "octocat@example.com", password = "typed password" } = {}) {
  await page.locator("#username").fill(username);
  await page.locator("#password").fill(password);
}

test.describe("simple login form", () => {
  test("a submitted login is offered once, attributed to the page's origin", async ({
    context,
    extension,
    site,
    stub,
  }) => {
    const page = await context.newPage();
    await page.goto(site.url("login.test", "/login.html"));
    await signIn(page);

    // A click on a submit button is a click *and* a submit; it is one sign-in.
    await page.locator("#submit").click();
    await page.waitForURL("**/signed-in");

    await expect.poll(() => stub.requests("capture")).toHaveLength(1);
    const [capture] = await stub.requests("capture");
    expect(capture).toMatchObject({
      origin: site.origin("login.test"),
      username: "octocat@example.com",
      password: "typed password",
    });
    // The app queued a prompt, so the toolbar says there is something to see.
    await expect.poll(() => extension.badge(page)).toBe("1");
  });

  test("Enter in the password field is a sign-in too", async ({ context, site, stub }) => {
    const page = await context.newPage();
    await page.goto(site.url("login.test", "/login.html"));
    await signIn(page);

    await page.locator("#password").press("Enter");

    await expect.poll(() => stub.requests("capture")).toHaveLength(1);
    expect((await stub.requests("capture"))[0].password).toBe("typed password");
  });

  test("nothing is sent when the password field is empty", async ({ context, site, stub }) => {
    const page = await context.newPage();
    await page.goto(site.url("login.test", "/login.html"));
    await page.locator("#username").fill("octocat@example.com");

    await page.locator("#submit").click();
    await page.waitForURL("**/signed-in");
    await page.waitForTimeout(500);

    expect(await stub.requests("capture")).toEqual([]);
  });

  test("a login the vault already holds queues nothing", async ({
    context,
    extension,
    site,
    stub,
  }) => {
    await stub.vault({
      logins: [
        login(site.origin("login.test"), {
          username: "octocat@example.com",
          password: "typed password",
        }),
      ],
    });
    const page = await context.newPage();
    await page.goto(site.url("login.test", "/login.html"));
    await signIn(page);
    await page.locator("#submit").click();
    await page.waitForURL("**/signed-in");

    await expect.poll(() => stub.requests("capture")).toHaveLength(1);
    // The app answers queued: false, so there is nothing to flag. Give the
    // reply time to arrive before checking that it did not.
    await page.waitForTimeout(1000);
    expect(await extension.badge(page)).not.toBe("1");
  });
});

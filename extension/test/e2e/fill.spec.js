/**
 * Filling a plain login form, from the inline button and from the popup.
 */

import { test, expect, inlineButton, login } from "./support/fixtures.js";

test.describe("simple login form", () => {
  test("a saved login shows the inline button and the toolbar count", async ({
    context,
    extension,
    site,
    stub,
  }) => {
    await stub.vault({ logins: [login(site.origin("login.test"))] });
    const page = await context.newPage();
    await page.goto(site.url("login.test", "/login.html"));

    await expect(inlineButton(page)).toBeVisible();
    await expect.poll(() => extension.badge(page)).toBe("1");
    // Asked about once, for the page's own origin.
    expect((await stub.requests("logins")).map((r) => r.origin)).toEqual([
      site.origin("login.test"),
    ]);
  });

  test("no saved login: no button, no count", async ({ context, extension, site, stub }) => {
    await stub.vault({ logins: [login(site.origin("idp.test"))] });
    const page = await context.newPage();
    await page.goto(site.url("login.test", "/login.html"));

    await expect.poll(async () => (await stub.requests("logins")).length).toBe(1);
    await expect.poll(() => extension.badge(page)).toBe("");
    await expect(inlineButton(page)).toHaveCount(0);
  });

  test("the inline button fills username and password", async ({ context, site, stub }) => {
    await stub.vault({ logins: [login(site.origin("login.test"))] });
    const page = await context.newPage();
    await page.goto(site.url("login.test", "/login.html"));

    await inlineButton(page).click();

    await expect(page.locator("#username")).toHaveValue("octocat");
    await expect(page.locator("#password")).toHaveValue("correct horse battery staple");
    await expect(page.locator("#password")).toBeFocused();
    // Removed shortly after a successful fill.
    await expect(inlineButton(page)).toHaveCount(0);

    const [credential] = await stub.requests("credential");
    expect(credential.origin).toBe(site.origin("login.test"));
  });

  test("the popup lists matches for the active tab and fills the one picked", async ({
    context,
    extension,
    site,
    stub,
  }) => {
    await stub.vault({
      logins: [
        login(site.origin("login.test"), { title: "Work", username: "work@example.com" }),
        login(site.origin("login.test"), {
          item_id: "ffeeddccbbaa99887766554433221100",
          title: "Personal",
          username: "me@example.com",
          password: "personal password",
        }),
      ],
    });
    const page = await context.newPage();
    await page.goto(site.url("login.test", "/login.html"));

    const popup = await extension.openPopup(page);
    await expect(popup.locator(".site")).toHaveText(site.origin("login.test"));
    await expect(popup.locator(".entry")).toHaveCount(2);

    const closed = popup.waitForEvent("close");
    await popup.locator(".entry", { hasText: "Personal" }).click();
    await closed; // the popup closes itself on success

    await expect(page.locator("#username")).toHaveValue("me@example.com");
    await expect(page.locator("#password")).toHaveValue("personal password");
  });

  test("the popup says so when there is nothing for this site", async ({
    context,
    extension,
    site,
  }) => {
    const page = await context.newPage();
    await page.goto(site.url("login.test", "/login.html"));

    const popup = await extension.openPopup(page);
    await expect(popup.locator(".count")).toHaveText("0");
    await expect(popup.getByText("No saved logins for this site")).toBeVisible();
  });

  test("the popup reports a page with no password field", async ({
    context,
    extension,
    site,
    stub,
  }) => {
    await stub.vault({ logins: [login(site.origin("login.test"))] });
    const page = await context.newPage();
    await page.goto(site.url("login.test", "/iframe.html?frame=about:blank"));

    const popup = await extension.openPopup(page);
    await popup.locator(".entry").click();
    await expect(popup.getByText("No password field found on this page.")).toBeVisible();
  });
});

test.describe("pairing", () => {
  test.use({ paired: false });

  test("an unpaired browser is asked to pair, and pairs once approved", async ({
    context,
    extension,
    site,
    stub,
  }) => {
    await stub.vault({ approve: false, paired: false, logins: [login(site.origin("login.test"))] });
    const page = await context.newPage();
    await page.goto(site.url("login.test", "/login.html"));

    const popup = await extension.openPopup(page);
    await expect(popup.getByRole("heading", { name: "Pair this browser" })).toBeVisible();

    await popup.getByRole("button", { name: "Pair" }).click();
    await expect(popup.getByRole("heading", { name: "Not approved yet" })).toBeVisible();

    // The user approves in the app; the next poll collects the key.
    await stub.vault({ approve: true, paired: true });
    await popup.getByRole("button", { name: "Check again" }).click();
    await expect(popup.locator(".entry")).toHaveCount(1);

    const [first, second] = await stub.requests("associate");
    expect(first.request_token).toBeNull();
    // The second ask carries the token the first reply handed out.
    expect(second.request_token).toBe("stub-token");
  });

  test("an unpaired content script asks nothing it would need a key for", async ({
    context,
    site,
    stub,
  }) => {
    await stub.vault({ logins: [login(site.origin("login.test"))] });
    const page = await context.newPage();
    await page.goto(site.url("login.test", "/login.html"));
    await page.waitForTimeout(1000);

    expect(await stub.requests()).toEqual([]);
    await expect(inlineButton(page)).toHaveCount(0);
  });
});

/**
 * A change-password form: current, new, confirm.
 */

import { test, expect, inlineButton, login } from "./support/fixtures.js";

test("fill puts the saved password in the current-password field only", async ({
  context,
  site,
  stub,
}) => {
  await stub.vault({ logins: [login(site.origin("login.test"))] });
  const page = await context.newPage();
  await page.goto(site.url("login.test", "/change-password.html"));

  await inlineButton(page).click();

  await expect(page.locator("#current")).toHaveValue("correct horse battery staple");
  await expect(page.locator("#new")).toHaveValue("");
  await expect(page.locator("#confirm")).toHaveValue("");
});

// FIXME: capture takes the first filled password field, which here is the
// *old* password, and finds no username because the only one is hidden. So
// changing a password offers to save the password being retired — or, as the
// vault already holds it, offers nothing — and the new one is lost. It should
// capture the new password (matching confirm), for the hidden username.
test.fixme("changing a password captures the new password, not the old one", async ({
  context,
  site,
  stub,
}) => {
  const page = await context.newPage();
  await page.goto(site.url("login.test", "/change-password.html"));

  await page.locator("#current").fill("old password");
  await page.locator("#new").fill("brand new password");
  await page.locator("#confirm").fill("brand new password");
  await page.locator("#submit").click();

  await expect.poll(() => stub.requests("capture")).toHaveLength(1);
  expect((await stub.requests("capture"))[0]).toMatchObject({
    origin: site.origin("login.test"),
    username: "octocat",
    password: "brand new password",
  });
});

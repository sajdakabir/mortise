import { test, expect } from "@playwright/test";

// The real Svelte shell with the in-memory mock. No vault, socket or keychain.
const request = {
  id: "req-1",
  project: "acme-api",
  environment: "dev",
  keys: null,
  command: "npm run dev",
  directory: "/Users/you/code/acme-api",
  process_chain: ["/usr/local/bin/mortise", "zsh", "claude"],
};

test("a command-line request shows kernel facts and records the answer", async ({ page }) => {
  await page.addInitScript((r) => { window.mortiseMockCliRequest = r; }, request);
  await page.goto("/");

  const dialog = page.getByRole("dialog", { name: "Command-line access" });
  await expect(dialog.getByRole("heading", { name: "Let a command read acme-api / dev?" })).toBeVisible();
  await expect(dialog.getByText("/Users/you/code/acme-api", { exact: true })).toBeVisible();
  await expect(dialog.getByText("/usr/local/bin/mortise ← zsh ← claude", { exact: true })).toBeVisible();
  await expect(dialog.getByText("npm run dev", { exact: true })).toBeVisible();
  await page.screenshot({ path: "../.context/cli-prompt.png" });

  // Nothing is answered by merely looking, and the backdrop does not dismiss.
  await page.mouse.click(5, 5);
  await expect(dialog).toBeVisible();
  expect(await page.evaluate(() => window.mortiseMockCliAnswers ?? [])).toEqual([]);

  await dialog.getByRole("button", { name: "Allow once", exact: true }).click();
  await expect(dialog).toBeHidden();
  expect(await page.evaluate(() => window.mortiseMockCliAnswers)).toEqual([{ id: "req-1", answer: "once" }]);
});

test("a request for specific keys names them", async ({ page }) => {
  await page.addInitScript((r) => { window.mortiseMockCliRequest = { ...r, keys: ["DATABASE_URL", "TOKEN"] }; }, request);
  await page.goto("/");
  await expect(page.getByText("It is asking for 2 secrets (DATABASE_URL, TOKEN) from that environment.")).toBeVisible();
});

test("live grants are listed in Settings and can be revoked", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: "Settings", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Command line" })).toBeVisible();
  await expect(page.getByText("acme-api / dev", { exact: true })).toBeVisible();
  await page.getByRole("heading", { name: "Command line" }).scrollIntoViewIfNeeded();
  await page.screenshot({ path: "../.context/cli-settings.png" });

  await page.getByRole("button", { name: "Revoke", exact: true }).click();
  await expect(page.getByText("No commands are allowed right now.")).toBeVisible();
});

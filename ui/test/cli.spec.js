import { test, expect } from "@playwright/test";

// The real Svelte shell with the in-memory mock. No vault, socket or keychain.
const request = {
  id: "req-1",
  kind: "run",
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

test("an agent session request offers only Start or Deny and records the answer", async ({ page }) => {
  await page.addInitScript((r) => {
    window.mortiseMockCliRequest = { ...r, id: "sess-1", kind: "session", command: "claude" };
  }, request);
  await page.goto("/");

  const dialog = page.getByRole("dialog", { name: "Command-line access" });
  await expect(dialog.getByRole("heading", { name: "Start an agent session for acme-api / dev?" })).toBeVisible();
  await expect(dialog.getByRole("button", { name: "Allow once" })).toHaveCount(0);
  await page.screenshot({ path: "../.context/cli-session-prompt.png" });

  await dialog.getByRole("button", { name: "Start session", exact: true }).click();
  await expect(dialog).toBeHidden();
  expect(await page.evaluate(() => window.mortiseMockCliAnswers)).toEqual([{ id: "sess-1", answer: "for_eight_hours" }]);
});

test("Settings lists directory grants and agent sessions, and each can be revoked", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: "Settings", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Command line" })).toBeVisible();
  await expect(page.getByText("from /Users/you/code/acme-api", { exact: false })).toBeVisible();
  await expect(page.getByText("claude (pid 4242)", { exact: true })).toBeVisible();

  const revoke = page.getByRole("button", { name: "Revoke", exact: true });
  await expect(revoke).toHaveCount(2);
  await revoke.first().click();
  await expect(revoke).toHaveCount(1);
  await revoke.first().click();
  await expect(page.getByText("No commands are allowed right now.")).toBeVisible();
});

test("recent access shows who asked and what happened, including refusals", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: "Settings", exact: true }).click();
  await page.getByRole("button", { name: "Recent access (2)" }).click();

  const log = page.getByRole("list", { name: "Recent command-line access" });
  await expect(log.getByText("Agent session", { exact: true })).toBeVisible();
  await expect(log.getByText("Refused", { exact: true })).toBeVisible();
  await expect(log.getByText("There is no project called “payroll” in Mortise.")).toBeVisible();
  await log.scrollIntoViewIfNeeded();
  await page.screenshot({ path: "../.context/cli-access-log.png" });
});

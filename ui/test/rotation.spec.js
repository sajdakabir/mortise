import { test, expect } from "@playwright/test";

// The real Svelte shell with the in-memory mock. The mock's "Anthropic API"
// key is 5 days overdue on a 90-day policy, with a previous key restorable.
async function openKey(page) {
  await page.goto("/");
  await page.getByRole("button", { name: /Anthropic API/ }).click();
}

test("overdue items are flagged in the list and explained in the detail", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByText(/· 1 to rotate/)).toBeVisible();
  await expect(page.getByRole("button", { name: /Anthropic API/ }).getByText("Rotate", { exact: true })).toBeVisible();

  await page.getByRole("button", { name: /Anthropic API/ }).click();
  await expect(page.getByText("Rotated 95 days ago · overdue by 5 days")).toBeVisible();
  await expect(page.getByText("· every 90 days")).toBeVisible();
  await page.screenshot({ path: "../.context/rotation-detail.png" });
});

test("rotating sends only the new value and keeps every other field", async ({ page }) => {
  await openKey(page);
  await page.getByRole("button", { name: "Rotate…" }).click();
  await page.getByLabel("New key").fill("sk-new-value");
  await page.getByRole("button", { name: "Save new key" }).click();

  const saves = await page.evaluate(() => window.mortiseMockSaves);
  expect(saves).toHaveLength(1);
  expect(saves[0].payload).toEqual({ kind: "ApiKey", key: "sk-new-value", notes: null });
  expect(saves[0].meta).toMatchObject({
    title: "Anthropic API", folder: "Work", tags: ["ai"], rotate_every_days: 90,
    urls: ["https://console.anthropic.com"],
  });
});

test("the previous value can be restored from the detail", async ({ page }) => {
  await openKey(page);
  await expect(page.getByText(/Restorable until/)).toBeVisible();
  await page.getByRole("button", { name: "Restore previous" }).click();
  expect(await page.evaluate(() => window.mortiseMockRestores)).toEqual(["c".repeat(32)]);
});

test("the editor sets a rotation policy and keeps it on save", async ({ page }) => {
  await openKey(page);
  await page.getByRole("button", { name: "Edit", exact: true }).click();
  await expect(page.getByLabel("Rotate every")).toHaveValue("90");
  await page.getByLabel("Rotate every").selectOption("30");
  await page.getByRole("button", { name: "Save", exact: true }).click();

  const saves = await page.evaluate(() => window.mortiseMockSaves);
  expect(saves.at(-1).meta).toMatchObject({ rotate_every_days: 30, folder: "Work" });
});

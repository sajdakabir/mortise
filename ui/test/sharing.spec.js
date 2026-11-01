import { test, expect } from "@playwright/test";

// The real Svelte shell with fake IPC only. No vault, keychain or relay access.
test.beforeEach(async ({ page }) => {
  await page.addInitScript(() => localStorage.setItem("mortise.mode", "secrets"));
  await page.goto("/");
  await page.getByRole("button", { name: "Share project", exact: true }).waitFor();
  await page.evaluate(async () => {
    const { ipc } = await import("/src/lib/ipc.ts");
    window.sharingCalls = [];
    window.requestAvailable = false;
    window.joinApproved = false;
    ipc.syncStatus = async () => ({ relay_url: "https://relay.example", pending: 0, cursor: 0 });
    ipc.createProjectInvite = async () => {
      window.sharingCalls.push("create"); return "mortise://join#test_invite";
    };
    ipc.pendingProjectJoin = async () => {
      window.sharingCalls.push("poll");
      return window.requestAvailable ? { name: "Grace", fingerprint: "12345 67890", request_token: "displayed-request" } : null;
    };
    ipc.grantProjectJoin = async (_link, role, token) => { window.sharingCalls.push(["grant", role, token]); };
    ipc.declineProjectJoin = async () => { window.sharingCalls.push("decline"); };
    ipc.inspectProjectInvite = async (link) => {
      if (link.includes("expired")) throw { code: "bad_request", message: "This invite is invalid or has expired. Ask for a new link." };
      return { project_name: "Payments", inviter_name: "Project owner", fingerprint: "67890 12345", expires_at_ms: Date.now() + 60000 };
    };
    ipc.requestProjectAccess = async () => { window.sharingCalls.push("request"); };
    ipc.completeProjectJoin = async () => window.joinApproved;
  });
});

async function createLink(page) {
  await page.getByRole("button", { name: "Share project", exact: true }).click();
  await expect(page.getByRole("textbox", { name: "Your name" })).toHaveCount(0);
  await page.getByRole("button", { name: "Create link", exact: true }).click();
  await expect(page.getByRole("textbox", { name: "Invite link", exact: true })).toHaveValue("mortise://join#test_invite");
}

test("request appears after dismissal and workspace switch; approval is explicit and bound", async ({ page }) => {
  await createLink(page);
  await page.getByRole("button", { name: "Close sharing" }).click();
  await page.getByRole("button", { name: "Secrets", exact: true }).click();
  await page.getByRole("menuitem", { name: /Passwords/ }).click();
  await page.evaluate(() => { window.requestAvailable = true; });
  await expect(page.getByText("wants access to this project.", { exact: false })).toBeVisible({ timeout: 8000 });
  expect(await page.evaluate(() => window.sharingCalls.filter(Array.isArray))).toEqual([]);
  await expect(page.getByLabel("Access", { exact: true })).toHaveValue("viewer");
  await page.getByRole("button", { name: "Allow access", exact: true }).click();
  expect(await page.evaluate(() => window.sharingCalls.filter(Array.isArray)))
    .toEqual([["grant", "viewer", "displayed-request"]]);
  await expect(page.getByText("Access allowed. They can now finish joining.")).toBeVisible();
});

test("declining closes the invite without granting", async ({ page }) => {
  await createLink(page);
  await page.evaluate(() => { window.requestAvailable = true; });
  await page.getByRole("button", { name: "Decline", exact: true }).click({ timeout: 8000 });
  await expect(page.getByText("Request declined. This link can no longer be used.")).toBeVisible();
  expect(await page.evaluate(() => window.sharingCalls.filter(Array.isArray))).toEqual([]);
  expect(await page.evaluate(() => window.sharingCalls)).toContain("decline");
});

test("recipient review makes no request until confirmation; approval is detected automatically", async ({ page }) => {
  await page.getByRole("button", { name: "Join with invite", exact: true }).click();
  await page.getByRole("textbox", { name: "Invite link", exact: true }).fill("mortise://join#recipient");
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await expect(page.getByText("Payments", { exact: true })).toBeVisible();
  expect(await page.evaluate(() => window.sharingCalls)).not.toContain("request");
  await page.getByRole("textbox", { name: "Your name", exact: true }).fill("Grace");
  await page.getByRole("button", { name: "Request access", exact: true }).click();
  await expect(page.getByText("Request sent. Waiting for the owner to approve.")).toBeVisible();
  await page.evaluate(() => { window.joinApproved = true; });
  await expect(page.getByText("Access approved. The encrypted project has been downloaded.")).toBeVisible({ timeout: 8000 });
  expect(await page.evaluate(() => window.sharingCalls.filter(Array.isArray))).toEqual([]);
});

test("missing setup and invalid links cannot create or request access", async ({ page }) => {
  await page.evaluate(async () => { (await import("/src/lib/ipc.ts")).ipc.syncStatus = async () => ({ relay_url: null }); });
  await page.getByRole("button", { name: "Share project", exact: true }).click();
  await expect(page.getByRole("button", { name: "Set up sharing", exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Create link", exact: true })).toHaveCount(0);
  await page.getByRole("button", { name: "Close sharing" }).click();
  await page.getByRole("button", { name: "Join with invite", exact: true }).click();
  await page.getByRole("textbox", { name: "Invite link", exact: true }).fill("mortise://join#expired");
  await page.getByRole("button", { name: "Continue", exact: true }).click();
  await expect(page.getByRole("alert")).toContainText("invalid or has expired");
  await expect(page.getByRole("button", { name: "Request access", exact: true })).toHaveCount(0);
  expect(await page.evaluate(() => window.sharingCalls)).not.toContain("request");
  expect(await page.evaluate(() => window.sharingCalls)).not.toContain("create");
});

test("locking pauses requests and hides the bearer link", async ({ page }) => {
  await createLink(page);
  await page.getByRole("button", { name: "Close sharing" }).click();
  await page.getByRole("button", { name: "Lock", exact: true }).click();
  const count = await page.evaluate(() => window.sharingCalls.length);
  await page.clock.install();
  await page.clock.fastForward(20_000);
  expect(await page.evaluate(() => window.sharingCalls.length)).toBe(count);
  await expect(page.getByRole("textbox", { name: "Invite link", exact: true })).toHaveCount(0);
});

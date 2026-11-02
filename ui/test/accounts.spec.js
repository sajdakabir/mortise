import { test, expect } from "@playwright/test";

// Real UI, fake account transport. These tests never open Keychain or a vault.
async function setup(page, { signedIn = true, trusted = true, owner = true } = {}) {
  await page.goto("/");
  await page.getByRole("button", { name: "Settings", exact: true }).waitFor();
  await page.evaluate(async ({ signedIn, trusted, owner }) => {
    const { ipc } = await import("/src/lib/ipc.ts");
    window.accountCalls = [];
    window.accountSignedIn = signedIn;
    window.accountJoined = false;
    window.accountDeviceApproved = false;
    window.requestApproved = false;
    ipc.accountStatus = async () => ({ configured: true, signed_in: window.accountSignedIn });
    ipc.accountSignIn = async () => { window.accountCalls.push({ kind: "sign_in" }); window.accountSignedIn = true; };
    ipc.accountSignOut = async () => { window.accountSignedIn = false; };
    ipc.accountAction = async (action) => {
      window.accountCalls.push(action);
      switch (action.kind) {
        case "dashboard": return {
          account: { id: "alice", name: "Alice", email: "alice@example.com" }, current_device_id: "current",
          devices: [
            { id: "current", name: "This Mac", fingerprint: "local-fingerprint", certificate: "local-cert", status: trusted ? "trusted" : "pending" },
            { id: "new", name: "Alice’s MacBook", fingerprint: "1234567890abcdef".repeat(4), certificate: "exact-reviewed-certificate", status: window.accountDeviceApproved ? "trusted" : "pending" },
          ],
          teams: [{ id: "team", name: "Mortise builders", role: owner ? "owner" : "member" },
            ...(window.accountJoined ? [{ id: "joined", name: "Design team", role: "member" }] : [])],
        };
        case "members": return [{ account_id: "alice", name: "Alice", email: "alice@example.com", role: "owner" }];
        case "requests": return window.requestApproved ? [] : [{ id: "invite-request", account_id: "grace-account", email: "grace@example.com", name: "Grace", role: "member" }];
        case "approve_device": window.accountDeviceApproved = true; return null;
        case "decide": window.requestApproved = true; return null;
        case "invite": return { id: "issued", link: "https://accounts.example/join#test-token", expires_at: Date.now() / 1000 + 86400 };
        case "preview_invite": return { team_id: "joined", team_name: "Design team", role: "member", status: "issued", expires_at: Date.now() / 1000 + 86400 };
        case "request_invite": return null;
        default: return null;
      }
    };
  }, { signedIn, trusted, owner });
  await page.getByRole("button", { name: "Settings", exact: true }).click();
  await page.getByRole("button", { name: signedIn ? "Manage account" : "Sign in", exact: true }).click();
}

test("device approval requires review and binds the exact certificate", async ({ page }) => {
  await setup(page);
  await page.getByRole("button", { name: "Devices", exact: true }).click();
  await page.getByRole("button", { name: "Review device", exact: true }).click();
  await expect(page.getByText("1234567890abcdef".repeat(4))).toBeVisible();
  expect(await page.evaluate(() => window.accountCalls.filter(a => a.kind === "approve_device"))).toEqual([]);
  await page.getByRole("button", { name: "Confirm", exact: true }).click();
  expect(await page.evaluate(() => window.accountCalls.filter(a => a.kind === "approve_device")))
    .toEqual([{ kind: "approve_device", id: "new", certificate: "exact-reviewed-certificate" }]);
  await expect(page.getByText("trusted · This Mac", { exact: true })).toBeVisible();
});

test("team invitation approval is explicit and bound to the displayed account", async ({ page }) => {
  await setup(page);
  await page.getByRole("button", { name: "Review request", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Approve grace@example.com?" })).toBeVisible();
  expect(await page.evaluate(() => window.accountCalls.filter(a => a.kind === "decide"))).toEqual([]);
  await page.getByRole("button", { name: "Confirm", exact: true }).click();
  expect(await page.evaluate(() => window.accountCalls.filter(a => a.kind === "decide")))
    .toEqual([{ kind: "decide", team: "team", invitation: "invite-request", account_id: "grace-account", approve: true }]);
  await page.getByRole("button", { name: "Invite people", exact: true }).click();
  await expect(page.getByRole("combobox", { name: "Team role", exact: true })).toHaveValue("member");
  await page.getByRole("button", { name: "Create invitation link", exact: true }).click();
  await expect(page.getByLabel("Team invitation link", { exact: true })).toHaveValue("https://accounts.example/join#test-token");
  await page.screenshot({ path: "/tmp/mortise-account-invite.png" });
});

test("recipient previews before requesting; membership appears after approval", async ({ page }) => {
  await setup(page);
  await page.getByRole("button", { name: "Join with link", exact: true }).click();
  await page.getByLabel("Team invitation link", { exact: true }).fill("https://accounts.example/join#test");
  await page.getByRole("button", { name: "Review invitation", exact: true }).click();
  await expect(page.getByText("Design team", { exact: true })).toBeVisible();
  expect(await page.evaluate(() => window.accountCalls.filter(a => a.kind === "request_invite"))).toEqual([]);
  await page.getByRole("button", { name: "Request to join", exact: true }).click();
  await expect(page.getByText("Request sent. Waiting for approval.")).toBeVisible();
  await page.evaluate(() => window.accountJoined = true);
  await expect(page.getByText("You joined Design team.")).toBeVisible({ timeout: 8000 });
});

test("pending devices cannot invite or create teams and signed-out UI uses browser sign-in", async ({ page }) => {
  await setup(page, { signedIn: false, trusted: false });
  await page.getByRole("button", { name: "Continue in browser", exact: true }).click();
  await expect(page.getByText("Approve this Mac from a trusted device", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "New team", exact: true })).toBeDisabled();
  await expect(page.getByRole("button", { name: "Join with link", exact: true })).toBeDisabled();
});

test("team members cannot approve requests or invite people", async ({ page }) => {
  await setup(page, { owner: false });
  await expect(page.getByText("alice@example.com · owner", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Invite people", exact: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Review request", exact: true })).toHaveCount(0);
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).not.toBeVisible();
});

test("unconfigured builds explain availability instead of faking sign-in", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: "Settings", exact: true }).click();
  await expect(page.getByText("Account service is not configured in this build. Local passwords and secrets work without it.", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Sign in", exact: true })).toHaveCount(0);
});

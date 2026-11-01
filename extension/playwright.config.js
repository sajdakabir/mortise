// End-to-end tests for the extension. See NOTES.md, "Tests".
import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "test/e2e",
  // One at a time. Each test already gets its own browser and profile, but
  // when two test workers launch Chromium at the same moment, the extension's
  // service worker can come up paused before its bindings exist (`chrome` is
  // undefined in it) and every evaluate against it hangs. Serial runs have not
  // shown it once.
  workers: 1,
  retries: process.env.CI ? 1 : 0,
  // Generous: every native request spawns a node process, which is slow on
  // a loaded machine.
  timeout: 60_000,
  expect: { timeout: 10_000 },
  reporter: process.env.CI ? [["list"], ["html", { open: "never" }]] : "list",
  use: {
    headless: true,
    trace: "retain-on-failure",
  },
});

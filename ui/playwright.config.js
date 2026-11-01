import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "test",
  workers: 1,
  use: {
    baseURL: "http://127.0.0.1:5174",
    viewport: { width: 1040, height: 720 },
    launchOptions: process.env.PLAYWRIGHT_EXECUTABLE_PATH
      ? { executablePath: process.env.PLAYWRIGHT_EXECUTABLE_PATH } : {},
  },
  webServer: {
    command: "npm run dev -- --host 127.0.0.1 --port 5174",
    url: "http://127.0.0.1:5174",
    reuseExistingServer: !process.env.CI,
  },
});

import { defineConfig, devices } from "@playwright/test";

// Serves the seeded database + built UI via the Go binary (started by the
// operator or CI before invoking; see README). Uses system Chrome — no
// browser download.
export default defineConfig({
  testDir: "./e2e",
  timeout: 30000,
  use: {
    baseURL: "http://127.0.0.1:18080",
    channel: "chrome",
    trace: "retain-on-failure",
  },
  projects: [{ name: "chrome", use: { ...devices["Desktop Chrome"] } }],
});

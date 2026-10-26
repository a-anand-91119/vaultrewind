import { defineConfig } from "@playwright/test";
export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false,
  workers: 1,
  timeout: 240000,
  expect: { timeout: 15000 },
  reporter: [
    ["list"],
    ["json", { outputFile: "../docs/evidence/browser-results.json" }],
  ],
  use: {
    baseURL: process.env.VAULTREWIND_TEST_URL || "http://127.0.0.1:8098",
    trace: "off",
    video: "off",
    screenshot: "off",
    launchOptions: { chromiumSandbox: false },
  },
  outputDir: "../.runtime/browser-artifacts",
});

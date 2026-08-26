// @ts-check
const { defineConfig, devices } = require("@playwright/test");

module.exports = defineConfig({
  testDir: ".",
  timeout: 30_000,
  expect: { timeout: 5_000 },
  reporter: "list",
  use: {
    ...devices["Desktop Chrome"],
    channel: "chrome",
    headless: true
  }
});

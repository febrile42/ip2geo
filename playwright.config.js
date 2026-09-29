// @ts-check
const { defineConfig, devices } = require('@playwright/test');

/**
 * Phase 2 Playwright config (design doc R3 + D16). Runs against a local
 * `php -S` server backed by the mmdb test fixtures copied into
 * data/geoip/ (gitignored; see tests/e2e/privacy.spec.js's header and
 * config.php, also gitignored, for the setup).
 *
 * Chromium only, per the environment note: "Chromium is preinstalled...
 * do NOT run `playwright install`". PLAYWRIGHT_BROWSERS_PATH must be set
 * in the environment before running `npm run e2e` — see README/report for
 * the exact path this environment uses.
 */
module.exports = defineConfig({
  testDir: './tests/e2e',
  timeout: 30 * 1000,
  fullyParallel: false,
  retries: 0,
  reporter: [['list']],
  use: {
    baseURL: 'http://127.0.0.1:8935',
    trace: 'retain-on-failure',
  },
  webServer: {
    command: 'php -S 127.0.0.1:8935',
    url: 'http://127.0.0.1:8935/index.php',
    reuseExistingServer: !process.env.CI,
    timeout: 15 * 1000,
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
  ],
});

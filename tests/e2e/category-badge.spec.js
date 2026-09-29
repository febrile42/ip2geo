// @ts-check
/**
 * IPG-192: on a phone the Category badge split across two lines ("Cloud" /
 * "exit") when the other rows were "Unknown DROP": the column shrank to its
 * longest single word and the multi-word badge wrapped inside itself. Each
 * label must render as one line box. /api/lookup.php is stubbed with the
 * owner's screenshot rows so the result doesn't depend on the .mmdb fixtures.
 */
const { test, expect, devices } = require('@playwright/test');

// Chromium-only suite, so Pixel 7 narrowed to the reporter's 375px screen.
test.use({ ...devices['Pixel 7'], viewport: { width: 375, height: 812 } });

const row = (ip, category, drop, asn, org) => ({
  ip, country_iso_code: 'JP', country_name: 'Japan', subdivision_1_name: null, city_name: null,
  autonomous_system_number: asn, autonomous_system_org: org, category, drop,
});

for (const [category, label] of [
  ['cloud', 'Cloud exit'], ['vpn', 'VPN/Proxy'], ['scanning', 'Scanning'], ['residential', 'Residential'],
]) {
  test(`"${label}" badge stays on one line beside Unknown DROP rows`, async ({ page }) => {
    await page.route('**/api/lookup.php', (route) => route.fulfill({
      contentType: 'application/json',
      body: JSON.stringify({ results: [
        row('99.77.62.207', category, false, 16509, 'Amazon.com, Inc.'),
        row('113.213.160.174', 'unknown', true, null, null),
        row('113.213.169.249', 'unknown', true, null, null),
      ], unresolved: [] }),
    }));
    await page.goto('/index.php');
    await page.fill('#message', '99.77.62.207 113.213.160.174 113.213.169.249');
    await page.tap('input[type=submit], button[type=submit]');
    const badges = page.locator('.wb-cat');
    await expect(badges).toHaveCount(3);
    const lines = await badges.evaluateAll((els) =>
      els.map((el) => [el.textContent, el.getClientRects().length]));
    expect(lines).toEqual([[label, 1], ['Unknown', 1], ['Unknown', 1]]);
  });
}

// @ts-check
/**
 * On a phone, tapping a DROP label must show the Spamhaus explanation
 * (title tooltips never appear on touch). /api/lookup.php is stubbed so the
 * result has a DROP row regardless of the tiny test .mmdb fixtures.
 */
const { test, expect, devices } = require('@playwright/test');

test.use({ ...devices['Pixel 7'] });

test('tapping a DROP tag in the workbench shows the explanation', async ({ page }) => {
  await page.route('**/api/lookup.php', (route) => route.fulfill({
    contentType: 'application/json',
    body: JSON.stringify({ results: [
      { ip: '45.93.20.223', country_iso_code: 'HK', country_name: 'Hong Kong', subdivision_1_name: null, city_name: null,
        autonomous_system_number: 201738, autonomous_system_org: 'Ufo Technologies Limited', category: 'scanning', drop: true },
      { ip: '8.8.8.8', country_iso_code: 'US', country_name: 'United States', subdivision_1_name: null, city_name: null,
        autonomous_system_number: 15169, autonomous_system_org: 'Google LLC', category: 'cloud', drop: false },
    ], unresolved: [] }),
  }));
  await page.goto('/index.php');
  await page.fill('#message', '45.93.20.223 8.8.8.8');
  await page.tap('input[type=submit], button[type=submit]');
  const tag = page.locator('abbr.drop-tag').first();
  await expect(tag).toBeVisible();
  await tag.tap();
  const pop = page.locator('#abbr-pop');
  await expect(pop).toBeVisible();
  await expect(pop).toContainText("Don't Route Or Peer");
  const box = await pop.boundingBox();
  const vw = page.viewportSize().width;
  expect(box.x).toBeGreaterThanOrEqual(0);
  expect(box.x + box.width).toBeLessThanOrEqual(vw);
  await page.tap('h1, h2');
  await expect(pop).toHaveCount(0);
});

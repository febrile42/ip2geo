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

test('tapping "Spamhaus DROP" in the summary line shows the explanation (IPG-33)', async ({ page }) => {
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
  const summary = page.locator('.wb-summary');
  await expect(summary).toBeVisible();
  await expect(summary).toContainText('1 IP in a Spamhaus DROP netblock');
  const abbr = page.locator('.lookup-summary-drop abbr');
  await expect(abbr).toBeVisible();
  await abbr.tap();
  const pop = page.locator('#abbr-pop');
  await expect(pop).toBeVisible();
  await expect(pop).toContainText("Don't Route Or Peer");
  const box = await pop.boundingBox();
  const vw = page.viewportSize().width;
  expect(box.x).toBeGreaterThanOrEqual(0);
  expect(box.x + box.width).toBeLessThanOrEqual(vw);
});

test('the IP column stays pinned when the workbench table scrolls sideways on a phone', async ({ page }) => {
  const rows = Array.from({ length: 6 }, (_, i) => ({
    ip: '45.93.20.' + (220 + i), country_iso_code: 'HK', country_name: 'Hong Kong',
    subdivision_1_name: 'Some Long Region Name', city_name: 'Some Long City Name',
    autonomous_system_number: 201738, autonomous_system_org: 'Ufo Technologies Limited With A Long Name',
    category: 'scanning', drop: i % 2 === 0,
  }));
  await page.route('**/api/lookup.php', (route) => route.fulfill({
    contentType: 'application/json', body: JSON.stringify({ results: rows, unresolved: [] }),
  }));
  await page.goto('/index.php');
  await page.fill('#message', rows.map((r) => r.ip).join(' '));
  await page.tap('input[type=submit], button[type=submit]');
  const firstCell = page.locator('#wb-results-table tbody td:first-child').first();
  await expect(firstCell).toBeVisible();
  const before = await firstCell.boundingBox();
  const scrolled = await page.evaluate(() => {
    let el = document.querySelector('#wb-results-table').parentElement;
    while (el && el.scrollWidth <= el.clientWidth) el = el.parentElement;
    if (!el || el === document.body || el === document.documentElement) return 0;
    el.scrollLeft = 400;
    return el.scrollLeft;
  });
  expect(scrolled).toBeGreaterThan(0);
  const after = await firstCell.boundingBox();
  expect(Math.abs(after.x - before.x)).toBeLessThan(2);
  const bg = await page.locator('#wb-results-table tbody tr:nth-child(2) td:first-child')
    .evaluate((td) => getComputedStyle(td).backgroundImage + ' ' + getComputedStyle(td).backgroundColor);
  expect(bg).not.toMatch(/rgba\([^)]*, 0\)\s*$/);
});

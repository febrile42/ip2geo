// @ts-check
/**
 * IPG-38: the results paste bar has no "New lookup" button, and "Edit
 * paste" only moves focus to the textarea — it must not hide the results,
 * clear filters/sort, or reset the pill (spec on IPG-31, acceptance 1-3).
 *
 * IPG-41: the paste bar's Recent button was a dead stub and is now gone
 * entirely — Recent moved next to the primary submit button (#rl-recent-btn).
 */
const path = require('path');
const { test, expect } = require('@playwright/test');
const Share = require(path.resolve(__dirname, '../../assets/js/share-link.js'));

test.beforeEach(async ({ page }) => {
  await page.route('**/api/lookup.php', (route) => route.fulfill({
    contentType: 'application/json',
    body: JSON.stringify({
      results: [
        { ip: '203.0.113.9', country_iso_code: 'US', country_name: 'United States', subdivision_1_name: 'CA', city_name: 'Fremont', autonomous_system_number: 14061, autonomous_system_org: 'DigitalOcean, LLC', category: 'cloud', drop: false },
        { ip: '198.51.100.23', country_iso_code: 'HK', country_name: 'Hong Kong', subdivision_1_name: null, city_name: null, autonomous_system_number: 201738, autonomous_system_org: 'Ufo Technologies Limited', category: 'scanning', drop: true },
      ],
      unresolved: [],
    }),
  }));
});

test('the paste bar has no New lookup button', async ({ page }) => {
  await page.goto('/index.php');
  await page.fill('#message', '203.0.113.9 198.51.100.23');
  await page.click('.lookup-form .submit');
  await page.waitForSelector('#workbench-root:not([hidden])', { timeout: 10000 });

  const bar = page.locator('.wb-paste-bar');
  await expect(bar.getByRole('button', { name: 'Edit paste' })).toBeVisible();
  await expect(bar.getByRole('button', { name: /^Recent/ })).toHaveCount(0);
  await expect(bar.getByRole('button', { name: 'New lookup' })).toHaveCount(0);
  await expect(page.locator('#recent-lookups')).toHaveCount(0);
});

test('Edit paste keeps filters/chip/search and moves focus to the textarea with the caret at the end', async ({ page }) => {
  await page.goto('/index.php');
  await page.fill('#message', '203.0.113.9 198.51.100.23');
  await page.click('.lookup-form .submit');
  await page.waitForSelector('#workbench-root:not([hidden])', { timeout: 10000 });

  // Apply a category chip and type in the filter box.
  await page.locator('.wb-chips-category .wb-chip', { hasText: 'scanning' }).click();
  await page.locator('.wb-search').fill('198.51');
  await expect(page.locator('.wb-shown-count')).toContainText('1');

  await page.locator('.wb-paste-bar').getByRole('button', { name: 'Edit paste' }).click();

  // Results, chip and search state are untouched.
  await expect(page.locator('#workbench-root')).toBeVisible();
  await expect(page.locator('.wb-shown-count')).toContainText('1');
  await expect(page.locator('.wb-chips-category .wb-chip', { hasText: 'scanning' })).toHaveClass(/wb-chip--sel/);
  await expect(page.locator('.wb-search')).toHaveValue('198.51');

  // Focus is in the textarea, caret at the end, nothing selected.
  const focusInfo = await page.evaluate(() => ({
    id: document.activeElement && document.activeElement.id,
    start: document.activeElement && document.activeElement.selectionStart,
    end: document.activeElement && document.activeElement.selectionEnd,
    length: document.activeElement && document.activeElement.value.length,
  }));
  expect(focusInfo.id).toBe('message');
  expect(focusInfo.start).toBe(focusInfo.length);
  expect(focusInfo.end).toBe(focusInfo.length);
});

test('a shared #v= link shows no Edit paste button', async ({ page }) => {
  const payload = Share.encodeShareState({ ips: ['203.0.113.9'], categories: [], countries: [], search: '' });
  await page.goto('/index.php#v=' + payload);
  await page.waitForSelector('.wb-recipient-banner:not([hidden])', { timeout: 10000 });

  const bar = page.locator('.wb-paste-bar');
  await expect(bar.getByRole('button', { name: 'Edit paste' })).toHaveCount(0);
  await expect(bar.getByRole('button', { name: /^Recent/ })).toHaveCount(0);
});

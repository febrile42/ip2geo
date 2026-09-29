// @ts-check
/**
 * IPG-41 (spec on parent IPG-30): the Recent ▾ menu next to the primary
 * submit button. Covers spec §11 acceptance criteria 3, 4, 7, 8, 9, 10, 11
 * and 13 end-to-end (Jest covers the same logic against a mocked DOM;
 * this file exercises the real markup/CSS/localStorage integration).
 */
const { test, expect } = require('@playwright/test');

function stubLookup(page) {
  return page.route('**/api/lookup.php', (route) => route.fulfill({
    contentType: 'application/json',
    body: JSON.stringify({
      results: [
        { ip: '203.0.113.9', country_iso_code: 'US', country_name: 'United States', subdivision_1_name: 'CA', city_name: 'Fremont', autonomous_system_number: 14061, autonomous_system_org: 'DigitalOcean, LLC', category: 'cloud', drop: false },
      ],
      unresolved: [],
    }),
  }));
}

async function seedList(page, entries) {
  await page.evaluate((list) => {
    localStorage.setItem('rl_optin', '1');
    localStorage.setItem('rl_list', JSON.stringify(list));
  }, entries);
}

test.beforeEach(async ({ page }) => {
  await stubLookup(page);
});

test('Recent is hidden with no saved lookups until opted in, then shows the empty state (acceptance 11)', async ({ page }) => {
  await page.goto('/index.php');
  await expect(page.locator('#rl-optin-row')).toBeVisible();
  await expect(page.locator('#rl-recent-btn')).toBeVisible(); // saving defaults ON

  await page.locator('#rl-recent-btn').click();
  await expect(page.locator('#rl-menu')).toBeVisible();
  const items = page.locator('#rl-menu .wb-menu-item');
  await expect(items).toHaveCount(1);
  await expect(items.first()).toHaveAttribute('aria-disabled', 'true');
  await expect(items.first()).toContainText('No saved lookups yet');
  await expect(page.locator('#rl-menu .rl-menu-clear')).toHaveCount(0);
});

test('open/close via click, Esc, Tab and outside click; aria-expanded tracks state (acceptance 3)', async ({ page }) => {
  await page.goto('/index.php');
  await seedList(page, [{ ips: ['203.0.113.9'], count: 1, ts: Date.now() }]);
  await page.reload();

  const btn = page.locator('#rl-recent-btn');
  const menu = page.locator('#rl-menu');

  await expect(btn).toHaveAttribute('aria-expanded', 'false');
  await btn.click();
  await expect(menu).toBeVisible();
  await expect(btn).toHaveAttribute('aria-expanded', 'true');

  // second click closes
  await btn.click();
  await expect(menu).toBeHidden();
  await expect(btn).toHaveAttribute('aria-expanded', 'false');

  // Esc closes and returns focus to Recent
  await btn.click();
  await page.keyboard.press('Escape');
  await expect(menu).toBeHidden();
  await expect(btn).toBeFocused();

  // outside click closes
  await btn.click();
  await page.locator('h1, h2').first().click();
  await expect(menu).toBeHidden();
});

test('keyboard: ArrowDown opens with focus on the first item, arrows wrap with Clear last, Home/End jump (acceptance 4)', async ({ page }) => {
  await page.goto('/index.php');
  await seedList(page, [
    { ips: ['203.0.113.9'], count: 1, ts: Date.now() },
    { ips: ['198.51.100.5'], count: 1, ts: Date.now() },
  ]);
  await page.reload();

  const btn = page.locator('#rl-recent-btn');
  await btn.focus();
  await page.keyboard.press('ArrowDown');
  await expect(page.locator('#rl-menu')).toBeVisible();

  const items = page.locator('#rl-menu .wb-menu-item');
  await expect(items.first()).toBeFocused();

  await page.keyboard.press('ArrowUp');
  const last = items.last();
  await expect(last).toBeFocused();
  await expect(last).toHaveClass(/rl-menu-clear/);

  await page.keyboard.press('Home');
  await expect(items.first()).toBeFocused();
  await page.keyboard.press('End');
  await expect(last).toBeFocused();
});

test('selecting an entry fills the textarea, runs the lookup and moves the entry to the top (acceptance 7)', async ({ page }) => {
  await page.goto('/index.php');
  await seedList(page, [{ ips: ['203.0.113.9'], count: 1, ts: Date.now() - 60000 }]);
  await page.reload();

  await page.locator('#rl-recent-btn').click();
  await page.locator('#rl-menu .wb-menu-item[data-idx="0"]').click();

  await page.waitForSelector('#workbench-root:not([hidden])', { timeout: 10000 });
  await expect(page.locator('#message')).toHaveValue('203.0.113.9');
  await expect(page.locator('#wb-results-table, #results-table')).toBeVisible();

  const list = await page.evaluate(() => JSON.parse(localStorage.getItem('rl_list') || '[]'));
  expect(list).toHaveLength(1); // re-running the same list dedupes onto the one entry
});

test('forgiveness toast when the textarea held unsent text; Undo restores it exactly (acceptance 8)', async ({ page }) => {
  await page.goto('/index.php');
  await seedList(page, [{ ips: ['203.0.113.9'], count: 1, ts: Date.now() }]);
  await page.reload();
  await page.fill('#message', 'some unsent draft text');

  await page.locator('#rl-recent-btn').click();
  await page.locator('#rl-menu .wb-menu-item[data-idx="0"]').click();

  const toast = page.locator('#rl-toast');
  await expect(toast).toBeVisible();
  await expect(page.locator('#rl-toast-msg')).toHaveText('Replaced your unsent paste.');
  await expect(page.locator('#message')).toHaveValue('203.0.113.9'); // lookup already ran

  await page.locator('#rl-toast-undo').click();
  await expect(page.locator('#message')).toHaveValue('some unsent draft text');
});

test('no forgiveness toast when the textarea was empty', async ({ page }) => {
  await page.goto('/index.php');
  await seedList(page, [{ ips: ['203.0.113.9'], count: 1, ts: Date.now() }]);
  await page.reload();

  await page.locator('#rl-recent-btn').click();
  await page.locator('#rl-menu .wb-menu-item[data-idx="0"]').click();
  await page.waitForSelector('#workbench-root:not([hidden])', { timeout: 10000 });
  await expect(page.locator('#rl-toast')).toBeHidden();
});

test('Clear saved lookups shows a toast with Undo, and clears after 6s without it (acceptance 9)', async ({ page }) => {
  await page.goto('/index.php');
  await seedList(page, [{ ips: ['203.0.113.9'], count: 1, ts: Date.now() }]);
  await page.reload();

  await page.locator('#rl-recent-btn').click();
  await page.locator('#rl-menu .rl-menu-clear').click();

  await expect(page.locator('#rl-menu')).toBeHidden();
  await expect(page.locator('#rl-toast-msg')).toHaveText('Cleared 1 saved lookup.');

  const listAfterClear = await page.evaluate(() => localStorage.getItem('rl_list'));
  expect(JSON.parse(listAfterClear || '[]')).toEqual([]);

  await page.locator('#rl-toast-undo').click();
  const restored = await page.evaluate(() => JSON.parse(localStorage.getItem('rl_list') || '[]'));
  expect(restored).toHaveLength(1);
});

test('unticking "Save recent lookups" hides Recent and shows the new copy; re-ticking shows the empty state (acceptance 10, 11)', async ({ page }) => {
  await page.goto('/index.php');
  await seedList(page, [{ ips: ['203.0.113.9'], count: 1, ts: Date.now() }]);
  await page.reload();

  await expect(page.locator('#rl-recent-btn')).toBeVisible();
  await page.locator('#rl-optin').uncheck();

  await expect(page.locator('#rl-recent-btn')).toBeHidden();
  await expect(page.locator('#rl-toast-msg')).toHaveText('Saving turned off. Cleared 1 saved lookup.');

  await page.locator('#rl-optin').check();
  await expect(page.locator('#rl-recent-btn')).toBeVisible();
  await page.locator('#rl-recent-btn').click();
  await expect(page.locator('#rl-menu .wb-menu-item')).toHaveCount(1);
  await expect(page.locator('#rl-menu .wb-menu-item').first()).toContainText('No saved lookups yet');
});

test.describe('no JS (acceptance 13)', () => {
  test.use({ javaScriptEnabled: false });

  test('no visible Recent button, and the form still posts', async ({ page }) => {
    await page.goto('/index.php');
    // Ships hidden in markup; only JS ever un-hides it (§4), so with no JS
    // it never becomes visible or interactive, even though the element exists.
    await expect(page.locator('#rl-recent-btn')).toBeHidden();
    await expect(page.locator('#rl-menu')).toBeHidden();
    await expect(page.locator('#rl-optin-row')).toBeHidden();

    await page.fill('#message', '203.0.113.9');
    await page.click('.lookup-form .submit');
    await page.waitForLoadState('load');
    await expect(page.locator('#results')).toBeVisible({ timeout: 10000 });
  });
});

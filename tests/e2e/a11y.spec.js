// @ts-check
/**
 * D16 accessibility scan: @axe-core/playwright over the results page and
 * the Phase 2 workbench, failing on serious or critical issues (design doc
 * Pass 6 / DT13).
 */

const { test, expect } = require('@playwright/test');
const AxeBuilder = require('@axe-core/playwright').default;

function seriousOrCritical(results) {
  return results.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical');
}

test.describe('D16: accessibility scan', () => {
  test('the lookup page (pre-results) has no serious/critical axe violations', async ({ page }) => {
    await page.goto('/index.php');
    const results = await new AxeBuilder({ page }).analyze();
    expect(seriousOrCritical(results), JSON.stringify(seriousOrCritical(results), null, 2)).toEqual([]);
  });

  test('the Phase 2 workbench, after a lookup, has no serious/critical axe violations', async ({ page }) => {
    await page.route('**/u/**', (route) => route.fulfill({ status: 200, contentType: 'application/javascript', body: '/* stub */' }));
    // A drop: true row so abbr.drop-tag and the .lookup-summary-drop abbr
    // (the DROP explainer, tap-to-explain via assets/js/abbr-popover.js)
    // render during this scan — they're skipped by non-DROP addresses,
    // which is how IPG-190's aria-allowed-attr violation escaped CI.
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
    await page.fill('#message', 'sample log with 45.93.20.223 and 8.8.8.8');
    await page.click('.lookup-form .submit');
    await page.waitForSelector('#workbench-root:not([hidden])', { timeout: 10000 });
    await expect(page.locator('abbr.drop-tag').first()).toBeVisible();

    const results = await new AxeBuilder({ page }).include('#workbench-root').analyze();
    expect(seriousOrCritical(results), JSON.stringify(seriousOrCritical(results), null, 2)).toEqual([]);
  });

  test('the Export menu is keyboard operable (arrow/Enter/Esc, D16 menu-button pattern)', async ({ page }) => {
    await page.route('**/u/**', (route) => route.fulfill({ status: 200, contentType: 'application/javascript', body: '/* stub */' }));
    await page.goto('/index.php');
    await page.fill('#message', '203.0.113.9');
    await page.click('.lookup-form .submit');
    await page.waitForSelector('#workbench-root:not([hidden])', { timeout: 10000 });

    const btn = page.locator('.wb-export-btn');
    await btn.focus();
    await expect(btn).toHaveAttribute('aria-expanded', 'false');
    await page.keyboard.press('Enter');
    await expect(btn).toHaveAttribute('aria-expanded', 'true');
    await page.keyboard.press('ArrowDown');
    await page.keyboard.press('Escape');
    await expect(btn).toHaveAttribute('aria-expanded', 'false');
    await expect(btn).toBeFocused();
  });

  test('arrow-key navigation skips the group labels and reaches iptables (IPG-32 menu groups)', async ({ page }) => {
    await page.route('**/u/**', (route) => route.fulfill({ status: 200, contentType: 'application/javascript', body: '/* stub */' }));
    await page.goto('/index.php');
    await page.fill('#message', '203.0.113.9');
    await page.click('.lookup-form .submit');
    await page.waitForSelector('#workbench-root:not([hidden])', { timeout: 10000 });

    const btn = page.locator('.wb-export-btn');
    await btn.focus();
    await page.keyboard.press('Enter');
    for (let i = 0; i < 4; i++) {
      await page.keyboard.press('ArrowDown');
    }
    const focused = page.locator('.wb-menu-item:focus');
    await expect(focused).toContainText('iptables');
  });

  // IPG-41/IPG-30 spec §11 item 14: the Recent menu must pass with the menu
  // open and closed, in both themes.
  test('the Recent menu has no serious/critical axe violations, open and closed, in light and dark', async ({ page }) => {
    // body has a 200ms background-color/color transition on theme switch
    // (disabled under prefers-reduced-motion). Without this, the immediate
    // axe scan after setAttribute('data-theme', ...) below can sample a color
    // mid-transition and report a false contrast violation.
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await page.goto('/index.php');
    await page.evaluate(() => {
      localStorage.setItem('rl_optin', '1');
      localStorage.setItem('rl_list', JSON.stringify([
        { ips: ['203.0.113.9', '198.51.100.5', '9.9.9.9'], count: 3, ts: Date.now() },
      ]));
    });
    await page.reload();
    await expect(page.locator('#rl-recent-btn')).toBeVisible();

    // Scoped to the Recent control itself (like the workbench-scoped test
    // above) so this doesn't also assert on unrelated, pre-existing page
    // content — this ticket is the Recent menu, not a full-page theme audit.
    for (const theme of ['dark', 'light']) {
      await page.evaluate((t) => document.documentElement.setAttribute('data-theme', t), theme);

      const closedResults = await new AxeBuilder({ page }).include('.actions-row').analyze();
      expect(seriousOrCritical(closedResults), `${theme}, closed: ` + JSON.stringify(seriousOrCritical(closedResults), null, 2)).toEqual([]);

      // Keyboard-open (not .click()): opening via a pointer click leaves the
      // first item's programmatic focus() without :focus-visible in Chromium,
      // which hid the IPG-92 contrast bug from a mouse-driven scan. Real
      // keyboard users (the D16 menu-button pattern this menu implements)
      // always get :focus-visible here, so the scan must match that path.
      await page.locator('#rl-recent-btn').focus();
      await page.keyboard.press('Enter');
      await expect(page.locator('#rl-menu')).toBeVisible();

      const openResults = await new AxeBuilder({ page }).include('.actions-row').analyze();
      expect(seriousOrCritical(openResults), `${theme}, open: ` + JSON.stringify(seriousOrCritical(openResults), null, 2)).toEqual([]);

      await page.keyboard.press('Escape');
      await expect(page.locator('#rl-menu')).toBeHidden();
    }
  });

  test('the Recent menu is keyboard operable (arrow/Home/End/Esc, D16 menu-button pattern)', async ({ page }) => {
    await page.goto('/index.php');
    await page.evaluate(() => {
      localStorage.setItem('rl_optin', '1');
      localStorage.setItem('rl_list', JSON.stringify([
        { ips: ['203.0.113.9'], count: 1, ts: Date.now() },
        { ips: ['198.51.100.5'], count: 1, ts: Date.now() },
      ]));
    });
    await page.reload();

    const btn = page.locator('#rl-recent-btn');
    await btn.focus();
    await expect(btn).toHaveAttribute('aria-expanded', 'false');
    await page.keyboard.press('Enter');
    await expect(btn).toHaveAttribute('aria-expanded', 'true');

    const items = page.locator('#rl-menu .wb-menu-item');
    await expect(items.first()).toBeFocused();
    await page.keyboard.press('End');
    await expect(items.last()).toBeFocused();
    await expect(items.last()).toHaveClass(/rl-menu-clear/);
    await page.keyboard.press('Home');
    await expect(items.first()).toBeFocused();

    await page.keyboard.press('Escape');
    await expect(btn).toHaveAttribute('aria-expanded', 'false');
    await expect(btn).toBeFocused();
  });
});

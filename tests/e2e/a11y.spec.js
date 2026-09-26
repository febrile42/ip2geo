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
    await page.goto('/index.php');
    await page.fill('#message', 'sample log with 203.0.113.9 and 2606:4700:4700::1111');
    await page.click('.lookup-form .submit');
    await page.waitForSelector('#workbench-root:not([hidden])', { timeout: 10000 });

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
});

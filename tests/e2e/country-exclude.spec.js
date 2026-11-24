// @ts-check
/**
 * "Countries to exclude" must give the same result with and without
 * JavaScript. v5.0.0-5.0.1 shipped a workbench that ignored the field (only
 * the no-JS fallback honored it), and every unit test passed because none of
 * them compared the two paths. This spec runs the same paste through both,
 * end to end against the real /api/lookup.php and the .mmdb test fixtures,
 * and asserts they show the same IPs.
 *
 * Fixture countries: 81.2.69.142 GB, 2.125.160.216 GB, 216.160.83.56 US,
 * 89.160.20.112 SE, 175.16.199.0 CN, 2001:218::1 JP.
 */
const { test, expect } = require('@playwright/test');

const PASTE = [
  'sshd[1]: Failed password for root from 81.2.69.142 port 22',
  'sshd[2]: Failed password for root from 2.125.160.216 port 22',
  'sshd[3]: Failed password for root from 216.160.83.56 port 22',
  'sshd[4]: Failed password for root from 89.160.20.112 port 22',
  'sshd[5]: Failed password for root from 175.16.199.0 port 22',
  'sshd[6]: Failed password for root from 2001:218::1 port 22',
].join('\n');

const CASES = [
  { exclude: 'gb', expected: ['175.16.199.0', '2001:218::1', '216.160.83.56', '89.160.20.112'], excluded: 2 },
  { exclude: 'US CN jp', expected: ['2.125.160.216', '81.2.69.142', '89.160.20.112'], excluded: 3 },
  { exclude: 'ZZ', expected: ['175.16.199.0', '2.125.160.216', '2001:218::1', '216.160.83.56', '81.2.69.142', '89.160.20.112'], excluded: 0 },
  // 5.0.3: other separators, which must behave identically on both paths
  { exclude: 'GB,JP', expected: ['175.16.199.0', '216.160.83.56', '89.160.20.112'], excluded: 3 },
  { exclude: 'us, cn; se', expected: ['2.125.160.216', '2001:218::1', '81.2.69.142'], excluded: 3 },
];

async function jsPath(page, exclude) {
  await page.goto('/index.php');
  await page.fill('#message', PASTE);
  await page.fill('#countries_filter', exclude);
  await page.click('#iplookup input[type=submit]');
  await expect(page.locator('#workbench-root .wb-body')).toBeVisible();
  const ips = await page.locator('#workbench-root .wb-table tbody:not(.wb-unresolved-rows) tr td:first-child')
    .evaluateAll((tds) => tds.map((td) => (td.querySelector('.ip-full') || td).textContent.trim().split(/\s/)[0]));
  const notice = page.locator('#workbench-root .wb-excluded');
  return { ips: ips.sort(), notice: (await notice.count()) ? await notice.textContent() : '' };
}

async function noJsPath(browser, exclude) {
  const ctx = await browser.newContext({ javaScriptEnabled: false });
  const page = await ctx.newPage();
  await page.goto('/index.php');
  await page.fill('#message', PASTE);
  await page.fill('#countries_filter', exclude);
  await page.click('#iplookup input[type=submit]');
  await expect(page.locator('#results-table')).toBeVisible();
  const ips = await page.locator('#results-table tbody td.cell-ip')
    .evaluateAll((tds) => tds.map((td) => (td.querySelector('.ip-full') || td).textContent.trim().split(/\s/)[0]));
  await ctx.close();
  return ips.sort();
}

for (const c of CASES) {
  test(`excluding "${c.exclude}" shows the same IPs with and without JavaScript`, async ({ page, browser }) => {
    const js = await jsPath(page, c.exclude);
    const nojs = await noJsPath(browser, c.exclude);
    expect(nojs).toEqual(c.expected);
    expect(js.ips).toEqual(c.expected);
    if (c.excluded === 0) {
      expect(js.notice).toBe(''); // nothing matched: no "0 IPs excluded" notice
    } else {
      expect(js.notice).toContain(`${c.excluded} IP${c.excluded === 1 ? '' : 's'} excluded by country filter`);
    }
  });
}

test('an empty field excludes nothing and shows no notice', async ({ page }) => {
  await page.goto('/index.php');
  await page.fill('#message', PASTE);
  await page.click('#iplookup input[type=submit]');
  await expect(page.locator('#workbench-root .wb-body')).toBeVisible();
  await expect(page.locator('#workbench-root .wb-table tbody:not(.wb-unresolved-rows) tr')).toHaveCount(6);
  await expect(page.locator('#workbench-root .wb-excluded')).toHaveCount(0);
});

test('excluded IPs are left out of the CSV export and the IP count', async ({ page, context }) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  await page.goto('/index.php');
  await page.fill('#message', PASTE);
  await page.fill('#countries_filter', 'GB');
  await page.click('#iplookup input[type=submit]');
  await expect(page.locator('#workbench-root .wb-excluded')).toBeVisible();
  await expect(page.locator('.wb-export-count')).toHaveText('4 IPs');
  await page.click('.wb-export-btn');
  await page.locator('.wb-menu-item', { hasText: 'CSV' }).click();
  const csv = await page.evaluate(() => navigator.clipboard.readText());
  expect(csv).toContain('216.160.83.56');
  expect(csv).not.toContain('81.2.69.142');
  expect(csv).not.toContain('2.125.160.216');
});

// @ts-check
/**
 * R3 privacy spec (design doc D5 = A, "Two protections + tested"): opens
 * two different pastes and two different #v= share links against a real
 * local server, records every network request, and asserts:
 *   1. no pasted log text appears in any request (URL, headers or body)
 *   2. IPs appear only in the /api/lookup.php request body
 *   3. no fragment content appears in any /u/ (Umami) request
 *
 * Runs against `php -S` (started by playwright.config.js's webServer)
 * using the mmdb test fixtures copied into data/geoip/ (gitignored; see
 * the worktree setup — tests/fixtures/mmdb/*.mmdb copied to
 * data/geoip/GeoLite2-{City,ASN}.mmdb) and a local, gitignored config.php
 * pointing GEOIP_MMDB_DIR there.
 *
 * The Umami tracker only loads when HTTP_HOST === 'ip2geo.org' in
 * production; this spec runs against 127.0.0.1, so index.php and
 * includes/page-chrome.php also check
 * getenv('IP2GEO_E2E_FORCE_UMAMI') === '1' (an explicit, narrow,
 * test-only seam — see the comment beside both `if` checks) so the
 * privacy protection is actually exercised end to end rather than
 * trivially passing because the script tag never renders locally. /u/
 * itself isn't a real Umami install here — it's stubbed via
 * page.route() so the spec has no external dependency.
 */

const { test, expect } = require('@playwright/test');
const path = require('path');
const Share = require(path.resolve(__dirname, '../../assets/js/share-link.js'));

const PASTE_A = 'auth log: Accepted publickey for admin from 203.0.113.9 port 51000 ssh2 — SECRET-LOG-MARKER-A';
const PASTE_B = 'firewall drop: src=198.51.100.42 dst=10.0.0.5 SECRET-LOG-MARKER-B, also 2606:4700:4700::1111';

/** Collects every request's method/url/headers/postData for later assertion. */
function recordRequests(page) {
  const requests = [];
  page.on('request', (req) => {
    requests.push({
      url: req.url(),
      method: req.method(),
      headers: req.headers(),
      postData: req.postData() || '',
    });
  });
  return requests;
}

async function stubUmami(page) {
  await page.route('**/u/**', (route) => {
    if (route.request().url().endsWith('script.js')) {
      route.fulfill({ status: 200, contentType: 'application/javascript', body: '/* stub */' });
    } else {
      route.fulfill({ status: 200, contentType: 'application/json', body: '{}' });
    }
  });
}

function assertNoLeak(requests, secrets) {
  for (const req of requests) {
    const haystack = req.url + '\n' + JSON.stringify(req.headers) + '\n' + req.postData;
    for (const secret of secrets) {
      expect(haystack, `request ${req.method} ${req.url} must not contain ${JSON.stringify(secret)}`).not.toContain(secret);
    }
  }
}

function lookupBodies(requests) {
  return requests.filter((r) => r.url.includes('/api/lookup.php') && r.method === 'POST');
}

function umamiRequests(requests) {
  return requests.filter((r) => r.url.includes('/u/'));
}

test.describe('R3: no log text or fragment content leaks to any request', () => {
  test.use({ extraHTTPHeaders: {} });

  test('two different pastes: log text stays out of every request; IPs only in the lookup body', async ({ page }) => {
    await stubUmami(page);
    const requests = recordRequests(page);

    await page.goto('/index.php');
    await page.fill('#message', PASTE_A);
    await page.click('.lookup-form .submit');
    await page.waitForSelector('#workbench-root:not([hidden])', { timeout: 10000 });
    await page.waitForFunction(() => {
      const el = document.querySelector('.wb-shown-count');
      return el && el.textContent && el.textContent !== '';
    });

    // Second, independent paste: a fresh page load keeps this deterministic
    // regardless of how "New lookup" resets workbench state.
    await page.goto('/index.php');
    await page.fill('#message', PASTE_B);
    await page.click('.lookup-form .submit');
    await page.waitForSelector('#workbench-root:not([hidden])', { timeout: 10000 });

    assertNoLeak(requests, ['SECRET-LOG-MARKER-A', 'SECRET-LOG-MARKER-B', 'Accepted publickey', 'firewall drop']);

    const lookups = lookupBodies(requests);
    expect(lookups.length).toBeGreaterThan(0);
    for (const req of lookups) {
      const parsed = JSON.parse(req.postData);
      expect(Array.isArray(parsed.ips)).toBe(true);
      for (const ip of parsed.ips) {
        expect(ip).toMatch(/^[0-9a-fA-F:.]+$/); // an IP-shaped token, never log prose
      }
    }
  });

  test('two different #v= share links: no fragment content reaches any request, especially /u/', async ({ page }) => {
    const stateOne = { ips: ['203.0.113.9', '198.51.100.42'], categories: ['scanning'], countries: ['US'], search: '' };
    const stateTwo = { ips: ['2606:4700:4700::1111', '192.0.2.55'], categories: [], countries: ['DE'], search: '' };
    const payloadOne = Share.encodeShareState(stateOne);
    const payloadTwo = Share.encodeShareState(stateTwo);

    await stubUmami(page);
    const requestsOne = recordRequests(page);
    await page.goto('/index.php#v=' + payloadOne);
    await page.waitForSelector('.wb-recipient-banner:not([hidden])', { timeout: 10000 });

    const hashAfterLoadOne = await page.evaluate(() => window.location.hash);
    expect(hashAfterLoadOne).toBe(''); // R3: stripped into memory before the tracker loads
    assertNoLeak(requestsOne, [payloadOne]);
    expect(umamiRequests(requestsOne).some((r) => r.url.includes(payloadOne))).toBe(false);

    // A navigation that differs only by fragment from the current URL is a
    // same-document navigation in Chromium (like clicking an in-page anchor)
    // — it does NOT reload the document, so index.php's <head> inline
    // strip-the-fragment script wouldn't re-run. Going through about:blank
    // forces a real reload for the second link, matching how a recipient
    // would actually arrive (a fresh tab/window on someone else's link).
    await page.goto('about:blank');
    const requestsTwo = recordRequests(page);
    await page.goto('/index.php#v=' + payloadTwo);
    await page.waitForSelector('.wb-recipient-banner:not([hidden])', { timeout: 10000 });

    const hashAfterLoadTwo = await page.evaluate(() => window.location.hash);
    expect(hashAfterLoadTwo).toBe('');
    assertNoLeak(requestsTwo, [payloadTwo, payloadOne]);
    expect(umamiRequests(requestsTwo).some((r) => r.url.includes(payloadTwo))).toBe(false);

    // The recipient's re-lookup must still only ever send IPs, never the fragment payload.
    const lookups = lookupBodies(requestsTwo);
    expect(lookups.length).toBeGreaterThan(0);
    const parsed = JSON.parse(lookups[0].postData);
    expect(parsed.ips).toEqual(expect.arrayContaining(stateTwo.ips));
  });
});

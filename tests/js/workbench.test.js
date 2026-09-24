/**
 * Tests for assets/js/workbench.js: the DOM-facing orchestration layer on
 * top of filters.js / export-templates.js / summary.js / share-link.js.
 * Covers buildRows(), ipv6MiddleTruncate(), the 30-day export hint, a
 * renderAll() smoke test against a DOM fixture, and runLookup()'s D6 state
 * handling against a mocked fetch.
 */

'use strict';

var WB = require('../../assets/js/workbench.js');

function buildDom() {
  document.body.innerHTML = `
    <div id="workbench-root" hidden>
      <div class="wb-toast-host"></div>
      <div class="wb-paste-bar"></div>
      <div class="wb-state" hidden></div>
      <div class="wb-body">
        <div class="wb-summary lookup-summary" role="status"></div>
        <div class="wb-export-hint" hidden></div>
        <div class="wb-chips-category"></div>
        <div class="wb-chips-country"></div>
        <div class="wb-export"></div>
        <button type="button" class="wb-share-btn"></button>
        <button type="button" class="wb-share-download" hidden></button>
        <button type="button" class="wb-toggle-unresolved" hidden></button>
        <button type="button" class="wb-clear-filters" hidden></button>
        <span class="wb-shown-count"></span>
        <p class="wb-empty-filter" hidden>No IPs match the current filter.</p>
        <table class="wb-table">
          <caption>Lookup results, one row per IP address</caption>
          <thead><tr>
            <th data-key="ip">IP</th><th data-key="country">CC</th><th data-key="region">Region</th>
            <th data-key="city">City</th><th data-key="asn">ASN</th><th data-key="asnOrg">ASN Org</th>
            <th data-key="category">Category</th><th data-key="hits" aria-sort="descending">Hits</th>
          </tr></thead>
          <tbody></tbody>
          <tbody class="wb-unresolved-rows" hidden></tbody>
        </table>
        <div class="wb-table-sentinel"></div>
      </div>
    </div>
  `;
  return document.getElementById('workbench-root');
}

describe('buildRows', () => {
  test('combines api results with client-side hit counts, defaulting to 1', () => {
    var apiResults = [
      { ip: '1.1.1.1', country_iso_code: 'US', country_name: 'United States', subdivision_1_name: 'CA', city_name: 'Fremont', autonomous_system_number: 14061, autonomous_system_org: 'DigitalOcean, LLC', category: 'cloud', drop: false },
      { ip: '2.2.2.2', country_iso_code: 'CN', country_name: 'China', subdivision_1_name: '', city_name: '', autonomous_system_number: 4134, autonomous_system_org: 'Chinanet', category: 'scanning', drop: true },
    ];
    var rows = WB.buildRows(apiResults, { '1.1.1.1': 5 });
    expect(rows[0]).toEqual({
      ip: '1.1.1.1', country: 'US', countryName: 'United States', region: 'CA', city: 'Fremont',
      asn: 'AS14061', asnOrg: 'DigitalOcean, LLC', category: 'cloud', drop: false, hits: 5
    });
    expect(rows[1].hits).toBe(1); // no entry in hitCounts -> defaults to 1
    expect(rows[1].drop).toBe(true);
  });
});

describe('ipv6MiddleTruncate', () => {
  test('leaves short addresses alone', () => {
    expect(WB.ipv6MiddleTruncate('::1')).toBe('::1');
  });

  test('middle-truncates long addresses the same way index.php does', () => {
    // Matches index.php's ipv6_middle_truncate(): substr($ip, 0, 8) . '…:' . substr($ip, -4) — 8 leading chars, not the full first group.
    expect(WB.ipv6MiddleTruncate('2001:0db8:0000:0000:0000:0000:0000:7334')).toBe('2001:0db…:7334');
  });
});

describe('maybeShowExportHint (D12 30-day hint)', () => {
  beforeEach(() => {
    buildDom();
    window.localStorage.clear();
  });

  test('shows the hint the first time (seeds the timestamp)', () => {
    var root = document.getElementById('workbench-root');
    WB.maybeShowExportHint(root);
    var hint = root.querySelector('.wb-export-hint');
    expect(hint.hidden).toBe(false);
    expect(hint.textContent).toContain('Firewall rules moved here');
    expect(window.localStorage.getItem(WB.EXPORT_HINT_KEY)).not.toBeNull();
  });

  test('hides itself once the hint is older than 30 days', () => {
    var root = document.getElementById('workbench-root');
    var old = Date.now() - (WB.EXPORT_HINT_DAYS + 1) * 86400000;
    window.localStorage.setItem(WB.EXPORT_HINT_KEY, String(old));
    WB.maybeShowExportHint(root);
    expect(root.querySelector('.wb-export-hint').hidden).toBe(true);
  });
});

describe('renderAll smoke test', () => {
  var root;
  beforeEach(() => {
    root = buildDom();
  });

  function rows() {
    return [
      { ip: '1.1.1.1', country: 'US', region: 'CA', city: 'Fremont', asn: 'AS14061', asnOrg: 'DigitalOcean, LLC', category: 'cloud', drop: false, hits: 5 },
      { ip: '2.2.2.2', country: 'CN', region: '', city: '', asn: 'AS4134', asnOrg: 'Chinanet', category: 'scanning', drop: true, hits: 12 },
      { ip: '3.3.3.3', country: 'US', region: 'NY', city: 'New York', asn: 'AS16509', asnOrg: 'Amazon.com, Inc.', category: 'cloud', drop: false, hits: 1 },
    ];
  }

  test('renders every row, the shown count, and table rows sorted by hits desc', () => {
    var state = WB.makeState();
    state.rows = rows();
    WB.renderAll(root, state);

    expect(root.querySelector('.wb-shown-count').textContent).toBe('3 shown');
    var trs = root.querySelectorAll('.wb-table tbody tr');
    expect(trs.length).toBe(3);
    expect(trs[0].querySelector('.cell-ip').textContent).toBe('2.2.2.2'); // hits=12, sorted first
  });

  test('the Export button has WAI-ARIA menu-button attributes (D16)', () => {
    var state = WB.makeState();
    state.rows = rows();
    WB.renderAll(root, state);
    var btn = root.querySelector('.wb-export-btn');
    expect(btn.getAttribute('aria-haspopup')).toBe('true');
    expect(btn.getAttribute('aria-expanded')).toBe('false');
    var menu = root.querySelector('.wb-menu');
    expect(menu.getAttribute('role')).toBe('menu');
  });

  test('category chip click filters the table (D10)', () => {
    var state = WB.makeState();
    state.rows = rows();
    WB.renderAll(root, state);

    var scanningChip = Array.from(root.querySelectorAll('.wb-chips-category .wb-chip'))
      .find(function (l) { return l.textContent.indexOf('Scanning') !== -1; });
    expect(scanningChip).toBeTruthy();
    scanningChip.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true }));

    expect(root.querySelector('.wb-shown-count').textContent).toBe('1 shown');
    expect(root.querySelector('.wb-clear-filters').hidden).toBe(false);
  });

  test('DROP tag appears in the category cell for drop rows', () => {
    var state = WB.makeState();
    state.rows = rows();
    WB.renderAll(root, state);
    var dropTags = root.querySelectorAll('.drop-tag');
    expect(dropTags.length).toBe(1);
    expect(dropTags[0].tagName).toBe('ABBR');
    expect(dropTags[0].getAttribute('title')).toMatch(/Don't Route Or Peer/);
  });

  test('table has a caption and aria-sort on the sorted column', () => {
    var state = WB.makeState();
    state.rows = rows();
    WB.renderAll(root, state);
    expect(root.querySelector('.wb-table caption')).toBeTruthy();
    expect(root.querySelector('.wb-table th[data-key="hits"]').getAttribute('aria-sort')).toBe('descending');
  });
});

describe('renderSummary (bug: the summary bar rendered empty because nothing ever called buildSummary)', () => {
  var root;
  beforeEach(() => {
    root = buildDom();
  });

  function rows() {
    return [
      { ip: '1.1.1.1', country: 'US', region: 'CA', city: 'Fremont', asn: 'AS14061', asnOrg: 'DigitalOcean, LLC', category: 'cloud', drop: false, hits: 5 },
      { ip: '2.2.2.2', country: 'CN', region: '', city: '', asn: 'AS4134', asnOrg: 'Chinanet', category: 'scanning', drop: true, hits: 12 },
      { ip: '3.3.3.3', country: 'US', region: 'NY', city: 'New York', asn: 'AS16509', asnOrg: 'Amazon.com, Inc.', category: 'cloud', drop: false, hits: 1 },
    ];
  }

  test('renders non-empty text into .wb-summary for a fixture result set', () => {
    var state = WB.makeState();
    state.rows = rows();
    WB.renderSummary(root, state);

    var host = root.querySelector('.wb-summary');
    expect(host.textContent.trim()).not.toBe('');
    expect(host.textContent).toMatch(/3 IPs looked up/);
    expect(host.textContent).toMatch(/Spamhaus DROP netblocks/);
  });

  test('top ASNs carry the org name from table rows (bug: rows use asnOrg, buildSummary reads asn_org)', () => {
    var state = WB.makeState();
    state.rows = rows();
    WB.renderSummary(root, state);
    expect(root.querySelector('.wb-summary').textContent).toMatch(/AS14061 DigitalOcean, LLC/);
  });

  test('is fixed (not filter-driven): still describes every resolved row after a chip filters the table', () => {
    var state = WB.makeState();
    state.rows = rows();
    WB.renderSummary(root, state);
    var before = root.querySelector('.wb-summary').textContent;

    WB.renderAll(root, state); // build chips/table so there's something to click
    var scanningChip = Array.from(root.querySelectorAll('.wb-chips-category .wb-chip'))
      .find(function (l) { return l.textContent.indexOf('Scanning') !== -1; });
    scanningChip.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true }));

    expect(root.querySelector('.wb-shown-count').textContent).toBe('1 shown');
    expect(root.querySelector('.wb-summary').textContent).toBe(before);
  });

  test('joins facts with " · " (space, middot, space) — no run-together separators', () => {
    var state = WB.makeState();
    state.rows = rows();
    WB.renderSummary(root, state);
    var facts = Array.from(root.querySelectorAll('.wb-summary .lookup-summary-fact')).map(function (f) { return f.textContent; });
    expect(facts.length).toBeGreaterThan(1);
    // Each fact is its own element with no leading/trailing space of its
    // own; the " · " separator is CSS generated content (::before) between
    // adjacent .lookup-summary-fact siblings, so nothing here should carry
    // a stray leading/trailing space that would double up with it.
    facts.forEach(function (t) { expect(t).toBe(t.trim()); });
  });
});

describe('renderUnresolved (bug: "Show N unresolved" never appeared)', () => {
  var root;
  beforeEach(() => {
    root = buildDom();
  });

  test('hides the toggle when there are no unresolved IPs', () => {
    var state = WB.makeState();
    state.rows = [];
    state.unresolved = [];
    WB.renderUnresolved(root, state);
    expect(root.querySelector('.wb-toggle-unresolved').hidden).toBe(true);
  });

  test('shows "Show N unresolved" and reveals rows on click', () => {
    var state = WB.makeState();
    state.rows = [];
    state.unresolved = ['not-an-ip', '999.1.2.3'];
    WB.renderUnresolved(root, state);

    var btn = root.querySelector('.wb-toggle-unresolved');
    expect(btn.hidden).toBe(false);
    expect(btn.textContent).toBe('Show 2 unresolved IPs');

    var body = root.querySelector('.wb-unresolved-rows');
    expect(body.hidden).toBe(true);
    btn.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true }));
    expect(body.hidden).toBe(false);
    expect(btn.textContent).toBe('Hide 2 unresolved IPs');
    expect(body.querySelectorAll('tr').length).toBe(2);
  });
});

describe('formatLookupTime (bug: always showed "0.0 s" for sub-100ms lookups)', () => {
  test('shows "<0.1 s" under 100ms', () => {
    expect(WB.formatLookupTime(42)).toBe('<0.1 s');
  });
  test('shows one decimal place at and above 100ms', () => {
    expect(WB.formatLookupTime(342)).toBe('0.3 s');
    expect(WB.formatLookupTime(1000)).toBe('1.0 s');
  });
});

describe('runLookup D6 states', () => {
  var root;
  beforeEach(() => {
    root = buildDom();
    root.hidden = false;
  });
  afterEach(() => {
    delete global.fetch;
  });

  test('429 renders the rate-limit message using Retry-After', () => {
    global.fetch = jest.fn().mockResolvedValue({
      status: 429,
      ok: false,
      headers: { get: function () { return '42'; } }
    });
    var state = WB.makeState();
    return WB.runLookup(root, state, ['1.1.1.1'], {}, { lines: 1, unique: 1, v6: 0 }).then(function (ok) {
      expect(ok).toBe(false);
      expect(root.querySelector('.wb-state').textContent).toContain('Try again in 42s');
    });
  });

  test('503 renders the "data is updating" message', () => {
    global.fetch = jest.fn().mockResolvedValue({ status: 503, ok: false, headers: { get: function () { return null; } } });
    var state = WB.makeState();
    return WB.runLookup(root, state, ['1.1.1.1'], {}, { lines: 1, unique: 1, v6: 0 }).then(function (ok) {
      expect(ok).toBe(false);
      expect(root.querySelector('.wb-state').textContent).toContain('Lookup data is updating');
    });
  });

  test('network failure renders a retry-able notice and keeps the paste', () => {
    global.fetch = jest.fn().mockRejectedValue(new Error('offline'));
    var state = WB.makeState();
    return WB.runLookup(root, state, ['1.1.1.1'], {}, { lines: 1, unique: 1, v6: 0 }).then(function (ok) {
      expect(ok).toBe(false);
      expect(root.querySelector('.wb-state').textContent).toContain('Your paste is still here');
      expect(root.querySelector('.wb-state button')).toBeTruthy(); // Retry
    });
  });

  test('success renders the workbench body', () => {
    global.fetch = jest.fn().mockResolvedValue({
      status: 200,
      ok: true,
      json: function () {
        return Promise.resolve({
          results: [{ ip: '1.1.1.1', country_iso_code: 'US', autonomous_system_number: 1, autonomous_system_org: 'Org', category: 'cloud', drop: false }],
          unresolved: []
        });
      }
    });
    var state = WB.makeState();
    return WB.runLookup(root, state, ['1.1.1.1'], { '1.1.1.1': 3 }, { lines: 1, unique: 1, v6: 0 }).then(function (ok) {
      expect(ok).toBe(true);
      expect(root.querySelector('.wb-state').hidden).toBe(true);
      expect(root.querySelector('.wb-body').hidden).toBe(false);
      expect(root.querySelector('.wb-shown-count').textContent).toBe('1 shown');
    });
  });
});

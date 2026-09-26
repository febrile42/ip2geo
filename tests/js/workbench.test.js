/**
 * Tests for assets/js/workbench.js: the DOM-facing orchestration layer on
 * top of filters.js / export-templates.js / summary.js / share-link.js.
 * Covers buildRows(), ipv6MiddleTruncate(), a renderAll() smoke test against
 * a DOM fixture, and runLookup()'s D6 state handling against a mocked fetch.
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
        <div class="wb-chips-category"></div>
        <div class="wb-chips-country"></div>
        <div class="wb-export"></div>
        <button type="button" class="wb-share-btn"></button>
        <button type="button" class="wb-share-download" hidden></button>
        <p class="wb-share-notice"></p>
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

describe('Export / Rules button and menu groups (IPG-32)', () => {
  var root;
  beforeEach(() => {
    root = buildDom();
  });

  function rows() {
    return [
      { ip: '1.1.1.1', country: 'US', region: 'CA', city: 'Fremont', asn: 'AS14061', asnOrg: 'DigitalOcean, LLC', category: 'cloud', drop: false, hits: 5 },
    ];
  }

  test('the Export button label starts with "Export / Rules" and wraps the caret in an aria-hidden span', () => {
    var state = WB.makeState();
    state.rows = rows();
    WB.renderAll(root, state);

    var btn = root.querySelector('.wb-export-btn');
    expect(btn.textContent.indexOf('Export / Rules')).toBe(0);
    var caret = btn.querySelector('span[aria-hidden="true"]');
    expect(caret).toBeTruthy();
    expect(caret.textContent).toBe('▾');
  });

  test('the menu has two role=group sections labelled "Data & queries" (4 items) and "Block rules" (3 items)', () => {
    var state = WB.makeState();
    state.rows = rows();
    WB.renderAll(root, state);

    var groups = root.querySelectorAll('.wb-menu [role="group"]');
    expect(groups.length).toBe(2);

    var dataGroup = groups[0];
    var dataLabelId = dataGroup.getAttribute('aria-labelledby');
    expect(document.getElementById(dataLabelId).textContent).toBe('Data & queries');
    expect(dataGroup.querySelectorAll('.wb-menu-item').length).toBe(4);

    var rulesGroup = groups[1];
    var rulesLabelId = rulesGroup.getAttribute('aria-labelledby');
    expect(document.getElementById(rulesLabelId).textContent).toBe('Block rules');
    var rulesItems = rulesGroup.querySelectorAll('.wb-menu-item');
    expect(rulesItems.length).toBe(3);
    expect(rulesItems[0].textContent).toContain('iptables');
    expect(rulesItems[1].textContent).toContain('ufw');
    expect(rulesItems[2].textContent).toContain('nginx');
  });

  test('mount() removes wb_export_hint_seen_at from localStorage when present', () => {
    window.localStorage.setItem('wb_export_hint_seen_at', String(Date.now()));
    var form = document.createElement('form');
    var textarea = document.createElement('textarea');
    WB.mount(root, form, textarea);
    expect(window.localStorage.getItem('wb_export_hint_seen_at')).toBeNull();
  });

  test('the D12 hint element is gone from the DOM', () => {
    expect(document.querySelector('.wb-export-hint')).toBeNull();
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

  test('typing in the search box keeps focus and caret, and still filters live (IPG-29)', () => {
    var state = WB.makeState();
    state.rows = rows();
    WB.renderAll(root, state);

    var search = root.querySelector('.wb-search');
    search.focus();
    expect(document.activeElement).toBe(search);

    // Type "1.1.1" one character at a time, the way a real keyboard does,
    // firing a native `input` event (not `fill()`) after each keystroke.
    var term = '1.1.1';
    for (var i = 0; i < term.length; i++) {
      search.value = term.slice(0, i + 1);
      search.setSelectionRange(search.value.length, search.value.length);
      search.dispatchEvent(new Event('input', { bubbles: true }));

      // The re-render triggered by this keystroke must not have rebuilt
      // (and thereby blurred) the input.
      expect(root.querySelector('.wb-search')).toBe(search);
      expect(document.activeElement).toBe(search);
      expect(search.selectionStart).toBe(search.value.length);
    }

    expect(root.querySelector('.wb-shown-count').textContent).toBe('1 shown');

    // Clearing the field (e.g. the native × or a Backspace run) restores all rows.
    search.value = '';
    search.dispatchEvent(new Event('input', { bubbles: true }));
    expect(document.activeElement).toBe(search);
    expect(root.querySelector('.wb-shown-count').textContent).toBe('3 shown');
  });

  test('chip filters still work once the search box has been rendered (IPG-29 regression guard)', () => {
    var state = WB.makeState();
    state.rows = rows();
    WB.renderAll(root, state);

    var scanningChip = Array.from(root.querySelectorAll('.wb-chips-category .wb-chip'))
      .find(function (l) { return l.textContent.indexOf('Scanning') !== -1; });
    scanningChip.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true }));

    expect(root.querySelector('.wb-shown-count').textContent).toBe('1 shown');
    expect(root.querySelectorAll('.wb-search').length).toBe(1);
  });
});

// IPG-42/M1 (IPG-53): the disclosure line and the over-cap "send the file"
// line are mutually exclusive and swap live as filtering changes the view
// size relative to share-link.js's URL_CAP_CHARS. Copy is verbatim (Bilac,
// IPG-50; verified against the code by Psyger, IPG-51) — don't reword it here.
describe('Share-link disclosure / over-cap notice (IPG-42/M1)', () => {
  var root;
  var DISCLOSURE = 'The IPs are in the link itself, not saved on our server. Anyone with the link can see them.';
  var OVER_CAP = 'Filter to fewer IPs to get a link, or download the view file and send that. To open it, the recipient pastes the file\'s contents into ip2geo.';

  beforeEach(() => {
    root = buildDom();
  });

  function row(ip, country) {
    return { ip: ip, country: country || 'US', region: '', city: '', asn: 'AS1', asnOrg: 'Test', category: 'cloud', drop: false, hits: 1 };
  }

  // IPv6 addresses (2001:db8::/32, synthetic per HANDOFF) pack heavier
  // (17 bytes each) than IPv4, so a few hundred are enough to comfortably
  // clear the ~8 KB share-link URL cap without a huge fixture.
  function manyRows(n) {
    var out = [];
    for (var i = 1; i <= n; i++) {
      out.push(row('2001:db8::' + i.toString(16)));
    }
    return out;
  }

  test('shows the disclosure line while the view is under the share-link cap', () => {
    var state = WB.makeState();
    state.rows = [row('198.51.100.1')];
    WB.renderAll(root, state);

    expect(root.querySelector('.wb-share-notice').textContent).toBe(DISCLOSURE);
    expect(root.querySelector('.wb-share-btn').disabled).toBe(false);
  });

  test('shows the over-cap line instead, once the view exceeds the share-link cap', () => {
    var state = WB.makeState();
    state.rows = manyRows(400);
    WB.renderAll(root, state);

    expect(root.querySelector('.wb-share-notice').textContent).toBe(OVER_CAP);
    expect(root.querySelector('.wb-share-btn').disabled).toBe(true);
  });

  test('only one of the two lines ever shows', () => {
    var underState = WB.makeState();
    underState.rows = [row('198.51.100.1')];
    WB.renderAll(root, underState);
    expect(root.querySelectorAll('.wb-share-notice').length).toBe(1);

    var overState = WB.makeState();
    overState.rows = manyRows(400);
    WB.renderAll(root, overState);
    expect(root.querySelectorAll('.wb-share-notice').length).toBe(1);
  });

  test('a filter that brings the view back under the cap swaps the over-cap line for the disclosure live', () => {
    var state = WB.makeState();
    state.rows = manyRows(400).concat([row('198.51.100.9', 'DE')]);
    WB.renderAll(root, state);
    expect(root.querySelector('.wb-share-notice').textContent).toBe(OVER_CAP);

    var deChip = Array.from(root.querySelectorAll('.wb-chips-country .wb-chip'))
      .find(function (l) { return l.textContent.indexOf('DE') !== -1; });
    expect(deChip).toBeTruthy();
    deChip.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true }));

    expect(root.querySelector('.wb-shown-count').textContent).toBe('1 shown');
    expect(root.querySelector('.wb-share-notice').textContent).toBe(DISCLOSURE);
  });

  test('a filter that pushes the view back over the cap swaps the disclosure for the over-cap line live', () => {
    var state = WB.makeState();
    state.rows = manyRows(400).concat([row('198.51.100.9', 'DE')]);
    state.filters = { categories: new Set(), countries: new Set(['DE']), search: '' };
    WB.renderAll(root, state);
    expect(root.querySelector('.wb-shown-count').textContent).toBe('1 shown');
    expect(root.querySelector('.wb-share-notice').textContent).toBe(DISCLOSURE);

    var deChip = Array.from(root.querySelectorAll('.wb-chips-country .wb-chip'))
      .find(function (l) { return l.textContent.indexOf('DE') !== -1; });
    expect(deChip).toBeTruthy();
    deChip.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true })); // deselect DE, back to all rows

    expect(root.querySelector('.wb-shown-count').textContent).toBe('401 shown');
    expect(root.querySelector('.wb-share-notice').textContent).toBe(OVER_CAP);
  });

  test('the share toast reads "Link copied · N IPs", with the disclosure living only in the notice line', () => {
    var state = WB.makeState();
    state.rows = [row('198.51.100.1'), row('198.51.100.2')];
    WB.renderAll(root, state);

    root.querySelector('.wb-share-btn').click();

    var toast = root.querySelector('.wb-toast-host .wb-toast');
    expect(toast).toBeTruthy();
    expect(toast.textContent).toBe('Link copied · 2 IPs');
  });
});

describe('filter_<dim> analytics (D9)', () => {
  var root;

  function rows() {
    return [
      { ip: '1.1.1.1', country: 'US', region: 'CA', city: 'Fremont', asn: 'AS14061', asnOrg: 'DigitalOcean, LLC', category: 'cloud', drop: false, hits: 5 },
      { ip: '2.2.2.2', country: 'CN', region: '', city: '', asn: 'AS4134', asnOrg: 'Chinanet', category: 'scanning', drop: true, hits: 12 },
    ];
  }

  beforeEach(() => {
    root = buildDom();
    window.umami = { track: jest.fn() };
  });

  afterEach(() => {
    delete window.umami;
    jest.useRealTimers();
  });

  test('clicking a category chip fires filter_category with no properties', () => {
    var state = WB.makeState();
    state.rows = rows();
    WB.renderAll(root, state);

    var scanningChip = Array.from(root.querySelectorAll('.wb-chips-category .wb-chip'))
      .find(function (l) { return l.textContent.indexOf('Scanning') !== -1; });
    scanningChip.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true }));

    expect(window.umami.track).toHaveBeenCalledWith('filter_category');
    expect(window.umami.track).not.toHaveBeenCalledWith('filter_category', expect.anything());
  });

  test('clicking a country chip fires filter_country with no properties', () => {
    var state = WB.makeState();
    state.rows = rows();
    WB.renderAll(root, state);

    var usChip = Array.from(root.querySelectorAll('.wb-chips-country .wb-chip'))
      .find(function (l) { return l.textContent.indexOf('US') !== -1; });
    usChip.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true }));

    expect(window.umami.track).toHaveBeenCalledWith('filter_country');
    expect(window.umami.track).not.toHaveBeenCalledWith('filter_country', expect.anything());
  });

  test('typing in the search box fires filter_search once, only after the debounce settles', () => {
    jest.useFakeTimers();
    var state = WB.makeState();
    state.rows = rows();
    WB.renderAll(root, state);

    var search = root.querySelector('.wb-search');
    'digi'.split('').forEach(function (ch) {
      search.value += ch;
      search.dispatchEvent(new Event('input', { bubbles: true }));
    });

    // No event yet -- still within the debounce window, and no value ever sent.
    expect(window.umami.track).not.toHaveBeenCalled();

    jest.advanceTimersByTime(600);

    expect(window.umami.track).toHaveBeenCalledTimes(1);
    expect(window.umami.track).toHaveBeenCalledWith('filter_search');
    expect(window.umami.track).not.toHaveBeenCalledWith('filter_search', expect.anything());
  });

  test('search input never appears in any tracked event payload', () => {
    jest.useFakeTimers();
    var state = WB.makeState();
    state.rows = rows();
    WB.renderAll(root, state);

    var search = root.querySelector('.wb-search');
    search.value = '203.0.113.5'; // looks like an IP typed into the free-text filter
    search.dispatchEvent(new Event('input', { bubbles: true }));
    jest.advanceTimersByTime(600);

    window.umami.track.mock.calls.forEach(function (call) {
      expect(JSON.stringify(call)).not.toMatch(/203\.0\.113\.5/);
    });
  });
});

describe('renderSummary (IPG-33: DROP count + single Top ASN only)', () => {
  var root;
  beforeEach(() => {
    root = buildDom();
  });

  // Two rows on AS14061 (a clear leader over AS16509's one) and one DROP hit,
  // so both facts render.
  function rows() {
    return [
      { ip: '1.1.1.1', country: 'US', region: 'CA', city: 'Fremont', asn: 'AS14061', asnOrg: 'DigitalOcean, LLC', category: 'cloud', drop: true, hits: 5 },
      { ip: '2.2.2.2', country: 'US', region: 'CA', city: 'Fremont', asn: 'AS14061', asnOrg: 'DigitalOcean, LLC', category: 'cloud', drop: false, hits: 3 },
      { ip: '3.3.3.3', country: 'CN', region: '', city: '', asn: 'AS4134', asnOrg: 'Chinanet', category: 'scanning', drop: true, hits: 12 },
    ];
  }

  test('renders the DROP count and Top ASN facts for a fixture result set', () => {
    var state = WB.makeState();
    state.rows = rows();
    WB.renderSummary(root, state);

    var host = root.querySelector('.wb-summary');
    expect(host.hidden).toBe(false);
    expect(host.textContent.trim()).not.toBe('');
    expect(host.textContent).toMatch(/2 IPs in Spamhaus DROP netblocks/);
    expect(host.textContent).toMatch(/Top ASN: AS14061 DigitalOcean, LLC \(2 IPs\)/);
  });

  test('old summary text (total looked up, category counts, "top ASNs") is gone', () => {
    var state = WB.makeState();
    state.rows = rows();
    WB.renderSummary(root, state);
    var text = root.querySelector('.wb-summary').textContent;
    expect(text).not.toMatch(/looked up/);
    expect(text).not.toMatch(/top ASNs/);
    expect(text).not.toMatch(/\(\d+%\)/);
  });

  test('Top ASN carries the org name from table rows (bug: rows use asnOrg, buildSummary reads asn_org)', () => {
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
    expect(facts.length).toBe(2);
    // Each fact is its own element with no leading/trailing space of its
    // own; the " · " separator is CSS generated content (::before) between
    // adjacent .lookup-summary-fact siblings, so nothing here should carry
    // a stray leading/trailing space that would double up with it.
    facts.forEach(function (t) { expect(t).toBe(t.trim()); });
  });

  test('singular grammar for exactly 1 DROP row', () => {
    var state = WB.makeState();
    state.rows = [{ ip: '1.1.1.1', asn: '', asnOrg: '', category: 'scanning', drop: true, hits: 1 }];
    WB.renderSummary(root, state);
    expect(root.querySelector('.wb-summary').textContent).toBe('1 IP in a Spamhaus DROP netblock');
  });

  test('no DROP rows and no clear leader: host is hidden and empty', () => {
    var state = WB.makeState();
    state.rows = [{ ip: '1.1.1.1', asn: 'AS1', asnOrg: 'Org', category: 'cloud', drop: false, hits: 1 }];
    WB.renderSummary(root, state);
    var host = root.querySelector('.wb-summary');
    expect(host.hidden).toBe(true);
    expect(host.textContent.trim()).toBe('');
  });

  test('tied leading ASNs: no Top ASN fact', () => {
    var state = WB.makeState();
    state.rows = [
      { ip: '8.8.8.8', asn: 'AS15169', asnOrg: 'Google LLC', category: 'cloud', drop: false, hits: 1 },
      { ip: '8.8.4.4', asn: 'AS15169', asnOrg: 'Google LLC', category: 'cloud', drop: false, hits: 1 },
      { ip: '1.1.1.1', asn: 'AS13335', asnOrg: 'Cloudflare, Inc.', category: 'cloud', drop: false, hits: 1 },
      { ip: '1.0.0.1', asn: 'AS13335', asnOrg: 'Cloudflare, Inc.', category: 'cloud', drop: false, hits: 1 },
    ];
    WB.renderSummary(root, state);
    expect(root.querySelector('.wb-summary').textContent).not.toMatch(/Top ASN/);
  });

  test('the DROP fact carries the explainer abbr, reachable via abbr-popover.js selectors', () => {
    var state = WB.makeState();
    state.rows = [{ ip: '1.1.1.1', asn: '', asnOrg: '', category: 'scanning', drop: true, hits: 1 }];
    WB.renderSummary(root, state);
    var abbr = root.querySelector('.lookup-summary-drop abbr');
    expect(abbr).toBeTruthy();
    expect(abbr.getAttribute('title')).toMatch(/Don't Route Or Peer/);
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

describe('formatIpSplit (IPG-39: pill/loading-line IPv4/IPv6 split)', () => {
  test('mixed v4 and v6', () => {
    expect(WB.formatIpSplit(3, 2)).toBe('3 IPv4 / 2 IPv6');
  });
  test('v4 only', () => {
    expect(WB.formatIpSplit(5, 0)).toBe('5 IPv4');
  });
  test('v6 only', () => {
    expect(WB.formatIpSplit(0, 4)).toBe('4 IPv6');
  });
  test('formats large counts with a thousands separator', () => {
    expect(WB.formatIpSplit(1234, 0)).toBe('1,234 IPv4');
  });
});

describe('renderPasteBar (IPG-38: New lookup removed, Edit paste kept; IPG-39: pill IPv4/IPv6 split; IPG-41: Recent button removed)', () => {
  var root;
  beforeEach(() => {
    root = buildDom();
  });

  test('renders exactly one button, Edit paste, with no Recent and no New lookup', () => {
    var state = WB.makeState();
    WB.renderPasteBar(root, state, function () {});

    var buttons = root.querySelectorAll('.wb-paste-bar button');
    var labels = Array.prototype.map.call(buttons, function (b) { return b.textContent; });
    expect(labels).toEqual(['Edit paste']);

    var editBtn = root.querySelector('.wb-paste-bar button');
    expect(editBtn.getAttribute('aria-controls')).toBe('message');
  });

  test('hides Edit paste when state.recipient is set (shared-view link), leaving no buttons', () => {
    var state = WB.makeState();
    state.recipient = { count: 3, categories: [], countries: [] };
    WB.renderPasteBar(root, state, function () {});

    var buttons = root.querySelectorAll('.wb-paste-bar button');
    expect(buttons.length).toBe(0);
  });

  test('exposes the raw paste text via root._wbLastRawText() for the Recent-lookups module', () => {
    var state = WB.makeState();
    state.pasteMeta = { lines: 1, v4: 1, v6: 0, overCap: false, lookupMs: null, rawText: '203.0.113.9' };
    WB.renderPasteBar(root, state, function () {});
    expect(typeof root._wbLastRawText).toBe('function');
    expect(root._wbLastRawText()).toBe('203.0.113.9');
  });

  test('singular "1 line" plus the Unique: split', () => {
    var state = WB.makeState();
    state.pasteMeta = { lines: 1, v4: 3, v6: 2, overCap: false, lookupMs: null, rawText: '' };
    WB.renderPasteBar(root, state, () => {});
    expect(root.querySelector('.wb-paste-pill').textContent).toBe('1 line · Unique: 3 IPv4 / 2 IPv6');
  });

  test('plural line count', () => {
    var state = WB.makeState();
    state.pasteMeta = { lines: 4, v4: 3, v6: 2, overCap: false, lookupMs: null, rawText: '' };
    WB.renderPasteBar(root, state, () => {});
    expect(root.querySelector('.wb-paste-pill').textContent).toBe('4 lines · Unique: 3 IPv4 / 2 IPv6');
  });

  test('omits the lines span and separator when lines is null (shared-view recipient form)', () => {
    var state = WB.makeState();
    state.pasteMeta = { lines: null, v4: 3, v6: 2, overCap: false, lookupMs: null, rawText: '' };
    WB.renderPasteBar(root, state, () => {});
    var pill = root.querySelector('.wb-paste-pill');
    expect(pill.textContent).toBe('Unique: 3 IPv4 / 2 IPv6');
    expect(pill.children.length).toBe(1);
  });

  test('labels "Looked up:" instead of "Unique:" when over the cap', () => {
    var state = WB.makeState();
    state.pasteMeta = { lines: 2, v4: 8000, v6: 2000, overCap: true, lookupMs: null, rawText: '' };
    WB.renderPasteBar(root, state, () => {});
    expect(root.querySelector('.wb-paste-pill').textContent).toBe('2 lines · Looked up: 8,000 IPv4 / 2,000 IPv6');
  });

  test('renders exactly one .wb-overcap notice, even across two renders', () => {
    var state = WB.makeState();
    state.pasteMeta = {
      lines: 2, v4: 8000, v6: 2000, overCap: true,
      overCapNotice: 'Looked up the first 10,000 of 12,000 unique IPs. 2,000 skipped. Paste the rest separately to check them.',
      lookupMs: null, rawText: ''
    };
    WB.renderPasteBar(root, state, () => {});
    WB.renderPasteBar(root, state, () => {});
    var notices = root.querySelectorAll('.wb-overcap');
    expect(notices.length).toBe(1);
    expect(notices[0].tagName).toBe('P');
    expect(notices[0].getAttribute('role')).toBe('status');
    expect(notices[0].previousElementSibling).toBe(root.querySelector('.wb-paste-bar'));
  });

  test('a later render without overCapNotice removes the stale notice', () => {
    var state = WB.makeState();
    state.pasteMeta = { lines: 2, v4: 8000, v6: 2000, overCap: true, overCapNotice: 'Looked up the first 10,000…', lookupMs: null, rawText: '' };
    WB.renderPasteBar(root, state, () => {});
    expect(root.querySelectorAll('.wb-overcap').length).toBe(1);

    state.pasteMeta = { lines: 2, v4: 3, v6: 2, overCap: false, lookupMs: null, rawText: '' };
    WB.renderPasteBar(root, state, () => {});
    expect(root.querySelectorAll('.wb-overcap').length).toBe(0);
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
    return WB.runLookup(root, state, ['1.1.1.1'], {}, { lines: 1, v4: 1, v6: 0 }).then(function (ok) {
      expect(ok).toBe(false);
      expect(root.querySelector('.wb-state').textContent).toContain('Try again in 42s');
    });
  });

  test('503 renders the "data is updating" message', () => {
    global.fetch = jest.fn().mockResolvedValue({ status: 503, ok: false, headers: { get: function () { return null; } } });
    var state = WB.makeState();
    return WB.runLookup(root, state, ['1.1.1.1'], {}, { lines: 1, v4: 1, v6: 0 }).then(function (ok) {
      expect(ok).toBe(false);
      expect(root.querySelector('.wb-state').textContent).toContain('Lookup data is updating');
    });
  });

  test('network failure renders a retry-able notice and keeps the paste', () => {
    global.fetch = jest.fn().mockRejectedValue(new Error('offline'));
    var state = WB.makeState();
    return WB.runLookup(root, state, ['1.1.1.1'], {}, { lines: 1, v4: 1, v6: 0 }).then(function (ok) {
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
    return WB.runLookup(root, state, ['1.1.1.1'], { '1.1.1.1': 3 }, { lines: 1, v4: 1, v6: 0 }).then(function (ok) {
      expect(ok).toBe(true);
      expect(root.querySelector('.wb-state').hidden).toBe(true);
      expect(root.querySelector('.wb-body').hidden).toBe(false);
      expect(root.querySelector('.wb-shown-count').textContent).toBe('1 shown');
    });
  });
});

describe('startLookup over-cap arithmetic (IPG-39 count bug)', () => {
  var extractIps = require('../../assets/js/extract-ips.js');

  beforeEach(() => {
    window.extractIps = extractIps;
  });
  afterEach(() => {
    delete window.extractIps;
    delete global.fetch;
  });

  test('v4 + v6 equals the looked-up count (the cap), not the pre-cap total', () => {
    // extracted.v6Count is already post-cap; deriving v4 from the pre-cap
    // extracted.totalUnique (the old bug) would make v4 + v6 disagree with
    // how many IPs were actually looked up once the paste is over the cap.
    var v4Lines = [];
    for (var i = 0; i < 10005; i++) {
      v4Lines.push('198.' + Math.floor(i / 256) + '.' + (i % 256) + '.5');
    }
    var v6Lines = [];
    for (var j = 1; j <= 8; j++) {
      v6Lines.push('2606:4700:4700::' + j.toString(16));
    }
    // v6 lines first so all 8 land inside the first 10,000 first-seen
    // entries even though the v4 lines alone already exceed the cap.
    var rawText = v6Lines.concat(v4Lines).join('\n');

    global.fetch = jest.fn().mockResolvedValue({
      status: 200,
      ok: true,
      json: function () { return Promise.resolve({ results: [], unresolved: [] }); }
    });

    var root = buildDom();
    var form = document.createElement('form');
    var textarea = document.createElement('textarea');
    form.appendChild(textarea);
    document.body.appendChild(form);

    var handle = WB.mount(root, form, textarea);
    return handle.startLookup(rawText).then(function (ok) {
      expect(ok).toBe(true);
      var m = handle.state.pasteMeta;
      expect(m.overCap).toBe(true);
      expect(m.v6).toBe(8);
      expect(m.v4 + m.v6).toBe(10000);
    });
  });
});

// IPG-10 S2: index.php chains .then() on mountSharedView, so a rejected
// share link must still hand back a promise, not null.
describe('mountSharedView with a rejected payload', () => {
  test('resolves false instead of returning null', async () => {
    var p = WB.mountSharedView(document.createElement('div'), 'not-valid-base64!!!', () => { throw new Error('banner must not render'); });
    expect(p).not.toBeNull();
    await expect(p).resolves.toBe(false);
  });
});

describe('mountSharedView (IPG-39: v4/v6 split, recipient pill has no line count)', () => {
  var Share = require('../../assets/js/share-link.js');

  afterEach(() => {
    delete global.fetch;
  });

  test('splits decoded IPs into v4/v6 and the pill omits the lines span', () => {
    var payload = Share.encodeShareState({
      ips: ['1.1.1.1', '2606:4700:4700::1111', '8.8.8.8'],
      categories: [], countries: [], search: ''
    });
    global.fetch = jest.fn().mockResolvedValue({
      status: 200,
      ok: true,
      json: function () { return Promise.resolve({ results: [], unresolved: [] }); }
    });

    var root = buildDom();
    return WB.mountSharedView(root, payload, () => {}).then(function (ok) {
      expect(ok).toBe(true);
      expect(root.querySelector('.wb-paste-pill').textContent).toBe('Unique: 2 IPv4 / 1 IPv6');
    });
  });
});

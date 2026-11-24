/**
 * "Countries to exclude" in the JS workbench. v5.0.0 moved lookups to the
 * client-side workbench, which POSTs only {ips} to /api/lookup.php; nothing
 * read the form's countries_filter field, so the exclusion silently stopped
 * working for every visitor with JavaScript (fixed in 5.0.2). The no-JS path
 * in index.php kept working, which is why nothing noticed.
 *
 * These tests drive the real entry point — mount() + startLookup() with the
 * field filled in — rather than calling the helpers alone, so a future
 * rewrite of the submit path that drops the field fails here.
 */

'use strict';

var WB = require('../../assets/js/workbench.js');
var extractIps = require('../../assets/js/extract-ips.js');

function buildDom() {
  document.body.innerHTML = `
    <form id="iplookup">
      <textarea id="message" name="ip_list"></textarea>
      <input type="text" id="countries_filter" name="countries_filter" />
    </form>
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
  return {
    root: document.getElementById('workbench-root'),
    form: document.getElementById('iplookup'),
    textarea: document.getElementById('message'),
    field: document.getElementById('countries_filter'),
  };
}

function apiRow(ip, cc, category) {
  return {
    ip: ip, country_iso_code: cc, country_name: cc, subdivision_1_name: '', city_name: '',
    autonomous_system_number: 64500, autonomous_system_org: 'Example ' + cc, category: category || 'unknown', drop: false,
  };
}

var API_RESULTS = [
  apiRow('8.8.8.8', 'US', 'cloud'),
  apiRow('8.8.4.4', 'US', 'cloud'),
  apiRow('81.2.69.142', 'GB'),
  apiRow('202.12.27.33', 'JP'),
  apiRow('1.1.1.1', '', 'cloud'), // anycast: no country
];
var PASTE = '8.8.8.8 8.8.4.4 81.2.69.142 202.12.27.33 1.1.1.1';

function mockApi() {
  global.fetch = jest.fn().mockResolvedValue({
    status: 200, ok: true,
    json: function () { return Promise.resolve({ results: API_RESULTS, unresolved: [] }); },
  });
}

function shownIps(root) {
  return Array.from(root.querySelectorAll('.wb-table tbody:not(.wb-unresolved-rows) tr'))
    .map(function (tr) { return tr.querySelector('td').textContent.replace(/\s.*$/, ''); })
    .sort();
}

describe('parseExcludeCountries (mirrors index.php)', () => {
  test.each([
    ['', []],
    [null, []],
    ['US', ['US']],
    ['us ca  gb', ['US', 'CA', 'GB']],
    ['  us\tCa\nGB  ', ['US', 'CA', 'GB']],
    ['US us US', ['US']],
    ['USA U1 X 12 US,CA de', ['DE']], // only exact A-Z pairs survive, like the PHP regex
  ])('%j -> %j', (input, expected) => {
    expect(WB.parseExcludeCountries(input)).toEqual(expected);
  });
});

describe('applyCountryExclusion', () => {
  var rows = WB.buildRows(API_RESULTS, {});

  test('no codes keeps every row', () => {
    expect(WB.applyCountryExclusion(rows, [])).toEqual({ rows: rows, excluded: 0 });
  });

  test('drops matching rows and keeps rows without a country', () => {
    var out = WB.applyCountryExclusion(rows, ['US', 'JP']);
    expect(out.excluded).toBe(3);
    expect(out.rows.map(function (r) { return r.ip; })).toEqual(['81.2.69.142', '1.1.1.1']);
  });
});

describe('startLookup honors the "Countries to exclude" field (5.0.2 regression)', () => {
  beforeEach(() => { window.extractIps = extractIps; mockApi(); });
  afterEach(() => { delete window.extractIps; delete global.fetch; });

  test('excluded countries never reach the table, chips, summary or state', async () => {
    var d = buildDom();
    d.field.value = 'us jp';
    var handle = WB.mount(d.root, d.form, d.textarea);
    expect(await handle.startLookup(PASTE)).toBe(true);

    expect(shownIps(d.root)).toEqual(['1.1.1.1', '81.2.69.142']);
    expect(handle.state.rows.map(function (r) { return r.country; })).not.toContain('US');
    expect(d.root.querySelector('.wb-chips-country').textContent).not.toMatch(/\bUS\b|\bJP\b/);
    expect(d.root.querySelector('.wb-summary').textContent).not.toContain('Example US');
    expect(d.root.querySelector('.wb-excluded').textContent)
      .toBe('3 IPs excluded by country filter (US JP).');
  });

  test('the field is read at submit time, so changing it and resubmitting re-applies it', async () => {
    var d = buildDom();
    var handle = WB.mount(d.root, d.form, d.textarea);

    d.field.value = 'GB';
    await handle.startLookup(PASTE);
    expect(shownIps(d.root)).not.toContain('81.2.69.142');
    expect(d.root.querySelector('.wb-excluded').textContent).toBe('1 IP excluded by country filter (GB).');

    d.field.value = '';
    await handle.startLookup(PASTE);
    expect(shownIps(d.root)).toHaveLength(5);
    expect(d.root.querySelector('.wb-excluded')).toBeNull();
  });

  test('a real form submit event goes through the same path', async () => {
    var d = buildDom();
    d.field.value = 'US';
    var handle = WB.mount(d.root, d.form, d.textarea);
    var done;
    var finished = new Promise(function (r) { done = r; });
    var real = handle.startLookup;
    handle.startLookup = function (t) { return real(t).then(function (ok) { done(ok); return ok; }); };

    d.textarea.value = PASTE;
    d.form.dispatchEvent(new Event('submit', { cancelable: true }));
    expect(await finished).toBe(true);
    expect(shownIps(d.root)).toEqual(['1.1.1.1', '202.12.27.33', '81.2.69.142']);
  });

  test('only IPs are sent to the API; the exclusion stays client-side', async () => {
    var d = buildDom();
    d.field.value = 'US';
    var handle = WB.mount(d.root, d.form, d.textarea);
    await handle.startLookup(PASTE);
    var body = JSON.parse(global.fetch.mock.calls[0][1].body);
    expect(Object.keys(body)).toEqual(['ips']);
  });
});

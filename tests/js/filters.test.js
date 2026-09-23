/**
 * Tests for assets/js/filters.js — the pure Phase 2 applyFilters(rows, state)
 * and the D10 chip reducer (design doc D5 = A, R14 step 2).
 *
 * Header per R14: intentional differences from today's ip2geo-app.js chips
 * (characterized in tests/js/filters-characterization.test.js) are:
 *  - empty selection means "show everything", not "show nothing"
 *  - plain click on an unselected chip replaces the whole selection with
 *    just that chip; on an already-selected chip it removes it (no
 *    separate "click the lone chip again to restore" step)
 *  - Shift/Ctrl+click toggles a chip in/out of the selection without
 *    touching the rest
 *  - an explicit clearFilters() resets both dimensions to "show everything"
 *  - a search box filters IP/ASN/org/country as a further AND condition
 */

'use strict';

var F = require('../../assets/js/filters.js');

function fixtureRows() {
  return [
    { ip: '1.1.1.1', country: 'US', asn: 'AS14061', asnOrg: 'DigitalOcean, LLC', category: 'cloud', drop: false, hits: 5 },
    { ip: '2.2.2.2', country: 'US', asn: 'AS398324', asnOrg: 'Censys, Inc.', category: 'scanning', drop: false, hits: 3 },
    { ip: '3.3.3.3', country: 'CN', asn: 'AS4134', asnOrg: 'Chinanet', category: 'scanning', drop: true, hits: 12 },
    { ip: '4.4.4.4', country: 'CN', asn: 'AS16509', asnOrg: 'Amazon.com, Inc.', category: 'cloud', drop: false, hits: 1 },
    { ip: '5.5.5.5', country: 'DE', asn: 'AS9009', asnOrg: 'M247 Europe SRL', category: 'vpn', drop: false, hits: 7 },
  ];
}

function ips(rows) {
  return rows.map(function (r) { return r.ip; });
}

describe('applyFilters', () => {
  test('with an empty state, every row is shown ("none" selected = all)', () => {
    var shown = F.applyFilters(fixtureRows(), F.emptyState());
    expect(ips(shown)).toEqual(['1.1.1.1', '2.2.2.2', '3.3.3.3', '4.4.4.4', '5.5.5.5']);
  });

  test('rows shown = selected categories ∩ selected countries', () => {
    var state = { categories: new Set(['scanning']), countries: new Set(['CN']), search: '' };
    var shown = F.applyFilters(fixtureRows(), state);
    expect(ips(shown)).toEqual(['3.3.3.3']);
  });

  test('a category filter alone narrows across all countries', () => {
    var state = { categories: new Set(['cloud']), countries: new Set(), search: '' };
    expect(ips(F.applyFilters(fixtureRows(), state))).toEqual(['1.1.1.1', '4.4.4.4']);
  });

  test('a country filter alone narrows across all categories', () => {
    var state = { categories: new Set(), countries: new Set(['US']), search: '' };
    expect(ips(F.applyFilters(fixtureRows(), state))).toEqual(['1.1.1.1', '2.2.2.2']);
  });

  test('search box filters by IP substring', () => {
    var state = { categories: new Set(), countries: new Set(), search: '3.3.3' };
    expect(ips(F.applyFilters(fixtureRows(), state))).toEqual(['3.3.3.3']);
  });

  test('search box filters by ASN, case-insensitive', () => {
    var state = { categories: new Set(), countries: new Set(), search: 'as14061' };
    expect(ips(F.applyFilters(fixtureRows(), state))).toEqual(['1.1.1.1']);
  });

  test('search box filters by org substring', () => {
    var state = { categories: new Set(), countries: new Set(), search: 'amazon' };
    expect(ips(F.applyFilters(fixtureRows(), state))).toEqual(['4.4.4.4']);
  });

  test('search combines with chip filters as an AND', () => {
    var state = { categories: new Set(['cloud']), countries: new Set(), search: 'amazon' };
    expect(ips(F.applyFilters(fixtureRows(), state))).toEqual(['4.4.4.4']);
  });

  test('"N shown" equals the filtered row count', () => {
    var state = { categories: new Set(['scanning']), countries: new Set(), search: '' };
    var shown = F.applyFilters(fixtureRows(), state);
    expect(shown.length).toBe(2); // 2.2.2.2 and 3.3.3.3
  });

  test('Export/CSV scope equals the visible rows (same function, no separate scoping)', () => {
    var state = { categories: new Set(['vpn']), countries: new Set(), search: '' };
    var shown = F.applyFilters(fixtureRows(), state);
    var exportScope = F.applyFilters(fixtureRows(), state); // export reuses applyFilters directly
    expect(exportScope).toEqual(shown);
  });
});

describe('D10 chip gestures', () => {
  test('plain click on an unselected chip replaces the selection with just that chip', () => {
    var selected = new Set(['US', 'DE']);
    var next = F.chipClick(selected, 'CN', {});
    expect(Array.from(next)).toEqual(['CN']);
    // original Set is untouched
    expect(Array.from(selected)).toEqual(['US', 'DE']);
  });

  test('plain click on an already-selected chip removes it', () => {
    var selected = new Set(['US']);
    var next = F.chipClick(selected, 'US', {});
    expect(Array.from(next)).toEqual([]);
  });

  test('plain click on one of several selected chips removes only that one', () => {
    var selected = new Set(['US', 'CN']);
    var next = F.chipClick(selected, 'US', {});
    expect(Array.from(next)).toEqual(['CN']);
  });

  test('shift+click adds an unselected chip to the current selection', () => {
    var selected = new Set(['US']);
    var next = F.chipClick(selected, 'CN', { shift: true });
    expect(Array.from(next).sort()).toEqual(['CN', 'US']);
  });

  test('ctrl+click behaves the same as shift+click', () => {
    var selected = new Set(['US']);
    var next = F.chipClick(selected, 'CN', { ctrl: true });
    expect(Array.from(next).sort()).toEqual(['CN', 'US']);
  });

  test('shift+click removes an already-selected chip without touching the rest', () => {
    var selected = new Set(['US', 'CN']);
    var next = F.chipClick(selected, 'US', { shift: true });
    expect(Array.from(next)).toEqual(['CN']);
  });

  test('Clear filters resets both dimensions to "show everything" but leaves search alone', () => {
    var state = { categories: new Set(['scanning']), countries: new Set(['CN']), search: 'amazon' };
    var cleared = F.clearFilters(state);
    expect(cleared.categories.size).toBe(0);
    expect(cleared.countries.size).toBe(0);
    expect(cleared.search).toBe('amazon');
  });

  test('a full click/shift/deselect/clear sequence ends up matching applyFilters expectations', () => {
    var categories = new Set();
    categories = F.chipClick(categories, 'scanning', {});          // solo scanning
    categories = F.chipClick(categories, 'cloud', { shift: true }); // add cloud
    var state = { categories: categories, countries: new Set(), search: '' };
    expect(ips(F.applyFilters(fixtureRows(), state)).sort()).toEqual(
      ['1.1.1.1', '2.2.2.2', '3.3.3.3', '4.4.4.4'].sort()
    );

    categories = F.chipClick(categories, 'scanning', {}); // remove scanning, cloud remains
    state = { categories: categories, countries: new Set(), search: '' };
    expect(ips(F.applyFilters(fixtureRows(), state))).toEqual(['1.1.1.1', '4.4.4.4']);

    var cleared = F.clearFilters(state);
    expect(ips(F.applyFilters(fixtureRows(), cleared))).toEqual(ips(fixtureRows()));
  });
});

describe('chipCounts', () => {
  test('counts are cross-filtered: a category chip count reflects the country filter, not its own', () => {
    var state = { categories: new Set(['scanning']), countries: new Set(['CN']), search: '' };
    var counts = F.chipCounts(fixtureRows(), state);
    // categories counted against the country filter only (CN): scanning=1 (3.3.3.3), cloud=1 (4.4.4.4)
    expect(counts.categories).toEqual({ scanning: 1, cloud: 1 });
    // countries counted against the category filter only (scanning): US=1 (2.2.2.2), CN=1 (3.3.3.3)
    expect(counts.countries).toEqual({ US: 1, CN: 1 });
  });
});

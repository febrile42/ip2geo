/**
 * Tests for assets/js/export-templates.js (design doc D9, revised Export
 * menu): template correctness at 10 / 1,500 / 10,000 IPs, CSV column order,
 * the 64 KB alert-rule note, and the toast text.
 */

'use strict';

var Exp = require('../../assets/js/export-templates.js');

function makeRows(n) {
  var rows = [];
  for (var i = 0; i < n; i++) {
    rows.push({
      ip: '10.' + ((i >> 16) & 255) + '.' + ((i >> 8) & 255) + '.' + (i & 255),
      country: 'US',
      region: 'California',
      city: 'Fremont',
      asn: 'AS14061',
      asnOrg: 'DigitalOcean, LLC',
      category: 'cloud',
      hits: i + 1,
      drop: i % 7 === 0
    });
  }
  return rows;
}

describe('CSV column order', () => {
  test('keeps the original 7 columns first, with Hits and DROP appended', () => {
    var rows = [{ ip: '1.1.1.1', country: 'US', region: 'CA', city: 'Fremont', asn: 'AS1', asnOrg: 'Org', category: 'cloud', hits: 3, drop: true }];
    var csv = Exp.buildExport('csv', rows);
    var lines = csv.replace(/^﻿/, '').split('\r\n');
    expect(lines[0]).toBe('IP,CC,State/Province,City,ASN,ASN Org,Category,Hits,DROP');
    expect(lines[1]).toBe('1.1.1.1,US,CA,Fremont,AS1,Org,cloud,3,DROP');
  });

  test('quotes fields containing commas or quotes', () => {
    var rows = [{ ip: '1.1.1.1', country: 'US', region: 'CA', city: 'Fremont', asn: 'AS1', asnOrg: 'Org, "Inc"', category: 'cloud', hits: 1, drop: false }];
    var csv = Exp.buildExport('csv', rows);
    expect(csv).toContain('"Org, ""Inc"""');
  });
});

describe.each([10, 1500, 10000])('templates at %d IPs', (n) => {
  var rows;
  beforeAll(() => { rows = makeRows(n); });

  test('csv has n+1 lines (header + rows)', () => {
    var csv = Exp.buildExport('csv', rows);
    var lines = csv.replace(/^﻿/, '').split('\r\n');
    expect(lines.length).toBe(n + 1);
  });

  test('tsv has n+1 lines, tab-separated', () => {
    var tsv = Exp.buildExport('tsv', rows);
    var lines = tsv.split('\r\n');
    expect(lines.length).toBe(n + 1);
    expect(lines[0].split('\t').length).toBe(9);
  });

  test('kql always uses the same shape: let-dynamic + edit-me comment', () => {
    var kql = Exp.buildExport('kql', rows);
    expect(kql).toMatch(/^\/\/ edit table and column\n/);
    expect(kql).toContain('let ips = dynamic([');
    expect(kql).toContain('SigninLogs');
    expect(kql).toContain('| where IPAddress in (ips)');
    // Every IP present as a quoted literal.
    expect(kql.match(/"10\./g).length).toBe(n);
  });

  test('spl always uses an inline IN (...) list', () => {
    var spl = Exp.buildExport('spl', rows);
    expect(spl).toContain('src_ip IN (');
    expect(spl.match(/"10\./g).length).toBe(n);
  });

  test('iptables/ufw/nginx cover every row', () => {
    expect(Exp.buildExport('iptables', rows).split('\n').length).toBe(n);
    expect(Exp.buildExport('ufw', rows).split('\n').length).toBe(n);
    var nginx = Exp.buildExport('nginx', rows);
    expect((nginx.match(/ 1;/g) || []).length).toBe(n);
  });

  test('exportLabel includes scope count and approx KB', () => {
    var label = Exp.exportLabel('kql', rows);
    expect(label.label).toMatch(new RegExp('KQL \\(Sentinel\\) · ' + n.toLocaleString() + ' IPs? · ~\\d+ KB'));
    expect(label.count).toBe(n);
  });
});

describe('64 KB alert-rule note', () => {
  test('is absent for a small KQL export', () => {
    var label = Exp.exportLabel('kql', makeRows(10));
    expect(label.over64kNote).toBe(false);
  });

  test('is present once the KQL text crosses 64 KB', () => {
    var label = Exp.exportLabel('kql', makeRows(10000));
    expect(label.approxKB).toBeGreaterThan(64);
    expect(label.over64kNote).toBe(true);
  });

  test('never applies to non-KQL formats even at 10k rows', () => {
    var csvLabel = Exp.exportLabel('csv', makeRows(10000));
    expect(csvLabel.over64kNote).toBe(false);
  });
});

describe('toast text', () => {
  test('reads "Copied N rows as <FORMAT>"', () => {
    expect(Exp.toastText('tsv', makeRows(614))).toBe('Copied 614 rows as TSV');
  });

  test('singular row', () => {
    expect(Exp.toastText('csv', makeRows(1))).toBe('Copied 1 row as CSV');
  });

  test('strips the parenthetical for kql/spl labels', () => {
    expect(Exp.toastText('kql', makeRows(3))).toBe('Copied 3 rows as KQL');
    expect(Exp.toastText('spl', makeRows(3))).toBe('Copied 3 rows as SPL');
  });
});

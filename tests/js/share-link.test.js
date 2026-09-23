/**
 * Tests for assets/js/share-link.js (design doc D8): round-trip encode/
 * decode of the #v= payload, the ~8 KB cap and its over-cap label, and the
 * .ip2geo.json view-file fallback.
 */

'use strict';

var Share = require('../../assets/js/share-link.js');

describe('encode/decode round trip', () => {
  test('IPv4-only state round-trips exactly', () => {
    var state = {
      ips: ['1.1.1.1', '10.0.0.255', '255.255.255.0'],
      categories: ['scanning', 'cloud'],
      countries: ['US', 'CN'],
      search: 'amazon'
    };
    var payload = Share.encodeShareState(state);
    expect(payload).not.toBeNull();
    var decoded = Share.decodeShareState(payload);
    expect(decoded).toEqual(state);
  });

  test('IPv6 addresses round-trip with standard shorthand', () => {
    var state = { ips: ['2001:db8::1', '::1', 'fe80::1234:5678:9abc:def0'], categories: [], countries: [], search: '' };
    var payload = Share.encodeShareState(state);
    var decoded = Share.decodeShareState(payload);
    expect(decoded.ips).toEqual(state.ips);
  });

  test('mixed v4/v6 round-trips', () => {
    var state = { ips: ['8.8.8.8', '2606:4700:4700::1111', '1.2.3.4'], categories: ['vpn'], countries: [], search: '' };
    var decoded = Share.decodeShareState(Share.encodeShareState(state));
    expect(decoded.ips).toEqual(state.ips);
    expect(decoded.categories).toEqual(['vpn']);
  });

  test('empty state round-trips', () => {
    var state = { ips: [], categories: [], countries: [], search: '' };
    var decoded = Share.decodeShareState(Share.encodeShareState(state));
    expect(decoded).toEqual(state);
  });

  test('malformed payload decodes to null instead of throwing', () => {
    expect(Share.decodeShareState('not-valid-base64!!!')).toBeNull();
    expect(Share.decodeShareState('')).toBeNull();
  });

  test('an unparseable IP fails encoding outright (returns null payload)', () => {
    var state = { ips: ['not-an-ip'], categories: [], countries: [], search: '' };
    expect(Share.encodeShareState(state)).toBeNull();
  });
});

describe('buildShareLink and the ~8 KB cap', () => {
  test('a small filtered view is well under cap', () => {
    var state = { ips: ['1.1.1.1', '2.2.2.2'], categories: [], countries: [], search: '' };
    var result = Share.buildShareLink(state);
    expect(result.overCap).toBe(false);
    expect(result.payload).not.toBeNull();
  });

  test('a large IP list goes over the URL cap', () => {
    var ips = [];
    for (var i = 0; i < 3000; i++) {
      ips.push('10.' + ((i >> 16) & 255) + '.' + ((i >> 8) & 255) + '.' + (i & 255));
    }
    var result = Share.buildShareLink({ ips: ips, categories: [], countries: [], search: '' });
    expect(result.overCap).toBe(true);
  });

  test('overCapLabel names the count and an approximate cap', () => {
    var label = Share.overCapLabel(3412);
    expect(label).toMatch(/^Too many IPs for a link \(3,412 \/ ~[\d,]+\)$/);
  });
});

describe('buildViewFile (.ip2geo.json fallback)', () => {
  test('serializes the same state a link would encode', () => {
    var state = { ips: ['1.1.1.1'], categories: ['cloud'], countries: ['US'], search: '' };
    var json = Share.buildViewFile(state);
    var parsed = JSON.parse(json);
    expect(parsed.ips).toEqual(['1.1.1.1']);
    expect(parsed.categories).toEqual(['cloud']);
    expect(parsed.countries).toEqual(['US']);
    expect(parsed.version).toBe(Share.VERSION);
  });
});

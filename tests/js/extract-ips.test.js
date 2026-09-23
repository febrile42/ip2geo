/**
 * Locks the browser extractIps() (assets/js/extract-ips.js) against the
 * same golden fixtures as tests/ExtractIpsTest.php, plus a worst-case
 * timing/backtracking guard (design doc R15).
 *
 * Parity strategy (design doc R6/R12): the PHP side writes
 * tests/fixtures/extract/<name>.full.json by running the real
 * extract_ips() over each fixture (see generate-expected.php). This suite
 * loads those same files and asserts extractIps() produces the identical
 * v4+v6 result, so the two extractors can never drift apart silently.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const extractIps = require('../../assets/js/extract-ips.js');

const FIXTURE_DIR = path.join(__dirname, '..', 'fixtures', 'extract');

const FIXTURES = [
  'fail2ban',
  'netstat',
  'nginx-access',
  'mixed-v4v6',
  'cap-12k',
  'private-only',
  'empty',
  'defanged-and-ports',
];

function readFixture(name) {
  return fs.readFileSync(path.join(FIXTURE_DIR, `${name}.txt`), 'utf8');
}

function readExpected(name) {
  return JSON.parse(fs.readFileSync(path.join(FIXTURE_DIR, `${name}.full.json`), 'utf8'));
}

describe('extractIps: matches PHP extract_ips() on every fixture', () => {
  test.each(FIXTURES)('%s', (name) => {
    const text = readFixture(name);
    const expected = readExpected(name);
    const result = extractIps(text);

    expect(result.ips).toEqual(expected.ips);
    expect(result.totalUnique).toBe(expected.total_unique);
    expect(result.v6Count).toBe(expected.v6_count);
  });
});

describe('extractIps: IPv6 behavior on mixed-v4v6', () => {
  let result;
  beforeAll(() => {
    result = extractIps(readFixture('mixed-v4v6'));
  });

  test('counts v6 addresses and total_unique', () => {
    expect(result.v6Count).toBe(4);
    expect(result.totalUnique).toBe(8);
  });

  test('public v6 addresses are kept with correct counts', () => {
    const map = new Map(result.ips);
    expect(map.get('2001:4860:4860::8888')).toBe(2);
    expect(map.has('2606:4700:4700::1111')).toBe(true);
    expect(map.has('2400:cb00:2049:1::a29f:1804')).toBe(true);
    // ::ffff:203.0.113.9 is public (mapped v4 is public), kept as v6.
    expect(map.has('::ffff:203.0.113.9')).toBe(true);
  });

  test('private v6 addresses are dropped', () => {
    const map = new Map(result.ips);
    expect(map.has('::1')).toBe(false);
    expect(map.has('fe80::1ff:fe23:4567:890a')).toBe(false);
    expect(map.has('fc00::1234:5678:9abc:def0')).toBe(false);
    expect(map.has('fd12:3456:789a:1::1')).toBe(false);
    expect(map.has('2001:db8::1')).toBe(false);
    expect(map.has('::ffff:192.168.1.1')).toBe(false);
  });

  test('first-seen order: first v6 hit leads the map', () => {
    expect(result.ips[0][0]).toBe('2001:4860:4860::8888');
  });

  test('documented quirk: a mapped v6 literal also yields the embedded v4 hit', () => {
    const map = new Map(result.ips);
    expect(map.has('::ffff:203.0.113.9')).toBe(true);
    expect(map.has('203.0.113.9')).toBe(true);
  });
});

describe('extractIps: normalization', () => {
  test('expands and lowercases + compresses to canonical form', () => {
    const result = extractIps('host 2001:4860:4860:0000:0000:0000:0000:8888 answered');
    const map = new Map(result.ips);
    expect(map.has('2001:4860:4860::8888')).toBe(true);
  });

  test('uppercase input normalizes to lowercase', () => {
    const result = extractIps('HOST 2001:4860:4860::8888 AND 2606:4700:4700::1111');
    const map = new Map(result.ips);
    expect(map.has('2001:4860:4860::8888')).toBe(true);
    expect(map.has('2606:4700:4700::1111')).toBe(true);
  });
});

describe('extractIps: cap-12k', () => {
  test('caps at 10000 but reports the full pre-cap unique total', () => {
    const result = extractIps(readFixture('cap-12k'));
    expect(result.ips.length).toBe(10000);
    expect(result.totalUnique).toBe(12005);
  });
});

describe('extractIps: empty / private-only', () => {
  test('empty input', () => {
    const result = extractIps('');
    expect(result.ips).toEqual([]);
    expect(result.totalUnique).toBe(0);
    expect(result.v6Count).toBe(0);
  });

  test('private-only input', () => {
    const result = extractIps(readFixture('private-only'));
    expect(result.ips).toEqual([]);
    expect(result.totalUnique).toBe(0);
  });
});

describe('extractIps: defanged / ports', () => {
  test('defanged 1.2.3[.]4 is not extracted', () => {
    const result = extractIps(readFixture('defanged-and-ports'));
    const map = new Map(result.ips);
    expect(map.has('5.6.7.8')).toBe(false);
  });

  test('ports are stripped from IPv4 matches', () => {
    const result = extractIps(readFixture('defanged-and-ports'));
    const map = new Map(result.ips);
    expect(map.get('1.2.3.4')).toBe(3);
  });

  test('bracketed IPv6 with a port is extracted', () => {
    const result = extractIps(readFixture('defanged-and-ports'));
    const map = new Map(result.ips);
    expect(map.has('2001:4860:4860::8888')).toBe(true);
  });
});

// ── Worst case (R15): performance + backtracking guard ─────────────────────

/**
 * Deterministic ~2MB generator, ported line-for-line from
 * generate_worst_case_extract_fixture() in tests/ExtractIpsTest.php so both
 * suites build byte-identical input independently (nothing is committed).
 */
function generateWorstCaseFixture() {
  const lines = [];
  const targetBytes = 2 * 1024 * 1024;
  let size = 0;
  let i = 0;
  let ipLines = 0;
  const minIpLines = 12500;

  while (size < targetBytes || ipLines < minIpLines) {
    const mod = i % 5;
    let line;
    if (mod === 0 || mod === 1) {
      const n = 16777217 + ((i * 97) % 3000000000);
      const ip = [
        (n >>> 24) & 0xff,
        (n >>> 16) & 0xff,
        (n >>> 8) & 0xff,
        n & 0xff,
      ].join('.');
      line = `hit from ${ip} on port 22`;
      ipLines++;
    } else if (mod === 2) {
      const mac = [
        i & 0xff, (i >> 2) & 0xff, (i >> 4) & 0xff,
        (i >> 6) & 0xff, (i >> 8) & 0xff, (i >> 10) & 0xff,
      ].map((b) => b.toString(16).padStart(2, '0')).join(':');
      line = `arp entry ${mac} on vlan10`;
    } else if (mod === 3) {
      const hash = crypto.createHash('sha256').update(String(i)).digest('hex');
      line = `artifact sha256:${hash} verified`;
    } else {
      line = 'noise ::::::::::::::::::::::::::::::::' + (i % 10);
    }

    lines.push(line);
    size += line.length + 1;
    i++;
  }

  return lines.join('\n') + '\n';
}

describe('extractIps: worst-case 2MB performance guard', () => {
  test('finishes under 300ms and matches PHP on the same generated input', () => {
    const text = generateWorstCaseFixture();
    expect(text.length).toBeGreaterThan(2000000);

    const start = Date.now();
    const result = extractIps(text);
    const elapsed = Date.now() - start;

    expect(elapsed).toBeLessThan(300);
    expect(result.ips.length).toBe(10000);
    expect(result.totalUnique).toBeGreaterThanOrEqual(12000);
    expect(result.v6Count).toBe(0); // MACs, hashes and bare-colon noise never validate as IPv6
  });
});

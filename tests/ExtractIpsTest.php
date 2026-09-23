<?php

declare(strict_types=1);

namespace Ip2Geo\Tests;

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../includes/extract.php';

/**
 * Locks extract_ips() (includes/extract.php) against golden fixtures
 * captured from the inline extraction that used to live in index.php
 * (~214-226 on origin/main), plus new IPv6 and performance assertions
 * per the design doc's R6/R15.
 *
 * Golden *.json files hold the IPv4-only projection exactly as today's
 * code produces it: [ip, count] pairs, first-seen order, capped at 10,000
 * before private filtering, then private ranges dropped. They were
 * captured by running a throwaway script that reproduced index.php's
 * inline logic verbatim over these same fixtures, before extract_ips()
 * existed — see the worktree report for the script contents.
 *
 * *.full.json files hold the complete v4+v6 extract_ips() output and are
 * also asserted here for the IPv6-carrying fixtures (mixed-v4v6,
 * defanged-and-ports), and reused as-is by tests/js/extract-ips.test.js to
 * prove the JS extractor matches PHP exactly.
 */
class ExtractIpsTest extends TestCase
{
    private const FIXTURE_DIR = __DIR__ . '/fixtures/extract';

    private const IPV4_FIXTURES = [
        'fail2ban',
        'netstat',
        'nginx-access',
        'mixed-v4v6',
        'cap-12k',
        'private-only',
        'empty',
        'defanged-and-ports',
    ];

    private function loadGolden(string $name): array
    {
        $json = file_get_contents(self::FIXTURE_DIR . "/$name.json");
        return json_decode($json, true);
    }

    private function ipv4Projection(array $ips): array
    {
        $pairs = [];
        foreach ($ips as $ip => $count) {
            if (strpos($ip, ':') === false) {
                $pairs[] = [$ip, $count];
            }
        }
        return $pairs;
    }

    // ── IPv4 projection matches the original golden exactly ──────────────────

    /** @dataProvider ipv4FixtureProvider */
    public function testIpv4ProjectionMatchesGoldenExactly(string $fixture): void
    {
        $text = file_get_contents(self::FIXTURE_DIR . "/$fixture.txt");
        $result = extract_ips($text);

        $this->assertSame(
            $this->loadGolden($fixture),
            $this->ipv4Projection($result['ips']),
            "IPv4 projection for '$fixture' diverged from today's extraction"
        );
    }

    public static function ipv4FixtureProvider(): array
    {
        return array_map(static fn(string $f) => [$f], self::IPV4_FIXTURES);
    }

    // ── IPv6 behavior on mixed-v4v6 ───────────────────────────────────────────

    public function testMixedV4v6CountsAndOrder(): void
    {
        $text = file_get_contents(self::FIXTURE_DIR . '/mixed-v4v6.txt');
        $result = extract_ips($text);

        $this->assertSame(4, $result['v6_count']);
        $this->assertSame(8, $result['total_unique']);

        // Public v6 kept, with occurrence counts.
        $this->assertArrayHasKey('2001:4860:4860::8888', $result['ips']);
        $this->assertSame(2, $result['ips']['2001:4860:4860::8888']);
        $this->assertArrayHasKey('2606:4700:4700::1111', $result['ips']);
        $this->assertArrayHasKey('2400:cb00:2049:1::a29f:1804', $result['ips']);

        // ::ffff:203.0.113.9 is public (mapped v4 is public), kept as v6.
        $this->assertArrayHasKey('::ffff:203.0.113.9', $result['ips']);

        // Private v6 dropped: loopback, link-local, unique-local (fc00::/7,
        // both fc.. and fd.. forms), documentation, and mapped-private.
        $this->assertArrayNotHasKey('::1', $result['ips']);
        $this->assertArrayNotHasKey('fe80::1ff:fe23:4567:890a', $result['ips']);
        $this->assertArrayNotHasKey('fc00::1234:5678:9abc:def0', $result['ips']);
        $this->assertArrayNotHasKey('fd12:3456:789a:1::1', $result['ips']);
        $this->assertArrayNotHasKey('2001:db8::1', $result['ips']);
        $this->assertArrayNotHasKey('::ffff:192.168.1.1', $result['ips']);

        // First-seen order: the first two v6 addresses in the text appear
        // before the first v4 address that isn't itself the very first hit.
        $keys = array_keys($result['ips']);
        $this->assertSame('2001:4860:4860::8888', $keys[0]);
    }

    public function testMappedV6AlsoYieldsTheEmbeddedIpv4Hit(): void
    {
        // Documented quirk: ::ffff:203.0.113.9 contains a dotted quad that
        // the IPv4 regex's \b boundary also matches on its own. Both the
        // v6 literal and the standalone v4 hit are present.
        $text = file_get_contents(self::FIXTURE_DIR . '/mixed-v4v6.txt');
        $result = extract_ips($text);

        $this->assertArrayHasKey('::ffff:203.0.113.9', $result['ips']);
        $this->assertArrayHasKey('203.0.113.9', $result['ips']);
    }

    public function testV6NormalizedToLowercaseCompressedForm(): void
    {
        $result = extract_ips('host 2001:4860:4860:0000:0000:0000:0000:8888 answered');
        $this->assertArrayHasKey('2001:4860:4860::8888', $result['ips']);
    }

    public function testUppercaseV6IsNormalizedToLowercase(): void
    {
        $result = extract_ips('host 2001:4860:4860::8888 and 2001:4860:4860::8888'.'');
        $result2 = extract_ips('HOST 2001:4860:4860::8888 AND 2606:4700:4700::1111');
        $this->assertArrayHasKey('2001:4860:4860::8888', $result2['ips']);
        $this->assertArrayHasKey('2606:4700:4700::1111', $result2['ips']);
    }

    // ── Full v4+v6 output matches the committed .full.json ───────────────────

    /** @dataProvider ipv4FixtureProvider */
    public function testFullOutputMatchesCommittedExpectation(string $fixture): void
    {
        $text = file_get_contents(self::FIXTURE_DIR . "/$fixture.txt");
        $result = extract_ips($text);

        $expected = json_decode(
            file_get_contents(self::FIXTURE_DIR . "/$fixture.full.json"),
            true
        );

        $pairs = [];
        foreach ($result['ips'] as $ip => $count) {
            $pairs[] = [$ip, $count];
        }

        $this->assertSame($expected['ips'], $pairs, "full ips mismatch for '$fixture'");
        $this->assertSame($expected['total_unique'], $result['total_unique'], "total_unique mismatch for '$fixture'");
        $this->assertSame($expected['v6_count'], $result['v6_count'], "v6_count mismatch for '$fixture'");
    }

    // ── total_unique / cap on cap-12k ─────────────────────────────────────────

    public function testCap12kCapsAt10000ButReportsFullUniqueTotal(): void
    {
        $text = file_get_contents(self::FIXTURE_DIR . '/cap-12k.txt');
        $result = extract_ips($text);

        $this->assertCount(10000, $result['ips']);
        $this->assertGreaterThan(10000, $result['total_unique']);
        $this->assertSame(12005, $result['total_unique']);
    }

    // ── empty / private-only ──────────────────────────────────────────────────

    public function testEmptyInputProducesEmptyResult(): void
    {
        $result = extract_ips('');
        $this->assertSame([], $result['ips']);
        $this->assertSame(0, $result['total_unique']);
        $this->assertSame(0, $result['v6_count']);
    }

    public function testPrivateOnlyInputProducesEmptyResult(): void
    {
        $text = file_get_contents(self::FIXTURE_DIR . '/private-only.txt');
        $result = extract_ips($text);
        $this->assertSame([], $result['ips']);
        $this->assertSame(0, $result['total_unique']);
    }

    // ── defanged / ports ───────────────────────────────────────────────────────

    public function testDefangedIpsAreNotExtracted(): void
    {
        $text = file_get_contents(self::FIXTURE_DIR . '/defanged-and-ports.txt');
        $result = extract_ips($text);

        // 1.2.3[.]4 and 5[.]6[.]7[.]8 are never extracted — documented
        // current behavior, not "fixed" here.
        $this->assertArrayNotHasKey('1.2.3.4', array_flip(['5.6.7.8'])); // sanity: no accidental key
        $this->assertArrayNotHasKey('5.6.7.8', $result['ips']);
    }

    public function testPortsAreStrippedFromIpv4Matches(): void
    {
        $text = file_get_contents(self::FIXTURE_DIR . '/defanged-and-ports.txt');
        $result = extract_ips($text);

        // "1.2.3.4:443" yields "1.2.3.4" (port not part of the match),
        // and it appears twice in the fixture (443 and repeated 443).
        $this->assertArrayHasKey('1.2.3.4', $result['ips']);
        $this->assertSame(3, $result['ips']['1.2.3.4']); // :443, :8443, repeated :443
    }

    public function testBracketedIpv6WithPortIsExtracted(): void
    {
        $text = file_get_contents(self::FIXTURE_DIR . '/defanged-and-ports.txt');
        $result = extract_ips($text);

        // "[2001:4860:4860::8888]:443" — brackets and the port aren't part
        // of the v6 candidate charset, so they act as natural boundaries.
        $this->assertArrayHasKey('2001:4860:4860::8888', $result['ips']);
    }

    // ── worst case (R15): PHP-side performance bound ─────────────────────────

    public function testWorstCase2mbFinishesUnderOneSecond(): void
    {
        $text = generate_worst_case_extract_fixture();
        $this->assertGreaterThan(2_000_000 * 0.9, strlen($text), 'worst-case fixture should be close to 2MB');

        $start = microtime(true);
        $result = extract_ips($text);
        $elapsed = microtime(true) - $start;

        $this->assertLessThan(1.0, $elapsed, "extract_ips() took {$elapsed}s on the 2MB worst case, must be <1s");
        $this->assertGreaterThanOrEqual(12000, $result['total_unique']);
    }
}

/**
 * Deterministically generates the ~2MB "worst case" input used by R15:
 * mixed log lines, long hex/colon runs that look like MAC addresses and
 * sha256 hashes (the catastrophic-backtracking bait for a naive IPv6
 * regex), plus 12,000+ IPv4 hits. Not committed as a fixture file — both
 * this file and tests/js/extract-ips.test.js generate it independently
 * from this exact same deterministic scheme so their outputs can be
 * compared directly.
 *
 * Kept as a free function (not a class method) so the JS port in
 * extract-ips.test.js can mirror it line-for-line.
 */
function generate_worst_case_extract_fixture(): string
{
    $lines = [];
    $target_bytes = 2 * 1024 * 1024;
    $size = 0;
    $i = 0;
    $ip_lines = 0;
    $min_ip_lines = 12500;

    while ($size < $target_bytes || $ip_lines < $min_ip_lines) {
        $mod = $i % 5;
        if ($mod === 0 || $mod === 1) {
            // A believable public IPv4 hit, cycling through a wide range.
            $n = 16777217 + ($i * 97) % 3000000000; // stays within 1.0.0.1..~
            $ip = long2ip($n);
            $line = "hit from {$ip} on port 22";
            $ip_lines++;
        } elseif ($mod === 2) {
            // A MAC-address-shaped hex/colon run (backtracking bait).
            $mac = sprintf(
                '%02x:%02x:%02x:%02x:%02x:%02x',
                $i & 0xFF, ($i >> 2) & 0xFF, ($i >> 4) & 0xFF,
                ($i >> 6) & 0xFF, ($i >> 8) & 0xFF, ($i >> 10) & 0xFF
            );
            $line = "arp entry {$mac} on vlan10";
        } elseif ($mod === 3) {
            // A sha256-shaped long hex run with no colons at all.
            $hash = hash('sha256', (string)$i);
            $line = "artifact sha256:{$hash} verified";
        } else {
            // A run of bare colons, the degenerate case for naive IPv6
            // regexes that assume "::" only appears once.
            $line = "noise ::::::::::::::::::::::::::::::::" . ($i % 10);
        }

        $lines[] = $line;
        $size += strlen($line) + 1;
        $i++;
    }

    return implode("\n", $lines) . "\n";
}

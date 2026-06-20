<?php

declare(strict_types=1);

namespace Ip2Geo\Tests;

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../report_functions.php';      // ip_in_spamhaus_drop(), apply_reputation_override(), build_teaser()
require_once __DIR__ . '/../scripts/gen-spamhaus-drop.php'; // spamhaus_drop_ranges_from_ndjson() (CLI entry self-guards)

/**
 * Spamhaus DROP reputation axis: the ASN-agnostic signal that fires the CTA on
 * residential attackers the ASN verdict would otherwise miss.
 *
 * Covers the lookup (binary search), the generator (CIDR -> sorted/merged int
 * ranges, skipping metadata + IPv6), the verdict override, the teaser drop_count,
 * the committed data file's integrity, and a perf guard for the 10k hot loop.
 */
class SpamhausDropTest extends TestCase
{
    /** @var array<int,array{0:int,1:int}>|null */
    private $origRanges;

    protected function setUp(): void
    {
        // Preserve the real committed ranges; individual tests may swap in a
        // deterministic fixture. tearDown always restores so the shape/perf
        // tests see the genuine data regardless of execution order.
        $this->origRanges = $GLOBALS['spamhaus_drop_ranges'] ?? null;
    }

    protected function tearDown(): void
    {
        $GLOBALS['spamhaus_drop_ranges'] = $this->origRanges;
    }

    // --- ip_in_spamhaus_drop(): binary search boundaries -------------------

    /** @dataProvider boundaryCases */
    public function testLookupBoundaries(int $ip, bool $expected): void
    {
        $GLOBALS['spamhaus_drop_ranges'] = [[100, 200], [300, 400]];
        $this->assertSame($expected, ip_in_spamhaus_drop($ip));
    }

    public static function boundaryCases(): array
    {
        return [
            'inside first'        => [150, true],
            'start boundary'      => [100, true],
            'end boundary'        => [200, true],
            'one below start'     => [99,  false],
            'one above end'       => [201, false],
            'gap between ranges'  => [250, false],
            'inside second'       => [350, true],
            'one above last'      => [401, false],
            'far below'           => [0,   false],
        ];
    }

    public function testLookupEmptyListNeverMatches(): void
    {
        $GLOBALS['spamhaus_drop_ranges'] = [];
        $this->assertFalse(ip_in_spamhaus_drop(123456));
        $this->assertFalse(ip_in_spamhaus_drop(0));
    }

    // --- generator: spamhaus_drop_ranges_from_ndjson() ---------------------

    public function testGeneratorParsesMergesSortsAndSkips(): void
    {
        // Two adjacent /24s (must merge), an out-of-order /8, a /32, plus a
        // metadata line and an IPv6 cidr that must both be skipped.
        $ndjson = implode("\n", [
            '{"cidr":"192.0.2.0/24","sblid":"SBL1","rir":"ripencc"}',
            '{"cidr":"10.0.0.0/8","sblid":"SBL2","rir":"arin"}',
            '{"cidr":"192.0.3.0/24","sblid":"SBL3","rir":"ripencc"}',   // adjacent to 192.0.2.0/24
            '{"cidr":"203.0.113.5/32","sblid":"SBL4","rir":"arin"}',
            '{"cidr":"2001:db8::/32","sblid":"SBL5","rir":"ripencc"}',  // IPv6 -> skipped
            '{"type":"metadata","records":4,"copyright":"x"}',          // metadata -> skipped
            '',                                                          // blank -> skipped
        ]);

        $ranges = spamhaus_drop_ranges_from_ndjson($ndjson);

        $this->assertSame([
            [167772160, 184549375],    // 10.0.0.0/8
            [3221225984, 3221226495],  // 192.0.2.0/24 + 192.0.3.0/24 merged
            [3405803781, 3405803781],  // 203.0.113.5/32
        ], $ranges);
    }

    public function testGeneratorReturnsEmptyOnNoCidrs(): void
    {
        $this->assertSame([], spamhaus_drop_ranges_from_ndjson('{"type":"metadata"}'));
        $this->assertSame([], spamhaus_drop_ranges_from_ndjson(''));
    }

    public function testGeneratorOutputRoundTripsThroughLookup(): void
    {
        $ranges = spamhaus_drop_ranges_from_ndjson('{"cidr":"45.155.205.0/24"}');
        $GLOBALS['spamhaus_drop_ranges'] = $ranges;
        $this->assertTrue(ip_in_spamhaus_drop((int) sprintf('%u', ip2long('45.155.205.99'))));
        $this->assertFalse(ip_in_spamhaus_drop((int) sprintf('%u', ip2long('45.155.206.0'))));
    }

    // --- apply_reputation_override() ---------------------------------------

    public function testOverrideFlipsLowToModerateAndOpensCta(): void
    {
        $r = apply_reputation_override('LOW', false, 30, 3, '');
        $this->assertSame('MODERATE', $r['verdict_level']);
        $this->assertTrue($r['show_cta']);
        $this->assertSame('3 IPs on the Spamhaus DROP list (hijacked/criminal netblocks).', $r['verdict_reason']);
    }

    public function testOverrideNoopWhenNoReputationHits(): void
    {
        // The regression guard: 0 hits must return inputs byte-identical.
        $r = apply_reputation_override('LOW', false, 30, 0, '');
        $this->assertSame(['verdict_level' => 'LOW', 'show_cta' => false, 'verdict_reason' => ''], $r);
    }

    public function testOverrideRespectsFiveIpFloor(): void
    {
        $r = apply_reputation_override('LOW', false, 4, 2, '');
        $this->assertSame('LOW', $r['verdict_level']);
        $this->assertFalse($r['show_cta']);
    }

    public function testOverrideKeepsHighAndDoesNotClobberReason(): void
    {
        $r = apply_reputation_override('HIGH', true, 300, 5, '90% of IPs are confirmed scanning.');
        $this->assertSame('HIGH', $r['verdict_level']);
        $this->assertTrue($r['show_cta']);
        $this->assertSame('90% of IPs are confirmed scanning.', $r['verdict_reason']);
    }

    public function testOverrideOpensCtaForModerateAndSingularReason(): void
    {
        $r = apply_reputation_override('MODERATE', false, 5, 1, '');
        $this->assertTrue($r['show_cta']);
        $this->assertSame('1 IP on the Spamhaus DROP list (hijacked/criminal netblocks).', $r['verdict_reason']);
    }

    // --- build_teaser() drop_count -----------------------------------------

    public function testBuildTeaserCarriesDropCount(): void
    {
        $t = build_teaser([], 0, 80, 7);
        $this->assertSame(7, $t['drop_count']);
    }

    public function testBuildTeaserDropCountDefaultsToZeroAndClamps(): void
    {
        $this->assertSame(0, build_teaser([], 0)['drop_count']);
        $this->assertSame(0, build_teaser([], 0, 80, -3)['drop_count']);
    }

    // --- committed data file integrity -------------------------------------

    public function testCommittedDataFileIsSortedDisjointIntPairs(): void
    {
        $ranges = $this->origRanges;
        $this->assertIsArray($ranges);
        $this->assertNotEmpty($ranges, 'spamhaus_drop_data.php should contain ranges');

        $prevEnd = -1;
        foreach ($ranges as $i => $pair) {
            $this->assertIsArray($pair);
            $this->assertCount(2, $pair, "range $i must be [start, end]");
            [$s, $e] = $pair;
            $this->assertIsInt($s);
            $this->assertIsInt($e);
            $this->assertLessThanOrEqual($e, $s, "range $i: start must be <= end");
            $this->assertGreaterThan($prevEnd, $s, "range $i: must be sorted and disjoint from the previous");
            $this->assertLessThanOrEqual(4294967295, $e, "range $i: end must be within unsigned 32-bit");
            $prevEnd = $e;
        }
    }

    // --- perf guard: 10k lookups must be cheap against the real set --------

    public function testTenThousandLookupsAreFast(): void
    {
        $ranges = $this->origRanges;
        $this->assertNotEmpty($ranges);

        // Deterministic spread of IPs across the 32-bit space (no Math.random()).
        $ips = [];
        for ($i = 0; $i < 10000; $i++) {
            $ips[] = (int) (($i * 429496) % 4294967296);
        }

        $start = microtime(true);
        foreach ($ips as $ip) {
            ip_in_spamhaus_drop($ip);
        }
        $elapsed = microtime(true) - $start;

        // Real number is single-digit ms; 0.2s is a loose CI-flake-proof ceiling
        // that still proves the in-PHP binary search is nowhere near the 6s gate.
        $this->assertLessThan(0.2, $elapsed, sprintf('10k DROP lookups took %.4fs', $elapsed));
    }
}

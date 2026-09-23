<?php

declare(strict_types=1);

namespace Ip2Geo\Tests;

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../includes/summary.php';

/**
 * Tests for build_summary() (design doc D4/D5): base = resolved IPs, fixed
 * (not filter-driven), zero-count categories omitted, Unknown shown only
 * when above zero, top 3 ASNs by unique IPs, and the Spamhaus DROP count.
 */
class SummaryTest extends TestCase
{
    private function row(string $category, string $asn = '', string $org = '', bool $drop = false): array
    {
        return ['category' => $category, 'asn' => $asn, 'asn_org' => $org, 'drop' => $drop];
    }

    public function testEmptyRowsReturnsZeroedSummary(): void
    {
        $summary = build_summary([]);

        $this->assertSame(0, $summary['total']);
        $this->assertSame([], $summary['categories']);
        $this->assertSame([], $summary['top_asns']);
        $this->assertSame(0, $summary['drop_count']);
        $this->assertSame('', $summary['line']);
    }

    public function testZeroCountCategoriesAreOmitted(): void
    {
        $rows = [
            $this->row('cloud', 'AS1', 'A'),
            $this->row('cloud', 'AS1', 'A'),
        ];
        $summary = build_summary($rows);

        $keys = array_column($summary['categories'], 'key');
        $this->assertSame(['cloud'], $keys);
        $this->assertStringNotContainsString('Scanning', $summary['line']);
        $this->assertStringNotContainsString('VPN/Proxy', $summary['line']);
        $this->assertStringNotContainsString('Residential', $summary['line']);
        $this->assertStringNotContainsString('Unknown', $summary['line']);
    }

    public function testUnknownShownOnlyWhenAboveZero(): void
    {
        $rows = [$this->row('cloud', 'AS1', 'A'), $this->row('unknown')];
        $summary = build_summary($rows);

        $keys = array_column($summary['categories'], 'key');
        $this->assertContains('unknown', $keys);
        $this->assertStringContainsString('Unknown', $summary['line']);
    }

    public function testUnrecognizedCategoryFallsBackToUnknown(): void
    {
        $rows = [$this->row('bogus-category')];
        $summary = build_summary($rows);

        $this->assertSame(['unknown'], array_column($summary['categories'], 'key'));
    }

    public function testCategoriesOrderedByCountDescending(): void
    {
        // Matches the design doc's worked example ordering: the biggest
        // category leads, not a fixed vocabulary order.
        $rows = array_merge(
            array_fill(0, 2, $this->row('scanning')),
            array_fill(0, 6, $this->row('cloud')),
            array_fill(0, 1, $this->row('vpn'))
        );
        $summary = build_summary($rows);

        $this->assertSame(['cloud', 'scanning', 'vpn'], array_column($summary['categories'], 'key'));
    }

    public function testPercentagesRoundToNearestInt(): void
    {
        $rows = [$this->row('cloud'), $this->row('cloud'), $this->row('scanning')];
        $summary = build_summary($rows);

        $byKey = array_column($summary['categories'], null, 'key');
        $this->assertSame(67, $byKey['cloud']['pct']); // 2/3 -> 67%
        $this->assertSame(33, $byKey['scanning']['pct']); // 1/3 -> 33%
    }

    public function testBaseIsResolvedIpsNotFiltered(): void
    {
        // build_summary() takes exactly the rows it's given — it has no
        // notion of "currently filtered"; the caller is responsible for
        // always passing every resolved row (D4: "fixed, not filter-driven").
        $rows = [$this->row('cloud'), $this->row('scanning'), $this->row('vpn')];
        $summary = build_summary($rows);

        $this->assertSame(3, $summary['total']);
        $this->assertStringStartsWith('3 IPs looked up', $summary['line']);
    }

    public function testTopThreeAsnsByUniqueIps(): void
    {
        $rows = array_merge(
            array_fill(0, 5, $this->row('cloud', 'AS14061', 'DigitalOcean')),
            array_fill(0, 3, $this->row('cloud', 'AS16509', 'Amazon')),
            array_fill(0, 2, $this->row('cloud', 'AS4134', 'Chinanet')),
            array_fill(0, 1, $this->row('cloud', 'AS9999', 'Tiny ISP'))
        );
        $summary = build_summary($rows);

        $this->assertCount(3, $summary['top_asns']);
        $this->assertSame(
            ['AS14061', 'AS16509', 'AS4134'],
            array_column($summary['top_asns'], 'asn')
        );
        $this->assertSame([5, 3, 2], array_column($summary['top_asns'], 'count'));
        $this->assertStringContainsString(
            'top ASNs: AS14061 DigitalOcean, AS16509 Amazon, AS4134 Chinanet',
            $summary['line']
        );
    }

    public function testAsnCountIsUniqueIpsNotOccurrenceFrequency(): void
    {
        // Two distinct rows on the same ASN count as 2, regardless of any
        // per-IP occurrence frequency the caller might also be tracking —
        // build_summary() only ever sees one entry per resolved IP.
        $rows = [
            $this->row('scanning', 'AS100', 'Org'),
            $this->row('scanning', 'AS100', 'Org'),
        ];
        $summary = build_summary($rows);

        $this->assertSame(2, $summary['top_asns'][0]['count']);
    }

    public function testRowsWithNoAsnAreExcludedFromRanking(): void
    {
        $rows = [$this->row('unknown', ''), $this->row('cloud', 'AS1', 'A')];
        $summary = build_summary($rows);

        $this->assertCount(1, $summary['top_asns']);
        $this->assertSame('AS1', $summary['top_asns'][0]['asn']);
    }

    public function testDropCountFromDropFlag(): void
    {
        $rows = [
            $this->row('scanning', 'AS1', 'A', true),
            $this->row('scanning', 'AS1', 'A', false),
            $this->row('residential', '', '', true),
        ];
        $summary = build_summary($rows);

        $this->assertSame(2, $summary['drop_count']);
        $this->assertStringContainsString('2 in Spamhaus DROP netblocks', $summary['line']);
    }

    public function testDropLineOmittedWhenZero(): void
    {
        $rows = [$this->row('cloud')];
        $summary = build_summary($rows);

        $this->assertSame(0, $summary['drop_count']);
        $this->assertStringNotContainsString('Spamhaus DROP', $summary['line']);
    }

    public function testFullLineMatchesDesignDocExampleShape(): void
    {
        $rows = array_merge(
            array_fill(0, 61, $this->row('cloud', 'AS14061', 'DigitalOcean')),
            array_fill(0, 18, $this->row('scanning', 'AS16509', 'Amazon')),
            array_fill(0, 6, $this->row('vpn', 'AS4134', 'Chinanet')),
            array_fill(0, 15, $this->row('residential'))
        );
        // 14 DROP hits scattered across the set.
        for ($i = 0; $i < 14; $i++) {
            $rows[$i]['drop'] = true;
        }
        $summary = build_summary($rows);

        $this->assertSame(100, $summary['total']);
        $this->assertStringContainsString('100 IPs looked up', $summary['line']);
        $this->assertStringContainsString('Cloud exit 61 (61%)', $summary['line']);
        $this->assertStringContainsString('Scanning 18 (18%)', $summary['line']);
        $this->assertStringContainsString('VPN/Proxy 6 (6%)', $summary['line']);
        $this->assertStringContainsString('top ASNs:', $summary['line']);
        $this->assertStringContainsString('14 in Spamhaus DROP netblocks', $summary['line']);
    }
}

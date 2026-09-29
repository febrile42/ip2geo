<?php

declare(strict_types=1);

namespace Ip2Geo\Tests;

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../includes/summary.php';

/**
 * Tests for build_summary() (design doc D4/D5, slimmed by IPG-33): base =
 * resolved IPs, fixed (not filter-driven), zero-count categories omitted,
 * Unknown shown only when above zero, top 3 ASNs by unique IPs kept in the
 * return shape — but the rendered `line` now holds only the Spamhaus DROP
 * count and a single leading Top ASN (IPG-33).
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
        $this->assertNull($summary['top_asn']);
        $this->assertSame('', $summary['line']);
    }

    public function testNeitherFactAppliesRendersEmptyLine(): void
    {
        // No DROP rows and no ASN with a clear lead (single row, single ASN,
        // but only 1 IP on it — the 1-IP rule keeps this from being a "top").
        $rows = [$this->row('cloud', 'AS1', 'Org')];
        $summary = build_summary($rows);

        $this->assertSame(0, $summary['drop_count']);
        $this->assertNull($summary['top_asn']);
        $this->assertSame('', $summary['line']);
    }

    public function testZeroCountCategoriesAreOmittedFromCategoriesField(): void
    {
        // categories/top_asns stay in the return shape (other callers, e.g.
        // the filter chips, still use them) even though the line no longer
        // renders them.
        $rows = [
            $this->row('cloud', 'AS1', 'A'),
            $this->row('cloud', 'AS1', 'A'),
        ];
        $summary = build_summary($rows);

        $keys = array_column($summary['categories'], 'key');
        $this->assertSame(['cloud'], $keys);
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
        // category leads, not a fixed vocabulary order. (categories field
        // only — the line itself no longer shows category breakdowns.)
        $rows = array_merge(
            array_fill(0, 2, $this->row('scanning')),
            array_fill(0, 6, $this->row('cloud')),
            array_fill(0, 1, $this->row('vpn'))
        );
        $summary = build_summary($rows);

        $this->assertSame(['cloud', 'scanning', 'vpn'], array_column($summary['categories'], 'key'));
    }

    public function testBaseIsResolvedIpsNotFiltered(): void
    {
        // build_summary() takes exactly the rows it's given — it has no
        // notion of "currently filtered"; the caller is responsible for
        // always passing every resolved row (D4: "fixed, not filter-driven").
        $rows = [
            $this->row('cloud', 'AS1', 'Org', true),
            $this->row('scanning', 'AS2', 'Other', false),
            $this->row('vpn', 'AS3', 'Third', false),
        ];
        $summary = build_summary($rows);

        $this->assertSame(3, $summary['total']);
        $this->assertSame('1 IP in a Spamhaus DROP netblock', $summary['line']);
    }

    public function testTopThreeAsnsByUniqueIpsKeptInReturnShape(): void
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
        $rows = [$this->row('unknown', ''), $this->row('cloud', 'AS1', 'A'), $this->row('cloud', 'AS1', 'A')];
        $summary = build_summary($rows);

        $this->assertCount(1, $summary['top_asns']);
        $this->assertSame('AS1', $summary['top_asns'][0]['asn']);
    }

    // ── IPG-33: the slim line itself ───────────────────────────────────────

    public function testDropCountSingular(): void
    {
        $summary = build_summary([$this->row('scanning', '', '', true)]);

        $this->assertSame(1, $summary['drop_count']);
        $this->assertSame('1 IP in a Spamhaus DROP netblock', $summary['line']);
    }

    public function testDropCountPlural(): void
    {
        $rows = [
            $this->row('scanning', '', '', true),
            $this->row('scanning', '', '', true),
        ];
        $summary = build_summary($rows);

        $this->assertSame(2, $summary['drop_count']);
        $this->assertSame('2 IPs in Spamhaus DROP netblocks', $summary['line']);
    }

    public function testDropLineOmittedWhenZero(): void
    {
        $rows = [$this->row('cloud')];
        $summary = build_summary($rows);

        $this->assertSame(0, $summary['drop_count']);
        $this->assertStringNotContainsString('Spamhaus DROP', $summary['line']);
    }

    public function testDropCountUsesThousandsSeparator(): void
    {
        $rows = array_fill(0, 1204, $this->row('scanning', '', '', true));
        $summary = build_summary($rows);

        $this->assertSame(1204, $summary['drop_count']);
        $this->assertSame('1,204 IPs in Spamhaus DROP netblocks', $summary['line']);
    }

    public function testTopAsnShownWhenLeaderClearlyLeads(): void
    {
        $rows = array_merge(
            array_fill(0, 12, $this->row('cloud', 'AS64500', 'Example Hosting B.V.')),
            array_fill(0, 3, $this->row('cloud', 'AS64501', 'Runner Up LLC'))
        );
        $summary = build_summary($rows);

        $this->assertSame(['asn' => 'AS64500', 'org' => 'Example Hosting B.V.', 'count' => 12], $summary['top_asn']);
        $this->assertSame('Top ASN: AS64500 Example Hosting B.V. (12 IPs)', $summary['line']);
    }

    public function testTopAsnOmitsOrgWhenEmpty(): void
    {
        $rows = array_merge(
            array_fill(0, 3, $this->row('cloud', 'AS64500', '')),
            array_fill(0, 1, $this->row('cloud', 'AS64501', 'Other'))
        );
        $summary = build_summary($rows);

        $this->assertSame('Top ASN: AS64500 (3 IPs)', $summary['line']);
    }

    public function testTopAsnOmittedOnTie(): void
    {
        // Tie rule: 8.8.8.8/8.8.4.4 (Google) vs 1.1.1.1/1.0.0.1 (Cloudflare)
        // both land at 2 IPs — no Top ASN line, by design.
        $rows = array_merge(
            array_fill(0, 2, $this->row('cloud', 'AS15169', 'Google LLC')),
            array_fill(0, 2, $this->row('cloud', 'AS13335', 'Cloudflare, Inc.'))
        );
        $summary = build_summary($rows);

        $this->assertNull($summary['top_asn']);
        $this->assertStringNotContainsString('Top ASN', $summary['line']);
    }

    public function testTopAsnOmittedWhenLeaderHasOnlyOneIp(): void
    {
        // 1-IP rule: a lone leader with only 1 IP is not a finding, even
        // with no runner-up at all.
        $summary = build_summary([$this->row('cloud', 'AS1', 'Org')]);

        $this->assertNull($summary['top_asn']);
        $this->assertStringNotContainsString('Top ASN', $summary['line']);
    }

    public function testTopAsnShownWithNoRunnerUpAtAll(): void
    {
        // A single ASN with >= 2 IPs and nothing to tie against still counts
        // as a clear leader (vacuously "strictly more than the runner-up").
        $rows = array_fill(0, 2, $this->row('cloud', 'AS1', 'Org'));
        $summary = build_summary($rows);

        $this->assertNotNull($summary['top_asn']);
        $this->assertSame('Top ASN: AS1 Org (2 IPs)', $summary['line']);
    }

    public function testTopAsnUsesThousandsSeparator(): void
    {
        $rows = array_merge(
            array_fill(0, 1500, $this->row('cloud', 'AS64500', 'Example Hosting B.V.')),
            array_fill(0, 1, $this->row('cloud', 'AS64501', 'Other'))
        );
        $summary = build_summary($rows);

        $this->assertSame('Top ASN: AS64500 Example Hosting B.V. (1,500 IPs)', $summary['line']);
    }

    public function testBothFactsJoinedByMiddot(): void
    {
        $rows = array_merge(
            array_fill(0, 12, $this->row('cloud', 'AS64500', 'Example Hosting B.V.', true)),
            array_fill(0, 3, $this->row('cloud', 'AS64501', 'Runner Up LLC'))
        );
        $summary = build_summary($rows);

        $this->assertSame(
            '12 IPs in Spamhaus DROP netblocks · Top ASN: AS64500 Example Hosting B.V. (12 IPs)',
            $summary['line']
        );
    }
}

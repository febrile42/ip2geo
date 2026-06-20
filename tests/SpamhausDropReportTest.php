<?php

declare(strict_types=1);

namespace Ip2Geo\Tests;

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../report_functions.php';        // spamhaus_drop_cidr_for_ip(), compute_drop_report_data(), get_script_lines(), render_free_report()
require_once __DIR__ . '/../scripts/gen-spamhaus-drop.php'; // spamhaus_drop_cidrs_from_ndjson(), spamhaus_drop_ranges_from_ndjson()
require_once __DIR__ . '/../includes/page-chrome.php';     // render_page_open()/render_page_close() for the free render integration

/**
 * Surfacing Spamhaus DROP intel in the free + paid threat reports.
 *
 * Covers the new data layer (spamhaus_drop_cidr_for_ip + the generator's second
 * array), the script-line range inclusion, the shared report-data builder, and
 * an end-to-end render of the free report (pill + count line). The paid render
 * lives in report.php, which bootstraps a DB at file scope and so can't be
 * loaded in isolation; its DROP contract is proven here through the data builder
 * (on_drop / drop_count / drop_ranges) and get_script_lines() instead.
 */
class SpamhausDropReportTest extends TestCase
{
    /** @var array<int,array{0:int,1:int}>|null */
    private $origRanges;
    /** @var array<int,array{0:int,1:int,2:string}>|null */
    private $origCidrs;

    protected function setUp(): void
    {
        // Preserve the real committed globals; tests swap in deterministic
        // fixtures and tearDown restores so order never leaks state.
        $this->origRanges = $GLOBALS['spamhaus_drop_ranges'] ?? null;
        $this->origCidrs  = $GLOBALS['spamhaus_drop_cidrs'] ?? null;
    }

    protected function tearDown(): void
    {
        $GLOBALS['spamhaus_drop_ranges'] = $this->origRanges;
        $GLOBALS['spamhaus_drop_cidrs']  = $this->origCidrs;
    }

    /** Build both globals from one fixture so membership + CIDR lookup agree. */
    private function loadFixture(array $cidrStrings): void
    {
        $ndjson = implode("\n", array_map(
            fn($c) => json_encode(['cidr' => $c]),
            $cidrStrings
        ));
        $GLOBALS['spamhaus_drop_cidrs']  = spamhaus_drop_cidrs_from_ndjson($ndjson);
        $GLOBALS['spamhaus_drop_ranges'] = spamhaus_drop_ranges_from_ndjson($ndjson);
    }

    private function toInt(string $ip): int
    {
        return (int) sprintf('%u', ip2long($ip));
    }

    // ── spamhaus_drop_cidr_for_ip(): covering / most-specific / unlisted ────────

    public function testCidrForIpReturnsCoveringBlock(): void
    {
        $this->loadFixture(['45.155.205.0/24', '192.0.2.0/28']);
        $this->assertSame('45.155.205.0/24', spamhaus_drop_cidr_for_ip($this->toInt('45.155.205.99')));
        $this->assertSame('192.0.2.0/28',    spamhaus_drop_cidr_for_ip($this->toInt('192.0.2.5')));
    }

    public function testCidrForIpReturnsMostSpecificOnOverlap(): void
    {
        // A /16 containing a /24 containing a /28 — the IP sits in all three; the
        // tightest (longest-prefix) cover is the one to name and block.
        $this->loadFixture(['10.1.0.0/16', '10.1.2.0/24', '10.1.2.0/28']);
        $this->assertSame('10.1.2.0/28', spamhaus_drop_cidr_for_ip($this->toInt('10.1.2.5')));
        // An IP only inside the /24 (not the /28) gets the /24.
        $this->assertSame('10.1.2.0/24', spamhaus_drop_cidr_for_ip($this->toInt('10.1.2.200')));
        // An IP only inside the /16 gets the /16.
        $this->assertSame('10.1.0.0/16', spamhaus_drop_cidr_for_ip($this->toInt('10.1.50.1')));
    }

    public function testCidrForIpReturnsNullWhenUnlisted(): void
    {
        $this->loadFixture(['45.155.205.0/24']);
        $this->assertNull(spamhaus_drop_cidr_for_ip($this->toInt('8.8.8.8')));
        // Boundary: one above the listed /24 is unlisted.
        $this->assertNull(spamhaus_drop_cidr_for_ip($this->toInt('45.155.206.0')));
        // Empty data never matches.
        $GLOBALS['spamhaus_drop_cidrs'] = [];
        $this->assertNull(spamhaus_drop_cidr_for_ip($this->toInt('45.155.205.1')));
    }

    // ── generator: dual array, merged unchanged, cidr array shape ───────────────

    public function testGeneratorEmitsBothArraysFromOneParse(): void
    {
        $ndjson = implode("\n", [
            '{"cidr":"192.0.2.0/24","sblid":"SBL1"}',
            '{"cidr":"192.0.3.0/24","sblid":"SBL2"}',   // adjacent — merges in ranges, distinct in cidrs
            '{"cidr":"2001:db8::/32"}',                  // IPv6 — skipped in both
            '{"type":"metadata"}',                       // metadata — skipped in both
        ]);

        $cidrs  = spamhaus_drop_cidrs_from_ndjson($ndjson);
        $ranges = spamhaus_drop_ranges_from_ndjson($ndjson);

        // Un-merged: both /24s survive as separate [start,end,cidr] records.
        $this->assertSame([
            [3221225984, 3221226239, '192.0.2.0/24'],
            [3221226240, 3221226495, '192.0.3.0/24'],
        ], $cidrs);

        // Merged: the two adjacent /24s collapse to one range.
        $this->assertSame([[3221225984, 3221226495]], $ranges);
    }

    public function testGeneratorCidrArrayIsSortedIntIntStringTriples(): void
    {
        // Deliberately out of order; must come back ascending by start.
        $ndjson = implode("\n", [
            '{"cidr":"203.0.113.0/24"}',
            '{"cidr":"10.0.0.0/8"}',
            '{"cidr":"192.0.2.5/32"}',
        ]);
        $cidrs = spamhaus_drop_cidrs_from_ndjson($ndjson);

        $prevStart = -1;
        foreach ($cidrs as $rec) {
            $this->assertCount(3, $rec);
            [$s, $e, $cidr] = $rec;
            $this->assertIsInt($s);
            $this->assertIsInt($e);
            $this->assertIsString($cidr);
            $this->assertLessThanOrEqual($e, $s);
            $this->assertGreaterThanOrEqual($prevStart, $s, 'cidrs must be sorted ascending by start');
            $prevStart = $s;
        }
        $this->assertSame('10.0.0.0/8', $cidrs[0][2]);
    }

    /** The committed data file must define both globals with consistent shape. */
    public function testCommittedDataFileDefinesBothGlobals(): void
    {
        $ranges = $this->origRanges;
        $cidrs  = $this->origCidrs;
        $this->assertIsArray($ranges);
        $this->assertIsArray($cidrs);
        $this->assertNotEmpty($cidrs, 'spamhaus_drop_data.php should define $spamhaus_drop_cidrs');

        // Every original CIDR must be covered by some merged range (the merged
        // set is a superset of the originals — the hot path can't lose members).
        foreach (array_slice($cidrs, 0, 50) as $rec) {
            [$start] = $rec;
            $this->assertTrue(ip_in_spamhaus_drop($start), 'each original CIDR start must be in the merged set');
        }
    }

    // ── get_script_lines(): range formats include drop_ranges, IP formats don't ──

    private function reportWithDrop(): array
    {
        return [
            'block_ips'   => ['1.2.3.4'],
            'top25'       => [['ip' => '1.2.3.4']],
            'asn_ranges'  => [['cidrs' => ['10.0.0.0/8'], 'total' => 1]],
            'drop_ranges' => ['45.155.205.0/24', '185.220.101.0/24'],
        ];
    }

    public function testRangeFormatsIncludeDropRanges(): void
    {
        $report = $this->reportWithDrop();
        foreach (['sh-iptables-ranges', 'sh-ufw-ranges', 'nginx-ranges', 'txt-ranges'] as $fmt) {
            $joined = implode("\n", get_script_lines($fmt, $report, 'tok'));
            $this->assertStringContainsString('45.155.205.0/24', $joined, "$fmt must include the DROP netblock");
            $this->assertStringContainsString('185.220.101.0/24', $joined, "$fmt must include the DROP netblock");
            $this->assertStringContainsString('10.0.0.0/8', $joined, "$fmt must still include the ASN range");
        }
        // The DROP netblocks lead the ASN ranges in the range scripts.
        $txt = get_script_lines('txt-ranges', $report, 'tok');
        $this->assertLessThan(
            array_search('10.0.0.0/8', $txt, true),
            array_search('45.155.205.0/24', $txt, true),
            'DROP netblocks should precede ASN ranges'
        );
    }

    public function testRangeScriptsLabelDropAndAsnSections(): void
    {
        $report = $this->reportWithDrop();   // 2 DROP netblocks + 1 ASN range
        $sh = implode("\n", get_script_lines('sh-iptables-ranges', $report, 'tok'));

        // Honest header names the DROP netblocks apart from the ASN ranges.
        $this->assertStringContainsString('2 Spamhaus DROP criminal netblocks', $sh);
        $this->assertStringContainsString('1 scanning/VPN ASN range', $sh);
        $this->assertStringNotContainsString('covering scanning/VPN ASN prefixes', $sh);

        // Body carries a labeled section per group, DROP leading.
        $this->assertStringContainsString('# Spamhaus DROP', $sh);
        $this->assertStringContainsString('# Scanning / VPN ASN ranges', $sh);
        $this->assertLessThan(
            strpos($sh, '# Scanning / VPN ASN ranges'),
            strpos($sh, '# Spamhaus DROP'),
            'DROP section must lead the ASN section'
        );
    }

    public function testRangeScriptsOmitSectionLabelsWhenNoDrop(): void
    {
        $report = [
            'block_ips'   => ['1.2.3.4'],
            'top25'       => [['ip' => '1.2.3.4']],
            'asn_ranges'  => [['cidrs' => ['10.0.0.0/8'], 'total' => 1]],
            'drop_ranges' => [],
        ];
        $sh = implode("\n", get_script_lines('sh-iptables-ranges', $report, 'tok'));

        // No DROP data → ASN-only header, no DROP wording, no section dividers.
        $this->assertStringContainsString('covering scanning/VPN ASN prefixes', $sh);
        $this->assertStringNotContainsString('Spamhaus DROP', $sh);
        $this->assertStringNotContainsString('# Scanning / VPN ASN ranges', $sh);
        $this->assertStringContainsString('10.0.0.0/8', $sh);
    }

    public function testIpFormatsDoNotIncludeDropRanges(): void
    {
        $report = $this->reportWithDrop();
        foreach (['sh-iptables', 'sh-ufw', 'nginx-ips'] as $fmt) {
            $joined = implode("\n", get_script_lines($fmt, $report, 'tok'));
            $this->assertStringNotContainsString('45.155.205.0/24', $joined, "$fmt is IP-only and must not list DROP CIDRs");
            $this->assertStringContainsString('1.2.3.4', $joined, "$fmt must still list the blockable IP");
        }
    }

    // ── compute_drop_report_data(): on_drop, drop_count, drop_ranges, empty case ─

    public function testBuilderTagsOnDropAndCountsAllIps(): void
    {
        $this->loadFixture(['45.155.205.0/24', '185.220.101.0/24']);

        // 6 submitted IPs: 3 listed, 3 clean. Top25 shows only a subset.
        $all = [
            ['ip' => '45.155.205.1'], ['ip' => '45.155.205.2'], ['ip' => '185.220.101.9'],
            ['ip' => '8.8.8.8'], ['ip' => '1.1.1.1'], ['ip' => 'not-an-ip'],
        ];
        $top = [
            ['ip' => '45.155.205.1', 'classification' => 'scanning'],
            ['ip' => '8.8.8.8',      'classification' => 'residential'],
        ];

        $out = compute_drop_report_data($all, $top, true);

        // drop_count counts ALL submitted IPs (3), not just the 2 shown in top25.
        $this->assertSame(3, $out['drop_count']);
        // Per-entry on_drop set on the top25 we passed.
        $this->assertTrue($out['top25'][0]['on_drop']);
        $this->assertFalse($out['top25'][1]['on_drop']);
        // drop_ranges is the deduped, sorted set of covering CIDRs.
        $this->assertSame(['185.220.101.0/24', '45.155.205.0/24'], $out['drop_ranges']);
    }

    public function testBuilderFreeTierSkipsRanges(): void
    {
        $this->loadFixture(['45.155.205.0/24']);
        $all = [['ip' => '45.155.205.1'], ['ip' => '45.155.205.2']];
        $top = [['ip' => '45.155.205.1']];

        $out = compute_drop_report_data($all, $top, false);

        $this->assertSame(2, $out['drop_count']);
        $this->assertTrue($out['top25'][0]['on_drop']);
        // with_ranges=false ⇒ no drop_ranges collected.
        $this->assertSame([], $out['drop_ranges']);
    }

    public function testBuilderEmptyCaseYieldsZeroAndNoRanges(): void
    {
        $this->loadFixture(['45.155.205.0/24']);
        $all = [['ip' => '8.8.8.8'], ['ip' => '1.1.1.1']];
        $top = [['ip' => '8.8.8.8'], ['ip' => '1.1.1.1']];

        $out = compute_drop_report_data($all, $top, true);

        $this->assertSame(0, $out['drop_count']);
        $this->assertSame([], $out['drop_ranges']);
        $this->assertFalse($out['top25'][0]['on_drop']);
        $this->assertFalse($out['top25'][1]['on_drop']);
    }

    // ── Integration: free report render (pill + count line, no drop group) ──────

    public function testFreeReportRenderShowsPillAndCountNoDropGroup(): void
    {
        $report = [
            'verdict'        => 'MODERATE',
            'total_ips'      => 6,
            'scanning_pct'   => 50,
            'scanning_count' => 3,
            'cat_counts'     => [],
            'top_countries'  => [],
            'top25'          => [
                ['ip' => '45.155.205.1', 'country' => 'NL', 'asn' => 'AS1', 'asn_org' => 'BadCo', 'classification' => 'scanning',    'freq' => 9, 'on_drop' => true],
                ['ip' => '8.8.8.8',      'country' => 'US', 'asn' => 'AS2', 'asn_org' => 'GoodCo', 'classification' => 'residential', 'freq' => 1, 'on_drop' => false],
            ],
            'block_ips'      => [],
            'asn_ranges'     => [],
            'drop_count'     => 2,
            'generated_at'   => '2026-06-20 00:00:00',
            'abuseipdb_note' => null,
        ];

        $html = $this->renderFree($report, 'free-tok-123');

        // Verdict count line, with the count surfaced.
        $this->assertStringContainsString('report-drop-count', $html);
        $this->assertStringContainsString('Spamhaus DROP netblocks', $html);
        $this->assertStringContainsString('<strong>2</strong>', $html);

        // Per-IP DROP pill present for the listed IP, with the colorblind-safe text label.
        $this->assertStringContainsString('class="drop-flag"', $html);
        $this->assertStringContainsString('>DROP<', $html);

        // Free tier has no block layer: no paid drop-range group / chips.
        $this->assertStringNotContainsString('cidr-group--drop', $html);
        $this->assertStringNotContainsString('cidr-chip--drop', $html);
    }

    public function testFreeReportRenderNoCountLineWhenZeroDrops(): void
    {
        $report = [
            'verdict'        => 'LOW',
            'total_ips'      => 2,
            'scanning_pct'   => 0,
            'scanning_count' => 0,
            'cat_counts'     => [],
            'top_countries'  => [],
            'top25'          => [
                ['ip' => '8.8.8.8', 'country' => 'US', 'asn' => 'AS2', 'asn_org' => 'GoodCo', 'classification' => 'residential', 'freq' => 1, 'on_drop' => false],
            ],
            'block_ips'      => [],
            'asn_ranges'     => [],
            'drop_count'     => 0,
            'generated_at'   => '2026-06-20 00:00:00',
            'abuseipdb_note' => null,
        ];

        $html = $this->renderFree($report, 'free-tok-456');

        // drop_count == 0 ⇒ neither the count line nor a DROP pill renders.
        $this->assertStringNotContainsString('report-drop-count', $html);
        $this->assertStringNotContainsString('class="drop-flag"', $html);
    }

    /**
     * Render render_free_report() into a string. setcookie() emits a header
     * warning under CLI/PHPUnit (output already buffered); the @ swallows it so
     * the test asserts on markup, not on header timing.
     */
    private function renderFree(array $report, string $token): string
    {
        $prevHost = $_SERVER['HTTP_HOST'] ?? null;
        $_SERVER['HTTP_HOST'] = 'staging.ip2geo.org';
        ob_start();
        @render_free_report($report, $token, date('Y-m-d H:i:s', time() + 5 * 86400), []);
        $html = (string) ob_get_clean();
        if ($prevHost === null) {
            unset($_SERVER['HTTP_HOST']);
        } else {
            $_SERVER['HTTP_HOST'] = $prevHost;
        }
        return $html;
    }
}

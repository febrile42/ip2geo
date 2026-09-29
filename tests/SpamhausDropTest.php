<?php

declare(strict_types=1);

namespace Ip2Geo\Tests;

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../report_functions.php';      // ip_in_spamhaus_drop(), ip2geo_ip_in_spamhaus_drop()
require_once __DIR__ . '/../scripts/gen-spamhaus-drop.php'; // spamhaus_drop_ranges_from_ndjson() (CLI entry self-guards)

/**
 * Spamhaus DROP reputation axis: the ASN-agnostic signal that fires the CTA on
 * residential attackers the ASN verdict would otherwise miss.
 *
 * Covers the lookup (binary search), the generator (CIDR -> sorted/merged int
 * ranges, skipping metadata + IPv6), the attribution header written from the
 * feed's metadata record, the committed data files' integrity, and a perf
 * guard for the 10k hot loop.
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

    // --- generator CLI: Spamhaus attribution header (IPG-148) --------------

    private const FEED_CIDRS = '{"cidr":"192.0.2.0/24","sblid":"SBL1","rir":"ripencc"}' . "\n"
        . '{"cidr":"198.51.100.0/24","sblid":"SBL2","rir":"arin"}' . "\n";

    /** A metadata record shaped like the live feed's, with a timestamp no real sync will match. */
    private static function metadataLine(array $overrides = []): string
    {
        return json_encode(array_merge([
            'type'      => 'metadata',
            'timestamp' => 1790518442,
            'size'      => 104402,
            'records'   => 2,
            'copyright' => '(c) 2026 The Spamhaus Project SLU',
            'terms'     => 'https://www.spamhaus.org/drop/terms/',
        ], $overrides), JSON_UNESCAPED_SLASHES);
    }

    /**
     * Run the generator the way sync-spamhaus-drop.yml does (feed on stdin,
     * data file on stdout) and return [exit code, stdout].
     *
     * @return array{0:int,1:string}
     */
    private static function runGenerator(string $feed): array
    {
        $proc = proc_open(
            [PHP_BINARY, __DIR__ . '/../scripts/gen-spamhaus-drop.php'],
            [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes
        );
        fwrite($pipes[0], $feed);
        fclose($pipes[0]);
        $stdout = stream_get_contents($pipes[1]);
        stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        return [proc_close($proc), $stdout];
    }

    public function testGeneratorHeaderCarriesFeedCopyrightTimestampAndTerms(): void
    {
        [$code, $out] = self::runGenerator(self::FEED_CIDRS . self::metadataLine() . "\n");

        $this->assertSame(0, $code);
        $this->assertStringContainsString("// Copyright: (c) 2026 The Spamhaus Project SLU\n", $out);
        $this->assertStringContainsString("// Terms: https://www.spamhaus.org/drop/terms/\n", $out);
        $this->assertStringContainsString("// Feed timestamp: 1790518442 (2026-09-27T14:14:02Z)\n", $out);
        $this->assertStringContainsString("// Spamhaus data, not covered by this repository's license; see NOTICE.\n", $out);
        $this->assertMatchesRegularExpression('~^// Last sync: \d{4}-\d{2}-\d{2}$~m', $out);
    }

    public function testGeneratorRefusesFeedWithoutMetadataRecord(): void
    {
        [$code, $out] = self::runGenerator(self::FEED_CIDRS);

        $this->assertNotSame(0, $code, 'a feed with no metadata record must abort the sync');
        $this->assertSame('', $out, 'nothing may be written over the committed data file');
    }

    /** @dataProvider unusableMetadata */
    public function testGeneratorRefusesUnusableMetadata(array $overrides): void
    {
        [$code, $out] = self::runGenerator(self::FEED_CIDRS . self::metadataLine($overrides) . "\n");

        $this->assertNotSame(0, $code);
        $this->assertSame('', $out);
    }

    public static function unusableMetadata(): array
    {
        return [
            'no copyright'             => [['copyright' => null]],
            'no timestamp'             => [['timestamp' => null]],
            'no terms'                 => [['terms' => null]],
            'timestamp as a string'    => [['timestamp' => '1790518442']],
            'terms not https'          => [['terms' => 'http://www.spamhaus.org/drop/terms/']],
            // Both would let feed text escape the // comment into executable PHP.
            'newline in copyright'     => [['copyright' => "(c) 2026 Spamhaus\nphpinfo();"]],
            'close tag in terms'       => [['terms' => 'https://example.com/?>x']],
            // A fake END marker in the ASN-DROP block header orphans the old
            // block on the next sync-spamhaus.yml run (IPG-153).
            'END marker in copyright'  => [['copyright' => '(c) 2026 Spamhaus // --- END AUTO-SYNC SPAMHAUS ASN-DROP ---']],
            'AUTO-SYNC in terms'       => [['terms' => 'https://example.com/AUTO-SYNC']],
            'bidi override'            => [['copyright' => "(c) 2026 \u{202E}ULS tcejorP ahmapS"]],
            'zero-width space'         => [['copyright' => "(c) 2026 Spam\u{200B}haus"]],
            'line separator'           => [['copyright' => "(c) 2026 Spamhaus\u{2028}x"]],
            'copyright of 201 chars'   => [['copyright' => str_repeat('a', 201)]],
            'space in terms'           => [['terms' => 'https://www.spamhaus.org/drop/terms/ x']],
        ];
    }

    public function testGeneratorAcceptsCopyrightSign(): void
    {
        [$code, $out] = self::runGenerator(
            self::FEED_CIDRS . self::metadataLine(['copyright' => '© 2026 The Spamhaus Project SLU']) . "\n"
        );

        $this->assertSame(0, $code);
        $this->assertStringContainsString("// Copyright: © 2026 The Spamhaus Project SLU\n", $out);
    }

    public function testFeedHeaderLinesForAsnDropBlock(): void
    {
        // sync-spamhaus.yml writes these lines into the ASN-DROP block header.
        $meta = spamhaus_feed_metadata(
            '{"asn":245,"rir":"arin"}' . "\n" . self::metadataLine(['timestamp' => 1790522042])
        );
        $this->assertSame([
            'Copyright: (c) 2026 The Spamhaus Project SLU',
            'Terms: https://www.spamhaus.org/drop/terms/',
            'Feed timestamp: 1790522042 (2026-09-27T15:14:02Z)',
        ], spamhaus_feed_header_lines($meta));
    }

    // --- ASN-DROP: only numeric ASNs reach asn_classification.php (IPG-154) --

    public function testAsnDropAsnsAreSortedDedupedAndSkipMetadata(): void
    {
        $feed = '{"asn":3507,"rir":"arin"}' . "\n"
            . '{"asn":245,"rir":"arin"}' . "\n"
            . '{"asn":3507,"rir":"arin"}' . "\n"
            . '{"asn":4294967295,"rir":"arin"}' . "\n"
            . self::metadataLine() . "\n";
        $this->assertSame(['AS245', 'AS3507', 'AS4294967295'], spamhaus_asndrop_asns($feed));
    }

    /** @dataProvider unusableAsnDropFeeds */
    public function testAsnDropAsnsRefusesFeed(string $feed): void
    {
        $this->assertNull(spamhaus_asndrop_asns($feed));
    }

    public static function unusableAsnDropFeeds(): array
    {
        $ok = '{"asn":245,"rir":"arin"}' . "\n";
        return [
            // Would be written as '1' => x, '' => 'scanning', and pass php -l.
            'string asn breaking out of the quote' => [$ok . '{"asn":"1\' => x, \'"}' . "\n"],
            'numeric string asn'                   => [$ok . '{"asn":"245"}' . "\n"],
            'float asn'                            => [$ok . '{"asn":245.5}' . "\n"],
            'zero'                                 => [$ok . '{"asn":0}' . "\n"],
            'negative'                             => [$ok . '{"asn":-1}' . "\n"],
            'above 32 bits'                        => [$ok . '{"asn":4294967296}' . "\n"],
            'boolean'                              => [$ok . '{"asn":true}' . "\n"],
            'array'                                => [$ok . '{"asn":[245]}' . "\n"],
            'line that is not JSON'                => [$ok . "AS666\n"],
            'no ASNs, only metadata'               => [self::metadataLine() . "\n"],
            'empty'                                => [''],
        ];
    }

    private const ASN_BLOCK_BEGIN = '    // --- BEGIN AUTO-SYNC SPAMHAUS ASN-DROP (do not hand-edit) ---';
    private const ASN_BLOCK_END   = '    // --- END AUTO-SYNC SPAMHAUS ASN-DROP ---';

    private static function asnFile(string ...$blockLines): string
    {
        return "<?php\n\$known_asns = [\n    'AS1' => 'hosting',\n" . self::ASN_BLOCK_BEGIN . "\n"
            . implode('', array_map(static fn($l) => "{$l}\n", $blockLines))
            . self::ASN_BLOCK_END . "\n];\n";
    }

    public function testAsnDropBlockCheckAcceptsCommentsAndEntries(): void
    {
        $this->assertTrue(spamhaus_asndrop_block_is_safe(self::asnFile(
            '    // Copyright: © 2026 The Spamhaus Project SLU',
            "    'AS245' => 'scanning',",
            "    'AS4294967295' => 'scanning',"
        )));
    }

    public function testCommittedAsnDropBlockPassesCheck(): void
    {
        $this->assertTrue(spamhaus_asndrop_block_is_safe(
            file_get_contents(__DIR__ . '/../asn_classification.php')
        ));
    }

    /** @dataProvider unsafeAsnBlocks */
    public function testAsnDropBlockCheckRefuses(string $src): void
    {
        $this->assertFalse(spamhaus_asndrop_block_is_safe($src));
    }

    public static function unsafeAsnBlocks(): array
    {
        return [
            // What today's jq filter writes for {"asn":"1' => x, '"}.
            'injected entry'        => [self::asnFile("    'AS1' => x, '' => 'scanning',")],
            'code line'             => [self::asnFile('    phpinfo(),')],
            'other category'        => [self::asnFile("    'AS245' => 'hosting',")],
            'trailing text'         => [self::asnFile("    'AS245' => 'scanning', phpinfo(),")],
            'close tag in comment'  => [self::asnFile('    // x ?> <?php phpinfo(); //')],
            'CR in comment'         => [self::asnFile("    // x\rphpinfo(); //")],
            'unindented comment'    => [self::asnFile('// x')],
            'blank line'            => [self::asnFile('')],
            'no markers'            => ["<?php\n\$known_asns = [\n    'AS1' => 'hosting',\n];\n"],
            'second END marker'     => [self::asnFile(self::ASN_BLOCK_END, "    'AS245' => 'scanning',")],
            'END before BEGIN'      => ["<?php\n" . self::ASN_BLOCK_END . "\n" . self::ASN_BLOCK_BEGIN . "\n"],
        ];
    }

    /**
     * The sync must go through the two checks above; fails if the workflow
     * goes back to writing whatever jq's tostring returns.
     */
    public function testSyncWorkflowUsesAsnChecks(): void
    {
        $yml = file_get_contents(__DIR__ . '/../.github/workflows/sync-spamhaus.yml');
        $this->assertStringContainsString('spamhaus_asndrop_asns(', $yml);
        $this->assertStringContainsString('spamhaus_asndrop_block_is_safe(', $yml);
        $this->assertStringNotContainsString('tostring', $yml);
        $this->assertLessThan(
            strpos($yml, 'php -l "$CLASSIFICATION_FILE"'),
            strpos($yml, 'spamhaus_asndrop_block_is_safe('),
            'the block check must run before php -l and the commit'
        );
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

    /**
     * The committed data files must carry the feed's own attribution. Fails if a
     * rebase or hand edit brings back a header without it.
     */
    public function testCommittedDataFilesCarrySpamhausAttribution(): void
    {
        $drop = file_get_contents(__DIR__ . '/../spamhaus_drop_data.php');
        $this->assertMatchesRegularExpression('~^// Copyright: \(c\) \d{4} The Spamhaus Project SLU$~m', $drop);
        $this->assertMatchesRegularExpression('~^// Feed timestamp: \d+ \(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\)$~m', $drop);

        $asn = file_get_contents(__DIR__ . '/../asn_classification.php');
        $block = substr($asn, strpos($asn, '// --- BEGIN AUTO-SYNC SPAMHAUS ASN-DROP'));
        $this->assertMatchesRegularExpression('~^    // Copyright: \(c\) \d{4} The Spamhaus Project SLU$~m', $block);
        $this->assertMatchesRegularExpression('~^    // Feed timestamp: \d+ \(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\)$~m', $block);
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

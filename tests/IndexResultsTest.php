<?php

declare(strict_types=1);

namespace Ip2Geo\Tests;

use PHPUnit\Framework\TestCase;

/**
 * Tests for index.php's results rendering.
 *
 * index.php always requires config.php in the historical version, and even
 * without that it renders a full standalone HTML page (head, nav, form,
 * footer, inline scripts) as a side effect of being included — not
 * something worth booting for a unit test. Per the task brief's fallback
 * ("if rendering index.php in a test is impractical, extract the results
 * rendering into a function and test that"), the results section was
 * pulled into render_lookup_results(): a pure-ish function of ($post,
 * $visitor_ip, $city_db, $asn_db) that returns the #results HTML string.
 *
 * Defining IP2GEO_SKIP_PAGE_RENDER before requiring index.php gets every
 * function defined in the file (render_lookup_results(), getRealIPAddr(),
 * ipv6_middle_truncate(), ip2geo_index_cache_control(), ...) without
 * executing the page body — no header()/session/HTML output, and no
 * config.php required.
 *
 * Uses MaxMind's own test .mmdb fixtures (tests/fixtures/mmdb/), same as
 * LookupTest.php and ApiLookupTest.php, so this runs offline.
 */
class IndexResultsTest extends TestCase
{
    private const FIXTURE_DIR = __DIR__ . '/fixtures/mmdb';
    private const CITY_DB     = self::FIXTURE_DIR . '/GeoIP2-City-Test.mmdb';
    private const ASN_DB      = self::FIXTURE_DIR . '/GeoLite2-ASN-Test.mmdb';

    public static function setUpBeforeClass(): void
    {
        if (!defined('IP2GEO_SKIP_PAGE_RENDER')) {
            define('IP2GEO_SKIP_PAGE_RENDER', true);
        }
        require_once __DIR__ . '/../index.php';
    }

    // ── No paid-tier debris (R17) ───────────────────────────────────────────

    public function testResultsHaveNoThreatReportCta(): void
    {
        $html = render_lookup_results(['ip_list' => '81.2.69.142'], '', self::CITY_DB, self::ASN_DB);

        $this->assertStringNotContainsString('Get Free Threat Report', $html);
        $this->assertStringNotContainsString('$9', $html);
        $this->assertStringNotContainsString('threat-cta', $html);
    }

    // ── Summary line (D4/D5) ────────────────────────────────────────────────

    public function testSummaryLinePresentForResolvedIps(): void
    {
        $html = render_lookup_results(['ip_list' => '81.2.69.142 1.0.0.1'], '', self::CITY_DB, self::ASN_DB);

        $this->assertStringContainsString('id="lookup-summary"', $html);
        $this->assertStringContainsString('IPs looked up', $html);
    }

    public function testNoSummaryLineWhenNothingResolves(): void
    {
        // Neither address is in the test fixture dbs, so both are unresolved
        // and build_summary() gets zero rows — no summary line to show.
        $html = render_lookup_results(['ip_list' => '203.0.113.1'], '', self::CITY_DB, self::ASN_DB);

        $this->assertStringNotContainsString('id="lookup-summary"', $html);
    }

    // ── IPv6 rows are normal rows (v5.0.0 release plan: real IPv6 lookup) ──

    public function testIpv6RowRendersWithLookupData(): void
    {
        $html = render_lookup_results(['ip_list' => '2001:220::'], '', self::CITY_DB, self::ASN_DB);

        $this->assertStringContainsString('2001:220::', $html);
        $this->assertStringContainsString('KR', $html); // South Korea, from the fixture db
        $this->assertStringNotContainsString('lookup coming', $html);
    }

    public function testMixedV4V6BothAppearAsResolvedRows(): void
    {
        $html = render_lookup_results(['ip_list' => '81.2.69.142 and 2001:220::'], '', self::CITY_DB, self::ASN_DB);

        $this->assertStringContainsString('81.2.69.142', $html);
        $this->assertStringContainsString('2001:220::', $html);
    }

    // ── DROP tag (D5) — IPv4 only ────────────────────────────────────────────

    public function testDropTagOmittedWhenIpNotInDropList(): void
    {
        $html = render_lookup_results(['ip_list' => '81.2.69.142'], '', self::CITY_DB, self::ASN_DB);

        $this->assertStringNotContainsString('drop-tag', $html);
    }

    public function testDropCountAppearsInSummaryWhenAnIpIsListed(): void
    {
        // Pick a real Spamhaus DROP-listed IPv4 from the synced data so the
        // ip_in_spamhaus_drop() hot path actually returns true. Reads the
        // first CIDR from spamhaus_drop_data.php and uses its base address.
        $ip = self::firstDropListedIp();
        if ($ip === null) {
            $this->markTestSkipped('spamhaus_drop_data.php has no ranges to test against.');
        }

        $html = render_lookup_results(['ip_list' => $ip], '', self::CITY_DB, self::ASN_DB);

        // The fixture DBs may not resolve this IP to a country/ASN at all,
        // in which case it lands in "no geo data" and never reaches the
        // DROP check — only assert the DROP surfaces when the row resolved.
        if (str_contains($html, 'id="lookup-summary"')) {
            $this->assertStringContainsString('DROP', $html);
        } else {
            $this->markTestSkipped('Chosen DROP IP is not covered by the MaxMind test fixture dbs.');
        }
    }

    private static function firstDropListedIp(): ?string
    {
        global $spamhaus_drop_cidrs;
        require_once __DIR__ . '/../spamhaus_drop_data.php';
        if (empty($spamhaus_drop_cidrs)) {
            return null;
        }
        $startInt = $spamhaus_drop_cidrs[0][0];
        return long2ip($startInt < 0 ? $startInt : (int) $startInt);
    }

    // ── "(you)" row (R16) ────────────────────────────────────────────────────

    public function testVisitorRowMarkedYou(): void
    {
        $html = render_lookup_results(['ip_list' => '81.2.69.142'], '81.2.69.142', self::CITY_DB, self::ASN_DB);

        $this->assertStringContainsString('you-tag', $html);
        $this->assertStringContainsString('(you)', $html);
    }

    public function testNoYouTagWhenVisitorIpNotInResults(): void
    {
        $html = render_lookup_results(['ip_list' => '81.2.69.142'], '198.51.100.9', self::CITY_DB, self::ASN_DB);

        $this->assertStringNotContainsString('you-tag', $html);
    }

    // ── D6 states ────────────────────────────────────────────────────────────

    public function testEmptyStateWhenNoIpsFound(): void
    {
        $html = render_lookup_results(['ip_list' => 'no ips in this text at all'], '', self::CITY_DB, self::ASN_DB);

        $this->assertStringContainsString('No IP addresses found', $html);
    }

    public function testPrivateOnlyState(): void
    {
        $html = render_lookup_results(['ip_list' => '192.168.1.1 10.0.0.1'], '', self::CITY_DB, self::ASN_DB);

        $this->assertStringContainsString('all private or internal', $html);
    }

    public function testOver2MbState(): void
    {
        $html = render_lookup_results(['ip_list' => str_repeat('a', 2097153)], '', self::CITY_DB, self::ASN_DB);

        $this->assertStringContainsString('over 2 MB', $html);
    }

    public function test503WhenGeoDbUnavailable(): void
    {
        $html = render_lookup_results(
            ['ip_list' => '81.2.69.142'],
            '',
            self::FIXTURE_DIR . '/does-not-exist.mmdb',
            self::ASN_DB
        );

        $this->assertStringContainsString('updating', $html);
        $this->assertStringContainsString('role="alert"', $html);
    }

    public function testOver10kNotice(): void
    {
        // 12,001 unique public IPv4 addresses — over EXTRACT_IPS_CAP (10,000).
        $ips = [];
        for ($i = 0; $i < 12001; $i++) {
            $ips[] = sprintf('203.%d.%d.%d', intdiv($i, 65536) + 1, intdiv($i, 256) % 256, $i % 256);
        }
        $html = render_lookup_results(['ip_list' => implode(' ', $ips)], '', self::CITY_DB, self::ASN_DB);

        $this->assertStringContainsString('Looked up the first 10,000 of', $html);
        $this->assertStringContainsString('skipped', $html);
    }

    // ── Cache-Control (R16) ─────────────────────────────────────────────────

    public function testCacheControlHelperReturnsPrivateNoStore(): void
    {
        // index.php calls header('Cache-Control: ' . ip2geo_index_cache_control())
        // before any output; PHP's CLI SAPI doesn't expose headers_list() the
        // way a real request would, so the value is asserted at the source
        // instead (same header() call site the page uses).
        $this->assertSame('private, no-store', ip2geo_index_cache_control());
    }
}

<?php

declare(strict_types=1);

namespace Ip2Geo\Tests;

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../includes/lookup.php';

/**
 * Tests for includes/lookup.php's lookup_ips() (R4).
 *
 * Uses MaxMind's official TEST databases (tests/fixtures/mmdb/, see the
 * README there for source and license) so these run offline and never
 * touch the real, license-restricted GeoLite2 data.
 */
class LookupTest extends TestCase
{
    private const FIXTURE_DIR = __DIR__ . '/fixtures/mmdb';
    private const CITY_DB     = self::FIXTURE_DIR . '/GeoIP2-City-Test.mmdb';
    private const ASN_DB      = self::FIXTURE_DIR . '/GeoLite2-ASN-Test.mmdb';

    protected function setUp(): void
    {
        reset_lookup_reader_open_count();
    }

    // ── v4 present ───────────────────────────────────────────────────────────

    public function testIpv4InCityDbReturnsGeoFields(): void
    {
        $result = lookup_ips(['81.2.69.142'], self::CITY_DB, self::ASN_DB);

        $this->assertArrayHasKey('81.2.69.142', $result);
        $row = $result['81.2.69.142'];
        $this->assertSame('GB', $row['country_iso_code']);
        $this->assertSame('United Kingdom', $row['country_name']);
        $this->assertSame('England', $row['subdivision_1_name']);
        $this->assertSame('London', $row['city_name']);
        // Not covered by the ASN test fixture's ranges — null, not an error.
        $this->assertNull($row['autonomous_system_number']);
        $this->assertNull($row['autonomous_system_org']);
    }

    public function testIpv4InAsnDbReturnsAsnFields(): void
    {
        $result = lookup_ips(['1.0.0.1'], self::CITY_DB, self::ASN_DB);

        $this->assertArrayHasKey('1.0.0.1', $result);
        $row = $result['1.0.0.1'];
        $this->assertSame(15169, $row['autonomous_system_number']);
        $this->assertSame('Google Inc.', $row['autonomous_system_org']);
    }

    // ── v6 present ───────────────────────────────────────────────────────────

    public function testIpv6InCityDbReturnsGeoFields(): void
    {
        $result = lookup_ips(['2001:220::'], self::CITY_DB, self::ASN_DB);

        $this->assertArrayHasKey('2001:220::', $result);
        $row = $result['2001:220::'];
        $this->assertSame('KR', $row['country_iso_code']);
        $this->assertSame('South Korea', $row['country_name']);
        // No subdivisions/city in this fixture record.
        $this->assertNull($row['subdivision_1_name']);
        $this->assertNull($row['city_name']);
    }

    // ── not in either db ─────────────────────────────────────────────────────

    public function testIpNotInDbReturnsAllNullFields(): void
    {
        $result = lookup_ips(['203.0.113.1', '2001:db8::1'], self::CITY_DB, self::ASN_DB);

        foreach (['203.0.113.1', '2001:db8::1'] as $ip) {
            $this->assertArrayHasKey($ip, $result);
            foreach ($result[$ip] as $field => $value) {
                $this->assertNull($value, "expected null for {$field} on {$ip}");
            }
        }
    }

    // ── missing / corrupt db ────────────────────────────────────────────────

    public function testMissingCityDbThrows(): void
    {
        $this->expectException(\GeoDbUnavailableException::class);
        lookup_ips(['81.2.69.142'], self::FIXTURE_DIR . '/does-not-exist.mmdb', self::ASN_DB);
    }

    public function testMissingAsnDbThrows(): void
    {
        $this->expectException(\GeoDbUnavailableException::class);
        lookup_ips(['81.2.69.142'], self::CITY_DB, self::FIXTURE_DIR . '/does-not-exist.mmdb');
    }

    public function testCorruptDbThrows(): void
    {
        $corrupt = tempnam(sys_get_temp_dir(), 'ip2geo-corrupt-mmdb-');
        file_put_contents($corrupt, "not a real mmdb file\x00\x01\x02");

        try {
            $this->expectException(\GeoDbUnavailableException::class);
            lookup_ips(['81.2.69.142'], $corrupt, self::ASN_DB);
        } finally {
            @unlink($corrupt);
        }
    }

    // ── reader reuse (R4/P2: one reader per db per call, not per IP) ────────

    public function testReaderIsOpenedOncePerDatabaseNotPerIp(): void
    {
        $ips = ['81.2.69.142', '1.0.0.1', '203.0.113.1', '2001:220::', '2001:db8::1'];

        reset_lookup_reader_open_count();
        lookup_ips($ips, self::CITY_DB, self::ASN_DB);

        // Exactly one open for the city db + one for the asn db, regardless
        // of how many IPs were looked up.
        $this->assertSame(2, lookup_reader_open_count());
    }

    public function testReaderOpenCountScalesWithCallsNotIps(): void
    {
        reset_lookup_reader_open_count();
        lookup_ips(['81.2.69.142'], self::CITY_DB, self::ASN_DB);
        lookup_ips(['1.0.0.1'], self::CITY_DB, self::ASN_DB);

        $this->assertSame(4, lookup_reader_open_count()); // 2 calls × 2 dbs
    }

    // ── default paths (GEOIP_MMDB_DIR) ──────────────────────────────────────

    public function testDefaultConstantIsDefined(): void
    {
        $this->assertTrue(defined('GEOIP_MMDB_DIR'));
    }
}

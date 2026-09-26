<?php

declare(strict_types=1);

namespace Ip2Geo\Tests;

use PHPUnit\Framework\TestCase;

// api/lookup.php's HTTP-wiring tail only runs when SCRIPT_FILENAME matches
// the file itself (see the guard at the bottom of that file), which it
// never does under phpunit — so requiring it here only defines the
// testable functions (handle_lookup_request() and friends), same as
// ReportFunctionsTest.php requiring report_functions.php directly.
require_once __DIR__ . '/../api/lookup.php';

/**
 * Tests for the api/lookup.php request contract (R4/T9): caps (413), APCu
 * rate limiting (429), missing/corrupt db (503), success (200), and that
 * request bodies never reach error_log.
 */
class ApiLookupTest extends TestCase
{
    private const FIXTURE_DIR = __DIR__ . '/fixtures/mmdb';
    private const CITY_DB     = self::FIXTURE_DIR . '/GeoIP2-City-Test.mmdb';
    private const ASN_DB      = self::FIXTURE_DIR . '/GeoLite2-ASN-Test.mmdb';

    private string $errorLogFile;
    private string $prevErrorLog;

    protected function setUp(): void
    {
        $this->errorLogFile = tempnam(sys_get_temp_dir(), 'ip2geo-errorlog-');
        $this->prevErrorLog = ini_get('error_log') ?: '';
        ini_set('error_log', $this->errorLogFile);
    }

    protected function tearDown(): void
    {
        ini_set('error_log', $this->prevErrorLog);
        @unlink($this->errorLogFile);
    }

    private function realLookup(): callable
    {
        return static fn(array $ips): array => \lookup_ips($ips, self::CITY_DB, self::ASN_DB);
    }

    private function notLimited(): callable
    {
        return static fn(string $ip): array => ['limited' => false, 'retry_after' => 0];
    }

    private function limited(int $retryAfter = 42): callable
    {
        return static fn(string $ip): array => ['limited' => true, 'retry_after' => $retryAfter];
    }

    private function errorLogContents(): string
    {
        return (string)@file_get_contents($this->errorLogFile);
    }

    // ── 200 success ──────────────────────────────────────────────────────────

    public function testSuccessfulLookupReturns200WithResultsAndUnresolved(): void
    {
        $body = json_encode(['ips' => ['81.2.69.142', '1.0.0.1', 'not-an-ip']]);

        $result = handle_lookup_request(
            ['REQUEST_METHOD' => 'POST', 'REMOTE_ADDR' => '198.51.100.1'],
            $body,
            $this->realLookup(),
            $this->notLimited()
        );

        $this->assertSame(200, $result['status']);
        $decoded = json_decode($result['body'], true);

        $this->assertCount(2, $decoded['results']);
        $this->assertSame(['not-an-ip'], $decoded['unresolved']);

        $byIp = [];
        foreach ($decoded['results'] as $row) {
            $byIp[$row['ip']] = $row;
        }
        $this->assertSame('GB', $byIp['81.2.69.142']['country_iso_code']);
        $this->assertArrayHasKey('category', $byIp['81.2.69.142']);
        $this->assertArrayHasKey('drop', $byIp['81.2.69.142']);
        $this->assertSame(15169, $byIp['1.0.0.1']['autonomous_system_number']);
    }

    public function testIpv6ResultNeverChecksSpamhausDropTrue(): void
    {
        $body = json_encode(['ips' => ['2001:220::']]);

        $result = handle_lookup_request(
            ['REQUEST_METHOD' => 'POST', 'REMOTE_ADDR' => '198.51.100.1'],
            $body,
            $this->realLookup(),
            $this->notLimited()
        );

        $decoded = json_decode($result['body'], true);
        $this->assertFalse($decoded['results'][0]['drop']);
    }

    // ── 413: body too large ─────────────────────────────────────────────────

    public function testOversizedBodyReturns413(): void
    {
        $hugeBody = json_encode(['ips' => ['1.2.3.4']]) . str_repeat('x', 2 * 1024 * 1024 + 1);

        $result = handle_lookup_request(
            ['REQUEST_METHOD' => 'POST', 'REMOTE_ADDR' => '198.51.100.1'],
            $hugeBody,
            $this->realLookup(),
            $this->notLimited()
        );

        $this->assertSame(413, $result['status']);
        $this->assertStringContainsString('too large', json_decode($result['body'], true)['error']);
    }

    // ── 413: too many unique IPs ─────────────────────────────────────────────

    public function testTooManyUniqueIpsReturns413(): void
    {
        $ips  = [];
        for ($i = 0; $i < 10001; $i++) {
            $ips[] = long2ip($i + 1000000);
        }
        $body = json_encode(['ips' => $ips]);

        $result = handle_lookup_request(
            ['REQUEST_METHOD' => 'POST', 'REMOTE_ADDR' => '198.51.100.1'],
            $body,
            $this->realLookup(),
            $this->notLimited()
        );

        $this->assertSame(413, $result['status']);
        $this->assertStringContainsString('max 10,000', json_decode($result['body'], true)['error']);
    }

    public function testDuplicateIpsAreDedupedBeforeTheCap(): void
    {
        $ips  = array_fill(0, 20000, '81.2.69.142'); // 20k entries, 1 unique
        $body = json_encode(['ips' => $ips]);

        $result = handle_lookup_request(
            ['REQUEST_METHOD' => 'POST', 'REMOTE_ADDR' => '198.51.100.1'],
            $body,
            $this->realLookup(),
            $this->notLimited()
        );

        $this->assertSame(200, $result['status']);
        $this->assertCount(1, json_decode($result['body'], true)['results']);
    }

    // ── 429: rate limited ────────────────────────────────────────────────────

    public function testRateLimitedReturns429WithRetryAfterHeader(): void
    {
        $body = json_encode(['ips' => ['1.2.3.4']]);

        $result = handle_lookup_request(
            ['REQUEST_METHOD' => 'POST', 'REMOTE_ADDR' => '198.51.100.1'],
            $body,
            $this->realLookup(),
            $this->limited(17)
        );

        $this->assertSame(429, $result['status']);
        $this->assertSame('17', $result['headers']['Retry-After']);
    }

    // ── 503: missing / corrupt db ────────────────────────────────────────────

    public function testMissingDbReturns503WithoutLoggingTheBody(): void
    {
        $secretLookingBody = json_encode(['ips' => ['203.0.113.99', '198.51.100.42']]);

        $throwingLookup = static function (array $ips): array {
            throw new \GeoDbUnavailableException('db missing for test');
        };

        $result = handle_lookup_request(
            ['REQUEST_METHOD' => 'POST', 'REMOTE_ADDR' => '198.51.100.1'],
            $secretLookingBody,
            $throwingLookup,
            $this->notLimited()
        );

        $this->assertSame(503, $result['status']);
        $this->assertSame(
            'Lookup data is updating. Try again in a minute.',
            json_decode($result['body'], true)['error']
        );

        $logged = $this->errorLogContents();
        $this->assertStringNotContainsString('203.0.113.99', $logged);
        $this->assertStringNotContainsString('198.51.100.42', $logged);
    }

    // ── client IP selection ──────────────────────────────────────────────────

    /** Runs one request and returns the key the rate limiter was called with. */
    private function rateLimitKeyFor(array $server): string
    {
        $seen = [];
        $spy  = function (string $ip) use (&$seen): array {
            $seen[] = $ip;
            return ['limited' => false, 'retry_after' => 0];
        };

        handle_lookup_request(
            ['REQUEST_METHOD' => 'POST'] + $server,
            json_encode(['ips' => ['1.2.3.4']]),
            $this->realLookup(),
            $spy
        );

        $this->assertCount(1, $seen);
        return $seen[0];
    }

    // IPG-10 F2: a direct-to-origin caller must not pick its own bucket.
    public function testCfHeaderIgnoredWhenRemoteAddrIsNotCloudflare(): void
    {
        $this->assertSame('203.0.113.5', $this->rateLimitKeyFor([
            'REMOTE_ADDR'           => '203.0.113.5',
            'HTTP_CF_CONNECTING_IP' => '198.51.100.9',
        ]));
    }

    public function testCfHeaderUsedWhenRemoteAddrIsCloudflareV4(): void
    {
        $this->assertSame('198.51.100.9', $this->rateLimitKeyFor([
            'REMOTE_ADDR'           => '162.158.1.1',
            'HTTP_CF_CONNECTING_IP' => '198.51.100.9',
        ]));
    }

    public function testCfHeaderUsedWhenRemoteAddrIsCloudflareV6(): void
    {
        $this->assertSame('2001:db8::1', $this->rateLimitKeyFor([
            'REMOTE_ADDR'           => '2a06:98c7:1::5',
            'HTTP_CF_CONNECTING_IP' => '2001:db8::1',
        ]));
    }

    public function testGarbageCfHeaderFromCloudflareFallsBackToRemoteAddr(): void
    {
        $this->assertSame('162.158.1.1', $this->rateLimitKeyFor([
            'REMOTE_ADDR'           => '162.158.1.1',
            'HTTP_CF_CONNECTING_IP' => 'not-an-ip; x',
        ]));
    }

    public function testIpInCidrBoundaries(): void
    {
        $this->assertTrue(lookup_endpoint_ip_in_cidr('104.16.0.0', '104.16.0.0/13'));
        $this->assertTrue(lookup_endpoint_ip_in_cidr('104.23.255.255', '104.16.0.0/13'));
        $this->assertFalse(lookup_endpoint_ip_in_cidr('104.24.0.0', '104.16.0.0/13'));
        $this->assertFalse(lookup_endpoint_ip_in_cidr('104.15.255.255', '104.16.0.0/13'));
        $this->assertTrue(lookup_endpoint_ip_in_cidr('2a06:98c7:ffff::1', '2a06:98c0::/29'));
        $this->assertFalse(lookup_endpoint_ip_in_cidr('2a06:98c8::1', '2a06:98c0::/29'));
        $this->assertFalse(lookup_endpoint_ip_in_cidr('162.158.1.1', '2400:cb00::/32'));
        $this->assertFalse(lookup_endpoint_ip_in_cidr('', '104.16.0.0/13'));
    }

    public function testClientIpFallsBackToRemoteAddr(): void
    {
        $seen = [];
        $spy  = function (string $ip) use (&$seen): array {
            $seen[] = $ip;
            return ['limited' => false, 'retry_after' => 0];
        };

        handle_lookup_request(
            ['REQUEST_METHOD' => 'POST', 'REMOTE_ADDR' => '10.0.0.1'],
            json_encode(['ips' => ['1.2.3.4']]),
            $this->realLookup(),
            $spy
        );

        $this->assertSame(['10.0.0.1'], $seen);
    }

    // ── never logs request bodies, on any path ──────────────────────────────

    public function testSuccessPathNeverLogsTheBody(): void
    {
        $body = json_encode(['ips' => ['81.2.69.142']]);

        handle_lookup_request(
            ['REQUEST_METHOD' => 'POST', 'REMOTE_ADDR' => '198.51.100.1'],
            $body,
            $this->realLookup(),
            $this->notLimited()
        );

        $this->assertStringNotContainsString('81.2.69.142', $this->errorLogContents());
    }

    // ── APCu-missing default rate limiter never blocks ──────────────────────

    public function testDefaultRateLimiterSkipsGracefullyWithoutApcu(): void
    {
        if (function_exists('apcu_inc')) {
            $this->markTestSkipped('APCu is loaded in this environment; the skip-gracefully path is untestable here.');
        }

        $result = \default_lookup_rate_limiter('198.51.100.1');
        $this->assertFalse($result['limited']);
    }
}

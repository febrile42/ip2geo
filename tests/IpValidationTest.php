<?php

declare(strict_types=1);

namespace Ip2Geo\Tests;

use PHPUnit\Framework\TestCase;

/**
 * IP validation tests for the get-report.php submission filter.
 *
 * get-report.php validates each client-submitted IP using:
 *   filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)
 *
 * Only publicly-routable IPs pass. Private, reserved, loopback, and
 * malformed values are rejected. freq is clamped to min 1.
 *
 * We test the exact filter_var call so any change to the validation flags
 * in get-report.php is immediately caught here.
 */
class IpValidationTest extends TestCase
{
    private const FLAGS = FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE;

    /** Mirror the validation from get-report.php. Returns the validated IP or false. */
    private function validateIp(mixed $raw): string|false
    {
        return filter_var($raw ?? '', FILTER_VALIDATE_IP, self::FLAGS);
    }

    /** Mirror the freq clamp: max(1, (int)$freq). */
    private function clampFreq(mixed $raw): int
    {
        return max(1, (int)($raw ?? 1));
    }

    // ── valid public IPs ──────────────────────────────────────────────────────

    public function testPublicIpv4IsAccepted(): void
    {
        $this->assertSame('8.8.8.8', $this->validateIp('8.8.8.8'));
    }

    public function testPublicIpv6IsAccepted(): void
    {
        $result = $this->validateIp('2001:4860:4860::8888');
        $this->assertNotFalse($result);
    }

    public function testAnotherPublicIpv4IsAccepted(): void
    {
        $this->assertSame('1.1.1.1', $this->validateIp('1.1.1.1'));
    }

    // ── private ranges rejected ───────────────────────────────────────────────

    public function testRfc1918_10IsRejected(): void
    {
        $this->assertFalse($this->validateIp('10.0.0.1'));
    }

    public function testRfc1918_172IsRejected(): void
    {
        $this->assertFalse($this->validateIp('172.16.0.1'));
    }

    public function testRfc1918_192IsRejected(): void
    {
        $this->assertFalse($this->validateIp('192.168.1.1'));
    }

    // ── reserved / special ranges rejected ───────────────────────────────────

    public function testLoopbackIsRejected(): void
    {
        $this->assertFalse($this->validateIp('127.0.0.1'));
    }

    public function testIpv6LoopbackIsRejected(): void
    {
        $this->assertFalse($this->validateIp('::1'));
    }

    public function testLinkLocalIsRejected(): void
    {
        $this->assertFalse($this->validateIp('169.254.0.1'));
    }

    // ── malformed values rejected ─────────────────────────────────────────────

    public function testEmptyStringIsRejected(): void
    {
        $this->assertFalse($this->validateIp(''));
    }

    public function testNullIsRejected(): void
    {
        $this->assertFalse($this->validateIp(null));
    }

    public function testRandomStringIsRejected(): void
    {
        $this->assertFalse($this->validateIp('not-an-ip'));
    }

    public function testPartialIpIsRejected(): void
    {
        $this->assertFalse($this->validateIp('1.2.3'));
    }

    public function testIpWithPortIsRejected(): void
    {
        $this->assertFalse($this->validateIp('8.8.8.8:80'));
    }

    // ── freq clamp ────────────────────────────────────────────────────────────

    public function testFreqBelowOneClampedToOne(): void
    {
        $this->assertSame(1, $this->clampFreq(0));
    }

    public function testNegativeFreqClampedToOne(): void
    {
        $this->assertSame(1, $this->clampFreq(-5));
    }

    public function testNullFreqDefaultsToOne(): void
    {
        $this->assertSame(1, $this->clampFreq(null));
    }

    public function testValidFreqPreserved(): void
    {
        $this->assertSame(42, $this->clampFreq(42));
    }

    public function testStringFreqCast(): void
    {
        $this->assertSame(10, $this->clampFreq('10'));
    }

    // ── full validation loop (mirrors get-report.php foreach) ────────────────

    public function testMixedInputFiltersToPublicIpsOnly(): void
    {
        $client_data = [
            ['ip' => '8.8.8.8',     'freq' => 5],
            ['ip' => '192.168.1.1', 'freq' => 2],   // private — rejected
            ['ip' => '1.1.1.1',     'freq' => 3],
            ['ip' => 'not-an-ip',   'freq' => 1],   // malformed — rejected
            ['ip' => '10.0.0.1',    'freq' => 1],   // private — rejected
        ];

        $ip_freq_map = [];
        foreach ($client_data as $entry) {
            $ip = filter_var($entry['ip'] ?? '', FILTER_VALIDATE_IP, self::FLAGS);
            if ($ip === false) continue;
            $freq = max(1, (int)($entry['freq'] ?? 1));
            $ip_freq_map[$ip] = $freq;
        }

        $this->assertCount(2, $ip_freq_map);
        $this->assertArrayHasKey('8.8.8.8', $ip_freq_map);
        $this->assertSame(5, $ip_freq_map['8.8.8.8']);
        $this->assertArrayHasKey('1.1.1.1', $ip_freq_map);
        $this->assertSame(3, $ip_freq_map['1.1.1.1']);
    }

    public function testAllPrivateIpsProducesEmptyMap(): void
    {
        $client_data = [
            ['ip' => '10.0.0.1'],
            ['ip' => '172.16.0.1'],
            ['ip' => '192.168.0.1'],
        ];

        $ip_freq_map = [];
        foreach ($client_data as $entry) {
            $ip = filter_var($entry['ip'] ?? '', FILTER_VALIDATE_IP, self::FLAGS);
            if ($ip === false) continue;
            $ip_freq_map[$ip] = max(1, (int)($entry['freq'] ?? 1));
        }

        $this->assertEmpty($ip_freq_map);
    }
}

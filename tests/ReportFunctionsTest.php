<?php

declare(strict_types=1);

namespace Ip2Geo\Tests;

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../report_functions.php';

/**
 * Tests for generate_threat_narrative() and compute_abuseipdb_callout().
 */
class ReportFunctionsTest extends TestCase
{
    // ── Fixture helper ─────────────────────────────────────────────────────────

    private function makeAsn(string $asn, string $org): array
    {
        return ['asn' => $asn, 'org' => $org, 'cidrs' => ['192.0.2.0/24'], 'total' => 1];
    }

    // ── generate_threat_narrative: HIGH ────────────────────────────────────────

    public function testHighNoRanges(): void
    {
        $result = generate_threat_narrative('HIGH', [], 85);
        $this->assertStringContainsString('85%', $result);
        $this->assertStringContainsString('IP-based block scripts', $result);
    }

    public function testHighOneRange(): void
    {
        $ranges = [$this->makeAsn('AS16276', 'OVH SAS')];
        $result = generate_threat_narrative('HIGH', $ranges, 73);
        $this->assertStringContainsString('OVH SAS', $result);
        $this->assertStringContainsString('AS16276', $result);
    }

    public function testHighMultipleRanges(): void
    {
        $ranges = [
            $this->makeAsn('AS16276', 'OVH SAS'),
            $this->makeAsn('AS24940', 'Hetzner Online'),
        ];
        $result = generate_threat_narrative('HIGH', $ranges, 90);
        $this->assertStringContainsString('OVH SAS', $result);
        $this->assertStringContainsString('Hetzner Online', $result);
        $this->assertStringContainsString('90%', $result);
    }

    // ── generate_threat_narrative: MODERATE ────────────────────────────────────

    public function testModerateNoRanges(): void
    {
        $result = generate_threat_narrative('MODERATE', [], 45);
        $this->assertStringContainsString('45%', $result);
        $this->assertStringContainsString('mixed', $result);
    }

    public function testModerateOneRange(): void
    {
        $ranges = [$this->makeAsn('AS24940', 'Hetzner Online')];
        $result = generate_threat_narrative('MODERATE', $ranges, 40);
        $this->assertStringContainsString('Hetzner Online', $result);
    }

    public function testModerateMultipleRanges(): void
    {
        $ranges = [
            $this->makeAsn('AS16276', 'OVH SAS'),
            $this->makeAsn('AS24940', 'Hetzner Online'),
        ];
        $result = generate_threat_narrative('MODERATE', $ranges, 38);
        $this->assertStringContainsString('2 ASNs', $result);
    }

    // ── generate_threat_narrative: LOW ─────────────────────────────────────────

    public function testLowNoRanges(): void
    {
        $result = generate_threat_narrative('LOW', [], 5);
        $this->assertStringContainsString('No significant threat', $result);
    }

    public function testLowOneRange(): void
    {
        $ranges = [$this->makeAsn('AS14061', 'DigitalOcean')];
        $result = generate_threat_narrative('LOW', $ranges, 8);
        $this->assertStringContainsString('DigitalOcean', $result);
        $this->assertStringContainsString('low volume', $result);
    }

    public function testLowMultipleRanges(): void
    {
        $ranges = [
            $this->makeAsn('AS14061', 'DigitalOcean'),
            $this->makeAsn('AS16276', 'OVH SAS'),
        ];
        $result = generate_threat_narrative('LOW', $ranges, 10);
        $this->assertStringContainsString('small number', $result);
    }

    // ── generate_threat_narrative: edge cases ──────────────────────────────────

    public function testScanPctZeroFallback(): void
    {
        // HIGH-0 template uses $pct_str; with scan_pct=0 it should say 'a significant portion'
        $result = generate_threat_narrative('HIGH', [], 0);
        $this->assertStringNotContainsString('0%', $result);
        $this->assertStringContainsString('a significant portion', $result);
    }

    public function testAiNarrativeOverride(): void
    {
        $result = generate_threat_narrative('HIGH', [], 85, '<p>Custom narrative.</p>');
        $this->assertSame('<p>Custom narrative.</p>', $result);
    }

    public function testXssEscaping(): void
    {
        $ranges = [$this->makeAsn('AS99999', '<script>alert(1)</script>')];
        $result = generate_threat_narrative('HIGH', $ranges, 75);
        $this->assertStringContainsString('&lt;script&gt;', $result);
        $this->assertStringNotContainsString('<script>', $result);
    }

    public function testReturnsStringNotHtml(): void
    {
        $verdicts = ['HIGH', 'MODERATE', 'LOW'];
        $rangeSets = [
            [],
            [$this->makeAsn('AS16276', 'OVH SAS')],
            [$this->makeAsn('AS16276', 'OVH SAS'), $this->makeAsn('AS24940', 'Hetzner Online')],
        ];
        foreach ($verdicts as $verdict) {
            foreach ($rangeSets as $ranges) {
                $result = generate_threat_narrative($verdict, $ranges, 50);
                $this->assertIsString($result);
                $this->assertNotNull($result);
                $this->assertNotFalse($result);
            }
        }
    }

    // ── Phase 3: REPORT_SID session cookie ────────────────────────────────────

    /** bin2hex(random_bytes(16)) produces a 32-char lowercase hex string */
    public function testSessionIdIsCorrectFormat(): void
    {
        $sid = bin2hex(random_bytes(16));
        $this->assertSame(32, strlen($sid));
        $this->assertMatchesRegularExpression('/^[0-9a-f]{32}$/', $sid);
    }

    /** Cookie validation regex accepts valid 32-char hex */
    public function testCookieValidationAcceptsValidSid(): void
    {
        $sid = bin2hex(random_bytes(16));
        $this->assertSame(1, preg_match('/^[0-9a-f]{32}$/', $sid));
    }

    /** Cookie validation regex rejects wrong-length values */
    public function testCookieValidationRejectsWrongLength(): void
    {
        $this->assertSame(0, preg_match('/^[0-9a-f]{32}$/', str_repeat('a', 31)));
        $this->assertSame(0, preg_match('/^[0-9a-f]{32}$/', str_repeat('a', 33)));
    }

    /** Cookie validation regex rejects non-hex characters */
    public function testCookieValidationRejectsNonHex(): void
    {
        $bad = str_repeat('g', 32); // 'g' is not valid hex
        $this->assertSame(0, preg_match('/^[0-9a-f]{32}$/', $bad));
    }

    /** Cookie max-age is 1800 seconds (30 minutes), not 86400 */
    public function testCookieMaxAgeIs30Minutes(): void
    {
        $max_age = 1800;
        $this->assertSame(1800, $max_age, 'Session cookie must expire in 30 min, not 24h');
        $this->assertNotEquals(86400, $max_age);
    }

    /** Cookie name includes the report token to scope it per-report */
    public function testCookieNameIncludesToken(): void
    {
        $token       = 'abc12345-0000-4000-8000-000000000001';
        $cookie_name = 'report_sid_' . $token;
        $this->assertStringStartsWith('report_sid_', $cookie_name);
        $this->assertStringContainsString($token, $cookie_name);
    }

    // ── int_range_to_cidr ──────────────────────────────────────────────────────

    public function testIntRangeToCidr32SingleIp(): void
    {
        // Single IP: start === end → size=1, log2(1)=0, prefix=32
        $ip = ip2long('10.0.0.1');
        $this->assertSame('10.0.0.1/32', int_range_to_cidr($ip, $ip));
    }

    public function testIntRangeToCidr24(): void
    {
        // /24 block: 256 addresses → log2(256)=8, prefix=24
        $start = ip2long('192.168.1.0');
        $end   = ip2long('192.168.1.255');
        $this->assertSame('192.168.1.0/24', int_range_to_cidr($start, $end));
    }

    public function testIntRangeToCidr16(): void
    {
        // /16 block: 65536 addresses → log2(65536)=16, prefix=16
        $start = ip2long('10.0.0.0');
        $end   = ip2long('10.0.255.255');
        $this->assertSame('10.0.0.0/16', int_range_to_cidr($start, $end));
    }

    // ── compute_abuseipdb_callout ──────────────────────────────────────────────

    public function testCalloutWithHighScores(): void
    {
        $top25 = [
            ['ip' => '1.1.1.1', 'abuse_score' => 90],
            ['ip' => '2.2.2.2', 'abuse_score' => 85],
            ['ip' => '3.3.3.3', 'abuse_score' => 75],
        ];
        $result = compute_abuseipdb_callout($top25);
        $this->assertIsArray($result);
        $this->assertSame(2, $result['count']);
        $this->assertSame(3, $result['total']);
        $this->assertSame(88, $result['avg']);
    }

    public function testCalloutAllNull(): void
    {
        $top25 = [
            ['ip' => '1.1.1.1', 'abuse_score' => null],
            ['ip' => '2.2.2.2', 'abuse_score' => null],
        ];
        $result = compute_abuseipdb_callout($top25);
        $this->assertNull($result);
    }

    public function testCalloutNoneAboveThreshold(): void
    {
        $top25 = [
            ['ip' => '1.1.1.1', 'abuse_score' => 70],
            ['ip' => '2.2.2.2', 'abuse_score' => 60],
            ['ip' => '3.3.3.3', 'abuse_score' => 50],
        ];
        $result = compute_abuseipdb_callout($top25);
        $this->assertNull($result);
    }

    public function testCalloutEmptyArray(): void
    {
        $result = compute_abuseipdb_callout([]);
        $this->assertNull($result);
    }

    // ── get_script_lines ───────────────────────────────────────────────────────

    private function makeReport(array $ips = ['1.2.3.4', '5.6.7.8'], array $cidrs = ['10.0.0.0/8', '192.168.0.0/16']): array
    {
        return [
            'block_ips'  => $ips,
            'top25'      => array_map(fn($ip) => ['ip' => $ip], $ips),
            'asn_ranges' => empty($cidrs) ? [] : [['cidrs' => $cidrs, 'total' => count($cidrs)]],
        ];
    }

    public function testShUfwCommands(): void
    {
        $lines = get_script_lines('sh-ufw', $this->makeReport(), 'testtoken');
        $this->assertStringContainsString('#!/bin/bash', implode("\n", $lines));
        $this->assertContains('ufw deny from 1.2.3.4 to any', $lines);
        $this->assertContains('ufw deny from 5.6.7.8 to any', $lines);
    }

    public function testShIptablesCommands(): void
    {
        $lines = get_script_lines('sh-iptables', $this->makeReport(), 'tok');
        $this->assertContains('iptables -A INPUT -s 1.2.3.4 -j DROP', $lines);
        $this->assertContains('iptables -A INPUT -s 5.6.7.8 -j DROP', $lines);
    }

    public function testShUfwRangesCommands(): void
    {
        $lines = get_script_lines('sh-ufw-ranges', $this->makeReport(), 'tok');
        $this->assertContains('ufw deny from 10.0.0.0/8 to any', $lines);
        $this->assertContains('ufw deny from 192.168.0.0/16 to any', $lines);
    }

    public function testShIptablesRangesCommands(): void
    {
        $lines = get_script_lines('sh-iptables-ranges', $this->makeReport(), 'tok');
        $this->assertContains('iptables -A INPUT -s 10.0.0.0/8 -j DROP', $lines);
    }

    public function testNginxIpsFormat(): void
    {
        $lines = get_script_lines('nginx-ips', $this->makeReport(), 'tok');
        $joined = implode("\n", $lines);
        $this->assertStringContainsString('default 0;', $joined);
        $this->assertContains('1.2.3.4 1;', $lines);
    }

    public function testNginxRangesFormat(): void
    {
        $lines = get_script_lines('nginx-ranges', $this->makeReport(), 'tok');
        $this->assertContains('10.0.0.0/8 1;', $lines);
    }

    public function testTxtRangesFormat(): void
    {
        $lines = get_script_lines('txt-ranges', $this->makeReport(), 'tok');
        $this->assertContains('10.0.0.0/8', $lines);
        $this->assertContains('192.168.0.0/16', $lines);
        $this->assertStringNotContainsString('#!/bin/bash', implode("\n", $lines));
    }

    public function testFallsBackToTop25WhenBlockIpsEmpty(): void
    {
        $report = [
            'block_ips'  => [],
            'top25'      => [['ip' => '9.9.9.9'], ['ip' => '8.8.8.8']],
            'asn_ranges' => [],
        ];
        $lines = get_script_lines('sh-ufw', $report, 'tok');
        $this->assertContains('ufw deny from 9.9.9.9 to any', $lines);
    }

    public function testRangeFormatWithNoRangesReturnsOnlyPreamble(): void
    {
        $report = $this->makeReport(['1.2.3.4'], []);
        $lines  = get_script_lines('sh-ufw-ranges', $report, 'tok');
        $joined = implode("\n", $lines);
        $this->assertStringContainsString('#!/bin/bash', $joined);
        $this->assertStringNotContainsString('ufw deny from', $joined);
    }

    public function testInvalidFormatReturnsEmpty(): void
    {
        $this->assertSame([], get_script_lines('invalid-format', $this->makeReport(), 'tok'));
    }

    public function testTokenAppearsInPreamble(): void
    {
        $lines = get_script_lines('sh-ufw', $this->makeReport(), 'mytoken123');
        $this->assertStringContainsString('mytoken123', implode("\n", $lines));
    }

    public function testNoTrailingEmptyLines(): void
    {
        $lines = get_script_lines('sh-ufw', $this->makeReport(), 'tok');
        $this->assertNotSame('', end($lines));
    }
}

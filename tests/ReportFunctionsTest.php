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
}
